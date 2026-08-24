use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use jsonc_parser::{ParseOptions, cst::CstInputValue, cst::CstRootNode, parse_to_serde_value};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};
use tokio::{process::Command, time::timeout};
use toml_edit::{Array, DocumentMut, Item, Table, value};

pub const ONBOARDING_VERSION: u8 = 1;
const CLIENT_IDS: [&str; 5] = ["codex", "claude-code", "cursor", "opencode", "openclaw"];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentClientStatus {
    pub client_id: String,
    pub display_name: String,
    pub detected: bool,
    pub state: String,
    pub install_path: String,
    pub config_path: String,
    pub can_register: bool,
    pub can_repair: bool,
    pub can_remove: bool,
    pub restart_required: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentActionResult {
    pub ok: bool,
    pub action: String,
    #[serde(flatten)]
    pub client: AgentClientStatus,
}

#[derive(Clone)]
pub struct AgentRegistry {
    executable: PathBuf,
    home: PathBuf,
    path_dirs: Vec<PathBuf>,
    app_data: PathBuf,
    local_app_data: PathBuf,
}

impl AgentRegistry {
    pub fn new(executable: PathBuf) -> Result<Self> {
        let home = dirs::home_dir().context("无法确定用户主目录")?;
        let path_dirs = env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect();
        let app_data = env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"));
        let local_app_data = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Local"));
        Ok(Self {
            executable: normalize_path(executable),
            home,
            path_dirs,
            app_data,
            local_app_data,
        })
    }

    #[cfg(test)]
    fn isolated(executable: PathBuf, home: PathBuf, path_dirs: Vec<PathBuf>) -> Self {
        Self {
            executable: normalize_path(executable),
            app_data: home.join("AppData").join("Roaming"),
            local_app_data: home.join("AppData").join("Local"),
            home,
            path_dirs,
        }
    }

    pub async fn list(&self) -> Vec<AgentClientStatus> {
        let mut clients = Vec::with_capacity(CLIENT_IDS.len());
        for client_id in CLIENT_IDS {
            clients.push(self.status(client_id).await);
        }
        clients
    }

    pub async fn register(&self, client_ids: &[String]) -> Vec<AgentActionResult> {
        let mut results = Vec::new();
        for client_id in client_ids {
            results.push(self.mutate(client_id, "register").await);
        }
        results
    }

    pub async fn repair(&self, client_id: &str) -> AgentActionResult {
        self.mutate(client_id, "repair").await
    }

    pub async fn remove(&self, client_id: &str) -> AgentActionResult {
        self.mutate(client_id, "remove").await
    }

    async fn mutate(&self, client_id: &str, action: &str) -> AgentActionResult {
        if !CLIENT_IDS.contains(&client_id) {
            return self.error_status(client_id, action, "不支持的 Agent 客户端");
        }
        let before = self.status(client_id).await;
        let allowed = match action {
            "register" => before.can_register,
            "repair" => before.can_repair,
            "remove" => before.can_remove,
            _ => false,
        };
        if !allowed {
            return AgentActionResult {
                ok: false,
                action: action.to_owned(),
                client: AgentClientStatus {
                    message: format!("当前状态不能执行{}", action_label(action)),
                    ..before
                },
            };
        }

        let result = match client_id {
            "codex" => self.mutate_codex(action),
            "cursor" | "opencode" => self.mutate_json_client(client_id, action),
            "claude-code" | "openclaw" => self.mutate_cli_client(client_id, action).await,
            _ => unreachable!(),
        };
        match result {
            Ok(()) => {
                let mut after = self.status(client_id).await;
                after.restart_required = true;
                AgentActionResult {
                    ok: true,
                    action: action.to_owned(),
                    client: after,
                }
            }
            Err(error) => {
                let mut after = self.status(client_id).await;
                after.message = error.to_string();
                AgentActionResult {
                    ok: false,
                    action: action.to_owned(),
                    client: after,
                }
            }
        }
    }

    async fn status(&self, client_id: &str) -> AgentClientStatus {
        let display_name = display_name(client_id).to_owned();
        let config_path = self.config_path(client_id);
        let executable = self.find_client_executable(client_id);
        let detected =
            config_path.is_file() || executable.is_some() || self.desktop_install_exists(client_id);
        let install_path = executable
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut status = AgentClientStatus {
            client_id: client_id.to_owned(),
            display_name,
            detected,
            state: if detected { "available" } else { "notDetected" }.to_owned(),
            install_path,
            config_path: config_path.to_string_lossy().into_owned(),
            can_register: detected,
            can_repair: false,
            can_remove: false,
            restart_required: false,
            message: if detected {
                "可以连接 KRU".to_owned()
            } else {
                "未在本机检测到".to_owned()
            },
        };
        if !detected {
            return status;
        }

        let inspected = match client_id {
            "codex" => self.inspect_codex(),
            "cursor" | "opencode" => self.inspect_json_client(client_id),
            "claude-code" | "openclaw" => {
                let Some(executable) = executable else {
                    status.state = "error".to_owned();
                    status.can_register = false;
                    status.message = "检测到配置，但找不到可调用的 CLI".to_owned();
                    return status;
                };
                self.inspect_cli_client(client_id, &executable).await
            }
            _ => Ok(EntryState::Available),
        };
        match inspected {
            Ok(entry) => apply_entry_state(&mut status, entry),
            Err(error) => {
                status.state = "error".to_owned();
                status.can_register = false;
                status.message = error.to_string();
            }
        }
        status
    }

    fn inspect_codex(&self) -> Result<EntryState> {
        let path = self.config_path("codex");
        if !path.is_file() {
            return Ok(EntryState::Available);
        }
        let text = fs::read_to_string(&path).context("无法读取 Codex 配置")?;
        let document = text.parse::<DocumentMut>().context("Codex TOML 配置无效")?;
        let Some(entry) = document
            .get("mcp_servers")
            .and_then(Item::as_table_like)
            .and_then(|table| table.get("kru"))
            .and_then(Item::as_table_like)
        else {
            return Ok(EntryState::Available);
        };
        let command = entry
            .get("command")
            .and_then(Item::as_str)
            .unwrap_or_default();
        let args = entry
            .get("args")
            .and_then(Item::as_array)
            .map(toml_array_strings)
            .unwrap_or_default();
        Ok(classify_command(command, &args, &self.executable))
    }

    fn inspect_json_client(&self, client_id: &str) -> Result<EntryState> {
        let path = self.config_path(client_id);
        if !path.is_file() {
            return Ok(EntryState::Available);
        }
        let text = fs::read_to_string(&path).context("无法读取 Agent JSON 配置")?;
        let document: JsonValue = parse_to_serde_value(&text, &ParseOptions::default())
            .context("Agent JSON/JSONC 配置无效")?;
        let entry = if client_id == "cursor" {
            document.pointer("/mcpServers/kru")
        } else {
            document.pointer("/mcp/kru")
        };
        let Some(entry) = entry else {
            return Ok(EntryState::Available);
        };
        let (command, args) = if client_id == "cursor" {
            (
                entry
                    .get("command")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                json_array_strings(entry.get("args")),
            )
        } else {
            let command = json_array_strings(entry.get("command"));
            (
                command.first().cloned().unwrap_or_default(),
                command.iter().skip(1).cloned().collect(),
            )
        };
        Ok(classify_command(&command, &args, &self.executable))
    }

    async fn inspect_cli_client(&self, client_id: &str, executable: &Path) -> Result<EntryState> {
        let args = if client_id == "claude-code" {
            vec!["mcp", "get", "kru"]
        } else {
            vec!["mcp", "show", "kru", "--json"]
        };
        let output = self.run_cli(executable, &args).await?;
        let text = output_text(&output);
        if !output.status.success() {
            if is_missing_entry(&text) {
                return Ok(EntryState::Available);
            }
            bail!("{}", clean_process_error(&text));
        }
        if text_matches(&text, &self.executable) {
            Ok(EntryState::Registered)
        } else if text_has_kru_command(&text) {
            Ok(EntryState::Stale)
        } else {
            Ok(EntryState::Conflict)
        }
    }

    fn mutate_codex(&self, action: &str) -> Result<()> {
        let path = self.config_path("codex");
        let original = read_or(&path, "")?;
        let mut document = original
            .parse::<DocumentMut>()
            .context("Codex TOML 配置无效，未进行修改")?;
        if action == "remove" {
            if let Some(servers) = document
                .get_mut("mcp_servers")
                .and_then(Item::as_table_like_mut)
            {
                servers.remove("kru");
            }
        } else {
            if action == "repair" && path.is_file() {
                backup_config(&path)?;
            }
            if !document.contains_key("mcp_servers") {
                document["mcp_servers"] = Item::Table(Table::new());
            }
            let servers = document["mcp_servers"]
                .as_table_like_mut()
                .context("Codex mcp_servers 不是表")?;
            let mut table = Table::new();
            table["command"] = value(self.executable.to_string_lossy().into_owned());
            let mut args = Array::new();
            args.push("mcp");
            args.push("stdio");
            table["args"] = value(args);
            servers.insert("kru", Item::Table(table));
        }
        write_atomic_checked(&path, &original, &document.to_string())
    }

    fn mutate_json_client(&self, client_id: &str, action: &str) -> Result<()> {
        let path = self.config_path(client_id);
        let original = read_or(&path, "{}\n")?;
        let root = CstRootNode::parse(&original, &ParseOptions::default())
            .context("Agent JSON/JSONC 配置无效，未进行修改")?;
        let root_object = root.object_value_or_set();
        let container_name = if client_id == "cursor" {
            "mcpServers"
        } else {
            "mcp"
        };
        if action == "remove" {
            if let Some(container) = root_object.object_value(container_name) {
                if let Some(entry) = container.get("kru") {
                    entry.remove();
                }
            }
        } else {
            if action == "repair" && path.is_file() {
                backup_config(&path)?;
            }
            let container = root_object.object_value_or_set(container_name);
            let entry = if client_id == "cursor" {
                CstInputValue::Object(vec![
                    (
                        "command".to_owned(),
                        self.executable.to_string_lossy().into_owned().into(),
                    ),
                    ("args".to_owned(), vec!["mcp", "stdio"].into()),
                ])
            } else {
                CstInputValue::Object(vec![
                    ("type".to_owned(), "local".into()),
                    (
                        "command".to_owned(),
                        vec![
                            self.executable.to_string_lossy().into_owned(),
                            "mcp".to_owned(),
                            "stdio".to_owned(),
                        ]
                        .into(),
                    ),
                    ("enabled".to_owned(), true.into()),
                ])
            };
            if let Some(current) = container.get("kru") {
                current.set_value(entry);
            } else {
                container.append("kru", entry);
            }
        }
        write_atomic_checked(&path, &original, &root.to_string())
    }

    async fn mutate_cli_client(&self, client_id: &str, action: &str) -> Result<()> {
        let executable = self
            .find_client_executable(client_id)
            .context("找不到 Agent CLI")?;
        if action == "remove" || action == "repair" {
            let args = if client_id == "claude-code" {
                vec!["mcp", "remove", "--scope", "user", "kru"]
            } else {
                vec!["mcp", "unset", "kru"]
            };
            let output = self.run_cli(&executable, &args).await?;
            if !output.status.success()
                && !(action == "remove" && is_missing_entry(&output_text(&output)))
            {
                bail!("{}", clean_process_error(&output_text(&output)));
            }
            if action == "remove" {
                return Ok(());
            }
        }
        let exe = self.executable.to_string_lossy().into_owned();
        let args = if client_id == "claude-code" {
            vec![
                "mcp".to_owned(),
                "add".to_owned(),
                "--scope".to_owned(),
                "user".to_owned(),
                "--transport".to_owned(),
                "stdio".to_owned(),
                "kru".to_owned(),
                "--".to_owned(),
                exe,
                "mcp".to_owned(),
                "stdio".to_owned(),
            ]
        } else {
            vec![
                "mcp".to_owned(),
                "add".to_owned(),
                "kru".to_owned(),
                "--command".to_owned(),
                exe,
                "--arg".to_owned(),
                "mcp".to_owned(),
                "--arg".to_owned(),
                "stdio".to_owned(),
            ]
        };
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.run_cli(&executable, &refs).await?;
        if !output.status.success() {
            bail!("{}", clean_process_error(&output_text(&output)));
        }
        Ok(())
    }

    async fn run_cli(&self, executable: &Path, args: &[&str]) -> Result<Output> {
        let (program, prefix) = self.resolve_program(executable)?;
        let mut command = Command::new(program);
        command.args(prefix).args(args).kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        timeout(Duration::from_secs(20), command.output())
            .await
            .context("Agent CLI 操作超时")?
            .context("无法启动 Agent CLI")
    }

    fn resolve_program(&self, executable: &Path) -> Result<(PathBuf, Vec<String>)> {
        if !cfg!(windows)
            || !executable
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd"))
        {
            return Ok((executable.to_path_buf(), Vec::new()));
        }
        let text = fs::read_to_string(executable).context("无法读取 npm 命令启动器")?;
        let pattern = regex::Regex::new(r#"(?i)%dp0%\\([^\"\r\n]+\.(?:c?js|mjs))"#)?;
        let relative = pattern
            .captures(&text)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str().replace('\\', "/"))
            .context("该 .cmd 不是受支持的标准 npm 启动器")?;
        let root = executable.parent().context("npm 启动器目录无效")?;
        let target = normalize_path(root.join(relative));
        let modules = normalize_path(root.join("node_modules"));
        if !target.starts_with(&modules) || !target.is_file() {
            bail!("npm 启动器目标不在受信任的 node_modules 中");
        }
        let node = self
            .find_named_command(&["node"])
            .context("找不到 node.exe，无法安全运行 npm Agent CLI")?;
        Ok((node, vec![target.to_string_lossy().into_owned()]))
    }

    fn config_path(&self, client_id: &str) -> PathBuf {
        match client_id {
            "codex" => self.home.join(".codex").join("config.toml"),
            "claude-code" => self.home.join(".claude.json"),
            "cursor" => self.home.join(".cursor").join("mcp.json"),
            "opencode" => self
                .home
                .join(".config")
                .join("opencode")
                .join("opencode.json"),
            "openclaw" => self.home.join(".openclaw").join("openclaw.json"),
            _ => self.home.join(".kru").join("unsupported"),
        }
    }

    fn find_client_executable(&self, client_id: &str) -> Option<PathBuf> {
        let names: &[&str] = match client_id {
            "claude-code" => &["claude"],
            "cursor" => &["cursor-agent", "cursor"],
            _ => &[client_id],
        };
        self.find_named_command(names)
    }

    fn find_named_command(&self, names: &[&str]) -> Option<PathBuf> {
        let mut directories = vec![
            self.home.join(".local").join("bin"),
            self.app_data.join("npm"),
        ];
        if cfg!(target_os = "macos") {
            directories.extend([
                self.home.join("Library").join("pnpm"),
                self.home.join(".npm-global").join("bin"),
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/bin"),
            ]);
        } else if !cfg!(windows) {
            directories.extend([PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")]);
        }
        directories.extend(self.path_dirs.iter().cloned());
        for directory in directories {
            for name in names {
                let candidates = if cfg!(windows) {
                    vec![
                        directory.join(format!("{name}.exe")),
                        directory.join(format!("{name}.cmd")),
                    ]
                } else {
                    vec![directory.join(name)]
                };
                if let Some(found) = candidates.into_iter().find(|path| path.is_file()) {
                    return Some(normalize_path(found));
                }
            }
        }
        None
    }

    fn desktop_install_exists(&self, client_id: &str) -> bool {
        let candidates: Vec<PathBuf> = match (client_id, env::consts::OS) {
            ("codex", "windows") => vec![
                self.local_app_data
                    .join("Programs")
                    .join("Codex")
                    .join("Codex.exe"),
                self.local_app_data.join("Codex").join("Codex.exe"),
            ],
            ("cursor", "windows") => vec![
                self.local_app_data
                    .join("Programs")
                    .join("cursor")
                    .join("Cursor.exe"),
            ],
            ("codex", "macos") => vec![
                PathBuf::from("/Applications/Codex.app"),
                self.home.join("Applications/Codex.app"),
            ],
            ("cursor", "macos") => vec![
                PathBuf::from("/Applications/Cursor.app"),
                self.home.join("Applications/Cursor.app"),
            ],
            _ => Vec::new(),
        };
        candidates.into_iter().any(|path| path.exists())
    }

    fn error_status(&self, client_id: &str, action: &str, message: &str) -> AgentActionResult {
        AgentActionResult {
            ok: false,
            action: action.to_owned(),
            client: AgentClientStatus {
                client_id: client_id.to_owned(),
                display_name: display_name(client_id).to_owned(),
                detected: false,
                state: "error".to_owned(),
                install_path: String::new(),
                config_path: String::new(),
                can_register: false,
                can_repair: false,
                can_remove: false,
                restart_required: false,
                message: message.to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    Available,
    Registered,
    Stale,
    Conflict,
}

fn apply_entry_state(status: &mut AgentClientStatus, state: EntryState) {
    match state {
        EntryState::Available => {
            status.state = "available".to_owned();
            status.can_register = true;
            status.message = "可以连接 KRU".to_owned();
        }
        EntryState::Registered => {
            status.state = "registered".to_owned();
            status.can_register = false;
            status.can_remove = true;
            status.message = "KRU 已连接".to_owned();
        }
        EntryState::Stale => {
            status.state = "stale".to_owned();
            status.can_register = false;
            status.can_repair = true;
            status.can_remove = true;
            status.message = "KRU 路径或参数已过期".to_owned();
        }
        EntryState::Conflict => {
            status.state = "conflict".to_owned();
            status.can_register = false;
            status.can_repair = true;
            status.message = "已有同名 kru 配置，但内容不同".to_owned();
        }
    }
}

fn classify_command(command: &str, args: &[String], executable: &Path) -> EntryState {
    if same_path(Path::new(command), executable) && args == ["mcp", "stdio"] {
        EntryState::Registered
    } else if is_kru_command(command) {
        EntryState::Stale
    } else {
        EntryState::Conflict
    }
}

fn text_matches(text: &str, executable: &Path) -> bool {
    let normalized = text.replace("\\/", "/").to_ascii_lowercase();
    let exact = executable.to_string_lossy().to_ascii_lowercase();
    let portable = exact.strip_prefix(r"\\?\").unwrap_or(&exact);
    let candidates = [
        exact.clone(),
        portable.to_owned(),
        exact.replace('\\', r"\\"),
        portable.replace('\\', r"\\"),
    ];
    candidates
        .iter()
        .any(|candidate| normalized.contains(candidate))
        && normalized.contains("mcp")
        && normalized.contains("stdio")
}

fn text_has_kru_command(text: &str) -> bool {
    let pattern =
        regex::Regex::new(r#"(?im)(?:^\s*command\s*:\s*|\"command\"\s*:\s*\")([^\"\r\n,]+)"#)
            .expect("static command regex");
    pattern
        .captures_iter(text)
        .filter_map(|captures| captures.get(1))
        .any(|command| is_kru_command(command.as_str().trim()))
}

fn is_kru_command(command: &str) -> bool {
    let file_name = command
        .trim()
        .trim_matches(['\'', '"'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command);
    Path::new(file_name)
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("kru"))
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = normalize_path(left);
    let right = normalize_path(right);
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    fs::canonicalize(path.as_ref()).unwrap_or_else(|_| path.as_ref().to_path_buf())
}

fn toml_array_strings(array: &Array) -> Vec<String> {
    array
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn json_array_strings(value: Option<&JsonValue>) -> Vec<String> {
    value
        .and_then(JsonValue::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn read_or(path: &Path, fallback: &str) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(fallback.to_owned()),
        Err(error) => Err(error).with_context(|| format!("无法读取 {}", path.display())),
    }
}

fn write_atomic_checked(path: &Path, expected: &str, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("无法创建 Agent 配置目录")?;
    }
    let current = read_or(path, expected)?;
    if current != expected {
        bail!("Agent 配置在修改期间发生变化，请重新扫描后再试");
    }
    let mut writer = AtomicWriteFile::open(path).context("无法创建 Agent 配置临时文件")?;
    writer
        .write_all(value.as_bytes())
        .context("无法写入 Agent 配置")?;
    writer.commit().context("无法原子保存 Agent 配置")?;
    Ok(())
}

fn backup_config(path: &Path) -> Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let backup = path.with_file_name(format!("{file_name}.kru.{stamp}.bak"));
    fs::copy(path, &backup).context("无法备份冲突配置")?;
    Ok(backup)
}

fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn is_missing_entry(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "not found",
        "does not exist",
        "no mcp",
        "unknown mcp",
        "unknown server",
        "未找到",
        "不存在",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn clean_process_error(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        "Agent CLI 操作失败".to_owned()
    } else {
        text.chars().take(600).collect()
    }
}

fn display_name(client_id: &str) -> &str {
    match client_id {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        "cursor" => "Cursor",
        "opencode" => "OpenCode",
        "openclaw" => "OpenClaw",
        _ => "Unknown Agent",
    }
}

fn action_label(action: &str) -> &str {
    match action {
        "register" => "连接",
        "repair" => "修复",
        "remove" => "移除",
        _ => "操作",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn registry() -> (tempfile::TempDir, AgentRegistry) {
        let temp = tempdir().unwrap();
        let exe = temp
            .path()
            .join(if cfg!(windows) { "kru.exe" } else { "kru" });
        fs::write(&exe, b"test").unwrap();
        let registry = AgentRegistry::isolated(exe, temp.path().to_path_buf(), vec![]);
        (temp, registry)
    }

    #[tokio::test]
    async fn codex_registration_preserves_unrelated_toml_and_is_idempotent() {
        let (_temp, registry) = registry();
        let path = registry.config_path("codex");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "# keep\nmodel = \"gpt-test\"\n\n[mcp_servers.other]\ncommand = \"other\"\n",
        )
        .unwrap();
        let first = registry.mutate("codex", "register").await;
        assert!(first.ok, "{}", first.client.message);
        let once = fs::read_to_string(&path).unwrap();
        assert!(once.contains("# keep"));
        assert!(once.contains("mcp_servers.other"));
        assert!(once.contains("mcp_servers.kru"));
        let second = registry.mutate("codex", "register").await;
        assert!(!second.ok);
        assert_eq!(once, fs::read_to_string(&path).unwrap());
    }

    #[tokio::test]
    async fn cursor_registration_and_removal_preserve_jsonc_comments() {
        let (_temp, registry) = registry();
        let path = registry.config_path("cursor");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\n  // keep\n  \"theme\": \"dark\",\n  \"mcpServers\": { \"other\": { \"command\": \"other\" } }\n}\n").unwrap();
        assert!(registry.mutate("cursor", "register").await.ok);
        let registered = fs::read_to_string(&path).unwrap();
        assert!(registered.contains("// keep"));
        assert!(registered.contains("\"other\""));
        assert!(registered.contains("\"kru\""));
        assert!(registry.mutate("cursor", "remove").await.ok);
        let removed = fs::read_to_string(&path).unwrap();
        assert!(removed.contains("// keep"));
        assert!(removed.contains("\"other\""));
        assert!(!removed.contains("\"kru\""));
    }

    #[tokio::test]
    async fn conflicting_entry_is_not_overwritten_without_repair() {
        let (_temp, registry) = registry();
        let path = registry.config_path("codex");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "[mcp_servers.kru]\ncommand = \"not-kru\"\nargs = []\n";
        fs::write(&path, original).unwrap();
        let status = registry.status("codex").await;
        assert_eq!(status.state, "conflict");
        assert!(!registry.mutate("codex", "register").await.ok);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(registry.mutate("codex", "repair").await.ok);
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().any(|item| {
            item.unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".kru.")
        }));
    }

    #[tokio::test]
    async fn opencode_registration_uses_local_stdio_shape() {
        let (_temp, registry) = registry();
        let path = registry.config_path("opencode");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{ \"mcp\": {} }\n").unwrap();
        assert!(registry.mutate("opencode", "register").await.ok);
        let text = fs::read_to_string(&path).unwrap();
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert_eq!(
            value.pointer("/mcp/kru/type"),
            Some(&serde_json::json!("local"))
        );
        assert_eq!(
            value.pointer("/mcp/kru/enabled"),
            Some(&serde_json::json!(true))
        );
        let command = value
            .pointer("/mcp/kru/command")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(command[1], "mcp");
        assert_eq!(command[2], "stdio");
    }

    #[test]
    fn cli_conflict_detection_checks_command_not_server_name() {
        assert!(!text_has_kru_command(
            "kru:\n  Command: C:\\tools\\other.exe\n  Args: mcp stdio"
        ));
        assert!(text_has_kru_command(
            r#"{"name":"kru","command":"C:\\old\\kru.exe","args":["mcp","stdio"]}"#
        ));
    }

    #[test]
    fn cli_path_match_accepts_windows_verbatim_path_output() {
        let executable = Path::new(r"\\?\C:\Users\malou\kru.exe");
        assert!(text_matches(
            r"Command: \\?\C:\Users\malou\kru.exe
Args: mcp stdio",
            executable
        ));
        assert!(text_matches(
            r#"{"command":"\\\\?\\C:\\Users\\malou\\kru.exe","args":["mcp","stdio"]}"#,
            executable
        ));
    }
}
