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
const STATUS_CLI_TIMEOUT: Duration = Duration::from_secs(3);
const ACTION_CLI_TIMEOUT: Duration = Duration::from_secs(20);
const KRU_INSTRUCTION_START: &str = "<!-- KRU MANAGED INSTRUCTION START -->";
const KRU_INSTRUCTION_END: &str = "<!-- KRU MANAGED INSTRUCTION END -->";
const KRU_INSTRUCTION_BLOCK: &str = r#"<!-- KRU MANAGED INSTRUCTION START -->
When a user asks to log in, connect to SSH, a VPS, or a server, call an authenticated API, or use any credential, check KRU first. Call `vault_items_list` before asking the user for credentials; if a matching item exists, use its advertised KRU action. Never ask KRU to reveal hidden secret plaintext. KRU has no observation, diagnostic, restricted, or execution mode; when `ssh_execute` is advertised, send the command the task actually requires and never ask the user to change a mode.
<!-- KRU MANAGED INSTRUCTION END -->"#;

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
    codex_home: PathBuf,
    opencode_config: PathBuf,
    opencode_config_explicit: bool,
    opencode_instruction_dir: PathBuf,
    openclaw_config: PathBuf,
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
        let codex_home = resolve_codex_home(&home, env::var_os("CODEX_HOME").map(PathBuf::from));
        let opencode_config_directory = env_path("OPENCODE_CONFIG_DIR");
        let xdg_config_home = env_path("XDG_CONFIG_HOME");
        let (opencode_config, opencode_config_explicit) = resolve_opencode_config(
            &home,
            env_path("OPENCODE_CONFIG"),
            opencode_config_directory.clone(),
            xdg_config_home.clone(),
        );
        let opencode_instruction_dir = opencode_config_directory.unwrap_or_else(|| {
            xdg_config_home
                .unwrap_or_else(|| home.join(".config"))
                .join("opencode")
        });
        let openclaw_config = resolve_openclaw_config(&home, env_path("OPENCLAW_CONFIG_PATH"));
        Ok(Self {
            executable: normalize_path(executable),
            home,
            codex_home,
            opencode_config,
            opencode_config_explicit,
            opencode_instruction_dir,
            openclaw_config,
            path_dirs,
            app_data,
            local_app_data,
        })
    }

    #[cfg(test)]
    fn isolated(executable: PathBuf, home: PathBuf, path_dirs: Vec<PathBuf>) -> Self {
        let (opencode_config, opencode_config_explicit) =
            resolve_opencode_config(&home, None, None, None);
        Self {
            executable: normalize_path(executable),
            app_data: home.join("AppData").join("Roaming"),
            local_app_data: home.join("AppData").join("Local"),
            codex_home: home.join(".codex"),
            opencode_config,
            opencode_config_explicit,
            opencode_instruction_dir: home.join(".config").join("opencode"),
            openclaw_config: resolve_openclaw_config(&home, None),
            home,
            path_dirs,
        }
    }

    pub async fn list(&self) -> Vec<AgentClientStatus> {
        // CLI-backed clients may need to start a Node process. Scan every client
        // concurrently so a slow or broken CLI cannot serially stall the settings page.
        let (codex, claude, cursor, opencode, openclaw) = tokio::join!(
            self.status(CLIENT_IDS[0]),
            self.status(CLIENT_IDS[1]),
            self.status(CLIENT_IDS[2]),
            self.status(CLIENT_IDS[3]),
            self.status(CLIENT_IDS[4]),
        );
        vec![codex, claude, cursor, opencode, openclaw]
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

        let result = if action == "remove" {
            self.mutate_global_instruction(client_id, action)
        } else {
            Ok(())
        };
        let result = match result {
            Ok(()) => self.mutate_mcp_client(client_id, action).await,
            Err(error) => Err(error),
        };
        let result = if result.is_ok() && action != "remove" {
            self.mutate_global_instruction(client_id, action)
        } else {
            result
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

    async fn mutate_mcp_client(&self, client_id: &str, action: &str) -> Result<()> {
        match client_id {
            "codex" => self.mutate_codex(action),
            "cursor" | "opencode" => self.mutate_json_client(client_id, action),
            "claude-code" | "openclaw" => self.mutate_cli_client(client_id, action).await,
            _ => unreachable!(),
        }
    }

    async fn status(&self, client_id: &str) -> AgentClientStatus {
        let display_name = display_name(client_id).to_owned();
        let config_path = self.config_path(client_id);
        let executable = self.find_client_executable(client_id);
        let detected = config_path.is_file()
            || executable.is_some()
            || self.desktop_install_exists(client_id)
            || (client_id == "opencode" && self.opencode_config_target_exists());
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
            Ok(EntryState::Registered) if supports_managed_instruction(client_id) => {
                match self.inspect_global_instruction(client_id) {
                    Ok(InstructionState::Current) => {
                        apply_entry_state(&mut status, EntryState::Registered)
                    }
                    Ok(InstructionState::Missing) => {
                        apply_entry_state(&mut status, EntryState::Stale)
                    }
                    Ok(InstructionState::Conflict) => {
                        apply_entry_state(&mut status, EntryState::Conflict)
                    }
                    Err(error) => {
                        status.state = "error".to_owned();
                        status.can_register = false;
                        status.message = error.to_string();
                    }
                }
            }
            Ok(entry) => apply_entry_state(&mut status, entry),
            Err(error) => {
                status.state = "error".to_owned();
                status.can_register = false;
                status.message = error.to_string();
            }
        }
        if app_translocated(&self.executable) {
            status.state = "pathChanged".to_owned();
            status.can_register = false;
            status.can_repair = false;
            status.message =
                "macOS 正在从临时隔离路径运行 KRU；请先将 KRU.app 移到 Applications 后再连接"
                    .to_owned();
        }
        status
    }

    fn inspect_global_instruction(&self, client_id: &str) -> Result<InstructionState> {
        let path = self.active_instruction_path(client_id)?;
        if !path.is_file() {
            return Ok(InstructionState::Missing);
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("无法读取 Agent 全局规则 {}", path.display()))?;
        if text.contains(KRU_INSTRUCTION_BLOCK) {
            return Ok(InstructionState::Current);
        }
        if client_id == "claude-code"
            && !text.trim().is_empty()
            && !text.contains(KRU_INSTRUCTION_START)
        {
            return Ok(InstructionState::Conflict);
        }
        Ok(InstructionState::Missing)
    }

    fn mutate_global_instruction(&self, client_id: &str, action: &str) -> Result<()> {
        if !supports_managed_instruction(client_id) {
            return Ok(());
        }
        if action == "remove" {
            for path in self.instruction_paths(client_id)? {
                remove_managed_instruction(&path, client_id == "claude-code")?;
            }
            return Ok(());
        }

        let path = self.active_instruction_path(client_id)?;
        upsert_managed_instruction(&path, client_id == "claude-code")
    }

    fn active_instruction_path(&self, client_id: &str) -> Result<PathBuf> {
        match client_id {
            "codex" => {
                let override_path = self.codex_home.join("AGENTS.override.md");
                let override_text = read_or(&override_path, "")?;
                if override_text.trim().is_empty() {
                    Ok(self.codex_home.join("AGENTS.md"))
                } else {
                    Ok(override_path)
                }
            }
            "claude-code" => Ok(self.home.join(".claude").join("rules").join("kru.md")),
            "opencode" => Ok(self.opencode_instruction_dir.join("AGENTS.md")),
            _ => bail!("该 Agent 没有可安全维护的全局规则入口"),
        }
    }

    fn instruction_paths(&self, client_id: &str) -> Result<Vec<PathBuf>> {
        if client_id == "codex" {
            return Ok(vec![
                self.codex_home.join("AGENTS.md"),
                self.codex_home.join("AGENTS.override.md"),
            ]);
        }
        Ok(vec![self.active_instruction_path(client_id)?])
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
        if client_id == "cursor" {
            let Some(entry) = document.pointer("/mcpServers/kru") else {
                return Ok(EntryState::Available);
            };
            let command = entry
                .get("command")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_owned();
            let args = json_array_strings(entry.get("args"));
            return Ok(classify_command(&command, &args, &self.executable));
        }

        let current = document.pointer("/mcp/servers/kru");
        let legacy = document.pointer("/mcp/kru");
        let classify = |entry: &JsonValue| {
            let command = json_array_strings(entry.get("command"));
            (
                command.first().cloned().unwrap_or_default(),
                command.iter().skip(1).cloned().collect::<Vec<_>>(),
            )
        };
        match (current, legacy) {
            (None, None) => Ok(EntryState::Available),
            (Some(entry), None) => {
                let (command, args) = classify(entry);
                Ok(classify_command(&command, &args, &self.executable))
            }
            (None, Some(entry)) => {
                let (command, args) = classify(entry);
                let state = classify_command(&command, &args, &self.executable);
                Ok(
                    if state == EntryState::Registered
                        && entry.get("enabled").and_then(JsonValue::as_bool) == Some(false)
                    {
                        EntryState::Stale
                    } else {
                        state
                    },
                )
            }
            (Some(current), Some(legacy)) => {
                let (current_command, current_args) = classify(current);
                let (legacy_command, legacy_args) = classify(legacy);
                let current_state =
                    classify_command(&current_command, &current_args, &self.executable);
                let legacy_state =
                    classify_command(&legacy_command, &legacy_args, &self.executable);
                Ok(
                    if current_state == EntryState::Conflict || legacy_state == EntryState::Conflict
                    {
                        EntryState::Conflict
                    } else {
                        EntryState::Stale
                    },
                )
            }
        }
    }

    async fn inspect_cli_client(&self, client_id: &str, executable: &Path) -> Result<EntryState> {
        let args = if client_id == "claude-code" {
            vec!["mcp", "get", "kru"]
        } else {
            vec!["mcp", "show", "kru", "--json"]
        };
        let output = self.run_cli_status(executable, &args).await?;
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
        if client_id == "cursor" {
            if action == "remove" {
                if let Some(container) = root_object.object_value("mcpServers") {
                    if let Some(entry) = container.get("kru") {
                        entry.remove();
                    }
                }
            } else {
                if action == "repair" && path.is_file() {
                    backup_config(&path)?;
                }
                let container = root_object.object_value_or_set("mcpServers");
                let entry = CstInputValue::Object(vec![
                    (
                        "command".to_owned(),
                        self.executable.to_string_lossy().into_owned().into(),
                    ),
                    ("args".to_owned(), vec!["mcp", "stdio"].into()),
                ]);
                if let Some(current) = container.get("kru") {
                    current.set_value(entry);
                } else {
                    container.append("kru", entry);
                }
            }
        } else {
            let mcp = root_object.object_value_or_set("mcp");
            // OpenCode's widely deployed configuration uses `mcp.<name>`, while
            // V2 uses `mcp.servers.<name>`. An existing `servers` object is an
            // unambiguous V2 signal; otherwise keep/default to the V1 shape.
            let use_v2 = mcp.object_value("servers").is_some();
            if action == "remove" {
                if let Some(servers) = mcp.object_value("servers") {
                    if let Some(entry) = servers.get("kru") {
                        entry.remove();
                    }
                }
                if let Some(legacy) = mcp.get("kru") {
                    legacy.remove();
                }
            } else {
                if action == "repair" && path.is_file() {
                    backup_config(&path)?;
                }
                let mut fields = vec![
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
                ];
                if use_v2 {
                    if let Some(legacy) = mcp.get("kru") {
                        legacy.remove();
                    }
                    let servers = mcp.object_value_or_set("servers");
                    let entry = CstInputValue::Object(fields);
                    if let Some(current) = servers.get("kru") {
                        current.set_value(entry);
                    } else {
                        servers.append("kru", entry);
                    }
                } else {
                    fields.push(("enabled".to_owned(), true.into()));
                    let entry = CstInputValue::Object(fields);
                    if let Some(current) = mcp.get("kru") {
                        current.set_value(entry);
                    } else {
                        mcp.append("kru", entry);
                    }
                }
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
            let output = self.run_cli_action(&executable, &args).await?;
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
        let output = self.run_cli_action(&executable, &refs).await?;
        if !output.status.success() {
            bail!("{}", clean_process_error(&output_text(&output)));
        }
        Ok(())
    }

    async fn run_cli_status(&self, executable: &Path, args: &[&str]) -> Result<Output> {
        self.run_cli(
            executable,
            args,
            STATUS_CLI_TIMEOUT,
            "Agent CLI 状态检查超时",
        )
        .await
    }

    async fn run_cli_action(&self, executable: &Path, args: &[&str]) -> Result<Output> {
        self.run_cli(executable, args, ACTION_CLI_TIMEOUT, "Agent CLI 操作超时")
            .await
    }

    async fn run_cli(
        &self,
        executable: &Path,
        args: &[&str],
        deadline: Duration,
        timeout_message: &str,
    ) -> Result<Output> {
        let (program, prefix) = self.resolve_program(executable)?;
        let mut command = Command::new(program);
        command.args(prefix).args(args).kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        timeout(deadline, command.output())
            .await
            .with_context(|| timeout_message.to_owned())?
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
        Ok((node, vec![node_script_argument_path(&target)]))
    }

    fn config_path(&self, client_id: &str) -> PathBuf {
        match client_id {
            "codex" => self.codex_home.join("config.toml"),
            "claude-code" => self.home.join(".claude.json"),
            "cursor" => self.home.join(".cursor").join("mcp.json"),
            "opencode" => self.opencode_config_path(),
            "openclaw" => self.openclaw_config.clone(),
            _ => self.home.join(".kru").join("unsupported"),
        }
    }

    fn opencode_config_path(&self) -> PathBuf {
        if !self.opencode_config_explicit
            && self.opencode_config.file_name().is_some_and(|name| {
                name.eq_ignore_ascii_case("opencode.jsonc") && !self.opencode_config.is_file()
            })
            && let Some(directory) = self.opencode_config.parent()
        {
            return preferred_json_config(directory);
        }
        self.opencode_config.clone()
    }

    fn opencode_config_target_exists(&self) -> bool {
        self.opencode_config_explicit
            || self
                .opencode_config
                .parent()
                .is_some_and(|directory| directory.is_dir())
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
            self.home.join("bin"),
            self.home.join(".bun").join("bin"),
            self.home.join(".volta").join("bin"),
            self.home.join(".local").join("share").join("pnpm"),
            self.home.join(".codex").join("bin"),
            self.home.join(".opencode").join("bin"),
            self.home.join(".openclaw").join("bin"),
            self.app_data.join("npm"),
            self.local_app_data.join("pnpm"),
        ];
        for variable in ["PNPM_HOME", "VOLTA_HOME", "BUN_INSTALL"] {
            if let Some(directory) = env_path(variable) {
                directories.push(if variable == "PNPM_HOME" {
                    directory
                } else {
                    directory.join("bin")
                });
            }
        }
        if cfg!(target_os = "macos") {
            directories.extend([
                self.home.join("Library").join("pnpm"),
                self.home.join(".npm-global").join("bin"),
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/bin"),
            ]);
        } else if !cfg!(windows) {
            directories.extend([
                self.home.join(".npm-global").join("bin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/bin"),
            ]);
        }
        directories.extend(self.path_dirs.iter().cloned());
        directories.dedup();
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
                if let Some(found) = candidates.into_iter().find(|path| is_runnable_file(path)) {
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
            ("opencode", "windows") => vec![
                self.local_app_data
                    .join("Programs")
                    .join("OpenCode")
                    .join("OpenCode.exe"),
                self.local_app_data
                    .join("Programs")
                    .join("opencode")
                    .join("OpenCode.exe"),
            ],
            ("codex", "macos") => vec![
                PathBuf::from("/Applications/Codex.app"),
                self.home.join("Applications/Codex.app"),
            ],
            ("cursor", "macos") => vec![
                PathBuf::from("/Applications/Cursor.app"),
                self.home.join("Applications/Cursor.app"),
            ],
            ("opencode", "macos") => vec![
                PathBuf::from("/Applications/OpenCode.app"),
                self.home.join("Applications/OpenCode.app"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstructionState {
    Current,
    Missing,
    Conflict,
}

fn supports_managed_instruction(client_id: &str) -> bool {
    matches!(client_id, "codex" | "claude-code" | "opencode")
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
            status.message = "KRU 路径、参数或全局规则需要更新".to_owned();
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

fn node_script_argument_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        let path = path.to_string_lossy();
        if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{path}")
        } else {
            path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
        }
    }
    #[cfg(not(windows))]
    {
        path.to_string_lossy().into_owned()
    }
}

fn is_runnable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0);
    }
    #[cfg(not(unix))]
    true
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn resolve_codex_home(home: &Path, configured: Option<PathBuf>) -> PathBuf {
    configured
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".codex"))
}

fn resolve_opencode_config(
    home: &Path,
    configured_file: Option<PathBuf>,
    configured_directory: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
) -> (PathBuf, bool) {
    if let Some(path) = configured_file.filter(|path| !path.as_os_str().is_empty()) {
        return (path, true);
    }
    if let Some(directory) = configured_directory.filter(|path| !path.as_os_str().is_empty()) {
        return (preferred_json_config(&directory), true);
    }
    let base = xdg_config_home
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".config"));
    (preferred_json_config(&base.join("opencode")), false)
}

fn preferred_json_config(directory: &Path) -> PathBuf {
    let jsonc = directory.join("opencode.jsonc");
    if jsonc.is_file() {
        return jsonc;
    }
    let json = directory.join("opencode.json");
    if json.is_file() { json } else { jsonc }
}

fn resolve_openclaw_config(home: &Path, configured: Option<PathBuf>) -> PathBuf {
    configured
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".openclaw").join("openclaw.json"))
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

fn upsert_managed_instruction(path: &Path, dedicated_file: bool) -> Result<()> {
    let original = read_or(path, "")?;
    if dedicated_file && !original.trim().is_empty() && !original.contains(KRU_INSTRUCTION_START) {
        bail!("{} 已存在且不是 KRU 托管规则，未进行覆盖", path.display());
    }
    let mut updated = strip_managed_instruction(&original)?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(KRU_INSTRUCTION_BLOCK);
    updated.push('\n');
    write_atomic_checked(path, &original, &updated)
}

fn remove_managed_instruction(path: &Path, dedicated_file: bool) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let original = fs::read_to_string(path)
        .with_context(|| format!("无法读取 Agent 全局规则 {}", path.display()))?;
    if !original.contains(KRU_INSTRUCTION_START) {
        return Ok(());
    }
    let updated = strip_managed_instruction(&original)?;
    if dedicated_file && updated.trim().is_empty() {
        fs::remove_file(path)
            .with_context(|| format!("无法移除 KRU 全局规则 {}", path.display()))?;
        return Ok(());
    }
    write_atomic_checked(path, &original, &updated)
}

fn strip_managed_instruction(text: &str) -> Result<String> {
    let Some(start) = text.find(KRU_INSTRUCTION_START) else {
        if text.contains(KRU_INSTRUCTION_END) {
            bail!("Agent 全局规则中的 KRU 托管标记不完整");
        }
        return Ok(text.to_owned());
    };
    let content_start = start + KRU_INSTRUCTION_START.len();
    let end_offset = text[content_start..]
        .find(KRU_INSTRUCTION_END)
        .context("Agent 全局规则中的 KRU 托管标记不完整")?;
    let end = content_start + end_offset + KRU_INSTRUCTION_END.len();
    let mut before = text[..start].trim_end_matches(['\r', '\n']).to_owned();
    let after = text[end..].trim_start_matches(['\r', '\n']);
    if !before.is_empty() && !after.is_empty() {
        before.push_str("\n\n");
    }
    before.push_str(after);
    if !before.is_empty() && text.ends_with('\n') && !before.ends_with('\n') {
        before.push('\n');
    }
    Ok(before)
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

#[cfg(target_os = "macos")]
fn app_translocated(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("AppTranslocation")
    })
}

#[cfg(not(target_os = "macos"))]
fn app_translocated(_path: &Path) -> bool {
    false
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

    fn make_test_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
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
        let instruction = fs::read_to_string(registry.codex_home.join("AGENTS.md")).unwrap();
        assert!(instruction.contains(KRU_INSTRUCTION_BLOCK));
        let second = registry.mutate("codex", "register").await;
        assert!(!second.ok);
        assert_eq!(once, fs::read_to_string(&path).unwrap());
    }

    #[tokio::test]
    async fn codex_instruction_uses_override_and_removal_preserves_user_content() {
        let (_temp, registry) = registry();
        let config = registry.config_path("codex");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, "model = \"gpt-test\"\n").unwrap();
        let override_path = registry.codex_home.join("AGENTS.override.md");
        fs::write(&override_path, "# Personal rules\n").unwrap();

        assert!(registry.mutate("codex", "register").await.ok);
        let installed = fs::read_to_string(&override_path).unwrap();
        assert!(installed.starts_with("# Personal rules\n"));
        assert!(installed.contains(KRU_INSTRUCTION_BLOCK));
        assert!(!registry.codex_home.join("AGENTS.md").exists());

        assert!(registry.mutate("codex", "remove").await.ok);
        assert_eq!(
            fs::read_to_string(&override_path).unwrap(),
            "# Personal rules\n"
        );
    }

    #[tokio::test]
    async fn existing_codex_connection_without_global_rule_requires_repair() {
        let (_temp, registry) = registry();
        registry.mutate_codex("register").unwrap();

        let before = registry.status("codex").await;
        assert_eq!(before.state, "stale");
        assert!(before.can_repair);

        assert!(registry.mutate("codex", "repair").await.ok);
        assert_eq!(registry.status("codex").await.state, "registered");
        assert!(registry.codex_home.join("AGENTS.md").is_file());
    }

    #[test]
    fn dedicated_rule_never_overwrites_an_unmanaged_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("kru.md");
        fs::write(&path, "user-owned rule\n").unwrap();

        let error = upsert_managed_instruction(&path, true).unwrap_err();
        assert!(error.to_string().contains("不是 KRU 托管规则"));
        assert_eq!(fs::read_to_string(path).unwrap(), "user-owned rule\n");
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
    async fn opencode_registration_defaults_to_v1_and_preserves_jsonc() {
        let (_temp, registry) = registry();
        let path = registry.config_path("opencode");
        assert_eq!(path.file_name().unwrap(), "opencode.jsonc");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "{\n  // keep this comment\n  \"theme\": \"dark\",\n  \"mcp\": {}\n}\n",
        )
        .unwrap();
        assert!(registry.mutate("opencode", "register").await.ok);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("// keep this comment"));
        assert!(text.contains("\"theme\": \"dark\""));
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert_eq!(
            value.pointer("/mcp/kru/type"),
            Some(&serde_json::json!("local"))
        );
        let command = value
            .pointer("/mcp/kru/command")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(command[1], "mcp");
        assert_eq!(command[2], "stdio");
        assert_eq!(
            value.pointer("/mcp/kru/enabled"),
            Some(&serde_json::json!(true))
        );
        assert!(value.pointer("/mcp/servers").is_none());
        assert!(
            fs::read_to_string(registry.opencode_instruction_dir.join("AGENTS.md"))
                .unwrap()
                .contains(KRU_INSTRUCTION_BLOCK)
        );
        assert_eq!(registry.status("opencode").await.state, "registered");
    }

    #[tokio::test]
    async fn opencode_registration_uses_v2_when_servers_container_exists() {
        let (_temp, registry) = registry();
        let path = registry.config_path("opencode");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "{\n  // V2 config\n  \"mcp\": { \"servers\": {} }\n}\n",
        )
        .unwrap();
        assert!(registry.mutate("opencode", "register").await.ok);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("// V2 config"));
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert!(value.pointer("/mcp/kru").is_none());
        assert!(value.pointer("/mcp/servers/kru").is_some());
        assert!(value.pointer("/mcp/servers/kru/enabled").is_none());
        assert_eq!(registry.status("opencode").await.state, "registered");
    }

    #[tokio::test]
    async fn opencode_repair_keeps_v1_shape_and_reenables_entry() {
        let (_temp, registry) = registry();
        let path = registry.config_path("opencode");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let executable = serde_json::to_string(&registry.executable.to_string_lossy()).unwrap();
        fs::write(
            &path,
            format!(
                "{{\n  // V1 setting stays readable\n  \"mcp\": {{\n    \"kru\": {{ \"type\": \"local\", \"command\": [{executable}, \"mcp\", \"stdio\"], \"enabled\": false }}\n  }}\n}}\n"
            ),
        )
        .unwrap();

        let status = registry.status("opencode").await;
        assert_eq!(status.state, "stale");
        assert!(status.can_repair);
        assert!(registry.mutate("opencode", "repair").await.ok);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("// V1 setting stays readable"));
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert_eq!(
            value.pointer("/mcp/kru/enabled"),
            Some(&serde_json::json!(true))
        );
        assert!(value.pointer("/mcp/servers").is_none());
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().any(|item| {
            item.unwrap()
                .file_name()
                .to_string_lossy()
                .contains("opencode.jsonc.kru.")
        }));
    }

    #[tokio::test]
    async fn opencode_remove_cleans_current_and_legacy_entries() {
        let (_temp, registry) = registry();
        let path = registry.config_path("opencode");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let executable = serde_json::to_string(&registry.executable.to_string_lossy()).unwrap();
        fs::write(
            &path,
            format!(
                "{{ \"mcp\": {{ \"kru\": {{ \"command\": [{executable}, \"mcp\", \"stdio\"] }}, \"servers\": {{ \"kru\": {{ \"command\": [{executable}, \"mcp\", \"stdio\"] }} }} }} }}\n"
            ),
        )
        .unwrap();

        assert_eq!(registry.status("opencode").await.state, "stale");
        assert!(registry.mutate("opencode", "remove").await.ok);
        let text = fs::read_to_string(&path).unwrap();
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert!(value.pointer("/mcp/kru").is_none());
        assert!(value.pointer("/mcp/servers/kru").is_none());
    }

    #[tokio::test]
    async fn opencode_uses_existing_json_file_when_jsonc_is_absent() {
        let (_temp, registry) = registry();
        let directory = registry.home.join(".config").join("opencode");
        fs::create_dir_all(&directory).unwrap();
        let json = directory.join("opencode.json");
        fs::write(&json, "{}\n").unwrap();

        assert_eq!(registry.config_path("opencode"), json);
        assert!(registry.mutate("opencode", "register").await.ok);
        let value: JsonValue = serde_json::from_str(&fs::read_to_string(json).unwrap()).unwrap();
        assert!(value.pointer("/mcp/kru").is_some());
    }

    #[test]
    fn codex_config_path_uses_configured_codex_home() {
        let (temp, mut registry) = registry();
        let codex_home = temp.path().join("portable-codex-home");
        assert_eq!(
            resolve_codex_home(temp.path(), Some(codex_home.clone())),
            codex_home
        );
        registry.codex_home = codex_home.clone();
        assert_eq!(
            registry.config_path("codex"),
            codex_home.join("config.toml")
        );
    }

    #[test]
    fn config_overrides_and_xdg_paths_are_respected() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let exact = temp.path().join("custom").join("open.jsonc");
        let directory = temp.path().join("opencode-dir");
        let xdg = temp.path().join("xdg");

        let resolved = resolve_opencode_config(
            &home,
            Some(exact.clone()),
            Some(directory.clone()),
            Some(xdg.clone()),
        );
        assert_eq!(resolved, (exact, true));

        let resolved =
            resolve_opencode_config(&home, None, Some(directory.clone()), Some(xdg.clone()));
        assert_eq!(resolved, (directory.join("opencode.jsonc"), true));

        let resolved = resolve_opencode_config(&home, None, None, Some(xdg.clone()));
        assert_eq!(resolved, (xdg.join("opencode/opencode.jsonc"), false));

        let openclaw = temp.path().join("openclaw-custom.json5");
        assert_eq!(
            resolve_openclaw_config(&home, Some(openclaw.clone())),
            openclaw
        );
    }

    #[test]
    fn explicit_opencode_jsonc_path_is_not_replaced_by_a_sibling_json_file() {
        let (temp, mut registry) = registry();
        let directory = temp.path().join("explicit-opencode");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("opencode.json"), "{}\n").unwrap();
        let explicit = directory.join("opencode.jsonc");
        registry.opencode_config = explicit.clone();
        registry.opencode_config_explicit = true;

        assert_eq!(registry.config_path("opencode"), explicit);
    }

    #[tokio::test]
    async fn opencode_explicit_or_existing_config_directory_allows_desktop_registration() {
        let (temp, mut registry) = registry();
        registry.opencode_config = temp.path().join("explicit").join("opencode.jsonc");
        registry.opencode_config_explicit = true;
        let explicit = registry.status("opencode").await;
        assert!(explicit.detected);
        assert!(explicit.can_register);
        assert_eq!(explicit.state, "available");

        registry.opencode_config_explicit = false;
        assert!(!registry.status("opencode").await.detected);
        fs::create_dir_all(registry.opencode_config.parent().unwrap()).unwrap();
        let desktop = registry.status("opencode").await;
        assert!(desktop.detected);
        assert!(desktop.can_register);
    }

    #[test]
    fn common_user_bin_directories_are_scanned_by_exact_name() {
        let (temp, registry) = registry();
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let opencode = temp
            .path()
            .join(".opencode/bin")
            .join(format!("opencode{suffix}"));
        fs::create_dir_all(opencode.parent().unwrap()).unwrap();
        fs::write(&opencode, b"test").unwrap();
        make_test_executable(&opencode);
        assert_eq!(
            registry.find_client_executable("opencode"),
            Some(normalize_path(&opencode))
        );

        let openclaw = temp
            .path()
            .join(".openclaw/bin")
            .join(format!("openclaw{suffix}"));
        fs::create_dir_all(openclaw.parent().unwrap()).unwrap();
        fs::write(&openclaw, b"test").unwrap();
        make_test_executable(&openclaw);
        assert_eq!(
            registry.find_client_executable("openclaw"),
            Some(normalize_path(&openclaw))
        );

        let unrelated = temp.path().join("bin/opencode-helper.exe");
        fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
        fs::write(unrelated, b"test").unwrap();
        fs::remove_file(opencode).unwrap();
        assert!(registry.find_client_executable("opencode").is_none());
    }

    #[tokio::test]
    async fn list_preserves_stable_client_order() {
        let (_temp, registry) = registry();
        let ids = registry
            .list()
            .await
            .into_iter()
            .map(|status| status.client_id)
            .collect::<Vec<_>>();
        assert_eq!(ids, CLIENT_IDS);
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

    #[cfg(windows)]
    #[test]
    fn node_argv_uses_an_ordinary_windows_path() {
        assert_eq!(
            node_script_argument_path(Path::new(r"\\?\C:\Users\test\node_modules\cli.js")),
            r"C:\Users\test\node_modules\cli.js"
        );
        assert_eq!(
            node_script_argument_path(Path::new(r"\\?\UNC\server\share\cli.js")),
            r"\\server\share\cli.js"
        );
    }
}
