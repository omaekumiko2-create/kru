use crate::{
    browser::{BrowserBridge, current_totp},
    desktop,
    executor::{ApiRequestInput, execute_api, execute_ssh},
    model::NewActivity,
    terminal::TerminalManager,
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    service::{MaybeSendFuture, NotificationContext, RoleServer},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, RwLock},
    time::Instant,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct VaultMcp {
    vault: Vault,
    browser: BrowserBridge,
    terminal: TerminalManager,
    client_name: Arc<RwLock<String>>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for VaultMcp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("VaultMcp").finish_non_exhaustive()
    }
}

impl VaultMcp {
    pub fn new(vault: Vault) -> Self {
        Self {
            browser: BrowserBridge::new(vault.clone()),
            terminal: TerminalManager::new(),
            client_name: Arc::new(RwLock::new(String::new())),
            vault,
            tool_router: Self::tool_router(),
        }
    }

    fn activity_source(&self) -> String {
        let client_name = self
            .client_name
            .read()
            .map(|name| name.clone())
            .unwrap_or_default();
        if client_name.is_empty() {
            "MCP CLIENT".to_owned()
        } else {
            format!("MCP · {client_name}")
        }
    }

    async fn track<T, F>(&self, item_id: Uuid, action: String, future: F) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let started = Instant::now();
        let decrypted = self.vault.get_connection(item_id).ok();
        let item_name = decrypted
            .as_ref()
            .map(|connection| connection.stored.name.clone())
            .unwrap_or_else(|| "未知项目".to_owned());
        match future.await {
            Ok(value) => {
                let _ = self.vault.add_activity(NewActivity {
                    status: "success".to_owned(),
                    source: self.activity_source(),
                    connection_name: item_name,
                    action,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: String::new(),
                });
                Ok(value)
            }
            Err(error) => {
                let message = decrypted.as_ref().map_or_else(
                    || error.to_string(),
                    |connection| {
                        crate::policy::redact(
                            error.to_string(),
                            &connection.stored,
                            &connection.secrets,
                        )
                    },
                );
                let _ = self.vault.add_activity(NewActivity {
                    status: "error".to_owned(),
                    source: self.activity_source(),
                    connection_name: item_name,
                    action,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: message.clone(),
                });
                Err(message)
            }
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SshExecuteInput {
    #[schemars(
        description = "Item ID returned by vault_items_list for an item advertising the derived ssh_execute action."
    )]
    connection_id: String,
    #[schemars(description = "One command to execute.")]
    command: String,
    #[serde(default)]
    #[schemars(description = "Optional remote working directory.")]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ApiToolInput {
    #[schemars(
        description = "Item ID returned by vault_items_list for an item advertising the derived api_request action."
    )]
    connection_id: String,
    #[serde(flatten)]
    request: ApiRequestInput,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SecretFillInput {
    #[schemars(description = "Item ID returned by vault_items_list.")]
    item_id: String,
    #[schemars(description = "Secret field name returned by vault_items_list.")]
    field: String,
    #[schemars(
        description = "Write target: browser (paired extension; recommended for reliable browser automation), desktop (only when the real operating-system foreground focus is guaranteed), or terminal."
    )]
    target: String,
    #[serde(default)]
    #[schemars(
        description = "Required when target=terminal; use the session ID returned by terminal_open."
    )]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalOpenInput {
    #[schemars(
        description = "Program name or path selected by the agent. KRU starts it directly without a shell."
    )]
    program: String,
    #[serde(default)]
    #[schemars(description = "Arguments passed as individual argv values.")]
    args: Vec<String>,
    #[serde(default)]
    #[schemars(description = "Optional absolute working directory.")]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalSessionInput {
    #[schemars(description = "Session ID returned by terminal_open.")]
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalInputInput {
    #[schemars(description = "Session ID returned by terminal_open.")]
    session_id: String,
    #[schemars(
        description = "Ordinary terminal input. Append a newline when the agent intends to press Enter."
    )]
    text: String,
}

#[tool_router(router = tool_router)]
impl VaultMcp {
    #[tool(
        name = "vault_items_list",
        description = "KRU's credential-discovery entry point. Call this tool first when the user writes 'use <item name> in KRU MCP', mentions KRU, or requests a task involving stored credentials such as a login, password, API key or token, authentication, SSH or VPS access, a private key or passphrase, or TOTP/2FA. In the canonical use phrase, match only the text between 'use ' and ' in KRU MCP' as the item name. Prefer an exact item-name match, then choose secret_fill, ssh_execute, or api_request from the item's advertised actions. Secret plaintext is never returned unless the user explicitly made that module visible to the agent."
    )]
    async fn vault_items_list(&self) -> Result<String, String> {
        let items = self
            .vault
            .list_decrypted_connections()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|decrypted| {
                decrypted.stored.enabled
                    && !decrypted.stored.normalized_capabilities().is_empty()
            })
            .map(|decrypted| -> Result<serde_json::Value, String> {
                let item = decrypted.stored.public(Some(&decrypted.secrets));
                let modules = decrypted
                    .stored
                    .modules
                    .iter()
                    .map(|module| -> Result<serde_json::Value, String> {
                        let agent_visible = module.agent_visible();
                        let configured = if let Some(name) = module.secret_name() {
                            decrypted.secrets.get(name).is_some()
                        } else {
                            !module.value.trim().is_empty()
                        };
                        let mut output = json!({
                            "kind": module.kind,
                            "name": module.name,
                            "secret": module.is_secret(),
                            "configured": configured,
                            "agentVisible": agent_visible,
                        });
                        if agent_visible {
                            let mut value = if let Some(name) = module.secret_name() {
                                decrypted.secrets.get(name).unwrap_or_default().to_owned()
                            } else {
                                module.value.clone()
                            };
                            if module.kind == "totp" && !value.is_empty() {
                                value = current_totp(&value).map_err(|error| error.to_string())?;
                            }
                            output["value"] = json!(value);
                        }
                        Ok(output)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let fields = item
                    .secret
                    .as_ref()
                    .map(|profile| profile.fields.iter().map(|field| json!({
                        "name": field.name,
                        "type": field.kind,
                        "agentVisible": decrypted.stored.modules.iter().find(|module| module.secret_name() == Some(field.name.as_str())).is_some_and(|module| module.agent_visible()),
                    })).collect::<Vec<_>>())
                    .unwrap_or_default();
                let has_ssh = item.capabilities.iter().any(|value| value == "ssh");
                let has_http = item.capabilities.iter().any(|value| value == "http");
                let mut target = json!({});
                let mut actions = Vec::new();
                if item.capabilities.iter().any(|value| value == "fill") {
                    actions.push("secret_fill");
                }
                if has_ssh {
                    let mut ssh = json!({});
                    if decrypted.stored.modules.iter().find(|module| module.kind == "host").is_some_and(|module| module.agent_visible()) {
                        ssh["host"] = json!(item.host);
                    }
                    if decrypted.stored.modules.iter().find(|module| module.kind == "port").is_some_and(|module| module.agent_visible()) {
                        ssh["port"] = json!(item.port);
                    }
                    target["ssh"] = ssh;
                    actions.push("ssh_execute");
                }
                if has_http {
                    let url_visible = decrypted.stored.modules.iter().find(|module| module.kind == "url").is_some_and(|module| module.agent_visible());
                    let mut http = json!({"runtimeUrlRequired": item.base_url.is_empty(), "methods": item.allowed_methods, "pathPrefixes": item.allowed_path_prefixes});
                    if url_visible {
                        http["baseUrl"] = json!(item.base_url);
                    }
                    target["http"] = http;
                    actions.push("api_request");
                }
                Ok(json!({
                    "id": item.id,
                    "name": item.name,
                    "type": "item",
                    "capabilities": item.capabilities,
                    "modules": modules,
                    "description": item.description,
                    "fields": fields,
                    "target": target,
                    "actions": actions,
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string_pretty(&json!({"items": items})).map_err(|error| error.to_string())
    }

    #[tool(
        name = "secret_fill",
        description = "Use when a login page, authentication dialog, or CLI prompt needs a stored field such as a username, password, token, or TOTP/2FA code. KRU writes the field to the control already focused by the agent or to a specified KRU terminal without returning hidden plaintext. Call vault_items_list first to select the item and field. Prefer browser through the paired extension for reliable browser automation; use desktop only when the real operating-system foreground focus is guaranteed. KRU never submits automatically."
    )]
    async fn secret_fill(
        &self,
        Parameters(input): Parameters<SecretFillInput>,
    ) -> Result<String, String> {
        let item_id = Uuid::parse_str(&input.item_id).map_err(|_| "项目 ID 无效".to_owned())?;
        let target = match input.target.as_str() {
            "browser" | "desktop" | "terminal" => input.target,
            _ => return Err("target 必须是 browser、desktop 或 terminal".to_owned()),
        };
        let field = input.field;
        self.track(item_id, format!("向 {target} 填写字段 {field}"), async {
            let (_, kind, mut value) = self.vault.get_secret_value(item_id, &field)?;
            if kind == "totp" {
                value = current_totp(&value)?;
            }
            match target.as_str() {
                "browser" => {
                    let result = self.browser.fill_value(value).await?;
                    if result.status != "ok" {
                        bail!("{}", result.message);
                    }
                }
                "desktop" => {
                    tokio::task::spawn_blocking(move || desktop::fill_focused(&value))
                        .await
                        .context("桌面输入任务失败")??;
                }
                "terminal" => {
                    let session_id = input
                        .session_id
                        .as_deref()
                        .context("target=terminal 时必须提供 sessionId")?;
                    let session_id = Uuid::parse_str(session_id)
                        .map_err(|_| anyhow::anyhow!("终端会话 ID 无效"))?;
                    self.terminal.fill_value(session_id, &value)?;
                }
                _ => unreachable!(),
            }
            Ok(())
        })
        .await?;
        serde_json::to_string(&json!({"ok": true, "target": target, "field": field}))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "terminal_open",
        description = "Start a program directly in a KRU-managed local PTY. The agent chooses the program and argv; no shell is used."
    )]
    async fn terminal_open(
        &self,
        Parameters(input): Parameters<TerminalOpenInput>,
    ) -> Result<String, String> {
        let result = self
            .terminal
            .open(&input.program, input.args, input.cwd)
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    #[tool(
        name = "terminal_input",
        description = "Write ordinary text to a KRU-managed PTY. secret_fill never adds a newline, so the agent must send Enter separately when submission is required."
    )]
    async fn terminal_input(
        &self,
        Parameters(input): Parameters<TerminalInputInput>,
    ) -> Result<String, String> {
        let session_id =
            Uuid::parse_str(&input.session_id).map_err(|_| "终端会话 ID 无效".to_owned())?;
        self.terminal
            .input(session_id, &input.text)
            .map_err(|error| error.to_string())?;
        Ok("{\"ok\":true}".to_owned())
    }

    #[tool(
        name = "terminal_read",
        description = "Read PTY output produced since the previous call and the current process state. Values filled by KRU and common encodings of those values are redacted."
    )]
    async fn terminal_read(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
    ) -> Result<String, String> {
        let session_id =
            Uuid::parse_str(&input.session_id).map_err(|_| "终端会话 ID 无效".to_owned())?;
        let result = self
            .terminal
            .read(session_id)
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    #[tool(
        name = "terminal_close",
        description = "Close and clean up a KRU-managed PTY, terminating the program if it is still running."
    )]
    async fn terminal_close(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
    ) -> Result<String, String> {
        let session_id =
            Uuid::parse_str(&input.session_id).map_err(|_| "终端会话 ID 无效".to_owned())?;
        self.terminal
            .close(session_id)
            .map_err(|error| error.to_string())?;
        Ok("{\"ok\":true}".to_owned())
    }

    #[tool(
        name = "ssh_execute",
        description = "Use when the user asks to connect to, inspect, or operate an SSH host, Linux server, or VPS stored in KRU. Call vault_items_list first and choose an item advertising ssh_execute. KRU authenticates locally with its stored password or private key and runs the requested command. KRU has no observation, diagnostic, restricted, or execution mode; do not ask the user to change one. Authentication plaintext is never returned to the agent."
    )]
    async fn ssh_execute(
        &self,
        Parameters(input): Parameters<SshExecuteInput>,
    ) -> Result<String, String> {
        let connection_id =
            Uuid::parse_str(&input.connection_id).map_err(|_| "连接 ID 无效".to_owned())?;
        let connection = self
            .vault
            .get_connection(connection_id)
            .map_err(|error| error.to_string())?;
        if !connection.stored.has_capability("ssh") {
            return Err("所选项目的模块尚未形成可用 SSH 动作".to_owned());
        }
        let result = self
            .track(
                connection_id,
                "执行 SSH 命令".to_owned(),
                execute_ssh(
                    &self.vault,
                    &connection,
                    &input.command,
                    input.cwd.as_deref(),
                ),
            )
            .await?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    #[tool(
        name = "api_request",
        description = "Use when an API request requires an API key, token, bearer token, or other credential stored in KRU. Call vault_items_list first and choose an item advertising api_request. KRU injects authentication locally and sends the request without returning credential plaintext. A saved URL locks requests to the same origin. Without a saved URL, the caller must provide an absolute HTTPS URL; HTTP is allowed only for loopback addresses."
    )]
    async fn api_request(
        &self,
        Parameters(input): Parameters<ApiToolInput>,
    ) -> Result<String, String> {
        let connection_id =
            Uuid::parse_str(&input.connection_id).map_err(|_| "连接 ID 无效".to_owned())?;
        let connection = self
            .vault
            .get_connection(connection_id)
            .map_err(|error| error.to_string())?;
        if !connection.stored.has_capability("http") {
            return Err("所选项目的模块尚未形成可用 HTTP 动作".to_owned());
        }
        let action = format!("发送 {} API 请求", input.request.method.to_uppercase());
        let result = self
            .track(
                connection_id,
                action,
                execute_api(&connection, input.request),
            )
            .await?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for VaultMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "KRU is a non-agentic local credential execution tool; it does not plan tasks. Discovery rule: when the user writes 'use <name> in KRU MCP', treat only the text between 'use ' and ' in KRU MCP' as the item name, call vault_items_list immediately, and prefer an exact name match. When a task involves a login, password, username, API key or token, authentication, SSH or VPS access, a private key or passphrase, TOTP/2FA, or any other credential, call vault_items_list before asking the user to provide or paste a secret. After selecting an item, use its advertised actions to call secret_fill, ssh_execute, or api_request. KRU has no observation, diagnostic, restricted, or execution mode; when ssh_execute is advertised, send the command the task actually requires and never ask the user to change a mode. A module contains value only when the user has explicitly made it visible to the agent. If value is absent, do not request, guess, or attempt to retrieve plaintext; let KRU perform the final authentication action. For reliable browser automation, use target=browser with the paired extension. Use target=desktop only when the real operating-system foreground focus is guaranteed; background DOM focus is not foreground OS focus.",
        )
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + MaybeSendFuture + '_ {
        if let Some(info) = context.peer.peer_info() {
            let client_name = display_client_name(&info.client_info.name);
            if let Ok(mut stored_name) = self.client_name.write() {
                *stored_name = client_name;
            }
        }
        std::future::ready(())
    }
}

fn display_client_name(raw_name: &str) -> String {
    let normalized = raw_name.trim().to_ascii_lowercase();
    if normalized.contains("claude") {
        "CLAUDE CODE".to_owned()
    } else if normalized.contains("codex") {
        "CODEX".to_owned()
    } else if normalized.contains("cursor") {
        "CURSOR".to_owned()
    } else if normalized.contains("opencode") {
        "OPENCODE".to_owned()
    } else if normalized.contains("chatgpt") {
        "CHATGPT".to_owned()
    } else {
        raw_name
            .trim()
            .chars()
            .filter(|character| !character.is_control())
            .take(24)
            .collect::<String>()
            .to_uppercase()
    }
}

pub async fn serve_stdio(vault: Vault) -> Result<()> {
    let data_dir = vault.data_dir().to_path_buf();
    let launcher = launcher_executable()?;
    let build_id = crate::runtime_epoch::activate_build(&data_dir, &launcher)?;
    crate::runtime_epoch::exit_process_when_changed(data_dir, build_id)?;
    let server = VaultMcp::new(vault);
    let browser = server.browser.clone();
    browser.sync().await;
    let result = async {
        let service = server.serve(stdio()).await?;
        service.waiting().await?;
        Ok(())
    }
    .await;
    browser.stop().await;
    result
}

pub fn render_config(format: &str) -> Result<String> {
    let executable = launcher_executable()?;
    let executable = path_text(&executable);
    match format {
        "stdio-json" => Ok(serde_json::to_string_pretty(&json!({
            "mcpServers": {"kru": {"command": executable, "args": ["mcp", "stdio"]}}
        }))?),
        "stdio-toml" => Ok(format!(
            "[mcp_servers.kru]\ncommand = \"{}\"\nargs = [\"mcp\", \"stdio\"]",
            toml_escape(&executable)
        )),
        _ => bail!("未知配置格式：{format}"),
    }
}

pub fn launcher_executable() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(path) = validated_linux_launcher(
        std::env::var_os("KRU_LAUNCHER_PATH").map(std::path::PathBuf::from),
        std::env::var_os("APPIMAGE").map(std::path::PathBuf::from),
    ) {
        return Ok(path);
    }
    #[cfg(target_os = "linux")]
    if let Some(path) = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from)
        && path.is_absolute()
        && path.is_file()
    {
        return Ok(path);
    }
    let current = std::env::current_exe().context("无法确定 KRU 可执行文件路径")?;
    Ok(stable_launcher_executable(current))
}

fn stable_launcher_executable(current: std::path::PathBuf) -> std::path::PathBuf {
    let Some(parent) = current.parent() else {
        return current;
    };
    if !parent
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("deps"))
    {
        return current;
    }
    let Some(file_name) = current.file_name() else {
        return current;
    };
    let Some(release_dir) = parent.parent() else {
        return current;
    };
    let stable = release_dir.join(file_name);
    if stable.is_file() { stable } else { current }
}

#[cfg(target_os = "linux")]
fn validated_linux_launcher(
    candidate: Option<std::path::PathBuf>,
    appimage: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let candidate = candidate?;
    let appimage = appimage?;
    let metadata = candidate.metadata().ok()?;
    if !candidate.is_absolute()
        || !appimage.is_absolute()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || !appimage.is_file()
        || candidate.parent()?.canonicalize().ok()? != appimage.parent()?.canonicalize().ok()?
    {
        return None;
    }
    Some(candidate)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ConnectionInput, ItemModule, NamedSecrets, SecretBundle, SecretField, SecretProfile,
    };
    use tempfile::tempdir;

    #[test]
    fn development_binary_registers_the_stable_release_launcher() {
        let directory = tempdir().unwrap();
        let release = directory.path().join("release");
        let deps = release.join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        let stable = release.join(if cfg!(windows) { "kru.exe" } else { "kru" });
        let development = deps.join(if cfg!(windows) { "kru.exe" } else { "kru" });
        std::fs::write(&stable, "stable").unwrap();
        std::fs::write(&development, "development").unwrap();

        assert_eq!(stable_launcher_executable(development), stable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn portable_launcher_must_be_executable_and_beside_appimage() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let launcher = directory.path().join("kru");
        let appimage = directory.path().join("KRU.AppImage");
        std::fs::write(&launcher, "#!/bin/sh\n").unwrap();
        std::fs::write(&appimage, "appimage").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            validated_linux_launcher(Some(launcher.clone()), Some(appimage.clone())),
            Some(launcher.clone())
        );

        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            validated_linux_launcher(Some(launcher), Some(appimage)),
            None
        );
    }

    #[tokio::test]
    async fn item_list_only_exposes_values_enabled_by_user() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut named = NamedSecrets::default();
        named.insert("username".into(), "mcp-visible-user-marker".into());
        named.insert("password".into(), "mcp-hidden-password-marker".into());
        let mut secrets = SecretBundle::default();
        secrets.named_secrets = named;
        let saved = vault
            .save_connection(ConnectionInput {
                id: None,
                kind: "secret".into(),
                capabilities: vec!["fill".into()],
                modules: vec![
                    ItemModule {
                        kind: "username".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(true),
                    },
                    ItemModule {
                        kind: "password".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(false),
                    },
                    ItemModule {
                        kind: "host".into(),
                        name: String::new(),
                        value: "ssh.example.test".into(),
                        agent_visible: Some(true),
                    },
                    ItemModule {
                        kind: "port".into(),
                        name: String::new(),
                        value: "22".into(),
                        agent_visible: Some(true),
                    },
                ],
                name: "test login".into(),
                enabled: true,
                description: String::new(),
                host: String::new(),
                port: 0,
                username: String::new(),
                auth_type: String::new(),
                ssh_auth_type: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                host_fingerprint: String::new(),
                base_url: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: vec![],
                allowed_methods: vec![],
                allowed_path_prefixes: vec![],
                test_path: String::new(),
                cli: None,
                browser: None,
                credential: None,
                secret: Some(SecretProfile {
                    fields: vec![
                        SecretField {
                            name: "username".into(),
                            kind: "text".into(),
                        },
                        SecretField {
                            name: "password".into(),
                            kind: "text".into(),
                        },
                    ],
                }),
                remove_secret_names: vec![],
                secrets,
            })
            .unwrap();

        let output = VaultMcp::new(vault.clone())
            .vault_items_list()
            .await
            .unwrap();
        assert!(output.contains("username"));
        assert!(output.contains("password"));
        let listed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(listed["items"][0]["type"], "item");
        assert_eq!(listed["items"][0]["capabilities"], json!(["fill", "ssh"]));
        assert_eq!(
            listed["items"][0]["target"]["ssh"]["host"],
            "ssh.example.test"
        );
        assert_eq!(listed["items"][0]["target"]["ssh"]["port"], 22);
        assert!(listed["items"][0]["target"]["ssh"].get("mode").is_none());
        assert!(
            listed["items"][0]["target"]["ssh"]
                .get("allowedCommands")
                .is_none()
        );
        assert!(output.contains("mcp-visible-user-marker"));
        assert!(!output.contains("mcp-hidden-password-marker"));

        vault.set_connection_enabled(saved.id, false).unwrap();
        let hidden = VaultMcp::new(vault).vault_items_list().await.unwrap();
        assert!(!hidden.contains("test login"));
        assert!(!hidden.contains("username"));
        assert!(!hidden.contains("password"));
    }
}
