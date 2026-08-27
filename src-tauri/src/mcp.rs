use crate::{
    browser::{BrowserBridge, current_totp},
    desktop,
    executor::{
        ApiRequestInput, ApiResponse, SshResponse, describe_api_request, execute_api, execute_ssh,
    },
    model::NewActivity,
    terminal::{TerminalManager, TerminalOpenResult, TerminalReadResult},
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo},
    service::{MaybeSendFuture, NotificationContext, RoleServer},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
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
        let action = decrypted.as_ref().map_or(action.clone(), |connection| {
            crate::policy::redact(action, &connection.stored, &connection.secrets)
        });
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

    fn search_items(&self, input: ItemsSearchInput) -> Result<ItemsSearchOutput, String> {
        let query = input
            .query
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let normalized_query = query.as_ref().map(|value| value.to_lowercase());
        let mut connections = self
            .vault
            .list_decrypted_connections()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|decrypted| {
                decrypted.stored.enabled && !decrypted.stored.normalized_capabilities().is_empty()
            })
            .collect::<Vec<_>>();

        if let Some(normalized_query) = normalized_query.as_deref() {
            let has_exact = connections
                .iter()
                .any(|item| item.stored.name.trim().to_lowercase() == normalized_query);
            connections.retain(|item| {
                let name = item.stored.name.trim().to_lowercase();
                if has_exact {
                    name == normalized_query
                } else {
                    name.contains(normalized_query)
                }
            });
        }

        let items = connections
            .into_iter()
            .map(|decrypted| -> Result<ItemOutput, String> {
                let modules = decrypted
                    .stored
                    .modules
                    .iter()
                    .map(|module| -> Result<ItemModuleOutput, String> {
                        let agent_visible = module.agent_visible();
                        let configured = if let Some(name) = module.secret_name() {
                            decrypted.secrets.get(name).is_some()
                        } else {
                            !module.value.trim().is_empty()
                        };
                        let value = if agent_visible {
                            let mut value = if let Some(name) = module.secret_name() {
                                decrypted.secrets.get(name).unwrap_or_default().to_owned()
                            } else {
                                module.value.clone()
                            };
                            if module.kind == "totp" && !value.is_empty() {
                                value = current_totp(&value).map_err(|error| error.to_string())?;
                            }
                            Some(value)
                        } else {
                            None
                        };
                        Ok(ItemModuleOutput {
                            kind: module.kind.clone(),
                            name: module.name.clone(),
                            configured,
                            agent_visible,
                            value,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut actions = Vec::new();
                if decrypted.stored.has_capability("fill") {
                    actions.push("credential_fill".to_owned());
                }
                if decrypted.stored.has_capability("ssh") {
                    actions.push("ssh_run".to_owned());
                }
                if decrypted.stored.has_capability("http") {
                    actions.push("http_send".to_owned());
                }
                Ok(ItemOutput {
                    id: decrypted.stored.id,
                    name: decrypted.stored.name,
                    modules,
                    actions,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ItemsSearchOutput { items })
    }
}

fn tool_success<T: Serialize>(value: T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(value) => {
            let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
            let mut result = CallToolResult::structured(value);
            result.content = vec![ContentBlock::text(text)];
            result
        }
        Err(_) => tool_error("KRU could not serialize the tool result."),
    }
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

fn into_tool_result<T: Serialize>(result: Result<T, String>) -> CallToolResult {
    match result {
        Ok(value) => tool_success(value),
        Err(message) => tool_error(message),
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ItemsSearchInput {
    #[serde(default)]
    #[schemars(
        description = "Optional project-name query. Exact case-insensitive matches win; otherwise KRU returns project names containing the query."
    )]
    query: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ItemsSearchOutput {
    items: Vec<ItemOutput>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ItemOutput {
    #[schemars(with = "String")]
    id: Uuid,
    name: String,
    modules: Vec<ItemModuleOutput>,
    actions: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ItemModuleOutput {
    kind: String,
    name: String,
    configured: bool,
    agent_visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CredentialFillOutput {
    target: String,
    module: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct OkOutput {
    ok: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshRunInput {
    #[schemars(description = "Item ID returned by items_search for an item advertising ssh_run.")]
    item_id: String,
    #[schemars(description = "One command to execute.")]
    command: String,
    #[serde(default)]
    #[schemars(description = "Optional remote working directory.")]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpSendInput {
    #[schemars(
        description = "Item ID returned by items_search for an item advertising http_send."
    )]
    item_id: String,
    #[schemars(description = "Absolute request URL.")]
    url: String,
    #[serde(default = "default_http_method")]
    #[schemars(description = "HTTP method. Defaults to GET.")]
    method: String,
    #[serde(default)]
    #[schemars(description = "Query parameters appended to the URL.")]
    query: HashMap<String, Value>,
    #[serde(default)]
    #[schemars(description = "Non-authentication request headers.")]
    headers: HashMap<String, String>,
    #[serde(default)]
    #[schemars(description = "Optional JSON request body.")]
    body: Option<Value>,
}

fn default_http_method() -> String {
    "GET".to_owned()
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialFillInput {
    #[schemars(description = "Item ID returned by items_search.")]
    item_id: String,
    #[schemars(description = "Module name returned by items_search.")]
    module: String,
    #[schemars(
        description = "Write target: browser (paired extension; recommended for reliable browser automation), desktop (only when the real operating-system foreground focus is guaranteed), or terminal."
    )]
    target: String,
    #[serde(default)]
    #[schemars(
        description = "Required when target=terminal; use the session ID returned by terminal_start."
    )]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalStartInput {
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSessionInput {
    #[schemars(description = "Session ID returned by terminal_start.")]
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalWriteInput {
    #[schemars(description = "Session ID returned by terminal_start.")]
    session_id: String,
    #[schemars(
        description = "Ordinary terminal input. Append a newline when the agent intends to press Enter."
    )]
    text: String,
}

#[tool_router(router = tool_router)]
impl VaultMcp {
    #[tool(
        name = "items_search",
        description = "Discover enabled KRU projects and their available actions. Call this first for tasks involving credentials, authentication, SSH, VPS access, API credentials, private keys, passphrases, or TOTP. When the user names a project, pass that name as query. Exact case-insensitive name matches win; otherwise KRU returns names containing the query. Only modules explicitly marked agentVisible include value.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ItemsSearchOutput>(),
        annotations(title = "Find KRU projects", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn items_search(
        &self,
        Parameters(input): Parameters<ItemsSearchInput>,
    ) -> CallToolResult {
        into_tool_result(self.search_items(input))
    }

    #[tool(
        name = "credential_fill",
        description = "Write one stored module to a paired browser, the real operating-system foreground control, or a KRU-managed terminal without returning hidden plaintext. Call items_search first. Prefer browser for browser automation. KRU never submits or presses Enter.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<CredentialFillOutput>(),
        annotations(title = "Fill a credential", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn credential_fill(
        &self,
        Parameters(input): Parameters<CredentialFillInput>,
    ) -> CallToolResult {
        let result: Result<CredentialFillOutput, String> = async {
            let item_id = Uuid::parse_str(&input.item_id).map_err(|_| "项目 ID 无效".to_owned())?;
            let target = match input.target.as_str() {
                "browser" | "desktop" | "terminal" => input.target,
                _ => return Err("target 必须是 browser、desktop 或 terminal".to_owned()),
            };
            let module = input.module;
            self.track(item_id, format!("向 {target} 填写模块 {module}"), async {
                let (_, kind, mut value) = self
                    .vault
                    .get_secret_value(item_id, &module)
                    .map_err(|error| anyhow::anyhow!(error))?;
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
            Ok(CredentialFillOutput { target, module })
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_start",
        description = "Start a program directly in a KRU-managed local PTY. The caller chooses the program and argv; no shell is inserted.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalOpenResult>(),
        annotations(title = "Open a managed terminal", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_start(
        &self,
        Parameters(input): Parameters<TerminalStartInput>,
    ) -> CallToolResult {
        into_tool_result(
            self.terminal
                .open(&input.program, input.args, input.cwd)
                .map_err(|error| error.to_string()),
        )
    }

    #[tool(
        name = "terminal_write",
        description = "Write ordinary text to a KRU-managed PTY. credential_fill never adds a newline, so send a newline separately only when submission is intended.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Write terminal input", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_write(
        &self,
        Parameters(input): Parameters<TerminalWriteInput>,
    ) -> CallToolResult {
        let result = Uuid::parse_str(&input.session_id)
            .map_err(|_| "终端会话 ID 无效".to_owned())
            .and_then(|session_id| {
                self.terminal
                    .input(session_id, &input.text)
                    .map_err(|error| error.to_string())
            })
            .map(|_| OkOutput { ok: true });
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_read",
        description = "Read PTY output produced since the previous call and the current process state. KRU redacts values it filled and common encodings of those values.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalReadResult>(),
        annotations(title = "Read terminal output", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn terminal_read(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
    ) -> CallToolResult {
        let result = Uuid::parse_str(&input.session_id)
            .map_err(|_| "终端会话 ID 无效".to_owned())
            .and_then(|session_id| {
                self.terminal
                    .read(session_id)
                    .map_err(|error| error.to_string())
            });
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_stop",
        description = "Close and clean up a KRU-managed PTY, terminating the program if it is still running.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Close a managed terminal", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn terminal_stop(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
    ) -> CallToolResult {
        let result = Uuid::parse_str(&input.session_id)
            .map_err(|_| "终端会话 ID 无效".to_owned())
            .and_then(|session_id| {
                self.terminal
                    .close(session_id)
                    .map_err(|error| error.to_string())
            })
            .map(|_| OkOutput { ok: true });
        into_tool_result(result)
    }

    #[tool(
        name = "ssh_run",
        description = "Execute the command the user requested on an SSH host stored in KRU. Call items_search first and use only a project advertising ssh_run. KRU authenticates locally; this action represents full command authority for that project. KRU has no observation, diagnostic, restricted, or execution mode.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshResponse>(),
        annotations(title = "Execute an SSH command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn ssh_run(&self, Parameters(input): Parameters<SshRunInput>) -> CallToolResult {
        let result: Result<SshResponse, String> = async {
            let item_id = Uuid::parse_str(&input.item_id).map_err(|_| "项目 ID 无效".to_owned())?;
            let connection = self
                .vault
                .get_connection(item_id)
                .map_err(|error| error.to_string())?;
            if !connection.stored.has_capability("ssh") {
                return Err("所选项目的模块尚未形成可用 SSH 动作".to_owned());
            }
            self.track(
                item_id,
                "执行 SSH 命令".to_owned(),
                execute_ssh(
                    &self.vault,
                    &connection,
                    &input.command,
                    input.cwd.as_deref(),
                ),
            )
            .await
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "http_send",
        description = "Send an authenticated HTTP request through KRU without returning hidden credential plaintext. Call items_search first and use only a project advertising http_send. Provide one absolute URL. A saved service URL locks requests to the same origin. Without one, HTTPS is required except for loopback HTTP. Redirects and caller-supplied authentication headers are blocked.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApiResponse>(),
        annotations(title = "Send an authenticated API request", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn http_send(&self, Parameters(input): Parameters<HttpSendInput>) -> CallToolResult {
        let result: Result<ApiResponse, String> = async {
            let item_id = Uuid::parse_str(&input.item_id).map_err(|_| "项目 ID 无效".to_owned())?;
            let connection = self
                .vault
                .get_connection(item_id)
                .map_err(|error| error.to_string())?;
            if !connection.stored.has_capability("http") {
                return Err("所选项目的模块尚未形成可用 HTTP 动作".to_owned());
            }
            let request = ApiRequestInput {
                url: input.url,
                method: input.method,
                query: input.query,
                headers: input.headers,
                body: input.body,
            };
            let action = describe_api_request(&request);
            self.track(item_id, action, execute_api(&connection, request))
                .await
        }
        .await;
        into_tool_result(result)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for VaultMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "KRU is a local, non-agentic credential execution tool. Before asking the user to provide a credential, call items_search. When the user names a KRU project, pass that name as query and prefer the exact match. Use only actions advertised by the selected project. A module includes value only when the user explicitly made it agent-visible; never request, guess, or try to extract a missing value. Let KRU perform hidden authentication through credential_fill, ssh_run, or http_send. KRU has no observation, diagnostic, restricted, or execution mode. For browser automation, prefer credential_fill with target=browser and the paired extension. Use target=desktop only when the real operating-system foreground focus is guaranteed. KRU never submits a filled value automatically.",
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
    use crate::model::{ConnectionInput, ItemModule, NamedSecrets, SecretBundle};
    use tempfile::tempdir;

    fn structured_value(result: &CallToolResult) -> serde_json::Value {
        assert_eq!(result.is_error, Some(false));
        let structured = result.structured_content.clone().unwrap();
        let wire = serde_json::to_value(result).unwrap();
        let text = wire["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(text).unwrap(),
            structured
        );
        structured
    }

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
        named.insert("totp".into(), "JBSWY3DPEHPK3PXP".into());
        let mut secrets = SecretBundle::default();
        secrets.named_secrets = named;
        let saved = vault
            .save_connection(ConnectionInput {
                id: None,
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
                        kind: "totp".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(true),
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
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: vec![],
                allowed_methods: vec![],
                allowed_path_prefixes: vec![],
                test_path: String::new(),
                remove_secret_names: vec![],
                secrets,
            })
            .unwrap();

        let mcp = VaultMcp::new(vault.clone());
        let output = mcp
            .items_search(Parameters(ItemsSearchInput::default()))
            .await;
        let listed = structured_value(&output);
        let text = serde_json::to_string(&listed).unwrap();
        assert!(text.contains("username"));
        assert!(text.contains("password"));
        assert_eq!(
            listed["items"][0]["actions"],
            json!(["credential_fill", "ssh_run"])
        );
        for removed in ["type", "capabilities", "description", "fields", "target"] {
            assert!(
                listed["items"][0].get(removed).is_none(),
                "legacy field {removed} remains"
            );
        }
        assert!(
            listed["items"][0]["modules"][0].get("secret").is_none(),
            "module output still exposes the removed secret projection"
        );
        assert!(text.contains("mcp-visible-user-marker"));
        assert!(!text.contains("mcp-hidden-password-marker"));
        assert!(!text.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            listed["items"][0]["modules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|module| module["kind"] == "totp")
                .unwrap()["value"]
                .as_str()
                .unwrap()
                .len(),
            6
        );

        let exact = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("TEST LOGIN".into()),
            }))
            .await,
        );
        assert_eq!(exact["items"].as_array().unwrap().len(), 1);
        assert_eq!(exact["items"][0]["name"], "test login");

        let partial = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("login".into()),
            }))
            .await,
        );
        assert_eq!(partial["items"].as_array().unwrap().len(), 1);

        let missing = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("does not exist".into()),
            }))
            .await,
        );
        assert!(missing["items"].as_array().unwrap().is_empty());

        vault.set_connection_enabled(saved.id, false).unwrap();
        let hidden = VaultMcp::new(vault)
            .items_search(Parameters(ItemsSearchInput::default()))
            .await;
        let hidden = serde_json::to_string(&structured_value(&hidden)).unwrap();
        assert!(!hidden.contains("test login"));
        assert!(!hidden.contains("username"));
        assert!(!hidden.contains("password"));
    }

    #[test]
    fn tool_contracts_have_output_schemas_and_annotations() {
        let router = VaultMcp::tool_router();
        let expected = [
            ("items_search", true, false, true, false),
            ("credential_fill", false, false, false, true),
            ("terminal_start", false, false, false, true),
            ("terminal_write", false, true, false, true),
            ("terminal_read", true, false, true, false),
            ("terminal_stop", false, true, true, false),
            ("ssh_run", false, true, false, true),
            ("http_send", false, true, false, true),
        ];
        for (name, read_only, destructive, idempotent, open_world) in expected {
            let tool = router.get(name).unwrap();
            assert!(
                tool.output_schema.is_some(),
                "{name} needs an output schema"
            );
            let annotations = tool.annotations.as_ref().unwrap();
            assert_eq!(annotations.read_only_hint, Some(read_only), "{name}");
            assert_eq!(annotations.destructive_hint, Some(destructive), "{name}");
            assert_eq!(annotations.idempotent_hint, Some(idempotent), "{name}");
            assert_eq!(annotations.open_world_hint, Some(open_world), "{name}");
        }
        for removed in [
            "vault_items_list",
            "secret_fill",
            "terminal_open",
            "terminal_input",
            "terminal_close",
            "ssh_execute",
            "api_request",
        ] {
            assert!(
                router.get(removed).is_none(),
                "removed tool {removed} is still registered"
            );
        }
    }

    #[test]
    fn renamed_arguments_are_rejected() {
        assert!(
            serde_json::from_value::<CredentialFillInput>(json!({
                "itemId": Uuid::new_v4().to_string(),
                "field": "password",
                "target": "browser"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SshRunInput>(json!({
                "connectionId": Uuid::new_v4().to_string(),
                "command": "hostname"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<HttpSendInput>(json!({
                "itemId": Uuid::new_v4().to_string(),
                "url": "https://api.example.test/v1/health",
                "path": "health"
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn business_failures_are_tool_errors() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let result = VaultMcp::new(vault)
            .terminal_read(Parameters(TerminalSessionInput {
                session_id: "not-a-session".into(),
            }))
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
    }
}
