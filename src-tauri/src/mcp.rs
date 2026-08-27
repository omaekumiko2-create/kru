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

    fn list_items(&self, input: VaultItemsListInput) -> Result<VaultItemsListOutput, String> {
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
            .map(|decrypted| -> Result<VaultItemOutput, String> {
                let item = decrypted.stored.public(Some(&decrypted.secrets));
                let modules = decrypted
                    .stored
                    .modules
                    .iter()
                    .map(|module| -> Result<VaultModuleOutput, String> {
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
                        Ok(VaultModuleOutput {
                            kind: module.kind.clone(),
                            name: module.name.clone(),
                            secret: module.is_secret(),
                            configured,
                            agent_visible,
                            value,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let fields = item
                    .secret
                    .as_ref()
                    .map(|profile| {
                        profile
                            .fields
                            .iter()
                            .map(|field| VaultFieldOutput {
                                name: field.name.clone(),
                                field_type: field.kind.clone(),
                                agent_visible: decrypted
                                    .stored
                                    .modules
                                    .iter()
                                    .find(|module| {
                                        module.secret_name() == Some(field.name.as_str())
                                    })
                                    .is_some_and(|module| module.agent_visible()),
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let has_ssh = item.capabilities.iter().any(|value| value == "ssh");
                let has_http = item.capabilities.iter().any(|value| value == "http");
                let mut actions = Vec::new();
                if item.capabilities.iter().any(|value| value == "fill") {
                    actions.push("secret_fill".to_owned());
                }
                let ssh = has_ssh.then(|| VaultSshTargetOutput {
                    host: decrypted
                        .stored
                        .modules
                        .iter()
                        .find(|module| module.kind == "host")
                        .is_some_and(|module| module.agent_visible())
                        .then(|| item.host.clone()),
                    port: decrypted
                        .stored
                        .modules
                        .iter()
                        .find(|module| module.kind == "port")
                        .is_some_and(|module| module.agent_visible())
                        .then_some(item.port),
                });
                if has_ssh {
                    actions.push("ssh_execute".to_owned());
                }
                let http = has_http.then(|| {
                    let url_visible = decrypted
                        .stored
                        .modules
                        .iter()
                        .find(|module| module.kind == "url")
                        .is_some_and(|module| module.agent_visible());
                    VaultHttpTargetOutput {
                        runtime_url_required: item.base_url.is_empty(),
                        methods: item.allowed_methods.clone(),
                        path_prefixes: item.allowed_path_prefixes.clone(),
                        base_url: url_visible.then(|| item.base_url.clone()),
                    }
                });
                if has_http {
                    actions.push("api_request".to_owned());
                }
                Ok(VaultItemOutput {
                    id: item.id,
                    name: item.name,
                    item_type: "item".to_owned(),
                    capabilities: item.capabilities,
                    modules,
                    description: item.description,
                    fields,
                    target: VaultTargetOutput { ssh, http },
                    actions,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VaultItemsListOutput {
            count: items.len(),
            query,
            items,
        })
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
#[serde(rename_all = "camelCase")]
struct VaultItemsListInput {
    #[serde(default)]
    #[schemars(
        description = "Optional project-name query. Exact case-insensitive matches win; otherwise KRU returns project names containing the query."
    )]
    query: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultItemsListOutput {
    count: usize,
    query: Option<String>,
    items: Vec<VaultItemOutput>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultItemOutput {
    #[schemars(with = "String")]
    id: Uuid,
    name: String,
    #[serde(rename = "type")]
    item_type: String,
    capabilities: Vec<String>,
    modules: Vec<VaultModuleOutput>,
    description: String,
    fields: Vec<VaultFieldOutput>,
    target: VaultTargetOutput,
    actions: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultModuleOutput {
    kind: String,
    name: String,
    secret: bool,
    configured: bool,
    agent_visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultFieldOutput {
    name: String,
    #[serde(rename = "type")]
    field_type: String,
    agent_visible: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultTargetOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh: Option<VaultSshTargetOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<VaultHttpTargetOutput>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultSshTargetOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct VaultHttpTargetOutput {
    runtime_url_required: bool,
    methods: Vec<String>,
    path_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SecretFillOutput {
    ok: bool,
    target: String,
    field: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct OkOutput {
    ok: bool,
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
        description = "Discover enabled KRU projects and their available actions. Call this first for tasks involving credentials, authentication, SSH, VPS access, API credentials, private keys, passphrases, or TOTP. When the user names a project, pass that name as query. Exact case-insensitive name matches win; otherwise KRU returns names containing the query. Only modules explicitly marked agentVisible include value.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<VaultItemsListOutput>(),
        annotations(title = "Find KRU projects", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn vault_items_list(
        &self,
        Parameters(input): Parameters<VaultItemsListInput>,
    ) -> CallToolResult {
        into_tool_result(self.list_items(input))
    }

    #[tool(
        name = "secret_fill",
        description = "Write one stored field to a paired browser, the real operating-system foreground control, or a KRU-managed terminal without returning hidden plaintext. Call vault_items_list first. Prefer browser for browser automation. KRU never submits or presses Enter.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SecretFillOutput>(),
        annotations(title = "Fill a credential", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn secret_fill(&self, Parameters(input): Parameters<SecretFillInput>) -> CallToolResult {
        let result: Result<SecretFillOutput, String> = async {
            let item_id = Uuid::parse_str(&input.item_id).map_err(|_| "项目 ID 无效".to_owned())?;
            let target = match input.target.as_str() {
                "browser" | "desktop" | "terminal" => input.target,
                _ => return Err("target 必须是 browser、desktop 或 terminal".to_owned()),
            };
            let field = input.field;
            self.track(item_id, format!("向 {target} 填写字段 {field}"), async {
                let (_, kind, mut value) = self
                    .vault
                    .get_secret_value(item_id, &field)
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
            Ok(SecretFillOutput {
                ok: true,
                target,
                field,
            })
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_open",
        description = "Start a program directly in a KRU-managed local PTY. The caller chooses the program and argv; no shell is inserted.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalOpenResult>(),
        annotations(title = "Open a managed terminal", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_open(
        &self,
        Parameters(input): Parameters<TerminalOpenInput>,
    ) -> CallToolResult {
        into_tool_result(
            self.terminal
                .open(&input.program, input.args, input.cwd)
                .map_err(|error| error.to_string()),
        )
    }

    #[tool(
        name = "terminal_input",
        description = "Write ordinary text to a KRU-managed PTY. secret_fill never adds a newline, so send a newline separately only when submission is intended.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Write terminal input", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_input(
        &self,
        Parameters(input): Parameters<TerminalInputInput>,
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
        name = "terminal_close",
        description = "Close and clean up a KRU-managed PTY, terminating the program if it is still running.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Close a managed terminal", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn terminal_close(
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
        name = "ssh_execute",
        description = "Execute the command the user requested on an SSH host stored in KRU. Call vault_items_list first and use only a project advertising ssh_execute. KRU authenticates locally; this action represents full command authority for that project. KRU has no observation, diagnostic, restricted, or execution mode.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshResponse>(),
        annotations(title = "Execute an SSH command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn ssh_execute(&self, Parameters(input): Parameters<SshExecuteInput>) -> CallToolResult {
        let result: Result<SshResponse, String> = async {
            let connection_id =
                Uuid::parse_str(&input.connection_id).map_err(|_| "连接 ID 无效".to_owned())?;
            let connection = self
                .vault
                .get_connection(connection_id)
                .map_err(|error| error.to_string())?;
            if !connection.stored.has_capability("ssh") {
                return Err("所选项目的模块尚未形成可用 SSH 动作".to_owned());
            }
            self.track(
                connection_id,
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
        name = "api_request",
        description = "Send an authenticated API request through KRU without returning hidden credential plaintext. Call vault_items_list first and use only a project advertising api_request. A saved URL locks requests to the same origin. Without a saved URL, provide an absolute HTTPS URL; HTTP is allowed only for loopback addresses. Redirects and caller-supplied authentication headers are blocked.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApiResponse>(),
        annotations(title = "Send an authenticated API request", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn api_request(&self, Parameters(input): Parameters<ApiToolInput>) -> CallToolResult {
        let result: Result<ApiResponse, String> = async {
            let connection_id =
                Uuid::parse_str(&input.connection_id).map_err(|_| "连接 ID 无效".to_owned())?;
            let connection = self
                .vault
                .get_connection(connection_id)
                .map_err(|error| error.to_string())?;
            if !connection.stored.has_capability("http") {
                return Err("所选项目的模块尚未形成可用 HTTP 动作".to_owned());
            }
            let action = describe_api_request(&connection.stored, &input.request);
            self.track(
                connection_id,
                action,
                execute_api(&connection, input.request),
            )
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
            "KRU is a local, non-agentic credential execution tool. Before asking the user to provide a credential, call vault_items_list. When the user names a KRU project, pass that name as query and prefer the exact match. Use only actions advertised by the selected project. A module includes value only when the user explicitly made it agent-visible; never request, guess, or try to extract a missing value. Let KRU perform hidden authentication through secret_fill, ssh_execute, or api_request. KRU has no observation, diagnostic, restricted, or execution mode. For browser automation, prefer secret_fill with target=browser and the paired extension. Use target=desktop only when the real operating-system foreground focus is guaranteed. KRU never submits a filled value automatically.",
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
                        SecretField {
                            name: "totp".into(),
                            kind: "totp".into(),
                        },
                    ],
                }),
                remove_secret_names: vec![],
                secrets,
            })
            .unwrap();

        let mcp = VaultMcp::new(vault.clone());
        let output = mcp
            .vault_items_list(Parameters(VaultItemsListInput::default()))
            .await;
        let listed = structured_value(&output);
        let text = serde_json::to_string(&listed).unwrap();
        assert!(text.contains("username"));
        assert!(text.contains("password"));
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
            &mcp.vault_items_list(Parameters(VaultItemsListInput {
                query: Some("TEST LOGIN".into()),
            }))
            .await,
        );
        assert_eq!(exact["count"], 1);
        assert_eq!(exact["items"][0]["name"], "test login");

        let partial = structured_value(
            &mcp.vault_items_list(Parameters(VaultItemsListInput {
                query: Some("login".into()),
            }))
            .await,
        );
        assert_eq!(partial["count"], 1);

        let missing = structured_value(
            &mcp.vault_items_list(Parameters(VaultItemsListInput {
                query: Some("does not exist".into()),
            }))
            .await,
        );
        assert_eq!(missing["count"], 0);

        vault.set_connection_enabled(saved.id, false).unwrap();
        let hidden = VaultMcp::new(vault)
            .vault_items_list(Parameters(VaultItemsListInput::default()))
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
            ("vault_items_list", true, false, true, false),
            ("secret_fill", false, false, false, true),
            ("terminal_open", false, false, false, true),
            ("terminal_input", false, true, false, true),
            ("terminal_read", true, false, true, false),
            ("terminal_close", false, true, true, false),
            ("ssh_execute", false, true, false, true),
            ("api_request", false, true, false, true),
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
