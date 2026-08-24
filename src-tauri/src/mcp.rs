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
    time::{Duration, Instant},
};
use tokio::time::sleep;
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

    async fn require_approval(&self, item_id: Uuid, action: &str, detail: &str) -> Result<bool> {
        let Some(request) =
            self.vault
                .create_approval_request(item_id, &self.activity_source(), action, detail)?
        else {
            return Ok(false);
        };
        for _ in 0..240 {
            sleep(Duration::from_millis(250)).await;
            match self.vault.approval_status(request.id)?.as_deref() {
                Some("approved") => {
                    self.vault.remove_approval(request.id)?;
                    return Ok(true);
                }
                Some("denied") => {
                    self.vault.remove_approval(request.id)?;
                    bail!("用户已拒绝本次调用");
                }
                Some("pending") => {}
                Some("expired") | None => bail!("审核请求已取消或过期"),
                Some(_) => bail!("审核请求状态无效"),
            }
        }
        self.vault.remove_approval(request.id)?;
        bail!("等待用户审核超时；请打开 KRU 后重试")
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
    #[schemars(description = "vault_items_list 返回的、已自动推导 SSH 动作的项目 ID")]
    connection_id: String,
    #[schemars(description = "要执行的单条命令")]
    command: String,
    #[serde(default)]
    #[schemars(description = "可选远程工作目录")]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ApiToolInput {
    #[schemars(description = "vault_items_list 返回的、已自动推导 HTTP 动作的项目 ID")]
    connection_id: String,
    #[serde(flatten)]
    request: ApiRequestInput,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SecretFillInput {
    #[schemars(description = "vault_items_list 返回的项目 ID")]
    item_id: String,
    #[schemars(description = "vault_items_list 返回的秘密字段名")]
    field: String,
    #[schemars(
        description = "写入目标：browser（已配对扩展，推荐用于可靠浏览器自动化）、desktop（仅在能保证真实操作系统前台焦点时）或 terminal"
    )]
    target: String,
    #[serde(default)]
    #[schemars(description = "target=terminal 时必填，来自 terminal_open")]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalOpenInput {
    #[schemars(description = "Agent 决定运行的程序名称或路径；直接启动，不经过 Shell")]
    program: String,
    #[serde(default)]
    #[schemars(description = "作为独立 argv 值传递的参数")]
    args: Vec<String>,
    #[serde(default)]
    #[schemars(description = "可选的绝对工作目录")]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalSessionInput {
    #[schemars(description = "terminal_open 返回的会话 ID")]
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TerminalInputInput {
    #[schemars(description = "terminal_open 返回的会话 ID")]
    session_id: String,
    #[schemars(description = "普通终端输入；需要回车时由 Agent 在末尾加入换行")]
    text: String,
}

#[tool_router(router = tool_router)]
impl VaultMcp {
    #[tool(
        name = "vault_items_list",
        description = "列出已向 Agent 开启的 KRU 项目、模块和支持动作。只有用户明确开启‘Agent 可见’的模块才会包含明文 value；其他模块只返回名称和配置状态。"
    )]
    async fn vault_items_list(&self) -> Result<String, String> {
        let items = self
            .vault
            .list_connections()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|item| item.enabled && !item.capabilities.is_empty())
            .map(|item| -> Result<serde_json::Value, String> {
                let decrypted = self
                    .vault
                    .get_connection(item.id)
                    .map_err(|error| error.to_string())?;
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
                    let mut ssh = json!({"mode": item.security_mode, "allowedCommands": item.allowed_commands});
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
        description = "把一个已保存字段写入 Agent 已聚焦的控件或指定 KRU 终端。可靠的浏览器自动化使用已配对扩展的 browser；desktop 仅在你能保证真实操作系统前台焦点时使用。KRU 不判断用途、不自动提交，也不返回字段值。"
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
            let was_approved = self
                .require_approval(item_id, "填写秘密", &format!("{target} · {field}"))
                .await?;
            if was_approved && target == "desktop" {
                sleep(Duration::from_secs(5)).await;
            }
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
        description = "在 KRU 托管的本地 PTY 中直接启动程序。Agent 决定程序和 argv；不经过 Shell。"
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
        description = "向 KRU 托管的 PTY 写入普通文本。secret_fill 不会自动换行，需要提交时由 Agent 再发送回车。"
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
        description = "读取 PTY 自上次调用后的输出和进程状态；KRU 填入过的秘密及常见编码形式会被脱敏。"
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
        description = "关闭并清理 KRU 托管的 PTY；若程序仍在运行则终止它。"
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
        description = "使用本地保险库在已保存 VPS 上执行受策略限制的命令；认证信息不会返回给 Agent。"
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
            .track(connection_id, "执行 SSH 命令".to_owned(), async {
                self.require_approval(connection_id, "执行 SSH 命令", &input.command)
                    .await?;
                execute_ssh(
                    &self.vault,
                    &connection,
                    &input.command,
                    input.cwd.as_deref(),
                )
                .await
            })
            .await?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    #[tool(
        name = "api_request",
        description = "调用 API；认证由 KRU 注入。保存 URL 时锁定同源；未保存 URL 时由调用方提供绝对 HTTPS URL（本机回环可用 HTTP）。"
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
        let approval_detail = format!(
            "{} {}",
            input.request.method.to_uppercase(),
            if input.request.url.is_empty() {
                input.request.path.as_str()
            } else {
                input.request.url.as_str()
            }
        );
        let result = self
            .track(connection_id, action, async {
                if connection.secrets.has_auth_secret() {
                    self.require_approval(connection_id, "发送 API 请求", &approval_detail)
                        .await?;
                }
                execute_api(&connection, input.request).await
            })
            .await?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for VaultMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "KRU 是无智能的本地凭据执行工具。先用 vault_items_list 选择项目和字段。模块仅在用户开启 Agent 可见时包含 value；没有 value 时不得索取或猜测，请调用 secret_fill、ssh_execute 或 api_request。可靠的浏览器自动化使用已配对扩展的 target=browser；target=desktop 只在你能保证真实操作系统前台焦点时使用。后台 DOM 聚焦不等于系统前台焦点。",
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
    let service = VaultMcp::new(vault).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

pub fn render_config(format: &str) -> Result<String> {
    let executable = std::env::current_exe().context("无法确定 KRU 可执行文件路径")?;
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
                security_mode: String::new(),
                allowed_commands: vec![],
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
        assert_eq!(listed["items"][0]["capabilities"], json!(["fill"]));
        assert!(output.contains("mcp-visible-user-marker"));
        assert!(!output.contains("mcp-hidden-password-marker"));

        vault.set_connection_enabled(saved.id, false).unwrap();
        let hidden = VaultMcp::new(vault).vault_items_list().await.unwrap();
        assert!(!hidden.contains("test login"));
        assert!(!hidden.contains("username"));
        assert!(!hidden.contains("password"));
    }
}
