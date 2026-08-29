use crate::{
    browser::{BrowserBridge, current_totp},
    desktop,
    executor::{
        ApiRequestInput, ApiResponse, SshResponse, SshTransferResponse, describe_api_request,
        execute_api, execute_local, execute_ssh, ssh_download, ssh_upload,
    },
    model::NewActivity,
    terminal::{TerminalManager, TerminalOpenResult, TerminalReadResult},
    vault::{DecryptedConnection, Vault},
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
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct VaultMcp {
    vault: Vault,
    browser: BrowserBridge,
    terminal: TerminalManager,
    active_item: Arc<RwLock<Option<Uuid>>>,
    active_terminal: Arc<RwLock<Option<Uuid>>>,
    terminal_items: Arc<RwLock<HashMap<Uuid, Uuid>>>,
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
            active_item: Arc::new(RwLock::new(None)),
            active_terminal: Arc::new(RwLock::new(None)),
            terminal_items: Arc::new(RwLock::new(HashMap::new())),
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

    fn bind_terminal_item(&self, session_id: Uuid, item_id: Uuid) {
        if let Ok(mut bindings) = self.terminal_items.write() {
            bindings.insert(session_id, item_id);
        }
    }

    fn bind_active_item(&self, item_id: Uuid) {
        if let Ok(mut active_item) = self.active_item.write() {
            *active_item = Some(item_id);
        }
    }

    fn clear_active_item(&self) {
        if let Ok(mut active_item) = self.active_item.write() {
            *active_item = None;
        }
    }

    fn bind_active_terminal(&self, session_id: Uuid) {
        if let Ok(mut active_terminal) = self.active_terminal.write() {
            *active_terminal = Some(session_id);
        }
    }

    fn clear_active_terminal(&self, session_id: Uuid) {
        if let Ok(mut active_terminal) = self.active_terminal.write()
            && *active_terminal == Some(session_id)
        {
            *active_terminal = None;
        }
    }

    fn resolve_terminal_session_id(
        &self,
        session_id: &str,
        require_running: bool,
    ) -> Result<Uuid, String> {
        let session_id = if session_id.trim().is_empty() {
            self.active_terminal
                .read()
                .ok()
                .and_then(|session_id| *session_id)
                .ok_or_else(|| {
                    "没有当前终端会话；请先调用 terminal_start 或提供 sessionId".to_owned()
                })?
        } else {
            Uuid::parse_str(session_id).map_err(|_| "终端会话 ID 无效".to_owned())?
        };
        if !self
            .terminal
            .contains(session_id)
            .map_err(|error| error.to_string())?
        {
            self.clear_active_terminal(session_id);
            return Err("找不到终端会话；请启动新的终端".to_owned());
        }
        if require_running
            && !self
                .terminal
                .is_running(session_id)
                .map_err(|error| error.to_string())?
        {
            self.clear_active_terminal(session_id);
            return Err("当前终端会话已经结束；请启动新的终端".to_owned());
        }
        self.bind_active_terminal(session_id);
        Ok(session_id)
    }

    fn active_connection_for_action(
        &self,
        capability: Option<&str>,
    ) -> Option<DecryptedConnection> {
        let item_id = self.active_item.read().ok().and_then(|item| *item)?;
        let connection = self.vault.get_connection(item_id).ok()?;
        let supports_action = connection_supports_action(&connection, capability);
        (connection.stored.enabled && supports_action).then_some(connection)
    }

    fn unbind_terminal_item(&self, session_id: Uuid) {
        if let Ok(mut bindings) = self.terminal_items.write() {
            bindings.remove(&session_id);
        }
    }

    fn resolve_terminal_item(
        &self,
        session_id: Uuid,
        query: &str,
    ) -> Result<DecryptedConnection, String> {
        if !query.trim().is_empty() {
            return self.resolve_item_for_action(query, Some("fill"));
        }
        let bound = self
            .terminal_items
            .read()
            .ok()
            .and_then(|bindings| bindings.get(&session_id).copied());
        if let Some(item_id) = bound {
            let connection = self
                .vault
                .get_connection(item_id)
                .map_err(|_| "该终端绑定的 KRU 项目已不可用；请重新指定 item".to_owned())?;
            if !connection.stored.enabled || !connection.stored.has_capability("fill") {
                return Err("该终端绑定的 KRU 项目已不可用；请重新指定 item".to_owned());
            }
            return Ok(connection);
        }
        self.resolve_item_for_action("", Some("fill"))
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
        let mut connections = self
            .vault
            .list_decrypted_connections()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|decrypted| {
                decrypted.stored.enabled && !decrypted.stored.normalized_capabilities().is_empty()
            })
            .collect::<Vec<_>>();

        if let Some(query) = query.as_deref() {
            connections = filter_connections_by_query(connections, query);
        }

        if connections.len() == 1 {
            self.bind_active_item(connections[0].stored.id);
        } else if query.is_some() {
            self.clear_active_item();
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
                if connection_supports_action(&decrypted, Some("ssh-auth")) {
                    actions.push("ssh_run".to_owned());
                    actions.push("ssh_upload".to_owned());
                    actions.push("ssh_download".to_owned());
                }
                if decrypted.stored.has_capability("http")
                    || decrypted.stored.has_capability("fill")
                {
                    actions.push("http_send".to_owned());
                }
                Ok(ItemOutput {
                    name: decrypted.stored.name,
                    modules,
                    actions,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ItemsSearchOutput { items })
    }

    fn resolve_item_for_action(
        &self,
        query: &str,
        capability: Option<&str>,
    ) -> Result<DecryptedConnection, String> {
        let query = query.trim();
        let connections = self
            .vault
            .list_decrypted_connections()
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|connection| {
                connection.stored.enabled && connection_supports_action(connection, capability)
            })
            .collect::<Vec<_>>();
        if query.is_empty() {
            if let Some(connection) = self.active_connection_for_action(capability) {
                return Ok(connection);
            }
            return match connections.len() {
                0 => Err(match capability {
                    Some(capability) => {
                        format!(
                            "没有启用且支持 {} 动作的 KRU 项目",
                            action_label(capability)
                        )
                    }
                    None => "没有可供 Agent 使用的 KRU 项目".to_owned(),
                }),
                1 => {
                    let connection = connections.into_iter().next().expect("length checked");
                    self.bind_active_item(connection.stored.id);
                    Ok(connection)
                }
                _ => Err(format!(
                    "有多个可用的 KRU 项目：{}；请指定 item",
                    connections
                        .iter()
                        .map(|connection| connection.stored.name.as_str())
                        .collect::<Vec<_>>()
                        .join("、")
                )),
            };
        }
        let mut matches = filter_connections_by_query(connections, query);
        if matches.len() != 1 {
            self.clear_active_item();
        }
        match matches.len() {
            0 => Err(format!("找不到启用的 KRU 项目：{query}")),
            1 => {
                let connection = matches.remove(0);
                self.bind_active_item(connection.stored.id);
                Ok(connection)
            }
            _ => Err(format!(
                "项目名称匹配多个结果：{}；请使用更完整的名称",
                matches
                    .iter()
                    .map(|connection| connection.stored.name.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            )),
        }
    }

    fn prepare_ssh_connection(
        &self,
        item: &str,
        host: Option<&str>,
        port: Option<u16>,
        username: Option<&str>,
    ) -> Result<DecryptedConnection, String> {
        let mut connection = self.resolve_item_for_action(item, Some("ssh-auth"))?;
        if let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) {
            connection.stored.host = host.to_owned();
        }
        if let Some(port) = port {
            if port == 0 {
                return Err("SSH 端口必须大于 0".to_owned());
            }
            connection.stored.port = port;
        } else if connection.stored.port == 0 {
            connection.stored.port = 22;
        }
        if let Some(username) = username.map(str::trim).filter(|value| !value.is_empty()) {
            connection
                .secrets
                .named_secrets
                .insert("username".to_owned(), username.to_owned());
        }
        if connection.stored.host.trim().is_empty() {
            return Err("SSH 项目没有保存主机；请在本次调用中提供 host".to_owned());
        }
        if connection.secrets.get("username").is_none() {
            return Err("SSH 项目没有保存用户名；请在本次调用中提供 username".to_owned());
        }
        Ok(connection)
    }

    fn resolve_secret_bindings(
        &self,
        connection: &mut DecryptedConnection,
        bindings: &HashMap<String, String>,
        item_hint: &str,
    ) -> Result<HashMap<String, String>, String> {
        let mut replacements = HashMap::new();
        for (raw_alias, module_hint) in bindings {
            let alias = raw_alias.trim();
            if alias.is_empty() || alias.chars().any(char::is_control) {
                return Err("秘密绑定名称无效".to_owned());
            }
            if replacements.contains_key(alias) {
                return Err(format!("秘密绑定名称重复：{alias}"));
            }
            let module = resolve_secret_module(connection, module_hint, item_hint)?;
            let (_, kind, mut value) = self
                .vault
                .get_secret_value(connection.stored.id, &module)
                .map_err(|error| error.to_string())?;
            if kind == "totp" {
                value = current_totp(&value).map_err(|error| error.to_string())?;
            }
            let mut redaction_index = connection.secrets.named_secrets.0.len();
            let redaction_name = loop {
                let candidate = format!("__kru_binding_{redaction_index}");
                if !connection.secrets.named_secrets.0.contains_key(&candidate) {
                    break candidate;
                }
                redaction_index += 1;
            };
            connection
                .secrets
                .named_secrets
                .insert(redaction_name, value.clone());
            replacements.insert(alias.to_owned(), value);
        }
        Ok(replacements)
    }

    fn prepare_http_secret_bindings(
        &self,
        connection: &mut DecryptedConnection,
        input: &mut HttpSendInput,
    ) -> Result<(), String> {
        let placeholders = collect_http_secret_placeholders(input)?;
        if placeholders.is_empty() {
            return Ok(());
        }
        let bindings = input
            .secret_bindings
            .iter()
            .filter(|(alias, _)| placeholders.contains(*alias))
            .map(|(alias, module)| (alias.clone(), module.clone()))
            .collect::<HashMap<_, _>>();
        let replacements = self.resolve_secret_bindings(connection, &bindings, &input.item)?;
        interpolate_http_input(input, &replacements)?;
        Ok(())
    }
}

fn connection_supports_action(connection: &DecryptedConnection, capability: Option<&str>) -> bool {
    match capability {
        None => !connection.stored.normalized_capabilities().is_empty(),
        Some("ssh-auth") => {
            connection.secrets.get("password").is_some()
                || connection.secrets.get("privateKey").is_some()
        }
        Some(capability) => connection.stored.has_capability(capability),
    }
}

fn action_label(capability: &str) -> &str {
    match capability {
        "ssh-auth" => "SSH",
        capability => capability,
    }
}

fn filter_connections_by_query(
    mut connections: Vec<DecryptedConnection>,
    query: &str,
) -> Vec<DecryptedConnection> {
    let normalized_query = query.trim().to_lowercase();
    let search_query = normalize_search_text(query);
    let has_literal_exact = connections
        .iter()
        .any(|item| item.stored.name.trim().to_lowercase() == normalized_query);
    let has_normalized_exact = !search_query.is_empty()
        && connections
            .iter()
            .any(|item| normalize_search_text(&item.stored.name) == search_query);
    let longest_embedded_name = if !has_literal_exact && !has_normalized_exact {
        connections
            .iter()
            .map(|item| normalize_search_text(&item.stored.name))
            .filter(|name| phrase_contains(&search_query, name))
            .map(|name| name.len())
            .max()
    } else {
        None
    };
    connections.retain(|item| {
        let name = item.stored.name.trim().to_lowercase();
        if has_literal_exact {
            name == normalized_query
        } else if has_normalized_exact {
            normalize_search_text(&item.stored.name) == search_query
        } else if let Some(longest) = longest_embedded_name {
            let normalized_name = normalize_search_text(&item.stored.name);
            normalized_name.len() == longest && phrase_contains(&search_query, &normalized_name)
        } else {
            let normalized_name = normalize_search_text(&item.stored.name);
            name.contains(&normalized_query)
                || phrase_contains(&search_query, &normalized_name)
                || phrase_contains(&normalized_name, &search_query)
        }
    });
    connections
}

fn normalize_search_text(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn phrase_contains(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && format!(" {haystack} ").contains(&format!(" {needle} "))
}

fn module_aliases(name: &str) -> &'static [&'static str] {
    match name {
        "username" => &[
            "username",
            "user name",
            "account",
            "email",
            "用户名",
            "账号",
        ],
        "password" => &["password", "passwd", "pwd", "密码"],
        "apiCredential" => &[
            "api credential",
            "api key",
            "access token",
            "bearer token",
            "token",
            "api 凭据",
        ],
        "privateKey" => &["private key", "ssh key", "identity file", "私钥"],
        "passphrase" => &[
            "passphrase",
            "key passphrase",
            "private key password",
            "私钥口令",
            "口令",
        ],
        "totp" => &[
            "totp",
            "otp",
            "one time code",
            "verification code",
            "2fa code",
            "验证码",
        ],
        _ => &[],
    }
}

fn secret_module_match_score(name: &str, phrase: &str) -> Option<usize> {
    let phrase = normalize_search_text(phrase);
    let normalized_name = normalize_search_text(name);
    if phrase == normalized_name {
        return Some(10_000 + normalized_name.len());
    }
    std::iter::once(normalized_name)
        .chain(
            module_aliases(name)
                .iter()
                .map(|alias| normalize_search_text(alias)),
        )
        .filter(|alias| phrase_contains(&phrase, alias))
        .map(|alias| alias.len())
        .max()
}

fn module_hint_from_item(item_phrase: &str, project_name: &str) -> String {
    let phrase = format!(" {} ", normalize_search_text(item_phrase));
    let project = format!(" {} ", normalize_search_text(project_name));
    phrase.replace(&project, " ").trim().to_owned()
}

fn resolve_secret_module(
    connection: &DecryptedConnection,
    requested: &str,
    item_phrase: &str,
) -> Result<String, String> {
    let fields = connection
        .secrets
        .available_fields(connection.stored.secret.as_ref())
        .into_iter()
        .filter(|field| connection.secrets.get(&field.name).is_some())
        .collect::<Vec<_>>();
    match fields.as_slice() {
        [] => return Err("该项目没有已配置的秘密模块".to_owned()),
        [field] if requested.trim().is_empty() => return Ok(field.name.clone()),
        _ => {}
    }

    let hint = if requested.trim().is_empty() {
        module_hint_from_item(item_phrase, &connection.stored.name)
    } else {
        requested.trim().to_owned()
    };
    let scored = fields
        .iter()
        .filter_map(|field| {
            secret_module_match_score(&field.name, &hint).map(|score| (field.name.clone(), score))
        })
        .collect::<Vec<_>>();
    let best_score = scored.iter().map(|(_, score)| *score).max();
    let best = best_score.map_or_else(Vec::new, |best_score| {
        scored
            .into_iter()
            .filter(|(_, score)| *score == best_score)
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    });
    if let [name] = best.as_slice() {
        return Ok(name.clone());
    }
    let names = fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>()
        .join("、");
    if requested.trim().is_empty() {
        Err(format!(
            "该项目包含多个秘密模块，请在 item 语句中说明要使用的模块，或指定 module：{names}"
        ))
    } else {
        Err(format!("无法唯一匹配秘密模块；可用模块：{names}"))
    }
}

fn interpolate_http_text(
    input: &str,
    replacements: &HashMap<String, String>,
    used: &mut HashSet<String>,
) -> Result<String, String> {
    const OPEN: &str = "{{kru:";
    let mut rest = input;
    let mut output = String::with_capacity(input.len());
    while let Some(start) = rest.find(OPEN) {
        output.push_str(&rest[..start]);
        let after_open = &rest[start + OPEN.len()..];
        let Some(end) = after_open.find("}}") else {
            return Err("KRU 秘密占位符缺少 }}".to_owned());
        };
        let alias = after_open[..end].trim();
        let value = replacements
            .get(alias)
            .ok_or_else(|| format!("KRU HTTP 秘密占位符没有对应绑定：{alias}"))?;
        output.push_str(value);
        used.insert(alias.to_owned());
        rest = &after_open[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

fn collect_secret_placeholders_text(
    input: &str,
    placeholders: &mut HashSet<String>,
) -> Result<(), String> {
    const OPEN: &str = "{{kru:";
    let mut rest = input;
    while let Some(start) = rest.find(OPEN) {
        let after_open = &rest[start + OPEN.len()..];
        let Some(end) = after_open.find("}}") else {
            return Err("KRU HTTP 秘密占位符缺少 }}".to_owned());
        };
        let module = after_open[..end].trim();
        if module.is_empty() {
            return Err("KRU 秘密占位符名称不能为空".to_owned());
        }
        placeholders.insert(module.to_owned());
        rest = &after_open[end + 2..];
    }
    Ok(())
}

fn collect_secret_placeholders_value(
    value: &Value,
    placeholders: &mut HashSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(text) => collect_secret_placeholders_text(text, placeholders)?,
        Value::Array(values) => {
            for value in values {
                collect_secret_placeholders_value(value, placeholders)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_secret_placeholders_value(value, placeholders)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_http_secret_placeholders(input: &HttpSendInput) -> Result<HashSet<String>, String> {
    let mut placeholders = HashSet::new();
    collect_secret_placeholders_text(&input.url, &mut placeholders)?;
    for value in input.headers.values() {
        collect_secret_placeholders_text(value, &mut placeholders)?;
    }
    for value in input.query.values() {
        collect_secret_placeholders_value(value, &mut placeholders)?;
    }
    if let Some(body) = input.body.as_ref() {
        collect_secret_placeholders_value(body, &mut placeholders)?;
    }
    for value in input.form.values() {
        collect_secret_placeholders_value(value, &mut placeholders)?;
    }
    Ok(placeholders)
}

fn interpolate_http_value(
    value: &mut Value,
    replacements: &HashMap<String, String>,
    used: &mut HashSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(text) => *text = interpolate_http_text(text, replacements, used)?,
        Value::Array(values) => {
            for value in values {
                interpolate_http_value(value, replacements, used)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                interpolate_http_value(value, replacements, used)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn interpolate_http_input(
    input: &mut HttpSendInput,
    replacements: &HashMap<String, String>,
) -> Result<HashSet<String>, String> {
    let mut used = HashSet::new();
    input.url = interpolate_http_text(&input.url, replacements, &mut used)?;
    for value in input.headers.values_mut() {
        *value = interpolate_http_text(value, replacements, &mut used)?;
    }
    for value in input.query.values_mut() {
        interpolate_http_value(value, replacements, &mut used)?;
    }
    if let Some(body) = input.body.as_mut() {
        interpolate_http_value(body, replacements, &mut used)?;
    }
    for value in input.form.values_mut() {
        interpolate_http_value(value, replacements, &mut used)?;
    }
    Ok(used)
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
        description = "Optional project query. It may be an exact name, a partial name, or a natural-language phrase containing the project name. Exact case-insensitive matches win."
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
    submitted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct OkOutput {
    ok: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshRunInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the KRU project."
    )]
    host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the KRU project."
    )]
    username: Option<String>,
    #[schemars(
        description = "One command to execute. A hidden module may be used directly as {{kru:password}} or {{kru:module name}} without surrounding quotes; KRU inserts a shell-quoted value."
    )]
    command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional text written directly to the remote command's standard input. It may contain {{kru:module name}} placeholders, which KRU substitutes and redacts locally."
    )]
    stdin: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional remote working directory. A hidden module may be used directly as {{kru:module name}}."
    )]
    cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional execution timeout in seconds. Omit or use 0 for no command deadline."
    )]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to any secret module in item. KRU injects each value into the remote command environment and redacts it from output without returning it to the caller. The command can reference variables such as $KRU_PASSWORD."
    )]
    secret_env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshUploadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the KRU project."
    )]
    host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the KRU project."
    )]
    username: Option<String>,
    #[schemars(
        description = "Local file or directory path on the machine running KRU. Absolute and ~/ paths are accepted; relative paths resolve from the KRU MCP process working directory. Directories are transferred recursively."
    )]
    local_path: String,
    #[serde(default)]
    #[schemars(
        description = "Optional remote file or directory path. Omit it to upload to the SSH login directory using the local source name."
    )]
    remote_path: String,
    #[serde(default = "default_true")]
    #[schemars(description = "Replace an existing destination file. Defaults to true.")]
    overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional transfer timeout in seconds. Omit or use 0 for no total deadline."
    )]
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshDownloadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the KRU project."
    )]
    host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the KRU project."
    )]
    username: Option<String>,
    #[schemars(
        description = "Remote file or directory path on the SSH host. Directories are transferred recursively."
    )]
    remote_path: String,
    #[serde(default)]
    #[schemars(
        description = "Optional local file or directory path. Omit it to save in the KRU MCP process working directory using the remote source name."
    )]
    local_path: String,
    #[serde(default = "default_true")]
    #[schemars(description = "Replace an existing destination file. Defaults to true.")]
    overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional transfer timeout in seconds. Omit or use 0 for no total deadline."
    )]
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpSendInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session has selected a compatible project, or when exactly one compatible project exists."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional absolute URL or path relative to the project's saved service URL. Omit to request the saved service URL itself. An item without a saved service URL requires an absolute URL."
    )]
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
    #[schemars(
        description = "Optional request body. Objects, arrays, numbers, and booleans are encoded as JSON; a string is sent directly as text."
    )]
    body: Option<Value>,
    #[serde(default)]
    #[schemars(description = "Optional URL-encoded form fields. Array values repeat a field.")]
    form: HashMap<String, Value>,
    #[serde(default)]
    #[schemars(description = "Optional multipart file uploads from local paths.")]
    files: Vec<crate::executor::ApiUploadFile>,
    #[serde(default)]
    #[schemars(description = "Optional Base64-encoded raw request body.")]
    body_base64: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional aliases from a placeholder name to a secret module. Usually omit this map and write the module directly, such as {{kru:password}} or {{kru:service token}}. Use secretBindings only when the placeholder should have a different short name. KRU substitutes and redacts values locally."
    )]
    secret_bindings: HashMap<String, String>,
    #[serde(default)]
    #[schemars(
        description = "Optional request timeout in seconds. Omit or use 0 for no total deadline."
    )]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional in-context response-body limit in bytes. Omit or use 0 for no limit. Not used when saveResponseTo is set; very large responses may instead be streamed directly to a file."
    )]
    max_response_bytes: Option<usize>,
    #[serde(default)]
    #[schemars(
        description = "Optional local file path for streaming the complete response body without the in-context size limit. Absolute and ~/ paths are accepted; relative paths resolve from the KRU MCP process working directory. Parent directories are created automatically."
    )]
    save_response_to: Option<String>,
    #[serde(default = "default_true")]
    #[schemars(
        description = "Replace an existing response file. Defaults to true and only applies with saveResponseTo."
    )]
    overwrite_response_file: bool,
}

fn default_http_method() -> String {
    "GET".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_shell_secret_literal(value: &str) -> String {
    #[cfg(windows)]
    {
        format!("'{}'", value.replace('\'', "''"))
    }
    #[cfg(not(windows))]
    {
        crate::executor::shell_quote(value)
    }
}

fn default_terminal_program() -> String {
    #[cfg(windows)]
    {
        "powershell.exe".to_owned()
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_owned())
    }
}

fn submitted_terminal_line(command: &str) -> String {
    if command.ends_with('\n') || command.ends_with('\r') {
        return command.to_owned();
    }
    #[cfg(windows)]
    let newline = "\r\n";
    #[cfg(not(windows))]
    let newline = "\n";
    format!("{command}{newline}")
}

fn transfer_file_name(path: &str, label: &str) -> Result<String, String> {
    let trimmed = path.trim().trim_end_matches(['/', '\\']);
    let name = trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."))
        .ok_or_else(|| format!("无法从{label}推导文件名"))?;
    Ok(name.to_owned())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialFillInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session or terminal has selected a compatible project, or when exactly one project supports credential filling."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional module name or common phrase such as password, API key, private key, or verification code. Omit it when the project has one configured secret, or mention the module in the item phrase."
    )]
    module: String,
    #[serde(default)]
    #[schemars(
        description = "Optional write target: browser, desktop, or terminal. Omit it to use the current running KRU terminal when one exists, otherwise a connected browser extension, otherwise the real operating-system foreground control."
    )]
    target: String,
    #[serde(default)]
    #[schemars(
        description = "Optional terminal session ID. Omit it to use the current KRU terminal; provide it only to switch among multiple terminal sessions."
    )]
    session_id: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Submit after filling. For terminal and desktop targets this presses Enter; for browser targets it submits the focused field's form when one exists. Defaults to false."
    )]
    submit: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalStartInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name or natural-language phrase. Pass it once to bind this terminal session, including when the first command has no secret; later terminal_write calls can then omit item. It is required for placeholders or secretEnv only when no unique or bound project can be inferred."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional program name or path selected by the agent. Omit it to start PowerShell on Windows, or $SHELL with a /bin/sh fallback on macOS and Linux. Native executables start directly; Windows .cmd and .bat scripts use cmd.exe."
    )]
    program: String,
    #[serde(default)]
    #[schemars(
        description = "Arguments passed as individual argv values. A hidden module may be used directly as {{kru:password}} or {{kru:module name}}."
    )]
    args: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional working directory. Absolute and ~/ paths are accepted; relative paths resolve from the KRU MCP process working directory. A hidden module may be used directly as {{kru:module name}}."
    )]
    cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional first line submitted immediately after the terminal starts. When program is omitted, this runs as a command in the platform's default shell. A hidden module may be used directly as {{kru:password}} or {{kru:module name}} without surrounding quotes; KRU handles shell quoting."
    )]
    command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to KRU module name or common module phrase. KRU injects each value into the child process and redacts it from terminal output without returning it to the caller."
    )]
    secret_env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalRunInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name or natural-language phrase. Omit it after this MCP session selected a compatible project, or when the command does not use a hidden module."
    )]
    item: String,
    #[schemars(
        description = "Shell command to run to completion. A hidden module may be used directly as {{kru:password}} or {{kru:module name}} without surrounding quotes; KRU inserts a shell-quoted value."
    )]
    command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional text written directly to the command's standard input. It may contain {{kru:module name}} placeholders, which KRU substitutes and redacts locally."
    )]
    stdin: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional working directory. Absolute, ~/ and MCP-session-relative paths are accepted. A hidden module may be used directly as {{kru:module name}}."
    )]
    cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional execution timeout in seconds. Omit or use 0 for no command deadline."
    )]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to a secret module. KRU injects and redacts each value locally."
    )]
    secret_env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSessionInput {
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to use the most recently started or explicitly used terminal in this MCP session."
    )]
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalReadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to read the current terminal for this MCP session."
    )]
    session_id: String,
    #[serde(default)]
    #[schemars(
        description = "Optional maximum seconds to wait. Omit it for an unlimited wait when until is provided, or for an immediate read when until is absent."
    )]
    wait_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional output substring to wait for. KRU accumulates output until this text appears or the process exits. Omit waitSeconds for no KRU deadline, or set it to bound the wait."
    )]
    until: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalWriteInput {
    #[serde(default)]
    #[schemars(
        description = "Optional KRU project name or natural-language phrase used when text contains a {{kru:module}} placeholder. Omit it when terminal_start or an earlier write already bound this session, or when exactly one enabled project contains usable secrets."
    )]
    item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to write to the current terminal for this MCP session."
    )]
    session_id: String,
    #[schemars(
        description = "Interactive terminal input. A hidden module may be inserted as raw input with {{kru:password}} or {{kru:module name}}. KRU redacts an echoed value from later terminal output."
    )]
    text: String,
    #[serde(default)]
    #[schemars(
        description = "Press Enter after text. KRU uses the correct newline for the current platform and avoids adding a second newline when text already ends with one. Defaults to false."
    )]
    submit: bool,
}

#[tool_router(router = tool_router)]
impl VaultMcp {
    #[tool(
        name = "items_search",
        description = "Discover or select enabled KRU projects, modules, and available actions. A query that finds one project makes it the current project for this MCP session, so later compatible actions can omit item. When the user already named a project and the intended action is clear, call that action directly instead. Query may be the project name or the user's natural-language phrase containing it. Exact case-insensitive name matches win. Only modules explicitly marked agentVisible include value.",
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
        description = "Use one stored module without returning hidden plaintext. Omit item when this MCP session or terminal already selected a compatible project, or when exactly one enabled project supports filling; otherwise pass its name or a natural phrase containing it. KRU infers a sole secret module and understands module names or common phrases such as password, API key, private key, and verification code in either module or item. Omit target to use the current running KRU terminal, otherwise try a connected browser extension and immediately fall back to the real operating-system foreground control; common target aliases are accepted. sessionId is only needed to switch among multiple terminals. Set submit=true to complete the focused form or press Enter in the same call. Call items_search only when discovery or genuine ambiguity remains.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<CredentialFillOutput>(),
        annotations(title = "Fill a credential", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn credential_fill(
        &self,
        Parameters(input): Parameters<CredentialFillInput>,
    ) -> CallToolResult {
        let result: Result<CredentialFillOutput, String> = async {
            let requested_target = normalize_search_text(&input.target);
            let automatic_target = matches!(requested_target.as_str(), "" | "auto" | "default");
            let terminal_target = matches!(
                requested_target.as_str(),
                "terminal" | "term" | "pty" | "shell" | "终端"
            );
            let terminal_session_id = if automatic_target || terminal_target {
                if let Some(session_id) = input.session_id.as_deref() {
                    Some(self.resolve_terminal_session_id(session_id, true)?)
                } else {
                    match self.resolve_terminal_session_id("", true) {
                        Ok(session_id) => Some(session_id),
                        Err(_) if automatic_target => None,
                        Err(error) => return Err(error),
                    }
                }
            } else {
                None
            };
            let connection = if input.item.trim().is_empty() {
                if let Some(session_id) = terminal_session_id {
                    self.resolve_terminal_item(session_id, "")?
                } else {
                    self.resolve_item_for_action("", Some("fill"))?
                }
            } else {
                self.resolve_item_for_action(&input.item, Some("fill"))?
            };
            let item_id = connection.stored.id;
            let target = match requested_target.as_str() {
                "" | "auto" | "default" if terminal_session_id.is_some() => "terminal".to_owned(),
                "" | "auto" | "default" => {
                    if self.browser.fill_configured() {
                        "browser".to_owned()
                    } else {
                        "desktop".to_owned()
                    }
                }
                "browser" | "web" | "chromium" | "浏览器" => "browser".to_owned(),
                "desktop" | "foreground" | "system" | "os" | "桌面" | "前台" => {
                    "desktop".to_owned()
                }
                "terminal" | "term" | "pty" | "shell" | "终端" => "terminal".to_owned(),
                _ => {
                    return Err(
                        "target 可使用 browser、desktop、terminal 或常见同义词，也可直接省略"
                            .to_owned(),
                    );
                }
            };
            let module = resolve_secret_module(&connection, &input.module, &input.item)?;
            let submit = input.submit;
            let action_target = if automatic_target { "auto" } else { &target };
            let actual_target = self
                .track(
                    item_id,
                    format!("向 {action_target} 填写模块 {module}"),
                    async {
                        let (_, kind, mut value) = self
                            .vault
                            .get_secret_value(item_id, &module)
                            .map_err(|error| anyhow::anyhow!(error))?;
                        if kind == "totp" {
                            value = current_totp(&value)?;
                        }
                        match target.as_str() {
                            "browser" => {
                                let browser_failure =
                                    match self.browser.fill_value(value.clone(), submit).await {
                                        Ok(result) if result.status == "ok" => {
                                            return Ok("browser".to_owned());
                                        }
                                        Ok(result) => result.message,
                                        Err(error) => error.to_string(),
                                    };
                                if !automatic_target {
                                    bail!("{browser_failure}");
                                }
                                tokio::task::spawn_blocking(move || {
                                    desktop::fill_focused(&value, submit)
                                })
                                .await
                                .context("桌面输入任务失败")?
                                .with_context(|| {
                                    format!("浏览器填写失败（{browser_failure}），桌面回退也失败")
                                })?;
                                Ok("desktop".to_owned())
                            }
                            "desktop" => {
                                tokio::task::spawn_blocking(move || {
                                    desktop::fill_focused(&value, submit)
                                })
                                .await
                                .context("桌面输入任务失败")??;
                                Ok("desktop".to_owned())
                            }
                            "terminal" => {
                                let session_id = terminal_session_id
                                    .context("没有当前终端会话；请先调用 terminal_start")?;
                                self.terminal.fill_value(session_id, &value, submit)?;
                                self.bind_terminal_item(session_id, item_id);
                                Ok("terminal".to_owned())
                            }
                            _ => unreachable!(),
                        }
                    },
                )
                .await?;
            Ok(CredentialFillOutput {
                target: actual_target,
                module,
                submitted: submit,
            })
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_run",
        description = "Run one local shell command to completion and return stdout, stderr, and exit status in the same call. Use this for ordinary non-interactive local work; use PTY tools only when the process must stay interactive. stdin sends text directly without shell escaping or temporary files. command, stdin, and cwd may contain {{kru:module}} placeholders, and secretEnv may inject a stored module when a child program needs an environment variable. KRU substitutes locally and redacts known values from output. Omit item when the session selected a compatible project or no hidden module is used. There is no sandbox, output limit, or default timeout.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshResponse>(),
        annotations(title = "Run a local command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_run(
        &self,
        Parameters(input): Parameters<TerminalRunInput>,
    ) -> CallToolResult {
        let result: Result<SshResponse, String> = async {
            let mut input = input;
            let mut placeholder_names = HashSet::new();
            collect_secret_placeholders_text(&input.command, &mut placeholder_names)?;
            if let Some(stdin) = input.stdin.as_deref() {
                collect_secret_placeholders_text(stdin, &mut placeholder_names)?;
            }
            if let Some(cwd) = input.cwd.as_deref() {
                collect_secret_placeholders_text(cwd, &mut placeholder_names)?;
            }
            let uses_project = !input.item.trim().is_empty()
                || !placeholder_names.is_empty()
                || !input.secret_env.is_empty();
            if !uses_project {
                return execute_local(
                    None,
                    &input.command,
                    input.cwd.as_deref(),
                    input.timeout_seconds,
                    &HashMap::new(),
                    input.stdin.as_deref(),
                )
                .await
                .map_err(|error| error.to_string());
            }

            let mut connection = self.resolve_item_for_action(&input.item, Some("fill"))?;
            let item_id = connection.stored.id;
            if !placeholder_names.is_empty() {
                let bindings = placeholder_names
                    .iter()
                    .map(|name| (name.clone(), name.clone()))
                    .collect::<HashMap<_, _>>();
                let replacements =
                    self.resolve_secret_bindings(&mut connection, &bindings, &input.item)?;
                let command_replacements = replacements
                    .iter()
                    .map(|(name, value)| (name.clone(), default_shell_secret_literal(value)))
                    .collect::<HashMap<_, _>>();
                let mut used = HashSet::new();
                input.command =
                    interpolate_http_text(&input.command, &command_replacements, &mut used)?;
                if let Some(cwd) = input.cwd.as_mut() {
                    *cwd = interpolate_http_text(cwd, &replacements, &mut used)?;
                }
                if let Some(stdin) = input.stdin.as_mut() {
                    *stdin = interpolate_http_text(stdin, &replacements, &mut used)?;
                }
            }
            let secret_env =
                self.resolve_secret_bindings(&mut connection, &input.secret_env, &input.item)?;
            self.track(
                item_id,
                "执行本地命令".to_owned(),
                execute_local(
                    Some(&connection),
                    &input.command,
                    input.cwd.as_deref(),
                    input.timeout_seconds,
                    &secret_env,
                    input.stdin.as_deref(),
                ),
            )
            .await
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_start",
        description = "Start a program or script in a KRU-managed local PTY and make it the current terminal for this MCP session. Omit program to start the platform's default shell, or provide any program and argv; Windows .cmd and .bat scripts use the native command processor. Pass item once to bind the terminal so later terminal_write placeholders can omit it. command, args, and cwd may use a hidden module directly as {{kru:password}} or {{kru:module name}}; KRU substitutes it locally and redacts it from output. Use secretEnv only when the child program specifically needs an environment variable. command may contain the first line to submit immediately after startup. This is not a sandbox.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalOpenResult>(),
        annotations(title = "Open a managed terminal", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_start(
        &self,
        Parameters(input): Parameters<TerminalStartInput>,
    ) -> CallToolResult {
        let mut input = input;
        let mut placeholder_names = HashSet::new();
        if let Err(error) = collect_secret_placeholders_text(&input.command, &mut placeholder_names)
        {
            return tool_error(error);
        }
        for argument in &input.args {
            if let Err(error) = collect_secret_placeholders_text(argument, &mut placeholder_names) {
                return tool_error(error);
            }
        }
        if let Some(cwd) = input.cwd.as_deref()
            && let Err(error) = collect_secret_placeholders_text(cwd, &mut placeholder_names)
        {
            return tool_error(error);
        }
        let uses_default_shell = input.program.trim().is_empty();
        let program = if uses_default_shell {
            default_terminal_program()
        } else {
            input.program
        };
        let mut environment = HashMap::new();
        let mut redacted_values = Vec::new();
        let mut injected_names = Vec::new();
        let tracked_item = if input.secret_env.is_empty()
            && placeholder_names.is_empty()
            && input.item.trim().is_empty()
        {
            None
        } else {
            let mut connection = match self.resolve_item_for_action(&input.item, Some("fill")) {
                Ok(connection) => connection,
                Err(error) => return tool_error(error),
            };
            if !placeholder_names.is_empty() {
                let bindings = placeholder_names
                    .iter()
                    .map(|name| (name.clone(), name.clone()))
                    .collect::<HashMap<_, _>>();
                let replacements =
                    match self.resolve_secret_bindings(&mut connection, &bindings, &input.item) {
                        Ok(replacements) => replacements,
                        Err(error) => return tool_error(error),
                    };
                let mut used = HashSet::new();
                let command_replacements = if uses_default_shell {
                    replacements
                        .iter()
                        .map(|(name, value)| (name.clone(), default_shell_secret_literal(value)))
                        .collect::<HashMap<_, _>>()
                } else {
                    replacements.clone()
                };
                input.command =
                    match interpolate_http_text(&input.command, &command_replacements, &mut used) {
                        Ok(command) => command,
                        Err(error) => return tool_error(error),
                    };
                for argument in &mut input.args {
                    *argument = match interpolate_http_text(argument, &replacements, &mut used) {
                        Ok(argument) => argument,
                        Err(error) => return tool_error(error),
                    };
                }
                if let Some(cwd) = input.cwd.as_mut() {
                    *cwd = match interpolate_http_text(cwd, &replacements, &mut used) {
                        Ok(cwd) => cwd,
                        Err(error) => return tool_error(error),
                    };
                }
                redacted_values.extend(replacements.into_values());
                injected_names.extend(placeholder_names);
            }
            for (name, module_hint) in input.secret_env {
                let module = match resolve_secret_module(&connection, &module_hint, &input.item) {
                    Ok(module) => module,
                    Err(error) => return tool_error(error),
                };
                let (_, kind, mut secret) =
                    match self.vault.get_secret_value(connection.stored.id, &module) {
                        Ok(secret) => secret,
                        Err(error) => return tool_error(error.to_string()),
                    };
                if kind == "totp" {
                    secret = match current_totp(&secret) {
                        Ok(value) => value,
                        Err(error) => return tool_error(error.to_string()),
                    };
                }
                redacted_values.push(secret.clone());
                environment.insert(name.clone(), secret);
                injected_names.push(name);
            }
            injected_names.sort();
            injected_names.dedup();
            let action = if injected_names.is_empty() {
                "启动项目终端".to_owned()
            } else {
                format!("使用隐藏模块启动终端：{}", injected_names.join("、"))
            };
            Some((connection.stored.id, action))
        };
        let terminal_item_id = tracked_item.as_ref().map(|(item_id, _)| *item_id);
        let start = async {
            self.terminal
                .open_with_env(
                    &program,
                    input.args,
                    input.cwd,
                    environment,
                    redacted_values,
                )
                .and_then(|opened| {
                    if !input.command.trim().is_empty()
                        && let Err(error) = self
                            .terminal
                            .input(opened.session_id, &submitted_terminal_line(&input.command))
                    {
                        let _ = self.terminal.close(opened.session_id);
                        return Err(error);
                    }
                    Ok(opened)
                })
        };
        let result = if let Some((item_id, action)) = tracked_item {
            self.track(item_id, action, start).await
        } else {
            start.await.map_err(|error| error.to_string())
        };
        if let (Ok(opened), Some(item_id)) = (&result, terminal_item_id) {
            self.bind_terminal_item(opened.session_id, item_id);
        }
        if let Ok(opened) = &result {
            self.bind_active_terminal(opened.session_id);
        }
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_write",
        description = "Write interactive input to the current KRU-managed PTY. Omit sessionId for the current terminal; provide it only to switch among multiple terminals. text may contain {{kru:password}} or {{kru:module name}}; KRU inserts the raw value locally and redacts any echo, so later password, sudo, token, or TOTP prompts do not require a separate tool. item may be omitted after terminal_start or an earlier write bound the terminal. Set submit=true to press Enter without constructing a platform-specific newline. Use credential_fill for browser or desktop controls.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Write terminal input", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn terminal_write(
        &self,
        Parameters(input): Parameters<TerminalWriteInput>,
    ) -> CallToolResult {
        let session_id = match self.resolve_terminal_session_id(&input.session_id, true) {
            Ok(session_id) => session_id,
            Err(error) => return tool_error(error),
        };
        let text = if input.submit {
            submitted_terminal_line(&input.text)
        } else {
            input.text.clone()
        };
        let mut placeholder_names = HashSet::new();
        if let Err(error) = collect_secret_placeholders_text(&text, &mut placeholder_names) {
            return tool_error(error);
        }
        if placeholder_names.is_empty() {
            return into_tool_result(
                self.terminal
                    .input(session_id, &text)
                    .map(|_| OkOutput { ok: true })
                    .map_err(|error| error.to_string()),
            );
        }

        let result: Result<OkOutput, String> = async {
            let mut connection = self.resolve_terminal_item(session_id, &input.item)?;
            let item_id = connection.stored.id;
            let bindings = placeholder_names
                .iter()
                .map(|name| (name.clone(), name.clone()))
                .collect::<HashMap<_, _>>();
            let replacements =
                self.resolve_secret_bindings(&mut connection, &bindings, &input.item)?;
            let mut used = HashSet::new();
            let text = interpolate_http_text(&text, &replacements, &mut used)?;
            let redacted_values = replacements.into_values().collect::<Vec<_>>();
            let mut names = placeholder_names.into_iter().collect::<Vec<_>>();
            names.sort();
            self.track(
                item_id,
                format!("使用隐藏模块写入终端：{}", names.join("、")),
                async {
                    self.terminal
                        .input_redacted(session_id, &text, &redacted_values)
                },
            )
            .await?;
            self.bind_terminal_item(session_id, item_id);
            Ok(OkOutput { ok: true })
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_read",
        description = "Read output from the current KRU-managed PTY. Omit sessionId for the current terminal; provide it only to switch among multiple terminals. Add until to accumulate output until that text appears or the process exits; this waits without a KRU deadline unless waitSeconds is set. Without until, waitSeconds waits until any output arrives. With neither, the read is immediate. KRU redacts values it filled and common encodings of those values.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<TerminalReadResult>(),
        annotations(title = "Read terminal output", read_only_hint = true, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn terminal_read(
        &self,
        Parameters(input): Parameters<TerminalReadInput>,
    ) -> CallToolResult {
        let session_id = match self.resolve_terminal_session_id(&input.session_id, false) {
            Ok(session_id) => session_id,
            Err(error) => return tool_error(error),
        };
        let until = input.until.filter(|value| !value.is_empty());
        let deadline = input
            .wait_seconds
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Instant::now() + Duration::from_secs(seconds));
        let mut output = String::new();
        let mut truncated = false;
        let result = loop {
            let mut read = match self.terminal.read(session_id) {
                Ok(read) => read,
                Err(error) => break Err(error.to_string()),
            };
            output.push_str(&read.output);
            truncated |= read.truncated;
            read.output = output.clone();
            read.truncated = truncated;
            if until.is_none() && deadline.is_none() {
                break Ok(read);
            }
            let reached = until
                .as_ref()
                .is_some_and(|expected| read.output.contains(expected));
            let has_enough_output = until.is_none() && !read.output.is_empty();
            let expired = deadline.is_some_and(|deadline| Instant::now() >= deadline);
            if reached || has_enough_output || !read.running || expired {
                break Ok(read);
            }
            let poll_interval = deadline.map_or(Duration::from_millis(50), |deadline| {
                Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now()))
            });
            tokio::time::sleep(poll_interval).await;
        };
        if matches!(&result, Ok(read) if !read.running) {
            self.unbind_terminal_item(session_id);
        }
        into_tool_result(result)
    }

    #[tool(
        name = "terminal_stop",
        description = "Close and clean up the current KRU-managed PTY, terminating the program if it is still running. Omit sessionId for the current terminal; provide it only to switch among multiple terminals.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<OkOutput>(),
        annotations(title = "Close a managed terminal", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn terminal_stop(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
    ) -> CallToolResult {
        let result = self
            .resolve_terminal_session_id(&input.session_id, false)
            .and_then(|session_id| {
                self.terminal
                    .close(session_id)
                    .map_err(|error| error.to_string())?;
                self.unbind_terminal_item(session_id);
                self.clear_active_terminal(session_id);
                Ok(OkOutput { ok: true })
            });
        into_tool_result(result)
    }

    #[tool(
        name = "ssh_run",
        description = "Execute the requested command through KRU SSH. The project only needs a saved password or private key: host, port, and username may be supplied at runtime, with saved values as defaults and port 22 as the fallback. stdin sends text directly to the remote command without shell escaping or temporary files. Omit item after selecting a compatible project or when exactly one project stores SSH authentication. command, stdin, and cwd may use {{kru:module}} placeholders; KRU substitutes and redacts them locally. Use secretEnv only when the remote program needs an environment variable. This grants full command authority and has no observation, diagnostic, restricted, or execution mode.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshResponse>(),
        annotations(title = "Execute an SSH command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn ssh_run(&self, Parameters(input): Parameters<SshRunInput>) -> CallToolResult {
        let result: Result<SshResponse, String> = async {
            let mut input = input;
            let mut placeholder_names = HashSet::new();
            collect_secret_placeholders_text(&input.command, &mut placeholder_names)?;
            if let Some(stdin) = input.stdin.as_deref() {
                collect_secret_placeholders_text(stdin, &mut placeholder_names)?;
            }
            if let Some(cwd) = input.cwd.as_deref() {
                collect_secret_placeholders_text(cwd, &mut placeholder_names)?;
            }
            let mut connection = self.prepare_ssh_connection(
                &input.item,
                input.host.as_deref(),
                input.port,
                input.username.as_deref(),
            )?;
            let item_id = connection.stored.id;
            if !placeholder_names.is_empty() {
                let bindings = placeholder_names
                    .iter()
                    .map(|name| (name.clone(), name.clone()))
                    .collect::<HashMap<_, _>>();
                let replacements =
                    self.resolve_secret_bindings(&mut connection, &bindings, &input.item)?;
                let mut used = HashSet::new();
                let command_replacements = replacements
                    .iter()
                    .map(|(name, value)| (name.clone(), crate::executor::shell_quote(value)))
                    .collect::<HashMap<_, _>>();
                input.command =
                    interpolate_http_text(&input.command, &command_replacements, &mut used)?;
                if let Some(cwd) = input.cwd.as_mut() {
                    *cwd = interpolate_http_text(cwd, &replacements, &mut used)?;
                }
                if let Some(stdin) = input.stdin.as_mut() {
                    *stdin = interpolate_http_text(stdin, &replacements, &mut used)?;
                }
            }
            let secret_env =
                self.resolve_secret_bindings(&mut connection, &input.secret_env, &input.item)?;
            self.track(
                item_id,
                "执行 SSH 命令".to_owned(),
                execute_ssh(
                    &self.vault,
                    &connection,
                    &input.command,
                    input.cwd.as_deref(),
                    input.timeout_seconds,
                    &secret_env,
                    input.stdin.as_deref(),
                ),
            )
            .await
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "ssh_upload",
        description = "Upload one local file or directory through KRU SFTP. The project only needs a saved password or private key; host, port, and username may be supplied at runtime, while saved values remain defaults and port 22 is the fallback. Directories are copied recursively. remotePath is optional and defaults to the local source name in the SSH login directory. Missing parents are created and an existing destination is replaced by default, even when its file/directory kind changed.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshTransferResponse>(),
        annotations(title = "Upload a path over SSH", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn ssh_upload(&self, Parameters(input): Parameters<SshUploadInput>) -> CallToolResult {
        let result: Result<SshTransferResponse, String> = async {
            let connection = self.prepare_ssh_connection(
                &input.item,
                input.host.as_deref(),
                input.port,
                input.username.as_deref(),
            )?;
            let item_id = connection.stored.id;
            let remote_path = if input.remote_path.trim().is_empty() {
                transfer_file_name(&input.local_path, "本地路径")?
            } else {
                input.remote_path
            };
            self.track(
                item_id,
                "上传 SSH 路径".to_owned(),
                ssh_upload(
                    &self.vault,
                    &connection,
                    &input.local_path,
                    &remote_path,
                    input.overwrite,
                    input.timeout_seconds,
                ),
            )
            .await
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "ssh_download",
        description = "Download one remote file or directory through KRU SFTP. The project only needs a saved password or private key; host, port, and username may be supplied at runtime, while saved values remain defaults and port 22 is the fallback. Directories are copied recursively. localPath is optional and defaults to the remote source name in the MCP working directory. Missing parents are created and an existing destination is replaced by default, even when its file/directory kind changed.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<SshTransferResponse>(),
        annotations(title = "Download a path over SSH", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn ssh_download(
        &self,
        Parameters(input): Parameters<SshDownloadInput>,
    ) -> CallToolResult {
        let result: Result<SshTransferResponse, String> = async {
            let connection = self.prepare_ssh_connection(
                &input.item,
                input.host.as_deref(),
                input.port,
                input.username.as_deref(),
            )?;
            let item_id = connection.stored.id;
            let local_path = if input.local_path.trim().is_empty() {
                transfer_file_name(&input.remote_path, "远端路径")?
            } else {
                input.local_path
            };
            self.track(
                item_id,
                "下载 SSH 路径".to_owned(),
                ssh_download(
                    &self.vault,
                    &connection,
                    &input.remote_path,
                    &local_path,
                    input.overwrite,
                    input.timeout_seconds,
                ),
            )
            .await
        }
        .await;
        into_tool_result(result)
    }

    #[tool(
        name = "http_send",
        description = "Send an HTTP request using any enabled KRU project that contains a configured secret, without returning hidden plaintext. Omit item when this MCP session already selected a compatible project or exactly one compatible project exists; otherwise pass its name or a natural phrase containing it. Built-in API/Basic authentication is injected automatically. For any other scheme, write a module directly as {{kru:password}} or {{kru:service token}} inside URL, header, query, JSON/text body, or form values; KRU resolves it locally. secretBindings is needed only for optional short aliases. A saved service URL is only a default; any HTTP/HTTPS URL and method may be used, redirects cross origins, and large responses may stream to saveResponseTo.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<ApiResponse>(),
        annotations(title = "Send an authenticated API request", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn http_send(&self, Parameters(input): Parameters<HttpSendInput>) -> CallToolResult {
        let result: Result<ApiResponse, String> = async {
            let mut input = input;
            for module in collect_http_secret_placeholders(&input)? {
                input
                    .secret_bindings
                    .entry(module.clone())
                    .or_insert(module);
            }
            let has_secret_bindings = !input.secret_bindings.is_empty();
            let mut connection = self.resolve_item_for_action(&input.item, Some("fill"))?;
            let item_id = connection.stored.id;
            self.prepare_http_secret_bindings(&mut connection, &mut input)?;
            let request = ApiRequestInput {
                url: input.url,
                method: input.method,
                query: input.query,
                headers: input.headers,
                body: input.body,
                form: input.form,
                files: input.files,
                body_base64: input.body_base64,
                timeout_seconds: input.timeout_seconds,
                max_response_bytes: input.max_response_bytes,
                save_response_to: input.save_response_to,
                overwrite_response_file: input.overwrite_response_file,
            };
            let mut action = describe_api_request(&connection.stored, &request);
            if has_secret_bindings {
                action = crate::policy::redact(action, &connection.stored, &connection.secrets);
            }
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
            "KRU lets agents use locally saved credentials without receiving hidden plaintext. An explicit item or unique items_search result becomes the current project; later compatible actions may omit item, and a terminal keeps its own binding. When the user names a project and the action is clear, call it directly. Use items_search only for discovery, selection, inspection, or genuine ambiguity. credential_fill understands common module phrases and may infer a sole secret; omit target to use the current running KRU terminal, otherwise a connected browser or foreground control, and use submit=true to complete the login. terminal_start makes the opened PTY current, so terminal_write, terminal_read, terminal_stop, and terminal credential fills should omit sessionId unless deliberately switching among multiple terminals. Use terminal_run for one-shot local commands and PTY tools only for persistent interaction. Direct {{kru:module}} placeholders work in commands, stdin, paths, terminal input, SSH, and HTTP values; KRU substitutes and redacts them locally. terminal_run.stdin and ssh_run.stdin pass scripts, JSON, or other text without shell escaping or temporary files. A password or private-key project can use SSH without saved target metadata: pass host, optional port, and username at runtime; saved values are defaults and port 22 is the fallback. Use secretEnv only when a program needs an environment variable, and HTTP secretBindings only for aliases. Never ask the user to reveal a hidden value. terminal_read.until waits without polling and has no deadline unless waitSeconds is supplied. KRU has no observation, diagnostic, restricted, or execution modes.",
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
    crate::runtime_epoch::monitor_until_invalidated(data_dir)?;
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
            json!([
                "credential_fill",
                "ssh_run",
                "ssh_upload",
                "ssh_download",
                "http_send"
            ])
        );
        for removed in [
            "id",
            "type",
            "capabilities",
            "description",
            "fields",
            "target",
        ] {
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

        let natural_phrase = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("Use TEST_LOGIN in KRU MCP to finish signing in".into()),
            }))
            .await,
        );
        assert_eq!(natural_phrase["items"].as_array().unwrap().len(), 1);
        assert_eq!(natural_phrase["items"][0]["name"], "test login");
        assert_eq!(
            mcp.resolve_item_for_action("Use TEST_LOGIN in KRU MCP to finish signing in", None,)
                .unwrap()
                .stored
                .name,
            "test login"
        );

        let mut api_named = NamedSecrets::default();
        api_named.insert("apiCredential".into(), "mcp-api-marker".into());
        let mut api_secrets = SecretBundle::default();
        api_secrets.named_secrets = api_named;
        let api_saved = vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![
                    ItemModule {
                        kind: "apiCredential".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(false),
                    },
                    ItemModule {
                        kind: "url".into(),
                        name: String::new(),
                        value: "https://example.test".into(),
                        agent_visible: Some(true),
                    },
                ],
                name: "test login api".into(),
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
                secrets: api_secrets,
            })
            .unwrap();
        assert_eq!(
            mcp.resolve_item_for_action("use test login api in KRU MCP", None)
                .unwrap()
                .stored
                .name,
            "test login api"
        );
        assert_eq!(
            mcp.resolve_item_for_action("use test login api in KRU MCP", Some("ssh"))
                .unwrap()
                .stored
                .name,
            "test login"
        );
        assert_eq!(
            mcp.resolve_item_for_action("", Some("http"))
                .unwrap()
                .stored
                .name,
            "test login api"
        );
        assert_eq!(
            mcp.resolve_item_for_action("", None).unwrap().stored.name,
            "test login api"
        );

        let selected = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("use test login in KRU MCP".into()),
            }))
            .await,
        );
        assert_eq!(selected["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            mcp.resolve_item_for_action("", None).unwrap().stored.name,
            "test login"
        );

        let missing = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("does not exist".into()),
            }))
            .await,
        );
        assert!(missing["items"].as_array().unwrap().is_empty());
        assert!(mcp.resolve_item_for_action("", None).is_err());

        vault.set_connection_enabled(saved.id, false).unwrap();
        vault.set_connection_enabled(api_saved.id, false).unwrap();
        let hidden = VaultMcp::new(vault)
            .items_search(Parameters(ItemsSearchInput::default()))
            .await;
        let hidden = serde_json::to_string(&structured_value(&hidden)).unwrap();
        assert!(!hidden.contains("test login"));
        assert!(!hidden.contains("username"));
        assert!(!hidden.contains("password"));
    }

    #[test]
    fn password_item_can_use_runtime_ssh_target_without_saved_target_modules() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut secrets = SecretBundle::default();
        secrets.password = Some("runtime-ssh-password-marker".into());
        vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![ItemModule {
                    kind: "password".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                }],
                name: "Reusable SSH Secret".into(),
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
        let mcp = VaultMcp::new(vault);

        let listed = mcp
            .search_items(ItemsSearchInput {
                query: Some("Reusable SSH Secret".into()),
            })
            .unwrap();
        assert_eq!(
            listed.items[0].actions,
            vec![
                "credential_fill",
                "ssh_run",
                "ssh_upload",
                "ssh_download",
                "http_send"
            ]
        );

        let connection = mcp
            .prepare_ssh_connection(
                "Reusable SSH Secret",
                Some("runtime.example.test"),
                None,
                Some("runtime-user"),
            )
            .unwrap();
        assert_eq!(connection.stored.host, "runtime.example.test");
        assert_eq!(connection.stored.port, 22);
        assert_eq!(connection.secrets.get("username"), Some("runtime-user"));
        assert_eq!(
            connection.secrets.get("password"),
            Some("runtime-ssh-password-marker")
        );
    }

    #[test]
    fn http_secret_placeholders_cover_request_values_without_rescanning_secrets() {
        let mut input = serde_json::from_value::<HttpSendInput>(json!({
            "url": "https://example.test/{{kru:token}}",
            "headers": {"X-Token": "Bearer {{kru:token}}"},
            "query": {"token": "{{kru:token}}", "nested": ["{{kru:second}}"]},
            "body": {"credential": "{{kru:token}}"},
            "form": {"credential": "prefix-{{kru:second}}"}
        }))
        .unwrap();
        let replacements = HashMap::from([
            ("token".to_owned(), "value-{{kru:second}}".to_owned()),
            ("second".to_owned(), "other-value".to_owned()),
        ]);

        assert_eq!(
            collect_http_secret_placeholders(&input).unwrap(),
            HashSet::from(["token".to_owned(), "second".to_owned()])
        );

        let used = interpolate_http_input(&mut input, &replacements).unwrap();

        assert_eq!(input.url, "https://example.test/value-{{kru:second}}");
        assert_eq!(input.headers["X-Token"], "Bearer value-{{kru:second}}");
        assert_eq!(input.query["token"], "value-{{kru:second}}");
        assert_eq!(input.query["nested"][0], "other-value");
        assert_eq!(input.body.unwrap()["credential"], "value-{{kru:second}}");
        assert_eq!(input.form["credential"], "prefix-other-value");
        assert_eq!(
            used,
            HashSet::from(["token".to_owned(), "second".to_owned()])
        );

        let mut used = HashSet::new();
        assert!(interpolate_http_text("{{kru:missing}}", &HashMap::new(), &mut used).is_err());
        assert!(interpolate_http_text("{{kru:token}", &replacements, &mut used).is_err());
    }

    #[tokio::test]
    async fn http_send_uses_any_hidden_module_and_redacts_dynamic_totp() {
        type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

        async fn echo(
            axum::extract::State(seen): axum::extract::State<Seen>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> String {
            let otp = headers
                .get("x-kru-otp")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let received = vec![
                otp,
                uri.to_string(),
                String::from_utf8_lossy(&body).into_owned(),
            ];
            *seen.lock().unwrap() = received.clone();
            received.join("|")
        }

        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let secret = "dynamic-http-secret-marker-7319";
        let totp_seed = "JBSWY3DPEHPK3PXP";
        let mut named = NamedSecrets::default();
        named.insert("service password".into(), secret.into());
        named.insert("totp".into(), totp_seed.into());
        let mut secrets = SecretBundle::default();
        secrets.named_secrets = named;
        vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![
                    ItemModule {
                        kind: "customSecret".into(),
                        name: "service password".into(),
                        value: String::new(),
                        agent_visible: Some(false),
                    },
                    ItemModule {
                        kind: "totp".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(false),
                    },
                ],
                name: "dynamic HTTP item".into(),
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

        let seen = Seen::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let application = axum::Router::new()
            .route("/echo/{secret}", axum::routing::post(echo))
            .with_state(seen.clone());
        let server = tokio::spawn(async move { axum::serve(listener, application).await });

        let mcp = VaultMcp::new(vault.clone());
        let listed = structured_value(
            &mcp.items_search(Parameters(ItemsSearchInput {
                query: Some("dynamic HTTP item".into()),
            }))
            .await,
        );
        assert_eq!(
            listed["items"][0]["actions"],
            json!(["credential_fill", "http_send"])
        );

        let request = serde_json::from_value::<HttpSendInput>(json!({
            "item": "dynamic HTTP item",
            "url": format!("http://{address}/echo/{{{{kru:auth}}}}"),
            "method": "POST",
            "headers": {"X-Kru-Otp": "{{kru:otp}}"},
            "query": {"credential": "{{kru:auth}}"},
            "body": {"credential": "{{kru:auth}}"},
            "secretBindings": {
                "auth": "service password",
                "otp": "totp",
                "unused": "service password"
            }
        }))
        .unwrap();
        let result = structured_value(&mcp.http_send(Parameters(request)).await);
        let output = serde_json::to_string(&result).unwrap();
        let received = seen.lock().unwrap().clone();
        let otp = &received[0];

        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|character| character.is_ascii_digit()));
        assert_ne!(otp, totp_seed);
        assert!(received[1].contains(secret));
        assert!(received[2].contains(secret));
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(secret));
        assert!(!output.contains(totp_seed));
        assert!(!output.contains(otp));

        let direct_request = serde_json::from_value::<HttpSendInput>(json!({
            "item": "dynamic HTTP item",
            "url": format!("http://{address}/echo/{{{{kru:service password}}}}"),
            "method": "POST",
            "headers": {"X-Kru-Otp": "{{kru:totp}}"},
            "query": {"credential": "{{kru:service password}}"},
            "body": {"credential": "{{kru:service password}}"}
        }))
        .unwrap();
        let direct_result = structured_value(&mcp.http_send(Parameters(direct_request)).await);
        let direct_output = serde_json::to_string(&direct_result).unwrap();
        let direct_received = seen.lock().unwrap().clone();
        let direct_otp = &direct_received[0];

        assert_eq!(direct_otp.len(), 6);
        assert!(
            direct_otp
                .chars()
                .all(|character| character.is_ascii_digit())
        );
        assert_ne!(direct_otp, totp_seed);
        assert!(direct_received[1].contains(secret));
        assert!(direct_received[2].contains(secret));
        assert!(direct_output.contains("[REDACTED]"));
        assert!(!direct_output.contains(secret));
        assert!(!direct_output.contains(totp_seed));
        assert!(!direct_output.contains(direct_otp));

        let plain_request = serde_json::from_value::<HttpSendInput>(json!({
            "item": "dynamic HTTP item",
            "url": format!("http://{address}/echo/plain"),
            "method": "POST",
            "body": {"ping": true}
        }))
        .unwrap();
        let plain_result = structured_value(&mcp.http_send(Parameters(plain_request)).await);
        assert_eq!(plain_result["status"], 200);
        assert!(plain_result["body"].as_str().unwrap().contains("plain"));

        let activities = serde_json::to_string(&vault.activities().unwrap()).unwrap();
        assert!(activities.contains("[REDACTED]"));
        assert!(!activities.contains(secret));
        assert!(!activities.contains(totp_seed));
        assert!(!activities.contains(otp));
        server.abort();
    }

    #[tokio::test]
    async fn credential_fill_infers_single_secret_and_terminal_target() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut secrets = SecretBundle::default();
        secrets.password = Some("single-secret-terminal-marker".into());
        vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![ItemModule {
                    kind: "password".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                }],
                name: "single secret".into(),
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

        let mcp = VaultMcp::new(vault);
        #[cfg(windows)]
        let (program, args) = ("cmd.exe", vec!["/Q".to_owned()]);
        #[cfg(not(windows))]
        let (program, args) = ("/bin/sh", Vec::new());
        let terminal = mcp.terminal.open(program, args, None).unwrap();
        mcp.bind_active_terminal(terminal.session_id);
        let output = mcp
            .credential_fill(Parameters(CredentialFillInput {
                item: String::new(),
                module: String::new(),
                target: String::new(),
                session_id: None,
                submit: false,
            }))
            .await;
        let filled = structured_value(&output);
        assert_eq!(filled["module"], "password");
        assert_eq!(filled["target"], "terminal");
        assert_eq!(filled["submitted"], false);
        assert!(
            !serde_json::to_string(&filled)
                .unwrap()
                .contains("single-secret-terminal-marker")
        );
        mcp.terminal.close(terminal.session_id).unwrap();
    }

    #[tokio::test]
    async fn credential_fill_resolves_module_and_target_from_common_phrases() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut named = NamedSecrets::default();
        named.insert("username".into(), "natural-user-marker".into());
        named.insert("password".into(), "natural-password-marker".into());
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
                        agent_visible: Some(false),
                    },
                    ItemModule {
                        kind: "password".into(),
                        name: String::new(),
                        value: String::new(),
                        agent_visible: Some(false),
                    },
                ],
                name: "multi login".into(),
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

        let connection = vault.get_connection(saved.id).unwrap();
        assert_eq!(
            resolve_secret_module(&connection, "user name", "").unwrap(),
            "username"
        );
        assert!(resolve_secret_module(&connection, "", "multi login").is_err());

        let mcp = VaultMcp::new(vault);
        #[cfg(windows)]
        let (program, args) = ("cmd.exe", vec!["/Q".to_owned()]);
        #[cfg(not(windows))]
        let (program, args) = ("/bin/sh", Vec::new());
        let terminal = mcp.terminal.open(program, args, None).unwrap();
        let output = mcp
            .credential_fill(Parameters(CredentialFillInput {
                item: "use the password from multi login in KRU MCP".into(),
                module: String::new(),
                target: "PTY".into(),
                session_id: Some(terminal.session_id.to_string()),
                submit: false,
            }))
            .await;
        let filled = structured_value(&output);
        assert_eq!(filled["module"], "password");
        assert_eq!(filled["target"], "terminal");
        assert!(
            !serde_json::to_string(&filled)
                .unwrap()
                .contains("natural-password-marker")
        );
        mcp.terminal.close(terminal.session_id).unwrap();
    }

    #[tokio::test]
    async fn terminal_start_without_program_opens_the_platform_shell() {
        let directory = tempdir().unwrap();
        let mcp = VaultMcp::new(Vault::open(directory.path().join("vault")).unwrap());
        let output = mcp
            .terminal_start(Parameters(TerminalStartInput {
                item: String::new(),
                program: String::new(),
                args: Vec::new(),
                cwd: None,
                command: String::new(),
                secret_env: HashMap::new(),
            }))
            .await;
        let opened = structured_value(&output);
        let session_id = Uuid::parse_str(opened["sessionId"].as_str().unwrap()).unwrap();
        assert!(!opened["executable"].as_str().unwrap().is_empty());
        #[cfg(windows)]
        assert!(
            opened["executable"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase()
                .ends_with("powershell.exe")
        );
        let stopped = mcp
            .terminal_stop(Parameters(TerminalSessionInput {
                session_id: String::new(),
            }))
            .await;
        assert_ne!(stopped.is_error, Some(true));
        assert!(!mcp.terminal.contains(session_id).unwrap());
    }

    #[tokio::test]
    async fn terminal_start_can_submit_first_command_and_read_can_wait() {
        let directory = tempdir().unwrap();
        let mcp = VaultMcp::new(Vault::open(directory.path().join("vault")).unwrap());
        #[cfg(windows)]
        let (program, args) = ("cmd.exe".to_owned(), vec!["/D".to_owned(), "/Q".to_owned()]);
        #[cfg(not(windows))]
        let (program, args) = (
            "/bin/sh".to_owned(),
            vec![
                "-c".to_owned(),
                "sleep 0.3; IFS= read -r line; printf '%s' \"$line\"".to_owned(),
            ],
        );
        let opened = structured_value(
            &mcp.terminal_start(Parameters(TerminalStartInput {
                item: String::new(),
                program,
                args,
                cwd: None,
                command: if cfg!(windows) {
                    "echo KRU_INITIAL_COMMAND_MARKER".to_owned()
                } else {
                    "KRU_INITIAL_COMMAND_MARKER".to_owned()
                },
                secret_env: HashMap::new(),
            }))
            .await,
        );
        let session_id = opened["sessionId"].as_str().unwrap().to_owned();
        let read = structured_value(
            &mcp.terminal_read(Parameters(TerminalReadInput {
                session_id: String::new(),
                wait_seconds: Some(10),
                until: Some("KRU_INITIAL_COMMAND_MARKER".into()),
            }))
            .await,
        );
        assert!(
            read["output"]
                .as_str()
                .unwrap()
                .contains("KRU_INITIAL_COMMAND_MARKER")
        );
        mcp.terminal
            .close(Uuid::parse_str(&session_id).unwrap())
            .unwrap();
    }

    #[tokio::test]
    async fn terminal_start_injects_and_redacts_hidden_environment_modules() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let secret = "terminal secret ' with spaces $ marker-7391";
        let mut secrets = SecretBundle::default();
        secrets.password = Some(secret.to_owned());
        vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![ItemModule {
                    kind: "password".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                }],
                name: "CLI Login".into(),
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
        let mut other_secrets = SecretBundle::default();
        other_secrets.password = Some("other-terminal-secret-marker".into());
        vault
            .save_connection(ConnectionInput {
                id: None,
                modules: vec![ItemModule {
                    kind: "password".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                }],
                name: "Other CLI Login".into(),
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
                secrets: other_secrets,
            })
            .unwrap();
        let mcp = VaultMcp::new(vault);
        #[cfg(windows)]
        let one_shot_command = "$kruInput=[Console]::In.ReadToEnd(); Write-Output {{kru:password}}; Write-Output $kruInput; [Console]::Error.WriteLine($env:KRU_HIDDEN_ENV)";
        #[cfg(not(windows))]
        let one_shot_command =
            "printf '%s\n' {{kru:password}}; cat; printf '%s\n' \"$KRU_HIDDEN_ENV\" >&2";
        let one_shot = structured_value(
            &mcp.terminal_run(Parameters(TerminalRunInput {
                item: "use CLI Login in KRU MCP".into(),
                command: one_shot_command.into(),
                stdin: Some("stdin={{kru:password}}".into()),
                cwd: None,
                timeout_seconds: Some(10),
                secret_env: HashMap::from([("KRU_HIDDEN_ENV".into(), "password".into())]),
            }))
            .await,
        );
        assert_eq!(one_shot["exitCode"], 0);
        assert!(one_shot["stdout"].as_str().unwrap().contains("[REDACTED]"));
        assert!(one_shot["stderr"].as_str().unwrap().contains("[REDACTED]"));
        assert!(!one_shot.to_string().contains(secret));

        #[cfg(windows)]
        let (program, args) = (
            "powershell.exe".to_owned(),
            vec![
                "-NoProfile".to_owned(),
                "-Command".to_owned(),
                "[Console]::Write($env:KRU_HIDDEN_ENV)".to_owned(),
            ],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "/bin/sh".to_owned(),
            vec![
                "-c".to_owned(),
                "printf '%s' \"$KRU_HIDDEN_ENV\"".to_owned(),
            ],
        );
        let opened = structured_value(
            &mcp.terminal_start(Parameters(TerminalStartInput {
                item: "use CLI Login in KRU MCP".into(),
                program,
                args,
                cwd: None,
                command: String::new(),
                secret_env: HashMap::from([("KRU_HIDDEN_ENV".into(), "password".into())]),
            }))
            .await,
        );
        assert!(!opened.to_string().contains(secret));
        let session_id = opened["sessionId"].as_str().unwrap().to_owned();
        let read = structured_value(
            &mcp.terminal_read(Parameters(TerminalReadInput {
                session_id: session_id.clone(),
                wait_seconds: Some(2),
                until: Some("[REDACTED]".into()),
            }))
            .await,
        );
        let terminal_output = read["output"].as_str().unwrap();
        assert!(terminal_output.contains("[REDACTED]"));
        assert!(!terminal_output.contains(secret));
        mcp.terminal
            .close(Uuid::parse_str(&session_id).unwrap())
            .unwrap();

        #[cfg(windows)]
        let direct_command = "Write-Output {{kru:password}}; exit";
        #[cfg(not(windows))]
        let direct_command = "printf '%s\\n' {{kru:password}}; exit";
        let direct = structured_value(
            &mcp.terminal_start(Parameters(TerminalStartInput {
                item: "use CLI Login in KRU MCP".into(),
                program: String::new(),
                args: Vec::new(),
                cwd: None,
                command: direct_command.into(),
                secret_env: HashMap::new(),
            }))
            .await,
        );
        assert!(!direct.to_string().contains(secret));
        let direct_session_id = direct["sessionId"].as_str().unwrap().to_owned();
        let direct_read = structured_value(
            &mcp.terminal_read(Parameters(TerminalReadInput {
                session_id: direct_session_id.clone(),
                wait_seconds: Some(10),
                until: Some("[REDACTED]".into()),
            }))
            .await,
        );
        let direct_output = direct_read["output"].as_str().unwrap();
        assert!(!direct_output.contains(secret));
        assert!(direct_output.contains("[REDACTED]"));
        mcp.terminal
            .close(Uuid::parse_str(&direct_session_id).unwrap())
            .unwrap();

        #[cfg(windows)]
        let (interactive_program, interactive_args, interactive_text) = (
            "powershell.exe".to_owned(),
            vec![
                "-NoProfile".to_owned(),
                "-Command".to_owned(),
                "Start-Sleep -Milliseconds 300; [Console]::ReadLine() | Write-Output".to_owned(),
            ],
            "{{kru:password}}".to_owned(),
        );
        #[cfg(not(windows))]
        let (interactive_program, interactive_args, interactive_text) = (
            "/bin/sh".to_owned(),
            vec![
                "-c".to_owned(),
                "sleep 0.3; IFS= read -r line; printf '%s' \"$line\"".to_owned(),
            ],
            "{{kru:password}}".to_owned(),
        );
        let interactive = structured_value(
            &mcp.terminal_start(Parameters(TerminalStartInput {
                item: "use CLI Login in KRU MCP".into(),
                program: interactive_program,
                args: interactive_args,
                cwd: None,
                command: String::new(),
                secret_env: HashMap::new(),
            }))
            .await,
        );
        let interactive_session_id = interactive["sessionId"].as_str().unwrap().to_owned();
        let written = mcp
            .terminal_write(Parameters(TerminalWriteInput {
                item: String::new(),
                session_id: String::new(),
                text: interactive_text,
                submit: true,
            }))
            .await;
        assert_ne!(written.is_error, Some(true));
        assert!(!serde_json::to_string(&written).unwrap().contains(secret));
        let interactive_read = structured_value(
            &mcp.terminal_read(Parameters(TerminalReadInput {
                session_id: String::new(),
                wait_seconds: Some(5),
                until: Some("[REDACTED]".into()),
            }))
            .await,
        );
        let interactive_output = interactive_read["output"].as_str().unwrap();
        assert!(!interactive_output.contains(secret));
        assert!(interactive_output.contains("[REDACTED]"));
        let stopped = mcp
            .terminal_stop(Parameters(TerminalSessionInput {
                session_id: String::new(),
            }))
            .await;
        assert_ne!(stopped.is_error, Some(true));
        let interactive_id = Uuid::parse_str(&interactive_session_id).unwrap();
        assert!(
            !mcp.terminal_items
                .read()
                .unwrap()
                .contains_key(&interactive_id)
        );
    }

    #[test]
    fn tool_contracts_have_output_schemas_and_annotations() {
        let router = VaultMcp::tool_router();
        let expected = [
            ("items_search", true, false, true, false),
            ("credential_fill", false, false, false, true),
            ("terminal_run", false, true, false, true),
            ("terminal_start", false, false, false, true),
            ("terminal_write", false, true, false, true),
            ("terminal_read", true, false, false, false),
            ("terminal_stop", false, true, true, false),
            ("ssh_run", false, true, false, true),
            ("ssh_upload", false, true, false, true),
            ("ssh_download", false, true, false, true),
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
                "item": "test login",
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

    #[test]
    fn low_friction_defaults_submit_only_when_requested_and_replace_transfer_targets() {
        let shell = serde_json::from_value::<TerminalStartInput>(json!({})).unwrap();
        assert!(shell.program.is_empty());
        assert!(shell.args.is_empty());
        assert!(shell.cwd.is_none());
        assert!(shell.command.is_empty());
        assert!(shell.item.is_empty());
        assert!(shell.secret_env.is_empty());

        let inferred_fill = serde_json::from_value::<CredentialFillInput>(json!({})).unwrap();
        assert!(inferred_fill.item.is_empty());
        assert!(inferred_fill.module.is_empty());
        assert!(inferred_fill.target.is_empty());
        assert!(inferred_fill.session_id.is_none());
        assert!(!inferred_fill.submit);

        let current_write = serde_json::from_value::<TerminalWriteInput>(json!({
            "text": "continue",
            "submit": true
        }))
        .unwrap();
        assert!(current_write.session_id.is_empty());
        let current_read = serde_json::from_value::<TerminalReadInput>(json!({
            "until": "ready"
        }))
        .unwrap();
        assert!(current_read.session_id.is_empty());
        let current_stop = serde_json::from_value::<TerminalSessionInput>(json!({})).unwrap();
        assert!(current_stop.session_id.is_empty());

        let fill = serde_json::from_value::<CredentialFillInput>(json!({
            "item": "test login",
            "module": "password",
            "target": "browser"
        }))
        .unwrap();
        assert!(!fill.submit);

        let ssh = serde_json::from_value::<SshRunInput>(json!({
            "command": "hostname"
        }))
        .unwrap();
        assert!(ssh.item.is_empty());
        assert!(ssh.host.is_none());
        assert!(ssh.port.is_none());
        assert!(ssh.username.is_none());

        let upload = serde_json::from_value::<SshUploadInput>(json!({
            "localPath": "C:\\fixture.bin"
        }))
        .unwrap();
        assert!(upload.item.is_empty());
        assert!(upload.host.is_none());
        assert!(upload.port.is_none());
        assert!(upload.username.is_none());
        assert!(upload.remote_path.is_empty());
        assert!(upload.overwrite);
        assert_eq!(
            transfer_file_name(&upload.local_path, "本地路径").unwrap(),
            "fixture.bin"
        );

        let download = serde_json::from_value::<SshDownloadInput>(json!({
            "remotePath": "/tmp/fixture.bin"
        }))
        .unwrap();
        assert!(download.item.is_empty());
        assert!(download.host.is_none());
        assert!(download.port.is_none());
        assert!(download.username.is_none());
        assert!(download.local_path.is_empty());
        assert!(download.overwrite);
        assert_eq!(
            transfer_file_name(&download.remote_path, "远端路径").unwrap(),
            "fixture.bin"
        );

        let response = serde_json::from_value::<HttpSendInput>(json!({
            "url": "https://example.test/file",
            "saveResponseTo": "C:\\fixture.bin"
        }))
        .unwrap();
        assert!(response.item.is_empty());
        assert!(response.secret_bindings.is_empty());
        assert!(response.overwrite_response_file);
    }

    #[tokio::test]
    async fn business_failures_are_tool_errors() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let result = VaultMcp::new(vault)
            .terminal_read(Parameters(TerminalReadInput {
                session_id: "not-a-session".into(),
                wait_seconds: None,
                until: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
    }
}
