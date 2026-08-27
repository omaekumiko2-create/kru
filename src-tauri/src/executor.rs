use crate::{
    model::{SecretBundle, StoredConnection},
    policy::{
        assert_api_request_allowed, blocked_header_names, redact, safe_response_headers,
        validate_ssh_command,
    },
    vault::{DecryptedConnection, Vault},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Method,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use russh::{
    ChannelMsg, Disconnect, client,
    keys::{PrivateKeyWithHashAlg, decode_secret_key, ssh_key},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

const MAX_RESULT_LENGTH: usize = 200_000;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiRequestInput {
    #[schemars(description = "Absolute request URL.")]
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub query: HashMap<String, Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
}

fn default_method() -> String {
    "GET".to_owned()
}

pub fn describe_api_request(input: &ApiRequestInput) -> String {
    let method = input.method.trim().to_ascii_uppercase();
    let method = if method.is_empty()
        || method.len() > 20
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        "REQUEST".to_owned()
    } else {
        method
    };
    let Ok(target) = build_api_url(&input.url, &input.query) else {
        return format!("API {method}");
    };
    let origin = target.origin().ascii_serialization();
    let mut path = target.path().to_owned();
    if path.len() > 160 {
        let boundary = path
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= 157)
            .last()
            .unwrap_or(0);
        path.truncate(boundary);
        path.push_str("...");
    }
    format!("API {method} {origin}{path}")
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse {
    pub status: u16,
    pub status_text: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshResponse {
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
}

pub async fn execute_api(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
) -> Result<ApiResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let mut target = build_api_url(&input.url, &input.query)?;
    let method = assert_api_request_allowed(&connection.stored, &input.method, &target)?;
    let method = Method::from_bytes(method.as_bytes()).context("HTTP 方法无效")?;
    let blocked = blocked_header_names(&connection.stored);
    let mut headers = HeaderMap::new();
    for (name, value) in input.headers {
        if blocked.contains(&name.to_lowercase()) {
            continue;
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).context("请求头名称无效")?,
            HeaderValue::from_str(&value).context("请求头内容无效")?,
        );
    }
    apply_api_auth(
        &connection.stored,
        &connection.secrets,
        &mut headers,
        &mut target,
    )?;

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut request = client
        .request(method.clone(), target.clone())
        .headers(headers);
    if method != Method::GET && method != Method::HEAD {
        if let Some(body) = input.body {
            if let Some(text) = body.as_str() {
                request = request.body(text.to_owned());
            } else {
                request = request.json(&body);
            }
        }
    }

    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("API 请求失败"))?;
    let status = response.status();
    let response_is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_json_content_type);
    let safe_headers = safe_response_headers(response.headers())
        .into_iter()
        .collect();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("无法读取 API 响应")? {
        let remaining = MAX_RESULT_LENGTH.saturating_sub(bytes.len());
        if remaining == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    let body = sanitize_api_body(
        String::from_utf8_lossy(&bytes).into_owned(),
        response_is_json,
        bytes.len() == MAX_RESULT_LENGTH,
        &connection.stored,
        &connection.secrets,
    );
    Ok(ApiResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().to_owned(),
        url: redact(target.to_string(), &connection.stored, &connection.secrets),
        headers: safe_headers,
        body,
    })
}

pub async fn execute_ssh(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    cwd: Option<&str>,
) -> Result<SshResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let command = validate_ssh_command(command)?;
    let command = match cwd.map(str::trim).filter(|value| !value.is_empty()) {
        Some(cwd) => format!("cd -- {} && {command}", shell_quote(cwd)),
        None => command,
    };
    tokio::time::timeout(
        Duration::from_secs(60),
        execute_ssh_inner(vault, connection, &command),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SSH 命令执行超时"))?
}

async fn execute_ssh_inner(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
) -> Result<SshResponse> {
    let expected_fingerprint = if connection
        .stored
        .host_fingerprint_host
        .eq_ignore_ascii_case(&connection.stored.host)
        && connection.stored.host_fingerprint_port == connection.stored.port
    {
        normalized_fingerprint(&connection.stored.host_fingerprint)
    } else {
        None
    };
    let observed_fingerprint = Arc::new(Mutex::new(None));
    let handler = SshClient {
        expected_fingerprint: expected_fingerprint.clone(),
        observed_fingerprint: observed_fingerprint.clone(),
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 2,
        ..Default::default()
    });
    let session = client::connect(
        config,
        (connection.stored.host.as_str(), connection.stored.port),
        handler,
    )
    .await;
    let mut session = match session {
        Ok(session) => session,
        Err(error) => {
            let observed = observed_fingerprint
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let (Some(expected), Some(actual)) = (&expected_fingerprint, observed) {
                if expected != &actual {
                    bail!(
                        "SSH 主机身份已变化，已在发送凭据前拒绝连接（预期 {expected}，实际 {actual}）；请确认服务器变更后在 KRU 中重置信任"
                    );
                }
            }
            return Err(anyhow::anyhow!(ssh_connect_error_message(&error)));
        }
    };

    let ssh_auth_type = if connection.stored.ssh_auth_type.is_empty() {
        connection.stored.auth_type.as_str()
    } else {
        connection.stored.ssh_auth_type.as_str()
    };
    let auth = if ssh_auth_type == "privateKey" {
        let username = connection
            .secrets
            .get("username")
            .context("保险库中没有 SSH 用户名")?;
        let private_key = connection
            .secrets
            .private_key
            .as_deref()
            .context("保险库中没有 SSH 私钥")?;
        let key = decode_secret_key(private_key, connection.secrets.passphrase.as_deref())
            .context("无法解析 SSH 私钥或口令不正确")?;
        let hash = session.best_supported_rsa_hash().await?.flatten();
        session
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await?
    } else {
        let username = connection
            .secrets
            .get("username")
            .context("保险库中没有 SSH 用户名")?;
        session
            .authenticate_password(
                username,
                connection
                    .secrets
                    .password
                    .clone()
                    .context("保险库中没有 SSH 密码")?,
            )
            .await?
    };
    if !auth.success() {
        bail!("SSH 认证失败");
    }

    let actual_fingerprint = observed_fingerprint
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .context("SSH 握手没有返回服务器指纹")?;
    if let Err(error) = vault.verify_or_pin_ssh_fingerprint(
        connection.stored.id,
        &actual_fingerprint,
        expected_fingerprint.is_none(),
    ) {
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        return Err(error);
    }

    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    let mut signal = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => append_limited(&mut stdout, &data),
            ChannelMsg::ExtendedData { data, .. } => append_limited(&mut stderr, &data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => signal = Some(format!("{signal_name:?}")),
            _ => {}
        }
    }
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;
    let stdout = redact(
        with_truncation_marker(stdout),
        &connection.stored,
        &connection.secrets,
    );
    let stderr = redact(
        with_truncation_marker(stderr),
        &connection.stored,
        &connection.secrets,
    );
    Ok(SshResponse {
        exit_code,
        signal,
        stdout,
        stderr,
    })
}

pub async fn test_connection(vault: &Vault, connection: &DecryptedConnection) -> Result<String> {
    if connection.stored.has_capability("ssh") {
        let testable = DecryptedConnection {
            stored: connection.stored.clone(),
            secrets: connection.secrets.clone(),
        };
        let result = execute_ssh(vault, &testable, "printf 'mcp-vault-ok'", None).await?;
        if result.stdout != "mcp-vault-ok" {
            bail!("VPS 返回了意外结果：{}", result.stderr);
        }
        Ok("SSH 连接成功".to_owned())
    } else {
        let mut base = Url::parse(&connection.stored.base_url).context("API URL 无效")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = if connection.stored.test_path.trim().is_empty() {
            base.to_string()
        } else {
            base.join(connection.stored.test_path.trim().trim_start_matches('/'))
                .context("API 测试路径无效")?
                .to_string()
        };
        let result = execute_api(
            connection,
            ApiRequestInput {
                url,
                method: "GET".to_owned(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: None,
            },
        )
        .await?;
        Ok(format!("API 已响应：HTTP {}", result.status))
    }
}

fn build_api_url(absolute_url: &str, query: &HashMap<String, Value>) -> Result<Url> {
    let mut target = Url::parse(absolute_url.trim()).context("API 请求 URL 必须是绝对地址")?;
    {
        let mut pairs = target.query_pairs_mut();
        for (name, value) in query {
            match value {
                Value::Array(values) => {
                    for value in values {
                        pairs.append_pair(name, &query_value(value));
                    }
                }
                Value::Null => {}
                value => {
                    pairs.append_pair(name, &query_value(value));
                }
            }
        }
    }
    Ok(target)
}

fn query_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn apply_api_auth(
    connection: &StoredConnection,
    secrets: &SecretBundle,
    headers: &mut HeaderMap,
    target: &mut Url,
) -> Result<()> {
    let auth_type = if connection.http_auth_type.is_empty() {
        connection.auth_type.as_str()
    } else {
        connection.http_auth_type.as_str()
    };
    match auth_type {
        "bearer" => {
            let prefix = if connection.auth_prefix.trim().is_empty() {
                "Bearer"
            } else {
                connection.auth_prefix.trim()
            };
            let value = format!(
                "{prefix} {}",
                secrets
                    .get("apiCredential")
                    .context("保险库中没有 API 凭据")?
            );
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&value)?,
            );
        }
        "apiKey" => {
            let secret = secrets
                .get("apiCredential")
                .context("保险库中没有 API 凭据")?;
            let value = if connection.auth_prefix.trim().is_empty() {
                secret.to_owned()
            } else {
                format!("{} {secret}", connection.auth_prefix.trim())
            };
            if connection.auth_location == "query" {
                replace_query_pair(target, &connection.auth_header, &value);
            } else {
                let name = HeaderName::from_bytes(connection.auth_header.as_bytes())
                    .context("API Key 请求头无效")?;
                headers.insert(name, HeaderValue::from_str(&value)?);
            }
        }
        "basic" => {
            let username = secrets
                .get("username")
                .context("保险库中没有 Basic Auth 用户名")?;
            let password = secrets
                .password
                .as_deref()
                .context("保险库中没有 Basic Auth 密码")?;
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {encoded}"))?,
            );
        }
        "custom" => {
            for header in &connection.api_auth_headers {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .context("自定义认证请求头名称无效")?;
                let value = secrets
                    .get(&header.secret_name)
                    .context("保险库中缺少自定义认证请求头")?;
                headers.insert(name, HeaderValue::from_str(value)?);
            }
        }
        _ => {}
    }
    Ok(())
}

fn replace_query_pair(target: &mut Url, name: &str, value: &str) {
    let retained = target
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    target.set_query(None);
    let mut pairs = target.query_pairs_mut();
    for (key, value) in retained {
        pairs.append_pair(&key, &value);
    }
    pairs.append_pair(name, value);
}

struct SshClient {
    expected_fingerprint: Option<String>,
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        let actual = format!("{}", key.fingerprint(ssh_key::HashAlg::Sha256));
        *self
            .observed_fingerprint
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(actual.clone());
        Ok(self
            .expected_fingerprint
            .as_ref()
            .is_none_or(|expected| expected == &actual))
    }
}

fn is_json_content_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.to_ascii_lowercase().ends_with("+json")
}

fn sanitize_api_body(
    mut body: String,
    is_json: bool,
    truncated: bool,
    connection: &StoredConnection,
    secrets: &SecretBundle,
) -> String {
    if is_json && !body.trim().is_empty() {
        if truncated {
            body = "[JSON 响应超过安全读取限制，正文已隐藏]".to_owned();
        } else {
            body = match serde_json::from_str::<Value>(&body) {
                Ok(mut value) => {
                    redact_sensitive_json_fields(&mut value);
                    serde_json::to_string_pretty(&value)
                        .unwrap_or_else(|_| "[JSON 响应无法安全序列化，正文已隐藏]".to_owned())
                }
                Err(_) => "[JSON 响应无法安全解析，正文已隐藏]".to_owned(),
            };
        }
    } else if truncated {
        body.push_str("\n…[结果已截断]");
    }
    redact(body, connection, secrets)
}

fn redact_sensitive_json_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if is_sensitive_json_key(key) {
                    *value = Value::String("[REDACTED]".to_owned());
                } else {
                    redact_sensitive_json_fields(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_sensitive_json_fields(value);
            }
        }
        _ => {}
    }
}

fn is_sensitive_json_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "apikey"
            | "privatekey"
            | "authorization"
            | "cookie"
            | "credential"
    )
}

fn normalized_fingerprint(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else if value.starts_with("SHA256:") {
        Some(value.to_owned())
    } else {
        Some(format!("SHA256:{value}"))
    }
}

fn ssh_connect_error_message(error: &impl Display) -> String {
    let raw = error.to_string();
    let normalized = raw.to_ascii_lowercase();
    if normalized.contains("disconnected") || normalized.contains("connection closed") {
        return "SSH 握手被远端提前关闭（凭据尚未发送）；请检查远端 sshd、VPN/代理链路或 SSH 并发限制".to_owned();
    }
    if normalized.contains("timed out")
        || normalized.contains("timeout")
        || normalized.contains("os error 10060")
    {
        return "SSH TCP 连接超时；请检查目标地址、VPN/代理路由和 22 端口".to_owned();
    }
    if normalized.contains("connection refused") || normalized.contains("os error 10061") {
        return "SSH 端口拒绝连接；目标可达，但 sshd 未监听该端口".to_owned();
    }
    if normalized.contains("no common") || normalized.contains("key exchange") {
        return format!("SSH 握手算法不兼容：{raw}");
    }
    format!("SSH 连接或握手失败：{raw}")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn append_limited(target: &mut Vec<u8>, chunk: &[u8]) {
    let remaining = MAX_RESULT_LENGTH.saturating_sub(target.len());
    target.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
}

fn with_truncation_marker(bytes: Vec<u8>) -> String {
    let truncated = bytes.len() == MAX_RESULT_LENGTH;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        text.push_str("\n…[结果已截断]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ApiAuthHeader, SecretEnvelope};
    use axum::{Router, extract::Query, http::HeaderMap as AxumHeaders, routing::get};
    use chrono::Utc;
    use uuid::Uuid;

    fn stored(base_url: String) -> StoredConnection {
        StoredConnection {
            id: Uuid::new_v4(),
            kind: "api".into(),
            capabilities: vec!["fill".into(), "http".into()],
            modules: vec![],
            name: "local-api".into(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            description: String::new(),
            host: String::new(),
            port: 0,
            username: String::new(),
            auth_type: "bearer".into(),
            ssh_auth_type: String::new(),
            http_auth_type: String::new(),
            private_key_name: String::new(),
            host_fingerprint: String::new(),
            host_fingerprint_host: String::new(),
            host_fingerprint_port: 0,
            base_url,
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_path_prefixes: vec!["/v1/".into()],
            test_path: String::new(),
            cli: None,
            browser: None,
            credential: None,
            secret: None,
            encrypted_secrets: SecretEnvelope {
                version: 1,
                nonce: String::new(),
                ciphertext: String::new(),
            },
        }
    }

    #[tokio::test]
    async fn api_injects_vault_auth_blocks_override_truncates_and_redacts() {
        async fn response(headers: AxumHeaders) -> String {
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            format!("auth={auth}\n{}", "x".repeat(MAX_RESULT_LENGTH + 100))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });

        let mut secrets = SecretBundle::default();
        secrets.token = Some("vault-secret-token-9384".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer attacker-value".into());
        headers.insert("Cookie".into(), "session=attacker".into());
        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query: HashMap::new(),
                headers,
                body: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert!(!result.body.contains("vault-secret-token-9384"));
        assert!(!result.body.contains("attacker-value"));
        assert!(result.body.contains("[REDACTED]"));
        assert!(result.body.contains("[结果已截断]"));
        server.abort();
    }

    #[tokio::test]
    async fn api_key_query_replaces_agent_value_without_exposing_secret() {
        async fn response(Query(query): Query<HashMap<String, String>>) -> &'static str {
            if query.get("key").map(String::as_str) == Some("vault-query-key-9384") {
                "correct"
            } else {
                "wrong"
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });
        let mut item = stored(format!("http://{address}/v1/"));
        item.auth_type = "apiKey".into();
        item.auth_location = "query".into();
        item.auth_header = "key".into();
        let mut secrets = SecretBundle::default();
        secrets.api_key = Some("vault-query-key-9384".into());
        let connection = DecryptedConnection {
            stored: item,
            secrets,
        };
        let mut query = HashMap::new();
        query.insert("key".into(), Value::String("agent-value".into()));

        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query,
                headers: HashMap::new(),
                body: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.body, "correct");
        assert!(!result.url.contains("vault-query-key-9384"));
        assert!(result.url.contains("[REDACTED]"));
        server.abort();
    }

    #[test]
    fn custom_auth_headers_are_injected_from_named_secrets() {
        let mut item = stored("https://api.example.test/v1/".to_owned());
        item.auth_type = "custom".into();
        item.api_auth_headers = vec![ApiAuthHeader {
            name: "X-Client-Secret".into(),
            secret_name: "apiHeader_client".into(),
        }];
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiHeader_client".into(), "custom-secret-9384".into());
        let mut headers = HeaderMap::new();
        let mut target = Url::parse("https://api.example.test/v1/").unwrap();

        apply_api_auth(&item, &secrets, &mut headers, &mut target).unwrap();

        assert_eq!(
            headers.get("x-client-secret").unwrap(),
            "custom-secret-9384"
        );
        assert!(blocked_header_names(&item).contains("x-client-secret"));
    }

    #[test]
    fn api_activity_description_omits_query_and_records_origin_and_path() {
        let mut query = HashMap::new();
        query.insert("token".into(), Value::String("must-not-be-logged".into()));
        let description = describe_api_request(&ApiRequestInput {
            url: "https://api.example.test/v1/items".into(),
            method: "post".into(),
            query,
            headers: HashMap::new(),
            body: None,
        });
        assert_eq!(description, "API POST https://api.example.test/v1/items");
        assert!(!description.contains("token"));
        assert!(!description.contains("must-not-be-logged"));
    }

    #[test]
    fn json_response_redacts_sensitive_fields_and_hides_unsafe_json() {
        let connection = stored("https://api.example.test/v1/".to_owned());
        let mut secrets = SecretBundle::default();
        secrets.token = Some("stored-token-9384".to_owned());
        let body = sanitize_api_body(
            r#"{
                "name": "visible",
                "access_token": "new-access-token",
                "nested": [{"client-secret": "new-client-secret"}],
                "credential": {"value": "new-credential"},
                "echo": "stored-token-9384"
            }"#
            .to_owned(),
            true,
            false,
            &connection,
            &secrets,
        );
        assert!(body.contains("visible"));
        for secret in [
            "new-access-token",
            "new-client-secret",
            "new-credential",
            "stored-token-9384",
        ] {
            assert!(!body.contains(secret), "JSON leaked {secret}");
        }

        let malformed = sanitize_api_body(
            r#"{"token":"new-token""#.to_owned(),
            true,
            false,
            &connection,
            &secrets,
        );
        assert_eq!(malformed, "[JSON 响应无法安全解析，正文已隐藏]");

        let truncated = sanitize_api_body(
            r#"{"name":"partial""#.to_owned(),
            true,
            true,
            &connection,
            &secrets,
        );
        assert_eq!(truncated, "[JSON 响应超过安全读取限制，正文已隐藏]");
        assert!(is_json_content_type(
            "application/problem+json; charset=utf-8"
        ));
    }

    #[test]
    fn ssh_connect_errors_name_the_failed_stage() {
        assert!(ssh_connect_error_message(&"Disconnected").contains("握手"));
        assert!(ssh_connect_error_message(&"os error 10060").contains("TCP"));
        assert!(ssh_connect_error_message(&"connection refused").contains("端口"));
    }
}
