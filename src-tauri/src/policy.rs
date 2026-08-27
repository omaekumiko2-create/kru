use crate::model::{SecretBundle, StoredConnection};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{HeaderMap, HeaderName};
use std::collections::HashSet;
use url::Url;

pub fn validate_ssh_command(command: &str) -> Result<String> {
    let value = command.trim();
    if value.is_empty() {
        bail!("命令不能为空");
    }
    if value.chars().count() > 4_000 {
        bail!("命令过长");
    }
    Ok(value.to_owned())
}

pub fn assert_api_request_allowed(
    connection: &StoredConnection,
    method: &str,
    target: &Url,
) -> Result<String> {
    let normalized = method.trim().to_uppercase();
    if !connection
        .allowed_methods
        .iter()
        .any(|allowed| allowed == &normalized)
    {
        bail!("该连接不允许 {normalized} 请求");
    }
    if connection.base_url.trim().is_empty() {
        let secure = target.scheme() == "https"
            || (target.scheme() == "http"
                && target
                    .host_str()
                    .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1")));
        if !secure {
            bail!("运行时 API URL 必须使用 HTTPS；仅本机回环地址允许 HTTP");
        }
    } else {
        let base = Url::parse(&connection.base_url)?;
        if target.origin() != base.origin() {
            bail!("请求不能离开已保存 API 的域名");
        }
    }
    if !connection.allowed_path_prefixes.is_empty()
        && !connection
            .allowed_path_prefixes
            .iter()
            .any(|prefix| target.path().starts_with(prefix))
    {
        bail!("请求路径不在允许范围内");
    }
    Ok(normalized)
}

pub fn blocked_header_names(connection: &StoredConnection) -> HashSet<String> {
    let mut blocked = [
        "authorization".to_owned(),
        "cookie".to_owned(),
        "host".to_owned(),
        "proxy-authorization".to_owned(),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    if connection.auth_location != "query" && !connection.auth_header.is_empty() {
        blocked.insert(connection.auth_header.to_lowercase());
    }
    blocked.extend(
        connection
            .api_auth_headers
            .iter()
            .map(|header| header.name.to_lowercase()),
    );
    blocked
}

pub fn safe_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let allowed = [
        "content-type",
        "date",
        "etag",
        "x-request-id",
        "retry-after",
        "ratelimit-remaining",
        "x-ratelimit-remaining",
    ];
    allowed
        .into_iter()
        .filter_map(|name| {
            let header = HeaderName::from_static(name);
            headers
                .get(&header)
                .and_then(|value| value.to_str().ok())
                .map(|value| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

pub fn redact(mut value: String, connection: &StoredConnection, secrets: &SecretBundle) -> String {
    let raw_secrets = secrets.non_empty_values();
    value = redact_values(value, &raw_secrets);
    let mut candidates = Vec::new();
    for secret in &raw_secrets {
        candidates.push(STANDARD.encode(secret.as_bytes()));
        candidates.push(url::form_urlencoded::byte_serialize(secret.as_bytes()).collect());
    }
    if let Some(token) = &secrets.token {
        candidates.push(format!("Bearer {token}"));
    }
    let http_auth_type = if connection.http_auth_type.is_empty() {
        connection.auth_type.as_str()
    } else {
        connection.http_auth_type.as_str()
    };
    if http_auth_type == "basic" {
        if let (Some(username), Some(password)) = (secrets.get("username"), &secrets.password) {
            candidates.push(STANDARD.encode(format!("{username}:{password}")));
        }
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));
    candidates.dedup();
    for candidate in candidates {
        if candidate.len() >= 4 {
            value = value.replace(&candidate, "[REDACTED]");
        }
    }
    value
}

pub fn redact_values(mut value: String, raw_secrets: &[String]) -> String {
    for candidate in redaction_candidates(raw_secrets) {
        value = value.replace(&candidate, "[REDACTED]");
    }
    value
}

pub fn redaction_candidates(raw_secrets: &[String]) -> Vec<String> {
    let mut candidates = raw_secrets.to_vec();
    for secret in raw_secrets {
        candidates.push(STANDARD.encode(secret.as_bytes()));
        candidates.push(url::form_urlencoded::byte_serialize(secret.as_bytes()).collect());
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));
    candidates.dedup();
    candidates.retain(|candidate| !candidate.is_empty());
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretEnvelope;
    use chrono::Utc;
    use uuid::Uuid;

    fn connection() -> StoredConnection {
        StoredConnection {
            id: Uuid::new_v4(),
            kind: "api".into(),
            capabilities: vec!["fill".into(), "http".into()],
            modules: vec![],
            name: "test".into(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            description: String::new(),
            host: String::new(),
            port: 0,
            username: String::new(),
            auth_type: "bearer".into(),
            ssh_auth_type: String::new(),
            http_auth_type: "bearer".into(),
            private_key_name: String::new(),
            host_fingerprint: String::new(),
            host_fingerprint_host: String::new(),
            host_fingerprint_port: 0,
            base_url: "https://api.example.com/v1/".into(),
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

    #[test]
    fn api_stays_on_origin_and_path() {
        let connection = connection();
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("https://api.example.com/v1/items").unwrap()
            )
            .is_ok()
        );
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("https://evil.example/v1/items").unwrap()
            )
            .is_err()
        );
        assert!(
            assert_api_request_allowed(
                &connection,
                "POST",
                &Url::parse("https://api.example.com/v1/items").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn addressless_api_accepts_safe_runtime_urls_only() {
        let mut connection = connection();
        connection.base_url.clear();
        connection.allowed_path_prefixes.clear();
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("https://api.example.com/v2/items").unwrap()
            )
            .is_ok()
        );
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("http://127.0.0.1:8080/test").unwrap()
            )
            .is_ok()
        );
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("http://localhost:3000/test").unwrap()
            )
            .is_ok()
        );
        assert!(
            assert_api_request_allowed(
                &connection,
                "GET",
                &Url::parse("http://api.example.com/test").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn redacts_raw_and_bearer_secret() {
        let connection = connection();
        let mut secrets = SecretBundle::default();
        secrets.token = Some("abc123secret".into());
        let result = redact(
            "Bearer abc123secret / abc123secret".into(),
            &connection,
            &secrets,
        );
        assert!(!result.contains("abc123secret"));
    }

    #[test]
    fn ssh_validation_accepts_commands_without_classifying_their_purpose() {
        for command in [
            "hostname",
            "nvidia-smi --query-gpu=name,memory.total --format=csv",
            "head /srv/app/.env | grep TOKEN",
            "mkdir -p /srv/train && python train.py --epochs 20",
            "printf fixture-ok > /tmp/kru-probe",
        ] {
            assert!(
                validate_ssh_command(command).is_ok(),
                "valid command should be accepted: {command}"
            );
        }
        assert!(validate_ssh_command("  ").is_err());
        assert!(validate_ssh_command(&"x".repeat(4_001)).is_err());
    }

    #[test]
    fn blocks_auth_cookie_proxy_and_configured_auth_header() {
        let blocked = blocked_header_names(&connection());
        for name in [
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-api-key",
        ] {
            assert!(blocked.contains(name));
        }
    }
}
