use crate::model::{SecretBundle, StoredConnection};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::HeaderMap;
use std::collections::HashSet;
use url::Url;

const MAX_SSH_COMMAND_BYTES: usize = 1_048_576;

pub fn validate_ssh_command(command: &str) -> Result<String> {
    let value = command.trim();
    if value.is_empty() {
        bail!("命令不能为空");
    }
    if value.contains('\0') {
        bail!("SSH 命令不能包含空字符");
    }
    if value.len() > MAX_SSH_COMMAND_BYTES {
        bail!("SSH 命令超过 1 MiB 上限");
    }
    Ok(value.to_owned())
}

pub fn assert_api_request_allowed(
    connection: &StoredConnection,
    method: &str,
    target: &Url,
) -> Result<String> {
    let normalized = method.trim().to_uppercase();
    if connection.base_url.trim().is_empty() {
        if !is_safe_api_url(target) {
            bail!("运行时 API URL 必须使用 HTTPS；仅本机回环地址允许 HTTP");
        }
    } else {
        let base = Url::parse(&connection.base_url)?;
        if target.origin() != base.origin() {
            bail!("请求不能离开已保存 API 的域名");
        }
    }
    Ok(normalized)
}

pub fn redirect_target_allowed(initial: &Url, target: &Url) -> bool {
    target.origin() == initial.origin() && is_safe_api_url(target)
}

fn is_safe_api_url(target: &Url) -> bool {
    target.scheme() == "https"
        || (target.scheme() == "http"
            && target
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1")))
}

pub fn blocked_header_names(connection: &StoredConnection) -> HashSet<String> {
    let mut blocked = ["host".to_owned()].into_iter().collect::<HashSet<_>>();
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

pub fn visible_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
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
    fn saved_api_stays_on_origin_without_hidden_method_or_path_modes() {
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
        for (method, target) in [
            ("POST", "https://api.example.com/v1/items"),
            ("PROPFIND", "https://api.example.com/other/path"),
        ] {
            assert!(
                assert_api_request_allowed(&connection, method, &Url::parse(target).unwrap())
                    .is_ok()
            );
        }
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
    fn redirects_follow_only_the_same_safe_origin() {
        let initial = Url::parse("https://api.example.com/v1/items").unwrap();
        assert!(redirect_target_allowed(
            &initial,
            &Url::parse("https://api.example.com/v2/items").unwrap()
        ));
        assert!(!redirect_target_allowed(
            &initial,
            &Url::parse("https://other.example/v2/items").unwrap()
        ));
        assert!(!redirect_target_allowed(
            &initial,
            &Url::parse("http://api.example.com/v2/items").unwrap()
        ));
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
        assert!(validate_ssh_command("printf 'a\0b'").is_err());
        assert!(validate_ssh_command(&"x".repeat(256_000)).is_ok());
        assert!(validate_ssh_command(&"x".repeat(MAX_SSH_COMMAND_BYTES)).is_ok());
        assert!(validate_ssh_command(&"x".repeat(MAX_SSH_COMMAND_BYTES + 1)).is_err());
    }

    #[test]
    fn reserves_only_host_and_headers_that_kru_injects() {
        let blocked = blocked_header_names(&connection());
        for name in ["host", "x-api-key"] {
            assert!(blocked.contains(name));
        }
        for name in ["authorization", "cookie", "proxy-authorization"] {
            assert!(!blocked.contains(name));
        }
    }

    #[test]
    fn response_headers_keep_service_metadata_but_not_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("x-feature-state", "ready".parse().unwrap());
        headers.append("set-cookie", "session=server-secret".parse().unwrap());

        let visible = visible_response_headers(&headers)
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            visible.get("x-feature-state").map(String::as_str),
            Some("ready")
        );
        assert!(!visible.contains_key("set-cookie"));
    }
}
