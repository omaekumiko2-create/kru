use crate::{
    crypto::{decrypt_backup, encrypt_backup},
    model::{ImportSummary, PublicConnection, SecretBundle, SecretEnvelope},
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupFile {
    format: String,
    version: u8,
    kdf: String,
    cipher: String,
    salt: String,
    payload: SecretEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    format: String,
    version: u8,
    created_at: String,
    connections: Vec<BackupConnection>,
}

#[derive(Serialize, Deserialize)]
struct BackupConnection {
    connection: PublicConnection,
    secrets: SecretBundle,
}

pub fn export_to_file(vault: &Vault, path: impl AsRef<Path>, password: &str) -> Result<()> {
    let connections = vault
        .export_connections()?
        .into_iter()
        .map(|(connection, secrets)| BackupConnection {
            connection,
            secrets,
        })
        .collect();
    let payload = BackupPayload {
        format: "mcp-vault-portable".to_owned(),
        version: 2,
        created_at: Utc::now().to_rfc3339(),
        connections,
    };
    let plain = serde_json::to_vec(&payload).context("无法序列化备份")?;
    let (salt, payload) = encrypt_backup(password, &plain)?;
    let file = BackupFile {
        format: "mcp-vault-backup".to_owned(),
        version: 1,
        kdf: "argon2id".to_owned(),
        cipher: "xchacha20poly1305".to_owned(),
        salt,
        payload,
    };
    let bytes = serde_json::to_vec_pretty(&file).context("无法生成备份文件")?;
    let mut writer = AtomicWriteFile::open(path.as_ref()).context("无法创建备份文件")?;
    writer.write_all(&bytes).context("无法写入备份文件")?;
    writer.commit().context("无法提交备份文件")?;
    Ok(())
}

pub fn import_from_file(
    vault: &Vault,
    path: impl AsRef<Path>,
    password: &str,
) -> Result<ImportSummary> {
    let bytes = fs::read(path.as_ref()).context("无法读取备份文件")?;
    let file: BackupFile = serde_json::from_slice(&bytes).context("备份文件格式无效")?;
    if file.format != "mcp-vault-backup" || file.version != 1 {
        bail!("不支持的备份文件版本");
    }
    if file.kdf != "argon2id" || file.cipher != "xchacha20poly1305" {
        bail!("不支持的备份加密方式");
    }
    let plain = decrypt_backup(password, &file.salt, &file.payload)?;
    let payload: BackupPayload =
        serde_json::from_slice(&plain).context("备份密码错误或内容损坏")?;
    if payload.format != "mcp-vault-portable" || !matches!(payload.version, 1 | 2) {
        bail!("不支持的备份内容版本");
    }
    vault.merge_connections(
        payload
            .connections
            .into_iter()
            .map(|item| (item.connection, item.secrets))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionInput, SecretBundle};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn input(id: Uuid, name: &str, token: &str) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets.token = Some(token.to_owned());
        ConnectionInput {
            id: Some(id),
            kind: "api".into(),
            capabilities: vec!["fill".into(), "http".into()],
            modules: vec![],
            name: name.into(),
            enabled: true,
            description: String::new(),
            host: String::new(),
            port: 0,
            username: String::new(),
            auth_type: "bearer".into(),
            ssh_auth_type: String::new(),
            http_auth_type: "bearer".into(),
            private_key_import_path: String::new(),
            host_fingerprint: String::new(),
            security_mode: String::new(),
            allowed_commands: vec![],
            base_url: "https://api.example.test/v1/".into(),
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
            remove_secret_names: vec![],
            secrets,
        }
    }

    #[test]
    fn encrypted_backup_contains_no_marker_plaintext() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let path = directory.path().join("test.mvault");
        export_to_file(&vault, &path, "a-valid-password").unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("private_key"));
        assert!(contents.contains("xchacha20poly1305"));
    }

    #[test]
    fn import_overwrites_same_uuid_and_keeps_same_name_with_other_uuid() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source")).unwrap();
        let target = Vault::open(directory.path().join("target")).unwrap();
        let shared_id = Uuid::new_v4();
        source
            .save_connection(input(shared_id, "from-backup", "backup-token-123"))
            .unwrap();
        target
            .save_connection(input(shared_id, "old-local", "old-token-123"))
            .unwrap();
        target
            .save_connection(input(Uuid::new_v4(), "from-backup", "other-token-123"))
            .unwrap();

        let path = directory.path().join("merge.mvault");
        export_to_file(&source, &path, "portable-password").unwrap();
        let summary = import_from_file(&target, &path, "portable-password").unwrap();
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.added, 0);
        let connections = target.list_connections().unwrap();
        assert_eq!(connections.len(), 2);
        assert_eq!(
            connections
                .iter()
                .filter(|item| item.name == "from-backup")
                .count(),
            2
        );
        assert_eq!(
            target
                .get_connection(shared_id)
                .unwrap()
                .secrets
                .token
                .as_deref(),
            Some("backup-token-123")
        );
    }
}
