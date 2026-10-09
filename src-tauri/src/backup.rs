use crate::{
    crypto::{decrypt_bytes, encrypt_bytes},
    model::{ImportSummary, PortableConnection, SecretBundle, SecretEnvelope},
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
use zeroize::Zeroize;

const BACKUP_VERSION: u8 = 4;

fn backup_aad(version: u8) -> Result<&'static [u8]> {
    match version {
        3 => Ok(b"kru/backup/v3"),
        BACKUP_VERSION => Ok(b"kru/backup/v4"),
        _ => bail!("不支持的备份文件版本"),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupFile {
    format: String,
    version: u8,
    cipher: String,
    unlock_key: String,
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
    connection: PortableConnection,
    secrets: SecretBundle,
}

// Only the v3 import boundary knows about obsolete connection metadata.
// Secret payloads are deserialized directly into their zeroizing type.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V3BackupPayload {
    format: String,
    version: u8,
    connections: Vec<V3BackupConnection>,
}

#[derive(Deserialize)]
struct V3BackupConnection {
    connection: serde_json::Value,
    secrets: SecretBundle,
}

pub fn export_to_file(vault: &Vault, path: impl AsRef<Path>) -> Result<()> {
    reject_vault_internal_export_path(vault, path.as_ref())?;
    let payload = backup_payload(vault)?;
    let mut plain = serde_json::to_vec(&payload).context("无法序列化备份")?;
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| anyhow::anyhow!("无法生成备份密钥：{error}"))?;
    let encrypted = encrypt_bytes(&key, &plain, backup_aad(BACKUP_VERSION)?);
    plain.zeroize();
    let payload = encrypted?;
    let unlock_key = STANDARD_NO_PAD.encode(key);
    key.zeroize();
    let file = BackupFile {
        format: "mcp-vault-backup".to_owned(),
        version: BACKUP_VERSION,
        cipher: "xchacha20poly1305".to_owned(),
        unlock_key,
        payload,
    };
    write_backup_file(path.as_ref(), &file)
}

fn backup_payload(vault: &Vault) -> Result<BackupPayload> {
    let connections = vault
        .export_connections()?
        .into_iter()
        .map(|(connection, secrets)| BackupConnection {
            connection,
            secrets,
        })
        .collect();
    Ok(BackupPayload {
        format: "mcp-vault-portable".to_owned(),
        version: BACKUP_VERSION,
        created_at: Utc::now().to_rfc3339(),
        connections,
    })
}

fn write_backup_file(path: &Path, file: &BackupFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&file).context("无法生成备份文件")?;
    let mut writer = AtomicWriteFile::open(path).context("无法创建备份文件")?;
    writer.write_all(&bytes).context("无法写入备份文件")?;
    writer.commit().context("无法提交备份文件")?;
    Ok(())
}

fn reject_vault_internal_export_path(vault: &Vault, path: &Path) -> Result<()> {
    let data_dir = fs::canonicalize(vault.data_dir()).context("无法确认保险库目录")?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("无法确认当前目录")?
            .join(path)
    };
    let target = if absolute.exists() {
        fs::canonicalize(&absolute).context("无法确认备份目标路径")?
    } else {
        let parent = absolute.parent().context("备份目标路径无效")?;
        let name = absolute.file_name().context("备份目标文件名无效")?;
        fs::canonicalize(parent)
            .context("无法确认备份目标目录")?
            .join(name)
    };
    if target.starts_with(&data_dir) {
        bail!("备份文件不能保存在 KRU 数据目录内，请选择其他位置");
    }
    Ok(())
}

pub fn import_from_file(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportSummary> {
    let file = read_backup_file(path.as_ref())?;
    validate_backup_file(&file)?;
    let mut plain = decrypt_automatic_backup(&file)?;
    let result = merge_backup_payload(vault, &plain, file.version);
    plain.zeroize();
    result
}

fn read_backup_file(path: &Path) -> Result<BackupFile> {
    let bytes = fs::read(path).context("无法读取备份文件")?;
    serde_json::from_slice(&bytes).context("备份文件格式无效")
}

fn validate_backup_file(file: &BackupFile) -> Result<()> {
    if file.format != "mcp-vault-backup" {
        bail!("不支持的备份文件版本");
    }
    backup_aad(file.version)?;
    if file.cipher != "xchacha20poly1305" {
        bail!("不支持的备份加密方式");
    }
    Ok(())
}

fn decrypt_automatic_backup(file: &BackupFile) -> Result<Vec<u8>> {
    let decoded = STANDARD_NO_PAD
        .decode(&file.unlock_key)
        .context("备份自动解锁材料无效")?;
    let mut key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("备份自动解锁材料长度无效"))?;
    let result = decrypt_bytes(&key, &file.payload, backup_aad(file.version)?);
    key.zeroize();
    result
}

fn merge_backup_payload(vault: &Vault, plain: &[u8], version: u8) -> Result<ImportSummary> {
    if version == 3 {
        let payload: V3BackupPayload = serde_json::from_slice(plain).context("备份内容损坏")?;
        if payload.format != "mcp-vault-portable" || payload.version != 3 {
            bail!("不支持的备份内容版本");
        }
        let mut connections = Vec::with_capacity(payload.connections.len());
        for mut item in payload.connections {
            if let Some(connection) = item.connection.as_object_mut() {
                for obsolete in [
                    "hostFingerprint",
                    "hostFingerprintHost",
                    "hostFingerprintPort",
                    "allowedMethods",
                    "allowedPathPrefixes",
                ] {
                    connection.remove(obsolete);
                }
            }
            let connection = serde_json::from_value(item.connection).context("备份项目格式无效")?;
            connections.push((connection, item.secrets));
        }
        return vault.merge_connections(connections);
    }
    let payload: BackupPayload = serde_json::from_slice(plain).context("备份内容损坏")?;
    if payload.format != "mcp-vault-portable"
        || payload.version != BACKUP_VERSION
        || version != BACKUP_VERSION
    {
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
        secrets
            .named_secrets
            .insert("apiCredential".into(), token.to_owned());
        ConnectionInput {
            id: Some(id),
            modules: vec![
                crate::model::ItemModule {
                    kind: "url".into(),
                    value: "https://api.example.test/v1/".into(),
                    ..Default::default()
                },
                crate::model::ItemModule {
                    kind: "apiCredential".into(),
                    ..Default::default()
                },
            ],
            name: name.into(),
            enabled: true,
            description: String::new(),
            http_auth_type: "bearer".into(),
            private_key_import_path: String::new(),
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets,
        }
    }

    #[test]
    fn automatic_backup_contains_no_marker_plaintext() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        vault
            .save_connection(input(
                Uuid::new_v4(),
                "private-service-marker",
                "marker-secret-123",
            ))
            .unwrap();
        let path = directory.path().join("test.mvault");
        export_to_file(&vault, &path).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("marker-secret-123"));
        assert!(!contents.contains("private_key"));
        assert!(contents.contains("xchacha20poly1305"));
        assert!(contents.contains("unlockKey"));
        let file: BackupFile = serde_json::from_str(&contents).unwrap();
        assert_eq!(file.version, BACKUP_VERSION);
        let plain = decrypt_automatic_backup(&file).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(payload["version"], BACKUP_VERSION);
        assert!(
            payload["connections"][0]["connection"]
                .get("allowedMethods")
                .is_none()
        );
        assert!(
            payload["connections"][0]["connection"]
                .get("hostFingerprint")
                .is_none()
        );
    }

    #[test]
    fn v3_backup_import_preserves_all_secret_payloads_and_current_transport_settings() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source")).unwrap();
        let target_dir = directory.path().join("target");
        let target = Vault::open(target_dir.clone()).unwrap();
        let id = Uuid::new_v4();
        source
            .save_connection(input(id, "v3 API", "api-marker"))
            .unwrap();
        let mut fixture = serde_json::to_value(backup_payload(&source).unwrap()).unwrap();
        fixture["version"] = serde_json::json!(3);
        let metadata = fixture["connections"][0]["connection"]
            .as_object_mut()
            .unwrap();
        metadata.insert(
            "hostFingerprint".into(),
            serde_json::json!("old-fingerprint"),
        );
        metadata.insert("hostFingerprintHost".into(), serde_json::json!("old-host"));
        metadata.insert("hostFingerprintPort".into(), serde_json::json!(22));
        metadata.insert("allowedMethods".into(), serde_json::json!(["GET"]));
        metadata.insert("allowedPathPrefixes".into(), serde_json::json!(["/v1/"]));
        metadata.insert("testPath".into(), serde_json::json!("/health"));
        fixture["connections"][0]["secrets"] = serde_json::json!({
            "privateKeyName": "existing-key",
            "password": "password-marker",
            "passphrase": "passphrase-marker",
            "privateKey": "private-key-marker",
            "token": "token-marker",
            "apiKey": "api-key-marker",
            "namedSecrets": {
                "username": "username-marker",
                "apiCredential": "api-marker",
                "extra": "extra-marker"
            }
        });
        let key = [31_u8; 32];
        let plain = serde_json::to_vec(&fixture).unwrap();
        let file = BackupFile {
            format: "mcp-vault-backup".into(),
            version: 3,
            cipher: "xchacha20poly1305".into(),
            unlock_key: STANDARD_NO_PAD.encode(key),
            payload: encrypt_bytes(&key, &plain, backup_aad(3).unwrap()).unwrap(),
        };
        let path = directory.path().join("existing-v3.mvault");
        write_backup_file(&path, &file).unwrap();
        assert_eq!(import_from_file(&target, &path).unwrap().added, 1);
        drop(target);

        let reopened = Vault::open(target_dir).unwrap();
        let imported = reopened.get_connection(id).unwrap();
        assert_eq!(imported.stored.http_auth_type, "bearer");
        assert_eq!(imported.stored.auth_header, "X-API-Key");
        assert_eq!(imported.stored.base_url, "https://api.example.test/v1/");
        assert_eq!(imported.stored.test_path, "/health");
        for (field, expected) in [
            ("password", "password-marker"),
            ("passphrase", "passphrase-marker"),
            ("privateKey", "private-key-marker"),
            ("token", "token-marker"),
            ("apiKey", "api-key-marker"),
            ("username", "username-marker"),
            ("apiCredential", "api-marker"),
            ("extra", "extra-marker"),
        ] {
            assert_eq!(imported.secrets.get(field), Some(expected), "{field}");
        }
        assert_eq!(
            imported.secrets.private_key_name.as_deref(),
            Some("existing-key")
        );
        let public = imported.stored.public(Some(&imported.secrets));
        assert_eq!(public.capabilities, ["fill", "http"]);
        assert!(public.can_test);
    }

    #[test]
    fn backup_version_is_bound_to_its_ciphertext() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let path = directory.path().join("version.mvault");
        export_to_file(&vault, &path).unwrap();
        let mut file = read_backup_file(&path).unwrap();
        file.version = 3;
        write_backup_file(&path, &file).unwrap();
        assert!(import_from_file(&vault, &path).is_err());
    }

    #[test]
    fn export_refuses_to_overwrite_files_inside_the_vault_directory() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();

        for name in ["vault.json", "master.key", "vault.lock", "backup.mvault"] {
            let error = export_to_file(&vault, vault.data_dir().join(name)).unwrap_err();
            assert!(error.to_string().contains("数据目录"));
        }
    }

    #[test]
    fn import_appends_conflicts_numbers_names_and_merges_reimports() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source")).unwrap();
        let target = Vault::open(directory.path().join("target")).unwrap();
        let shared_id = Uuid::new_v4();
        source
            .save_connection(input(shared_id, "service", "backup-token-123"))
            .unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service(2)", "backup-token-456"))
            .unwrap();
        target
            .save_connection(input(shared_id, "service", "local-token-123"))
            .unwrap();

        let path = directory.path().join("merge.mvault");
        export_to_file(&source, &path).unwrap();
        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(summary.merged, 0);
        let connections = target.list_connections().unwrap();
        assert_eq!(connections.len(), 3);
        assert_eq!(connections[0].name, "service");
        assert_eq!(connections[1].name, "service(2)");
        assert_eq!(connections[2].name, "service(3)");
        assert_eq!(
            target
                .get_connection(shared_id)
                .unwrap()
                .secrets
                .get("apiCredential"),
            Some("local-token-123")
        );

        let mut locally_edited = input(connections[1].id, "service(2)", "backup-token-123");
        locally_edited.description = "local note".to_owned();
        target.save_connection(locally_edited).unwrap();

        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 0);
        assert_eq!(summary.merged, 2);
        assert_eq!(target.list_connections().unwrap().len(), 3);
    }

    #[test]
    fn import_treats_an_existing_numbered_name_as_literal_until_the_base_exists() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source-numbered")).unwrap();
        let target = Vault::open(directory.path().join("target-numbered")).unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service", "shared-token"))
            .unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service(2)", "backup-token"))
            .unwrap();
        target
            .save_connection(input(Uuid::new_v4(), "service(2)", "shared-token"))
            .unwrap();

        let path = directory.path().join("numbered.mvault");
        export_to_file(&source, &path).unwrap();
        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(summary.merged, 0);
        let names = target
            .list_connections()
            .unwrap()
            .into_iter()
            .map(|item| item.name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["service(2)", "service", "service(3)"]);

        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 0);
        assert_eq!(summary.merged, 2);
    }
}
