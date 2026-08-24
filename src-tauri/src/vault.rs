use crate::{
    api_catalog,
    crypto::{MasterKey, create_owner_pin_verifier, verify_owner_pin},
    model::{
        Activity, ApiAuthHeader, AppState, ApprovalRequest, ConnectionInput, ImportSummary,
        ItemModule, McpState, NewActivity, OwnerEditorDraft, OwnerSecretField, OwnerSecretView,
        PublicConnection, SecretBundle, SecretField, SecretProfile, SecurityState, Settings,
        StoredConnection, StoredEditorDraft, VaultDocument, normalize_item_capabilities,
    },
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use url::Url;
use uuid::Uuid;

const MAX_ACTIVITIES: usize = 3_000;

#[derive(Clone)]
pub struct Vault {
    inner: Arc<VaultInner>,
}

struct VaultInner {
    data_dir: PathBuf,
    vault_path: PathBuf,
    lock_path: PathBuf,
    key: MasterKey,
}

pub struct DecryptedConnection {
    pub stored: StoredConnection,
    pub secrets: SecretBundle,
}

impl Vault {
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&data_dir).context("无法创建保险库目录")?;
        let vault_path = data_dir.join("vault.json");
        let key = MasterKey::load_or_create(&data_dir, vault_path.exists())?;
        let vault = Self {
            inner: Arc::new(VaultInner {
                lock_path: data_dir.join("vault.lock"),
                data_dir,
                vault_path,
                key,
            }),
        };

        if !vault.inner.vault_path.exists() {
            let document = VaultDocument {
                version: 7,
                settings: Settings::default(),
                browser_bridge_secret: None,
                owner_pin: None,
                connections: Vec::new(),
                editor_drafts: Vec::new(),
                activities: Vec::new(),
                approvals: Vec::new(),
            };
            vault.with_exclusive_lock(|_| vault.write_document_unlocked(&document))?;
        } else {
            vault.migrate_to_v7()?;
        }
        Ok(vault)
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn storage_label(&self) -> &str {
        self.inner.key.source()
    }

    fn migrate_to_v7(&self) -> Result<()> {
        self.with_exclusive_lock(|_| {
            let bytes = fs::read(&self.inner.vault_path).context("无法读取保险库")?;
            let mut document: VaultDocument =
                serde_json::from_slice(&bytes).context("保险库文件格式无效")?;
            let reset_legacy_fingerprints = match document.version {
                7 => return Ok(()),
                6 | 5 => false,
                4 => true,
                3 => true,
                2 => {
                    for connection in &mut document.connections {
                        migrate_connection_to_v3(connection, &self.inner.key)?;
                    }
                    true
                }
                version => bail!("不支持的保险库版本 {version}"),
            };
            for connection in &mut document.connections {
                let mut secrets: SecretBundle =
                    self.inner.key.decrypt(&connection.encrypted_secrets)?;
                let legacy_capabilities =
                    normalize_item_capabilities(&connection.capabilities, &connection.kind);
                if connection.ssh_auth_type.is_empty()
                    && legacy_capabilities.iter().any(|value| value == "ssh")
                {
                    connection.ssh_auth_type = connection.auth_type.clone();
                }
                if connection.http_auth_type.is_empty()
                    && legacy_capabilities.iter().any(|value| value == "http")
                {
                    connection.http_auth_type = connection.auth_type.clone();
                }
                if connection.modules.is_empty() {
                    connection.modules = modules_from_legacy(connection, &mut secrets);
                }
                connection.modules = normalize_modules(connection.modules.clone())?;
                let capabilities = derive_capabilities(
                    &connection.modules,
                    &secrets,
                    &connection.http_auth_type,
                    &connection.api_auth_headers,
                );
                let auth_kind = if capabilities.iter().any(|value| value == "ssh") {
                    "ssh"
                } else if capabilities.iter().any(|value| value == "http") {
                    "api"
                } else {
                    "secret"
                };
                normalize_active_auth_secrets(
                    auth_kind,
                    &connection.auth_type,
                    &connection.api_auth_headers,
                    &mut secrets,
                    &mut connection.private_key_name,
                );
                connection.encrypted_secrets = self.inner.key.encrypt(&secrets)?;
                connection.capabilities = capabilities;
                connection.kind.clear();
                if reset_legacy_fingerprints {
                    // Versions before v5 did not record which endpoint owned a fingerprint.
                    // It is unsafe to carry that trust forward, so force one fresh TOFU pin.
                    connection.host_fingerprint.clear();
                    connection.host_fingerprint_host.clear();
                    connection.host_fingerprint_port = 0;
                }
            }
            document.version = 7;
            self.write_document_unlocked(&document)
        })
    }

    pub fn owner_pin_configured(&self) -> Result<bool> {
        Ok(self.read_document()?.owner_pin.is_some())
    }

    pub fn set_owner_pin(&self, pin: &str) -> Result<()> {
        let verifier = create_owner_pin_verifier(pin)?;
        self.update_document(|document| {
            if document.owner_pin.is_some() {
                bail!("PIN 已设置");
            }
            document.owner_pin = Some(verifier);
            Ok(())
        })
    }

    pub fn verify_owner_pin(&self, pin: &str) -> Result<bool> {
        let document = self.read_document()?;
        let verifier = document.owner_pin.as_ref().context("尚未设置 PIN")?;
        verify_owner_pin(pin, verifier)
    }

    pub fn owner_secret_view(&self, id: Uuid) -> Result<OwnerSecretView> {
        let connection = self.get_connection(id)?;
        let fields = connection
            .secrets
            .available_fields(connection.stored.secret.as_ref())
            .into_iter()
            .filter_map(|field| {
                connection
                    .secrets
                    .get(&field.name)
                    .map(|value| OwnerSecretField {
                        name: field.name,
                        kind: field.kind,
                        value: value.to_owned(),
                    })
            })
            .collect();
        Ok(OwnerSecretView { id, fields })
    }

    pub fn list_editor_drafts(&self) -> Result<Vec<OwnerEditorDraft>> {
        let document = self.read_document()?;
        let mut drafts = document
            .editor_drafts
            .into_iter()
            .map(|draft| {
                Ok(OwnerEditorDraft {
                    id: draft.id,
                    updated_at: draft.updated_at,
                    input: self.inner.key.decrypt(&draft.payload)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        drafts.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        Ok(drafts)
    }

    pub fn save_editor_draft(
        &self,
        id: Option<Uuid>,
        mut input: ConnectionInput,
    ) -> Result<OwnerEditorDraft> {
        input.id = None;
        input.name = clean_text(&input.name, 80);
        input.description = clean_text(&input.description, 240);
        let id = id.unwrap_or_else(Uuid::new_v4);
        let updated_at = Utc::now().to_rfc3339();
        let payload = self.inner.key.encrypt(&input)?;
        self.update_document(|document| {
            document.editor_drafts.clear();
            document.editor_drafts.push(StoredEditorDraft {
                id,
                updated_at: updated_at.clone(),
                payload,
            });
            Ok(())
        })?;
        Ok(OwnerEditorDraft {
            id,
            updated_at,
            input,
        })
    }

    pub fn delete_editor_draft(&self, id: Uuid) -> Result<()> {
        self.update_document(|document| {
            document.editor_drafts.retain(|draft| draft.id != id);
            Ok(())
        })
    }

    pub fn settings(&self) -> Result<Settings> {
        Ok(self.read_document()?.settings)
    }

    pub fn update_settings(&self, mut next: Settings) -> Result<Settings> {
        if next.browser_port < 1024 {
            bail!("本地端口必须在 1024–65535 之间");
        }
        next.language = if next.language.eq_ignore_ascii_case("en") {
            "en".to_owned()
        } else {
            "zh".to_owned()
        };
        next.close_behavior = if next.close_behavior.eq_ignore_ascii_case("exit") {
            "exit".to_owned()
        } else {
            "tray".to_owned()
        };
        self.update_document(|document| {
            // Pairing state is changed only by the authenticated bridge handshake.
            next.browser_paired = document.settings.browser_paired;
            // Agent onboarding is changed only by its dedicated command.
            next.agent_mcp_onboarding_version = document.settings.agent_mcp_onboarding_version;
            if !next.approval_mode {
                document.approvals.clear();
            }
            document.settings = next.clone();
            Ok(())
        })?;
        Ok(next)
    }

    pub fn complete_agent_mcp_onboarding(&self) -> Result<()> {
        self.update_document(|document| {
            document.settings.agent_mcp_onboarding_version = 1;
            Ok(())
        })
    }

    pub fn browser_bridge_secret(&self) -> Result<String> {
        self.update_document_with_result(|document| {
            if document.browser_bridge_secret.is_none() {
                document.browser_bridge_secret = Some(self.inner.key.encrypt(&random_token()?)?);
            }
            self.inner.key.decrypt(
                document
                    .browser_bridge_secret
                    .as_ref()
                    .context("Browser Bridge 密钥缺失")?,
            )
        })
    }

    pub fn rotate_browser_bridge_secret(&self) -> Result<()> {
        let encrypted = self.inner.key.encrypt(&random_token()?)?;
        self.update_document(|document| {
            document.browser_bridge_secret = Some(encrypted);
            document.settings.browser_paired = false;
            Ok(())
        })
    }

    pub fn set_browser_paired(&self, paired: bool) -> Result<()> {
        self.update_document(|document| {
            document.settings.browser_paired = paired;
            Ok(())
        })
    }

    pub fn list_connections(&self) -> Result<Vec<PublicConnection>> {
        let document = self.read_document()?;
        document
            .connections
            .iter()
            .map(|connection| {
                let secrets: SecretBundle =
                    self.inner.key.decrypt(&connection.encrypted_secrets)?;
                Ok(connection.public(Some(&secrets)))
            })
            .collect()
    }

    pub fn get_connection(&self, id: Uuid) -> Result<DecryptedConnection> {
        let document = self.read_document()?;
        let stored = document
            .connections
            .into_iter()
            .find(|connection| connection.id == id)
            .context("找不到该连接")?;
        let secrets = self.inner.key.decrypt(&stored.encrypted_secrets)?;
        Ok(DecryptedConnection { stored, secrets })
    }

    pub fn get_secret_value(&self, id: Uuid, field: &str) -> Result<(String, String, String)> {
        let connection = self.get_connection(id)?;
        if !connection.stored.enabled {
            bail!("该项目已禁用");
        }
        let field = clean_text(field, 80);
        let metadata = connection
            .secrets
            .available_fields(connection.stored.secret.as_ref())
            .into_iter()
            .find(|candidate| candidate.name == field)
            .context("该项目没有这个秘密字段")?;
        let value = connection
            .secrets
            .get(&field)
            .context("该秘密字段尚未配置")?
            .to_owned();
        Ok((connection.stored.name, metadata.kind, value))
    }

    pub fn verify_or_pin_ssh_fingerprint(
        &self,
        id: Uuid,
        fingerprint: &str,
        may_pin: bool,
    ) -> Result<String> {
        let actual = normalize_ssh_fingerprint(fingerprint)?;
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            let connection = document
                .connections
                .iter_mut()
                .find(|connection| connection.id == id)
                .context("找不到该连接")?;
            if !connection.has_capability("ssh") {
                bail!("所选项目的模块尚未形成可用 SSH 动作");
            }
            let trust_matches_endpoint = connection
                .host_fingerprint_host
                .eq_ignore_ascii_case(&connection.host)
                && connection.host_fingerprint_port == connection.port;
            if !trust_matches_endpoint {
                connection.host_fingerprint.clear();
                connection.host_fingerprint_host.clear();
                connection.host_fingerprint_port = 0;
            }
            let current = connection.host_fingerprint.trim();
            if current.is_empty() {
                if !may_pin {
                    bail!("SSH 主机信任在连接期间已被重置，请重新连接");
                }
                connection.host_fingerprint = actual.clone();
                connection.host_fingerprint_host = connection.host.clone();
                connection.host_fingerprint_port = connection.port;
                connection.updated_at = Utc::now().to_rfc3339();
                self.write_document_unlocked(&document)?;
                return Ok(actual.clone());
            }
            if normalize_ssh_fingerprint(current)? != actual {
                bail!("SSH 主机信任在连接期间发生变化，已取消命令");
            }
            Ok(actual.clone())
        })
    }

    pub fn reset_ssh_fingerprint(&self, id: Uuid) -> Result<()> {
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            let connection = document
                .connections
                .iter_mut()
                .find(|connection| connection.id == id)
                .context("找不到该连接")?;
            if !connection.has_capability("ssh") {
                bail!("所选项目的模块尚未形成可用 SSH 动作");
            }
            if !connection.host_fingerprint.is_empty()
                || !connection.host_fingerprint_host.is_empty()
                || connection.host_fingerprint_port != 0
            {
                connection.host_fingerprint.clear();
                connection.host_fingerprint_host.clear();
                connection.host_fingerprint_port = 0;
                connection.updated_at = Utc::now().to_rfc3339();
                self.write_document_unlocked(&document)?;
            }
            Ok(())
        })
    }

    pub fn save_connection(&self, mut input: ConnectionInput) -> Result<PublicConnection> {
        self.update_document_with_result(|document| {
            let existing_index = input.id.and_then(|id| {
                document
                    .connections
                    .iter()
                    .position(|connection| connection.id == id)
            });
            let existing = existing_index.map(|index| document.connections[index].clone());
            let mut secrets = if let Some(connection) = &existing {
                self.inner
                    .key
                    .decrypt::<SecretBundle>(&connection.encrypted_secrets)?
            } else {
                SecretBundle::default()
            };
            if !input.modules.is_empty() {
                input.modules = normalize_modules(input.modules.clone())?;
                if let Some(connection) = &existing {
                    let retained = input
                        .modules
                        .iter()
                        .filter_map(ItemModule::secret_name)
                        .collect::<Vec<_>>();
                    for removed in connection
                        .modules
                        .iter()
                        .filter_map(ItemModule::secret_name)
                        .filter(|name| !retained.contains(name))
                    {
                        input.remove_secret_names.push(removed.to_owned());
                    }
                }
                input.host = module_value(&input.modules, "host")
                    .unwrap_or_default()
                    .to_owned();
                input.port = module_value(&input.modules, "port")
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(0);
                input.base_url = module_value(&input.modules, "url")
                    .unwrap_or_default()
                    .to_owned();
                if input
                    .modules
                    .iter()
                    .any(|module| module.kind == "apiCredential")
                {
                    input.auth_type = "auto".to_owned();
                    input.http_auth_type = "auto".to_owned();
                }
            }
            merge_secret_bundle(&mut secrets, &input.secrets);
            if !input.username.trim().is_empty() {
                secrets
                    .named_secrets
                    .insert("username".to_owned(), clean_text(&input.username, 160));
            }
            for name in &input.remove_secret_names {
                secrets.named_secrets.remove(name.trim());
                match name.trim() {
                    "password" => secrets.password = None,
                    "passphrase" => secrets.passphrase = None,
                    "privateKey" | "private_key" => {
                        secrets.private_key = None;
                        secrets.private_key_name = None;
                    }
                    "token" => secrets.token = None,
                    "apiKey" | "api_key" => secrets.api_key = None,
                    "apiCredential" | "api_credential" => {
                        secrets.named_secrets.remove("apiCredential");
                        secrets.token = None;
                        secrets.api_key = None;
                    }
                    _ => {}
                }
            }

            // v7 callers send modules directly.  Keep accepting the old GUI/input shape
            // while existing installations and backups cross the migration boundary.
            if input.modules.is_empty()
                && (!input.capabilities.is_empty() || !input.kind.trim().is_empty())
            {
                input.modules = normalize_modules(modules_from_legacy_input(&input, &secrets))?;
                input.host = module_value(&input.modules, "host")
                    .unwrap_or_default()
                    .to_owned();
                input.port = module_value(&input.modules, "port")
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(0);
                input.base_url = module_value(&input.modules, "url")
                    .unwrap_or_default()
                    .to_owned();
                if input
                    .modules
                    .iter()
                    .any(|module| module.kind == "apiCredential")
                {
                    input.auth_type = "auto".to_owned();
                    input.http_auth_type = "auto".to_owned();
                }
            }

            input.name = clean_text(&input.name, 80);
            if input.name.is_empty() {
                bail!("项目名称不能为空");
            }
            if input.modules.is_empty() {
                bail!("项目至少需要一个模块");
            }

            let mut imported_key_name = existing
                .as_ref()
                .map(|v| v.private_key_name.clone())
                .unwrap_or_default();
            if !input.private_key_import_path.trim().is_empty() {
                let path = PathBuf::from(input.private_key_import_path.trim());
                let metadata = fs::metadata(&path).context("无法读取 SSH 私钥")?;
                if metadata.len() > 1_048_576 {
                    bail!("SSH 私钥文件不能超过 1 MB");
                }
                secrets.private_key =
                    Some(fs::read_to_string(&path).context("SSH 私钥必须是文本格式")?);
                imported_key_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("SSH KEY")
                    .to_owned();
                secrets.private_key_name = Some(imported_key_name.clone());
            }

            prepare_auto_api(&mut input, &mut secrets)?;

            let now = Utc::now().to_rfc3339();
            let mut stored = normalize_connection_v7(
                input,
                existing.as_ref(),
                &secrets,
                imported_key_name,
                now,
            )?;
            stored.encrypted_secrets = self.inner.key.encrypt(&secrets)?;
            let public = stored.public(Some(&secrets));
            if let Some(index) = existing_index {
                document.connections[index] = stored;
            } else {
                document.connections.push(stored);
            }
            Ok(public)
        })
    }

    pub fn delete_connection(&self, id: Uuid) -> Result<()> {
        self.update_document(|document| {
            let before = document.connections.len();
            document
                .connections
                .retain(|connection| connection.id != id);
            if before == document.connections.len() {
                bail!("找不到该连接");
            }
            Ok(())
        })
    }

    pub fn set_connection_enabled(&self, id: Uuid, enabled: bool) -> Result<()> {
        self.update_document(|document| {
            let connection = document
                .connections
                .iter_mut()
                .find(|connection| connection.id == id)
                .context("找不到该连接")?;
            connection.enabled = enabled;
            connection.updated_at = Utc::now().to_rfc3339();
            Ok(())
        })
    }

    pub fn activities(&self) -> Result<Vec<Activity>> {
        Ok(self.read_document()?.activities)
    }

    pub fn add_activity(&self, activity: NewActivity) -> Result<()> {
        self.update_document(|document| {
            document.activities.insert(
                0,
                Activity {
                    id: Uuid::new_v4(),
                    time: Utc::now().to_rfc3339(),
                    status: if activity.status == "error" {
                        "error"
                    } else {
                        "success"
                    }
                    .to_owned(),
                    source: clean_text(&activity.source, 40),
                    connection_name: clean_text(&activity.connection_name, 80),
                    action: clean_text(&activity.action, 160),
                    duration_ms: activity.duration_ms,
                    error: clean_text(&activity.error, 240),
                },
            );
            document.activities.truncate(MAX_ACTIVITIES);
            Ok(())
        })
    }

    pub fn clear_activities(&self) -> Result<()> {
        self.update_document(|document| {
            document.activities.clear();
            Ok(())
        })
    }

    pub fn create_approval_request(
        &self,
        item_id: Uuid,
        source: &str,
        action: &str,
        detail: &str,
    ) -> Result<Option<ApprovalRequest>> {
        if !self.settings()?.approval_mode {
            return Ok(None);
        }
        self.update_document_with_result(|document| {
            if !document.settings.approval_mode {
                return Ok(None);
            }
            let item_name = document
                .connections
                .iter()
                .find(|connection| connection.id == item_id)
                .map(|connection| connection.name.clone())
                .context("找不到该项目")?;
            purge_old_approvals(&mut document.approvals);
            if document
                .approvals
                .iter()
                .filter(|request| request.status == "pending")
                .count()
                >= 20
            {
                bail!("待审核请求过多，请先在 KRU 中处理");
            }
            let request = ApprovalRequest {
                id: Uuid::new_v4(),
                created_at: Utc::now().to_rfc3339(),
                status: "pending".to_owned(),
                source: clean_text(source, 40),
                item_id,
                item_name: clean_text(&item_name, 80),
                action: clean_text(action, 80),
                detail: clean_text(detail, 240),
            };
            document.approvals.push(request.clone());
            Ok(Some(request))
        })
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>> {
        let mut requests = self
            .read_document()?
            .approvals
            .into_iter()
            .filter(|request| request.status == "pending" && approval_is_recent(request))
            .collect::<Vec<_>>();
        requests.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(requests)
    }

    pub fn resolve_approval(&self, id: Uuid, approved: bool) -> Result<()> {
        self.update_document(|document| {
            let request = document
                .approvals
                .iter_mut()
                .find(|request| request.id == id && request.status == "pending")
                .context("审核请求已结束或不存在")?;
            if !approval_is_recent(request) {
                request.status = "expired".to_owned();
                bail!("审核请求已超时");
            }
            request.status = if approved { "approved" } else { "denied" }.to_owned();
            Ok(())
        })
    }

    pub fn approval_status(&self, id: Uuid) -> Result<Option<String>> {
        Ok(self
            .read_document()?
            .approvals
            .into_iter()
            .find(|request| request.id == id)
            .map(|request| request.status))
    }

    pub fn remove_approval(&self, id: Uuid) -> Result<()> {
        self.update_document(|document| {
            document.approvals.retain(|request| request.id != id);
            Ok(())
        })
    }

    pub fn app_state(
        &self,
        executable: &str,
        browser_bridge: crate::model::BrowserBridgeState,
    ) -> Result<AppState> {
        let settings = self.settings()?;
        Ok(AppState {
            connections: self.list_connections()?,
            activities: self.activities()?,
            mcp: McpState {
                status: "ready".to_owned(),
                error: String::new(),
                endpoint: "stdio".to_owned(),
                stdio_command: executable.to_owned(),
            },
            browser_bridge,
            security: SecurityState {
                encrypted: true,
                storage: self.storage_label().to_owned(),
            },
            settings,
        })
    }

    pub fn export_connections(&self) -> Result<Vec<(PublicConnection, SecretBundle)>> {
        let document = self.read_document()?;
        document
            .connections
            .into_iter()
            .map(|connection| {
                let secrets = self
                    .inner
                    .key
                    .decrypt::<SecretBundle>(&connection.encrypted_secrets)?;
                Ok((connection.public(Some(&secrets)), secrets))
            })
            .collect()
    }

    pub fn merge_connections(
        &self,
        imported: Vec<(PublicConnection, SecretBundle)>,
    ) -> Result<ImportSummary> {
        self.update_document_with_result(|document| {
            let mut summary = ImportSummary {
                added: 0,
                updated: 0,
            };
            for (public, secrets) in &imported {
                let stored = stored_from_portable(public, secrets, &self.inner.key)?;
                if let Some(index) = document
                    .connections
                    .iter()
                    .position(|item| item.id == public.id)
                {
                    document.connections[index] = stored;
                    summary.updated += 1;
                } else {
                    document.connections.push(stored);
                    summary.added += 1;
                }
            }
            document.activities.insert(
                0,
                Activity {
                    id: Uuid::new_v4(),
                    time: Utc::now().to_rfc3339(),
                    status: "success".to_owned(),
                    source: "应用".to_owned(),
                    connection_name: "便携备份".to_owned(),
                    action: format!("导入备份：新增 {}，更新 {}", summary.added, summary.updated),
                    duration_ms: 0,
                    error: String::new(),
                },
            );
            document.activities.truncate(MAX_ACTIVITIES);
            Ok(summary)
        })
    }

    fn read_document(&self) -> Result<VaultDocument> {
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock).context("无法锁定保险库")?;
        let result = self.read_document_unlocked();
        let _ = FileExt::unlock(&lock);
        result
    }

    fn read_document_unlocked(&self) -> Result<VaultDocument> {
        let bytes = fs::read(&self.inner.vault_path).context("无法读取保险库")?;
        let document: VaultDocument =
            serde_json::from_slice(&bytes).context("保险库文件格式无效")?;
        if document.version != 7 {
            bail!("不支持的保险库版本 {}", document.version);
        }
        Ok(document)
    }

    fn write_document_unlocked(&self, document: &VaultDocument) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(document).context("无法序列化保险库")?;
        let mut file =
            AtomicWriteFile::open(&self.inner.vault_path).context("无法创建保险库临时文件")?;
        file.write_all(&bytes).context("无法写入保险库")?;
        file.commit().context("无法提交保险库文件")?;
        Ok(())
    }

    fn update_document<F>(&self, update: F) -> Result<()>
    where
        F: FnOnce(&mut VaultDocument) -> Result<()>,
    {
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            update(&mut document)?;
            self.write_document_unlocked(&document)
        })
    }

    fn update_document_with_result<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut VaultDocument) -> Result<T>,
    {
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            let result = update(&mut document)?;
            self.write_document_unlocked(&document)?;
            Ok(result)
        })
    }

    fn with_exclusive_lock<T, F>(&self, action: F) -> Result<T>
    where
        F: FnOnce(&File) -> Result<T>,
    {
        let lock = self.open_lock()?;
        lock.lock_exclusive().context("无法锁定保险库")?;
        let result = action(&lock);
        let _ = FileExt::unlock(&lock);
        result
    }

    fn open_lock(&self) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.inner.lock_path)
            .context("无法打开保险库锁文件")
    }
}

fn migrate_connection_to_v3(connection: &mut StoredConnection, key: &MasterKey) -> Result<()> {
    let mut secrets: SecretBundle = key.decrypt(&connection.encrypted_secrets)?;
    let username = match connection.kind.as_str() {
        "browser" => connection
            .browser
            .as_ref()
            .map(|profile| profile.username.as_str())
            .unwrap_or(&connection.username),
        "credential" => connection
            .credential
            .as_ref()
            .map(|profile| profile.username.as_str())
            .unwrap_or(&connection.username),
        _ => &connection.username,
    }
    .trim();
    if !username.is_empty() && secrets.named_secrets.get("username").is_none() {
        secrets
            .named_secrets
            .insert("username".to_owned(), username.to_owned());
    }
    if let Some(seed) = secrets.named_secrets.get("totpSeed").cloned() {
        if secrets.named_secrets.get("totp").is_none() {
            secrets.named_secrets.insert("totp".to_owned(), seed);
        }
        secrets.named_secrets.remove("totpSeed");
    }

    if matches!(connection.kind.as_str(), "browser" | "credential" | "cli") {
        connection.kind = "secret".to_owned();
        connection.host.clear();
        connection.port = 0;
        connection.auth_type.clear();
        connection.private_key_name.clear();
        connection.host_fingerprint.clear();
        connection.host_fingerprint_host.clear();
        connection.host_fingerprint_port = 0;
        connection.security_mode.clear();
        connection.allowed_commands.clear();
        connection.base_url.clear();
        connection.auth_header.clear();
        connection.allowed_methods.clear();
        connection.allowed_path_prefixes.clear();
        connection.test_path.clear();
    }
    connection.username.clear();
    connection.cli = None;
    connection.browser = None;
    connection.credential = None;
    connection.secret = Some(SecretProfile {
        fields: secrets.available_fields(connection.secret.as_ref()),
    });
    connection.encrypted_secrets = key.encrypt(&secrets)?;
    Ok(())
}

fn canonical_secret_module_name(kind: &str) -> Option<&'static str> {
    match kind {
        "username" => Some("username"),
        "password" => Some("password"),
        "apiCredential" => Some("apiCredential"),
        "privateKey" => Some("privateKey"),
        "passphrase" => Some("passphrase"),
        "totp" => Some("totp"),
        _ => None,
    }
}

fn normalize_modules(modules: Vec<ItemModule>) -> Result<Vec<ItemModule>> {
    let mut output = Vec::new();
    let mut singleton_kinds = Vec::new();
    let mut secret_names = Vec::new();
    for mut module in modules {
        module.kind = clean_text(&module.kind, 40);
        if !matches!(
            module.kind.as_str(),
            "username"
                | "password"
                | "apiCredential"
                | "privateKey"
                | "passphrase"
                | "totp"
                | "customSecret"
                | "host"
                | "port"
                | "url"
        ) {
            bail!("不支持的模块：{}", module.kind);
        }
        if module.agent_visible.is_none() {
            module.agent_visible = Some(!module.is_secret());
        }
        if module.kind != "customSecret" {
            if singleton_kinds.contains(&module.kind) {
                bail!("模块不能重复：{}", module.kind);
            }
            singleton_kinds.push(module.kind.clone());
        }
        if let Some(name) = canonical_secret_module_name(&module.kind) {
            module.name = name.to_owned();
            module.value.clear();
        } else if module.kind == "customSecret" {
            module.name = clean_text(&module.name, 80);
            if !valid_identifier(&module.name)
                || canonical_secret_module_name(&module.name).is_some()
                || matches!(module.name.as_str(), "token" | "apiKey" | "api_key")
            {
                bail!("自定义秘密字段名称无效：{}", module.name);
            }
            module.value.clear();
        } else {
            module.name.clear();
            module.value = clean_text(&module.value, if module.kind == "url" { 500 } else { 255 });
            if module.kind == "port" && !module.value.is_empty() {
                let port = module.value.parse::<u16>().context("端口必须是 1–65535")?;
                if port == 0 {
                    bail!("端口必须是 1–65535");
                }
                module.value = port.to_string();
            }
        }
        if let Some(name) = module.secret_name() {
            if secret_names.iter().any(|candidate| candidate == name) {
                bail!("秘密模块字段名称重复：{name}");
            }
            secret_names.push(name.to_owned());
        }
        output.push(module);
    }
    if output.len() > 50 {
        bail!("每个项目最多包含 50 个模块");
    }
    Ok(output)
}

fn module_value<'a>(modules: &'a [ItemModule], kind: &str) -> Option<&'a str> {
    modules
        .iter()
        .find(|module| module.kind == kind)
        .map(|module| module.value.trim())
        .filter(|value| !value.is_empty())
}

fn module_secret_configured(modules: &[ItemModule], secrets: &SecretBundle, kind: &str) -> bool {
    modules
        .iter()
        .find(|module| module.kind == kind)
        .and_then(ItemModule::secret_name)
        .and_then(|name| secrets.get(name))
        .is_some()
}

fn derive_capabilities(
    modules: &[ItemModule],
    secrets: &SecretBundle,
    http_auth_type: &str,
    api_auth_headers: &[ApiAuthHeader],
) -> Vec<String> {
    let mut capabilities = Vec::new();
    if modules.iter().any(|module| {
        module
            .secret_name()
            .and_then(|name| secrets.get(name))
            .is_some()
    }) {
        capabilities.push("fill".to_owned());
    }
    let port_ready = module_value(modules, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .is_some_and(|port| port > 0);
    if module_value(modules, "host").is_some()
        && port_ready
        && module_secret_configured(modules, secrets, "username")
        && (module_secret_configured(modules, secrets, "password")
            || module_secret_configured(modules, secrets, "privateKey"))
    {
        capabilities.push("ssh".to_owned());
    }
    let api_ready = module_secret_configured(modules, secrets, "apiCredential");
    let basic_ready = http_auth_type == "basic"
        && module_value(modules, "url").is_some()
        && module_secret_configured(modules, secrets, "username")
        && module_secret_configured(modules, secrets, "password");
    let custom_ready = http_auth_type == "custom"
        && !api_auth_headers.is_empty()
        && api_auth_headers
            .iter()
            .all(|header| secrets.get(&header.secret_name).is_some());
    if api_ready || basic_ready || custom_ready {
        capabilities.push("http".to_owned());
    }
    capabilities
}

fn module_fields(modules: &[ItemModule]) -> Vec<SecretField> {
    modules
        .iter()
        .filter_map(|module| {
            module.secret_name().map(|name| SecretField {
                name: name.to_owned(),
                kind: if module.kind == "totp" {
                    "totp"
                } else {
                    "text"
                }
                .to_owned(),
            })
        })
        .collect()
}

fn push_module(modules: &mut Vec<ItemModule>, kind: &str, name: &str, value: &str) {
    if kind != "customSecret" && modules.iter().any(|module| module.kind == kind) {
        return;
    }
    if kind == "customSecret" && modules.iter().any(|module| module.name == name) {
        return;
    }
    modules.push(ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: value.to_owned(),
        agent_visible: Some(!matches!(
            kind,
            "username"
                | "password"
                | "apiCredential"
                | "privateKey"
                | "passphrase"
                | "totp"
                | "customSecret"
        )),
    });
}

fn modules_from_legacy(
    connection: &StoredConnection,
    secrets: &mut SecretBundle,
) -> Vec<ItemModule> {
    let capabilities = normalize_item_capabilities(&connection.capabilities, &connection.kind);
    let has_ssh = capabilities.iter().any(|value| value == "ssh");
    let has_http = capabilities.iter().any(|value| value == "http");
    let mut modules = Vec::new();
    if !connection.host.is_empty() {
        push_module(&mut modules, "host", "", &connection.host);
    }
    if has_ssh && connection.port > 0 {
        push_module(&mut modules, "port", "", &connection.port.to_string());
    }
    if !connection.base_url.is_empty() {
        push_module(&mut modules, "url", "", &connection.base_url);
    }
    if has_http && !matches!(connection.auth_type.as_str(), "basic" | "custom" | "none") {
        let credential = secrets
            .token
            .as_ref()
            .or(secrets.api_key.as_ref())
            .filter(|value| !value.is_empty())
            .cloned();
        if let Some(credential) = credential {
            if secrets.named_secrets.get("apiCredential").is_none() {
                secrets
                    .named_secrets
                    .insert("apiCredential".to_owned(), credential);
            }
            push_module(&mut modules, "apiCredential", "apiCredential", "");
        }
    }
    for field in secrets.available_fields(connection.secret.as_ref()) {
        let kind = match field.name.as_str() {
            "username" => "username",
            "password" => "password",
            "passphrase" => "passphrase",
            "privateKey" | "private_key" => "privateKey",
            "totp" => "totp",
            "token" | "apiKey" | "api_key" if has_http => "apiCredential",
            "apiCredential" => "apiCredential",
            _ => "customSecret",
        };
        let name = if kind == "customSecret" {
            &field.name
        } else {
            kind
        };
        push_module(&mut modules, kind, name, "");
    }
    modules
}

fn fallback_item_name(
    requested: &str,
    id: Uuid,
    modules: &[ItemModule],
    secrets: &SecretBundle,
) -> String {
    let requested = clean_text(requested, 80);
    if !requested.is_empty() {
        return requested;
    }
    if let Some(host) = module_value(modules, "host") {
        return clean_text(host, 80);
    }
    if let Some(url) = module_value(modules, "url") {
        let profile = api_catalog::infer("", url, secrets.get("apiCredential").unwrap_or_default());
        return api_catalog::fallback_name(url, profile);
    }
    if let Some(secret) = secrets.get("apiCredential") {
        let inferred = api_catalog::fallback_name("", api_catalog::infer("", "", secret));
        if inferred != "API" {
            return inferred;
        }
    }
    let short = id.simple().to_string()[..6].to_ascii_uppercase();
    if module_secret_configured(modules, secrets, "username")
        && module_secret_configured(modules, secrets, "password")
    {
        format!("LOGIN-{short}")
    } else {
        format!("ITEM-{short}")
    }
}

fn modules_from_legacy_input(input: &ConnectionInput, secrets: &SecretBundle) -> Vec<ItemModule> {
    let capabilities = normalize_item_capabilities(&input.capabilities, &input.kind);
    let mut modules = Vec::new();
    if !input.host.trim().is_empty() {
        push_module(&mut modules, "host", "", input.host.trim());
    }
    if capabilities.iter().any(|value| value == "ssh") && input.port > 0 {
        push_module(&mut modules, "port", "", &input.port.to_string());
    }
    if !input.base_url.trim().is_empty() {
        push_module(&mut modules, "url", "", input.base_url.trim());
    }
    if let Some(profile) = &input.secret {
        for field in &profile.fields {
            let kind = match field.name.as_str() {
                "username" => "username",
                "password" => "password",
                "passphrase" => "passphrase",
                "privateKey" | "private_key" => "privateKey",
                "totp" => "totp",
                "token" | "apiKey" | "api_key"
                    if capabilities.iter().any(|value| value == "http") =>
                {
                    "apiCredential"
                }
                "apiCredential" => "apiCredential",
                _ => "customSecret",
            };
            push_module(
                &mut modules,
                kind,
                if kind == "customSecret" {
                    &field.name
                } else {
                    kind
                },
                "",
            );
        }
    }
    if !modules.iter().any(|module| module.kind == "username") && secrets.get("username").is_some()
    {
        push_module(&mut modules, "username", "username", "");
    }
    if !modules.iter().any(|module| module.kind == "password") && secrets.get("password").is_some()
    {
        push_module(&mut modules, "password", "password", "");
    }
    if !modules.iter().any(|module| module.kind == "privateKey")
        && (secrets.get("privateKey").is_some()
            || !input.private_key_import_path.trim().is_empty()
            || input.ssh_auth_type == "privateKey"
            || input.auth_type == "privateKey")
    {
        push_module(&mut modules, "privateKey", "privateKey", "");
    }
    if !modules.iter().any(|module| module.kind == "passphrase")
        && secrets.get("passphrase").is_some()
    {
        push_module(&mut modules, "passphrase", "passphrase", "");
    }
    if capabilities.iter().any(|value| value == "http")
        && !modules.iter().any(|module| module.kind == "apiCredential")
        && secrets.get("apiCredential").is_some()
    {
        push_module(&mut modules, "apiCredential", "apiCredential", "");
    }
    modules
}

fn normalize_connection_v7(
    mut input: ConnectionInput,
    existing: Option<&StoredConnection>,
    secrets: &SecretBundle,
    private_key_name: String,
    now: String,
) -> Result<StoredConnection> {
    if input.modules.is_empty() && (!input.capabilities.is_empty() || !input.kind.is_empty()) {
        input.modules = modules_from_legacy_input(&input, secrets);
    }
    let mut modules = normalize_modules(input.modules)?;
    if !input.base_url.trim().is_empty() {
        if let Some(module) = modules.iter_mut().find(|module| module.kind == "url") {
            module.value = input.base_url.trim().to_owned();
        } else if modules.iter().any(|module| module.kind == "apiCredential") {
            push_module(&mut modules, "url", "", input.base_url.trim());
        }
    }
    modules = normalize_modules(modules)?;

    let id = existing
        .map(|value| value.id)
        .or(input.id)
        .unwrap_or_else(Uuid::new_v4);
    let created_at = existing
        .map(|value| value.created_at.clone())
        .unwrap_or_else(|| now.clone());
    let host = module_value(&modules, "host")
        .unwrap_or_default()
        .to_owned();
    let port = module_value(&modules, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let base_url = if let Some(raw) = module_value(&modules, "url") {
        let normalized = api_catalog::normalize_base_url(raw, "")?;
        let parsed = Url::parse(&normalized).context("API URL 无效")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("API URL 仅支持不含认证、查询参数或片段的 HTTP/HTTPS 地址");
        }
        normalized
    } else {
        String::new()
    };
    let ssh_auth_type = if module_secret_configured(&modules, secrets, "password") {
        "password"
    } else if module_secret_configured(&modules, secrets, "privateKey") {
        "privateKey"
    } else {
        ""
    }
    .to_owned();
    let http_auth_type = if input.http_auth_type.is_empty() {
        input.auth_type.clone()
    } else {
        input.http_auth_type.clone()
    };
    let capabilities =
        derive_capabilities(&modules, secrets, &http_auth_type, &input.api_auth_headers);
    let (host_fingerprint, host_fingerprint_host, host_fingerprint_port) = match existing {
        Some(connection)
            if !host.is_empty()
                && connection.host.eq_ignore_ascii_case(&host)
                && connection.port == port
                && connection.host_fingerprint_host.eq_ignore_ascii_case(&host)
                && connection.host_fingerprint_port == port =>
        {
            (
                connection.host_fingerprint.clone(),
                connection.host_fingerprint_host.clone(),
                connection.host_fingerprint_port,
            )
        }
        _ => (String::new(), String::new(), 0),
    };
    let allowed_methods = if input.allowed_methods.is_empty() {
        ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        normalize_list(input.allowed_methods, 10, 10)
            .into_iter()
            .map(|method| method.to_uppercase())
            .filter(|method| {
                matches!(
                    method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
                )
            })
            .collect()
    };
    let name = fallback_item_name(&input.name, id, &modules, secrets);
    Ok(StoredConnection {
        id,
        kind: String::new(),
        capabilities,
        modules: modules.clone(),
        name,
        enabled: input.enabled,
        created_at,
        updated_at: now,
        description: clean_text(&input.description, 240),
        host,
        port,
        username: String::new(),
        auth_type: http_auth_type.clone(),
        ssh_auth_type,
        http_auth_type,
        private_key_name: if modules.iter().any(|module| module.kind == "privateKey") {
            private_key_name
        } else {
            String::new()
        },
        host_fingerprint,
        host_fingerprint_host,
        host_fingerprint_port,
        security_mode: match input.security_mode.as_str() {
            "diagnostic" | "restricted" | "unrestricted" => input.security_mode,
            _ => "readonly".to_owned(),
        },
        allowed_commands: normalize_list(input.allowed_commands, 30, 180),
        base_url,
        auth_header: clean_text(&input.auth_header, 100),
        auth_location: clean_text(&input.auth_location, 20),
        auth_prefix: clean_text(&input.auth_prefix, 32),
        api_auth_headers: input.api_auth_headers,
        allowed_methods,
        allowed_path_prefixes: normalize_list(input.allowed_path_prefixes, 30, 180),
        test_path: clean_text(&input.test_path, 500),
        cli: None,
        browser: None,
        credential: None,
        secret: Some(SecretProfile {
            fields: module_fields(&modules),
        }),
        encrypted_secrets: empty_envelope(),
    })
}

fn stored_from_portable(
    public: &PublicConnection,
    secrets: &SecretBundle,
    key: &MasterKey,
) -> Result<StoredConnection> {
    let mut secrets = secrets.clone();
    let mut private_key_name = public.private_key_name.clone();
    normalize_active_auth_secrets(
        if public.capabilities.iter().any(|value| value == "ssh") {
            "ssh"
        } else if public.capabilities.iter().any(|value| value == "http") {
            "api"
        } else {
            &public.kind
        },
        &public.auth_type,
        &public.api_auth_headers,
        &mut secrets,
        &mut private_key_name,
    );
    let mut stored = StoredConnection {
        id: public.id,
        kind: public.kind.clone(),
        capabilities: normalize_item_capabilities(&public.capabilities, &public.kind),
        modules: public
            .modules
            .iter()
            .map(|module| ItemModule {
                kind: module.kind.clone(),
                name: module.name.clone(),
                value: if module.secret {
                    String::new()
                } else {
                    module.value.clone()
                },
                agent_visible: Some(module.agent_visible()),
            })
            .collect(),
        name: public.name.clone(),
        enabled: public.enabled,
        created_at: public.created_at.clone(),
        updated_at: public.updated_at.clone(),
        description: public.description.clone(),
        host: public.host.clone(),
        port: public.port,
        username: public.username.clone(),
        auth_type: public.auth_type.clone(),
        ssh_auth_type: public.ssh_auth_type.clone(),
        http_auth_type: public.http_auth_type.clone(),
        private_key_name,
        // Backup payloads predating v5 cannot prove which endpoint owned this
        // fingerprint. Import it as untrusted and pin again on first use.
        host_fingerprint: String::new(),
        host_fingerprint_host: String::new(),
        host_fingerprint_port: 0,
        security_mode: public.security_mode.clone(),
        allowed_commands: public.allowed_commands.clone(),
        base_url: public.base_url.clone(),
        auth_header: public.auth_header.clone(),
        auth_location: public.auth_location.clone(),
        auth_prefix: public.auth_prefix.clone(),
        api_auth_headers: public.api_auth_headers.clone(),
        allowed_methods: public.allowed_methods.clone(),
        allowed_path_prefixes: public.allowed_path_prefixes.clone(),
        test_path: public.test_path.clone(),
        cli: public.cli.clone(),
        browser: public.browser.clone(),
        credential: public.credential.clone(),
        secret: public.secret.clone(),
        encrypted_secrets: key.encrypt(&secrets)?,
    };
    migrate_connection_to_v3(&mut stored, key)?;
    if stored.modules.is_empty() {
        stored.modules = modules_from_legacy(&stored, &mut secrets);
    }
    stored.modules = normalize_modules(stored.modules)?;
    stored.capabilities = derive_capabilities(
        &stored.modules,
        &secrets,
        &stored.http_auth_type,
        &stored.api_auth_headers,
    );
    stored.secret = Some(SecretProfile {
        fields: module_fields(&stored.modules),
    });
    stored.encrypted_secrets = key.encrypt(&secrets)?;
    stored.kind.clear();
    Ok(stored)
}

fn empty_envelope() -> crate::model::SecretEnvelope {
    crate::model::SecretEnvelope {
        version: 0,
        nonce: String::new(),
        ciphertext: String::new(),
    }
}

fn merge_secret_bundle(current: &mut SecretBundle, next: &SecretBundle) {
    if next.password.as_ref().is_some_and(|v| !v.is_empty()) {
        current.password = next.password.clone();
    }
    if next.passphrase.as_ref().is_some_and(|v| !v.is_empty()) {
        current.passphrase = next.passphrase.clone();
    }
    if next.token.as_ref().is_some_and(|v| !v.is_empty()) {
        current.token = next.token.clone();
    }
    if next.api_key.as_ref().is_some_and(|v| !v.is_empty()) {
        current.api_key = next.api_key.clone();
    }
    for (name, value) in next.named_secrets.iter() {
        if !value.is_empty() {
            current.named_secrets.insert(name.clone(), value.clone());
        }
    }
}

fn prepare_auto_api(input: &mut ConnectionInput, secrets: &mut SecretBundle) -> Result<()> {
    if !input
        .modules
        .iter()
        .any(|module| module.kind == "apiCredential")
        || (input.auth_type != "auto" && input.http_auth_type != "auto")
    {
        return Ok(());
    }
    let Some(secret) = secrets
        .get("apiCredential")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
    else {
        // An empty API credential module is a valid draft.  It becomes callable
        // only after a value is configured and capabilities are derived again.
        return Ok(());
    };
    let profile = api_catalog::infer(&input.name, &input.base_url, &secret);
    input.base_url = api_catalog::normalize_base_url(&input.base_url, profile.default_base_url)?;
    input.auth_type = profile.auth_type.to_owned();
    input.http_auth_type = profile.auth_type.to_owned();
    input.auth_header = profile.auth_header.to_owned();
    input.auth_location = profile.auth_location.to_owned();
    input.auth_prefix = profile.auth_prefix.to_owned();
    input.api_auth_headers.clear();
    input.allowed_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    input.allowed_path_prefixes.clear();
    input.test_path.clear();
    Ok(())
}

fn normalize_active_auth_secrets(
    kind: &str,
    auth_type: &str,
    _api_auth_headers: &[ApiAuthHeader],
    secrets: &mut SecretBundle,
    private_key_name: &mut String,
) {
    // Authentication is an optional capability layered on top of the item's
    // encrypted fields. Changing or removing a capability must never erase a
    // password, token, private key, or unrelated custom field.
    if kind == "ssh" && auth_type == "privateKey" && private_key_name.is_empty() {
        *private_key_name = secrets.private_key_name.clone().unwrap_or_default();
    }
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn normalize_list(values: Vec<String>, max_items: usize, max_len: usize) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let value = clean_text(&value, max_len);
        if !value.is_empty() && !output.contains(&value) {
            output.push(value);
        }
        if output.len() == max_items {
            break;
        }
    }
    output
}

fn clean_text(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

fn approval_is_recent(request: &ApprovalRequest) -> bool {
    chrono::DateTime::parse_from_rfc3339(&request.created_at)
        .map(|created| {
            Utc::now()
                .signed_duration_since(created.with_timezone(&Utc))
                .num_seconds()
                < 60
        })
        .unwrap_or(false)
}

fn purge_old_approvals(requests: &mut Vec<ApprovalRequest>) {
    requests.retain(|request| approval_is_recent(request));
}

fn normalize_ssh_fingerprint(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("SSH 主机指纹不能为空");
    }
    let normalized = if value.starts_with("SHA256:") {
        value.to_owned()
    } else {
        format!("SHA256:{value}")
    };
    if normalized.chars().count() > 200 {
        bail!("SSH 主机指纹无效");
    }
    Ok(normalized)
}

fn random_token() -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token)
        .map_err(|error| anyhow::anyhow!("无法生成 MCP 访问令牌：{error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn api_input(id: Option<Uuid>, name: &str, token: &str) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets.token = Some(token.to_owned());
        ConnectionInput {
            id,
            kind: "api".to_owned(),
            capabilities: vec!["fill".to_owned(), "http".to_owned()],
            modules: vec![],
            name: name.to_owned(),
            enabled: true,
            description: "test connection".to_owned(),
            host: String::new(),
            port: 0,
            username: String::new(),
            auth_type: "bearer".to_owned(),
            ssh_auth_type: String::new(),
            http_auth_type: "bearer".to_owned(),
            private_key_import_path: String::new(),
            host_fingerprint: String::new(),
            security_mode: String::new(),
            allowed_commands: Vec::new(),
            base_url: "https://api.example.test/v1/".to_owned(),
            auth_header: "X-API-Key".to_owned(),
            auth_location: "header".to_owned(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            allowed_methods: vec!["GET".to_owned()],
            allowed_path_prefixes: vec!["/v1/".to_owned()],
            test_path: "/health".to_owned(),
            cli: None,
            browser: None,
            credential: None,
            secret: None,
            remove_secret_names: vec![],
            secrets,
        }
    }

    fn ssh_input(id: Option<Uuid>) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets.password = Some("test-password".to_owned());
        ConnectionInput {
            id,
            kind: "ssh".to_owned(),
            capabilities: vec!["fill".to_owned(), "ssh".to_owned()],
            modules: vec![],
            name: "ssh-test".to_owned(),
            enabled: true,
            description: String::new(),
            host: "127.0.0.1".to_owned(),
            port: 22,
            username: "root".to_owned(),
            auth_type: "password".to_owned(),
            ssh_auth_type: "password".to_owned(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            host_fingerprint: String::new(),
            security_mode: "diagnostic".to_owned(),
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
            secret: None,
            remove_secret_names: vec![],
            secrets,
        }
    }

    #[test]
    fn vault_file_contains_no_plain_secret_and_remains_valid_json() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        vault
            .save_connection(api_input(None, "plain-check", "unique-secret-marker-9437"))
            .unwrap();

        let contents = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(!contents.contains("unique-secret-marker-9437"));
        let stored_json: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert!(stored_json["connections"][0].get("type").is_none());
        assert_eq!(
            stored_json["connections"][0]["capabilities"],
            serde_json::json!(["fill", "http"])
        );
        assert!(serde_json::from_str::<VaultDocument>(&contents).is_ok());
        let public = vault.list_connections().unwrap();
        let serialized = serde_json::to_string(&public).unwrap();
        assert!(!serialized.contains("unique-secret-marker-9437"));
        let public_json = serde_json::to_value(&public).unwrap();
        assert!(public_json[0].get("type").is_none());
        assert_eq!(
            public_json[0]["capabilities"],
            serde_json::json!(["fill", "http"])
        );
    }

    #[test]
    fn editor_draft_encrypts_the_entire_form_and_can_be_reopened() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let mut input = ssh_input(None);
        input.name = "unfinished-draft-name-7129".to_owned();
        input.description = "unfinished-draft-note-7129".to_owned();
        input.modules = vec![ItemModule {
            kind: "password".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        }];
        input.secrets.password = Some("unfinished-draft-secret-7129".to_owned());

        let saved = vault.save_editor_draft(None, input).unwrap();
        let contents = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(!contents.contains("unfinished-draft-name-7129"));
        assert!(!contents.contains("unfinished-draft-note-7129"));
        assert!(!contents.contains("unfinished-draft-secret-7129"));

        let drafts = vault.list_editor_drafts().unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].id, saved.id);
        assert_eq!(drafts[0].input.name, "unfinished-draft-name-7129");
        assert_eq!(
            drafts[0].input.secrets.password.as_deref(),
            Some("unfinished-draft-secret-7129")
        );

        let mut replacement = ssh_input(None);
        replacement.name = "replacement-draft".to_owned();
        let replacement = vault.save_editor_draft(None, replacement).unwrap();
        let drafts = vault.list_editor_drafts().unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].id, replacement.id);
        assert_ne!(replacement.id, saved.id);

        vault.delete_editor_draft(replacement.id).unwrap();
        assert!(vault.list_editor_drafts().unwrap().is_empty());
    }

    #[test]
    fn automatic_api_requires_only_a_secret_and_normalizes_optional_url() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut input = api_input(None, "Addressless API", "opaque-api-secret");
        input.auth_type = "auto".to_owned();
        input.base_url.clear();
        let addressless = vault.save_connection(input).unwrap();
        assert_eq!(addressless.name, "Addressless API");
        assert!(addressless.base_url.is_empty());
        assert_eq!(addressless.auth_type, "bearer");

        let mut input = api_input(None, "Example", "another-api-secret");
        input.auth_type = "auto".to_owned();
        input.base_url = "api.example.test/v1".to_owned();
        let normalized = vault.save_connection(input).unwrap();
        assert_eq!(normalized.base_url, "https://api.example.test/v1");
    }

    #[test]
    fn v7_modules_derive_mixed_actions_and_keep_incomplete_items_as_drafts() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut mixed = ssh_input(None);
        mixed.kind.clear();
        mixed.capabilities.clear();
        mixed.http_auth_type = "auto".to_owned();
        mixed.modules = vec![
            ItemModule {
                kind: "host".into(),
                name: String::new(),
                value: "127.0.0.1".into(),
                agent_visible: None,
            },
            ItemModule {
                kind: "port".into(),
                name: String::new(),
                value: "22".into(),
                agent_visible: None,
            },
            ItemModule {
                kind: "username".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            },
            ItemModule {
                kind: "password".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            },
            ItemModule {
                kind: "apiCredential".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            },
        ];
        mixed
            .secrets
            .named_secrets
            .insert("apiCredential".into(), "mixed-api-marker".into());
        let saved = vault.save_connection(mixed).unwrap();
        assert_eq!(saved.capabilities, vec!["fill", "ssh", "http"]);
        assert!(
            saved
                .modules
                .iter()
                .all(|module| module.value != "mixed-api-marker")
        );

        let mut draft = ssh_input(None);
        draft.kind.clear();
        draft.capabilities.clear();
        draft.name = "Draft host".to_owned();
        draft.username.clear();
        draft.secrets = SecretBundle::default();
        draft.modules = vec![
            ItemModule {
                kind: "host".into(),
                name: String::new(),
                value: "draft.example".into(),
                agent_visible: None,
            },
            ItemModule {
                kind: "port".into(),
                name: String::new(),
                value: "22".into(),
                agent_visible: None,
            },
            ItemModule {
                kind: "username".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            },
        ];
        let saved_draft = vault.save_connection(draft).unwrap();
        assert!(saved_draft.capabilities.is_empty());
        assert_eq!(saved_draft.name, "Draft host");
    }

    #[test]
    fn new_items_require_a_name_and_at_least_one_module() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();

        let mut missing_name = ssh_input(None);
        missing_name.kind.clear();
        missing_name.capabilities.clear();
        missing_name.name.clear();
        missing_name.modules = vec![ItemModule {
            kind: "password".into(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        }];
        assert!(
            vault
                .save_connection(missing_name)
                .unwrap_err()
                .to_string()
                .contains("名称")
        );

        let mut missing_modules = ssh_input(None);
        missing_modules.kind.clear();
        missing_modules.capabilities.clear();
        missing_modules.modules.clear();
        assert!(
            vault
                .save_connection(missing_modules)
                .unwrap_err()
                .to_string()
                .contains("模块")
        );
    }

    #[test]
    fn removing_a_secret_module_deletes_its_encrypted_value() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let saved = vault.save_connection(ssh_input(None)).unwrap();
        let existing = vault.get_connection(saved.id).unwrap();
        let mut update = ssh_input(Some(saved.id));
        update.kind.clear();
        update.capabilities.clear();
        update.username.clear();
        update.secrets = SecretBundle::default();
        update.modules = existing
            .stored
            .modules
            .into_iter()
            .filter(|module| module.kind != "password")
            .collect();
        vault.save_connection(update).unwrap();
        let after = vault.get_connection(saved.id).unwrap();
        assert!(after.secrets.get("password").is_none());
        assert!(!after.stored.capabilities.iter().any(|value| value == "ssh"));
    }

    #[test]
    fn v6_items_migrate_to_v7_modules_without_losing_ssh_trust() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let saved = vault.save_connection(ssh_input(None)).unwrap();
        vault
            .verify_or_pin_ssh_fingerprint(saved.id, "v6-trust", true)
            .unwrap();
        vault
            .update_document(|document| {
                document.version = 6;
                let connection = document.connections.first_mut().unwrap();
                connection.kind = "ssh".to_owned();
                connection.modules.clear();
                Ok(())
            })
            .unwrap();
        drop(vault);

        let migrated = Vault::open(vault_dir.clone()).unwrap();
        let connection = migrated.get_connection(saved.id).unwrap().stored;
        assert_eq!(connection.capabilities, vec!["fill", "ssh"]);
        assert!(
            connection
                .modules
                .iter()
                .any(|module| module.kind == "host")
        );
        assert_eq!(connection.host_fingerprint, "SHA256:v6-trust");
        let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(raw.contains("\"version\": 7"));
    }

    #[test]
    fn owner_pin_is_hashed_and_owner_view_returns_only_on_explicit_request() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        vault.set_owner_pin("123456").unwrap();
        let saved = vault
            .save_connection(api_input(None, "owner-view", "owner-token-marker-7721"))
            .unwrap();

        assert!(vault.verify_owner_pin("123456").unwrap());
        assert!(!vault.verify_owner_pin("654321").unwrap());
        let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(!raw.contains("123456"));
        assert!(!raw.contains("owner-token-marker-7721"));
        let public = serde_json::to_string(&vault.list_connections().unwrap()).unwrap();
        assert!(!public.contains("owner-token-marker-7721"));
        let owner = vault.owner_secret_view(saved.id).unwrap();
        assert_eq!(
            owner
                .fields
                .iter()
                .find(|field| field.name == "token")
                .map(|field| field.value.as_str()),
            Some("owner-token-marker-7721")
        );
    }

    #[test]
    fn approval_mode_gates_each_request_without_storing_secret_values() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().to_path_buf()).unwrap();
        let saved = vault
            .save_connection(api_input(None, "approval-item", "approval-secret-marker"))
            .unwrap();

        assert!(
            vault
                .create_approval_request(saved.id, "MCP · CODEX", "发送 API 请求", "GET /v1/me")
                .unwrap()
                .is_none()
        );

        let mut settings = vault.settings().unwrap();
        settings.approval_mode = true;
        vault.update_settings(settings).unwrap();
        let request = vault
            .create_approval_request(saved.id, "MCP · CODEX", "发送 API 请求", "GET /v1/me")
            .unwrap()
            .unwrap();
        let pending = vault.pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source, "MCP · CODEX");
        assert!(
            !serde_json::to_string(&pending)
                .unwrap()
                .contains("approval-secret-marker")
        );

        vault.resolve_approval(request.id, true).unwrap();
        assert_eq!(
            vault.approval_status(request.id).unwrap().as_deref(),
            Some("approved")
        );
        vault.remove_approval(request.id).unwrap();
        assert!(vault.approval_status(request.id).unwrap().is_none());

        let request = vault
            .create_approval_request(saved.id, "MCP · CODEX", "填写秘密", "browser · password")
            .unwrap()
            .unwrap();
        let mut settings = vault.settings().unwrap();
        settings.approval_mode = false;
        vault.update_settings(settings).unwrap();
        assert!(vault.approval_status(request.id).unwrap().is_none());
    }

    #[test]
    fn concurrent_writes_keep_every_connection() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let handles = (0..4)
            .map(|index| {
                let vault = vault.clone();
                std::thread::spawn(move || {
                    vault
                        .save_connection(api_input(
                            None,
                            &format!("connection-{index}"),
                            &format!("secret-token-{index}"),
                        ))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(vault.list_connections().unwrap().len(), 4);
    }

    #[test]
    fn ssh_fingerprint_tracks_the_same_endpoint_and_clears_after_endpoint_change() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut new_connection = ssh_input(None);
        new_connection.host_fingerprint = "SHA256:client-supplied-key".to_owned();
        let saved = vault.save_connection(new_connection).unwrap();
        assert!(
            vault
                .get_connection(saved.id)
                .unwrap()
                .stored
                .host_fingerprint
                .is_empty()
        );

        let pinned = vault
            .verify_or_pin_ssh_fingerprint(saved.id, "first-key", true)
            .unwrap();
        assert_eq!(pinned, "SHA256:first-key");
        let trusted = vault.get_connection(saved.id).unwrap().stored;
        assert_eq!(trusted.host_fingerprint, "SHA256:first-key");
        assert_eq!(trusted.host_fingerprint_host, "127.0.0.1");
        assert_eq!(trusted.host_fingerprint_port, 22);
        assert!(
            vault
                .verify_or_pin_ssh_fingerprint(saved.id, "second-key", true)
                .is_err()
        );

        let mut edited = ssh_input(Some(saved.id));
        edited.host_fingerprint.clear();
        vault.save_connection(edited).unwrap();
        assert_eq!(
            vault
                .get_connection(saved.id)
                .unwrap()
                .stored
                .host_fingerprint,
            "SHA256:first-key"
        );

        let mut moved = ssh_input(Some(saved.id));
        moved.host = "new-host.example.test".to_owned();
        moved.host_fingerprint = "SHA256:first-key".to_owned();
        vault.save_connection(moved).unwrap();
        assert!(
            vault
                .get_connection(saved.id)
                .unwrap()
                .stored
                .host_fingerprint
                .is_empty()
        );

        vault.reset_ssh_fingerprint(saved.id).unwrap();
        let reset = vault.get_connection(saved.id).unwrap().stored;
        assert!(reset.host_fingerprint.is_empty());
        assert!(reset.host_fingerprint_host.is_empty());
        assert_eq!(reset.host_fingerprint_port, 0);
        assert!(
            vault
                .verify_or_pin_ssh_fingerprint(saved.id, "first-key", false)
                .is_err()
        );
    }

    #[test]
    fn v4_ssh_fingerprint_is_cleared_before_fresh_tofu() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let saved = vault.save_connection(ssh_input(None)).unwrap();
        vault
            .verify_or_pin_ssh_fingerprint(saved.id, "legacy-key", true)
            .unwrap();
        vault
            .update_document(|document| {
                document.version = 4;
                let connection = document.connections.first_mut().unwrap();
                connection.host_fingerprint_host.clear();
                connection.host_fingerprint_port = 0;
                Ok(())
            })
            .unwrap();
        drop(vault);

        let migrated = Vault::open(vault_dir).unwrap();
        let connection = migrated.get_connection(saved.id).unwrap().stored;
        assert!(connection.host_fingerprint.is_empty());
        assert!(connection.host_fingerprint_host.is_empty());
        assert_eq!(connection.host_fingerprint_port, 0);
    }

    #[test]
    fn v5_item_migration_preserves_endpoint_bound_ssh_trust() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let saved = vault.save_connection(ssh_input(None)).unwrap();
        vault
            .verify_or_pin_ssh_fingerprint(saved.id, "trusted-key", true)
            .unwrap();
        vault
            .update_document(|document| {
                document.version = 5;
                let connection = document.connections.first_mut().unwrap();
                connection.kind = "ssh".to_owned();
                connection.capabilities.clear();
                Ok(())
            })
            .unwrap();
        drop(vault);

        let migrated = Vault::open(vault_dir).unwrap();
        let connection = migrated.get_connection(saved.id).unwrap().stored;
        assert!(connection.kind.is_empty());
        assert_eq!(connection.capabilities, vec!["fill", "ssh"]);
        assert_eq!(connection.host_fingerprint, "SHA256:trusted-key");
        assert_eq!(connection.host_fingerprint_host, "127.0.0.1");
        assert_eq!(connection.host_fingerprint_port, 22);
    }

    #[test]
    fn imported_private_key_survives_source_file_removal() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let key_path = directory.path().join("id_test");
        let key_marker =
            "-----BEGIN PRIVATE KEY-----\nprivate-key-marker-4382\n-----END PRIVATE KEY-----";
        fs::write(&key_path, key_marker).unwrap();
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let saved = vault
            .save_connection(ConnectionInput {
                id: None,
                kind: "ssh".into(),
                capabilities: vec!["fill".into(), "ssh".into()],
                modules: vec![],
                name: "key-test".into(),
                enabled: true,
                description: String::new(),
                host: "127.0.0.1".into(),
                port: 22,
                username: "root".into(),
                auth_type: "privateKey".into(),
                ssh_auth_type: "privateKey".into(),
                http_auth_type: String::new(),
                private_key_import_path: key_path.to_string_lossy().into_owned(),
                host_fingerprint: String::new(),
                security_mode: "readonly".into(),
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
                secret: None,
                remove_secret_names: vec![],
                secrets: SecretBundle::default(),
            })
            .unwrap();
        fs::remove_file(&key_path).unwrap();

        let decrypted = vault.get_connection(saved.id).unwrap();
        assert_eq!(decrypted.secrets.private_key.as_deref(), Some(key_marker));
        assert_eq!(decrypted.stored.private_key_name, "id_test");
        let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(!raw.contains("private-key-marker-4382"));

        vault.save_connection(ssh_input(Some(saved.id))).unwrap();
        let password_mode = vault.get_connection(saved.id).unwrap();
        assert_eq!(password_mode.stored.auth_type, "password");
        assert_eq!(password_mode.stored.private_key_name, "id_test");
        assert_eq!(
            password_mode.secrets.private_key.as_deref(),
            Some(key_marker)
        );
        assert_eq!(
            password_mode.secrets.password.as_deref(),
            Some("test-password")
        );
    }

    #[test]
    fn named_secrets_are_encrypted_preserved_on_empty_and_explicitly_deleted() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("password".into(), "browser-secret-marker-7482".into());
        secrets
            .named_secrets
            .insert("username".into(), "developer@example.test".into());
        let input = |id, secrets, remove_secret_names| ConnectionInput {
            id,
            kind: "secret".into(),
            capabilities: vec!["fill".into()],
            modules: vec![],
            name: "generic-login".into(),
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
            secret: None,
            remove_secret_names,
            secrets,
        };
        let saved = vault.save_connection(input(None, secrets, vec![])).unwrap();
        assert!(
            !fs::read_to_string(vault_dir.join("vault.json"))
                .unwrap()
                .contains("browser-secret-marker-7482")
        );

        vault
            .save_connection(input(Some(saved.id), SecretBundle::default(), vec![]))
            .unwrap();
        assert_eq!(
            vault
                .get_connection(saved.id)
                .unwrap()
                .secrets
                .named_secrets
                .get("password")
                .map(String::as_str),
            Some("browser-secret-marker-7482")
        );

        vault
            .save_connection(input(
                Some(saved.id),
                SecretBundle::default(),
                vec!["password".into()],
            ))
            .unwrap();
        assert!(
            vault
                .get_connection(saved.id)
                .unwrap()
                .secrets
                .named_secrets
                .get("password")
                .is_none()
        );
    }

    #[test]
    fn v2_browser_item_migrates_to_v7_without_plaintext_metadata() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("password".into(), "migration-password-marker".into());
        secrets
            .named_secrets
            .insert("totpSeed".into(), "JBSWY3DPEHPK3PXP".into());
        let now = Utc::now().to_rfc3339();
        let legacy = StoredConnection {
            id: Uuid::new_v4(),
            kind: "browser".into(),
            capabilities: Vec::new(),
            modules: Vec::new(),
            name: "legacy browser".into(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            description: String::new(),
            host: String::new(),
            port: 0,
            username: "legacy-user-marker".into(),
            auth_type: "password".into(),
            ssh_auth_type: String::new(),
            http_auth_type: String::new(),
            private_key_name: String::new(),
            host_fingerprint: String::new(),
            host_fingerprint_host: String::new(),
            host_fingerprint_port: 0,
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
            browser: Some(crate::model::BrowserProfile {
                origin: "https://legacy.example".into(),
                username: "legacy-user-marker".into(),
                selectors: Default::default(),
            }),
            credential: None,
            secret: None,
            encrypted_secrets: vault.inner.key.encrypt(&secrets).unwrap(),
        };
        vault
            .write_document_unlocked(&VaultDocument {
                version: 2,
                settings: Settings::default(),
                browser_bridge_secret: None,
                owner_pin: None,
                connections: vec![legacy],
                editor_drafts: vec![],
                activities: vec![],
                approvals: vec![],
            })
            .unwrap();
        drop(vault);

        let migrated = Vault::open(vault_dir.clone()).unwrap();
        let item = migrated.export_connections().unwrap().pop().unwrap();
        assert!(item.0.kind.is_empty());
        assert_eq!(item.0.capabilities, vec!["fill"]);
        assert_eq!(item.1.get("username"), Some("legacy-user-marker"));
        assert_eq!(item.1.get("password"), Some("migration-password-marker"));
        assert_eq!(item.1.get("totp"), Some("JBSWY3DPEHPK3PXP"));
        let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(raw.contains("\"version\": 7"));
        assert!(!raw.contains("legacy-user-marker"));
        assert!(!raw.contains("migration-password-marker"));
        assert!(!raw.contains("legacy.example"));
    }
}
