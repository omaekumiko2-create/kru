use crate::{
    api_catalog,
    crypto::{MasterKey, create_owner_pin_verifier, verify_owner_pin},
    model::{
        Activity, ApiAuthHeader, AppState, ConnectionInput, ImportSummary, ItemModule, McpState,
        NewActivity, OwnerEditorDraft, OwnerSecretField, OwnerSecretView, PortableConnection,
        PublicConnection, SecretBundle, SecretField, SecretProfile, SecurityState, Settings,
        SettingsPatch, StoredConnection, StoredEditorDraft, VaultDocument,
        module_kind_has_plaintext_reveal,
    },
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use fs2::FileExt;
use reqwest::Method;
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
        let bootstrap = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(data_dir.join("bootstrap.lock"))
            .context("无法打开保险库启动锁")?;
        FileExt::lock_exclusive(&bootstrap).context("无法锁定保险库启动过程")?;

        let result = (|| {
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
                };
                vault.with_exclusive_lock(|_| vault.write_document_unlocked(&document))?;
            } else {
                vault.require_v7()?;
            }
            Ok(vault)
        })();
        let _ = FileExt::unlock(&bootstrap);
        result
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn storage_label(&self) -> &str {
        self.inner.key.source()
    }

    fn require_v7(&self) -> Result<()> {
        let bytes = fs::read(&self.inner.vault_path).context("无法读取保险库")?;
        let document: VaultDocument =
            serde_json::from_slice(&bytes).context("保险库文件格式无效")?;
        if document.version != 7 {
            bail!(
                "KRU 0.14 仅支持模块化 v7 保险库；当前文件版本为 {}",
                document.version
            );
        }
        Ok(())
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

    pub fn disable_owner_pin(&self) -> Result<()> {
        self.update_document(|document| {
            document.owner_pin = None;
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
        input.name = checked_text(&input.name, "项目名称", 80)?;
        input.description = checked_text(&input.description, "项目说明", 240)?;
        let id = id.unwrap_or_else(Uuid::new_v4);
        let updated_at = Utc::now().to_rfc3339();
        let payload = self.inner.key.encrypt(&input)?;
        self.update_document(|document| {
            document.editor_drafts.retain(|draft| draft.id != id);
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
            document.settings = next.clone();
            Ok(())
        })?;
        Ok(next)
    }

    pub fn update_settings_patch(&self, patch: SettingsPatch) -> Result<Settings> {
        self.update_document_with_result(|document| {
            let mut next = document.settings.clone();
            if let Some(language) = patch.language {
                next.language = if language.eq_ignore_ascii_case("en") {
                    "en".to_owned()
                } else {
                    "zh".to_owned()
                };
            }
            if let Some(close_behavior) = patch.close_behavior {
                next.close_behavior = if close_behavior.eq_ignore_ascii_case("exit") {
                    "exit".to_owned()
                } else {
                    "tray".to_owned()
                };
            }
            if let Some(browser_enabled) = patch.browser_enabled {
                next.browser_enabled = browser_enabled;
            }
            if let Some(browser_port) = patch.browser_port {
                if browser_port < 1024 {
                    bail!("本地端口必须在 1024–65535 之间");
                }
                next.browser_port = browser_port;
            }
            document.settings = next.clone();
            Ok(next)
        })
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
        self.list_decrypted_connections().map(|connections| {
            connections
                .into_iter()
                .map(|connection| connection.stored.public(Some(&connection.secrets)))
                .collect()
        })
    }

    pub fn list_decrypted_connections(&self) -> Result<Vec<DecryptedConnection>> {
        let document = self.read_document()?;
        document
            .connections
            .into_iter()
            .map(|stored| {
                let secrets = self.inner.key.decrypt(&stored.encrypted_secrets)?;
                Ok(DecryptedConnection { stored, secrets })
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
        // Module names are length-checked when saved. Do not truncate a caller's
        // lookup here: a longer, different name must never alias an existing
        // credential and fill the wrong value.
        let field = field.trim().to_owned();
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
            }
            merge_secret_bundle(&mut secrets, &input.secrets);
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

            input.name = checked_text(&input.name, "项目名称", 80)?;
            if input.name.is_empty() {
                bail!("项目名称不能为空");
            }
            if document
                .connections
                .iter()
                .enumerate()
                .any(|(index, item)| {
                    Some(index) != existing_index && same_item_name(&item.name, &input.name)
                })
            {
                bail!("项目名称已存在，请使用其他名称");
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

    pub fn app_state(
        &self,
        executable: &str,
        browser_bridge: crate::model::BrowserBridgeState,
    ) -> Result<AppState> {
        let document = self.read_document()?;
        let connections = document
            .connections
            .iter()
            .map(|connection| {
                let secrets: SecretBundle =
                    self.inner.key.decrypt(&connection.encrypted_secrets)?;
                Ok(connection.public(Some(&secrets)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AppState {
            connections,
            activities: document.activities.clone(),
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
            settings: document.settings.clone(),
        })
    }

    pub fn export_connections(&self) -> Result<Vec<(PortableConnection, SecretBundle)>> {
        let document = self.read_document()?;
        document
            .connections
            .into_iter()
            .map(|connection| {
                let secrets = self
                    .inner
                    .key
                    .decrypt::<SecretBundle>(&connection.encrypted_secrets)?;
                Ok((
                    PortableConnection {
                        id: connection.id,
                        modules: connection.modules,
                        name: connection.name,
                        enabled: connection.enabled,
                        created_at: connection.created_at,
                        updated_at: connection.updated_at,
                        description: connection.description,
                        http_auth_type: connection.http_auth_type,
                        private_key_name: connection.private_key_name,
                        host_fingerprint: connection.host_fingerprint,
                        host_fingerprint_host: connection.host_fingerprint_host,
                        host_fingerprint_port: connection.host_fingerprint_port,
                        auth_header: connection.auth_header,
                        auth_location: connection.auth_location,
                        auth_prefix: connection.auth_prefix,
                        api_auth_headers: connection.api_auth_headers,
                        allowed_methods: connection.allowed_methods,
                        allowed_path_prefixes: connection.allowed_path_prefixes,
                        test_path: connection.test_path,
                    },
                    secrets,
                ))
            })
            .collect()
    }

    pub fn merge_connections(
        &self,
        imported: Vec<(PortableConnection, SecretBundle)>,
    ) -> Result<ImportSummary> {
        self.update_document_with_result(|document| {
            let mut summary = ImportSummary {
                added: 0,
                merged: 0,
            };
            for (public, secrets) in imported {
                let mut stored = stored_from_portable(&public, &secrets, &self.inner.key)?;
                let imported_secrets: SecretBundle =
                    self.inner.key.decrypt(&stored.encrypted_secrets)?;
                let requested_name = clean_text(&stored.name, 80);
                stored.name = if requested_name.is_empty() {
                    "导入项目".to_owned()
                } else {
                    requested_name
                };

                let has_requested_name = document
                    .connections
                    .iter()
                    .any(|item| same_item_name(&item.name, &stored.name));
                let mut duplicate = false;
                for existing in document.connections.iter().filter(|item| {
                    same_item_name(&item.name, &stored.name)
                        || (has_requested_name && import_name_in_family(&item.name, &stored.name))
                }) {
                    let existing_secrets: SecretBundle =
                        self.inner.key.decrypt(&existing.encrypted_secrets)?;
                    if same_portable_content(
                        existing,
                        &existing_secrets,
                        &stored,
                        &imported_secrets,
                    ) {
                        duplicate = true;
                        break;
                    }
                }

                if duplicate {
                    summary.merged += 1;
                    continue;
                }

                stored.name = unique_import_name(&document.connections, &stored.name);
                if document.connections.iter().any(|item| item.id == stored.id) {
                    stored.id = Uuid::new_v4();
                }
                document.connections.push(stored);
                summary.added += 1;
            }
            document.activities.insert(
                0,
                Activity {
                    id: Uuid::new_v4(),
                    time: Utc::now().to_rfc3339(),
                    status: "success".to_owned(),
                    source: "应用".to_owned(),
                    connection_name: "便携备份".to_owned(),
                    action: format!(
                        "导入备份：新增 {}，合并重复 {}",
                        summary.added, summary.merged
                    ),
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
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.inner.lock_path)
            .context("无法打开保险库锁文件")
    }
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
        module.kind = module.kind.trim().to_owned();
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
            module.agent_visible = Some(!module_kind_has_plaintext_reveal(&module.kind));
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
            module.name = checked_text(&module.name, "自定义秘密字段名称", 80)?;
            if !valid_identifier(&module.name)
                || canonical_secret_module_name(&module.name).is_some()
                || matches!(module.name.as_str(), "token" | "apiKey" | "api_key")
            {
                bail!("自定义秘密字段名称无效：{}", module.name);
            }
            module.value.clear();
        } else {
            module.name.clear();
            module.value = module.value.trim().to_owned();
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
        agent_visible: Some(!module_kind_has_plaintext_reveal(kind)),
    });
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

fn normalize_connection_v7(
    input: ConnectionInput,
    existing: Option<&StoredConnection>,
    secrets: &SecretBundle,
    private_key_name: String,
    now: String,
) -> Result<StoredConnection> {
    let modules = normalize_modules(input.modules)?;

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
    let http_auth_type = input.http_auth_type.clone();
    let capabilities =
        derive_capabilities(&modules, secrets, &http_auth_type, &input.api_auth_headers);
    let allowed_methods = normalize_http_methods(input.allowed_methods)?;
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
        description: checked_text(&input.description, "项目说明", 240)?,
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
        host_fingerprint: String::new(),
        host_fingerprint_host: String::new(),
        host_fingerprint_port: 0,
        base_url,
        auth_header: input.auth_header.trim().to_owned(),
        auth_location: input.auth_location.trim().to_owned(),
        auth_prefix: input.auth_prefix.trim().to_owned(),
        api_auth_headers: input.api_auth_headers,
        allowed_methods,
        allowed_path_prefixes: normalize_trimmed_list(input.allowed_path_prefixes),
        test_path: input.test_path.trim().to_owned(),
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
    portable: &PortableConnection,
    secrets: &SecretBundle,
    key: &MasterKey,
) -> Result<StoredConnection> {
    let input = ConnectionInput {
        id: Some(portable.id),
        modules: portable.modules.clone(),
        name: portable.name.clone(),
        enabled: portable.enabled,
        description: portable.description.clone(),
        http_auth_type: portable.http_auth_type.clone(),
        private_key_import_path: String::new(),
        auth_header: portable.auth_header.clone(),
        auth_location: portable.auth_location.clone(),
        auth_prefix: portable.auth_prefix.clone(),
        api_auth_headers: portable.api_auth_headers.clone(),
        allowed_methods: portable.allowed_methods.clone(),
        allowed_path_prefixes: portable.allowed_path_prefixes.clone(),
        test_path: portable.test_path.clone(),
        remove_secret_names: Vec::new(),
        secrets: secrets.clone(),
    };
    let mut stored = normalize_connection_v7(
        input,
        None,
        secrets,
        portable.private_key_name.clone(),
        portable.updated_at.clone(),
    )?;
    stored.created_at = portable.created_at.clone();
    stored.encrypted_secrets = key.encrypt(&secrets)?;
    Ok(stored)
}

fn same_portable_content(
    left: &StoredConnection,
    left_secrets: &SecretBundle,
    right: &StoredConnection,
    right_secrets: &SecretBundle,
) -> bool {
    if left.modules != right.modules {
        return false;
    }
    for module in &left.modules {
        let Some(name) = module.secret_name() else {
            continue;
        };
        if left_secrets.get(name) != right_secrets.get(name) {
            return false;
        }
    }
    true
}

fn import_name_in_family(candidate: &str, requested: &str) -> bool {
    let Some((candidate_base, candidate_index)) = split_numbered_import_name(candidate) else {
        return false;
    };
    let (requested_base, requested_index) = split_numbered_import_name(requested)
        .map(|(base, index)| (base, index + 1))
        .unwrap_or((requested, 2));
    same_item_name(candidate_base, requested_base) && candidate_index >= requested_index
}

fn split_numbered_import_name(name: &str) -> Option<(&str, usize)> {
    let without_closing = name.strip_suffix(')')?;
    let opening = without_closing.rfind('(')?;
    let index = without_closing[opening + 1..].parse::<usize>().ok()?;
    ((2..usize::MAX).contains(&index) && opening > 0)
        .then_some((&without_closing[..opening], index))
}

fn unique_import_name(connections: &[StoredConnection], requested: &str) -> String {
    unique_item_name(requested, |candidate| {
        connections
            .iter()
            .any(|item| same_item_name(&item.name, candidate))
    })
}

fn unique_item_name<F>(requested: &str, exists: F) -> String
where
    F: Fn(&str) -> bool,
{
    if !exists(requested) {
        return requested.to_owned();
    }
    let (base, mut index) = split_numbered_import_name(requested)
        .map(|(base, index)| (base, index + 1))
        .unwrap_or((requested, 2));
    loop {
        let candidate = format!("{base}({index})");
        if !exists(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn same_item_name(left: &str, right: &str) -> bool {
    left.trim().to_lowercase() == right.trim().to_lowercase()
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
        || input.http_auth_type != "auto"
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
    let current_url = module_value(&input.modules, "url").unwrap_or_default();
    let profile = api_catalog::infer(&input.name, current_url, &secret);
    let normalized_url = api_catalog::normalize_base_url(current_url, profile.default_base_url)?;
    if !normalized_url.is_empty() {
        if let Some(module) = input.modules.iter_mut().find(|module| module.kind == "url") {
            module.value = normalized_url;
        } else {
            push_module(&mut input.modules, "url", "", &normalized_url);
        }
    }
    input.http_auth_type = profile.auth_type.to_owned();
    input.auth_header = profile.auth_header.to_owned();
    input.auth_location = profile.auth_location.to_owned();
    input.auth_prefix = profile.auth_prefix.to_owned();
    input.api_auth_headers.clear();
    input.allowed_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    input.allowed_path_prefixes.clear();
    input.test_path.clear();
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn normalize_http_methods(values: Vec<String>) -> Result<Vec<String>> {
    let mut output = Vec::new();
    for value in values {
        let value = value.trim().to_ascii_uppercase();
        if value.is_empty() || output.contains(&value) {
            continue;
        }
        Method::from_bytes(value.as_bytes()).with_context(|| format!("HTTP 方法无效：{value}"))?;
        output.push(value);
    }
    if output.is_empty() {
        output = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
            .into_iter()
            .map(str::to_owned)
            .collect();
    }
    Ok(output)
}

fn normalize_trimmed_list(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let value = value.trim().to_owned();
        if !value.is_empty() && !output.contains(&value) {
            output.push(value);
        }
    }
    output
}

fn checked_text(value: &str, label: &str, max_chars: usize) -> Result<String> {
    let value = value.trim();
    if value.chars().count() > max_chars {
        bail!("{label}不能超过 {max_chars} 个字符");
    }
    Ok(value.to_owned())
}

fn clean_text(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
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

    #[test]
    fn module_normalization_preserves_editor_order() {
        let modules = vec![
            ItemModule {
                kind: "url".to_owned(),
                name: String::new(),
                value: "https://example.test".to_owned(),
                agent_visible: None,
            },
            ItemModule {
                kind: "password".to_owned(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            },
            ItemModule {
                kind: "host".to_owned(),
                name: String::new(),
                value: "example.test".to_owned(),
                agent_visible: None,
            },
        ];

        let normalized = normalize_modules(modules).unwrap();
        assert_eq!(
            normalized
                .iter()
                .map(|module| module.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["url", "password", "host"]
        );
        assert_eq!(
            normalized
                .iter()
                .map(|module| module.agent_visible)
                .collect::<Vec<_>>(),
            vec![Some(true), Some(false), Some(true)]
        );
    }

    fn api_input(id: Option<Uuid>, name: &str, token: &str) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiCredential".into(), token.to_owned());
        ConnectionInput {
            id,
            modules: vec![
                ItemModule {
                    kind: "url".into(),
                    value: "https://api.example.test/v1/".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "apiCredential".into(),
                    ..Default::default()
                },
            ],
            name: name.to_owned(),
            enabled: true,
            description: "test connection".to_owned(),
            http_auth_type: "bearer".to_owned(),
            private_key_import_path: String::new(),
            auth_header: "X-API-Key".to_owned(),
            auth_location: "header".to_owned(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            allowed_methods: vec!["GET".to_owned()],
            allowed_path_prefixes: vec!["/v1/".to_owned()],
            test_path: "/health".to_owned(),
            remove_secret_names: vec![],
            secrets,
        }
    }

    fn ssh_input(id: Option<Uuid>) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets.password = Some("test-password".to_owned());
        secrets
            .named_secrets
            .insert("username".into(), "root".into());
        ConnectionInput {
            id,
            modules: vec![
                ItemModule {
                    kind: "host".into(),
                    value: "127.0.0.1".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "port".into(),
                    value: "22".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "username".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "password".into(),
                    ..Default::default()
                },
            ],
            name: "ssh-test".to_owned(),
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

        let existing_item_id = Uuid::new_v4();
        let mut replacement = ssh_input(Some(existing_item_id));
        replacement.name = "replacement-draft".to_owned();
        let replacement = vault.save_editor_draft(None, replacement).unwrap();
        let drafts = vault.list_editor_drafts().unwrap();
        assert_eq!(drafts.len(), 2);
        assert!(drafts.iter().any(|draft| draft.id == replacement.id));
        assert_eq!(
            drafts
                .iter()
                .find(|draft| draft.id == replacement.id)
                .unwrap()
                .input
                .id,
            Some(existing_item_id)
        );
        assert_ne!(replacement.id, saved.id);

        vault.delete_editor_draft(replacement.id).unwrap();
        let drafts = vault.list_editor_drafts().unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].id, saved.id);
    }

    #[test]
    fn automatic_api_requires_only_a_secret_and_normalizes_optional_url() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut input = api_input(None, "Addressless API", "opaque-api-secret");
        input.http_auth_type = "auto".to_owned();
        input.modules.retain(|module| module.kind != "url");
        let addressless = vault.save_connection(input).unwrap();
        assert_eq!(addressless.name, "Addressless API");
        assert!(addressless.base_url.is_empty());
        assert_eq!(addressless.auth_type, "bearer");

        let mut input = api_input(None, "Example", "another-api-secret");
        input.http_auth_type = "auto".to_owned();
        input
            .modules
            .iter_mut()
            .find(|module| module.kind == "url")
            .unwrap()
            .value = "api.example.test/v1".to_owned();
        let normalized = vault.save_connection(input).unwrap();
        assert_eq!(normalized.base_url, "https://api.example.test/v1");
    }

    #[test]
    fn explicit_api_transport_settings_survive_editor_saves() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut input = api_input(None, "Configured API", "configured-api-secret");
        input.auth_prefix = "Token".to_owned();
        input.allowed_methods.push("PROPFIND".to_owned());
        let saved = vault.save_connection(input).unwrap();

        assert_eq!(saved.http_auth_type, "bearer");
        assert_eq!(saved.auth_header, "X-API-Key");
        assert_eq!(saved.auth_prefix, "Token");
        assert_eq!(saved.allowed_methods, vec!["GET", "PROPFIND"]);
        assert_eq!(saved.allowed_path_prefixes, vec!["/v1/"]);
        assert_eq!(saved.test_path, "/health");
    }

    #[test]
    fn operational_api_values_are_preserved_instead_of_silently_truncated() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let long_url = format!("https://example.test/{}", "route/".repeat(120));
        let long_prefix = format!("/{}", "scope/".repeat(80));
        let long_test_path = format!("/{}", "health/".repeat(80));
        let long_auth_prefix = "CustomAuthorizationPrefix".repeat(4);
        let mut input = api_input(None, "Long API configuration", "long-api-secret");
        input
            .modules
            .iter_mut()
            .find(|module| module.kind == "url")
            .unwrap()
            .value = long_url.clone();
        input.allowed_methods = vec!["get".to_owned(), "PROPFIND".to_owned()];
        input.allowed_path_prefixes = vec![long_prefix.clone()];
        input.test_path = long_test_path.clone();
        input.auth_prefix = long_auth_prefix.clone();

        let saved = vault.save_connection(input).unwrap();
        assert_eq!(saved.base_url, long_url);
        assert_eq!(saved.allowed_methods, vec!["GET", "PROPFIND"]);
        assert_eq!(saved.allowed_path_prefixes, vec![long_prefix]);
        assert_eq!(saved.test_path, long_test_path);
        assert_eq!(saved.auth_prefix, long_auth_prefix);

        let mut invalid = api_input(None, "Invalid method", "invalid-method-secret");
        invalid.allowed_methods = vec!["NOT VALID".to_owned()];
        assert!(
            vault
                .save_connection(invalid)
                .unwrap_err()
                .to_string()
                .contains("HTTP 方法无效")
        );
    }

    #[test]
    fn v7_modules_derive_mixed_actions_and_keep_incomplete_items_as_drafts() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut mixed = ssh_input(None);
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
        draft.name = "Draft host".to_owned();
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
    fn item_names_are_unique_ignoring_case_and_outer_whitespace() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let saved = vault
            .save_connection(api_input(None, "Production API", "first-token"))
            .unwrap();

        let duplicate = vault
            .save_connection(api_input(None, "  production api  ", "second-token"))
            .unwrap_err();
        assert!(duplicate.to_string().contains("名称已存在"));

        let renamed = vault
            .save_connection(api_input(Some(saved.id), "PRODUCTION API", "first-token"))
            .unwrap();
        assert_eq!(renamed.name, "PRODUCTION API");
    }

    #[test]
    fn unsupported_vault_versions_are_rejected() {
        let directory = tempdir().unwrap();
        let vault_dir = directory.path().join("vault");
        let vault = Vault::open(vault_dir.clone()).unwrap();
        let mut document = vault.read_document().unwrap();
        document.version = 6;
        vault.write_document_unlocked(&document).unwrap();
        drop(vault);

        let error = Vault::open(vault_dir).err().expect("version 6 must fail");
        assert!(format!("{error:#}").contains("仅支持模块化 v7"));
    }

    #[test]
    fn removing_a_secret_module_deletes_its_encrypted_value() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let saved = vault.save_connection(ssh_input(None)).unwrap();
        let existing = vault.get_connection(saved.id).unwrap();
        let mut update = ssh_input(Some(saved.id));
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
                .find(|field| field.name == "apiCredential")
                .map(|field| field.value.as_str()),
            Some("owner-token-marker-7721")
        );

        vault.disable_owner_pin().unwrap();
        assert!(!vault.owner_pin_configured().unwrap());
    }

    #[test]
    fn settings_patches_do_not_overwrite_unrelated_concurrent_changes() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().to_path_buf()).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

        let language_vault = vault.clone();
        let language_barrier = barrier.clone();
        let language = std::thread::spawn(move || {
            language_barrier.wait();
            language_vault
                .update_settings_patch(SettingsPatch {
                    language: Some("en".to_owned()),
                    ..SettingsPatch::default()
                })
                .unwrap();
        });

        let browser_vault = vault.clone();
        let browser_barrier = barrier.clone();
        let browser = std::thread::spawn(move || {
            browser_barrier.wait();
            browser_vault
                .update_settings_patch(SettingsPatch {
                    browser_enabled: Some(true),
                    ..SettingsPatch::default()
                })
                .unwrap();
        });

        barrier.wait();
        language.join().unwrap();
        browser.join().unwrap();

        let settings = vault.settings().unwrap();
        assert_eq!(settings.language, "en");
        assert!(settings.browser_enabled);
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
    fn concurrent_first_open_uses_one_initialized_vault() {
        let directory = tempdir().unwrap();
        let vault_dir = Arc::new(directory.path().join("vault"));
        let barrier = Arc::new(std::sync::Barrier::new(6));
        let handles = (0..6)
            .map(|index| {
                let vault_dir = vault_dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let vault = Vault::open((*vault_dir).clone()).unwrap();
                    vault
                        .save_connection(api_input(
                            None,
                            &format!("first-open-{index}"),
                            &format!("first-open-secret-{index}"),
                        ))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let reopened = Vault::open((*vault_dir).clone()).unwrap();
        let connections = reopened.list_decrypted_connections().unwrap();
        assert_eq!(connections.len(), 6);
        for index in 0..6 {
            assert!(connections.iter().any(|connection| {
                connection.stored.name == format!("first-open-{index}")
                    && connection.secrets.get("apiCredential")
                        == Some(format!("first-open-secret-{index}").as_str())
            }));
        }
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
                modules: vec![
                    ItemModule {
                        kind: "host".into(),
                        value: "127.0.0.1".into(),
                        ..Default::default()
                    },
                    ItemModule {
                        kind: "port".into(),
                        value: "22".into(),
                        ..Default::default()
                    },
                    ItemModule {
                        kind: "username".into(),
                        ..Default::default()
                    },
                    ItemModule {
                        kind: "privateKey".into(),
                        ..Default::default()
                    },
                ],
                name: "key-test".into(),
                enabled: true,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: key_path.to_string_lossy().into_owned(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: vec![],
                allowed_methods: vec![],
                allowed_path_prefixes: vec![],
                test_path: String::new(),
                remove_secret_names: vec![],
                secrets: {
                    let mut secrets = SecretBundle::default();
                    secrets
                        .named_secrets
                        .insert("username".into(), "root".into());
                    secrets
                },
            })
            .unwrap();
        fs::remove_file(&key_path).unwrap();

        let decrypted = vault.get_connection(saved.id).unwrap();
        assert_eq!(decrypted.secrets.private_key.as_deref(), Some(key_marker));
        assert_eq!(decrypted.stored.private_key_name, "id_test");
        let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
        assert!(!raw.contains("private-key-marker-4382"));
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
            modules: vec![
                ItemModule {
                    kind: "username".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "password".into(),
                    ..Default::default()
                },
            ],
            name: "generic-login".into(),
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
    fn secret_lookup_never_aliases_a_longer_module_name() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let module_name = format!("a{}", "x".repeat(79));
        let mut input = api_input(None, "Exact module lookup", "api-secret");
        input.modules.push(ItemModule {
            kind: "customSecret".into(),
            name: module_name.clone(),
            agent_visible: Some(false),
            ..Default::default()
        });
        input
            .secrets
            .named_secrets
            .insert(module_name.clone(), "exact-secret".into());
        let saved = vault.save_connection(input).unwrap();

        assert_eq!(
            vault.get_secret_value(saved.id, &module_name).unwrap().2,
            "exact-secret"
        );
        assert!(
            vault
                .get_secret_value(saved.id, &format!("{module_name}x"))
                .is_err()
        );
    }
}
