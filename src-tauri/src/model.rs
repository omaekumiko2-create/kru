use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEnvelope {
    pub version: u8,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerPinVerifier {
    pub version: u8,
    pub salt: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct Settings {
    pub language: String,
    pub close_behavior: String,
    pub browser_enabled: bool,
    pub browser_port: u16,
    pub browser_paired: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    pub language: Option<String>,
    pub close_behavior: Option<String>,
    pub browser_enabled: Option<bool>,
    pub browser_port: Option<u16>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "en".to_owned(),
            close_behavior: "tray".to_owned(),
            browser_enabled: false,
            browser_port: 39_272,
            browser_paired: false,
        }
    }
}

#[cfg(test)]
mod settings_tests {
    use super::Settings;

    #[test]
    fn older_settings_keep_current_defaults() {
        let settings: Settings = serde_json::from_str(
            r#"{"httpEnabled":false,"httpPort":39271,"browserEnabled":false,"browserPort":39272,"browserPaired":false}"#,
        )
        .unwrap();
        assert_eq!(settings.language, "en");
        assert_eq!(settings.close_behavior, "tray");
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NamedSecrets(pub BTreeMap<String, String>);

impl Zeroize for NamedSecrets {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
        self.0.clear();
    }
}

impl NamedSecrets {
    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.0.values()
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.0.get(name)
    }

    pub fn insert(&mut self, name: String, value: String) {
        self.0.insert(name, value);
    }

    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretField {
    pub name: String,
    #[serde(default = "default_secret_field_kind")]
    pub kind: String,
}

fn default_secret_field_kind() -> String {
    "text".to_owned()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretProfile {
    #[serde(default)]
    pub fields: Vec<SecretField>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemModule {
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub agent_visible: Option<bool>,
}

pub(crate) fn module_kind_has_plaintext_reveal(kind: &str) -> bool {
    matches!(
        kind,
        "username"
            | "password"
            | "apiCredential"
            | "privateKey"
            | "passphrase"
            | "totp"
            | "customSecret"
    )
}

impl ItemModule {
    pub fn is_secret(&self) -> bool {
        module_kind_has_plaintext_reveal(&self.kind)
    }

    pub fn secret_name(&self) -> Option<&str> {
        match self.kind.as_str() {
            "username" => Some("username"),
            "password" => Some("password"),
            "apiCredential" => Some("apiCredential"),
            "privateKey" => Some("privateKey"),
            "passphrase" => Some("passphrase"),
            "totp" => Some("totp"),
            "customSecret" if !self.name.is_empty() => Some(&self.name),
            _ => None,
        }
    }

    pub fn agent_visible(&self) -> bool {
        self.agent_visible
            .unwrap_or(!module_kind_has_plaintext_reveal(&self.kind))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicItemModule {
    pub kind: String,
    pub name: String,
    pub value: String,
    pub secret: bool,
    pub configured: bool,
    #[serde(default)]
    pub agent_visible: Option<bool>,
}

impl PublicItemModule {
    pub fn agent_visible(&self) -> bool {
        self.agent_visible
            .unwrap_or(!module_kind_has_plaintext_reveal(&self.kind))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SecretBundle {
    #[zeroize(skip)]
    #[serde(default)]
    pub private_key_name: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub named_secrets: NamedSecrets,
}

impl SecretBundle {
    pub fn non_empty_values(&self) -> Vec<String> {
        [
            self.password.as_ref(),
            self.passphrase.as_ref(),
            self.private_key.as_ref(),
            self.token.as_ref(),
            self.api_key.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .cloned()
        .chain(
            self.named_secrets
                .values()
                .filter(|value| !value.is_empty())
                .cloned(),
        )
        .collect()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let standard = match name {
            "password" => self.password.as_deref(),
            "passphrase" => self.passphrase.as_deref(),
            "privateKey" | "private_key" => self.private_key.as_deref(),
            "token" => self.token.as_deref(),
            "apiKey" | "api_key" => self.api_key.as_deref(),
            "apiCredential" | "api_credential" => self
                .named_secrets
                .get("apiCredential")
                .map(String::as_str)
                .or(self.token.as_deref())
                .or(self.api_key.as_deref()),
            _ => None,
        };
        standard
            .or_else(|| self.named_secrets.get(name).map(String::as_str))
            .filter(|value| !value.is_empty())
    }

    pub fn available_fields(&self, profile: Option<&SecretProfile>) -> Vec<SecretField> {
        let mut fields = profile
            .map(|profile| profile.fields.clone())
            .unwrap_or_default();
        for (name, present) in [
            (
                "password",
                self.password.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "passphrase",
                self.passphrase.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "privateKey",
                self.private_key.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            ("token", self.token.as_ref().is_some_and(|v| !v.is_empty())),
            (
                "apiKey",
                self.api_key.as_ref().is_some_and(|v| !v.is_empty()),
            ),
        ] {
            if present && !fields.iter().any(|field| field.name == name) {
                fields.push(SecretField {
                    name: name.to_owned(),
                    kind: "text".to_owned(),
                });
            }
        }
        for name in self.named_secrets.keys() {
            if !fields.iter().any(|field| &field.name == name) {
                fields.push(SecretField {
                    name: name.clone(),
                    kind: if name == "totp" { "totp" } else { "text" }.to_owned(),
                });
            }
        }
        fields
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredConnection {
    pub id: Uuid,
    #[serde(default)]
    pub modules: Vec<ItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    #[serde(default)]
    pub private_key_name: String,

    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    #[serde(default)]
    pub test_path: String,
    #[serde(default)]
    pub secret: Option<SecretProfile>,

    pub encrypted_secrets: SecretEnvelope,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiAuthHeader {
    pub name: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableConnection {
    pub id: Uuid,
    pub modules: Vec<ItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
    pub http_auth_type: String,
    pub private_key_name: String,
    pub auth_header: String,
    pub auth_location: String,
    pub auth_prefix: String,
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub test_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicConnection {
    pub id: Uuid,
    pub capabilities: Vec<String>,
    pub can_test: bool,
    #[serde(default)]
    pub modules: Vec<PublicItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    pub private_key_name: String,
    pub base_url: String,
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub test_path: String,
    #[serde(default)]
    pub secret: Option<SecretProfile>,
}

impl StoredConnection {
    fn module_configured(&self, secrets: &SecretBundle, kind: &str) -> bool {
        self.modules.iter().any(|module| {
            module.kind == kind
                && module
                    .secret_name()
                    .and_then(|name| secrets.get(name))
                    .is_some()
        })
    }

    pub fn capabilities(&self, secrets: &SecretBundle) -> Vec<String> {
        let can_fill = self.modules.iter().any(|module| {
            module
                .secret_name()
                .and_then(|name| secrets.get(name))
                .is_some()
        });
        let mut capabilities = Vec::new();
        if can_fill {
            capabilities.push("fill".to_owned());
        }
        if self.module_configured(secrets, "password")
            || self.module_configured(secrets, "privateKey")
        {
            capabilities.push("ssh".to_owned());
        }
        if can_fill {
            capabilities.push("http".to_owned());
        }
        capabilities
    }

    pub fn has_capability(&self, secrets: &SecretBundle, capability: &str) -> bool {
        self.capabilities(secrets)
            .iter()
            .any(|candidate| candidate == capability)
    }

    pub fn test_target(&self, secrets: &SecretBundle) -> Option<&'static str> {
        if self.has_capability(secrets, "ssh")
            && !self.host.trim().is_empty()
            && self.port > 0
            && self.module_configured(secrets, "username")
        {
            Some("ssh")
        } else if self.has_capability(secrets, "http") && !self.base_url.trim().is_empty() {
            Some("http")
        } else {
            None
        }
    }

    pub fn public(&self, secrets: Option<&SecretBundle>) -> PublicConnection {
        PublicConnection {
            id: self.id,
            capabilities: secrets
                .map(|bundle| self.capabilities(bundle))
                .unwrap_or_default(),
            can_test: secrets.is_some_and(|bundle| self.test_target(bundle).is_some()),
            modules: self
                .modules
                .iter()
                .map(|module| {
                    let secret = module.is_secret();
                    PublicItemModule {
                        kind: module.kind.clone(),
                        name: module.name.clone(),
                        value: if secret {
                            String::new()
                        } else {
                            module.value.clone()
                        },
                        secret,
                        configured: if let Some(name) = module.secret_name() {
                            secrets.and_then(|bundle| bundle.get(name)).is_some()
                        } else {
                            !module.value.trim().is_empty()
                        },
                        agent_visible: Some(module.agent_visible()),
                    }
                })
                .collect(),
            name: self.name.clone(),
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            description: self.description.clone(),
            host: self.host.clone(),
            port: self.port,
            ssh_auth_type: self.ssh_auth_type.clone(),
            http_auth_type: self.http_auth_type.clone(),
            private_key_name: self.private_key_name.clone(),
            base_url: self.base_url.clone(),
            auth_header: self.auth_header.clone(),
            auth_location: self.auth_location.clone(),
            auth_prefix: self.auth_prefix.clone(),
            api_auth_headers: self.api_auth_headers.clone(),
            test_path: self.test_path.clone(),
            secret: Some(SecretProfile {
                fields: secrets
                    .map(|bundle| bundle.available_fields(self.secret.as_ref()))
                    .unwrap_or_default(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInput {
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub modules: Vec<ItemModule>,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub http_auth_type: String,
    #[serde(default)]
    pub private_key_import_path: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    #[serde(default)]
    pub test_path: String,
    #[serde(default)]
    pub remove_secret_names: Vec<String>,

    #[serde(default)]
    pub secrets: SecretBundle,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: Uuid,
    pub time: String,
    pub status: String,
    pub source: String,
    pub connection_name: String,
    pub action: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct NewActivity {
    pub status: String,
    pub source: String,
    pub connection_name: String,
    pub action: String,
    pub duration_ms: u64,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDocument {
    pub version: u8,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub browser_bridge_secret: Option<SecretEnvelope>,
    #[serde(default)]
    pub owner_pin: Option<OwnerPinVerifier>,
    #[serde(default)]
    pub connections: Vec<StoredConnection>,
    #[serde(default)]
    pub editor_drafts: Vec<StoredEditorDraft>,
    #[serde(default)]
    pub activities: Vec<Activity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredEditorDraft {
    pub id: Uuid,
    pub updated_at: String,
    pub payload: SecretEnvelope,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerEditorDraft {
    pub id: Uuid,
    pub updated_at: String,
    pub input: ConnectionInput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSecretField {
    pub name: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSecretView {
    pub id: Uuid,
    pub fields: Vec<OwnerSecretField>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerLockState {
    pub pin_configured: bool,
    pub unlocked: bool,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpState {
    pub status: String,
    pub error: String,
    pub endpoint: String,
    pub stdio_command: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityState {
    pub encrypted: bool,
    pub storage: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserBridgeState {
    pub enabled: bool,
    pub paired: bool,
    pub connected: bool,
    pub status: String,
    pub error: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub settings: Settings,
    pub connections: Vec<PublicConnection>,
    pub activities: Vec<Activity>,
    pub mcp: McpState,
    pub browser_bridge: BrowserBridgeState,
    pub security: SecurityState,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub added: usize,
    pub merged: usize,
}

#[cfg(test)]
mod tests {
    use super::{ItemModule, module_kind_has_plaintext_reveal};

    #[test]
    fn plaintext_reveal_capability_drives_default_agent_visibility() {
        for kind in [
            "username",
            "password",
            "apiCredential",
            "privateKey",
            "passphrase",
            "totp",
            "customSecret",
        ] {
            let module = ItemModule {
                kind: kind.to_owned(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            };
            assert!(module_kind_has_plaintext_reveal(kind));
            assert!(!module.agent_visible());
        }

        for kind in ["host", "port", "url"] {
            let module = ItemModule {
                kind: kind.to_owned(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            };
            assert!(!module_kind_has_plaintext_reveal(kind));
            assert!(module.agent_visible());
        }
    }

    #[test]
    fn explicit_agent_visibility_overrides_the_module_default() {
        let visible_secret = ItemModule {
            kind: "password".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: Some(true),
        };
        let hidden_public_value = ItemModule {
            kind: "host".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: Some(false),
        };

        assert!(visible_secret.agent_visible());
        assert!(!hidden_public_value.agent_visible());
    }
}
