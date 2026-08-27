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
    pub agent_mcp_onboarding_version: u8,
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
            agent_mcp_onboarding_version: 0,
        }
    }
}

#[cfg(test)]
mod settings_tests {
    use super::Settings;

    #[test]
    fn older_settings_default_agent_onboarding_to_zero() {
        let settings: Settings = serde_json::from_str(
            r#"{"httpEnabled":false,"httpPort":39271,"browserEnabled":false,"browserPort":39272,"browserPaired":false}"#,
        )
        .unwrap();
        assert_eq!(settings.agent_mcp_onboarding_version, 0);
        assert_eq!(settings.language, "en");
        assert_eq!(settings.close_behavior, "tray");
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliParameterSpec {
    pub name: String,
    pub label: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_parameter_length")]
    pub max_length: usize,
    #[serde(default)]
    pub allow_leading_dash: bool,
}

fn default_parameter_length() -> usize {
    200
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliEnvBinding {
    pub variable: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliAction {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<CliParameterSpec>,
    #[serde(default)]
    pub env: Vec<CliEnvBinding>,
    #[serde(default)]
    pub stdin_secret: String,
    #[serde(default = "default_cli_timeout")]
    pub timeout_seconds: u64,
}

fn default_cli_timeout() -> u64 {
    60
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
pub struct CliProfile {
    pub executable_path: String,
    #[serde(default)]
    pub working_directory: String,
    #[serde(default)]
    pub secret_names: Vec<String>,
    #[serde(default)]
    pub actions: Vec<CliAction>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSelectors {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub submit: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProfile {
    pub origin: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub selectors: BrowserSelectors,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProfile {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub bound_executable: String,
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

    pub fn has_auth_secret(&self) -> bool {
        self.password.as_ref().is_some_and(|v| !v.is_empty())
            || self.private_key.as_ref().is_some_and(|v| !v.is_empty())
            || self.token.as_ref().is_some_and(|v| !v.is_empty())
            || self.api_key.as_ref().is_some_and(|v| !v.is_empty())
            || self.named_secrets.values().any(|value| !value.is_empty())
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
    #[serde(default, rename = "type", skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
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
    pub username: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    #[serde(default)]
    pub private_key_name: String,
    #[serde(default)]
    pub host_fingerprint: String,
    #[serde(default)]
    pub host_fingerprint_host: String,
    #[serde(default)]
    pub host_fingerprint_port: u16,

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
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    #[serde(default)]
    pub test_path: String,
    #[serde(default)]
    pub cli: Option<CliProfile>,
    #[serde(default)]
    pub browser: Option<BrowserProfile>,
    #[serde(default)]
    pub credential: Option<CredentialProfile>,
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
    pub host_fingerprint: String,
    pub host_fingerprint_host: String,
    pub host_fingerprint_port: u16,
    pub auth_header: String,
    pub auth_location: String,
    pub auth_prefix: String,
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub test_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicConnection {
    pub id: Uuid,
    #[serde(default, rename = "type", skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default = "default_item_capabilities")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub modules: Vec<PublicItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    pub private_key_name: String,
    pub has_private_key: bool,
    pub host_fingerprint: String,
    pub base_url: String,
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub test_path: String,
    #[serde(default)]
    pub cli: Option<CliProfile>,
    #[serde(default)]
    pub browser: Option<BrowserProfile>,
    #[serde(default)]
    pub credential: Option<CredentialProfile>,
    #[serde(default)]
    pub secret: Option<SecretProfile>,
    #[serde(default)]
    pub executable_available: bool,
    #[serde(default)]
    pub secret_names: Vec<String>,
    pub has_secret: bool,
}

impl StoredConnection {
    pub fn normalized_capabilities(&self) -> Vec<String> {
        normalize_item_capabilities(&self.capabilities, &self.kind)
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.normalized_capabilities()
            .iter()
            .any(|candidate| candidate == capability)
    }

    pub fn public(&self, secrets: Option<&SecretBundle>) -> PublicConnection {
        PublicConnection {
            id: self.id,
            kind: String::new(),
            capabilities: self.normalized_capabilities(),
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
            // Usernames are secrets in v3. The public model never exposes them.
            username: String::new(),
            auth_type: self.auth_type.clone(),
            ssh_auth_type: self.ssh_auth_type.clone(),
            http_auth_type: self.http_auth_type.clone(),
            private_key_name: self.private_key_name.clone(),
            has_private_key: secrets.and_then(|s| s.private_key.as_ref()).is_some(),
            host_fingerprint: self.host_fingerprint.clone(),
            base_url: self.base_url.clone(),
            auth_header: self.auth_header.clone(),
            auth_location: self.auth_location.clone(),
            auth_prefix: self.auth_prefix.clone(),
            api_auth_headers: self.api_auth_headers.clone(),
            allowed_methods: self.allowed_methods.clone(),
            allowed_path_prefixes: self.allowed_path_prefixes.clone(),
            test_path: self.test_path.clone(),
            cli: None,
            browser: None,
            credential: None,
            secret: Some(SecretProfile {
                fields: secrets
                    .map(|bundle| bundle.available_fields(self.secret.as_ref()))
                    .unwrap_or_default(),
            }),
            executable_available: true,
            secret_names: secrets
                .map(|bundle| bundle.named_secrets.keys().cloned().collect())
                .unwrap_or_default(),
            has_secret: secrets.is_some_and(SecretBundle::has_auth_secret),
        }
    }
}

fn default_item_capabilities() -> Vec<String> {
    vec!["fill".to_owned()]
}

pub fn normalize_item_capabilities(values: &[String], legacy_kind: &str) -> Vec<String> {
    let mut capabilities = Vec::new();
    let recognized = values
        .iter()
        .any(|value| matches!(value.as_str(), "fill" | "ssh" | "api" | "http"));
    if recognized {
        capabilities.push("fill".to_owned());
    }
    for value in values {
        let capability = match value.as_str() {
            "ssh" => "ssh",
            "api" | "http" => "http",
            _ => continue,
        };
        if !capabilities.iter().any(|item| item == capability) {
            capabilities.push(capability.to_owned());
        }
    }
    if capabilities.is_empty() {
        match legacy_kind {
            "ssh" => capabilities.extend(["fill".to_owned(), "ssh".to_owned()]),
            "api" => capabilities.extend(["fill".to_owned(), "http".to_owned()]),
            "secret" | "browser" | "credential" | "cli" => capabilities.push("fill".to_owned()),
            _ => {}
        }
    }
    capabilities
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
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
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
