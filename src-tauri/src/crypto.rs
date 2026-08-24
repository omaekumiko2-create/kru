use crate::model::{OwnerPinVerifier, SecretEnvelope};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{fs, path::Path};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SECRET_AAD: &[u8] = b"mcp-vault/secret/v2";
const BACKUP_AAD: &[u8] = b"mcp-vault/backup/v1";

pub fn create_owner_pin_verifier(pin: &str) -> Result<OwnerPinVerifier> {
    validate_owner_pin(pin)?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|error| anyhow::anyhow!("无法生成 PIN salt：{error}"))?;
    let hash = derive_owner_pin_hash(pin, &salt)?;
    Ok(OwnerPinVerifier {
        version: 1,
        salt: STANDARD_NO_PAD.encode(salt),
        hash: STANDARD_NO_PAD.encode(hash),
    })
}

pub fn verify_owner_pin(pin: &str, verifier: &OwnerPinVerifier) -> Result<bool> {
    validate_owner_pin(pin)?;
    if verifier.version != 1 {
        bail!("不支持的 PIN 版本");
    }
    let salt = STANDARD_NO_PAD
        .decode(&verifier.salt)
        .context("PIN salt 无效")?;
    let expected = STANDARD_NO_PAD
        .decode(&verifier.hash)
        .context("PIN hash 无效")?;
    let actual = derive_owner_pin_hash(pin, &salt)?;
    Ok(expected.len() == actual.len() && expected.ct_eq(actual.as_slice()).into())
}

fn validate_owner_pin(pin: &str) -> Result<()> {
    if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("PIN 必须是六位数字");
    }
    Ok(())
}

fn derive_owner_pin_hash(pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("Argon2 参数无效：{error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0_u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut hash)
        .map_err(|error| anyhow::anyhow!("无法验证 PIN：{error}"))?;
    Ok(hash)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
    #[zeroize(skip)]
    source: String,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MasterKey")
            .field("bytes", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

impl MasterKey {
    pub fn load_or_create(data_dir: &Path, vault_exists: bool) -> Result<Self> {
        Self::load_or_create_inner(data_dir, vault_exists, true)
    }

    fn load_or_create_inner(
        data_dir: &Path,
        vault_exists: bool,
        use_keyring: bool,
    ) -> Result<Self> {
        fs::create_dir_all(data_dir).context("无法创建保险库目录")?;
        let key_file = data_dir.join("master.key");

        if use_keyring && let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
            if let Ok(encoded) = entry.get_password() {
                if let Ok(bytes) = decode_key(&encoded) {
                    return Ok(Self {
                        bytes,
                        source: system_storage_label().to_owned(),
                    });
                }
            }
        }

        if key_file.exists() {
            let encoded = fs::read_to_string(&key_file).context("无法读取本地权限密钥文件")?;
            return Ok(Self {
                bytes: decode_key(encoded.trim())?,
                source: "本地权限密钥文件".to_owned(),
            });
        }

        if vault_exists {
            bail!("保险库主密钥缺失；为避免覆盖数据，程序已拒绝生成新密钥");
        }

        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("无法生成保险库主密钥：{error}"))?;
        let encoded = STANDARD_NO_PAD.encode(bytes);

        if use_keyring && let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
            if entry.set_password(&encoded).is_ok() {
                return Ok(Self {
                    bytes,
                    source: system_storage_label().to_owned(),
                });
            }
        }

        write_private_file(&key_file, encoded.as_bytes())?;
        Ok(Self {
            bytes,
            source: "本地权限密钥文件".to_owned(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn encrypt<T: Serialize>(&self, value: &T) -> Result<SecretEnvelope> {
        let bytes = serde_json::to_vec(value).context("无法序列化秘密")?;
        encrypt_bytes(&self.bytes, &bytes, SECRET_AAD)
    }

    pub fn decrypt<T: DeserializeOwned>(&self, envelope: &SecretEnvelope) -> Result<T> {
        let plain = decrypt_bytes(&self.bytes, envelope, SECRET_AAD)?;
        serde_json::from_slice(&plain).context("秘密内容格式无效")
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD_NO_PAD.decode(encoded).context("主密钥格式无效")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("主密钥长度无效"))
}

fn system_storage_label() -> &'static str {
    #[cfg(target_os = "windows")]
    return "Windows Credential Manager";
    #[cfg(target_os = "macos")]
    return "macOS Keychain";
    #[cfg(all(unix, not(target_os = "macos")))]
    return "Linux Secret Service";
    #[allow(unreachable_code)]
    "系统安全存储"
}

pub fn encrypt_bytes(key: &[u8; 32], bytes: &[u8], aad: &[u8]) -> Result<SecretEnvelope> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| anyhow::anyhow!("无法生成加密 nonce：{error}"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: bytes, aad })
        .map_err(|_| anyhow::anyhow!("秘密加密失败"))?;
    Ok(SecretEnvelope {
        version: 1,
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_bytes(key: &[u8; 32], envelope: &SecretEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.version != 1 {
        bail!("不支持的密文版本");
    }
    let nonce = STANDARD_NO_PAD
        .decode(&envelope.nonce)
        .context("密文 nonce 无效")?;
    if nonce.len() != 24 {
        bail!("密文 nonce 长度无效");
    }
    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.ciphertext)
        .context("密文内容无效")?;
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("密文校验失败或密钥不正确"))
}

pub fn derive_backup_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    if password.chars().count() < 8 {
        bail!("备份密码至少需要 8 个字符");
    }
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("Argon2 参数无效：{error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow::anyhow!("备份密钥派生失败：{error}"))?;
    Ok(key)
}

pub fn encrypt_backup(password: &str, bytes: &[u8]) -> Result<(String, SecretEnvelope)> {
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|error| anyhow::anyhow!("无法生成备份 salt：{error}"))?;
    let mut key = derive_backup_key(password, &salt)?;
    let envelope = encrypt_bytes(&key, bytes, BACKUP_AAD)?;
    key.zeroize();
    Ok((STANDARD_NO_PAD.encode(salt), envelope))
}

pub fn decrypt_backup(password: &str, salt: &str, envelope: &SecretEnvelope) -> Result<Vec<u8>> {
    let salt = STANDARD_NO_PAD.decode(salt).context("备份 salt 无效")?;
    let mut key = derive_backup_key(password, &salt)?;
    let result = decrypt_bytes(&key, envelope, BACKUP_AAD);
    key.zeroize();
    result
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::{fs::OpenOptions, io::Write};
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .context("无法创建本地权限密钥文件")?;
        file.write_all(bytes).context("无法写入本地权限密钥文件")?;
    }
    #[cfg(not(unix))]
    fs::write(path, bytes).context("无法写入本地权限密钥文件")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn secret_roundtrip_and_tamper_detection() {
        let key = [7_u8; 32];
        let envelope = encrypt_bytes(&key, b"hidden", SECRET_AAD).unwrap();
        assert_eq!(
            decrypt_bytes(&key, &envelope, SECRET_AAD).unwrap(),
            b"hidden"
        );
        let mut tampered = envelope;
        tampered.ciphertext.push('A');
        assert!(decrypt_bytes(&key, &tampered, SECRET_AAD).is_err());
    }

    #[test]
    fn backup_wrong_password_fails() {
        let (salt, envelope) = encrypt_backup("correct-password", b"backup").unwrap();
        assert!(decrypt_backup("incorrect-password", &salt, &envelope).is_err());
    }

    #[test]
    fn owner_pin_verifier_accepts_only_the_configured_six_digits() {
        let verifier = create_owner_pin_verifier("123456").unwrap();
        assert!(verify_owner_pin("123456", &verifier).unwrap());
        assert!(!verify_owner_pin("654321", &verifier).unwrap());
        assert!(create_owner_pin_verifier("12345").is_err());
        assert!(!verifier.hash.contains("123456"));
    }

    #[test]
    fn existing_vault_without_master_key_is_rejected() {
        let directory = tempdir().unwrap();
        let result = MasterKey::load_or_create_inner(directory.path(), true, false);
        assert!(result.is_err());
        assert!(!directory.path().join("master.key").exists());
    }
}
