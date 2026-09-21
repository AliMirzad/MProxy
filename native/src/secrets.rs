//! Encryption of the secrets file with a data key held by the OS credential store.
//!
//! * Data key: 32 random bytes, stored via `keyring` as one generic credential:
//!   Windows Credential Manager (DPAPI-protected, per user) / macOS login Keychain.
//! * File format: `PPS1` || 24-byte nonce || XChaCha20-Poly1305(ciphertext+tag), AAD = `PPS1`.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"PPS1";
const SERVICE: &str = "com.privateproxy.host";
const ACCOUNT: &str = "secrets-data-key";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secure storage is unavailable: {0}")]
    Unavailable(String),
    #[error("the secure storage key is missing, so stored credentials cannot be decrypted")]
    KeyMissing,
    #[error("stored credentials are corrupted or were encrypted with a different key")]
    Corrupt,
}

pub trait KeyProvider: Send + Sync {
    /// Returns the data key, or `None` if no key exists yet.
    fn load(&self) -> Result<Option<[u8; 32]>, SecretError>;
    fn store(&self, key: &[u8; 32]) -> Result<(), SecretError>;
    fn delete(&self) -> Result<(), SecretError>;
    fn describe(&self) -> &'static str;
}

fn decode_key(s: &str) -> Result<[u8; 32], SecretError> {
    let v = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| SecretError::Corrupt)?;
    v.try_into().map_err(|_| SecretError::Corrupt)
}

/// OS credential store (Credential Manager / Keychain).
pub struct KeyringProvider;

impl KeyProvider for KeyringProvider {
    fn load(&self) -> Result<Option<[u8; 32]>, SecretError> {
        let e = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| SecretError::Unavailable(e.to_string()))?;
        match e.get_password() {
            Ok(s) => decode_key(&s).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Unavailable(e.to_string())),
        }
    }
    fn store(&self, key: &[u8; 32]) -> Result<(), SecretError> {
        let e = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| SecretError::Unavailable(e.to_string()))?;
        e.set_password(&base64::engine::general_purpose::STANDARD.encode(key))
            .map_err(|e| SecretError::Unavailable(e.to_string()))
    }
    fn delete(&self) -> Result<(), SecretError> {
        let e = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| SecretError::Unavailable(e.to_string()))?;
        match e.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Unavailable(e.to_string())),
        }
    }
    fn describe(&self) -> &'static str {
        if cfg!(windows) {
            "Windows Credential Manager"
        } else if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else {
            "OS keyring"
        }
    }
}

/// **Development/test only**: key in a plain file next to the data. Enabled with
/// `PRIVATE_PROXY_INSECURE_FILE_KEY=1`; never used by installed builds.
pub struct FileKeyProvider {
    pub path: PathBuf,
}

impl KeyProvider for FileKeyProvider {
    fn load(&self) -> Result<Option<[u8; 32]>, SecretError> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => decode_key(&s).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SecretError::Unavailable(e.to_string())),
        }
    }
    fn store(&self, key: &[u8; 32]) -> Result<(), SecretError> {
        std::fs::write(&self.path, base64::engine::general_purpose::STANDARD.encode(key))
            .map_err(|e| SecretError::Unavailable(e.to_string()))?;
        crate::paths::harden_file(&self.path);
        Ok(())
    }
    fn delete(&self) -> Result<(), SecretError> {
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
    fn describe(&self) -> &'static str {
        "INSECURE development key file"
    }
}

pub fn default_provider(data_dir: &std::path::Path) -> Box<dyn KeyProvider> {
    if crate::test_flag("PRIVATE_PROXY_INSECURE_FILE_KEY") {
        Box::new(FileKeyProvider { path: data_dir.join("dev-insecure.key") })
    } else {
        Box::new(KeyringProvider)
    }
}

pub fn new_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: MAGIC })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(4 + 24 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, SecretError> {
    if blob.len() < 4 + 24 + 16 || &blob[..4] != MAGIC {
        return Err(SecretError::Corrupt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(&blob[4..28]), Payload { msg: &blob[28..], aad: MAGIC })
        .map_err(|_| SecretError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let k = new_key();
        let blob = encrypt(&k, b"secret");
        assert!(!blob.windows(6).any(|w| w == b"secret"));
        assert_eq!(decrypt(&k, &blob).unwrap(), b"secret");
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt(&k, &bad).is_err());
        assert!(decrypt(&new_key(), &blob).is_err());
        assert!(decrypt(&k, b"PPS1").is_err());
    }
}
