//! Client-facing error model of the Core.
//!
//! `message` is meant for the user and is safe to show or return to any client: it is built
//! from fixed text plus details that are already redacted or truncated. It never contains proxy
//! credentials, server secrets, subscription URLs (only their host), authentication headers or
//! generated configuration. Technical detail goes to the local log instead.

use crate::core::secrets::SecretError;
use crate::core::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Malformed or out-of-range request arguments.
    InvalidRequest,
    NotFound,
    /// Imported data or a stored profile failed parsing/validation.
    InvalidProfile,
    /// A destination forbidden by the network policy (loopback, metadata, ...).
    SecurityPolicyViolation,
    SubscriptionFailure,
    /// The pinned Xray binary is not installed.
    RuntimeUnavailable,
    /// The Xray binary does not match its pinned hash.
    RuntimeIntegrityFailure,
    /// A MANDATORY isolation protection could not be applied or verified (fail closed).
    RuntimeIsolationFailure,
    /// Xray could not be started or stopped unexpectedly.
    RuntimeFailure,
    /// Xray's own config test rejected the generated configuration.
    ConfigRejected,
    PortUnavailable,
    /// Xray runs but no traffic passes through the server.
    ConnectionFailure,
    /// The OS credential store (Credential Manager / Keychain) cannot provide the data key.
    SecureStorageUnavailable,
    /// Local data could not be read or written.
    Storage,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoreError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CoreError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> CoreError {
        CoreError { kind, message: message.into() }
    }

    /// A failed MANDATORY runtime protection, from a runtime/platform error text that contains
    /// "runtime security check failed" (see `runtime::xray`). `None` for other errors.
    pub fn from_runtime_security(err: &str) -> Option<CoreError> {
        let i = err.find("runtime security check failed")?;
        let detail = err[i + "runtime security check failed".len()..].trim_start_matches(':').trim();
        Some(CoreError::new(
            ErrorKind::RuntimeIsolationFailure,
            format!("Runtime security check failed: {}. The connection was not started.", crate::core::validate::truncate(detail, 200)),
        ))
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> CoreError {
        match e {
            StoreError::Secret(SecretError::KeyMissing) | StoreError::Secret(SecretError::Corrupt) => CoreError::new(
                ErrorKind::SecureStorageUnavailable,
                "The key that protects your saved servers is missing or was replaced (it lives in the system credential store), so they can't be read. Open Settings → Remove all servers, then add your subscription or links again.",
            ),
            StoreError::Secret(SecretError::Unavailable(m)) => {
                CoreError::new(ErrorKind::SecureStorageUnavailable, format!("Secure storage is unavailable: {}", crate::log::redact(&m)))
            }
            StoreError::NotFound => CoreError::new(ErrorKind::NotFound, "Not found"),
            StoreError::Invalid(m) => CoreError::new(ErrorKind::InvalidProfile, m),
            StoreError::Io(m) => CoreError::new(ErrorKind::Storage, format!("Local data error: {m}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_security_failures_are_classified() {
        let e = CoreError::from_runtime_security("spawn: runtime security check failed: token integrity is not Low").unwrap();
        assert_eq!(e.kind, ErrorKind::RuntimeIsolationFailure);
        assert_eq!(e.message, "Runtime security check failed: token integrity is not Low. The connection was not started.");
        assert!(CoreError::from_runtime_security("address already in use").is_none());
    }

    #[test]
    fn storage_errors_do_not_leak_details() {
        // log::redact masks URLs (keeping the host), UUIDs and tokens of 32+ characters.
        let raw = "at https://sub.example.com/s?token=QmFzZTY0VG9rZW5WYWx1ZTAxMjM0NTY3ODk key 5783a3e7-e373-51cd-8642-c83782b807c5 blob QmFzZTY0VG9rZW5WYWx1ZTAxMjM0NTY3ODkw";
        let e: CoreError = StoreError::Secret(SecretError::Unavailable(raw.into())).into();
        assert_eq!(e.kind, ErrorKind::SecureStorageUnavailable);
        for secret in ["token=", "5783a3e7", "QmFzZTY0VG9rZW5WYWx1ZTAxMjM0NTY3ODkw"] {
            assert!(!e.message.contains(secret), "{secret} in {}", e.message);
        }
        assert!(e.message.contains("sub.example.com"));
    }
}
