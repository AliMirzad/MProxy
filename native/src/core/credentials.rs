//! Credentials of the local proxy listeners (the browser's per-connection inbound and the IDE
//! endpoint). Sensitive runtime state:
//!
//! * no `Serialize`: they can only leave the Core through the explicit accessors that need them
//!   (`Core::browser_proxy_endpoint`, `Core::ide_credentials`);
//! * `Debug` is redacted, so `{:?}` in logs or errors never prints them;
//! * the bytes are overwritten when a value is dropped (best effort: copies made by the
//!   allocator or the OS are outside our control).

use crate::core::store;

#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    pub user: String,
    pub pass: String,
}

impl ProxyCredentials {
    /// Fresh random credentials for one browser connection (~58 bits in the user name, ~140 bits
    /// in the password; OS CSPRNG).
    pub fn random_for_browser() -> ProxyCredentials {
        ProxyCredentials { user: format!("b{}", store::random_token(10)), pass: store::random_token(24) }
    }
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyCredentials(<redacted>)")
    }
}

impl Drop for ProxyCredentials {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8, so both strings stay valid until they are freed.
        unsafe {
            self.user.as_bytes_mut().fill(0);
            self.pass.as_bytes_mut().fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_values_are_random() {
        let a = ProxyCredentials::random_for_browser();
        let b = ProxyCredentials::random_for_browser();
        assert_ne!(a, b);
        assert!(a.user.starts_with('b') && a.user.len() == 11 && a.pass.len() == 24);
        let shown = format!("{a:?} {:?}", Some(&a));
        assert!(!shown.contains(&a.pass) && !shown.contains(&a.user), "{shown}");
        assert!(shown.contains("redacted"));
    }
}
