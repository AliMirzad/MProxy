//! Core library of the Private Proxy native helper.
//!
//! The binary (`main.rs`) is a thin shell around this library so that parsing,
//! config generation, storage and the connection state machine can be unit- and
//! integration-tested without a browser.

pub mod harden;
pub mod install;
pub mod log;
#[cfg(any(target_os = "macos", test))]
pub mod macsandbox;
pub mod model;
pub mod netpolicy;
pub mod nm;
pub mod parse;
pub mod paths;
pub mod ports;
pub mod probe;
pub mod protocol;
pub mod secrets;
pub mod service;
pub mod store;
pub mod subscription;
pub mod validate;
pub mod xray;
pub mod xrayconf;
#[cfg(windows)]
pub mod winproc;

/// Development/test overrides (`PRIVATE_PROXY_*` environment variables).
///
/// Release builds ignore every override, so nothing in the environment of the browser that
/// launches the helper can redirect its data directory, key storage, Xray binary or probe
/// target, or relax its network restrictions. Debug builds honour them only when
/// `PRIVATE_PROXY_TEST_MODE=1` is also set.
pub fn test_hook(name: &str) -> Option<std::ffi::OsString> {
    if !cfg!(debug_assertions) || std::env::var_os("PRIVATE_PROXY_TEST_MODE").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return None;
    }
    std::env::var_os(name)
}

/// True when a boolean test hook is set to "1" (see [`test_hook`]).
pub fn test_flag(name: &str) -> bool {
    test_hook(name).as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Version of the extension <-> helper message protocol.
/// Bump on any incompatible change to `protocol.rs`.
pub const PROTOCOL_VERSION: u32 = 3;

/// Native messaging host name (must match the extension and the host manifest).
pub const HOST_NAME: &str = "com.privateproxy.host";

/// Version of this helper.
pub const NATIVE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Chromium extension ID(s) allowed to talk to this host (one per line).
pub const DEFAULT_EXTENSION_IDS: &str = include_str!("../../shared/extension-id.txt");

pub fn allowed_extension_ids() -> Vec<String> {
    DEFAULT_EXTENSION_IDS
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect()
}
