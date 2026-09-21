//! Core library of the Private Proxy native helper.
//!
//! The binary (`main.rs`) is a thin shell around this library so that parsing,
//! config generation, storage and the connection state machine can be unit- and
//! integration-tested without a browser.

pub mod install;
pub mod log;
pub mod model;
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

/// Version of the extension <-> helper message protocol.
/// Bump on any incompatible change to `protocol.rs`.
pub const PROTOCOL_VERSION: u32 = 1;

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
