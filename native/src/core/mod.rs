//! Shared Core: everything a client (browser extension today, a desktop app later) needs,
//! without any knowledge of how the client talks to it.
//!
//! May depend on: `runtime`, `platform`, `log`. Must never depend on `browser` (checked by
//! `tests/architecture.rs`).
//!
//! Trust boundary for imported data (links, QR, JSON, subscriptions):
//! untrusted text → strict parser (`import`) → field validation (`validate`, `netpolicy`) →
//! normalized profile (`profile`) → trusted config generator (`xray_config`) → Xray.
//! Imported content is data; it is never forwarded to Xray as configuration.

pub mod api;
pub mod credentials;
pub mod error;
pub mod import;
pub mod netpolicy;
pub mod probe;
pub mod profile;
pub mod secrets;
pub mod session;
pub mod store;
pub mod subscription;
pub mod validate;
pub mod xray_config;
