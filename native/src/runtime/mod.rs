//! Xray runtime boundary: locating the pinned binary, integrity verification, config testing,
//! restricted launch (via `platform`), supervision and termination, local port handling.
//!
//! Receives generated configuration as bytes; knows nothing about profiles or clients.
//! May depend on: `platform`, `log`. Must never depend on `core` or `browser`.

pub mod ports;
pub mod xray;
