//! Browser client adapter: the Chromium native-messaging host.
//!
//! * `nm`: stdio framing (length-prefixed JSON, size limit).
//! * `protocol`: the closed, strictly typed command set of the extension ↔ helper protocol.
//! * `adapter`: maps protocol commands onto the Core API and Core state onto protocol JSON.
//! * `install`: installs the runtime and registers the native-messaging host for browsers.
//!
//! The native-messaging JSON protocol ends here; it is not the Core's internal API.

pub mod adapter;
pub mod install;
pub mod nm;
pub mod protocol;
