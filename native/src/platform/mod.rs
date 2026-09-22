//! OS security primitives and locations.
//!
//! * `winproc` (Windows): restricted token (user SID deny-only, no privileges), Low integrity,
//!   job limits, child-process policy, handle list, minimal environment, and verification of all
//!   of it on the suspended process before it runs.
//! * `macsandbox` (macOS): Seatbelt profile and self-test for Xray. Implemented and code-reviewed;
//!   real-hardware verification pending. Replacing the deprecated `sandbox-exec` mechanism only
//!   touches this module.
//! * `harden`: process hardening, private-directory ACLs/modes and their verification, links.
//! * `paths`: data, log and install locations.
//!
//! May depend on: `log`. Must never depend on `core`, `runtime` or `browser`.

pub mod harden;
#[cfg(any(target_os = "macos", test))]
pub mod macsandbox;
pub mod paths;
#[cfg(windows)]
pub mod winproc;
