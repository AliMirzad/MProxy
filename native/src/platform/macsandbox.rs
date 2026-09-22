//! macOS: runs Xray inside the system sandbox (`/usr/bin/sandbox-exec`, Seatbelt).
//!
//! Profile (last matching rule wins):
//! * network and everything else Xray needs: allowed (`allow default`)
//! * **no new processes**: `process-fork` denied, `process-exec` allowed only for the Xray binary
//! * **no file writes**, except `/dev/null`-style devices
//! * **no reads in the user's home folder** (documents, keychains, browser profiles, our data
//!   directory with `secrets.bin`), except Xray's own directory
//!
//! A compromised Xray therefore cannot read the stored credentials or the user's files, plant
//! files, or start programs. It can still use the network (which it needs).
//!
//! `sandbox-exec` is deprecated by Apple (see docs/threat-model.md, "macOS isolation"). The helper
//! runs a **self-test** (sandboxed `xray version`) once per session. The sandbox is MANDATORY: if it
//! is unavailable or the self-test fails, Xray is **not started** and the connection fails with
//! "Runtime security check failed". It is never started unsandboxed.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

static STATE: OnceLock<Result<(), String>> = OnceLock::new();

fn sbpl_string(p: &Path) -> String {
    format!("\"{}\"", p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\""))
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The Seatbelt profile for `xray` (pure; unit-tested).
pub fn profile(xray: &Path, home: &Path) -> String {
    let xray = canonical(xray);
    let dir = xray.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"));
    let home = canonical(home);
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny process-fork)\n\
         (deny process-exec)\n\
         (allow process-exec (literal {x}))\n\
         (deny file-write*)\n\
         (allow file-write* (literal \"/dev/null\") (literal \"/dev/dtracehelper\") (literal \"/dev/tty\"))\n\
         (deny file-read* (subpath {h}))\n\
         (allow file-read* (subpath {d}))\n",
        x = sbpl_string(&xray),
        h = sbpl_string(&home),
        d = sbpl_string(&dir),
    )
}

fn self_test(xray: &Path) -> Result<(), String> {
    if !Path::new(SANDBOX_EXEC).is_file() {
        return Err("sandbox-exec is not available".into());
    }
    let out = std::process::Command::new(SANDBOX_EXEC)
        .arg("-p")
        .arg(profile(xray, &crate::platform::paths::home_dir()))
        .arg(canonical(xray))
        .arg("version")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("sandbox self-test could not run: {e}"))?;
    if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Xray") {
        Ok(())
    } else {
        Err(format!("sandbox self-test failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")))
    }
}

/// Whether Xray can be sandboxed on this machine (self-test runs once per helper session).
pub fn usable(xray: &Path) -> Result<(), String> {
    STATE
        .get_or_init(|| {
            let r = self_test(xray);
            match &r {
                Ok(()) => crate::log::info("Xray runs in the macOS sandbox"),
                Err(e) => crate::log::error(format!("macOS sandbox unavailable; Xray will not be started: {e}")),
            }
            r
        })
        .clone()
}

/// State for Diagnostics (None before the first launch).
pub fn state() -> Option<Result<(), String>> {
    STATE.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_restrictive_and_escaped() {
        let p = profile(Path::new("/Users/a b/Library/PP/runtime/xray/xray"), Path::new("/Users/a b"));
        assert!(p.contains("(deny process-fork)"));
        assert!(p.contains("(deny process-exec)"));
        assert!(p.contains("(allow process-exec (literal \"/Users/a b/Library/PP/runtime/xray/xray\"))"));
        assert!(p.contains("(deny file-write*)"));
        assert!(p.contains("(deny file-read* (subpath \"/Users/a b\"))"));
        assert!(p.contains("(allow file-read* (subpath \"/Users/a b/Library/PP/runtime/xray\"))"));
        // The home deny comes before the Xray-dir allow (last matching rule wins).
        assert!(p.find("(deny file-read*").unwrap() < p.find("(allow file-read*").unwrap());
        let q = profile(Path::new("/tmp/x\"y/xray"), Path::new("/h"));
        assert!(q.contains("\"/tmp/x\\\"y/xray\""));
    }
}
