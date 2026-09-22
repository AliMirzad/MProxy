//! Enforces the layer rule of the multi-client architecture (docs/module-boundaries.md):
//!
//! ```text
//!   browser → core → runtime → platform      (log: shared by all)
//! ```
//!
//! The Shared Core must not know the browser client, its Native Messaging protocol or Chrome;
//! the runtime and platform layers must not know the Core. A future client is added next to
//! `browser` and reuses `core` unchanged.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(rust_files(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// Source without `//` comments (docs may mention other layers).
fn code_of(p: &Path) -> String {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn src(layer: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join(layer)
}

fn violations(layer: &str, forbidden: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    for f in rust_files(&src(layer)) {
        let code = code_of(&f);
        for bad in forbidden {
            if code.contains(bad) {
                v.push(format!("{} uses `{bad}`", f.display()));
            }
        }
    }
    v
}

#[test]
fn core_does_not_depend_on_the_browser_client() {
    let v = violations(
        "core",
        &[
            "crate::browser",
            "browser::",
            "protocol::",
            "ApiError",
            "ErrorCode",
            "encode_response",
            "encode_event",
            "chrome-extension",
            "nativeMessaging",
            "HOST_NAME",
            "PROTOCOL_VERSION",
        ],
    );
    assert!(v.is_empty(), "the Shared Core must not depend on the browser adapter:\n{}", v.join("\n"));
}

#[test]
fn runtime_depends_only_on_platform() {
    let v = violations("runtime", &["crate::core", "crate::browser"]);
    assert!(v.is_empty(), "{}", v.join("\n"));
}

#[test]
fn platform_depends_on_nothing_above_it() {
    let v = violations("platform", &["crate::core", "crate::runtime", "crate::browser"]);
    assert!(v.is_empty(), "{}", v.join("\n"));
}

#[test]
fn only_the_runtime_launches_xray() {
    // Nothing outside `runtime` (and the platform launcher it uses) may start processes.
    let mut v = Vec::new();
    for layer in ["core", "browser"] {
        for f in rust_files(&src(layer)) {
            let code = code_of(&f);
            for bad in ["Command::new", "spawn_with", "CreateProcess", "winproc::"] {
                // The installer may run fixed System32 tools (cmd, PING) and xattr on macOS.
                if code.contains(bad) && !f.ends_with("install.rs") {
                    v.push(format!("{} uses `{bad}`", f.display()));
                }
            }
        }
    }
    assert!(v.is_empty(), "process launch outside the runtime boundary:\n{}", v.join("\n"));
}
