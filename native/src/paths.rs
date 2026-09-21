//! Per-user filesystem locations. Nothing here is caller controlled; the only override is
//! the `PRIVATE_PROXY_DATA_DIR` environment variable used by tests and development.

use std::path::PathBuf;

pub const APP_DIR: &str = "PrivateProxy";

fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `%LOCALAPPDATA%\PrivateProxy` / `~/Library/Application Support/PrivateProxy`.
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PRIVATE_PROXY_DATA_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home().join("AppData").join("Local")).join(APP_DIR)
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support").join(APP_DIR)
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".local/share")).join("private-proxy")
    }
}

/// `%LOCALAPPDATA%\PrivateProxy\logs` / `~/Library/Logs/PrivateProxy`.
pub fn log_dir() -> PathBuf {
    if std::env::var_os("PRIVATE_PROXY_DATA_DIR").is_some() || !cfg!(target_os = "macos") {
        data_dir().join("logs")
    } else {
        home().join("Library/Logs").join(APP_DIR)
    }
}

/// Default per-user runtime install location (helper + Xray + host manifest).
pub fn default_install_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home().join("AppData").join("Local")).join("Programs").join(APP_DIR)
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support").join(APP_DIR).join("runtime")
    } else {
        home().join(".local/lib/private-proxy")
    }
}

pub fn home_dir() -> PathBuf {
    home()
}

/// Restrict a directory to the current user (0700) on Unix. Windows per-user profile
/// directories already carry a user-only ACL.
pub fn harden_dir(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = p;
}

pub fn harden_file(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = p;
}
