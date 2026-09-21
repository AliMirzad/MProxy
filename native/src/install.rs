//! Per-user installation of the native runtime and native messaging registration.
//! Invoked only from the command line (`private-proxy-host install|uninstall`), never by the
//! browser. Chromium launches the host with the caller origin as its only argument.
//!
//! Registration targets (see docs/technical-decisions.md TD-9):
//! * Windows: `HKCU\<browser key>\NativeMessagingHosts\com.privateproxy.host` (default value =
//!   manifest path). Brave is registered under both its own key and Chrome's.
//! * macOS: `~/Library/Application Support/<browser>/NativeMessagingHosts/com.privateproxy.host.json`.

use crate::{paths, HOST_NAME};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Browser {
    pub id: &'static str,
    pub label: &'static str,
    pub win_keys: &'static [&'static str],
    pub mac_dir: &'static str,
}

pub const BROWSERS: &[Browser] = &[
    Browser { id: "chrome", label: "Google Chrome", win_keys: &[r"Software\Google\Chrome\NativeMessagingHosts"], mac_dir: "Google/Chrome" },
    Browser { id: "chrome-beta", label: "Google Chrome Beta/Dev/Canary (macOS)", win_keys: &[], mac_dir: "Google/Chrome Beta" },
    Browser { id: "chromium", label: "Chromium", win_keys: &[r"Software\Chromium\NativeMessagingHosts"], mac_dir: "Chromium" },
    Browser {
        id: "brave",
        label: "Brave",
        win_keys: &[r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts"],
        mac_dir: "BraveSoftware/Brave-Browser",
    },
    Browser { id: "edge", label: "Microsoft Edge", win_keys: &[r"Software\Microsoft\Edge\NativeMessagingHosts"], mac_dir: "Microsoft Edge" },
    Browser { id: "vivaldi", label: "Vivaldi", win_keys: &[], mac_dir: "Vivaldi" },
];

pub fn host_exe_name() -> &'static str {
    if cfg!(windows) {
        "private-proxy-host.exe"
    } else {
        "private-proxy-host"
    }
}

pub fn manifest_json(host_path: &Path, extension_ids: &[String]) -> String {
    let origins: Vec<String> = extension_ids.iter().map(|id| format!("chrome-extension://{id}/")).collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "Private Proxy native runtime (manages Xray-core)",
        "path": host_path.display().to_string(),
        "type": "stdio",
        "allowed_origins": origins,
    }))
    .unwrap()
}

pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| ('a'..='p').contains(&c))
}

pub struct InstallOptions {
    pub source_dir: PathBuf,
    pub target_dir: PathBuf,
    pub extension_ids: Vec<String>,
    /// macOS: also register for browsers whose profile directory does not exist yet.
    pub all_browsers: bool,
    /// Only write native messaging registration for an already-installed runtime in
    /// `target_dir` (used by the macOS .pkg postinstall for the logged-in user).
    pub register_only: bool,
}

/// Copies `src` over `dst`. On Windows a running executable cannot be overwritten but can be
/// renamed, so an existing file is moved aside first (cleaned up on the next install).
fn replace_file(src: &Path, dst: &Path) -> Result<(), String> {
    if src == dst {
        return Ok(());
    }
    if dst.exists()
        && fs::remove_file(dst).is_err() {
            let aside = dst.with_extension(format!("old-{}", std::process::id()));
            fs::rename(dst, &aside).map_err(|e| format!("cannot replace {} (close all browsers and retry): {e}", dst.display()))?;
        }
    fs::copy(src, dst).map_err(|e| format!("cannot copy {} -> {}: {e}", src.display(), dst.display()))?;
    // CopyFileEx copies alternate data streams; drop the downloaded-file mark (Zone.Identifier)
    // so the installed copy is not treated as an untrusted download.
    #[cfg(windows)]
    let _ = fs::remove_file(format!("{}:Zone.Identifier", dst.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o755));
    }
    Ok(())
}

fn cleanup_old(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains(".old-") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

fn find_xray(source_dir: &Path) -> Option<PathBuf> {
    let exe = crate::xray::exe_name();
    [source_dir.join("xray").join(exe), source_dir.join(exe)].into_iter().find(|p| p.is_file())
}

pub fn install(o: &InstallOptions) -> Result<Vec<String>, String> {
    if o.extension_ids.is_empty() || !o.extension_ids.iter().all(|i| valid_extension_id(i)) {
        return Err("invalid extension id".into());
    }
    if crate::harden::is_link(&o.target_dir) {
        return Err(format!("{} is a link or junction; refusing to install there", o.target_dir.display()));
    }
    let mut log = Vec::new();
    if o.register_only {
        let host = o.target_dir.join(host_exe_name());
        if !host.is_file() || find_xray(&o.target_dir).is_none() {
            return Err(format!("no installed runtime in {}", o.target_dir.display()));
        }
        let manifest = manifest_json(&host, &o.extension_ids);
        let manifest_path = o.target_dir.join(format!("{HOST_NAME}.json"));
        if fs::write(&manifest_path, &manifest).is_err() {
            log.push("(runtime directory is read-only; manifest written per browser only)".into());
        }
        platform::register(o, &manifest_path, &manifest, &mut log)?;
        return Ok(log);
    }
    let xray_src = find_xray(&o.source_dir).ok_or_else(|| format!("Xray binary not found next to the installer in {}", o.source_dir.display()))?;
    // Refuse to install anything but the pinned Xray build.
    drop(crate::xray::verify(&xray_src).map_err(|e| format!("{}: {e}", xray_src.display()))?);
    let xray_dir = o.target_dir.join("xray");
    fs::create_dir_all(&xray_dir).map_err(|e| format!("cannot create {}: {e}", xray_dir.display()))?;
    // Only this user (and SYSTEM/Administrators) may modify the executables, whatever the
    // permissions of the chosen parent directory.
    if let Err(e) = crate::harden::restrict_install_dir(&o.target_dir) {
        log.push(format!("warning: could not restrict permissions of {}: {e}", o.target_dir.display()));
    }
    cleanup_old(&o.target_dir);
    cleanup_old(&xray_dir);

    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let host_dst = o.target_dir.join(host_exe_name());
    replace_file(&me, &host_dst)?;
    let xray_dst = xray_dir.join(crate::xray::exe_name());
    replace_file(&xray_src, &xray_dst)?;
    if let Some(lic) = xray_src.parent().map(|p| p.join("LICENSE")).filter(|p| p.is_file()) {
        let _ = fs::copy(lic, xray_dir.join("LICENSE"));
    }
    let lic_src = o.source_dir.join("LICENSES");
    if lic_src.is_dir() {
        let lic_dst = o.target_dir.join("LICENSES");
        let _ = fs::create_dir_all(&lic_dst);
        if let Ok(rd) = fs::read_dir(&lic_src) {
            for e in rd.flatten() {
                let _ = fs::copy(e.path(), lic_dst.join(e.file_name()));
            }
        }
    }
    log.push(format!("Installed runtime to {}", o.target_dir.display()));

    #[cfg(target_os = "macos")]
    {
        // Files extracted from a downloaded archive carry the quarantine attribute, which would
        // make Gatekeeper block the unsigned helper when Chrome launches it.
        let _ = std::process::Command::new("/usr/bin/xattr").args(["-dr", "com.apple.quarantine"]).arg(&o.target_dir).status();
    }

    let manifest = manifest_json(&host_dst, &o.extension_ids);
    let manifest_path = o.target_dir.join(format!("{HOST_NAME}.json"));
    fs::write(&manifest_path, &manifest).map_err(|e| format!("cannot write manifest: {e}"))?;
    platform::register(o, &manifest_path, &manifest, &mut log)?;
    Ok(log)
}

pub fn uninstall(target_dir: &Path, purge: bool) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    platform::unregister(&mut log);
    if purge {
        let data = paths::data_dir();
        // Only the key that protects *this* data directory (see secrets::KeyringProvider).
        let _ = crate::secrets::default_provider(&data).delete();
        // Only fixed product paths are deleted, and a link is removed itself, never followed.
        for d in [data.clone(), paths::log_dir()] {
            if crate::harden::is_link(&d) {
                let _ = fs::remove_dir(&d).or_else(|_| fs::remove_file(&d));
            } else {
                let _ = fs::remove_dir_all(&d);
            }
        }
        log.push(format!("Removed servers, credentials and logs ({})", data.display()));
    } else {
        log.push(format!("Kept imported servers in {} (run `uninstall --purge` to remove them)", paths::data_dir().display()));
    }
    platform::remove_files(target_dir, &mut log);
    Ok(log)
}


#[cfg(windows)]
mod platform {
    use super::*;
    use winreg::enums::*;
    use winreg::RegKey;

    const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivateProxy";

    pub fn register(o: &InstallOptions, manifest_path: &Path, _manifest: &str, log: &mut Vec<String>) -> Result<(), String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for b in BROWSERS {
            for k in b.win_keys {
                let path = format!(r"{k}\{HOST_NAME}");
                let (key, _) = hkcu.create_subkey(&path).map_err(|e| format!("registry write failed ({path}): {e}"))?;
                key.set_value("", &manifest_path.display().to_string()).map_err(|e| e.to_string())?;
                log.push(format!("Registered for {} (HKCU\\{path})", b.label));
            }
        }
        let (u, _) = hkcu.create_subkey(UNINSTALL_KEY).map_err(|e| e.to_string())?;
        let host = o.target_dir.join(host_exe_name());
        let _ = u.set_value("DisplayName", &"Private Proxy (browser runtime)");
        let _ = u.set_value("DisplayVersion", &crate::NATIVE_VERSION);
        let _ = u.set_value("Publisher", &"Private Proxy");
        let _ = u.set_value("InstallLocation", &o.target_dir.display().to_string());
        let _ = u.set_value("UninstallString", &format!("\"{}\" uninstall --interactive", host.display()));
        let _ = u.set_value("NoModify", &1u32);
        let _ = u.set_value("NoRepair", &1u32);
        Ok(())
    }

    pub fn unregister(log: &mut Vec<String>) {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for b in BROWSERS {
            for k in b.win_keys {
                if hkcu.delete_subkey_all(format!(r"{k}\{HOST_NAME}")).is_ok() {
                    log.push(format!("Unregistered from {}", b.label));
                }
            }
        }
        let _ = hkcu.delete_subkey_all(UNINSTALL_KEY);
    }

    pub fn remove_files(target_dir: &Path, log: &mut Vec<String>) {
        if fs::remove_dir_all(target_dir).is_ok() {
            log.push(format!("Removed {}", target_dir.display()));
            return;
        }
        // We are probably running from inside target_dir: delete after we exit. Absolute System32
        // paths and a System32 working directory, so nothing next to the helper can run instead.
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        let sys32 = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32");
        let target = target_dir.display().to_string();
        if target.contains(['"', '%', '&', '|', '^', '<', '>', '!']) {
            log.push(format!("Please delete {target} manually"));
            return;
        }
        let cmd = format!("\"{}\" -n 3 127.0.0.1 >NUL & rmdir /S /Q \"{target}\"", sys32.join("PING.EXE").display());
        let _ = std::process::Command::new(sys32.join("cmd.exe"))
            .raw_arg(format!("/D /C \"{cmd}\""))
            .current_dir(&sys32)
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn();
        log.push(format!("Scheduled removal of {} (close all browsers if it remains)", target_dir.display()));
    }

    pub fn registered_browsers() -> Vec<&'static str> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        BROWSERS
            .iter()
            .filter(|b| b.win_keys.iter().any(|k| hkcu.open_subkey(format!(r"{k}\{HOST_NAME}")).is_ok()))
            .map(|b| b.label)
            .collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    fn app_support() -> PathBuf {
        paths::home_dir().join("Library/Application Support")
    }

    pub fn register(o: &InstallOptions, _manifest_path: &Path, manifest: &str, log: &mut Vec<String>) -> Result<(), String> {
        let mut any = false;
        for b in BROWSERS {
            let base = app_support().join(b.mac_dir);
            if !base.is_dir() && !o.all_browsers {
                continue;
            }
            let dir = base.join("NativeMessagingHosts");
            fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            let f = dir.join(format!("{HOST_NAME}.json"));
            fs::write(&f, manifest).map_err(|e| format!("cannot write {}: {e}", f.display()))?;
            log.push(format!("Registered for {} ({})", b.label, f.display()));
            any = true;
        }
        if !any {
            return Err("No supported Chromium browser profile was found. Start the browser once, or rerun with --all-browsers.".into());
        }
        Ok(())
    }

    pub fn unregister(log: &mut Vec<String>) {
        for b in BROWSERS {
            let f = app_support().join(b.mac_dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json"));
            if fs::remove_file(&f).is_ok() {
                log.push(format!("Unregistered from {}", b.label));
            }
        }
    }

    pub fn remove_files(target_dir: &Path, log: &mut Vec<String>) {
        match fs::remove_dir_all(target_dir) {
            Ok(()) => log.push(format!("Removed {}", target_dir.display())),
            Err(e) => log.push(format!("Could not remove {}: {e}", target_dir.display())),
        }
    }

    pub fn registered_browsers() -> Vec<&'static str> {
        BROWSERS
            .iter()
            .filter(|b| app_support().join(b.mac_dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json")).is_file())
            .map(|b| b.label)
            .collect()
    }
}

pub use platform::registered_browsers;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_shape() {
        let m: serde_json::Value = serde_json::from_str(&manifest_json(Path::new("/opt/pp/host"), &["pmagpgfembejahekgbdifepphmaigngl".into()])).unwrap();
        assert_eq!(m["name"], "com.privateproxy.host");
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["allowed_origins"][0], "chrome-extension://pmagpgfembejahekgbdifepphmaigngl/");
        assert!(valid_extension_id("pmagpgfembejahekgbdifepphmaigngl"));
        assert!(!valid_extension_id("*"));
        assert!(!valid_extension_id("pmagpgfembejahekgbdifepphmaignz"));
    }
}
