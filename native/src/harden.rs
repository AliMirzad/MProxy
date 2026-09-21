//! OS-level hardening of the helper process and of the directories that hold credentials.
//!
//! See docs/threat-model.md ("Process isolation") for what each measure protects against and
//! for the measures that were evaluated and deliberately not applied.
//!
//! Windows
//! * DLL search order restricted to System32 (`SetDefaultDllDirectories`; static imports are
//!   covered by the `/DEPENDENTLOADFLAG:0x800` linker flag in `.cargo/config.toml`).
//! * Mitigation policies: no legacy extension-point DLLs (AppInit, winsock LSPs, ...), no images
//!   from remote shares or with a Low integrity label, System32 images preferred.
//! * Data directory: protected DACL (current user + SYSTEM only) and a Medium mandatory label with
//!   no-read-up/no-write-up, so the Low-integrity Xray child cannot read stored credentials.
//!
//! Unix
//! * `umask 077` and no core dumps (a core file would contain decrypted credentials).
//! * Data directory 0700, files 0600.

use std::path::Path;

/// Applied once, first thing in `main`.
pub fn harden_current_process() {
    #[cfg(windows)]
    win::harden_process();
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

/// Makes `dir` private to the current user (see module docs). Errors are returned so callers can
/// decide; the store logs them and continues (the parent profile directory is already private).
pub fn restrict_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return win::restrict_dir(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
}

/// Install directory of the runtime: writable only by this user, SYSTEM and Administrators
/// (readable/executable as usual). Windows only; on macOS the per-user install lives in the
/// user-only Library folder and the .pkg installs root-owned files.
pub fn restrict_install_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    return win::set_dacl(dir, &format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", win::current_user_sid()?), false);
    #[cfg(not(windows))]
    {
        let _ = dir;
        Ok(())
    }
}

pub fn restrict_file(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = p; // inherits the directory's protected DACL
}

/// True if `p` is a symbolic link, junction or other reparse point. Data directories must be real
/// directories so that nothing redirects where credentials are written or what gets deleted.
pub fn is_link(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(m) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                m.file_type().is_symlink() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            }
            #[cfg(not(windows))]
            {
                m.file_type().is_symlink()
            }
        }
        Err(_) => false,
    }
}

/// MANDATORY check before any secret (Xray config, credentials) is handed to Xray: `dir` must
/// be private right now, as read back from the OS (not assumed from an earlier restrict call).
/// Windows: protected DACL granting only this user, SYSTEM and Administrators, plus a mandatory
/// label with no-read-up. Unix: no group/other permission bits.
pub fn verify_private_dir(dir: &Path) -> Result<(), String> {
    if is_link(dir) {
        return Err(format!("{} is a link or junction", dir.display()));
    }
    #[cfg(windows)]
    {
        let sddl = win::sddl_of(dir).ok_or("cannot read the permissions of the data folder")?;
        let sid = win::current_user_sid().map_err(|e| e.to_string())?;
        let (dacl, label) = sddl.split_once("S:").unwrap_or((&sddl, ""));
        if !dacl.starts_with("D:P") {
            return Err("the data folder inherits permissions from its parent".into());
        }
        for ace in dacl.trim_start_matches("D:P").trim_start_matches("AI").split(')').filter(|a| !a.is_empty()) {
            let trustee = ace.rsplit(';').next().unwrap_or("");
            if trustee != sid && trustee != "SY" && trustee != "BA" {
                return Err(format!("the data folder grants access to {trustee}"));
            }
        }
        let ml = label.split("(ML;").nth(1).unwrap_or("");
        if !ml.contains("NR") {
            return Err("the data folder is readable by Low-integrity processes".into());
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir).map_err(|e| e.to_string())?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!("the data folder is accessible to other users (mode {:o})", mode & 0o777));
        }
        Ok(())
    }
}

/// Human-readable description of `dir`'s protection, for diagnostics and tests
/// (Windows: the SDDL of its DACL and label; Unix: the mode).
pub fn describe_dir(dir: &Path) -> Option<String> {
    #[cfg(windows)]
    return win::sddl_of(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(dir).ok().map(|m| format!("{:o}", m.permissions().mode() & 0o777))
    }
}

#[cfg(windows)]
pub(crate) mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
    use windows_sys::Win32::System::Threading::*;

    pub fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn harden_process() {
        unsafe {
            SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
            // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY: DisableExtensionPoints.
            let ext: u32 = 1;
            SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext as *const u32 as *const _, 4);
            // PROCESS_MITIGATION_IMAGE_LOAD_POLICY: NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images.
            let img: u32 = 0b111;
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img as *const u32 as *const _, 4);
        }
    }

    /// String SID of the user running this process.
    pub fn current_user_sid() -> std::io::Result<String> {
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr() as *mut _, len, &mut len);
            CloseHandle(tok);
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let out = from_wide_ptr(s);
            LocalFree(s as _);
            Ok(out)
        }
    }

    unsafe fn from_wide_ptr(p: *const u16) -> String {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    pub fn restrict_dir(dir: &Path) -> std::io::Result<()> {
        let sid = current_user_sid()?;
        set_dacl(dir, &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)S:(ML;OICI;NRNWNX;;;ME)"), true)
    }

    pub fn set_dacl(dir: &Path, sddl: &str, with_label: bool) -> std::io::Result<()> {
        // D:P            protected DACL (no inheritance from the profile)
        // (A;OICI;FA;;;<user>) (A;OICI;FA;;;SY)   full control: this user and SYSTEM only
        // S:(ML;OICI;NRNWNX;;;ME)                 Medium label, no read/write/execute up:
        //                                         Low-integrity processes (Xray) cannot read it
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let w = wide(std::ffi::OsStr::new(sddl));
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sacl: *mut ACL = std::ptr::null_mut();
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
            GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut defaulted);
            let path = wide(dir.as_os_str());
            let rc = SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | if with_label { LABEL_SECURITY_INFORMATION } else { 0 },
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                sacl,
            );
            LocalFree(sd as _);
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(rc as i32));
            }
        }
        Ok(())
    }

    pub fn sddl_of(dir: &Path) -> Option<String> {
        unsafe {
            let path = wide(dir.as_os_str());
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let info = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
            let rc = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return None;
            }
            let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info, &mut s, std::ptr::null_mut());
            LocalFree(sd as _);
            if ok == 0 {
                return None;
            }
            let out = from_wide_ptr(s);
            LocalFree(s as _);
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dir_and_link_detection() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("data");
        std::fs::create_dir(&d).unwrap();
        restrict_dir(&d).unwrap();
        let desc = describe_dir(&d).unwrap();
        #[cfg(windows)]
        {
            let sid = win::current_user_sid().unwrap();
            assert!(desc.contains("D:P"), "{desc}");
            assert!(desc.contains(&sid), "{desc}");
            let label = desc.split("(ML;").nth(1).unwrap_or("");
            assert!(label.contains(";;;ME)") && label.contains("NR") && label.contains("NW") && label.contains("NX"), "{desc}");
            for broad in [";;;WD)", ";;;AU)", ";;;BU)", ";;;IU)"] {
                assert!(!desc.contains(broad), "{desc}");
            }
        }
        #[cfg(unix)]
        assert_eq!(desc, "700");
        assert!(!is_link(&d));

        // A junction/symlink must be detected (junctions need no privileges on Windows).
        let link = t.path().join("link");
        #[cfg(windows)]
        let made = std::process::Command::new(std::env::var("ComSpec").unwrap_or("cmd.exe".into()))
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&d)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&d, &link).is_ok();
        assert!(made);
        assert!(is_link(&link));
    }
}
