//! TEST FIXTURE (never packaged): reports, from the inside, what a process started by the Xray
//! launcher (`winproc::ChildProc`) can actually do. `native/tests/integration.rs
//! xray_sandbox_probe` runs it with exactly the restrictions Xray gets and asserts on the JSON.
//!
//!   sandbox_probe [--handle <inherited handle value>] [--read <path>]... [--write <path>]... [--reg-write]
//!
//! Output: one JSON object on stdout.

#[cfg(windows)]
fn main() {
    use serde_json::{json, Map, Value};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::*;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = Map::new();

    unsafe {
        // ---- token
        // Whether the process may open its own token (a restricted token usually may not).
        let mut opened: HANDLE = std::ptr::null_mut();
        let can_open = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut opened) != 0;
        out.insert("canOpenOwnToken".into(), json!(can_open));
        if can_open {
            CloseHandle(opened);
        }
        // GetCurrentProcessToken() pseudo-handle: always queryable.
        let tok: HANDLE = -4isize as HANDLE;
        let info = |class: TOKEN_INFORMATION_CLASS| -> Vec<u8> {
            let mut len = 0u32;
            GetTokenInformation(tok, class, std::ptr::null_mut(), 0, &mut len);
            let mut b = vec![0u64; (len as usize).div_ceil(8).max(1)];
            GetTokenInformation(tok, class, b.as_mut_ptr() as *mut _, len, &mut len);
            b.into_iter().flat_map(u64::to_ne_bytes).collect()
        };
        let il = info(TokenIntegrityLevel);
        let label = &*(il.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let n = *GetSidSubAuthorityCount(label.Label.Sid);
        out.insert("integrityRid".into(), json!(format!("{:#x}", *GetSidSubAuthority(label.Label.Sid, (n - 1) as u32))));
        let user = info(TokenUser);
        let user = &*(user.as_ptr() as *const TOKEN_USER);
        out.insert("userSidDenyOnly".into(), json!(user.User.Attributes & 0x10 != 0));
        let el = info(TokenElevation);
        out.insert("elevated".into(), json!(!el.is_empty() && (*(el.as_ptr() as *const TOKEN_ELEVATION)).TokenIsElevated != 0));
        let pv = info(TokenPrivileges);
        let privs = &*(pv.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(privs.Privileges.as_ptr(), privs.PrivilegeCount as usize);
        let mut names = Vec::new();
        for p in arr {
            let mut buf = [0u16; 128];
            let mut len = buf.len() as u32;
            if LookupPrivilegeNameW(std::ptr::null(), &p.Luid, buf.as_mut_ptr(), &mut len) != 0 {
                names.push(String::from_utf16_lossy(&buf[..len as usize]));
            }
        }
        out.insert("privileges".into(), json!(names));

        // ---- job (NULL job handle = the job of the calling process)
        let mut in_job = 0;
        IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job);
        out.insert("inJob".into(), json!(in_job != 0));
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        if QueryInformationJobObject(std::ptr::null_mut(), JobObjectExtendedLimitInformation, &mut ext as *mut _ as *mut _, std::mem::size_of_val(&ext) as u32, std::ptr::null_mut()) != 0 {
            let f = ext.BasicLimitInformation.LimitFlags;
            out.insert(
                "job".into(),
                json!({
                    "killOnClose": f & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
                    "dieOnUnhandledException": f & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION != 0,
                    "activeProcessLimit": if f & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0 { json!(ext.BasicLimitInformation.ActiveProcessLimit) } else { Value::Null },
                    "processMemoryLimit": if f & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0 { json!(ext.ProcessMemoryLimit) } else { Value::Null },
                    "breakawayAllowed": f & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0,
                }),
            );
        }
        let mut ui: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
        if QueryInformationJobObject(std::ptr::null_mut(), JobObjectBasicUIRestrictions, &mut ui as *mut _ as *mut _, std::mem::size_of_val(&ui) as u32, std::ptr::null_mut()) != 0 {
            out.insert("uiRestrictions".into(), json!(format!("{:#x}", ui.UIRestrictionsClass)));
        }

        // ---- mitigation policies, as the process sees them
        let pol = |p: PROCESS_MITIGATION_POLICY| -> u32 {
            let mut v: u32 = 0;
            GetProcessMitigationPolicy(GetCurrentProcess(), p, &mut v as *mut u32 as *mut _, 4);
            v
        };
        out.insert(
            "mitigations".into(),
            json!({
                "childProcess": pol(ProcessChildProcessPolicy),
                "extensionPoints": pol(ProcessExtensionPointDisablePolicy),
                "imageLoad": pol(ProcessImageLoadPolicy),
                "font": pol(ProcessFontDisablePolicy),
                "aslr": pol(ProcessASLRPolicy),
            }),
        );

        // ---- inherited handle
        if let Some(pos) = args.iter().position(|a| a == "--handle") {
            let v: usize = args[pos + 1].parse().unwrap_or(0);
            let mut flags = 0u32;
            out.insert("inheritedHandleUsable".into(), json!(GetHandleInformation(v as HANDLE, &mut flags) != 0));
        }

        // ---- starting another program
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let mut cmd: Vec<u16> = format!("\"{sys}\\System32\\cmd.exe\" /c exit 0\0").encode_utf16().collect();
        let ok = CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, 0x0800_0000, std::ptr::null(), std::ptr::null(), &si, &mut pi);
        out.insert("canStartProcess".into(), json!(ok != 0));
        if ok != 0 {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            out.insert("startProcessError".into(), json!(GetLastError()));
        }
    }

    // ---- environment
    out.insert("env".into(), json!(std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect::<Vec<_>>()));

    // ---- filesystem
    let mut reads = Map::new();
    let mut writes = Map::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--read" => {
                let p = &args[i + 1];
                reads.insert(p.clone(), json!(std::fs::read(p).is_ok()));
                i += 2;
            }
            "--write" => {
                let p = &args[i + 1];
                let ok = std::fs::write(p, b"probe").is_ok();
                if ok {
                    let _ = std::fs::remove_file(p);
                }
                writes.insert(p.clone(), json!(ok));
                i += 2;
            }
            "--reg-write" => {
                let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
                let ok = hkcu.create_subkey("Software\\pp-sandbox-probe").is_ok();
                if ok {
                    let _ = hkcu.delete_subkey_all("Software\\pp-sandbox-probe");
                }
                out.insert("canWriteHkcuSoftware".into(), json!(ok));
                let low = hkcu.create_subkey("Software\\AppDataLow\\pp-sandbox-probe").is_ok();
                if low {
                    let _ = hkcu.delete_subkey_all("Software\\AppDataLow\\pp-sandbox-probe");
                }
                out.insert("canWriteHkcuAppDataLow".into(), json!(low));
                i += 1;
            }
            _ => i += 1,
        }
    }
    out.insert("reads".into(), Value::Object(reads));
    out.insert("writes".into(), Value::Object(writes));
    println!("{}", Value::Object(out));
}

#[cfg(not(windows))]
fn main() {
    println!("{{\"unsupported\":true}}");
}
