//! Windows: launches Xray in a constrained process.
//!
//! `std::process::Command` cannot set a token, process attributes or join a job before the
//! child runs, so the child is created directly with `CreateProcessAsUserW`:
//!
//! * **Low integrity token** (a duplicate of our own token with the Low mandatory label). Xray
//!   still runs as the same user and can use the network, but it cannot write to the user's
//!   files, registry or Medium-integrity processes, and it cannot read the data directory
//!   (which carries a no-read-up label, see `harden.rs`). A compromised Xray therefore cannot
//!   read other stored credentials or plant files.
//! * **Creation-time mitigation policies**: no extension-point DLLs, no images from remote
//!   shares or with a Low label, System32 images preferred, no Win32k font loading, heap
//!   terminate on corruption, mandatory bottom-up/high-entropy ASLR.
//! * **Child process creation blocked** (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) and a job
//!   with an active-process limit of 1: Xray cannot start other programs.
//! * **Job object** assigned while the process is still suspended: kill-on-close (Xray dies with
//!   the helper), die-on-unhandled-exception, 2 GiB memory cap, UI restrictions (no clipboard,
//!   desktop, global atoms, system parameters).
//! * **Only the three pipe handles are inheritable** (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
//! * **Minimal environment** (`SystemRoot` only): nothing from the browser's environment reaches
//!   Xray (e.g. `XRAY_LOCATION_*`, `GODEBUG`, proxy variables).
//!
//! If the OS rejects the mitigation attributes (older Windows 10 builds), the launch is retried
//! without them; the token, job and handle list are always applied.

use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::*;

use crate::harden::win::wide;

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST_: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_: usize = 0x0002_0007;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY_: usize = 0x0002_000E;
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x01;
const SE_GROUP_INTEGRITY_: u32 = 0x20;

const MITIGATIONS: u64 = (1 << 12)  // HEAP_TERMINATE_ALWAYS_ON
    | (1 << 16)                      // BOTTOM_UP_ASLR_ALWAYS_ON
    | (1 << 20)                      // HIGH_ENTROPY_ASLR_ALWAYS_ON
    | (1 << 32)                      // EXTENSION_POINT_DISABLE_ALWAYS_ON
    | (1 << 48)                      // FONT_DISABLE_ALWAYS_ON
    | (1 << 52)                      // IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
    | (1 << 56)                      // IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
    | (1 << 60); // IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON

const JOB_MEMORY_LIMIT: usize = 2 << 30;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}
unsafe impl Send for Handle {}

pub struct ChildProc {
    process: Handle,
    _job: Handle,
    pid: u32,
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
    exited: Option<u32>,
}

/// Which restrictions to apply. Production always uses [`Restrictions::ALL`]; the fields
/// exist so tests can show which restriction a failure comes from.
#[derive(Clone, Copy, Debug)]
pub struct Restrictions {
    pub low_integrity: bool,
    pub mitigations: bool,
    pub no_child_processes: bool,
    pub job_limits: bool,
}

impl Restrictions {
    pub const ALL: Restrictions = Restrictions { low_integrity: true, mitigations: true, no_child_processes: true, job_limits: true };
}

#[derive(Clone, Copy)]
pub struct Stdio {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// (parent end, child end); only the child end is inheritable.
fn pipe(child_reads: bool) -> io::Result<(Handle, Handle)> {
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(last());
    }
    let (r, w) = (Handle(r), Handle(w));
    let (parent, child) = if child_reads { (w, r) } else { (r, w) };
    unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) };
    Ok((parent, child))
}

fn nul() -> io::Result<Handle> {
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
    let name = wide(std::ffi::OsStr::new("NUL"));
    let h = unsafe {
        CreateFileW(name.as_ptr(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, std::ptr::null_mut())
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last());
    }
    Ok(Handle(h))
}

fn low_integrity_token() -> io::Result<Handle> {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &mut tok) == 0 {
            return Err(last());
        }
        let tok = Handle(tok);
        let mut dup: HANDLE = std::ptr::null_mut();
        if DuplicateTokenEx(
            tok.0,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        ) == 0
        {
            return Err(last());
        }
        let dup = Handle(dup);
        let mut sid: PSID = std::ptr::null_mut();
        let low = wide(std::ffi::OsStr::new("S-1-16-4096"));
        if ConvertStringSidToSidW(low.as_ptr(), &mut sid) == 0 {
            return Err(last());
        }
        let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: SE_GROUP_INTEGRITY_ } };
        let ok = SetTokenInformation(
            dup.0,
            TokenIntegrityLevel,
            &label as *const _ as *const _,
            (std::mem::size_of::<TOKEN_MANDATORY_LABEL>() + GetLengthSid(sid) as usize) as u32,
        );
        LocalFree(sid as _);
        if ok == 0 {
            return Err(last());
        }
        Ok(dup)
    }
}

fn restricted_job(limits: bool) -> io::Result<Handle> {
    unsafe {
        let job = Handle(CreateJobObjectW(std::ptr::null(), std::ptr::null()));
        if job.0.is_null() {
            return Err(last());
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if limits {
            info.BasicLimitInformation.LimitFlags |=
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        info.ProcessMemoryLimit = JOB_MEMORY_LIMIT;
        if SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, &info as *const _ as *const _, std::mem::size_of_val(&info) as u32) == 0 {
            return Err(last());
        }
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        if limits {
            SetInformationJobObject(job.0, JobObjectBasicUIRestrictions, &ui as *const _ as *const _, std::mem::size_of_val(&ui) as u32);
        }
        Ok(job)
    }
}

fn quote(arg: &str) -> String {
    // Our arguments are fixed literals and a path without quotes; quote when needed.
    if arg.is_empty() || arg.contains([' ', '\t']) {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

fn env_block() -> Vec<u16> {
    let mut s = String::new();
    if let Some(root) = std::env::var_os("SystemRoot") {
        s.push_str("SystemRoot=");
        s.push_str(&root.to_string_lossy());
        s.push('\0');
    }
    s.push('\0');
    s.encode_utf16().collect()
}

impl ChildProc {
    pub fn spawn(exe: &Path, args: &[&str], cwd: &Path, io_: Stdio) -> io::Result<ChildProc> {
        Self::spawn_with(exe, args, cwd, io_, Restrictions::ALL)
    }

    pub fn spawn_with(exe: &Path, args: &[&str], cwd: &Path, io_: Stdio, r: Restrictions) -> io::Result<ChildProc> {
        match Self::spawn_inner(exe, args, cwd, io_, r) {
            Err(e) if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) || e.raw_os_error() == Some(ERROR_NOT_SUPPORTED as i32) => {
                crate::log::warn("process mitigation attributes not supported by this Windows build; launching Xray without them");
                Self::spawn_inner(exe, args, cwd, io_, Restrictions { mitigations: false, no_child_processes: false, ..r })
            }
            r => r,
        }
    }

    fn spawn_inner(exe: &Path, args: &[&str], cwd: &Path, io_: Stdio, r: Restrictions) -> io::Result<ChildProc> {
        let (stdin_parent, stdin_child) = if io_.stdin { let (p, c) = pipe(true)?; (Some(p), c) } else { (None, nul()?) };
        let (stdout_parent, stdout_child) = if io_.stdout { let (p, c) = pipe(false)?; (Some(p), c) } else { (None, nul()?) };
        let (stderr_parent, stderr_child) = if io_.stderr { let (p, c) = pipe(false)?; (Some(p), c) } else { (None, nul()?) };
        let token = if r.low_integrity { Some(low_integrity_token()?) } else { None };
        let job = restricted_job(r.job_limits)?;

        let inherit = [stdin_child.0, stdout_child.0, stderr_child.0];
        let policy = MITIGATIONS;
        let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        let n_attrs = 1 + r.mitigations as u32 + r.no_child_processes as u32;
        unsafe {
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), n_attrs, 0, &mut size);
            let mut attr_buf = vec![0u8; size];
            let attrs = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
            if InitializeProcThreadAttributeList(attrs, n_attrs, 0, &mut size) == 0 {
                return Err(last());
            }
            struct AttrList(LPPROC_THREAD_ATTRIBUTE_LIST);
            impl Drop for AttrList {
                fn drop(&mut self) {
                    unsafe { DeleteProcThreadAttributeList(self.0) };
                }
            }
            let _guard = AttrList(attrs);
            if UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST_, inherit.as_ptr() as *const _, std::mem::size_of_val(&inherit), std::ptr::null_mut(), std::ptr::null()) == 0 {
                return Err(last());
            }
            if r.mitigations
                && UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY_, &policy as *const u64 as *const _, 8, std::ptr::null_mut(), std::ptr::null()) == 0
            {
                return Err(last());
            }
            if r.no_child_processes {
                if UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY_, &child_policy as *const u32 as *const _, 4, std::ptr::null_mut(), std::ptr::null()) == 0 {
                    return Err(last());
                }
            }

            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = stdin_child.0;
            si.StartupInfo.hStdOutput = stdout_child.0;
            si.StartupInfo.hStdError = stderr_child.0;
            si.lpAttributeList = attrs;

            let app = wide(exe.as_os_str());
            let mut cmdline: Vec<u16> = {
                let mut s = quote(&exe.to_string_lossy());
                for a in args {
                    s.push(' ');
                    s.push_str(&quote(a));
                }
                wide(std::ffi::OsStr::new(&s))
            };
            let dir = wide(cwd.as_os_str());
            let env = env_block();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            // DETACHED_PROCESS, not CREATE_NO_WINDOW: a console program started with CREATE_NO_WINDOW still gets
            // a conhost.exe child, which the no-child-process policy forbids (STATUS_DLL_INIT_FAILED).
            // Xray needs no console; its output goes through the pipes.
            let flags = CREATE_SUSPENDED | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
            let own_token = if token.is_none() {
                let mut t: HANDLE = std::ptr::null_mut();
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &mut t);
                Some(Handle(t))
            } else {
                None
            };
            let tok = token.as_ref().or(own_token.as_ref()).map(|h| h.0).unwrap_or(std::ptr::null_mut());
            if CreateProcessAsUserW(
                tok,
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                env.as_ptr() as *const _,
                dir.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ) == 0
            {
                return Err(last());
            }
            let process = Handle(pi.hProcess);
            let thread = Handle(pi.hThread);
            if AssignProcessToJobObject(job.0, process.0) == 0 {
                let e = last();
                TerminateProcess(process.0, 1);
                return Err(e);
            }
            ResumeThread(thread.0);
            drop(thread);
            // Child ends are owned by the child now; close ours so EOF propagates.
            drop((stdin_child, stdout_child, stderr_child));
            let file = |h: Option<Handle>| {
                h.map(|h| {
                    let raw = h.0;
                    std::mem::forget(h);
                    File::from_raw_handle(raw as _)
                })
            };
            Ok(ChildProc {
                process,
                _job: job,
                pid: pi.dwProcessId,
                stdin: file(stdin_parent),
                stdout: file(stdout_parent),
                stderr: file(stderr_parent),
                exited: None,
            })
        }
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn try_wait(&mut self) -> io::Result<Option<u32>> {
        if let Some(c) = self.exited {
            return Ok(Some(c));
        }
        unsafe {
            match WaitForSingleObject(self.process.0, 0) {
                WAIT_OBJECT_0 => {
                    let mut code = 0u32;
                    GetExitCodeProcess(self.process.0, &mut code);
                    self.exited = Some(code);
                    Ok(Some(code))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(last()),
            }
        }
    }

    pub fn kill(&mut self) {
        if self.exited.is_none() {
            unsafe { TerminateProcess(self.process.0, 1) };
        }
    }

    pub fn wait(&mut self) -> io::Result<u32> {
        unsafe { WaitForSingleObject(self.process.0, INFINITE) };
        Ok(self.try_wait()?.unwrap_or(1))
    }
}

/// What the OS reports about a running process's isolation (for diagnostics and tests).
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Isolation {
    /// "low" | "medium" | "high" | "system" | "untrusted" | "unknown"
    pub integrity: String,
    pub child_processes_blocked: bool,
    pub extension_points_disabled: bool,
    pub remote_images_blocked: bool,
}

pub fn isolation_of(pid: u32) -> Option<Isolation> {
    unsafe {
        let p = Handle(OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid));
        if p.0.is_null() {
            return None;
        }
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(p.0, TOKEN_QUERY, &mut tok) == 0 {
            return None;
        }
        let tok = Handle(tok);
        let mut len = 0u32;
        GetTokenInformation(tok.0, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(tok.0, TokenIntegrityLevel, buf.as_mut_ptr() as *mut _, len, &mut len) == 0 {
            return None;
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        let rid = *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
        let integrity = match rid {
            0x0000 => "untrusted",
            0x1000 => "low",
            0x2000 | 0x2100 => "medium",
            0x3000 => "high",
            0x4000 => "system",
            _ => "unknown",
        }
        .to_string();
        let flags = |policy: PROCESS_MITIGATION_POLICY| -> u32 {
            let mut v: u32 = 0;
            if GetProcessMitigationPolicy(p.0, policy, &mut v as *mut u32 as *mut _, 4) == 0 {
                0
            } else {
                v
            }
        };
        Some(Isolation {
            integrity,
            child_processes_blocked: flags(ProcessChildProcessPolicy) & 1 != 0,
            extension_points_disabled: flags(ProcessExtensionPointDisablePolicy) & 1 != 0,
            remote_images_blocked: flags(ProcessImageLoadPolicy) & 1 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Runs `xray version` under each restriction on its own and all together, and reports which
    /// ones Xray tolerates. Needs the pinned Xray in native/xray/dist (skipped otherwise).
    #[test]
    fn xray_runs_under_restrictions() {
        let xray = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("xray/dist/windows-x64/xray.exe");
        if !xray.is_file() {
            eprintln!("skipped: {} missing", xray.display());
            return;
        }
        let none = Restrictions { low_integrity: false, mitigations: false, no_child_processes: false, job_limits: false };
        let cases = [
            ("none", none),
            ("low_integrity", Restrictions { low_integrity: true, ..none }),
            ("mitigations", Restrictions { mitigations: true, ..none }),
            ("no_child_processes", Restrictions { no_child_processes: true, ..none }),
            ("job_limits", Restrictions { job_limits: true, ..none }),
            ("ALL", Restrictions::ALL),
        ];
        let mut report = Vec::new();
        for (name, r) in cases {
            let mut c = ChildProc::spawn_with(&xray, &["version"], xray.parent().unwrap(), Stdio { stdin: false, stdout: true, stderr: true }, r).unwrap();
            let mut out = String::new();
            let _ = c.stdout.take().unwrap().read_to_string(&mut out);
            let mut err = String::new();
            let _ = c.stderr.take().unwrap().read_to_string(&mut err);
            let code = c.wait().unwrap();
            report.push(format!("{name}: exit {code:#x} out={:?} err={:?}", out.lines().next().unwrap_or(""), err.lines().next().unwrap_or("")));
        }
        let all_ok = report.last().is_some_and(|l| l.contains("exit 0x0"));
        assert!(all_ok, "{}", report.join("
"));
    }
}
