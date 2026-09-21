//! Xray-core process management.
//!
//! * Location: `PRIVATE_PROXY_XRAY` (development), else `<helper dir>/xray/xray[.exe]`,
//!   else `<helper dir>/xray[.exe]`. Never a caller-supplied path.
//! * Arguments are fixed: `run -c stdin: -format json` (and `-test` for validation).
//!   The config, which contains credentials, is written to the child's stdin: no temp file, and
//!   nothing sensitive in the process arguments.
//! * Windows: the child joins a Job Object with KILL_ON_JOB_CLOSE, so it cannot outlive the
//!   helper, and it is created with CREATE_NO_WINDOW.
//! * Unix: a PID file per helper instance lets the next helper reap an Xray orphaned by a
//!   `SIGKILL`ed helper; SIGTERM/SIGHUP/SIGINT kill the child before exiting.

use crate::log::{self, Tail};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn exe_name() -> &'static str {
    if cfg!(windows) {
        "xray.exe"
    } else {
        "xray"
    }
}

pub fn locate() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PRIVATE_PROXY_XRAY") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let me = std::env::current_exe().ok()?;
    let dir = me.parent()?;
    [dir.join("xray").join(exe_name()), dir.join(exe_name())].into_iter().find(|p| p.is_file())
}

fn command(xray: &Path) -> Command {
    let mut c = Command::new(xray);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    // Xray must not pick up asset/config locations from the environment.
    c.env_remove("XRAY_LOCATION_CONFIG").env_remove("XRAY_LOCATION_CONFDIR").env_remove("XRAY_LOCATION_ASSET");
    if let Some(dir) = xray.parent() {
        c.current_dir(dir);
    }
    c
}

/// `xray version` -> "26.3.27".
pub fn version(xray: &Path) -> Option<String> {
    let out = command(xray).arg("version").stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?;
    let v = first.split_whitespace().nth(1)?;
    Some(v.to_string())
}

/// Validates a config with `xray run -test`. Returns the (redacted) failure reason.
pub fn test_config(xray: &Path, config: &[u8]) -> Result<(), String> {
    let mut child = command(xray)
        .args(["run", "-test", "-c", "stdin:", "-format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start Xray: {e}"))?;
    {
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        stdin.write_all(config).map_err(|e| format!("could not pass config to Xray: {e}"))?;
    }
    let out = wait_with_timeout(child, Duration::from_secs(15))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let reason = text
        .lines()
        .rev()
        .find(|l| l.contains("Failed") || l.contains("failed") || l.contains("error"))
        .unwrap_or("Xray rejected the configuration");
    // Keep the most specific ("> ...") part of Xray's error chain.
    let short = reason.rsplit(" > ").next().unwrap_or(reason);
    Err(log::redact(short.trim()))
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> Result<std::process::Output, String> {
    fn drain(r: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut r) = r {
                let _ = std::io::Read::read_to_end(&mut r, &mut v);
            }
            v
        })
    }
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Xray did not finish validating the configuration in time".into());
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    Ok(std::process::Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
}

pub struct Running {
    child: Arc<Mutex<Child>>,
    pub pid: u32,
    pub tail: Arc<Mutex<Tail>>,
    #[cfg(windows)]
    _job: job::Job,
    #[cfg(unix)]
    pidfile: Option<PathBuf>,
}

impl Running {
    /// Non-blocking: `Some(exit description)` once the process has exited.
    pub fn try_exit(&self) -> Option<String> {
        let mut c = self.child.lock().unwrap_or_else(|e| e.into_inner());
        match c.try_wait() {
            Ok(Some(st)) => Some(format!("{st}")),
            Ok(None) => None,
            Err(e) => Some(format!("wait failed: {e}")),
        }
    }

    pub fn stop(self) {
        {
            let mut c = self.child.lock().unwrap_or_else(|e| e.into_inner());
            let _ = c.kill();
            let _ = c.wait();
        }
        #[cfg(unix)]
        {
            unix::set_child(0);
            if let Some(p) = &self.pidfile {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// Starts `xray run` with `config` on stdin and captures its output into a bounded tail
/// (and into the debug log when enabled).
pub fn spawn(xray: &Path, config: &[u8], run_dir: &Path) -> Result<Running, String> {
    let mut child = command(xray)
        .args(["run", "-c", "stdin:", "-format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start Xray: {e}"))?;
    let pid = child.id();

    #[cfg(windows)]
    let job = match job::Job::new_kill_on_close() {
        Ok(j) => {
            if let Err(e) = j.assign(&child) {
                log::warn(format!("could not assign Xray to job object: {e}"));
            }
            j
        }
        Err(e) => {
            let _ = child.kill();
            return Err(format!("could not create job object: {e}"));
        }
    };
    let _ = &run_dir; // only used on Unix (PID file)

    #[cfg(unix)]
    let pidfile = {
        unix::set_child(pid as i32);
        let p = run_dir.join(format!("xray-{}.pid", std::process::id()));
        let _ = std::fs::write(&p, format!("{pid}\n{}\n", xray.display()));
        Some(p)
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(config) {
            let _ = child.kill();
            return Err(format!("could not pass config to Xray: {e}"));
        }
        // dropping stdin closes it; Xray reads the config until EOF
    }

    let tail = Arc::new(Mutex::new(Tail::new(60)));
    for stream in [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)].into_iter().flatten() {
        let tail = tail.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                tail.lock().unwrap_or_else(|e| e.into_inner()).push(&line);
                if log::debug_enabled() {
                    log::debug(format!("xray: {line}"));
                }
            }
        });
    }

    Ok(Running {
        child: Arc::new(Mutex::new(child)),
        pid,
        tail,
        #[cfg(windows)]
        _job: job,
        #[cfg(unix)]
        pidfile,
    })
}

/// Unix: kill Xray processes left behind by helpers that no longer exist.
pub fn reap_orphans(run_dir: &Path, xray: &Path) {
    #[cfg(unix)]
    unix::reap(run_dir, xray);
    #[cfg(not(unix))]
    let _ = (run_dir, xray);
}

/// Unix: install signal handlers that kill the current child before exiting.
pub fn install_signal_handlers() {
    #[cfg(unix)]
    unix::install();
}

#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::*;

    pub struct Job(HANDLE);
    unsafe impl Send for Job {}

    impl Job {
        pub fn new_kill_on_close() -> std::io::Result<Job> {
            unsafe {
                let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if h.is_null() {
                    return Err(std::io::Error::last_os_error());
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    let e = std::io::Error::last_os_error();
                    CloseHandle(h);
                    return Err(e);
                }
                Ok(Job(h))
            }
        }
        pub fn assign(&self, child: &std::process::Child) -> std::io::Result<()> {
            unsafe {
                if AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::path::Path;
    use std::sync::atomic::{AtomicI32, Ordering};

    static CHILD: AtomicI32 = AtomicI32::new(0);

    pub fn set_child(pid: i32) {
        CHILD.store(pid, Ordering::SeqCst);
    }

    extern "C" fn on_signal(_: libc::c_int) {
        let pid = CHILD.load(Ordering::SeqCst);
        unsafe {
            if pid > 0 {
                libc::kill(pid, libc::SIGKILL);
            }
            libc::_exit(0);
        }
    }

    pub fn install() {
        unsafe {
            for s in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
                libc::signal(s, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
            }
            // A closed stdout must surface as an error, not kill us before cleanup.
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
    }

    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[cfg(target_os = "macos")]
    fn exe_of(pid: i32) -> Option<std::path::PathBuf> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(std::path::PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
    }

    #[cfg(not(target_os = "macos"))]
    fn exe_of(pid: i32) -> Option<std::path::PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    pub fn reap(run_dir: &Path, xray: &Path) {
        let Ok(rd) = std::fs::read_dir(run_dir) else { return };
        let want = std::fs::canonicalize(xray).unwrap_or_else(|_| xray.to_path_buf());
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(helper) = name.strip_prefix("xray-").and_then(|s| s.strip_suffix(".pid")).and_then(|s| s.parse::<i32>().ok()) else { continue };
            if alive(helper) {
                continue; // another helper (another browser) still owns it
            }
            if let Ok(txt) = std::fs::read_to_string(e.path()) {
                if let Some(pid) = txt.lines().next().and_then(|l| l.trim().parse::<i32>().ok()) {
                    let same = exe_of(pid).map(|p| std::fs::canonicalize(&p).unwrap_or(p) == want).unwrap_or(false);
                    if pid > 0 && alive(pid) && same {
                        crate::log::warn(format!("killing orphaned Xray pid {pid}"));
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(e.path());
        }
    }
}
