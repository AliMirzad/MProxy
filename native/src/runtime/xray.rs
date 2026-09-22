//! Xray-core process management.
//!
//! * Location: `<helper dir>/xray/xray[.exe]` (installed layout), else `<helper dir>/xray[.exe]`.
//!   Never a caller-supplied path and never a PATH search. Debug builds in test mode may
//!   override it with `PRIVATE_PROXY_XRAY`; the binary must still match the pinned hash.
//! * Integrity: before every launch the binary's SHA-256 must equal the value pinned in
//!   `native/xray/xray.lock.json` (compiled in by `build.rs`). The file stays open while it is
//!   launched; on Windows the handle denies writers and deleters, so it cannot be swapped between
//!   the check and the launch.
//! * Arguments are fixed: `run -c stdin: -format json` (and `-test` for validation).
//!   The config, which contains credentials, is written to the child's stdin: no temp file, and
//!   nothing sensitive in the process arguments.
//! * Environment: cleared; only `SystemRoot` is passed on Windows.
//! * Windows: see `winproc.rs` (Low integrity, mitigation policies, no child processes,
//!   restricted kill-on-close job, explicit handle list).
//! * Unix: a PID file per helper instance lets the next helper reap an Xray orphaned by a
//!   `SIGKILL`ed helper; SIGTERM/SIGHUP/SIGINT kill the child before exiting.

use crate::log::{self, Tail};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// SHA-256 of the pinned Xray binary for this platform (empty if the platform has none).
pub const PINNED_SHA256: &str = env!("PP_XRAY_SHA256");
/// Pinned Xray-core release, e.g. "v26.3.27".
pub const PINNED_VERSION: &str = env!("PP_XRAY_VERSION");

pub fn exe_name() -> &'static str {
    if cfg!(windows) {
        "xray.exe"
    } else {
        "xray"
    }
}

pub fn locate() -> Option<PathBuf> {
    if let Some(p) = crate::test_hook("PRIVATE_PROXY_XRAY") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let me = std::env::current_exe().ok()?;
    let dir = me.parent()?;
    [dir.join("xray").join(exe_name()), dir.join(exe_name())].into_iter().find(|p| p.is_file())
}

/// Opens `xray` so that it cannot be modified while the handle is open (Windows) and checks its
/// SHA-256 against the pinned value. Keep the returned handle alive until the process is started.
pub fn verify(xray: &Path) -> Result<std::fs::File, String> {
    if PINNED_SHA256.is_empty() {
        return Err("no pinned Xray build for this platform".into());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        opts.share_mode(FILE_SHARE_READ); // no FILE_SHARE_WRITE / FILE_SHARE_DELETE
    }
    let mut f = opts.open(xray).map_err(|e| format!("cannot open Xray: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("cannot read Xray: {e}"))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != PINNED_SHA256 {
        log::error(format!("Xray integrity check failed for {} (sha256 {got})", xray.display()));
        return Err("the Xray binary does not match the pinned release (modified or corrupted). Reinstall the runtime.".into());
    }
    Ok(f)
}

/// A started Xray process, independent of platform.
struct Proc {
    #[cfg(windows)]
    inner: crate::platform::winproc::ChildProc,
    #[cfg(not(windows))]
    inner: std::process::Child,
}

impl Proc {
    fn spawn(xray: &Path, args: &[&str], stdin: bool) -> Result<Proc, String> {
        let guard = verify(xray)?;
        let dir = xray.parent().unwrap_or(Path::new("."));
        #[cfg(windows)]
        let r = crate::platform::winproc::ChildProc::spawn(xray, args, dir, crate::platform::winproc::Stdio { stdin, stdout: true, stderr: true })
            .map(|inner| Proc { inner });
        #[cfg(not(windows))]
        let r = {
            use std::process::{Command, Stdio};
            #[cfg(target_os = "macos")]
            // MANDATORY: never run Xray outside the sandbox.
            if let Err(e) = crate::platform::macsandbox::usable(xray) {
                drop(guard);
                return Err(format!("runtime security check failed: the macOS sandbox is unavailable ({e})"));
            }
            let mut c = match crate::platform::macsandbox::usable(xray) {
                Ok(()) => {
                    let mut c = Command::new(crate::platform::macsandbox::SANDBOX_EXEC);
                    // Canonical path: the profile allows exec of exactly this file.
                    c.arg("-p").arg(crate::platform::macsandbox::profile(xray, &crate::platform::paths::home_dir())).arg(std::fs::canonicalize(xray).unwrap_or_else(|_| xray.to_path_buf()));
                    c
                }
                Err(_) => unreachable!("checked above"),
            };
            #[cfg(not(target_os = "macos"))]
            let mut c = Command::new(xray);
            c.args(args)
                .env_clear()
                .current_dir(dir)
                .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map(|inner| Proc { inner })
        };
        drop(guard);
        r.map_err(|e| {
            let m = e.to_string();
            if m.starts_with("runtime security check failed") {
                m
            } else {
                format!("could not start Xray: {m}")
            }
        })
    }
    fn id(&self) -> u32 {
        self.inner.id()
    }
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.inner.stdin.take().map(|s| Box::new(s) as Box<dyn Write + Send>)
    }
    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>)
    }
    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>)
    }
    /// `Some(description)` once exited.
    fn try_exit(&mut self) -> Result<Option<(bool, String)>, String> {
        #[cfg(windows)]
        return self.inner.try_wait().map(|o| o.map(|c| (c == 0, format!("exit code {c}")))).map_err(|e| e.to_string());
        #[cfg(not(windows))]
        return self.inner.try_wait().map(|o| o.map(|s| (s.success(), format!("{s}")))).map_err(|e| e.to_string());
    }
    fn kill(&mut self) {
        #[cfg(windows)]
        self.inner.kill();
        #[cfg(not(windows))]
        let _ = self.inner.kill();
    }
    fn wait(&mut self) {
        let _ = self.inner.wait();
    }
}

/// Validates a config with `xray run -test`. Returns the (redacted) failure reason.
pub fn test_config(xray: &Path, config: &[u8]) -> Result<(), String> {
    let mut child = Proc::spawn(xray, &["run", "-test", "-c", "stdin:", "-format", "json"], true)?;
    {
        let mut stdin = child.take_stdin().ok_or("no stdin")?;
        stdin.write_all(config).map_err(|e| format!("could not pass config to Xray: {e}"))?;
    }
    let (ok, text) = wait_with_timeout(child, Duration::from_secs(15))?;
    if ok {
        return Ok(());
    }
    let reason = text
        .lines()
        .rev()
        .find(|l| l.contains("Failed") || l.contains("failed") || l.contains("error"))
        .unwrap_or("Xray rejected the configuration");
    // Keep the most specific ("> ...") part of Xray's error chain.
    let short = reason.rsplit(" > ").next().unwrap_or(reason);
    Err(log::redact(short.trim()))
}

fn wait_with_timeout(mut child: Proc, timeout: Duration) -> Result<(bool, String), String> {
    fn drain(r: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut v);
            }
            v
        })
    }
    let out = drain(child.take_stdout());
    let err = drain(child.take_stderr());
    let deadline = std::time::Instant::now() + timeout;
    let ok = loop {
        match child.try_exit()? {
            Some((ok, _)) => break ok,
            None if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => {
                child.kill();
                child.wait();
                return Err("Xray did not finish validating the configuration in time".into());
            }
        }
    };
    let text = format!("{}{}", String::from_utf8_lossy(&out.join().unwrap_or_default()), String::from_utf8_lossy(&err.join().unwrap_or_default()));
    Ok((ok, text))
}

pub struct Running {
    child: Arc<Mutex<Proc>>,
    pub pid: u32,
    pub tail: Arc<Mutex<Tail>>,
    #[cfg(unix)]
    pidfile: Option<PathBuf>,
}

impl Running {
    /// Non-blocking: `Some(exit description)` once the process has exited.
    pub fn try_exit(&self) -> Option<String> {
        let mut c = self.child.lock().unwrap_or_else(|e| e.into_inner());
        match c.try_exit() {
            Ok(Some((_, how))) => Some(how),
            Ok(None) => None,
            Err(e) => Some(format!("wait failed: {e}")),
        }
    }

    pub fn stop(self) {
        {
            let mut c = self.child.lock().unwrap_or_else(|e| e.into_inner());
            c.kill();
            c.wait();
        }
        #[cfg(unix)]
        {
            unix::set_child(0);
            if let Some(p) = &self.pidfile {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    /// OS-reported isolation of the running process (Windows), for diagnostics and tests.
    pub fn isolation(&self) -> Option<serde_json::Value> {
        #[cfg(windows)]
        return crate::platform::winproc::isolation_of(self.pid).and_then(|i| serde_json::to_value(i).ok());
        #[cfg(target_os = "macos")]
        return crate::platform::macsandbox::state().map(|r| match r {
            Ok(()) => serde_json::json!({ "sandbox": true }),
            Err(e) => serde_json::json!({ "sandbox": false, "reason": e }),
        });
        #[cfg(not(any(windows, target_os = "macos")))]
        None
    }
}

/// Starts `xray run` with `config` on stdin and captures its output into a bounded tail
/// (and into the debug log when enabled).
pub fn spawn(xray: &Path, config: &[u8], run_dir: &Path) -> Result<Running, String> {
    let mut child = Proc::spawn(xray, &["run", "-c", "stdin:", "-format", "json"], true)?;
    let pid = child.id();
    let _ = &run_dir; // only used on Unix (PID file)

    #[cfg(unix)]
    let pidfile = {
        unix::set_child(pid as i32);
        let p = run_dir.join(format!("xray-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .and_then(|mut f| f.write_all(format!("{pid}\n{}\n", xray.display()).as_bytes()));
        Some(p)
    };

    if let Some(mut stdin) = child.take_stdin() {
        if let Err(e) = stdin.write_all(config) {
            child.kill();
            return Err(format!("could not pass config to Xray: {e}"));
        }
        // dropping stdin closes it; Xray reads the config until EOF
    }

    let tail = Arc::new(Mutex::new(Tail::new(60)));
    for stream in [child.take_stdout(), child.take_stderr()].into_iter().flatten() {
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
            if crate::platform::harden::is_link(&e.path()) {
                let _ = std::fs::remove_file(e.path());
                continue;
            }
            if alive(helper) {
                continue; // another helper (another browser) still owns it
            }
            if let Ok(txt) = std::fs::read_to_string(e.path()) {
                if let Some(pid) = txt.lines().next().and_then(|l| l.trim().parse::<i32>().ok()) {
                    // Only ever kill a process that is running *our* Xray binary.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_hash_is_compiled_in() {
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(PINNED_SHA256.len(), 64);
            assert!(PINNED_VERSION.starts_with('v'));
        }
    }

    #[test]
    fn modified_binary_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(exe_name());
        std::fs::write(&p, b"MZ not the pinned xray").unwrap();
        let e = verify(&p).unwrap_err();
        assert!(e.contains("does not match") || e.contains("no pinned"), "{e}");
        assert!(test_config(&p, b"{}").is_err());
        assert!(spawn(&p, b"{}", t.path()).is_err());
    }
}
