//! Tests of the Shared Core used directly, in-process, without the browser adapter or native
//! messaging: the way any future client consumes it. Real Xray (pinned, restricted), a real local
//! Xray "server" and a local HTTP target reachable only as `probe.test` through the server.
//!
//! Test hooks are process-wide environment variables, so everything here shares one server and
//! one probe target, set up once.

use ppcore::core::api::{Core, CoreEvent, CoreMsg, ImportKind, Poster, Timing};
use ppcore::core::error::ErrorKind;
use ppcore::core::secrets::FileKeyProvider;
use ppcore::core::session::{SessionState, StartPhase};
use ppcore::core::store::Store;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn xray_path() -> Option<PathBuf> {
    let plat = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "windows-x64",
        ("windows", "aarch64") => "windows-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("macos", "aarch64") => "macos-arm64",
        _ => return None,
    };
    let exe = if cfg!(windows) { "xray.exe" } else { "xray" };
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xray/dist").join(plat).join(exe);
    p.is_file().then_some(p)
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

struct World {
    xray: PathBuf,
    server_port: u16,
    target_port: u16,
    _server: Mutex<Child>,
}

/// One server + target for the whole binary; test hooks set once, before any Core exists.
fn world() -> Option<&'static World> {
    static W: OnceLock<Option<World>> = OnceLock::new();
    W.get_or_init(|| {
        let xray = xray_path()?;
        // Target: answers 204, closes gracefully (see integration.rs start_target).
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target_port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut buf = [0u8; 2048];
                    let mut got = Vec::new();
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                    let _ = s.shutdown(std::net::Shutdown::Write);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                });
            }
        });
        let server_port = free_port();
        let cfg = json!({
            "log": {"loglevel": "warning"},
            "dns": {"hosts": {"probe.test": "127.0.0.1"}},
            "inbounds": [{"listen":"127.0.0.1","port":server_port,"protocol":"vless","settings":{"clients":[{"id":UUID}],"decryption":"none"},"streamSettings":{"network":"raw"}}],
            "outbounds": [{"protocol":"freedom","settings":{"domainStrategy":"UseIP"}}]
        });
        let mut child = Command::new(&xray).args(["run", "-c", "stdin:", "-format", "json"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(cfg.to_string().as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", server_port)).is_err() {
            assert!(Instant::now() < deadline, "server xray did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        std::env::set_var("PRIVATE_PROXY_TEST_MODE", "1");
        std::env::set_var("PRIVATE_PROXY_ALLOW_LOOPBACK", "1");
        std::env::set_var("PRIVATE_PROXY_PROBE_URL", format!("probe.test:{target_port}/generate_204"));
        Some(World { xray, server_port, target_port, _server: Mutex::new(child) })
    })
    .as_ref()
}

macro_rules! require_world {
    () => {
        match world() {
            Some(w) => w,
            None => {
                eprintln!("skipped: pinned Xray not present (node scripts/fetch-xray.mjs)");
                return;
            }
        }
    };
}

struct Harness {
    core: Core,
    rx: Receiver<CoreMsg>,
    events: Vec<CoreEvent>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new(xray: Option<PathBuf>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let store = Store::open(data.clone(), Box::new(FileKeyProvider { path: dir.path().join("test.key") })).unwrap();
        let (tx, rx) = channel::<CoreMsg>();
        let tx = Mutex::new(tx);
        let post: Poster = Arc::new(move |m| {
            let _ = tx.lock().unwrap().send(m);
        });
        let mut core = Core::new(store, xray, post, Timing::default());
        let s = core.update_settings(ppcore::core::api::SettingsUpdate { jetbrains_enabled: Some(false), ..Default::default() });
        assert!(s.is_ok());
        core.start();
        Harness { core, rx, events: Vec::new(), _dir: dir }
    }

    /// Feeds worker results and ticks into the Core until `done` holds.
    fn pump_until(&mut self, what: &str, timeout: Duration, done: impl Fn(&Core, &[CoreEvent]) -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            self.events.extend(self.core.take_events());
            if done(&self.core, &self.events) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}; state {:?}", self.core.session_status().state);
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(m) => self.core.handle(m),
                Err(_) => self.core.handle(CoreMsg::Tick),
            }
        }
    }

    fn connect(&mut self, id: &str) -> SessionState {
        self.core.start_session(id).unwrap();
        let id = id.to_string();
        self.pump_until("connected or failed", Duration::from_secs(30), move |c, _| match &c.session_status().state {
            SessionState::Connected { profile_id, .. } => *profile_id == id,
            SessionState::Failed { .. } => true,
            _ => false,
        });
        self.core.session_status().state
    }
}

fn vless(port: u16, name: &str) -> String {
    format!("vless://{UUID}@127.0.0.1:{port}?type=tcp&security=none#{name}")
}

/// GET through an HTTP proxy with Basic credentials; returns the status line.
fn via_proxy(port: u16, host: &str, target: u16, cred: Option<(&str, &str)>) -> String {
    use base64::Engine;
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return "connection refused".into() };
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let auth = cred.map(|(u, p)| format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))).unwrap_or_default();
    let _ = s.write_all(format!("GET http://{host}:{target}/x HTTP/1.1\r\nHost: {host}:{target}\r\n{auth}Connection: close\r\n\r\n").as_bytes());
    let mut line = String::new();
    let _ = BufReader::new(s).read_line(&mut line);
    line.trim().to_string()
}

// ---------------------------------------------------------------- profiles and import

#[test]
fn imports_normalize_vless_and_vmess_and_keep_provenance() {
    let _ = require_world!();
    let mut h = Harness::new(xray_path());
    use base64::Engine;
    let vm = json!({"v":"2","ps":"VM \u{202e}gnp.exe","add":"vm.example.com","port":"443","id":UUID,"net":"ws","path":"/p","tls":"tls","sni":"vm.example.com"});
    let text = format!(
        "vless://{UUID}@VL.Example.COM:443?type=ws&path=%2Fws&security=tls&sni=vl.example.com#A%E2%80%8Bb\nvmess://{}",
        base64::engine::general_purpose::STANDARD.encode(vm.to_string())
    );
    let r = h.core.import_profiles(&text, ImportKind::Text).unwrap();
    assert_eq!((r.added, r.rejected), (2, 0));
    let l = h.core.list_profiles().unwrap();
    let vl = l.profiles.iter().find(|p| p.address == "vl.example.com").expect("host normalized to lower case");
    assert_eq!(serde_json::to_value(vl.protocol).unwrap(), "vless");
    assert_eq!((vl.transport.as_str(), vl.security.as_str(), vl.port), ("ws", "tls", 443));
    assert_eq!(vl.name, "Ab", "zero-width stripped at the trust boundary");
    let vmp = l.profiles.iter().find(|p| p.address == "vm.example.com").unwrap();
    assert_eq!(serde_json::to_value(vmp.protocol).unwrap(), "vmess");
    assert_eq!(vmp.name, "VM gnp.exe", "bidi override stripped");
    assert!(l.profiles.iter().all(|p| p.subscription_id.is_none()), "manual provenance");
    // Summaries never carry the user id.
    assert!(!format!("{:?}", l.profiles).contains(UUID));
    // Importing the same servers again updates, never duplicates.
    let again = h.core.import_profiles(&text, ImportKind::Text).unwrap();
    assert_eq!((again.added, again.updated), (0, 2));
}

#[test]
fn hostile_imports_are_rejected_as_data() {
    let _ = require_world!();
    let mut h = Harness::new(xray_path());
    let cases = [
        // A full Xray config: only VLESS/VMess outbounds are ever read; here there is none.
        r#"{"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks"}],"api":{"tag":"api"}}"#.to_string(),
        // Dangerous / unknown outbound fields reject the entry.
        format!(r#"{{"protocol":"vless","settings":{{"address":"s.example.com","port":443,"id":"{UUID}"}},"streamSettings":{{"security":"tls","tlsSettings":{{"masterKeyLog":"C:\\x.log"}}}}}}"#),
        format!(r#"{{"protocol":"vless","settings":{{"address":"s.example.com","port":443,"id":"{UUID}"}},"futureField":1}}"#),
        // Unknown link parameter, malformed URI, unsupported scheme, metadata target.
        format!("vless://{UUID}@s.example.com:443?security=tls&fm=%7B%7D#x"),
        "vless://@:0".into(),
        "trojan://pw@s.example.com:443#t".into(),
        format!("vless://{UUID}@169.254.169.254:80?security=none#meta"),
    ];
    for c in cases {
        let e = h.core.import_profiles(&c, ImportKind::Text).expect_err(&c);
        assert_eq!(e.kind, ErrorKind::InvalidProfile, "{c}: {e:?}");
    }
    // QR payloads that are not proxy configs are refused (never opened).
    assert!(h.core.import_profiles("https://evil.example/", ImportKind::Qr).is_err());
    assert!(h.core.list_profiles().unwrap().profiles.is_empty());
}

// ---------------------------------------------------------------- subscriptions

struct SubServer {
    url: String,
    body: Arc<Mutex<String>>,
    location: Arc<Mutex<Option<String>>>,
}

fn sub_server() -> SubServer {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    let body = Arc::new(Mutex::new(String::new()));
    let location = Arc::new(Mutex::new(None::<String>));
    let (b2, l2) = (body.clone(), location.clone());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let resp = match l2.lock().unwrap().clone() {
                Some(loc) => format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                None => {
                    let b = b2.lock().unwrap().clone();
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                }
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    SubServer { url: format!("http://127.0.0.1:{port}/sub"), body, location }
}

fn wait_subscription(h: &mut Harness, ticket: u64) -> Result<ppcore::core::api::RefreshReport, ppcore::core::error::CoreError> {
    h.pump_until("subscription", Duration::from_secs(30), move |_, ev| ev.iter().any(|e| matches!(e, CoreEvent::SubscriptionDone { ticket: t, .. } if *t == ticket)));
    let i = h.events.iter().position(|e| matches!(e, CoreEvent::SubscriptionDone { ticket: t, .. } if *t == ticket)).unwrap();
    match h.events.remove(i) {
        CoreEvent::SubscriptionDone { result, .. } => result,
        _ => unreachable!(),
    }
}

#[test]
fn subscriptions_associate_source_dedupe_refresh_and_refuse_bad_redirects() {
    let _ = require_world!();
    let mut h = Harness::new(xray_path());
    let s = sub_server();
    let a = format!("vless://{UUID}@a.example.com:443?security=tls#A");
    let b = format!("vless://{UUID}@b.example.com:443?security=tls#B");
    let c = format!("vless://{UUID}@c.example.com:443?security=tls#C");
    *s.body.lock().unwrap() = format!("{a}\n{b}\n{a}\n");
    h.core.add_subscription("Work", &s.url, 1).unwrap();
    let r = wait_subscription(&mut h, 1).unwrap();
    assert_eq!((r.added, r.removed), (2, 0), "duplicate entry collapsed");
    let l = h.core.list_profiles().unwrap();
    assert_eq!(l.subscriptions.len(), 1);
    assert!(l.profiles.iter().all(|p| p.subscription_id.as_deref() == Some(r.subscription_id.as_str())), "source association");
    assert!(!format!("{:?}", l.subscriptions).contains("/sub"), "subscription URL is not exposed");

    *s.body.lock().unwrap() = format!("{b}\n{c}\n");
    h.core.refresh_subscription(&r.subscription_id, 2).unwrap();
    let r2 = wait_subscription(&mut h, 2).unwrap();
    assert_eq!((r2.added, r2.updated, r2.removed), (1, 1, 1));

    // Manual profiles are never touched by a subscription refresh.
    h.core.import_profiles(&format!("vless://{UUID}@m.example.com:443?security=tls#Manual"), ImportKind::Text).unwrap();
    h.core.refresh_subscription(&r.subscription_id, 3).unwrap();
    wait_subscription(&mut h, 3).unwrap();
    assert!(h.core.list_profiles().unwrap().profiles.iter().any(|p| p.name == "Manual" && p.subscription_id.is_none()));

    for loc in ["https://169.254.169.254/latest/meta-data/", "https://10.0.0.1/sub", "http://sub.example.com/downgrade", "file:///C:/Windows/win.ini"] {
        *s.location.lock().unwrap() = Some(loc.into());
        h.core.refresh_subscription(&r.subscription_id, 4).unwrap();
        let e = wait_subscription(&mut h, 4).unwrap_err();
        assert_eq!(e.kind, ErrorKind::SubscriptionFailure, "{loc}");
    }
    *s.location.lock().unwrap() = None;
    // URL policy is checked before any network access. (Loopback is allowed by this binary's test
    // hook for its local servers; integration.rs checks loopback refusal on a production-like helper.)
    for bad in ["http://sub.example.com/x", "https://169.254.169.254/", "https://[fe80::1]/x", "https://0.0.0.0/x", "ftp://x/y"] {
        let e = h.core.add_subscription("x", bad, 5).unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidProfile, "{bad}");
    }
    // Removing the subscription removes its profiles, keeps manual ones.
    h.core.remove_subscription(&r.subscription_id, true).unwrap();
    let l = h.core.list_profiles().unwrap();
    assert!(l.subscriptions.is_empty() && l.profiles.len() == 1);
}

// ---------------------------------------------------------------- sessions

#[test]
fn session_lifecycle_credentials_and_cleanup() {
    let w = require_world!();
    let mut h = Harness::new(Some(w.xray.clone()));
    assert!(!h.core.runtime_capabilities().application_routing, "never claimed");
    let id = h.core.import_profiles(&vless(w.server_port, "Local"), ImportKind::Text).unwrap().profile_ids[0].clone();
    assert!(h.core.browser_proxy_endpoint().is_none());

    h.core.start_session(&id).unwrap();
    let evs = h.core.take_events();
    let phases: Vec<_> = evs
        .iter()
        .filter_map(|e| match e {
            CoreEvent::StatusChanged { status, browser_proxy } => {
                assert!(browser_proxy.is_none(), "no credentials before the tunnel is verified");
                match &status.state {
                    SessionState::Starting { phase, .. } => Some(*phase),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect();
    assert_eq!(phases, vec![StartPhase::Launching, StartPhase::Verifying], "Connected is never set before the probe");
    h.pump_until("connected", Duration::from_secs(30), |c, _| matches!(c.session_status().state, SessionState::Connected { .. } | SessionState::Failed { .. }));
    assert!(matches!(h.core.session_status().state, SessionState::Connected { .. }), "{:?}", h.core.session_status().state);

    let ep = h.core.browser_proxy_endpoint().expect("endpoint while connected");
    assert_eq!(ep.host, "127.0.0.1");
    let (user, pass) = (ep.credentials.user.clone(), ep.credentials.pass.clone());
    assert!(via_proxy(ep.port, "probe.test", w.target_port, Some((&user, &pass))).contains("204"), "tunnel works with the credentials");
    assert!(via_proxy(ep.port, "probe.test", w.target_port, None).contains("407"), "no credentials: 407");
    assert!(via_proxy(ep.port, "probe.test", w.target_port, Some((&user, "wrong"))).contains("407"));
    // Nothing printable or serializable exposes them.
    let dump = format!("{:?} {:?} {:?}", h.core.session_status(), ep, h.events);
    assert!(!dump.contains(&pass), "credentials in Debug output");
    assert!(!serde_json::to_string(&h.core.diagnostics()).unwrap().contains(&pass), "credentials in diagnostics");

    // A second connection gets new credentials; the old ones stop working.
    h.core.stop_session();
    assert_eq!(h.core.session_status().state, SessionState::Disconnected);
    assert!(h.core.browser_proxy_endpoint().is_none(), "credentials dropped on stop");
    assert!(h.core.diagnostics().xray_pid.is_none(), "Xray terminated");
    assert!(!via_proxy(ep.port, "probe.test", w.target_port, Some((&user, &pass))).contains("204"), "old endpoint unusable after stop");
    assert!(matches!(h.connect(&id), SessionState::Connected { .. }));
    let ep2 = h.core.browser_proxy_endpoint().unwrap();
    assert_ne!(ep2.credentials.pass, pass, "fresh credentials per connection");

    // Crash: Xray is restarted with the same endpoint and credentials.
    let pid = h.core.diagnostics().xray_pid.unwrap();
    kill(pid);
    h.pump_until("restart", Duration::from_secs(20), move |c, _| c.diagnostics().xray_pid.is_some_and(|p| p != pid) && matches!(c.session_status().state, SessionState::Connected { .. }));
    let ep3 = h.core.browser_proxy_endpoint().unwrap();
    assert_eq!((ep3.port, &ep3.credentials), (ep2.port, &ep2.credentials));
    h.core.stop_session();
    h.core.shutdown();
}

#[test]
fn start_failures_are_reported_and_leave_nothing_running() {
    let w = require_world!();
    let mut h = Harness::new(Some(w.xray.clone()));
    // Unreachable server: Xray starts, the probe fails.
    let id = h.core.import_profiles(&vless(free_port(), "Dead"), ImportKind::Text).unwrap().profile_ids[0].clone();
    match h.connect(&id) {
        SessionState::Failed { error, profile_id } => {
            assert_eq!(error.kind, ErrorKind::ConnectionFailure);
            assert_eq!(profile_id.as_deref(), Some(id.as_str()));
        }
        s => panic!("expected failure, got {s:?}"),
    }
    assert!(h.core.browser_proxy_endpoint().is_none());
    assert!(h.core.diagnostics().xray_pid.is_none());
    // Unknown and malformed ids.
    assert_eq!(h.core.start_session("not-a-uuid").unwrap_err().kind, ErrorKind::InvalidRequest);
    assert_eq!(h.core.start_session("00000000-0000-4000-8000-000000000000").unwrap_err().kind, ErrorKind::NotFound);
}

#[test]
fn tampered_runtime_is_never_started() {
    let w = require_world!();
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join(if cfg!(windows) { "xray.exe" } else { "xray" });
    let mut bytes = std::fs::read(&w.xray).unwrap();
    let n = bytes.len() / 2;
    bytes[n] ^= 1;
    std::fs::write(&fake, bytes).unwrap();
    let mut h = Harness::new(Some(fake));
    assert!(!h.core.session_status().runtime_available);
    let id = h.core.import_profiles(&vless(w.server_port, "Local"), ImportKind::Text).unwrap().profile_ids[0].clone();
    match h.connect(&id) {
        SessionState::Failed { error, .. } => assert_eq!(error.kind, ErrorKind::RuntimeIntegrityFailure),
        s => panic!("tampered Xray was accepted: {s:?}"),
    }
    assert!(h.core.diagnostics().xray_pid.is_none());
    let mut h = Harness::new(None);
    let id = h.core.import_profiles(&vless(w.server_port, "Local"), ImportKind::Text).unwrap().profile_ids[0].clone();
    match h.connect(&id) {
        SessionState::Failed { error, .. } => assert_eq!(error.kind, ErrorKind::RuntimeUnavailable),
        s => panic!("{s:?}"),
    }
}

#[test]
fn weakened_data_directory_blocks_the_session() {
    let w = require_world!();
    let mut h = Harness::new(Some(w.xray.clone()));
    let id = h.core.import_profiles(&vless(w.server_port, "Local"), ImportKind::Text).unwrap().profile_ids[0].clone();
    let data = PathBuf::from(h.core.diagnostics().data_dir);
    weaken(&data);
    match h.connect(&id) {
        SessionState::Failed { error, .. } => {
            assert_eq!(error.kind, ErrorKind::RuntimeIsolationFailure);
            assert!(error.message.starts_with("Runtime security check failed"), "{}", error.message);
        }
        s => panic!("session started with a weakened data directory: {s:?}"),
    }
    assert!(h.core.diagnostics().xray_pid.is_none());
}

#[test]
fn ide_credentials_are_redacted_in_debug_output() {
    let _ = require_world!();
    let mut h = Harness::new(xray_path());
    let c = h.core.ide_credentials(false).unwrap();
    assert!(c.password.len() >= 20);
    assert!(!format!("{c:?}").contains(&c.password));
    let n = h.core.ide_credentials(true).unwrap();
    assert_ne!(n.password, c.password, "regeneration replaces the password");
    assert!(!serde_json::to_string(&h.core.settings()).unwrap().contains(&n.password));
}

#[cfg(windows)]
fn kill(pid: u32) {
    let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).output();
}
#[cfg(unix)]
fn kill(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
}

#[cfg(windows)]
fn weaken(dir: &Path) {
    let icacls = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("icacls.exe");
    assert!(Command::new(icacls).arg(dir).args(["/grant", "*S-1-1-0:(R)"]).output().unwrap().status.success());
}
#[cfg(unix)]
fn weaken(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}
