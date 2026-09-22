//! EXPERIMENTAL test helpers shared by the Phase 7.5 validation binaries (not used by the product).
use ppcore::core::api::{Core, CoreMsg, ImportKind, Poster, SettingsUpdate, Timing};
use ppcore::core::secrets::FileKeyProvider;
use ppcore::core::session::SessionState;
use ppcore::core::store::Store;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

pub fn repo() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    PathBuf::from(p.display().to_string().trim_start_matches(r"\\?\").to_string())
}
pub fn sys32(exe: &str) -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32").join(exe)
}
pub fn xray() -> PathBuf {
    repo().join("native/xray/dist/windows-x64/xray.exe")
}
pub fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

/// HTTP target on 127.0.0.1 (reachable as `probe.test` only through the test server).
pub fn start_target() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nPOC-OK");
                let _ = s.shutdown(std::net::Shutdown::Write);
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    port
}

/// A controlled listener that counts what actually arrives (the ground truth for "blocked").
pub struct Listener {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

pub fn tcp_listener(bind: SocketAddr) -> std::io::Result<Listener> {
    let l = TcpListener::bind(bind)?;
    let addr = l.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    Ok(Listener { addr, hits })
}

pub fn udp_listener(bind: SocketAddr) -> std::io::Result<Listener> {
    let s = UdpSocket::bind(bind)?;
    let addr = s.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while s.recv_from(&mut buf).is_ok() {
            h.fetch_add(1, Ordering::SeqCst);
        }
    });
    Ok(Listener { addr, hits })
}

pub fn start_server() -> (std::process::Child, u16) {
    let port = free_port();
    let cfg = json!({
        "log": {"loglevel": "warning"},
        "dns": {"hosts": {"probe.test": "127.0.0.1"}},
        "inbounds": [{"listen":"127.0.0.1","port":port,"protocol":"vless","settings":{"clients":[{"id":UUID}],"decryption":"none"},"streamSettings":{"network":"raw"}}],
        "outbounds": [{"protocol":"freedom","settings":{"domainStrategy":"UseIP"}}]
    });
    let mut child = Command::new(xray()).args(["run", "-c", "stdin:", "-format", "json"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(cfg.to_string().as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "server xray did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, port)
}

/// The real Shared Core with one connected session (debug build + test hooks).
pub struct Session {
    pub core: Core,
    rx: Receiver<CoreMsg>,
}

impl Session {
    pub fn start(server_port: u16, data: &Path) -> Session {
        let store = Store::open(data.join("data"), Box::new(FileKeyProvider { path: data.join("test.key") })).unwrap();
        let (tx, rx) = channel::<CoreMsg>();
        let tx = Mutex::new(tx);
        let post: Poster = Arc::new(move |m| {
            let _ = tx.lock().unwrap().send(m);
        });
        let mut core = Core::new(store, Some(xray()), post, Timing::default());
        core.update_settings(SettingsUpdate { jetbrains_enabled: Some(false), ..Default::default() }).unwrap();
        core.start();
        let id = core.import_profiles(&format!("vless://{UUID}@127.0.0.1:{server_port}?type=tcp&security=none#PoC"), ImportKind::Text).unwrap().profile_ids[0].clone();
        core.start_session(&id).unwrap();
        let mut s = Session { core, rx };
        s.pump(Duration::from_secs(30), |c| matches!(c.session_status().state, SessionState::Connected { .. } | SessionState::Failed { .. }));
        assert!(matches!(s.core.session_status().state, SessionState::Connected { .. }), "{:?}", s.core.session_status().state);
        s
    }
    pub fn pump(&mut self, timeout: Duration, done: impl Fn(&Core) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let _ = self.core.take_events();
            if done(&self.core) {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(m) => self.core.handle(m),
                Err(_) => self.core.handle(CoreMsg::Tick),
            }
        }
    }
    pub fn endpoint(&self) -> crate::LocalEndpoint {
        let e = self.core.browser_proxy_endpoint().expect("connected");
        crate::LocalEndpoint { port: e.port, user: e.credentials.user.clone(), pass: e.credentials.pass.clone() }
    }
}

pub fn run_json(mut child: std::process::Child) -> Value {
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok();
    let _ = child.wait();
    serde_json::from_str(out.trim()).unwrap_or(json!({ "raw": out.trim() }))
}

pub fn plain(exe: &Path, args: &[&str]) -> Value {
    let c = Command::new(exe).args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    run_json(c)
}

pub fn with_env(exe: &Path, args: &[&str], env: &[(&str, String)]) -> Value {
    let mut c = Command::new(exe);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    run_json(c.spawn().unwrap())
}

pub fn powershell(script: &str) -> String {
    Command::new(sys32("WindowsPowerShell\\v1.0\\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Read-only system snapshot. `wfp` needs administrator rights (netsh wfp).
pub fn snapshot(elevated: bool) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("systemProxy".into(), powershell("Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL | Format-List | Out-String; netsh winhttp show proxy | Out-String"));
    m.insert("routes".into(), powershell("Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -notlike 'ff00*' } | Sort-Object DestinationPrefix,InterfaceIndex,NextHop | ForEach-Object { \"$($_.DestinationPrefix) $($_.NextHop) if$($_.InterfaceIndex) m$($_.RouteMetric)\" } | Out-String"));
    m.insert("dns".into(), powershell("Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | ForEach-Object { \"$($_.InterfaceAlias) $($_.AddressFamily) $($_.ServerAddresses -join ',')\" } | Out-String"));
    m.insert("adapters".into(), powershell("Get-NetAdapter -IncludeHidden | Sort-Object Name | ForEach-Object { \"$($_.Name) | $($_.InterfaceDescription) | $($_.Status)\" } | Out-String"));
    m.insert("firewallRules".into(), powershell("(Get-NetFirewallRule -ErrorAction SilentlyContinue | Measure-Object).Count"));
    m.insert("drivers".into(), powershell("driverquery /fo csv | Out-String"));
    m.insert("services".into(), powershell("Get-Service | Sort-Object Name | ForEach-Object Name | Out-String"));
    m.insert("wfpPocObjects".into(), if elevated { wfp_poc_objects() } else { "NOT AVAILABLE (needs administrator)".into() });
    m
}

/// Number of WFP filters/sublayers named "MProxy PoC" (dumped with netsh; administrator only).
pub fn wfp_poc_objects() -> String {
    let f = std::env::temp_dir().join(format!("poc-wfp-{}.xml", std::process::id()));
    let _ = Command::new(sys32("netsh.exe")).args(["wfp", "show", "filters", &format!("file={}", f.display())]).output();
    let text = std::fs::read(&f).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default();
    let _ = std::fs::remove_file(&f);
    if text.is_empty() {
        return "netsh wfp show filters produced no output".into();
    }
    format!("MProxy PoC filters: {}", text.matches("MProxy PoC").count())
}

pub fn diff_snapshots(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Value {
    let mut v = serde_json::Map::new();
    for (k, before) in a {
        let after = b.get(k).cloned().unwrap_or_default();
        if &after == before {
            v.insert(k.clone(), json!("unchanged"));
        } else {
            let bl: std::collections::BTreeSet<&str> = before.lines().collect();
            let al: std::collections::BTreeSet<&str> = after.lines().collect();
            v.insert(k.clone(), json!({ "removed": bl.difference(&al).take(10).collect::<Vec<_>>(), "added": al.difference(&bl).take(10).collect::<Vec<_>>() }));
        }
    }
    Value::Object(v)
}

pub fn is_elevated() -> bool {
    Command::new(sys32("net.exe")).arg("session").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}
