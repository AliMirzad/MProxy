//! End-to-end tests: native messaging client <-> helper binary <-> real Xray <-> local
//! Xray "remote server" <-> local HTTP target.
//!
//! The "remote server" is a second Xray process with one inbound per protocol/transport/
//! security combination. The probe target `probe.test` resolves only inside the server's
//! DNS config (`dns.hosts`), so a successful request proves that name resolution happened on
//! the server side (no local DNS for proxied traffic).
//!
//! Requires the pinned Xray binary: `node scripts/fetch-xray.mjs` (tests are skipped with a
//! message if it is missing).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EXT_ORIGIN_FILE: &str = include_str!("../../shared/extension-id.txt");
const TEST_UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn origin() -> String {
    format!("chrome-extension://{}/", EXT_ORIGIN_FILE.lines().next().unwrap().trim())
}

fn xray_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PRIVATE_PROXY_XRAY") {
        return Some(PathBuf::from(p));
    }
    let plat = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "windows-x64",
        ("windows", "aarch64") => "windows-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("macos", "aarch64") => "macos-arm64",
        _ => return None,
    };
    let exe = if cfg!(windows) { "xray.exe" } else { "xray" };
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("xray/dist").join(plat).join(exe);
    p.is_file().then_some(p)
}

macro_rules! require_xray {
    () => {
        match xray_path() {
            Some(p) => p,
            None => {
                eprintln!("SKIPPED: Xray binary not found; run `node scripts/fetch-xray.mjs`");
                return;
            }
        }
    };
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------- local HTTP target

struct Target {
    port: u16,
    hits: Arc<Mutex<u32>>,
}

fn start_target() -> Target {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let h = h.clone();
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
                *h.lock().unwrap() += 1;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            });
        }
    });
    Target { port, hits }
}

// ---------------------------------------------------------------- remote server (Xray)

struct Keys {
    reality_private: String,
    reality_public: String,
    cert_dir: PathBuf,
    cert_hash: String,
}

fn gen_keys(xray: &Path, dir: &Path) -> Keys {
    let out = Command::new(xray).arg("x25519").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |prefix: &str| s.lines().find(|l| l.starts_with(prefix)).and_then(|l| l.split(':').nth(1)).unwrap().trim().to_string();
    let reality_private = field("PrivateKey");
    let reality_public = field("Password");
    let st = Command::new(xray).current_dir(dir).args(["tls", "cert", "--domain=tls.test", "--name=tls.test", "--file=srv"]).output().unwrap();
    assert!(st.status.success());
    let h = Command::new(xray).current_dir(dir).args(["tls", "hash", "--cert", "srv.crt"]).output().unwrap();
    let hs = String::from_utf8_lossy(&h.stdout);
    let cert_hash = hs.split(':').nth(1).unwrap().trim().to_string();
    Keys { reality_private, reality_public, cert_dir: dir.to_path_buf(), cert_hash }
}

struct Ports {
    raw: u16,
    ws: u16,
    grpc: u16,
    httpupgrade: u16,
    xhttp: u16,
    vmess_ws: u16,
    vmess_raw: u16,
    tls_ws: u16,
    reality: u16,
    reality_target: u16,
}

struct ServerXray {
    child: Child,
    ports: Ports,
}

impl Drop for ServerXray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(xray: &Path, k: &Keys) -> ServerXray {
    let p = Ports {
        raw: free_port(),
        ws: free_port(),
        grpc: free_port(),
        httpupgrade: free_port(),
        xhttp: free_port(),
        vmess_ws: free_port(),
        vmess_raw: free_port(),
        tls_ws: free_port(),
        reality: free_port(),
        reality_target: free_port(),
    };
    let vless = |port: u16, stream: Value| json!({"listen":"127.0.0.1","port":port,"protocol":"vless","settings":{"clients":[{"id":TEST_UUID}],"decryption":"none"},"streamSettings":stream});
    let vmess = |port: u16, stream: Value| json!({"listen":"127.0.0.1","port":port,"protocol":"vmess","settings":{"clients":[{"id":TEST_UUID}]},"streamSettings":stream});
    let crt = k.cert_dir.join("srv.crt").display().to_string();
    let key = k.cert_dir.join("srv.key").display().to_string();
    let cfg = json!({
        "log": {"loglevel": "warning"},
        "dns": {"hosts": {"probe.test": "127.0.0.1"}},
        "inbounds": [
            vless(p.raw, json!({"network":"raw"})),
            vless(p.ws, json!({"network":"ws","wsSettings":{"path":"/ws"}})),
            vless(p.grpc, json!({"network":"grpc","grpcSettings":{"serviceName":"svc"}})),
            vless(p.httpupgrade, json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/up"}})),
            vless(p.xhttp, json!({"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"}})),
            vmess(p.vmess_ws, json!({"network":"ws","wsSettings":{"path":"/vm"}})),
            vmess(p.vmess_raw, json!({"network":"raw"})),
            vless(p.tls_ws, json!({"network":"ws","wsSettings":{"path":"/tws"},"security":"tls",
                "tlsSettings":{"certificates":[{"certificateFile":crt,"keyFile":key}]}})),
            // REALITY target: a local TLS 1.3 server (Xray TLS inbound with h2).
            {"listen":"127.0.0.1","port":p.reality_target,"protocol":"vless","settings":{"clients":[{"id":"00000000-0000-0000-0000-000000000001"}],"decryption":"none"},
             "streamSettings":{"network":"raw","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"certificates":[{"certificateFile":crt,"keyFile":key}]}}},
            {"listen":"127.0.0.1","port":p.reality,"protocol":"vless",
             "settings":{"clients":[{"id":TEST_UUID,"flow":"xtls-rprx-vision"}],"decryption":"none"},
             "streamSettings":{"network":"raw","security":"reality","realitySettings":{
                "target": format!("127.0.0.1:{}", p.reality_target), "serverNames":["tls.test"],
                "privateKey": k.reality_private, "shortIds":["", "ab12"]}}}
        ],
        "outbounds": [{"protocol":"freedom","settings":{"domainStrategy":"UseIP"}}]
    });
    let mut child = Command::new(xray)
        .args(["run", "-c", "stdin:", "-format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(cfg.to_string().as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", p.reality)).is_err() {
        assert!(Instant::now() < deadline, "server xray did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    ServerXray { child, ports: p }
}

// ---------------------------------------------------------------- native messaging client

struct Host {
    child: Child,
    rx: Receiver<Value>,
    next_id: u32,
    events: Vec<Value>,
    _data: tempfile::TempDir,
}

struct HostOpts {
    xray: Option<PathBuf>,
    probe_port: u16,
    jb_socks: u16,
    jb_http: u16,
    /// Test servers listen on 127.0.0.1; release builds refuse loopback destinations.
    allow_loopback: bool,
    extra_env: Vec<(&'static str, &'static str)>,
}

impl Host {
    fn start(o: &HostOpts) -> Host {
        let data = tempfile::tempdir().unwrap();
        // Pre-seed settings with test-specific JetBrains ports (never touch the real 10808/10809).
        std::fs::write(
            data.path().join("state.json"),
            json!({"version":1,"settings":{"jetbrainsEnabled":true,"jetbrainsSocksPort":o.jb_socks,"jetbrainsHttpPort":o.jb_http,"passthroughWhenDisconnected":true,"debugLogging":true,"ideAuth":false}}).to_string(),
        )
        .unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_private-proxy-host"));
        cmd.arg(origin())
            .env("PRIVATE_PROXY_TEST_MODE", "1")
            .env("PRIVATE_PROXY_ALLOW_LOOPBACK", if o.allow_loopback { "1" } else { "0" })
            .env("PRIVATE_PROXY_DATA_DIR", data.path())
            .env("PRIVATE_PROXY_INSECURE_FILE_KEY", "1")
            .env("PRIVATE_PROXY_PROBE_URL", format!("probe.test:{}/generate_204", o.probe_port))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in &o.extra_env {
            cmd.env(k, v);
        }
        match &o.xray {
            Some(x) => cmd.env("PRIVATE_PROXY_XRAY", x),
            None => cmd.env("PRIVATE_PROXY_XRAY", data.path().join("does-not-exist")),
        };
        let mut child = cmd.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || loop {
            let mut len = [0u8; 4];
            if stdout.read_exact(&mut len).is_err() {
                break;
            }
            let mut buf = vec![0u8; u32::from_ne_bytes(len) as usize];
            if stdout.read_exact(&mut buf).is_err() {
                break;
            }
            if tx.send(serde_json::from_slice::<Value>(&buf).unwrap()).is_err() {
                break;
            }
        });
        Host { child, rx, next_id: 1, events: vec![], _data: data }
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(&(bytes.len() as u32).to_ne_bytes()).unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, cmd: &str, args: Value) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"id": id, "cmd": cmd, "args": args});
        self.send_raw(msg.to_string().as_bytes());
        id
    }

    fn wait_response(&mut self, id: u32, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let m = self.rx.recv_timeout(left).unwrap_or_else(|_| panic!("no response to {id}"));
            if m.get("id").and_then(Value::as_u64) == Some(id as u64) {
                return m;
            }
            self.events.push(m);
        }
    }

    fn req(&mut self, cmd: &str, args: Value) -> Value {
        let id = self.send(cmd, args);
        self.wait_response(id, Duration::from_secs(30))
    }

    fn ok(&mut self, cmd: &str, args: Value) -> Value {
        let r = self.req(cmd, args.clone());
        assert_eq!(r["ok"], true, "{cmd} {args} -> {r}");
        r["result"].clone()
    }

    /// Waits for a status (from events or polling) satisfying `pred`.
    fn wait_status(&mut self, what: &str, timeout: Duration, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            for e in std::mem::take(&mut self.events) {
                if e["event"] == "status" && pred(&e["status"]) {
                    return e["status"].clone();
                }
            }
            let st = self.ok("getStatus", json!({}));
            if pred(&st) {
                return st;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}; last status {st}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn connect_and_wait(&mut self, server_id: &str) -> Value {
        self.events.clear();
        self.ok("connect", json!({"serverId": server_id}));
        let sid = server_id.to_string();
        self.wait_status("connected or error", Duration::from_secs(30), move |s| {
            s["serverId"] == sid.as_str() && (s["state"] == "connected" || s["state"] == "error")
        })
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self._data.path().join("logs").join("helper.log")).unwrap_or_default()
    }

    fn close(mut self) -> std::process::ExitStatus {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < deadline, "helper did not exit after stdin closed");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------- client-side traffic helpers

/// HTTP GET through a SOCKS5 proxy, sending the hostname unresolved (like Chromium).
/// The browser path: the authenticated HTTP proxy inbound with the per-connection credentials
/// from the status (hostname sent unresolved, so DNS happens on the server).
fn via_browser(st: &Value, host: &str, target_port: u16) -> Result<String, String> {
    let port = st["proxy"]["port"].as_u64().ok_or("no proxy in status")? as u16;
    assert_eq!(st["proxy"]["scheme"], "http", "{st}");
    let (u, p) = (st["proxy"]["username"].as_str().unwrap(), st["proxy"]["password"].as_str().unwrap());
    http_proxy_with_auth(port, host, target_port, Some((u, p)))
}

/// Whether `port` accepts a SOCKS5 no-auth greeting (answers 05 00) within 2 s.
fn socks_greeting_accepted(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return false };
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if s.write_all(&[5, 1, 0]).is_err() {
        return false;
    }
    let mut r = [0u8; 2];
    s.read_exact(&mut r).is_ok() && r == [5, 0]
}

fn get_via_socks(port: u16, host: &str, target_port: u16) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).map_err(|e| e.to_string())?;
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).map_err(|e| e.to_string())?;
    let mut head = [0u8; 10];
    s.read_exact(&mut head).map_err(|e| e.to_string())?;
    if head[1] != 0 {
        return Err(format!("socks error {}", head[1]));
    }
    s.write_all(format!("GET /x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

/// HTTP GET through an HTTP proxy (absolute-form request), like an IDE configured with an HTTP proxy.
fn get_via_http_proxy(port: u16, host: &str, target_port: u16) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(format!("GET http://{host}:{target_port}/x HTTP/1.1\r\nHost: {host}:{target_port}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), Duration::from_millis(300)).is_ok()
}

fn kill_pid(pid: u64) {
    if cfg!(windows) {
        let _ = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).output();
    } else {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
    }
}

struct Env {
    xray: PathBuf,
    target: Target,
    server: ServerXray,
    keys: Keys,
    _tmp: tempfile::TempDir,
}

fn env() -> Option<Env> {
    let xray = xray_path()?;
    let tmp = tempfile::tempdir().unwrap();
    let keys = gen_keys(&xray, tmp.path());
    let target = start_target();
    let server = start_server(&xray, &keys);
    Some(Env { xray, target, server, keys, _tmp: tmp })
}

fn links(e: &Env) -> Vec<(&'static str, String)> {
    let p = &e.server.ports;
    let vm = |port: u16, net: &str, path: &str| {
        let j = json!({"v":"2","ps":format!("VMess {net}"),"add":"127.0.0.1","port":port.to_string(),"id":TEST_UUID,"aid":"0","scy":"auto","net":net,"type":"none","host":"","path":path,"tls":""});
        use base64::Engine;
        format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j.to_string()))
    };
    vec![
        ("vless-raw", format!("vless://{TEST_UUID}@127.0.0.1:{}?type=tcp&security=none#VLESS%20raw", p.raw)),
        ("vless-ws", format!("vless://{TEST_UUID}@127.0.0.1:{}?type=ws&path=%2Fws&security=none#VLESS%20ws", p.ws)),
        ("vless-grpc", format!("vless://{TEST_UUID}@127.0.0.1:{}?type=grpc&serviceName=svc&security=none#VLESS%20grpc", p.grpc)),
        ("vless-httpupgrade", format!("vless://{TEST_UUID}@127.0.0.1:{}?type=httpupgrade&path=%2Fup&security=none#VLESS%20hu", p.httpupgrade)),
        ("vless-xhttp", format!("vless://{TEST_UUID}@127.0.0.1:{}?type=xhttp&path=%2Fxh&mode=auto&security=none#VLESS%20xhttp", p.xhttp)),
        ("vmess-ws", vm(p.vmess_ws, "ws", "/vm")),
        ("vmess-raw", vm(p.vmess_raw, "tcp", "")),
        (
            "vless-ws-tls-pinned",
            format!("vless://{TEST_UUID}@127.0.0.1:{}?type=ws&path=%2Ftws&security=tls&sni=tls.test&fp=chrome&pcs={}#TLS%20pinned", p.tls_ws, e.keys.cert_hash),
        ),
        (
            "vless-reality-vision",
            format!(
                "vless://{TEST_UUID}@127.0.0.1:{}?type=tcp&security=reality&sni=tls.test&fp=chrome&pbk={}&sid=ab12&flow=xtls-rprx-vision#REALITY",
                p.reality, e.keys.reality_public
            ),
        ),
    ]
}

fn opts(e: &Env) -> HostOpts {
    HostOpts { xray: Some(e.xray.clone()), probe_port: e.target.port, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] }
}

// ================================================================ tests

#[test]
fn all_transports_end_to_end() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    let hello = h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    assert_eq!(hello["protocolVersion"], 3);
    assert_eq!(hello["xrayAvailable"], true);
    assert!(hello["xrayVersion"].as_str().unwrap().starts_with("26."));

    let all: Vec<String> = links(&e).into_iter().map(|(_, l)| l).collect();
    let imp = h.ok("importText", json!({"text": all.join("\n"), "source": "paste"}));
    assert_eq!(imp["added"], all.len(), "{imp}");
    let list = h.ok("listServers", json!({}));
    let servers = list["servers"].as_array().unwrap().clone();
    assert_eq!(servers.len(), all.len());
    // The extension never receives credentials.
    assert!(!list.to_string().contains(TEST_UUID));
    assert!(!list.to_string().contains(&e.keys.reality_public));

    for (i, (label, _)) in links(&e).iter().enumerate() {
        let id = servers[i]["id"].as_str().unwrap().to_string();
        let st = h.connect_and_wait(&id);
        assert_eq!(st["state"], "connected", "{label}: {st}");
        let port = st["proxy"]["port"].as_u64().unwrap() as u16;
        let before = *e.target.hits.lock().unwrap();
        // Browser path (authenticated HTTP proxy, remote DNS: probe.test only resolves on the server).
        let r = via_browser(&st, "probe.test", e.target.port);
        // Without the per-connection credentials the browser port is useless to other processes.
        assert!(http_proxy_with_auth(port, "probe.test", e.target.port, None).unwrap_or_default().contains("407"), "{label}: browser port open without credentials");
        assert!(!socks_greeting_accepted(port), "{label}: browser port usable as unauthenticated SOCKS");
        if r.is_err() {
            eprintln!("status={st}
log:
{}", h.log());
        }
        assert_eq!(r.unwrap(), "HTTP/1.1 204 No Content", "{label}");
        // JetBrains paths.
        assert_eq!(get_via_http_proxy(o.jb_http, "probe.test", e.target.port).unwrap_or_else(|x| format!("{x} status={st}")), "HTTP/1.1 204 No Content", "{label} http");
        assert_eq!(get_via_socks(o.jb_socks, "probe.test", e.target.port).unwrap(), "HTTP/1.1 204 No Content", "{label} socks");
        assert!(*e.target.hits.lock().unwrap() >= before + 3);
        assert_eq!(st["jetbrains"]["mode"], "tunnel");
        eprintln!("ok: {label}");
    }

    // Disconnect: browser port goes away; JetBrains endpoint stays up in direct mode.
    let st = h.wait_status("connected", Duration::from_secs(5), |s| s["state"] == "connected");
    let port = st["proxy"]["port"].as_u64().unwrap() as u16;
    h.ok("disconnect", json!({}));
    let st = h.wait_status("disconnected", Duration::from_secs(10), |s| s["state"] == "disconnected");
    assert!(st.get("proxy").is_none());
    assert!(!port_open(port), "browser proxy port must be closed after disconnect");
    assert_eq!(st["jetbrains"]["mode"], "direct");
    // Requests aimed at our own inbound are refused instead of looping.
    let t0 = Instant::now();
    let r = get_via_http_proxy(o.jb_http, "127.0.0.1", o.jb_http);
    assert!(r.map(|l| !l.contains("200")).unwrap_or(true));
    assert!(t0.elapsed() < Duration::from_secs(5), "self-loop must fail fast");
    assert!(port_open(o.jb_http), "endpoint survives a self-loop attempt");
    // Direct passthrough: an IP literal target works, and no tunnel is involved.
    assert_eq!(get_via_http_proxy(o.jb_http, "127.0.0.1", e.target.port).unwrap(), "HTTP/1.1 204 No Content");
    // probe.test is only resolvable on the server, so in direct mode it must fail: proves the tunnel is really off.
    let r = get_via_http_proxy(o.jb_http, "probe.test", e.target.port);
    assert!(r.map(|l| !l.contains("204")).unwrap_or(true));

    let st = h.close();
    assert!(st.success());
    assert!(!port_open(o.jb_http), "no orphaned Xray after the browser closes the port");
    assert!(!port_open(o.jb_socks));
}

#[test]
fn failures_and_idempotency() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));

    // Incompatible protocol version.
    let r = h.req("hello", json!({"protocolVersion": 99, "extensionVersion": "x"}));
    assert_eq!(r["error"]["code"], "INCOMPATIBLE_VERSION");

    // Malformed messages never crash the helper.
    h.send_raw(b"this is not json");
    h.send_raw(br#"{"id":77,"cmd":"exec","args":{"command":"calc.exe"}}"#);
    let r = h.wait_response(77, Duration::from_secs(5));
    assert_eq!(r["error"]["code"], "INVALID_REQUEST");
    let r = h.req("connect", json!({"serverId": "../../etc/passwd"}));
    assert_eq!(r["error"]["code"], "INVALID_REQUEST");
    let r = h.req("connect", json!({"serverId": "00000000-0000-4000-8000-000000000000"}));
    assert_eq!(r["error"]["code"], "NOT_FOUND");

    // Invalid imports.
    let r = h.req("importText", json!({"text": "https://example.com", "source": "qr"}));
    assert_eq!(r["error"]["code"], "INVALID_CONFIG");
    let r = h.req("importText", json!({"text": "vless://garbage", "source": "paste"}));
    assert_eq!(r["error"]["code"], "INVALID_CONFIG");

    let p = &e.server.ports;
    let good = format!("vless://{TEST_UUID}@127.0.0.1:{}?type=ws&path=%2Fws&security=none#Good", p.ws);
    let bad_uuid = format!("vless://11111111-2222-4333-8444-555555555555@127.0.0.1:{}?type=ws&path=%2Fws&security=none#WrongUser", p.ws);
    let dead = format!("vless://{TEST_UUID}@127.0.0.1:{}?type=tcp&security=none#Dead", free_port());
    let imp = h.ok("importText", json!({"text": format!("{good}\n{bad_uuid}\n{dead}"), "source": "paste"}));
    let ids: Vec<String> = imp["serverIds"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();

    // Wrong credentials / dead server -> SERVER_UNREACHABLE, and nothing left listening.
    for id in &ids[1..] {
        let st = h.connect_and_wait(id);
        assert_eq!(st["state"], "error", "{st}");
        assert_eq!(st["error"]["code"], "SERVER_UNREACHABLE");
        assert_eq!(st["jetbrains"]["mode"], "direct", "passthrough restored after failure: {st}");
    }

    // Repeated Connect clicks: idempotent, single instance.
    h.events.clear();
    let a = h.send("connect", json!({"serverId": ids[0]}));
    let b = h.send("connect", json!({"serverId": ids[0]}));
    let c = h.send("connect", json!({"serverId": ids[0]}));
    for id in [a, b, c] {
        assert_eq!(h.wait_response(id, Duration::from_secs(30))["ok"], true);
    }
    let id0 = ids[0].clone();
    let st = h.wait_status("connected", Duration::from_secs(30), move |s| s["serverId"] == id0.as_str() && (s["state"] == "connected" || s["state"] == "error"));
    assert_eq!(st["state"], "connected", "{st}");
    let pid_a = h.ok("getDiagnostics", json!({}))["xrayPid"].as_u64();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(h.ok("getDiagnostics", json!({}))["xrayPid"].as_u64(), pid_a, "repeated clicks must not restart Xray");

    // Occupied JetBrains port is reported, the browser tunnel still works.
    // (Reconnect with the HTTP port taken by someone else.)
    h.ok("disconnect", json!({}));
    h.wait_status("disconnected", Duration::from_secs(10), |s| s["state"] == "disconnected");
    h.ok("setSettings", json!({"passthroughWhenDisconnected": false}));
    let blocker = TcpListener::bind(("127.0.0.1", o.jb_http)).unwrap();
    let st = h.connect_and_wait(&ids[0]);
    assert_eq!(st["state"], "connected", "{st}");
    assert!(st["jetbrains"]["issue"].as_str().unwrap().contains(&o.jb_http.to_string()), "{st}");
    assert_eq!(st["jetbrains"]["socksPort"], o.jb_socks);
    assert!(st["jetbrains"]["httpPort"].is_null());
    drop(blocker);

    // Xray crash -> automatic restart on the same port.
    let port = st["proxy"]["port"].as_u64().unwrap() as u16;
    let pid = h.ok("getDiagnostics", json!({}))["xrayPid"].as_u64().unwrap();
    kill_pid(pid);
    let deadline = Instant::now() + Duration::from_secs(20);
    let pid2 = loop {
        let d = h.ok("getDiagnostics", json!({}));
        let st = h.ok("getStatus", json!({}));
        if let Some(p2) = d["xrayPid"].as_u64() {
            if p2 != pid && st["state"] == "connected" {
                assert_eq!(st["proxy"]["port"], port, "restart keeps the browser port");
                break p2;
            }
        }
        assert!(Instant::now() < deadline, "Xray was not restarted: {st}");
        std::thread::sleep(Duration::from_millis(200));
    };
    let st = h.ok("getStatus", json!({}));
    assert_ne!(pid, pid2);
    assert_eq!(via_browser(&st, "probe.test", e.target.port).unwrap(), "HTTP/1.1 204 No Content", "credentials survive the restart");
    let _ = st;

    // Repeated crashes -> XRAY_FAILED; status says error so the extension clears the browser proxy.
    for _ in 0..3 {
        if let Some(pid) = h.ok("getDiagnostics", json!({}))["xrayPid"].as_u64() {
            kill_pid(pid);
        }
        std::thread::sleep(Duration::from_millis(1500));
    }
    let st = h.wait_status("xray failed", Duration::from_secs(20), |s| s["state"] == "error");
    assert_eq!(st["error"]["code"], "XRAY_FAILED", "{st}");
    assert!(!port_open(port));

    // Repeated Disconnect clicks are harmless.
    for _ in 0..3 {
        let st = h.ok("disconnect", json!({}));
        assert_eq!(st["state"], "disconnected");
    }

    // Browser closes the port during startup: helper exits, no Xray left behind.
    h.ok("setSettings", json!({"passthroughWhenDisconnected": true}));
    h.send("connect", json!({"serverId": ids[0]}));
    let st = h.close();
    assert!(st.success());
    std::thread::sleep(Duration::from_millis(500));
    assert!(!port_open(o.jb_http) && !port_open(o.jb_socks), "orphaned Xray after close during startup");
}

#[test]
fn xray_missing_is_reported() {
    let o = HostOpts { xray: None, probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    let hello = h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    assert_eq!(hello["xrayAvailable"], false);
    let imp = h.ok("importText", json!({"text": format!("vless://{TEST_UUID}@example.com:443?security=tls#x"), "source": "paste"}));
    let id = imp["serverIds"][0].as_str().unwrap().to_string();
    let st = h.connect_and_wait(&id);
    assert_eq!(st["error"]["code"], "XRAY_MISSING", "{st}");
}

#[test]
fn rejected_by_xray_validation() {
    let _ = require_xray!();
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    // Structurally valid for our parser but rejected by Xray's own validation (-test):
    // a VLESS Encryption string with a bogus key.
    let link = format!("vless://{TEST_UUID}@example.com:443?security=none&encryption=mlkem768x25519plus.native.0rtt.AAAA#x");
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let id = imp["serverIds"][0].as_str().unwrap().to_string();
    let st = h.connect_and_wait(&id);
    assert_eq!(st["error"]["code"], "XRAY_CONFIG_REJECTED", "{st}");
}

#[test]
fn subscriptions_add_update_fail() {
    let _ = require_xray!();
    use base64::Engine;
    let body = Arc::new(Mutex::new(String::new()));
    let status = Arc::new(Mutex::new(200u16));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = l.local_addr().unwrap().port();
    let (b2, s2) = (body.clone(), status.clone());
    let ua_seen = Arc::new(Mutex::new(String::new()));
    let ua2 = ua_seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            if let Some(ua) = req.lines().find(|l| l.to_ascii_lowercase().starts_with("user-agent:")) {
                *ua2.lock().unwrap() = ua.to_string();
            }
            let b = b2.lock().unwrap().clone();
            let code = *s2.lock().unwrap();
            let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).as_bytes());
        }
    });
    let l1 = format!("vless://{TEST_UUID}@a.example.com:443?security=tls#A");
    let l2 = format!("vless://{TEST_UUID}@b.example.com:443?security=tls#B");
    let l3 = format!("vless://{TEST_UUID}@c.example.com:443?security=tls#C");
    *body.lock().unwrap() = base64::engine::general_purpose::STANDARD.encode(format!("{l1}\n{l2}\nss://x@y:1#ss\nvless://bad"));

    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    let url = format!("http://127.0.0.1:{sport}/sub?token=SECRET123");
    let r = h.ok("addSubscription", json!({"name": "Work", "url": url}));
    assert_eq!((r["added"].as_u64(), r["rejected"].as_u64(), r["unsupported"].as_u64()), (Some(2), Some(1), Some(1)), "{r}");
    assert!(ua_seen.lock().unwrap().contains("PrivateProxy/"));
    let sub_id = r["subscriptionId"].as_str().unwrap().to_string();
    let list = h.ok("listServers", json!({}));
    assert!(!list.to_string().contains("SECRET123"), "subscription URL must not be exposed");
    assert_eq!(list["subscriptions"][0]["serverCount"], 2);

    *body.lock().unwrap() = format!("{l2}\n{l3}\n");
    let r = h.ok("updateSubscription", json!({"id": sub_id}));
    assert_eq!((r["added"].as_u64(), r["updated"].as_u64(), r["removed"].as_u64()), (Some(1), Some(1), Some(1)), "{r}");

    // Provider failure keeps existing servers and records the error.
    *status.lock().unwrap() = 500;
    let r = h.req("updateSubscription", json!({"id": sub_id}));
    assert_eq!(r["error"]["code"], "SUBSCRIPTION_FAILED");
    let list = h.ok("listServers", json!({}));
    assert_eq!(list["servers"].as_array().unwrap().len(), 2);
    assert!(list["subscriptions"][0]["lastError"].as_str().unwrap().contains("500"));

    // HTML login page instead of a subscription.
    *status.lock().unwrap() = 200;
    *body.lock().unwrap() = "<html>login</html>".into();
    let r = h.req("updateSubscription", json!({"id": sub_id}));
    assert_eq!(r["error"]["code"], "SUBSCRIPTION_FAILED");

    // Non-HTTPS remote URL rejected before any network access.
    let r = h.req("addSubscription", json!({"name": "x", "url": "http://sub.example.com/x"}));
    assert_eq!(r["error"]["code"], "INVALID_CONFIG");

    // Delete subscription together with its servers.
    h.ok("deleteSubscription", json!({"id": sub_id, "deleteServers": true}));
    assert_eq!(h.ok("listServers", json!({}))["servers"].as_array().unwrap().len(), 0);
}

// ================================================================ security (host-compromise prevention)
//
// These tests exercise the real helper binary, the real (restricted) Xray process and the OS
// mechanisms themselves. They are the evidence referenced by docs/security-gate.md.

/// Listening sockets of `pid` as (protocol, local address).
fn listeners_of(pid: u32) -> Vec<(String, String)> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        let netstat = PathBuf::from(std::env::var("SystemRoot").unwrap_or("C:\\Windows".into())).join("System32").join("NETSTAT.EXE");
        for proto in ["TCP", "TCPv6", "UDP", "UDPv6"] {
            let o = Command::new(&netstat).args(["-ano", "-p", proto]).output().unwrap();
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                let is_udp = proto.starts_with("UDP");
                let (ok, owner) = if is_udp { (f.len() == 4, f.get(3)) } else { (f.len() == 5 && f[3] == "LISTENING", f.get(4)) };
                if ok && owner.and_then(|p| p.parse::<u32>().ok()) == Some(pid) {
                    out.push((proto.to_string(), f[1].to_string()));
                }
            }
        }
    }
    #[cfg(unix)]
    {
        for (flag, proto) in [("-iTCP", "TCP"), ("-iUDP", "UDP")] {
            let mut c = Command::new("lsof");
            c.args(["-nP", "-a", "-p", &pid.to_string(), flag]);
            if proto == "TCP" {
                c.arg("-sTCP:LISTEN");
            }
            if let Ok(o) = c.output() {
                for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                    if let Some(addr) = line.split_whitespace().nth(8) {
                        out.push((proto.to_string(), addr.to_string()));
                    }
                }
            }
        }
    }
    out
}

#[test]
fn xray_isolation_and_listeners() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    let (_, link) = links(&e).pop().unwrap(); // REALITY + Vision
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let id = imp["serverIds"][0].as_str().unwrap().to_string();
    let st = h.connect_and_wait(&id);
    assert_eq!(st["state"], "connected", "{st}");
    let browser_port = st["proxy"]["port"].as_u64().unwrap() as u16;
    let d = h.ok("getDiagnostics", json!({}));
    assert_eq!(d["xrayVerified"], true, "{d}");
    assert_eq!(d["xrayPinnedSha256"].as_str().unwrap().len(), 64);
    let xray_pid = d["xrayPid"].as_u64().unwrap() as u32;

    // Every listener belongs to Xray, is on 127.0.0.1, and is one of the three expected ports.
    let xl = listeners_of(xray_pid);
    eprintln!("xray listeners: {xl:?}");
    let expected: Vec<String> = [browser_port, o.jb_socks, o.jb_http].iter().map(|p| format!("127.0.0.1:{p}")).collect();
    assert_eq!(xl.len(), 3, "unexpected listeners: {xl:?}");
    for (proto, addr) in &xl {
        assert!(proto.starts_with("TCP"), "{proto} {addr}");
        assert!(expected.contains(addr), "unexpected listener {proto} {addr}");
    }
    let helper_pid = h.child.id();
    assert!(listeners_of(helper_pid).is_empty(), "the helper must not listen on any socket");

    #[cfg(windows)]
    {
        use ppcore::winproc::{ChildProc, Restrictions, Stdio as PStdio};
        // The OS reports Xray at Low integrity with the creation-time policies in force.
        let iso = &d["xrayIsolation"];
        assert_eq!(iso["integrity"], "low", "{d}");
        assert_eq!(iso["childProcessesBlocked"], true, "{d}");
        assert_eq!(iso["extensionPointsDisabled"], true, "{d}");
        assert_eq!(iso["remoteImagesBlocked"], true, "{d}");
        assert_eq!(iso["userSidDenyOnly"], true, "{d}");
        assert!(iso["privileges"].as_u64().unwrap() <= 1, "only SeChangeNotifyPrivilege may remain: {d}");
        assert_eq!(iso["inJob"], true, "{d}");
        assert_eq!(iso["mitigationsApplied"], true, "{d}");
        // The data directory is private and carries the no-read-up label.
        let prot = d["dataDirProtection"].as_str().unwrap();
        assert!(prot.starts_with("D:P") && !prot.contains(";;;WD)") && !prot.contains(";;;BU)") && !prot.contains(";;;AU)"), "{prot}");
        assert!(prot.contains("(ML;") && prot.contains("NR"), "{prot}");

        // What a compromised Xray could do at Low integrity, demonstrated with cmd.exe under the
        // same token: it can neither read the stored credentials nor write into the user profile.
        let data_dir = PathBuf::from(d["dataDir"].as_str().unwrap());
        let secrets = data_dir.join("secrets.bin");
        assert!(secrets.is_file());
        let cmd = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        let run = |r: Restrictions, args: &[&str]| -> (u32, usize) {
            let mut c = ChildProc::spawn_with(&cmd, args, &data_dir, PStdio { stdin: false, stdout: true, stderr: true }, r).unwrap();
            let mut out = Vec::new();
            let _ = c.stdout.take().unwrap().read_to_end(&mut out);
            (c.wait().unwrap(), out.len())
        };
        let low = Restrictions { low_integrity: true, ..Restrictions::NONE };
        let medium = Restrictions { low_integrity: false, ..low };
        let target = secrets.to_string_lossy().to_string();
        let (code_med, bytes_med) = run(medium, &["/C", "type", &target]);
        assert!(code_med == 0 && bytes_med > 0, "control: Medium integrity can read it");
        let (code_low, bytes_low) = run(low, &["/C", "type", &target]);
        assert!(code_low != 0 && bytes_low == 0, "Low integrity read the secrets file (exit {code_low}, {bytes_low} bytes)");
        let probe = PathBuf::from(std::env::var("USERPROFILE").unwrap()).join(format!("pp-lowil-probe-{}.txt", std::process::id()));
        let _ = run(low, &["/C", &format!("echo x> \"{}\"", probe.display())]);
        let created = probe.exists();
        let _ = std::fs::remove_file(&probe);
        assert!(!created, "Low integrity could write into the user profile");
    }
}

#[test]
fn hostile_native_messages() {
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    // No generic OS operations exist.
    for cmd in ["exec", "executeCommand", "runProcess", "openFile", "writeFile", "downloadAndExecute", "installPackage", "runScript", "shell", "powershell", "cmd", "bash", "setXrayArgs", "setEnv"] {
        let r = h.req(cmd, json!({"command": "calc.exe", "path": "C:\\Windows\\System32\\calc.exe", "args": ["-c", "id"]}));
        assert_eq!(r["error"]["code"], "INVALID_REQUEST", "{cmd}: {r}");
    }
    // Paths, traversal and metacharacters in ids are rejected before any lookup.
    for id in ["..\\..\\Windows\\System32", "../../etc/passwd", "C:\\x", "\\\\host\\share", "file:///etc/passwd", "$(id)", "a;b"] {
        for cmd in ["deleteServer", "selectServer", "updateSubscription"] {
            let r = h.req(cmd, json!({"id": id}));
            assert_eq!(r["error"]["code"], "INVALID_REQUEST", "{cmd} {id}: {r}");
        }
    }
    // Extra fields that would steer the helper are refused, not ignored.
    for (cmd, args) in [
        ("setSettings", json!({"xrayPath": "C:\\evil.exe"})),
        ("setSettings", json!({"dataDir": "C:\\Users\\Public"})),
        ("connect", json!({"serverId": TEST_UUID, "xrayArgs": ["-c", "http://evil/config"]})),
        ("importText", json!({"text": "x", "source": "paste", "path": "C:\\secrets.txt"})),
        ("importText", json!({"text": "x", "source": "url"})),
    ] {
        let r = h.req(cmd, args.clone());
        assert_eq!(r["error"]["code"], "INVALID_REQUEST", "{cmd} {args}: {r}");
    }
    // Malformed frames: not JSON / not an object / no id -> protocolError event, helper keeps running.
    h.send_raw(b"\xff\xfe not json");
    h.send_raw(b"[1,2,3]");
    h.send_raw(br#"{"cmd":"getStatus"}"#);
    assert_eq!(h.ok("getStatus", json!({}))["state"], "disconnected");

    // Metadata APIs never return credentials.
    let pbk = "IYmFOdB-5LkWj4xG_qNnekepkVTEG_VLr2PbHV9zT0o";
    let name = "$(calc) `id` | & > %COMSPEC% ..\\..\\";
    let enc: String = name.bytes().map(|b| format!("%{b:02X}")).collect();
    let link = format!("vless://{TEST_UUID}@srv.example.com:443?type=tcp&security=reality&sni=www.example.com&pbk={pbk}&sid=ab12#{enc}");
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let id = imp["serverIds"][0].as_str().unwrap().to_string();
    let list = h.ok("listServers", json!({}));
    let s = list.to_string();
    assert!(!s.contains(TEST_UUID) && !s.contains(pbk) && !s.contains("ab12"), "{s}");
    assert_eq!(list["servers"][0]["name"], name, "hostile names stay literal data");
    for cmd in ["getStatus", "getSettings", "getDiagnostics"] {
        let v = h.ok(cmd, json!({})).to_string();
        assert!(!v.contains(TEST_UUID) && !v.contains(pbk), "{cmd} leaked a secret: {v}");
    }
    let r = h.ok("renameServer", json!({"id": id, "name": "\"; rm -rf / #"}));
    assert_eq!(r, json!({}));

    // Oversized frame (just over the 8 MiB cap): the helper closes the connection and exits,
    // stopping Xray (the IDE passthrough ports close).
    let stdin = h.child.stdin.as_mut().unwrap();
    let _ = stdin.write_all(&((8 * 1024 * 1024 + 1) as u32).to_ne_bytes());
    let _ = stdin.flush();
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "helper did not exit after an oversized message");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(!port_open(o.jb_http) && !port_open(o.jb_socks), "Xray survived the helper");
}

fn raw_helper(args: &[&str], data: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_private-proxy-host"));
    c.args(args)
        .env("PRIVATE_PROXY_TEST_MODE", "1")
        .env("PRIVATE_PROXY_DATA_DIR", data)
        .env("PRIVATE_PROXY_INSECURE_FILE_KEY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

fn run_with_timeout(mut c: Command) -> (Option<i32>, Vec<u8>) {
    let mut child = c.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            let mut out = Vec::new();
            let _ = child.stdout.take().unwrap().read_to_end(&mut out);
            return (st.code(), out);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("helper did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn unauthorized_callers_are_rejected() {
    let data = tempfile::tempdir().unwrap();
    // Another extension (not in allowed_origins) - Chromium would refuse it already; the helper
    // re-checks the origin and exits without speaking the protocol.
    for origin in [
        "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        &format!("{}evil/", origin()),
        "chrome-extension://",
    ] {
        let (code, out) = run_with_timeout(raw_helper(&[origin], data.path()));
        assert_eq!(code, Some(3), "{origin}");
        assert!(out.is_empty(), "{origin}: spoke to an unauthorized caller");
    }
    // Anything that is not a browser launch or a documented CLI verb does nothing.
    for args in [&["https://evil.example/"][..], &["--data-dir", "C:\\x"], &["file:///etc/passwd"], &["exec", "calc.exe"]] {
        let (code, out) = run_with_timeout(raw_helper(args, data.path()));
        assert_eq!(code, Some(2), "{args:?}");
        assert!(out.is_empty());
    }
    assert!(!data.path().join("secrets.bin").exists());
}

#[test]
fn tampered_xray_is_never_executed() {
    let Some(real) = xray_path() else { return };
    let dir = tempfile::tempdir().unwrap();
    // A one-byte change and a completely different executable are both refused.
    let patched = dir.path().join("patched").join(if cfg!(windows) { "xray.exe" } else { "xray" });
    std::fs::create_dir_all(patched.parent().unwrap()).unwrap();
    let mut bytes = std::fs::read(&real).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 0x01;
    std::fs::write(&patched, &bytes).unwrap();
    let other = dir.path().join("other").join(if cfg!(windows) { "xray.exe" } else { "xray" });
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::copy(if cfg!(windows) { PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("cmd.exe") } else { PathBuf::from("/bin/sh") }, &other).unwrap();
    for bin in [patched, other] {
        let o = HostOpts { xray: Some(bin.clone()), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
        let mut h = Host::start(&o);
        let hello = h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
        assert_eq!(hello["xrayAvailable"], false, "{}", bin.display());
        let st = h.ok("getStatus", json!({}));
        assert_eq!(st["jetbrains"]["mode"], "off", "passthrough must not start: {st}");
        let imp = h.ok("importText", json!({"text": format!("vless://{TEST_UUID}@srv.example.com:443?security=tls#x"), "source": "paste"}));
        let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
        assert_eq!(st["error"]["code"], "XRAY_FAILED", "{st}");
        assert!(st["error"]["message"].as_str().unwrap().contains("integrity"), "{st}");
        assert!(h.ok("getDiagnostics", json!({}))["xrayPid"].is_null());
        assert!(!port_open(o.jb_http));
    }
}

#[test]
fn linked_data_dir_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = t.path().join("link");
    #[cfg(windows)]
    let made = Command::new(PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("cmd.exe"))
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .output()
        .unwrap()
        .status
        .success();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&real, &link).is_ok();
    assert!(made);
    let (code, out) = run_with_timeout(raw_helper(&[&origin()], &link));
    assert_eq!(code, Some(4), "helper must refuse a data directory that is a link/junction");
    assert!(out.is_empty());
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0, "nothing may be written through the link");
}

#[test]
fn subscription_ssrf_is_blocked() {
    // A local service that must never receive a request.
    let hits = Arc::new(Mutex::new(0u32));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            *h2.lock().unwrap() += 1;
            drop(s);
        }
    });
    // Release policy (no loopback allowance).
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: false, extra_env: vec![] };
    let mut h = Host::start(&o);
    for url in [
        format!("http://127.0.0.1:{port}/sub"),
        format!("https://127.0.0.1:{port}/sub"),
        format!("https://localhost:{port}/sub"),
        format!("https://[::1]:{port}/sub"),
        format!("https://2130706433:{port}/sub"),
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/".into(),
        "https://metadata.google.internal/computeMetadata/v1/".into(),
        "https://[fe80::1]/".into(),
        "https://0.0.0.0/".into(),
        "file:///C:/Windows/win.ini".into(),
        "ftp://sub.example.com/x".into(),
    ] {
        let r = h.req("addSubscription", json!({"name": "x", "url": url}));
        assert_eq!(r["error"]["code"], "INVALID_CONFIG", "{url}: {r}");
    }
    let r = h.req("addSubscription", json!({"name": "x", "url": "https://10.255.255.1/sub"}));
    assert!(r["error"]["message"].as_str().unwrap().contains("private network"), "{r}");
    h.ok("setSettings", json!({"allowPrivateSubscriptionHosts": true}));
    let r = h.req("addSubscription", json!({"name": "x", "url": format!("https://127.0.0.1:{port}/sub")}));
    assert_eq!(r["error"]["code"], "INVALID_CONFIG", "loopback stays blocked with the private-network setting: {r}");

    // DNS rebinding: a public name that resolves to 127.0.0.1 (only checked when DNS is available).
    use std::net::ToSocketAddrs;
    if ("localtest.me", 443).to_socket_addrs().map(|mut a| a.any(|x| x.ip().is_loopback())).unwrap_or(false) {
        let r = h.req("addSubscription", json!({"name": "x", "url": format!("https://localtest.me:{port}/sub")}));
        assert_eq!(r["error"]["code"], "SUBSCRIPTION_FAILED", "{r}");
        assert!(r["error"]["message"].as_str().unwrap().contains("this computer"), "{r}");
    } else {
        eprintln!("note: DNS-rebinding check skipped (localtest.me not resolvable)");
    }
    // Proxy servers on loopback are refused too.
    let r = h.req("importText", json!({"text": format!("vless://{TEST_UUID}@127.0.0.1:{port}?security=none#local"), "source": "paste"}));
    assert_eq!(r["error"]["code"], "INVALID_CONFIG", "{r}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(*hits.lock().unwrap(), 0, "a blocked destination received a connection");
}

#[test]
fn malicious_subscription_bodies() {
    use base64::Engine;
    let body = Arc::new(Mutex::new(Vec::<u8>::new()));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = l.local_addr().unwrap().port();
    let b2 = body.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let b = b2.lock().unwrap().clone();
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).as_bytes());
            let _ = s.write_all(&b);
        }
    });
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    let url = format!("http://127.0.0.1:{sport}/sub");
    let ob = |extra: &str| {
        format!(r#"{{"protocol":"vless","settings":{{"address":"s.example.com","port":443,"id":"{TEST_UUID}"}},"streamSettings":{{"security":"tls"{extra}}}}}"#)
    };
    // One clean entry among hostile ones: only the clean one is imported.
    let arr = format!(
        "[{},{},{},{}]",
        ob(""),
        ob(r#","tlsSettings":{"masterKeyLog":"C:\\Users\\Public\\keys.log"}"#),
        ob(r#","sockopt":{"dialerProxy":"x"}"#),
        ob(r#","tlsSettings":{"certificates":[{"keyFile":"/etc/shadow"}]}"#)
    );
    *body.lock().unwrap() = arr.into_bytes();
    let r = h.ok("addSubscription", json!({"name": "mixed", "url": url}));
    assert_eq!((r["added"].as_u64(), r["rejected"].as_u64()), (Some(1), Some(3)), "{r}");
    let sub_id = r["subscriptionId"].as_str().unwrap().to_string();

    let fails = [
        vec![b'A'; 5 * 1024 * 1024 + 10],                                    // over the size cap
        b"not base64 !!! %%% ".to_vec(),                                      // malformed
        base64::engine::general_purpose::STANDARD.encode("\u{0}\u{1}binary").into_bytes(),
        br#"{"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks"}]}"#.to_vec(), // a server config
        vec![0xff, 0xfe, 0x00, 0x41],                                         // not UTF-8
    ];
    for f in fails {
        *body.lock().unwrap() = f;
        let r = h.req("updateSubscription", json!({"id": sub_id}));
        assert_eq!(r["error"]["code"], "SUBSCRIPTION_FAILED", "{r}");
    }
    // The last good server list survives failed updates.
    assert_eq!(h.ok("listServers", json!({}))["servers"].as_array().unwrap().len(), 1);
    // Too many entries: capped.
    let many: String = (0..2100).map(|i| format!("vless://{TEST_UUID}@s{i}.example.com:443?security=tls#n{i}\n")).collect();
    *body.lock().unwrap() = many.into_bytes();
    let r = h.ok("updateSubscription", json!({"id": sub_id}));
    assert_eq!(h.ok("listServers", json!({}))["servers"].as_array().unwrap().len(), 2000, "{r}");
}

/// DLL planting: fake copies of the helper's non-KnownDLL imports next to the executable (e.g. in
/// the Downloads folder the package was extracted to) must not be loaded. Covered by
/// DependentLoadFlags=LOAD_LIBRARY_SEARCH_SYSTEM32 (.cargo/config.toml).
#[cfg(windows)]
#[test]
fn planted_dlls_are_not_loaded() {
    let t = tempfile::tempdir().unwrap();
    let exe = t.path().join("private-proxy-host.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_private-proxy-host"), &exe).unwrap();
    for dll in ["secur32", "bcrypt", "crypt32", "bcryptprimitives", "version", "userenv", "winhttp", "dbghelp"] {
        std::fs::write(t.path().join(format!("{dll}.dll")), b"MZ planted - not a real DLL").unwrap();
    }
    let out = Command::new(&exe).arg("--version").output().unwrap();
    assert!(out.status.success(), "helper failed next to planted DLLs: {:?}", out.status);
    assert!(String::from_utf8_lossy(&out.stdout).contains("private-proxy-host"));
}

/// HTTP proxy request with optional Basic credentials; returns the status line.
fn http_proxy_with_auth(port: u16, host: &str, target_port: u16, auth: Option<(&str, &str)>) -> Result<String, String> {
    use base64::Engine;
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let cred = auth.map(|(u, p)| format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))).unwrap_or_default();
    s.write_all(format!("GET http://{host}:{target_port}/x HTTP/1.1\r\nHost: {host}:{target_port}\r\n{cred}Connection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

/// SOCKS5 with username/password (RFC 1929) or no auth; Ok(status line) or Err(reason).
fn socks_with_auth(port: u16, host: &str, target_port: u16, auth: Option<(&str, &str)>) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let method = if auth.is_some() { 2u8 } else { 0u8 };
    s.write_all(&[5, 1, method]).map_err(|e| e.to_string())?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).map_err(|e| e.to_string())?;
    if r[1] != method {
        return Err(format!("method refused ({:#x})", r[1]));
    }
    if let Some((u, p)) = auth {
        let mut m = vec![1, u.len() as u8];
        m.extend_from_slice(u.as_bytes());
        m.push(p.len() as u8);
        m.extend_from_slice(p.as_bytes());
        s.write_all(&m).map_err(|e| e.to_string())?;
        let mut a = [0u8; 2];
        s.read_exact(&mut a).map_err(|e| e.to_string())?;
        if a[1] != 0 {
            return Err("authentication failed".into());
        }
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).map_err(|e| e.to_string())?;
    let mut head = [0u8; 10];
    s.read_exact(&mut head).map_err(|e| e.to_string())?;
    if head[1] != 0 {
        return Err(format!("socks error {}", head[1]));
    }
    s.write_all(format!("GET /x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

/// The IDE endpoint requires the generated username/password (default on), in direct
/// passthrough and in tunnel mode; the credentials stay out of every other API.
#[test]
fn ide_endpoint_requires_password() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    // The harness starts with ideAuth off; switch to the product default (on).
    h.ok("setSettings", json!({"ideAuth": true}));
    let c = h.ok("getIdeCredentials", json!({}));
    let (user, pass) = (c["username"].as_str().unwrap().to_string(), c["password"].as_str().unwrap().to_string());
    assert_eq!(c["required"], true);
    assert!(pass.len() >= 20, "{c}");
    let st = h.ok("getStatus", json!({}));
    assert_eq!(st["jetbrains"]["authRequired"], true, "{st}");
    assert!(!st.to_string().contains(&pass) && !h.ok("getDiagnostics", json!({})).to_string().contains(&pass));
    assert!(!h.ok("getSettings", json!({})).to_string().contains(&pass));
    assert_eq!(h.ok("getIdeCredentials", json!({}))["password"], pass.as_str(), "stable across calls");

    let target = e.target.port;
    let check_mode = |label: &str| {
        let no = http_proxy_with_auth(o.jb_http, "127.0.0.1", target, None).unwrap_or_default();
        assert!(no.contains("407"), "{label}: HTTP without credentials must get 407, got {no:?}");
        let wrong = http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&user, "wrong-password"))).unwrap_or_default();
        assert!(wrong.contains("407"), "{label}: wrong password must get 407, got {wrong:?}");
        let ok = http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&user, &pass))).unwrap();
        assert!(ok.contains("204"), "{label}: correct credentials must work, got {ok:?}");
        assert!(socks_with_auth(o.jb_socks, "127.0.0.1", target, None).is_err(), "{label}: SOCKS without credentials must fail");
        assert!(socks_with_auth(o.jb_socks, "127.0.0.1", target, Some((&user, "nope"))).is_err(), "{label}: wrong SOCKS password must fail");
        assert!(socks_with_auth(o.jb_socks, "127.0.0.1", target, Some((&user, &pass))).unwrap().contains("204"), "{label}: SOCKS with credentials");
    };
    assert!(port_open(o.jb_http));
    check_mode("direct");

    // Tunnel mode: IDE ports require the password; the browser port does not (Chromium cannot send it).
    let (_, link) = links(&e).remove(1); // VLESS WS
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
    assert_eq!(st["state"], "connected", "{st}");
    check_mode("tunnel");
    let bp = st["proxy"]["port"].as_u64().unwrap() as u16;
    assert_eq!(via_browser(&st, "probe.test", e.target.port).unwrap(), "HTTP/1.1 204 No Content");
    // The IDE password does not open the browser port and vice versa.
    assert!(http_proxy_with_auth(bp, "probe.test", e.target.port, Some((&user, &pass))).unwrap_or_default().contains("407"));
    let (bu, bpw) = (st["proxy"]["username"].as_str().unwrap().to_string(), st["proxy"]["password"].as_str().unwrap().to_string());
    assert!(http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&bu, &bpw))).unwrap_or_default().contains("407"));
    // Under heavy parallel test load the first tunnelled request can get a 503 (outbound dial
    // failure, not an auth issue; see docs/adversarial-testing.md). Retry up to 3 times.
    let mut via_ide = http_proxy_with_auth(o.jb_http, "probe.test", e.target.port, Some((&user, &pass)));
    for _ in 0..2 {
        if via_ide.as_deref().unwrap_or("").contains("204") {
            break;
        }
        eprintln!("retrying IDE request after {via_ide:?}");
        std::thread::sleep(Duration::from_millis(500));
        via_ide = http_proxy_with_auth(o.jb_http, "probe.test", e.target.port, Some((&user, &pass)));
    }
    assert!(via_ide.as_deref().unwrap_or("").contains("204"), "IDE endpoint in tunnel mode: {via_ide:?}");

    // Regenerating invalidates the old password.
    h.ok("disconnect", json!({}));
    h.wait_status("disconnected", Duration::from_secs(10), |s| s["state"] == "disconnected");
    let n = h.ok("regenerateIdeCredentials", json!({}));
    let new_pass = n["password"].as_str().unwrap().to_string();
    assert_ne!(new_pass, pass);
    assert!(ports_ready(o.jb_http));
    assert!(http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&user, &pass))).unwrap_or_default().contains("407"));
    assert!(http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&user, &new_pass))).unwrap().contains("204"));

    // Turning it off gives an open endpoint again (user's explicit choice).
    h.ok("setSettings", json!({"ideAuth": false}));
    assert!(ports_ready(o.jb_http));
    assert!(http_proxy_with_auth(o.jb_http, "127.0.0.1", target, None).unwrap().contains("204"));
}

fn ports_ready(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if port_open(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Runs the `sandbox_probe` test fixture under exactly the restrictions Xray gets and asserts,
/// from inside the process, what it can and cannot do. A control run without restrictions proves
/// the probe detects each capability (so a PASS is not an artefact of the probe).
#[cfg(windows)]
#[test]
fn xray_sandbox_probe() {
    use ppcore::winproc::{ChildProc, Restrictions, Stdio as PStdio};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::CreateEventW;

    let probe = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("examples").join("sandbox_probe.exe");
    if !probe.is_file() {
        eprintln!("skipped: {} not built", probe.display());
        return;
    }
    let home = PathBuf::from(std::env::var("USERPROFILE").unwrap());
    let tag = std::process::id();
    // A "company document" in the user profile, a protected data dir like ours, user temp.
    let doc = home.join(format!("pp-probe-document-{tag}.txt"));
    std::fs::write(&doc, b"confidential").unwrap();
    let data = tempfile::tempdir().unwrap();
    ppcore::harden::restrict_dir(data.path()).unwrap();
    let secret = data.path().join("secrets.bin");
    std::fs::write(&secret, b"secret").unwrap();
    let tmp_file = std::env::temp_dir().join(format!("pp-probe-temp-{tag}.txt"));
    std::fs::write(&tmp_file, b"temp").unwrap();
    let local_low = home.join("AppData").join("LocalLow").join(format!("pp-probe-{tag}.txt"));
    let hosts = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("drivers").join("etc").join("hosts");
    let install_dir = probe.parent().unwrap().join(format!("pp-probe-install-{tag}.txt"));

    // An inheritable handle in the parent that the child must NOT receive.
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
    let event: HANDLE = unsafe { CreateEventW(&sa, 1, 0, std::ptr::null()) };
    assert!(!event.is_null());

    let s = |p: &Path| p.to_string_lossy().to_string();
    let args: Vec<String> = vec![
        "--handle".into(), (event as usize).to_string(),
        "--read".into(), s(&doc), "--read".into(), s(&secret), "--read".into(), s(&tmp_file), "--read".into(), s(&hosts),
        "--write".into(), s(&home.join(format!("pp-probe-write-{tag}.txt"))),
        "--write".into(), s(&std::env::temp_dir().join(format!("pp-probe-write-{tag}.txt"))),
        "--write".into(), s(&local_low),
        "--write".into(), s(&install_dir),
        "--write".into(), s(&data.path().join("planted.txt")),
        "--reg-write".into(),
    ];
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = |r: Restrictions| -> Value {
        let mut c = ChildProc::spawn_with(&probe, &argv, probe.parent().unwrap(), PStdio { stdin: false, stdout: true, stderr: true }, r).unwrap();
        let mut out = String::new();
        c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
        let mut err = String::new();
        c.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        let code = c.wait().unwrap();
        serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("probe ({r:?}) exit {code:#x}, stdout {out:?}, stderr {err:?}: {e}"))
    };
    let restricted = run(Restrictions::ALL);
    let control = run(Restrictions::NONE);
    unsafe { CloseHandle(event) };
    let _ = std::fs::remove_file(&doc);
    let _ = std::fs::remove_file(&tmp_file);
    eprintln!("RESTRICTED: {restricted}");
    eprintln!("CONTROL:    {control}");

    // Control: the probe can observe every capability when unrestricted.
    assert_eq!(control["reads"][s(&doc)], true, "control must read the document");
    assert_eq!(control["canStartProcess"], true);
    assert_eq!(control["reads"][s(&secret)], true);
    assert_eq!(control["canWriteHkcuSoftware"], true);
    assert_eq!(control["integrityRid"], "0x2000");
    // The minimal environment and the explicit handle list are applied by the launcher
    // unconditionally (not part of Restrictions), so the control shows them restricted too.
    assert_eq!(control["env"], json!(["SystemRoot"]));

    let r = &restricted;
    // Token
    assert_eq!(r["integrityRid"], "0x1000", "Low integrity");
    assert_eq!(r["userSidDenyOnly"], true, "user SID deny-only");
    assert_eq!(r["elevated"], false);
    for p in r["privileges"].as_array().unwrap() {
        assert_eq!(p, "SeChangeNotifyPrivilege", "unexpected privilege {p}");
    }
    // Job
    assert_eq!(r["inJob"], true);
    assert_eq!(r["job"]["killOnClose"], true);
    assert_eq!(r["job"]["activeProcessLimit"], 1);
    assert_eq!(r["job"]["dieOnUnhandledException"], true);
    assert_eq!(r["job"]["processMemoryLimit"], 2u64 << 30);
    assert_eq!(r["job"]["breakawayAllowed"], false);
    assert_ne!(r["uiRestrictions"], "0x0");
    // Mitigations (best effort, but expected on this Windows build)
    assert_eq!(r["mitigations"]["childProcess"].as_u64().unwrap() & 1, 1);
    assert_eq!(r["mitigations"]["extensionPoints"].as_u64().unwrap() & 1, 1);
    assert_eq!(r["mitigations"]["imageLoad"].as_u64().unwrap() & 0b111, 0b111);
    assert_eq!(r["mitigations"]["font"].as_u64().unwrap() & 1, 1);
    // Handles, processes, environment
    assert_eq!(r["inheritedHandleUsable"], false, "an inheritable parent handle leaked into Xray");
    assert_eq!(r["canStartProcess"], false, "Xray could start a program");
    assert_eq!(r["env"], json!(["SystemRoot"]));
    // Files and registry
    assert_eq!(r["reads"][s(&doc)], false, "Xray could read a user document");
    assert_eq!(r["reads"][s(&secret)], false, "Xray could read the credential store");
    assert_eq!(r["reads"][s(&tmp_file)], false, "Xray could read user temp files");
    assert_eq!(r["reads"][s(&hosts)], true, "baseline: world-readable system files stay readable");
    for (path, ok) in r["writes"].as_object().unwrap() {
        assert_eq!(ok, &json!(false), "Xray could write {path}");
    }
    assert_eq!(r["canWriteHkcuSoftware"], false, "Xray could write HKCU Software");
    assert_eq!(r["canWriteHkcuAppDataLow"], false, "Xray could write HKCU AppDataLow");
}


/// Fail closed: when a MANDATORY protection cannot be established, no Xray runs, no port opens,
/// and the user sees "Runtime security check failed" (never a silently weaker launch).
#[cfg(windows)]
#[test]
fn mandatory_protection_failure_blocks_connection() {
    let _ = require_xray!();
    let e = env().unwrap();
    let mut o = opts(&e);
    o.extra_env = vec![("PRIVATE_PROXY_TEST_BREAK_ISOLATION", "1")];
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    // The IDE passthrough (also a Xray launch) must not have started either.
    assert!(!port_open(o.jb_http) && !port_open(o.jb_socks), "IDE endpoint started despite the failed check");
    let (_, link) = links(&e).remove(1);
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
    assert_eq!(st["state"], "error", "{st}");
    assert!(st["error"]["message"].as_str().unwrap().starts_with("Runtime security check failed"), "{st}");
    assert!(st["proxy"].is_null());
    assert!(h.ok("getDiagnostics", json!({}))["xrayPid"].is_null(), "an Xray process is running");
}

/// Fail closed: a data folder that is no longer private (here: readable by Everyone) blocks the
/// connection before any credential reaches Xray.
#[cfg(windows)]
#[test]
fn weakened_data_folder_blocks_connection() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    let (_, link) = links(&e).remove(1);
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let data = PathBuf::from(h.ok("getDiagnostics", json!({}))["dataDir"].as_str().unwrap());
    let icacls = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("icacls.exe");
    let st = Command::new(&icacls).arg(&data).args(["/grant", "*S-1-1-0:(OI)(CI)R"]).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stdout));
    let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
    assert_eq!(st["state"], "error", "{st}");
    let m = st["error"]["message"].as_str().unwrap();
    assert!(m.starts_with("Runtime security check failed") && m.contains("grants access"), "{m}");
    assert!(h.ok("getDiagnostics", json!({}))["xrayPid"].is_null());
}

/// Adversarial checks of the IDE endpoint authentication: randomness, brute force, malformed
/// Proxy-Authorization / SOCKS auth, stability, and that neither the IDE nor the browser
/// credentials are logged or stored in plaintext.
#[test]
fn ide_auth_adversarial() {
    use base64::Engine;
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 3, "extensionVersion": "test"}));
    h.ok("setSettings", json!({"ideAuth": true}));
    assert!(ports_ready(o.jb_http));

    // Randomness: regenerated passwords are distinct, 24 chars from the 57-symbol alphabet.
    let alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        let p = h.ok("regenerateIdeCredentials", json!({}))["password"].as_str().unwrap().to_string();
        assert_eq!(p.len(), 24);
        assert!(p.chars().all(|c| alphabet.contains(c)), "{p}");
        assert!(seen.insert(p));
    }
    let c = h.ok("getIdeCredentials", json!({}));
    let (user, pass) = (c["username"].as_str().unwrap().to_string(), c["password"].as_str().unwrap().to_string());
    assert!(ports_ready(o.jb_http));
    let target = e.target.port;
    let pid_before = h.ok("getDiagnostics", json!({}))["xrayPid"].clone();

    // Malformed Proxy-Authorization headers: never let through, never crash.
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let long = "A".repeat(64 * 1024);
    let malformed = vec![
        "Basic".to_string(),
        "Basic ".to_string(),
        "Basic !!!!".to_string(),
        format!("Basic {}", b64("nocolon")),
        format!("Basic {}", b64(&format!("{user}:"))),
        format!("Basic {}", b64(&format!(":{pass}"))),
        format!("Basic {}", b64(&format!("{user}:{pass}x"))),
        format!("Basic {}", b64(&format!("{user}x:{pass}"))),
        format!("Basic {}", b64(&format!("{user}:{}", &pass[..23]))),
        format!("Bearer {pass}"),
        format!("Basic {long}"),
        format!("Basic {}", b64(&format!("{user}:{pass}\0"))),
        format!("basic {}", b64(&format!("{user}:{}", pass.to_uppercase()))),
    ];
    for hdr in &malformed {
        let mut s = TcpStream::connect(("127.0.0.1", o.jb_http)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let _ = s.write_all(format!("GET http://127.0.0.1:{target}/x HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nProxy-Authorization: {hdr}\r\nConnection: close\r\n\r\n").as_bytes());
        let mut line = String::new();
        let _ = BufReader::new(s).read_line(&mut line);
        assert!(!line.contains(" 2"), "malformed header let through: {}… -> {line:?}", hdr.chars().take(40).collect::<String>());
    }
    // Malformed SOCKS username/password auth.
    for payload in [vec![1u8, 0, 0], vec![1, 255], vec![1, 12, b'p', b'r'], vec![9, 1, b'x', 1, b'y'], vec![1, 3, b'a', b'b', b'c', 0]] {
        let mut s = TcpStream::connect(("127.0.0.1", o.jb_socks)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let _ = s.write_all(&[5, 1, 2]);
        let mut r = [0u8; 2];
        let _ = s.read_exact(&mut r);
        let _ = s.write_all(&payload);
        let mut a = [0u8; 2];
        let ok = s.read_exact(&mut a).is_ok() && a == [1, 0];
        assert!(!ok, "malformed SOCKS auth accepted: {payload:?}");
    }

    // Brute force: 8 threads x 100 wrong passwords on HTTP and SOCKS.
    let started = Instant::now();
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let (u, port_h, port_s) = (user.clone(), o.jb_http, o.jb_socks);
            std::thread::spawn(move || {
                let mut hits = 0;
                for i in 0..100 {
                    let guess = format!("guess-{t}-{i}-xxxxxxxxxxxx");
                    if http_proxy_with_auth(port_h, "127.0.0.1", target, Some((&u, &guess))).unwrap_or_default().contains(" 2") {
                        hits += 1;
                    }
                    if i % 4 == 0 && socks_with_auth(port_s, "127.0.0.1", target, Some((&u, &guess))).is_ok() {
                        hits += 1;
                    }
                }
                hits
            })
        })
        .collect();
    let hits: usize = handles.into_iter().map(|j| j.join().unwrap()).sum();
    eprintln!("brute force: 1000 attempts in {:?}, {hits} accepted", started.elapsed());
    assert_eq!(hits, 0);
    // Still healthy, same Xray process, correct credentials still work.
    assert_eq!(h.ok("getDiagnostics", json!({}))["xrayPid"], pid_before, "Xray restarted or crashed under brute force");
    assert!(http_proxy_with_auth(o.jb_http, "127.0.0.1", target, Some((&user, &pass))).unwrap().contains("204"));
    assert!(socks_with_auth(o.jb_socks, "127.0.0.1", target, Some((&user, &pass))).unwrap().contains("204"));

    // Tunnel mode: browser credentials in play as well.
    let (_, link) = links(&e).remove(1);
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
    assert_eq!(st["state"], "connected", "{st}");
    let browser_pass = st["proxy"]["password"].as_str().unwrap().to_string();
    assert_eq!(browser_pass.len(), 24);

    // Nothing sensitive in the log (debug logging is on in the harness) or in plaintext files.
    let data = PathBuf::from(h.ok("getDiagnostics", json!({}))["dataDir"].as_str().unwrap());
    let log = h.log();
    let state = std::fs::read_to_string(data.join("state.json")).unwrap();
    let secrets = std::fs::read(data.join("secrets.bin")).unwrap();
    for (what, secret) in [("IDE password", &pass), ("browser password", &browser_pass)] {
        assert!(!log.contains(secret.as_str()), "{what} in the helper log");
        assert!(!state.contains(secret.as_str()), "{what} in state.json");
        assert!(!secrets.windows(secret.len()).any(|w| w == secret.as_bytes()), "{what} in plaintext in secrets.bin");
    }
    assert!(!h.ok("getSettings", json!({})).to_string().contains(&pass));
    assert!(!h.ok("getDiagnostics", json!({})).to_string().contains(&pass));
    assert!(!h.ok("listServers", json!({})).to_string().contains(&browser_pass));
}

/// Malicious subscription corpus (native/tests/fixtures/subscriptions, see
/// docs/adversarial-testing.md) plus redirects to forbidden targets. Invariants: the helper never
/// crashes or hangs, nothing pointing at this computer / internal ranges / metadata is imported,
/// nothing outside the allowlisted protocols is imported, and names are inert data.
#[test]
fn malicious_subscription_corpus() {
    let body = Arc::new(Mutex::new(Vec::<u8>::new()));
    let location = Arc::new(Mutex::new(None::<String>));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = l.local_addr().unwrap().port();
    let (b2, loc2) = (body.clone(), location.clone());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let hop: usize = req.split("hop=").nth(1).and_then(|x| x.split(|c: char| !c.is_ascii_digit()).next()).and_then(|x| x.parse().ok()).unwrap_or(0);
            if let Some(loc) = loc2.lock().unwrap().clone() {
                let loc = loc.replace("{NEXT}", &(hop + 1).to_string());
                let _ = s.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
                continue;
            }
            let b = b2.lock().unwrap().clone();
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).as_bytes());
            let _ = s.write_all(&b);
        }
    });
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true, extra_env: vec![] };
    let mut h = Host::start(&o);
    let url = format!("http://127.0.0.1:{sport}/sub");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/subscriptions");
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
    files.sort();
    // This helper runs with the test-mode loopback allowance (needed for the plain-HTTP subscription
    // server), so loopback is checked separately below with a helper that has no allowance.
    let loopback = ["127.0.0.1", "localhost", "::1", "2130706433", "0x7f000001", "::ffff:127.0.0.1"];
    let forbidden_hosts = ["169.254.169.254", "metadata.google.internal", "0.0.0.0", "224.0.0.1"];
    let mut corpus = Vec::new();
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&f).unwrap().replace("{UUID}", TEST_UUID);
        corpus.push((name.clone(), text.clone()));
        *body.lock().unwrap() = text.into_bytes();
        let started = Instant::now();
        let r = h.req("addSubscription", json!({"name": name, "url": url}));
        let took = started.elapsed();
        let list = h.ok("listServers", json!({}));
        let servers = list["servers"].as_array().unwrap().clone();
        eprintln!("{name}: {took:?} -> {} | {} servers: {:?}", if r["ok"] == true { r["result"].to_string() } else { r["error"].to_string() }, servers.len(), servers.iter().map(|s| format!("{}@{}", s["protocol"], s["address"])).collect::<Vec<_>>());
        assert!(took < Duration::from_secs(20), "{name}: took {took:?}");
        for s in &servers {
            let addr = s["address"].as_str().unwrap_or("").trim_matches(['[', ']']).to_ascii_lowercase();
            assert!(!forbidden_hosts.contains(&addr.as_str()), "{name}: imported a forbidden target {addr}");
            assert!(["vless", "vmess"].contains(&s["protocol"].as_str().unwrap_or("")), "{name}: unexpected protocol {s}");
            let n = s["name"].as_str().unwrap_or("");
            assert!(!n.chars().any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}' | '\u{feff}')), "{name}: unsanitized name {n:?}");
            assert!(n.chars().count() <= 200, "{name}: name not truncated ({} chars)", n.chars().count());
        }
        // Clean up for the next file.
        if let Some(id) = r["result"]["subscriptionId"].as_str() {
            h.ok("deleteSubscription", json!({"id": id, "deleteServers": true}));
        }
        assert_eq!(h.ok("getStatus", json!({}))["state"], "disconnected", "{name}: helper unhealthy");
    }

    // Redirects to forbidden targets and redirect loops.
    *body.lock().unwrap() = format!("vless://{TEST_UUID}@ok.example.com:443?security=tls#ok").into_bytes();
    for loc in [
        "https://169.254.169.254/latest/meta-data/".to_string(),
        "https://metadata.google.internal/".into(),
        "https://10.0.0.1/sub".into(),
        "https://192.168.1.1/sub".into(),
        "http://sub.example.com/downgrade".into(),
        "file:///C:/Windows/win.ini".into(),
        "ftp://sub.example.com/x".into(),
        "https://[fe80::1]/x".into(),
        "https://0.0.0.0/x".into(),
        format!("http://127.0.0.1:{sport}/sub?hop={{NEXT}}"), // endless loop -> redirect limit
    ] {
        *location.lock().unwrap() = Some(loc.clone());
        let r = h.req("addSubscription", json!({"name": "redir", "url": url}));
        eprintln!("redirect to {loc}: {}", r["error"]);
        assert_eq!(r["error"]["code"], "SUBSCRIPTION_FAILED", "redirect to {loc} was followed: {r}");
    }
    *location.lock().unwrap() = None;
    assert_eq!(h.ok("listServers", json!({}))["servers"].as_array().unwrap().len(), 0);
    drop(h);

    // The same corpus pasted/imported into a production-like helper (no loopback allowance).
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: false, extra_env: vec![] };
    let mut h = Host::start(&o);
    for (name, text) in corpus {
        let r = h.req("importText", json!({"text": text, "source": "paste"}));
        let servers = h.ok("listServers", json!({}))["servers"].as_array().unwrap().clone();
        eprintln!("paste {name}: {} servers", servers.len());
        for s in &servers {
            let addr = s["address"].as_str().unwrap_or("").trim_matches(['[', ']']).to_ascii_lowercase();
            assert!(!forbidden_hosts.contains(&addr.as_str()) && !loopback.contains(&addr.as_str()), "paste {name}: imported {addr}: {r}");
            h.ok("deleteServer", json!({"id": s["id"]}));
        }
    }
    assert_eq!(h.ok("getStatus", json!({}))["state"], "disconnected");
}

/// Regression: while connected, subscription fetches go through the tunnel's inbound, which is an
/// authenticated HTTP proxy since protocol 3 (they used unauthenticated SOCKS before and failed).
#[test]
fn subscription_update_while_connected() {
    let _ = require_xray!();
    let e = env().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = l.local_addr().unwrap().port();
    let s2 = seen.clone();
    let sub_body = format!("vless://{TEST_UUID}@sub-a.example.com:443?security=tls#SubA\n");
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            s2.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string());
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sub_body}", sub_body.len()).as_bytes());
        }
    });
    let o = opts(&e);
    let mut h = Host::start(&o);
    let (_, link) = links(&e).remove(1);
    let imp = h.ok("importText", json!({"text": link, "source": "paste"}));
    let st = h.connect_and_wait(imp["serverIds"][0].as_str().unwrap());
    assert_eq!(st["state"], "connected", "{st}");
    let r = h.req("addSubscription", json!({"name": "while connected", "url": format!("http://127.0.0.1:{sport}/sub")}));
    assert_eq!(r["ok"], true, "subscription fetch through the tunnel failed: {r}");
    assert_eq!(r["result"]["added"], 1, "{r}");
    let id = r["result"]["subscriptionId"].as_str().unwrap().to_string();
    let r = h.req("updateSubscription", json!({"id": id}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(h.ok("getStatus", json!({}))["state"], "connected");
}
