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
}

impl Host {
    fn start(o: &HostOpts) -> Host {
        let data = tempfile::tempdir().unwrap();
        // Pre-seed settings with test-specific JetBrains ports (never touch the real 10808/10809).
        std::fs::write(
            data.path().join("state.json"),
            json!({"version":1,"settings":{"jetbrainsEnabled":true,"jetbrainsSocksPort":o.jb_socks,"jetbrainsHttpPort":o.jb_http,"passthroughWhenDisconnected":true,"debugLogging":true}}).to_string(),
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
    HostOpts { xray: Some(e.xray.clone()), probe_port: e.target.port, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true }
}

// ================================================================ tests

#[test]
fn all_transports_end_to_end() {
    let _ = require_xray!();
    let e = env().unwrap();
    let o = opts(&e);
    let mut h = Host::start(&o);
    let hello = h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));
    assert_eq!(hello["protocolVersion"], 1);
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
        // Browser path (SOCKS5, remote DNS: probe.test only resolves on the server).
        let r = get_via_socks(port, "probe.test", e.target.port);
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
    h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));

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
    assert_eq!(get_via_socks(port, "probe.test", e.target.port).unwrap(), "HTTP/1.1 204 No Content");
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
    let o = HostOpts { xray: None, probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
    let mut h = Host::start(&o);
    let hello = h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));
    assert_eq!(hello["xrayAvailable"], false);
    let imp = h.ok("importText", json!({"text": format!("vless://{TEST_UUID}@example.com:443?security=tls#x"), "source": "paste"}));
    let id = imp["serverIds"][0].as_str().unwrap().to_string();
    let st = h.connect_and_wait(&id);
    assert_eq!(st["error"]["code"], "XRAY_MISSING", "{st}");
}

#[test]
fn rejected_by_xray_validation() {
    let _ = require_xray!();
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
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

    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
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
    h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));
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
        let low = Restrictions { low_integrity: true, mitigations: false, no_child_processes: false, job_limits: false };
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
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
    let mut h = Host::start(&o);
    h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));
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
        let o = HostOpts { xray: Some(bin.clone()), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
        let mut h = Host::start(&o);
        let hello = h.ok("hello", json!({"protocolVersion": 1, "extensionVersion": "test"}));
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
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: false };
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
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port(), allow_loopback: true };
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
