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
            for e in self.events.drain(..).collect::<Vec<_>>() {
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
    HostOpts { xray: Some(e.xray.clone()), probe_port: e.target.port, jb_socks: free_port(), jb_http: free_port() }
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
    let o = HostOpts { xray: None, probe_port: 1, jb_socks: free_port(), jb_http: free_port() };
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
    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port() };
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

    let o = HostOpts { xray: xray_path(), probe_port: 1, jb_socks: free_port(), jb_http: free_port() };
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
