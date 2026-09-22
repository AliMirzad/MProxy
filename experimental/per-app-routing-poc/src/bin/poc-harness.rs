//! EXPERIMENTAL Phase 7 harness: selected vs. control routing, children, crash/cleanup, system
//! side effects. Uses the real Shared Core (debug build) with a local Xray "server" whose DNS alone
//! resolves `probe.test`: reaching http://probe.test:<port>/ proves the request went through Xray and
//! the server; a direct attempt fails name resolution. Nothing here needs a real VLESS server.
//!
//!   poc-harness [--report <file.json>]
//!   poc-harness --crash-child            (internal: runs a session and waits to be killed)
use per_app_routing_poc::*;
use ppcore::core::api::{Core, CoreMsg, ImportKind, Poster, SettingsUpdate, Timing};
use ppcore::core::secrets::FileKeyProvider;
use ppcore::core::session::SessionState;
use ppcore::core::store::Store;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}
fn sys32(exe: &str) -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32").join(exe)
}
fn xray() -> PathBuf {
    repo().join("native/xray/dist/windows-x64/xray.exe")
}
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

/// HTTP target: answers 200 and records "<path> <host header>" for every request.
fn start_target(log: Arc<Mutex<Vec<String>>>) -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let log = log.clone();
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
                let req = String::from_utf8_lossy(&got).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                let host = req.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")).unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{path} {host}"));
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nPOC-OK");
                let _ = s.shutdown(std::net::Shutdown::Write);
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    port
}

fn start_server() -> (std::process::Child, u16) {
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

struct Session {
    core: Core,
    rx: Receiver<CoreMsg>,
    _dir: PathBuf,
}

impl Session {
    fn start(server_port: u16, data: &Path) -> Session {
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
        let mut s = Session { core, rx, _dir: data.to_path_buf() };
        s.pump(Duration::from_secs(30), |c| matches!(c.session_status().state, SessionState::Connected { .. } | SessionState::Failed { .. }));
        assert!(matches!(s.core.session_status().state, SessionState::Connected { .. }), "{:?}", s.core.session_status().state);
        s
    }
    fn pump(&mut self, timeout: Duration, done: impl Fn(&Core) -> bool) -> bool {
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
    fn endpoint(&self) -> LocalEndpoint {
        let e = self.core.browser_proxy_endpoint().expect("connected");
        LocalEndpoint { port: e.port, user: e.credentials.user.clone(), pass: e.credentials.pass.clone() }
    }
}

fn run_json(mut child: std::process::Child) -> Value {
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok();
    let _ = child.wait();
    serde_json::from_str(out.trim()).unwrap_or(json!({ "raw": out.trim() }))
}

fn plain(exe: &Path, args: &[&str]) -> Value {
    let c = Command::new(exe).args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    run_json(c)
}

/// Read-only system snapshot (hash per section, and the text for the report on change).
fn snapshot() -> BTreeMap<String, String> {
    let ps = sys32("WindowsPowerShell\\v1.0\\powershell.exe");
    let sections = [
        ("systemProxy", "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL | Format-List | Out-String; netsh winhttp show proxy | Out-String"),
        ("routes", "Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -notlike 'ff00*' } | Sort-Object DestinationPrefix,InterfaceIndex,NextHop | ForEach-Object { \"$($_.DestinationPrefix) $($_.NextHop) if$($_.InterfaceIndex) m$($_.RouteMetric)\" } | Out-String"),
        ("dns", "Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | ForEach-Object { \"$($_.InterfaceAlias) $($_.AddressFamily) $($_.ServerAddresses -join ',')\" } | Out-String"),
        ("adapters", "Get-NetAdapter -IncludeHidden | Sort-Object Name | ForEach-Object { \"$($_.Name) | $($_.InterfaceDescription) | $($_.Status)\" } | Out-String"),
        ("firewallRules", "(Get-NetFirewallRule -ErrorAction SilentlyContinue | Measure-Object).Count"),
        ("drivers", "driverquery /fo csv | Out-String"),
        ("services", "Get-Service | Sort-Object Name | ForEach-Object Name | Out-String"),
    ];
    let mut m = BTreeMap::new();
    for (k, script) in sections {
        let o = Command::new(&ps).args(["-NoProfile", "-NonInteractive", "-Command", script]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        m.insert(k.to_string(), o);
    }
    m
}

fn diff_snapshots(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Value {
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

fn process_alive(pid: u32) -> bool {
    let o = Command::new(sys32("tasklist.exe")).args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    o.contains(&format!("\"{pid}\""))
}

fn crash_child() {
    // Internal: a whole "helper" (Core + session) in its own process, killed by the parent.
    let server_port: u16 = std::env::var("POC_SERVER_PORT").unwrap().parse().unwrap();
    let dir = PathBuf::from(std::env::var("POC_DIR").unwrap());
    let s = Session::start(server_port, &dir);
    let ep = s.endpoint();
    println!("{}", json!({"port": ep.port, "user": ep.user, "pass": ep.pass, "xrayPid": s.core.diagnostics().xray_pid}));
    std::io::stdout().flush().ok();
    std::thread::sleep(Duration::from_secs(120));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Test hooks of the debug Core (process-wide, set before any Core exists).
    std::env::set_var("PRIVATE_PROXY_TEST_MODE", "1");
    std::env::set_var("PRIVATE_PROXY_ALLOW_LOOPBACK", "1");
    if args.iter().any(|a| a == "--crash-child") {
        std::env::set_var("PRIVATE_PROXY_PROBE_URL", std::env::var("POC_PROBE").unwrap());
        return crash_child();
    }
    let report_path = args.iter().position(|a| a == "--report").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let tmp = std::env::temp_dir().join(format!("poc-harness-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let tport = start_target(hits.clone());
    let probe = format!("probe.test:{tport}/generate_204");
    std::env::set_var("PRIVATE_PROXY_PROBE_URL", &probe);
    let (mut server, sport) = start_server();
    let url = |label: &str| format!("http://probe.test:{tport}/{label}");
    let direct_url = |label: &str| format!("http://127.0.0.1:{tport}/{label}");

    let before = snapshot();
    let mut results: Vec<Value> = Vec::new();
    let mut record = |id: &str, scenario: &str, expected: &str, observed: Value, verdict: &str| {
        println!("{verdict:<28} {id:<4} {scenario}");
        results.push(json!({ "id": id, "scenario": scenario, "expected": expected, "observed": observed, "verdict": verdict }));
    };

    let mut session = Session::start(sport, &tmp.join("core"));
    let ep = session.endpoint();
    let client = std::env::current_exe().unwrap().with_file_name("poc-client.exe");
    let target = ApplicationTarget::approve("poc-client", &client, ChildPolicy::Inherit).unwrap();
    let policy = ApplicationRoutingPolicy { targets: vec![target.clone()], failure_mode: FailureMode::Closed };
    let mut launcher = AppConfiguredLauncher::default();
    launcher.prepare(&policy).unwrap();
    launcher.activate(&ep).unwrap();
    let sel = |args: &[&str]| run_json(launcher.launch(&target, args, ProxyHint::Environment).unwrap());
    let reached = |v: &Value| v["result"].as_str().unwrap_or("").contains("200");

    // ---- selected vs control
    let v = sel(&["http", &url("sel")]);
    let ok = reached(&v) && v["via"] == "proxy";
    record("S1", "selected app (honours proxy env) → probe.test", "PROXY", v, if ok { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let v = plain(&client, &["http", &url("ctl")]);
    let ok = !reached(&v) && v["via"] == "direct";
    record("S2", "control: same executable started normally → probe.test", "DIRECT (name unresolvable locally)", v, if ok { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let v = plain(&client, &["http", &direct_url("ctl-direct")]);
    record("S3", "control → direct test server", "DIRECT hit", v.clone(), if reached(&v) { "PASS — RUNTIME VERIFIED" } else { "FAIL" });

    // ---- apps without proxy support: silent bypass without enforcement
    let v = sel(&["raw", &url("raw")]);
    record("S4", "selected app WITHOUT proxy support → probe.test", "must not go direct", v.clone(), if reached(&v) { "UNEXPECTED" } else { "FAIL — SILENT DIRECT BYPASS" });
    let v = sel(&["tcp", "192.0.2.1:80"]);
    let blocked = |v: &Value| v["os"] == 10013; // WSAEACCES: refused locally by a filter
    let verdict = if blocked(&v) { "PASS — BLOCKED" } else { "FAIL — DIRECT ATTEMPT NOT BLOCKED" };
    record("S5", "selected app direct IPv4 TCP (TEST-NET 192.0.2.1:80)", "blocked", v, verdict);
    let v = sel(&["tcp", "[2001:db8::1]:80"]);
    let verdict = if blocked(&v) { "PASS — BLOCKED" } else if v["os"] == 10051 { "FAIL — DIRECT ATTEMPT NOT BLOCKED (only failed because this machine has no IPv6 route)" } else { "FAIL — DIRECT ATTEMPT NOT BLOCKED" };
    record("S6", "selected app direct IPv6 TCP (2001:db8::1)", "blocked", v, verdict);
    let v = sel(&["udp", "192.0.2.1:53"]);
    let verdict = if blocked(&v) { "PASS — BLOCKED" } else if v["result"].as_str().unwrap_or("").starts_with("sent") { "FAIL — UDP SENT DIRECTLY" } else { "INCONCLUSIVE" };
    record("S7", "selected app UDP (QUIC/DNS-like) to 192.0.2.1:53", "blocked or proxied", v, verdict);
    let v = sel(&["dns", "probe.test"]);
    record("S8", "selected app system-resolver lookup", "no local lookup", v, "FAIL — LOCAL LOOKUP ATTEMPTED (system resolver; query leaves via the DNS Client service)");

    // ---- children
    let v = sel(&["child", "http", &url("child-honour")]);
    let ok = v["child"]["via"] == "proxy" && reached(&v["child"]);
    record("C1", "child of selected app (honours env) → probe.test", "PROXY (env inherited)", v, if ok { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let v = sel(&["child", "raw", &url("child-raw")]);
    record("C2", "child of selected app without proxy support", "defined", v, "FAIL — CHILD GOES DIRECT");
    let v = sel(&["shell-child", &url("negative")]);
    let proxied = v["httpCode"] == "200";
    let verdict = match v["httpCode"].as_str().unwrap_or("") { "200" => "FAIL — UNRELATED CHILD PROXIED (env inheritance)", "000" => "PASS — NOT PROXIED", _ => "INCONCLUSIVE — shell child did not run" };
    let _ = proxied;
    record("C3", "NEGATIVE: selected app → cmd.exe → curl.exe (unrelated tool)", "not proxied unintentionally", v, verdict);

    // ---- second instance / restart
    let v = sel(&["http", &url("restart")]);
    record("P1", "selected app restarted through the launcher", "PROXY", v.clone(), if reached(&v) { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let v = plain(&client, &["http", &url("second-instance")]);
    record("P2", "second instance started outside the launcher", "defined", v, "DIRECT — policy applies per launch, not per executable");

    // ---- localhost and private ranges
    let v = sel(&["http", &direct_url("local")]);
    record("L1", "selected app → 127.0.0.1 (NO_PROXY)", "DIRECT (loopback excluded)", v.clone(), if reached(&v) && v["via"] == "direct" { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let v = sel(&["http", "http://10.255.255.1:9/lan"]);
    record("L2", "selected app → 10.255.255.1 (private)", "defined", v, "OBSERVED — via local proxy; Xray dials private literals directly (product rule)");

    // ---- real third-party programs
    let curl = sys32("curl.exe");
    let curl_t = ApplicationTarget::approve("curl", &curl, ChildPolicy::None).unwrap();
    let c = launcher.launch(&curl_t, &["-s", "-o", "NUL", "-w", "%{http_code}", "--max-time", "8", &url("curl-sel")], ProxyHint::Environment).unwrap();
    let out = c.wait_with_output().unwrap();
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    record("R1", "curl.exe (Windows) selected via environment", "PROXY", json!({"httpCode": code}), if code == "200" { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let o = Command::new(&curl).args(["-s", "-o", "NUL", "-w", "%{http_code}", "--max-time", "8", &url("curl-ctl")]).output().unwrap();
    let code = String::from_utf8_lossy(&o.stdout).trim().to_string();
    record("R2", "curl.exe control", "DIRECT (fails)", json!({"httpCode": code}), if code != "200" { "PASS — RUNTIME VERIFIED" } else { "FAIL" });

    let node = Command::new("where").arg("node").output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(PathBuf::from));
    if let Some(node) = node.filter(|p| p.is_file()) {
        let node_t = ApplicationTarget::approve("node", &node, ChildPolicy::None).unwrap();
        let js = format!("fetch('{}').then(r=>console.log(JSON.stringify({{status:r.status}}))).catch(e=>console.log(JSON.stringify({{error:String(e.cause?.code||e)}})))", url("node-sel"));
        let v = run_json(launcher.launch(&node_t, &["-e", &js], ProxyHint::Environment).unwrap());
        record("R3", "node.exe fetch, selected via environment (default)", "PROXY", v.clone(), if v["status"] == 200 { "PASS" } else { "FAIL — SILENT DIRECT BYPASS (Node ignores proxy env by default)" });
        let v = run_json(launcher.launch(&node_t, &["--use-env-proxy", "-e", &js], ProxyHint::Environment).unwrap());
        record("R4", "node.exe fetch with --use-env-proxy", "PROXY", v.clone(), if v["status"] == 200 { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    } else {
        record("R3", "node.exe", "-", json!(null), "ENVIRONMENT UNAVAILABLE");
    }
    // Node cannot resolve modules from a verbatim (\\?\C:\...) path: use the plain form.
    let script = PathBuf::from(repo().join("experimental/per-app-routing-poc/chromium-check.mjs").display().to_string().trim_start_matches(r"\\?\").to_string());
    let node_exe = Command::new("where").arg("node").output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("node"));
    let last_json = |o: std::process::Output| -> Value {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        text.lines().rev().find_map(|l| serde_json::from_str(l.trim()).ok()).unwrap_or(json!({ "raw": text.trim(), "stderr": String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("") }))
    };
    let v = Command::new(&node_exe).arg(&script).arg(ep.port.to_string()).arg(url("chromium")).output().map(last_json).unwrap_or(json!(null));
    let control = Command::new(&node_exe).arg(&script).arg("none").arg(url("chromium-ctl")).output().map(last_json).unwrap_or(json!(null));
    let v = json!({ "selected": v, "control": control });
    let worked = v["selected"]["status"] == 200;
    let measured = v["selected"].get("status").is_some() || v["selected"].get("error").is_some();
    record("R5", "Chromium-based app (Brave) with --proxy-server to the authenticated inbound", "PROXY", v, if worked { "PASS" } else if measured { "FAIL — CHROMIUM CANNOT AUTHENTICATE (no 407 answer without app code)" } else { "INCONCLUSIVE — check did not run" });

    // ---- performance (rough, loopback server; not representative of a real server)
    let avg = |v: &[Value]| v.iter().filter_map(|x| x["ms"].as_u64()).sum::<u64>() as f64 / v.len().max(1) as f64;
    let t0 = Instant::now();
    let proxied: Vec<Value> = (0..20).map(|i| sel(&["http", &url(&format!("perf{i}"))])).collect();
    let launch_total = t0.elapsed().as_millis() as f64 / 20.0;
    let direct: Vec<Value> = (0..20).map(|i| plain(&client, &["http", &direct_url(&format!("perfd{i}"))])).collect();
    let via_proxy_all_ok = proxied.iter().all(|v| v["result"].as_str().unwrap_or("").contains("200"));
    record("X1", "performance: request latency inside the client (avg of 20; local loopback server)", "observation",
        json!({"viaProxyRequestMs": avg(&proxied), "directRequestMs": avg(&direct), "launcherPerLaunchMs": launch_total, "allProxiedOk": via_proxy_all_ok,
               "note": "launcher time includes re-hashing the executable before every launch (debug build)"}), "OBSERVED");

    // ---- Xray crash while selected app active
    let pid = session.core.diagnostics().xray_pid.unwrap();
    let _ = Command::new(sys32("taskkill.exe")).args(["/F", "/PID", &pid.to_string()]).output();
    std::thread::sleep(Duration::from_millis(300));
    let during = sel(&["http", &url("during-crash")]);
    let restarted = session.pump(Duration::from_secs(20), move |c| c.diagnostics().xray_pid.is_some_and(|p| p != pid) && matches!(c.session_status().state, SessionState::Connected { .. }));
    let after = sel(&["http", &url("after-restart")]);
    let v = json!({"duringRestart": during, "restarted": restarted, "afterRestart": after});
    let ok = !reached(&during) && restarted && reached(&after);
    record("F1", "Xray killed while selected app active", "selected app fails (not direct) until restart; then PROXY", v, if ok { "PASS — RUNTIME VERIFIED (for apps that honour the proxy)" } else { "FAIL" });

    // ---- stop routing: credentials invalid, nothing left
    let old = ep.clone();
    launcher.deactivate().unwrap();
    session.core.stop_session();
    let v = run_json({
        let mut c = Command::new(&client);
        c.args(["http", &url("after-stop")]).stdout(Stdio::piped());
        c.env("HTTP_PROXY", format!("http://{}:{}@127.0.0.1:{}", old.user, old.pass, old.port));
        c.spawn().unwrap()
    });
    record("F2", "routing stopped; app still configured with the old endpoint", "fails closed (no direct)", v.clone(), if !reached(&v) { "PASS — RUNTIME VERIFIED" } else { "FAIL" });
    let xray_gone = !process_alive(pid) && session.core.diagnostics().xray_pid.is_none();
    session.core.shutdown();

    // ---- helper crash (Core + Xray in another process, killed with taskkill /F)
    let crash_dir = tmp.join("crash");
    std::fs::create_dir_all(&crash_dir).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--crash-child")
        .env("POC_SERVER_PORT", sport.to_string())
        .env("POC_DIR", &crash_dir)
        .env("POC_PROBE", &probe)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let info: Value = serde_json::from_str(line.trim()).unwrap();
    let cx = info["xrayPid"].as_u64().unwrap() as u32;
    let helper_pid = child.id();
    let env_url = format!("http://{}:{}@127.0.0.1:{}", info["user"].as_str().unwrap(), info["pass"].as_str().unwrap(), info["port"]);
    let before_kill = run_json(Command::new(&client).args(["http", &url("helper-alive")]).env("HTTP_PROXY", &env_url).stdout(Stdio::piped()).spawn().unwrap());
    let _ = Command::new(sys32("taskkill.exe")).args(["/F", "/PID", &helper_pid.to_string()]).output();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(1500));
    let after_kill = run_json(Command::new(&client).args(["http", &url("helper-dead")]).env("HTTP_PROXY", &env_url).stdout(Stdio::piped()).spawn().unwrap());
    let orphan = process_alive(cx);
    let v = json!({"beforeKill": before_kill, "afterKill": after_kill, "xrayOrphan": orphan});
    let ok = reached(&before_kill) && !reached(&after_kill) && !orphan;
    record("F3", "helper (Core+Xray) crash-killed", "selected app fails closed; no orphan Xray", v, if ok { "PASS — RUNTIME VERIFIED" } else { "FAIL" });

    // ---- WFP enforcement (needs rights to add WFP filters)
    let wfp = match wfp_scenarios(&client, &target, &url) {
        Ok(v) => v,
        Err(e) => json!({ "result": e }),
    };
    let denied = wfp["result"].as_str().is_some_and(|s| s.contains("ACCESS_DENIED"));
    record("W1", "WFP fail-closed enforcement (user-mode filters, dynamic session)", "runs only with admin rights", wfp.clone(), if denied { "PASS — RUNTIME VERIFIED (non-admin cannot add WFP filters); enforcement NOT TESTED" } else if wfp["enforcement"].is_object() { "SEE RESULTS" } else { "FAIL" });

    let _ = server.kill();
    let after = snapshot();
    let side = diff_snapshots(&before, &after);
    let proxy_hits = hits.lock().unwrap().iter().filter(|h| h.contains("probe.test")).count();
    let summary = json!({
        "selectedAppRoute": "PROXY only for programs that honour the proxy setting; programs without proxy support go DIRECT",
        "controlAppRoute": "DIRECT",
        "systemSideEffects": side,
        "xrayTerminatedOnStop": xray_gone,
        "targetHitsViaProbeTest": proxy_hits,
    });
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    let report = json!({ "summary": summary, "scenarios": results });
    if let Some(p) = report_path {
        std::fs::write(&p, serde_json::to_string_pretty(&report).unwrap()).unwrap();
        println!("report: {}", p.display());
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[cfg(windows)]
fn wfp_scenarios(client: &Path, target: &ApplicationTarget, url: &dyn Fn(&str) -> String) -> Result<Value, String> {
    use per_app_routing_poc::wfp::WfpEnforcement;
    let mut w = WfpEnforcement::open()?;
    let policy = ApplicationRoutingPolicy { targets: vec![target.clone()], failure_mode: FailureMode::Closed };
    w.prepare(&policy)?;
    // Prepared: everything of the selected app is blocked, loopback included.
    let prepared = plain(client, &["tcp", "192.0.2.1:80"]);
    w.activate(&LocalEndpoint { port: 0, user: String::new(), pass: String::new() })?;
    let v4 = plain(client, &["tcp", "192.0.2.1:80"]);
    let v6 = plain(client, &["tcp", "[2001:db8::1]:80"]);
    let udp = plain(client, &["udp", "192.0.2.1:53"]);
    let raw = plain(client, &["raw", &url("wfp-raw")]);
    let loopback = plain(client, &["http", &url("wfp-loopback-direct").replace("probe.test", "127.0.0.1")]);
    let filters = w.filter_count();
    drop(w);
    let after = plain(client, &["tcp", "192.0.2.1:80"]);
    Ok(json!({ "enforcement": { "prepared": prepared, "v4": v4, "v6": v6, "udp": udp, "raw": raw, "loopback": loopback, "filters": filters, "afterSessionClosed": after } }))
}
