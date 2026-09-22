//! EXPERIMENTAL Phase 7.5 Track A validation: fail-closed "protected apps"
//! (app-configured proxy + user-mode WFP BLOCK filters in a dynamic session).
//!
//!   track-a [--report <file.json>]          run everything possible; WFP parts need an elevated shell
//!   track-a --enforcer-child <exe>          (internal) hold a WFP session for <exe> until killed
//!
//! Ground truth is observed, never assumed:
//! * "blocked" = the client's connect/send fails with WSAEACCES (10013) AND the controlled listener
//!   received nothing;
//! * "direct"  = the controlled listener received the connection/datagram;
//! * "proxy"   = reached `probe.test`, a name only the test server's DNS resolves.
//! The controlled listeners bind this machine's own LAN address, so WFP classifies the traffic as
//! non-loopback without anything leaving the machine.
//!
//! Safety: filters exist only in a dynamic WFP session (removed when this process exits, including
//! crashes), only for the test client's path and the current user. No other security setting is touched.
use per_app_routing_poc::testkit::*;
use per_app_routing_poc::*;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[cfg(windows)]
use per_app_routing_poc::wfp::WfpEnforcement;

const BLOCKED: i64 = 10013; // WSAEACCES: refused locally by a WFP filter

fn os(v: &Value) -> Option<i64> {
    v["os"].as_i64().or_else(|| {
        let s = v["result"].as_str().unwrap_or("");
        s.rsplit("(os ").next().and_then(|t| t.trim_end_matches(')').parse().ok())
    })
}

fn lan_ipv4() -> Option<IpAddr> {
    // A UDP "connect" picks the outgoing interface without sending anything.
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

struct Report {
    rows: Vec<Value>,
}

impl Report {
    fn add(&mut self, id: &str, scenario: &str, expected: &str, observed: Value, evidence: &str, status: &str) {
        println!("{status:<34} {id:<4} {scenario}");
        self.rows.push(json!({ "id": id, "scenario": scenario, "expected": expected, "actual": observed, "evidence": evidence, "status": status }));
    }
}

#[cfg(windows)]
fn enforce(targets: &[&Path]) -> Result<WfpEnforcement, String> {
    let mut w = WfpEnforcement::open()?;
    let targets = targets.iter().map(|p| ApplicationTarget::approve("selected", p, ChildPolicy::None).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    w.prepare(&ApplicationRoutingPolicy { targets, failure_mode: FailureMode::Closed })?;
    w.activate(&LocalEndpoint { port: 0, user: String::new(), pass: String::new() })?;
    Ok(w)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    #[cfg(windows)]
    if let Some(i) = args.iter().position(|a| a == "--enforcer-child") {
        let exe = PathBuf::from(&args[i + 1]);
        match enforce(&[&exe]) {
            Ok(_w) => {
                println!("READY");
                std::thread::sleep(Duration::from_secs(120));
            }
            Err(e) => println!("ERROR {e}"),
        }
        return;
    }
    std::env::set_var("PRIVATE_PROXY_TEST_MODE", "1");
    std::env::set_var("PRIVATE_PROXY_ALLOW_LOOPBACK", "1");
    let report_path = args.iter().position(|a| a == "--report").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let elevated = is_elevated();
    println!("elevated: {elevated}");
    let tmp = std::env::temp_dir().join(format!("track-a-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut r = Report { rows: Vec::new() };

    // ---- environment
    let tport = start_target();
    std::env::set_var("PRIVATE_PROXY_PROBE_URL", format!("probe.test:{tport}/generate_204"));
    let (mut server, sport) = start_server();
    let lan = lan_ipv4().expect("no LAN IPv4 address: cannot build the controlled non-loopback listeners");
    let lan_tcp = tcp_listener(SocketAddr::new(lan, 0)).unwrap();
    let lan_udp = udp_listener(SocketAddr::new(lan, 0)).unwrap();
    let v6_loop = tcp_listener("[::1]:0".parse().unwrap()).unwrap();
    let before = snapshot(elevated);

    let client = std::env::current_exe().unwrap().with_file_name("poc-client.exe");
    let control = tmp.join("poc-control.exe"); // identical bytes, different path: unselected
    std::fs::copy(&client, &control).unwrap();
    let mut session = Session::start(sport, &tmp.join("core"));
    let ep = session.endpoint();
    let proxy_env = vec![("HTTP_PROXY", format!("http://{}:{}@127.0.0.1:{}", ep.user, ep.pass, ep.port)), ("NO_PROXY", "localhost,127.0.0.1,::1".to_string())];
    let probe_url = |l: &str| format!("http://probe.test:{tport}/{l}");
    let lan_tcp_s = lan_tcp.addr.to_string();
    let lan_udp_s = lan_udp.addr.to_string();
    let tcp_hits = || lan_tcp.hits.load(Ordering::SeqCst);
    let udp_hits = || lan_udp.hits.load(Ordering::SeqCst);

    // ---- enforcement for the selected executable (poc-client.exe)
    #[cfg(windows)]
    let mut wfp = enforce(&[&client]);
    #[cfg(windows)]
    let enforced = wfp.is_ok();
    #[cfg(not(windows))]
    let enforced = false;
    #[cfg(windows)]
    let wfp_error = wfp.as_ref().err().cloned();
    #[cfg(not(windows))]
    let wfp_error: Option<String> = Some("not Windows".into());
    r.add("W0", "open WFP dynamic session + add filters", "succeeds when elevated", json!({"elevated": elevated, "error": wfp_error}),
        "runtime", if enforced { "PASS: RUNTIME VERIFIED" } else if elevated { "FAIL" } else { "NOT TESTED: NOT ELEVATED" });
    let nt = "NOT TESTED: WFP NOT ACTIVE (not elevated)";

    // Blocked = WSAEACCES and nothing arrived.
    let check_block = |v: &Value, hits_before: usize, hits_after: usize| -> &'static str {
        if !enforced {
            return "NOT TESTED: WFP NOT ACTIVE (not elevated)";
        }
        if os(v) == Some(BLOCKED) && hits_after == hits_before { "PASS: RUNTIME VERIFIED" } else { "FAIL" }
    };

    // ---- T1 proxy-aware selected
    let v = with_env(&client, &["http", &probe_url("t1")], &proxy_env);
    let ok = v["via"] == "proxy" && v["result"].as_str().unwrap_or("").contains("200");
    r.add("T1", "selected proxy-aware TCP → approved proxy → probe.test", "PROXY", v, "runtime", if ok { if enforced { "PASS: RUNTIME VERIFIED" } else { "PASS (without WFP)" } } else { "FAIL" });

    // ---- T2 proxy-unaware selected direct IPv4 (LAN address of this machine)
    let h = tcp_hits();
    let v = plain(&client, &["tcp", &lan_tcp_s]);
    std::thread::sleep(Duration::from_millis(200));
    r.add("T2", "selected proxy-unaware direct TCP IPv4 (own LAN address)", "BLOCKED", json!({"client": v, "listenerHits": tcp_hits() - h}), "runtime", check_block(&v, h, tcp_hits()));

    // ---- T3 unselected direct IPv4
    let h = tcp_hits();
    let v = plain(&control, &["tcp", &lan_tcp_s]);
    std::thread::sleep(Duration::from_millis(200));
    let got = tcp_hits() - h;
    r.add("T3", "unselected TCP IPv4 (same bytes, different path)", "DIRECT", json!({"client": v, "listenerHits": got}), "runtime", if got == 1 { "PASS: RUNTIME VERIFIED" } else { "FAIL" });

    // ---- T4/T5 UDP
    let h = udp_hits();
    let v = plain(&client, &["udp", &lan_udp_s]);
    std::thread::sleep(Duration::from_millis(300));
    let udp_status = if !enforced { nt } else if udp_hits() == h { "PASS: RUNTIME VERIFIED" } else { "FAIL" };
    r.add("T4", "selected direct UDP (own LAN address)", "BLOCKED (nothing received)", json!({"client": v, "listenerHits": udp_hits() - h}), "runtime", udp_status);
    let h = udp_hits();
    let v = plain(&control, &["udp", &lan_udp_s]);
    std::thread::sleep(Duration::from_millis(300));
    let got = udp_hits() - h;
    r.add("T5", "unselected direct UDP", "DIRECT (received)", json!({"client": v, "listenerHits": got}), "runtime", if got == 1 { "PASS: RUNTIME VERIFIED" } else { "FAIL" });

    // ---- T6/T7 IPv6 (this machine has no non-loopback IPv6 address)
    let v = plain(&client, &["tcp", "[2001:db8::1]:80"]);
    let st = if !enforced { nt.to_string() } else if os(&v) == Some(BLOCKED) { "PASS: BLOCKED BY THE V6 FILTER (no IPv6 route here; reachability not testable)".into() } else { "NOT TESTED: ENVIRONMENT LIMITATION (no IPv6 route)".into() };
    r.add("T6", "selected direct TCP IPv6 (2001:db8::1)", "BLOCKED", v, "runtime (error code)", &st);
    let v = plain(&control, &["tcp", "[2001:db8::1]:80"]);
    r.add("T7", "unselected direct TCP IPv6", "DIRECT (attempted)", v.clone(), "runtime (error code)", if os(&v) == Some(10051) { "NOT TESTED: ENVIRONMENT LIMITATION (no IPv6 route)" } else { "OBSERVED" });

    // ---- T8 DNS: who performs the lookup, and does the name leave?
    let name = format!("poc-{}-{}.localtest.me", std::process::id(), Instant::now().elapsed().as_nanos() % 100000);
    let v = plain(&client, &["dns", &name]);
    let cache = powershell(&format!("Get-DnsClientCache -Name '{name}' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Entry + ' ' + $_.Data }}"));
    let resolved = v["result"].as_str().unwrap_or("").starts_with("resolved");
    let st = if !resolved {
        "INCONCLUSIVE (lookup failed)"
    } else if enforced {
        "FAIL: DNS METADATA LEAKED (resolved via the DNS Client service despite the app block)"
    } else {
        "OBSERVED: resolved by the DNS Client service (cache entry); WFP not active"
    };
    r.add("T8", "selected app hostname lookup (unique name)", "defined", json!({"client": v, "dnsClientCache": cache.trim()}), "runtime (resolver cache)", st);

    // ---- T9 localhost
    let v4 = plain(&client, &["raw", &format!("http://127.0.0.1:{tport}/local")]);
    let v6 = plain(&client, &["tcp", &v6_loop.addr.to_string()]);
    let ok = v4["result"].as_str().unwrap_or("").contains("200") && v6["result"] == "connected";
    r.add("T9", "selected → 127.0.0.1 and ::1", "DIRECT (loopback permitted)", json!({"v4": v4, "v6": v6}), "runtime", if ok { if enforced { "PASS: RUNTIME VERIFIED" } else { "PASS (without WFP)" } } else { "FAIL" });

    // ---- T10 private ranges (destinations unreachable: the error code tells blocked vs attempted)
    let mut priv_rows = serde_json::Map::new();
    let mut all_blocked = true;
    for dst in ["10.255.255.1:9", "172.16.255.1:9"] {
        let s = plain(&client, &["tcp", dst]);
        let c = plain(&control, &["tcp", dst]);
        all_blocked &= os(&s) == Some(BLOCKED);
        priv_rows.insert(dst.into(), json!({"selected": s, "control": c}));
    }
    r.add("T10", "selected → private ranges 10/8, 172.16/12 (192.168/16 = T2)", "BLOCKED for selected (PoC policy); control attempts", Value::Object(priv_rows), "runtime (error code)",
        if !enforced { nt } else if all_blocked { "PASS: RUNTIME VERIFIED (selected cannot reach LAN/intranet)" } else { "FAIL" });

    // ---- T11 restart, T12 multiple instances
    let h = tcp_hits();
    let v = plain(&client, &["tcp", &lan_tcp_s]);
    std::thread::sleep(Duration::from_millis(200));
    r.add("T11", "selected app restarted (new process, same path)", "BLOCKED (policy is per path)", v.clone(), "runtime", check_block(&v, h, tcp_hits()));
    let h = tcp_hits();
    let spawn = || Command::new(&client).args(["tcp", &lan_tcp_s]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let (a, b) = (spawn(), spawn());
    let (va, vb) = (run_json(a), run_json(b));
    std::thread::sleep(Duration::from_millis(200));
    let st = if !enforced { nt } else if os(&va) == Some(BLOCKED) && os(&vb) == Some(BLOCKED) && tcp_hits() == h { "PASS: RUNTIME VERIFIED (all instances)" } else { "FAIL" };
    r.add("T12", "two concurrent instances of the selected executable", "both BLOCKED", json!({"a": va, "b": vb}), "runtime", st);

    // ---- T13 children, include_children = false
    let h = tcp_hits();
    let same = plain(&client, &["child", "tcp", &lan_tcp_s]);
    let other = plain(&client, &["exec", &control.display().to_string(), "tcp", &lan_tcp_s]);
    std::thread::sleep(Duration::from_millis(200));
    let hits = tcp_hits() - h;
    let st = if !enforced { nt } else if os(&same["child"]) == Some(BLOCKED) && other["child"]["result"] == "connected" && hits == 1 {
        "OBSERVED: same-path child protected, other-path child NOT protected (no process tree)"
    } else { "FAIL / UNEXPECTED" };
    r.add("T13", "children with include_children=false (child of same path vs other path)", "defined", json!({"sameExeChild": same, "otherExeChild": other, "listenerHits": hits}), "runtime", st);

    // ---- T14 include_children=true, prototype = explicit allowlist of the child's executable
    #[cfg(windows)]
    let st14 = if enforced {
        drop(wfp.take_ok());
        let w2 = enforce(&[&client, &control]);
        let h = tcp_hits();
        let other = plain(&client, &["exec", &control.display().to_string(), "tcp", &lan_tcp_s]);
        std::thread::sleep(Duration::from_millis(200));
        let ok = os(&other["child"]) == Some(BLOCKED) && tcp_hits() == h;
        drop(w2);
        wfp = enforce(&[&client]);
        (json!({"otherExeChild": other}), if ok { "PASS: RUNTIME VERIFIED (only by listing the child's executable explicitly)" } else { "FAIL" })
    } else {
        (json!(null), nt)
    };
    #[cfg(not(windows))]
    let st14 = (json!(null), nt);
    r.add("T14", "include_children=true, prototype: explicit executable allowlist", "child BLOCKED", st14.0, "runtime", st14.1);

    // ---- T15 negative child: selected → cmd.exe → curl.exe (unrelated, unselected)
    let h = tcp_hits();
    let v = plain(&client, &["shell-child", &format!("http://{lan_tcp_s}/neg")]);
    std::thread::sleep(Duration::from_millis(300));
    let reached = tcp_hits() - h;
    r.add("T15", "NEGATIVE: selected → cmd.exe → curl.exe (unrelated)", "not silently treated as protected", json!({"client": v, "listenerHits": reached}), "runtime",
        if reached >= 1 { "OBSERVED: unrelated program is neither proxied nor blocked (WFP does not inherit)" } else { "OBSERVED: unrelated program blocked/failed" });

    // ---- T16 Xray crash while selected app runs
    let pid = session.core.diagnostics().xray_pid.unwrap();
    let _ = Command::new(sys32("taskkill.exe")).args(["/F", "/PID", &pid.to_string()]).output();
    std::thread::sleep(Duration::from_millis(300));
    let during_proxy = with_env(&client, &["http", &probe_url("t16")], &proxy_env);
    let h = tcp_hits();
    let during_direct = plain(&client, &["tcp", &lan_tcp_s]);
    let direct_status = check_block(&during_direct, h, tcp_hits());
    let restarted = session.pump(Duration::from_secs(20), move |c| c.diagnostics().xray_pid.is_some_and(|p| p != pid));
    let after = with_env(&client, &["http", &probe_url("t16b")], &proxy_env);
    let ok_proxy = !during_proxy["result"].as_str().unwrap_or("").contains("200") && restarted && after["result"].as_str().unwrap_or("").contains("200");
    let st = if !ok_proxy { "FAIL" } else if direct_status.starts_with("PASS") { "PASS: RUNTIME VERIFIED (no direct fallback)" } else { direct_status };
    r.add("T16", "Xray killed: selected app has no direct Internet, then recovers", "NO DIRECT; recovery", json!({"proxyDuringCrash": during_proxy, "directDuringCrash": during_direct, "restarted": restarted, "proxyAfter": after}), "runtime", st);

    // ---- T17 helper (enforcer) crash: dynamic session vanishes
    #[cfg(windows)]
    let t17 = if enforced {
        drop(wfp.take_ok());
        let mut child = Command::new(std::env::current_exe().unwrap()).args(["--enforcer-child", &client.display().to_string()]).stdout(Stdio::piped()).spawn().unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).ok();
        let h = tcp_hits();
        let while_alive = plain(&client, &["tcp", &lan_tcp_s]);
        let blocked_alive = os(&while_alive) == Some(BLOCKED) && tcp_hits() == h;
        let _ = Command::new(sys32("taskkill.exe")).args(["/F", "/PID", &child.id().to_string()]).output();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(1500));
        let h = tcp_hits();
        let after_kill = plain(&client, &["tcp", &lan_tcp_s]);
        std::thread::sleep(Duration::from_millis(200));
        let reopened = after_kill["result"] == "connected" && tcp_hits() == h + 1;
        wfp = enforce(&[&client]);
        (json!({"enforcer": line.trim(), "whileAlive": while_alive, "afterKill": after_kill}),
         if blocked_alive && reopened { "OBSERVED: filters removed automatically on crash → selected app FAILS OPEN" } else if blocked_alive { "OBSERVED: still blocked after crash" } else { "FAIL" })
    } else {
        (json!(null), nt)
    };
    #[cfg(not(windows))]
    let t17 = (json!(null), nt);
    r.add("T17", "helper/enforcer crash-killed (taskkill /F)", "defined (dynamic session)", t17.0, "runtime", t17.1);

    // ---- performance: request latency through the proxy vs direct, inside the client
    let avg = |v: &[Value]| v.iter().filter_map(|x| x["ms"].as_u64()).sum::<u64>() as f64 / v.len().max(1) as f64;
    let prox: Vec<Value> = (0..20).map(|i| with_env(&client, &["http", &probe_url(&format!("p{i}"))], &proxy_env)).collect();
    let dir: Vec<Value> = (0..20).map(|i| plain(&control, &["raw", &format!("http://127.0.0.1:{tport}/d{i}")])).collect();
    r.add("X1", "latency: selected via proxy vs direct (local test server)", "observation", json!({"proxyMs": avg(&prox), "directMs": avg(&dir), "wfpActive": enforced}), "runtime", "OBSERVED");

    // ---- T18 normal cleanup
    #[cfg(windows)]
    drop(wfp);
    std::thread::sleep(Duration::from_millis(500));
    let h = tcp_hits();
    let v = plain(&client, &["tcp", &lan_tcp_s]);
    std::thread::sleep(Duration::from_millis(200));
    let restored = v["result"] == "connected" && tcp_hits() == h + 1;
    session.core.stop_session();
    session.core.shutdown();
    let _ = server.kill();
    let after_snap = snapshot(elevated);
    let side = diff_snapshots(&before, &after_snap);
    r.add("T18", "after normal shutdown: selected app direct again, no WFP objects left", "restored", json!({"client": v, "wfpAfter": after_snap.get("wfpPocObjects")}), "runtime",
        if !enforced { "NOT TESTED: WFP NOT ACTIVE" } else if restored && after_snap.get("wfpPocObjects").is_some_and(|s| s.ends_with(": 0")) { "PASS: RUNTIME VERIFIED" } else { "FAIL" });

    let report = json!({ "elevated": elevated, "wfpActive": enforced, "lan": lan.to_string(), "systemSideEffects": side, "scenarios": r.rows });
    println!("{}", serde_json::to_string_pretty(&report["systemSideEffects"]).unwrap());
    if let Some(p) = report_path {
        std::fs::write(&p, serde_json::to_string_pretty(&report).unwrap()).unwrap();
        println!("report: {}", p.display());
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

/// `Result<WfpEnforcement, _>` helper: take the active session out (to drop it), leaving an error marker.
#[cfg(windows)]
trait TakeOk {
    fn take_ok(&mut self) -> Option<WfpEnforcement>;
}
#[cfg(windows)]
impl TakeOk for Result<WfpEnforcement, String> {
    fn take_ok(&mut self) -> Option<WfpEnforcement> {
        std::mem::replace(self, Err("dropped".into())).ok()
    }
}
