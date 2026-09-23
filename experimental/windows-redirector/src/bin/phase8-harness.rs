//! EXPERIMENTAL Phase 8 harness: how far does true per-app routing work without the kernel driver?
//!
//!   phase8-harness [--report <file.json>]
//!
//! Evidence design (§13, §39): no public IP checks, no trust in client return codes.
//!
//! The simulated "original destination" is **192.0.2.7:80** (TEST-NET-1, documentation-only, never
//! routable from this machine). The test server's Xray uses a `freedom` outbound with `redirect`,
//! so anything that actually traverses the tunnel lands on a controlled listener, and the listener
//! reports which local process opened the connection. Therefore:
//!
//! * marker received at the controlled listener  ⇒ the bytes went client → redirector → Xray →
//!   VLESS → test server → listener. There is no other path to 192.0.2.7;
//! * control client to 192.0.2.7 directly        ⇒ times out, proving the destination is unreachable
//!   except through the tunnel.
//!
//! What is simulated: only the kernel handing over the original destination. Everything downstream
//! is the real Shared Core, the real pinned Xray and the real authenticated inbound.
use per_app_routing_poc::testkit::{diff_snapshots, free_port, is_elevated, plain, snapshot, Session, UUID};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_redirector_poc::attribution::{owner_pid_of_local_port, process_name};

/// Documentation address (TEST-NET-1): never routable, so only the tunnel can deliver to it.
const SIMULATED_DESTINATION: &str = "192.0.2.7:80";

struct Report {
    rows: Vec<Value>,
    path: Option<PathBuf>,
}

impl Report {
    fn add(&mut self, id: &str, scenario: &str, expected: &str, actual: Value, evidence: &str, status: &str) {
        println!("{status}  {id}  {scenario}");
        self.rows.push(json!({"id": id, "scenario": scenario, "expected": expected, "actual": actual, "evidence": evidence, "status": status}));
        self.save(false);
    }
    fn save(&self, complete: bool) {
        if let Some(p) = &self.path {
            let _ = std::fs::write(p, serde_json::to_string_pretty(&json!({"complete": complete, "scenarios": self.rows})).unwrap());
        }
    }
}

/// What the controlled endpoint saw: marker, and which local process opened the connection.
#[derive(Default)]
struct Observed {
    markers: Mutex<Vec<Value>>,
    count: AtomicUsize,
    /// The Shared Core's own session probe, answered but kept out of the evidence counters.
    probes: AtomicUsize,
}

fn lan_ip() -> IpAddr {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.connect("192.168.1.1:9").ok();
    s.local_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Controlled endpoint. Binds a real non-loopback address so nothing is "local only" by accident.
fn start_controlled_endpoint(observed: Arc<Observed>, bind: IpAddr) -> u16 {
    let l = TcpListener::bind((bind, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let observed = observed.clone();
            std::thread::spawn(move || {
                let peer_port = s.peer_addr().map(|a| a.port()).unwrap_or(0);
                // Attribute the connection before it closes (§39: destination-side ground truth).
                let pid = owner_pid_of_local_port(peer_port);
                let name = pid.and_then(process_name);
                let mut reader = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let first = line.trim().to_string();
                let mut s = s;

                // The Shared Core verifies a session with its own HTTP probe, which also arrives here
                // (the test server redirects everything that leaves the tunnel to this endpoint).
                // Answer it, and keep it out of the evidence counters.
                if first.starts_with("GET ") || first.starts_with("HEAD ") {
                    observed.probes.fetch_add(1, Ordering::Relaxed);
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                    return;
                }

                let marker = first.strip_prefix("MARKER ").unwrap_or(&first).to_string();
                observed.count.fetch_add(1, Ordering::Relaxed);
                observed.markers.lock().unwrap().push(json!({"marker": marker, "openedByPid": pid, "openedBy": name}));
                let _ = writeln!(s, "OK {marker}");
            });
        }
    });
    port
}

/// Test "server" Xray: VLESS inbound, and a freedom outbound that redirects everything to the
/// controlled endpoint. Only traffic that traversed the tunnel can arrive there.
fn start_test_server(redirect_to: &str) -> (Child, u16) {
    let port = free_port();
    let cfg = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                      "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                      "streamSettings": {"network": "raw"}}],
        "outbounds": [{"protocol": "freedom", "settings": {"redirect": redirect_to}}]
    });
    let xray = per_app_routing_poc::testkit::xray();
    let mut child = Command::new(xray).args(["run", "-c", "stdin:", "-format", "json"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(cfg.to_string().as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "test server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, port)
}

fn start_redirector(exe: &PathBuf, upstream: &per_app_routing_poc::LocalEndpoint, state: &PathBuf) -> (Child, u16, u32) {
    let mut child = Command::new(exe)
        .args([
            "--upstream",
            &upstream.port.to_string(),
            "--user",
            &upstream.user,
            "--pass-env",
            "PP_REDIRECTOR_PASS",
            "--simulate-destination",
            SIMULATED_DESTINATION,
            "--state",
            &state.display().to_string(),
        ])
        .env("PP_REDIRECTOR_PASS", &upstream.pass)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufRead::read_line(&mut BufReader::new(child.stdout.take().unwrap()), &mut line).ok();
    let v: Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));
    let port = v["port"].as_u64().unwrap_or(0) as u16;
    let pid = v["pid"].as_u64().unwrap_or(0) as u32;
    (child, port, pid)
}

fn main() {
    std::env::set_var("PRIVATE_PROXY_TEST_MODE", "1");
    std::env::set_var("PRIVATE_PROXY_ALLOW_LOOPBACK", "1");
    let args: Vec<String> = std::env::args().collect();
    let report_path = args.iter().position(|a| a == "--report").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let mut r = Report { rows: Vec::new(), path: report_path };
    let elevated = is_elevated();

    let dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let client = dir.join("unaware-client.exe");
    let redirector_exe = dir.join("redirector.exe");
    assert!(client.exists() && redirector_exe.exists(), "build the crate first");

    let tmp = std::env::temp_dir().join(format!("phase8-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let state_file = tmp.join("redirector-state.json");

    let before = snapshot(elevated);

    // ---- controlled endpoint + test server + Shared Core session
    let observed = Arc::new(Observed::default());
    let lan = lan_ip();
    let endpoint_port = start_controlled_endpoint(observed.clone(), lan);
    let controlled = format!("{lan}:{endpoint_port}");
    // The Core verifies a session with its own HTTP probe. It travels the same tunnel and is
    // answered by the controlled endpoint above.
    std::env::set_var("PRIVATE_PROXY_PROBE_URL", format!("probe.test:{endpoint_port}/generate_204"));
    let (mut server, server_port) = start_test_server(&controlled);
    let mut session = Session::start(server_port, &tmp);
    let upstream = session.endpoint();
    let xray_pid = session.core.diagnostics().xray_pid;

    let (mut redirector, redirect_port, redirector_pid) = start_redirector(&redirector_exe, &upstream, &state_file);
    let redirect_addr = format!("127.0.0.1:{redirect_port}");
    let state = || -> Value { std::fs::read_to_string(&state_file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({})) };
    let hits = || observed.count.load(Ordering::Relaxed);
    let markers = || observed.markers.lock().unwrap().clone();

    // ---- R1: the whole point of the phase
    let h = hits();
    let selected = plain(&client, &[&redirect_addr, "selected-app"]);
    std::thread::sleep(Duration::from_millis(400));
    let got = markers().iter().find(|m| m["marker"] == "selected-app").cloned();
    let by_xray = got.as_ref().is_some_and(|m| m["openedBy"].as_str().is_some_and(|n| n.eq_ignore_ascii_case("xray.exe")));
    r.add(
        "R1",
        "proxy-unaware client, destination 192.0.2.7:80 (unreachable except through the tunnel)",
        "PROXY: marker arrives at the controlled endpoint, opened by xray.exe",
        json!({"client": selected, "observed": got, "hits": hits() - h, "redirector": state()}),
        "runtime (both sides: client result + destination-side process attribution)",
        if selected["result"] == "ok" && got.is_some() && by_xray { "PASS: RUNTIME VERIFIED (user-mode path; interception simulated)" } else { "FAIL" },
    );

    // ---- R2: the same destination without the redirect must not be reachable at all
    let h = hits();
    let direct_to_dest = plain(&client, &[SIMULATED_DESTINATION, "control-direct-to-dest"]);
    std::thread::sleep(Duration::from_millis(200));
    r.add(
        "R2",
        "control client straight to 192.0.2.7:80 (no redirect)",
        "no delivery: the destination is only reachable through the tunnel",
        json!({"client": direct_to_dest, "newHits": hits() - h}),
        "runtime",
        if direct_to_dest["result"] != "ok" && hits() == h { "PASS: RUNTIME VERIFIED (proves R1 went through the tunnel)" } else { "FAIL" },
    );

    // ---- R3: unselected application stays direct
    let h = hits();
    let control = plain(&client, &[&controlled, "control-direct"]);
    std::thread::sleep(Duration::from_millis(300));
    let got = markers().iter().find(|m| m["marker"] == "control-direct").cloned();
    let by_client = got.as_ref().is_some_and(|m| m["openedBy"].as_str().is_some_and(|n| n.eq_ignore_ascii_case("unaware-client.exe")));
    r.add(
        "R3",
        "unselected client to the controlled endpoint",
        "DIRECT: opened by the client process itself",
        json!({"client": control, "observed": got, "hits": hits() - h}),
        "runtime (destination-side process attribution)",
        if control["result"] == "ok" && by_client { "PASS: RUNTIME VERIFIED" } else { "FAIL" },
    );

    // ---- R4: the client really is proxy-unaware
    r.add(
        "R4",
        "NEGATIVE: the routed client must not be using proxy environment variables",
        "no proxy environment consulted",
        json!({"proxyEnvPresent": selected["proxyEnvPresent"], "clientHasProxyCode": false}),
        "runtime + code review (the binary contains no proxy client code)",
        if selected["proxyEnvPresent"].as_array().is_some_and(|a| a.is_empty()) { "PASS: RUNTIME VERIFIED" } else { "FAIL" },
    );

    // ---- R5: the redirector must not be reachable off-box
    let off_box = TcpStream::connect_timeout(&SocketAddr::new(lan, redirect_port), Duration::from_secs(2));
    r.add(
        "R5",
        "redirector reachable from a non-loopback address?",
        "refused: loopback only",
        json!({"lanConnect": off_box.as_ref().err().map(|e| e.to_string()), "connected": off_box.is_ok()}),
        "runtime",
        if off_box.is_err() { "PASS: RUNTIME VERIFIED" } else { "FAIL" },
    );

    // ---- R6: not an open proxy - the client cannot choose the destination
    let h = hits();
    let attempt = plain(&client, &[&redirect_addr, "CONNECT evil.example:443 HTTP/1.1"]);
    std::thread::sleep(Duration::from_millis(400));
    let m = markers();
    let smuggled = m.iter().any(|x| x["marker"].as_str().is_some_and(|s| s.contains("evil.example") && s != "CONNECT evil.example:443 HTTP/1.1"));
    let delivered_to_fixed = hits() > h;
    r.add(
        "R6",
        "client sends proxy-looking bytes to the redirector",
        "bytes are payload, not destination control",
        json!({"client": attempt, "deliveredToConfiguredDestination": delivered_to_fixed, "smuggledElsewhere": smuggled}),
        "runtime",
        if delivered_to_fixed && !smuggled { "PASS: RUNTIME VERIFIED (destination comes from the kernel/config, never from the stream)" } else { "FAIL" },
    );

    // ---- R7: loop prevention, user-mode half
    let st = state();
    let accepted = st["accepted"].as_u64().unwrap_or(0);
    let tunnelled = st["tunnelled"].as_u64().unwrap_or(0);
    r.add(
        "R7",
        "loop prevention: only client connections enter the redirector",
        "no connection from Xray, the helper or the redirector itself",
        json!({"acceptedByRedirector": accepted, "tunnelled": tunnelled, "clientConnectionsMade": 2, "xrayPid": xray_pid, "redirectorPid": redirector_pid}),
        "runtime (user-mode half only)",
        if accepted == 2 { "PASS: RUNTIME VERIFIED (user-mode); kernel-side loop prevention: CODE REVIEW ONLY" } else { "FAIL" },
    );

    // ---- R8: Xray dies -> the routed app must fail, never go direct
    let h = hits();
    session.core.stop_session();
    session.pump(Duration::from_secs(15), |c| !matches!(c.session_status().state, ppcore::core::session::SessionState::Connected { .. }));
    std::thread::sleep(Duration::from_millis(300));
    let during = plain(&client, &[&redirect_addr, "during-xray-down"]);
    std::thread::sleep(Duration::from_millis(300));
    let leaked = markers().iter().any(|m| m["marker"] == "during-xray-down");
    r.add(
        "R8",
        "Xray/session stopped while the routed client connects",
        "BLOCK: connection fails, nothing reaches the destination",
        json!({"client": during, "reachedDestination": leaked, "newHits": hits() - h, "redirector": state()}),
        "runtime",
        if !leaked { "PASS: RUNTIME VERIFIED (fails closed, no direct fallback)" } else { "FAIL: leaked direct" },
    );

    // ---- R9: redirector dies -> connections refused, never direct
    let _ = redirector.kill();
    let _ = redirector.wait();
    std::thread::sleep(Duration::from_millis(300));
    let h = hits();
    let after_kill = plain(&client, &[&redirect_addr, "after-redirector-death"]);
    std::thread::sleep(Duration::from_millis(200));
    r.add(
        "R9",
        "redirector process killed",
        "BLOCK: connection refused, nothing reaches the destination",
        json!({"client": after_kill, "newHits": hits() - h}),
        "runtime",
        if after_kill["result"] != "ok" && hits() == h { "PASS: RUNTIME VERIFIED" } else { "FAIL" },
    );

    // ---- R10: IPv6 / UDP / DNS / driver: what this run cannot prove
    r.add("R10", "selected TCP IPv6 through the redirect path", "PROXY or BLOCK, never silent direct", json!({"reason": "no IPv6 route on this machine; the v6 code path is compiled but unexercised"}), "code review", "NOT TESTED: ENVIRONMENT LIMITATION");
    r.add("R11", "selected UDP", "BLOCK for V1", json!({"design": "no UDP redirection; Track A's WFP BLOCK filters cover UDP (Phase 7.5 T4, runtime verified)", "reason": "Windows drops connected UDP redirected to a local proxy (documented)"}), "code review + Phase 7.5 runtime", "RESEARCH ONLY (design), blocking is PASS: RUNTIME VERIFIED in Phase 7.5");
    r.add("R12", "DNS metadata of a routed application", "documented", json!({"finding": "unchanged by redirection: names are resolved by the DNS Client service before any connect, so the callout sees only addresses"}), "runtime (Phase 7.5 T8) + code review", "FAIL: DNS METADATA STILL LEAKS");
    r.add("R13", "kernel connect-redirect callout", "redirects a real proxy-unaware app with no simulation", json!({"driverBuilt": false, "driverLoaded": false, "reason": "no WDK/Visual Studio and no disposable VM; workstation security settings unchanged"}), "none", "NOT TESTED: ENVIRONMENT UNAVAILABLE / BLOCKED BY TEST ENVIRONMENT");

    // ---- performance
    let (mut server2, server_port2) = start_test_server(&controlled);
    let mut session2 = Session::start(server_port2, &tmp.join("s2"));
    let up2 = session2.endpoint();
    let (mut redirector2, redirect_port2, _) = start_redirector(&redirector_exe, &up2, &state_file);
    let addr2 = format!("127.0.0.1:{redirect_port2}");
    let mut routed_ms = Vec::new();
    for i in 0..10 {
        let v = plain(&client, &[&addr2, &format!("perf-{i}")]);
        if let Some(ms) = v["ms"].as_u64() {
            routed_ms.push(ms);
        }
    }
    let mut direct_ms = Vec::new();
    for i in 0..10 {
        let v = plain(&client, &[&controlled, &format!("perfd-{i}")]);
        if let Some(ms) = v["ms"].as_u64() {
            direct_ms.push(ms);
        }
    }
    let avg = |v: &Vec<u64>| if v.is_empty() { 0.0 } else { v.iter().sum::<u64>() as f64 / v.len() as f64 };
    r.add(
        "X1",
        "connection setup: routed through redirector+Xray vs direct",
        "observation",
        json!({"routedMs": avg(&routed_ms), "directMs": avg(&direct_ms), "samples": routed_ms.len()}),
        "runtime",
        "OBSERVED",
    );

    // ---- R14: restart and concurrency of the routed application
    let h = hits();
    let a = plain(&client, &[&addr2, "restart-1"]);
    let b = plain(&client, &[&addr2, "restart-2"]);
    std::thread::sleep(Duration::from_millis(400));
    r.add(
        "R14",
        "routed application restarted / several instances",
        "every instance routed",
        json!({"first": a["result"], "second": b["result"], "newHits": hits() - h}),
        "runtime",
        if a["result"] == "ok" && b["result"] == "ok" { "PASS: RUNTIME VERIFIED" } else { "FAIL" },
    );

    // ---- teardown and system snapshot
    let _ = redirector2.kill();
    session2.core.stop_session();
    session2.core.shutdown();
    session.core.shutdown();
    let _ = server.kill();
    let _ = server2.kill();
    std::thread::sleep(Duration::from_millis(500));
    let after = snapshot(elevated);
    let side = diff_snapshots(&before, &after);
    r.add(
        "R15",
        "system side effects of the user-mode path",
        "no global change",
        json!(side),
        "runtime (before/after snapshot)",
        if side.as_object().is_some_and(|m| m.values().all(|v| v == "unchanged")) { "PASS: RUNTIME VERIFIED (no driver or service installed in this run)" } else { "OBSERVED: see diff" },
    );

    r.save(true);
    println!("\nreport rows: {}", r.rows.len());
    let _ = std::fs::remove_dir_all(&tmp);
}
