//! EXPERIMENTAL Phase 8 local redirector.
//!
//!   redirector --port <p> --upstream <proxyPort> --user <u> --pass-env <ENVVAR>
//!              [--simulate-destination <ip:port>] [--state <file.json>]
//!
//! Loopback only. For each accepted connection it recovers the original destination (from the WFP
//! redirect context if a driver is present, otherwise from `--simulate-destination`) and tunnels the
//! stream through the product's authenticated local inbound into Xray.
//!
//! Security properties this binary must keep (§32):
//! * binds 127.0.0.1 only — never a LAN address, never a wildcard;
//! * it is not an open proxy: the destination is decided by the kernel context or by the single
//!   configured simulation value, never by anything the client sends;
//! * credentials arrive through an environment variable from the parent and are never logged;
//! * a connection whose destination cannot be established is closed, never forwarded anywhere.
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use windows_redirector_poc::{original_destination_from_wfp, pump, tunnel_through_proxy, RedirectSource, UpstreamProxy};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = arg(&args, "--port").and_then(|v| v.parse().ok()).unwrap_or(0);
    let upstream_port: u16 = arg(&args, "--upstream").and_then(|v| v.parse().ok()).expect("--upstream <port>");
    let user = arg(&args, "--user").unwrap_or_default();
    let pass = arg(&args, "--pass-env").and_then(|k| std::env::var(k).ok()).unwrap_or_default();
    let simulated: Option<SocketAddr> = arg(&args, "--simulate-destination").and_then(|v| v.parse().ok());
    let state_file = arg(&args, "--state");

    let upstream = UpstreamProxy { port: upstream_port, user, pass };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("bind loopback");
    let bound = listener.local_addr().unwrap().port();

    let accepted = Arc::new(AtomicU64::new(0));
    let tunnelled = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));

    // One line of machine-readable startup state; the harness waits for it.
    println!("{}", serde_json::json!({
        "event": "listening",
        "port": bound,
        "pid": std::process::id(),
        "destinationSource": if simulated.is_some() { RedirectSource::Simulated.as_str() } else { RedirectSource::Wfp.as_str() },
    }));
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let upstream = upstream.clone();
        let (accepted, tunnelled, refused) = (accepted.clone(), tunnelled.clone(), refused.clone());
        let state_file = state_file.clone();
        std::thread::spawn(move || {
            accepted.fetch_add(1, Ordering::Relaxed);
            // Counters are written as soon as they change, so a reader never sees a stale count
            // while a connection is still being pumped.
            let write_state = |extra: serde_json::Value| {
                if let Some(path) = &state_file {
                    let mut v = serde_json::json!({
                        "accepted": accepted.load(Ordering::Relaxed),
                        "tunnelled": tunnelled.load(Ordering::Relaxed),
                        "refused": refused.load(Ordering::Relaxed),
                    });
                    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
                        for (k, val) in e {
                            o.insert(k.clone(), val.clone());
                        }
                    }
                    let _ = std::fs::write(path, v.to_string());
                }
            };
            write_state(serde_json::json!({}));

            // Prefer the kernel's answer; fall back to the simulated destination.
            let (dest, source) = match original_destination_from_wfp(&stream) {
                Ok(Some(addr)) => (Some(addr), RedirectSource::Wfp),
                _ => (simulated, RedirectSource::Simulated),
            };
            let Some(dest) = dest else {
                // No destination: close. Never guess, never forward.
                refused.fetch_add(1, Ordering::Relaxed);
                write_state(serde_json::json!({"lastError": "no original destination available"}));
                return;
            };

            match tunnel_through_proxy(&upstream, &dest.to_string()) {
                Ok(up) => {
                    tunnelled.fetch_add(1, Ordering::Relaxed);
                    write_state(serde_json::json!({"lastDestination": dest.to_string(), "destinationSource": source.as_str()}));
                    let (sent, received) = pump(stream, up);
                    write_state(serde_json::json!({
                        "lastDestination": dest.to_string(),
                        "destinationSource": source.as_str(),
                        "lastBytes": { "clientToUpstream": sent, "upstreamToClient": received },
                    }));
                }
                Err(e) => {
                    // Fail closed: the client's connection dies with us, it never goes direct.
                    refused.fetch_add(1, Ordering::Relaxed);
                    write_state(serde_json::json!({"lastError": e}));
                }
            }
        });
    }
}
