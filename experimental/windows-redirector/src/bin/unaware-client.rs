//! EXPERIMENTAL Phase 8 proxy-unaware client (§12).
//!
//!   unaware-client <ip:port> <marker>
//!
//! It opens one plain TCP connection to an address literal and sends a marker line. It has no proxy
//! support of any kind: it never reads HTTP_PROXY/ALL_PROXY, has no SOCKS or HTTP proxy code, and
//! takes no proxy arguments. It also reports which proxy environment variables were present, so a
//! run cannot later be explained away as "it picked up the environment".
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_default();
    let marker = args.get(1).cloned().unwrap_or_else(|| "none".into());

    let proxy_env: Vec<String> = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .filter(|k| std::env::var(k).is_ok())
        .map(|k| k.to_string())
        .collect();

    let Ok(addr) = target.parse::<SocketAddr>() else {
        println!("{}", serde_json::json!({"result": format!("bad address {target:?}")}));
        return;
    };

    let t0 = Instant::now();
    let out = match TcpStream::connect_timeout(&addr, Duration::from_secs(8)) {
        Ok(mut s) => {
            s.set_read_timeout(Some(Duration::from_secs(8))).ok();
            let local = s.local_addr().map(|a| a.port()).unwrap_or(0);
            match s.write_all(format!("MARKER {marker}\n").as_bytes()) {
                Ok(()) => {
                    let mut line = String::new();
                    match BufReader::new(&s).read_line(&mut line) {
                        Ok(_) => serde_json::json!({
                            "result": "ok",
                            "reply": line.trim(),
                            "localPort": local,
                            "ms": t0.elapsed().as_millis() as u64,
                        }),
                        Err(e) => serde_json::json!({"result": format!("read error: {e}"), "os": e.raw_os_error()}),
                    }
                }
                Err(e) => serde_json::json!({"result": format!("write error: {e}"), "os": e.raw_os_error()}),
            }
        }
        Err(e) => serde_json::json!({"result": format!("connect error: {e}"), "os": e.raw_os_error()}),
    };

    let mut out = out;
    out["proxyEnvPresent"] = serde_json::json!(proxy_env);
    out["target"] = serde_json::json!(target);
    println!("{out}");
}
