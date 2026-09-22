//! EXPERIMENTAL test client for the per-app routing PoC. Prints one JSON line.
//!
//!   poc-client http <url>          honours HTTP(S)_PROXY / NO_PROXY like curl (Basic credentials in the URL)
//!   poc-client raw <url>           no proxy support at all: resolves locally, connects directly
//!   poc-client tcp <ip:port>       direct TCP connect to an address literal (IPv4 or [IPv6])
//!   poc-client udp <ip:port>       one UDP datagram to an address literal
//!   poc-client dns <name>          system resolver lookup
//!   poc-client child <args...>     runs itself again with <args> (environment inherited)
//!   poc-client shell-child <url>   cmd.exe /c curl.exe <url>: an unrelated program started through a shell
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

fn proxy_for(host: &str) -> Option<(String, u16, Option<(String, String)>)> {
    let raw = ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"].iter().find_map(|k| std::env::var(k).ok())?;
    let no = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")).unwrap_or_default();
    if no.split(',').any(|n| !n.trim().is_empty() && host.eq_ignore_ascii_case(n.trim())) {
        return None;
    }
    let rest = raw.strip_prefix("http://")?;
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (a.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())), h.trim_end_matches('/')),
        None => (None, rest.trim_end_matches('/')),
    };
    let (h, p) = hostport.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?, auth))
}

fn split_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (h, p) = hostport.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80))).unwrap_or((hostport.to_string(), 80));
    Some((h, p, path))
}

fn status_line(mut s: TcpStream, req: String) -> Result<String, String> {
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

fn connect(addr: &str) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))?.collect();
    let a = addrs.first().ok_or("no address")?;
    TcpStream::connect_timeout(a, Duration::from_secs(3)).map_err(|e| format!("connect {a}: {e} (os {})", e.raw_os_error().unwrap_or(0)))
}

fn http(url: &str, honour_env: bool) -> serde_json::Value {
    let Some((host, port, path)) = split_url(url) else { return json!({"error": "bad url"}) };
    let t0 = Instant::now();
    let proxy = if honour_env { proxy_for(&host) } else { None };
    let result = match &proxy {
        Some((ph, pp, auth)) => connect(&format!("{ph}:{pp}")).and_then(|s| {
            use base64::Engine;
            let a = auth.as_ref().map(|(u, p)| format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))).unwrap_or_default();
            status_line(s, format!("GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\n{a}Connection: close\r\n\r\n"))
        }),
        None => connect(&format!("{host}:{port}")).and_then(|s| status_line(s, format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"))),
    };
    json!({ "via": if proxy.is_some() { "proxy" } else { "direct" }, "result": result.unwrap_or_else(|e| format!("error: {e}")), "ms": t0.elapsed().as_millis() as u64 })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    let out = match arg(0).as_str() {
        "http" => http(&arg(1), true),
        "raw" => http(&arg(1), false),
        "tcp" => {
            let a: Result<SocketAddr, _> = arg(1).parse();
            match a {
                Ok(a) => match TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
                    Ok(_) => json!({"result": "connected"}),
                    Err(e) => json!({"result": format!("error: {e}"), "os": e.raw_os_error()}),
                },
                Err(e) => json!({"error": e.to_string()}),
            }
        }
        "udp" => {
            let a: SocketAddr = match arg(1).parse() {
                Ok(a) => a,
                Err(e) => return println!("{}", json!({"error": e.to_string()})),
            };
            let bind = if a.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let r = UdpSocket::bind(bind).and_then(|s| s.send_to(b"poc", a));
            match r {
                Ok(n) => json!({"result": format!("sent {n} bytes")}),
                Err(e) => json!({"result": format!("error: {e}"), "os": e.raw_os_error()}),
            }
        }
        "dns" => match (arg(1).as_str(), 80).to_socket_addrs() {
            Ok(a) => json!({"result": format!("resolved {:?}", a.collect::<Vec<_>>())}),
            Err(e) => json!({"result": format!("error: {e}")}),
        },
        "child" => {
            let me = std::env::current_exe().unwrap();
            let o = std::process::Command::new(me).args(&args[1..]).output();
            match o {
                Ok(o) => json!({"child": serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap_or(json!(String::from_utf8_lossy(&o.stdout)))}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }
        "shell-child" => {
            let sys = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32");
            // cmd.exe parses its own command line: pass it verbatim (Rust's argument escaping is not
            // what cmd expects). Test-only: the URL comes from the harness.
            use std::os::windows::process::CommandExt;
            let cmdline = format!("/d /c \"\"{}\" -s -o NUL -w %{{http_code}} --max-time 8 {}\"", sys.join("curl.exe").display(), arg(1));
            let o = std::process::Command::new(sys.join("cmd.exe")).raw_arg(cmdline).output();
            match o {
                Ok(o) => json!({"shellChild": "cmd.exe -> curl.exe", "httpCode": String::from_utf8_lossy(&o.stdout).trim()}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }
        m => json!({"error": format!("unknown mode {m:?}")}),
    };
    println!("{out}");
}
