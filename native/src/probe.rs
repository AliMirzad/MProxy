//! End-to-end connectivity probe through the local SOCKS5 inbound.
//!
//! A successful probe proves the whole path: local inbound -> Xray -> selected
//! VLESS/VMess server -> Internet. The target hostname is sent to the proxy unresolved
//! (SOCKS5 ATYP=domain), exactly like the browser does, so no local DNS lookup happens.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Default probe targets: well-known "connectivity check" endpoints that return 204.
pub fn default_targets() -> Vec<Target> {
    if let Some(v) = crate::test_hook("PRIVATE_PROXY_PROBE_URL").and_then(|v| v.into_string().ok()) {
        // Test hook: "host:port/path".
        if let Some((hp, path)) = v.split_once('/') {
            if let Some((h, p)) = hp.rsplit_once(':') {
                if let Ok(port) = p.parse() {
                    return vec![Target { host: h.into(), port, path: format!("/{path}") }];
                }
            }
        }
    }
    vec![
        Target { host: "www.gstatic.com".into(), port: 80, path: "/generate_204".into() },
        Target { host: "cp.cloudflare.com".into(), port: 80, path: "/generate_204".into() },
    ]
}

#[derive(Debug)]
pub enum ProbeError {
    /// The local inbound itself misbehaved.
    Local(String),
    /// The server could not be reached / refused the connection.
    Remote(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Local(s) | ProbeError::Remote(s) => f.write_str(s),
        }
    }
}

/// Performs one HTTP request through SOCKS5 and returns the HTTP status line.
pub fn probe_once(socks_port: u16, t: &Target, timeout: Duration) -> Result<String, ProbeError> {
    let deadline = Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| ProbeError::Local(format!("local proxy not reachable: {e}")))?;
    s.set_nodelay(true).ok();
    let io = |e: std::io::Error| ProbeError::Remote(format!("connection through the server failed: {e}"));

    s.set_write_timeout(Some(remaining())).ok();
    s.set_read_timeout(Some(remaining())).ok();
    s.write_all(&[5, 1, 0]).map_err(|e| ProbeError::Local(e.to_string()))?;
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).map_err(|e| ProbeError::Local(format!("SOCKS greeting failed: {e}")))?;
    if rep != [5, 0] {
        return Err(ProbeError::Local("local SOCKS inbound rejected the greeting".into()));
    }
    let host = t.host.as_bytes();
    if host.len() > 255 {
        return Err(ProbeError::Local("probe host too long".into()));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&t.port.to_be_bytes());
    s.write_all(&req).map_err(io)?;
    s.set_read_timeout(Some(remaining())).ok();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).map_err(io)?;
    if head[1] != 0 {
        return Err(ProbeError::Remote(format!("proxy refused the connection (SOCKS code {})", head[1])));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).map_err(io)?;
            l[0] as usize + 2
        }
        _ => return Err(ProbeError::Local("malformed SOCKS reply".into())),
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).map_err(io)?;

    let http = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        t.path, t.host
    );
    s.set_write_timeout(Some(remaining())).ok();
    s.write_all(http.as_bytes()).map_err(io)?;
    s.set_read_timeout(Some(remaining())).ok();
    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    while !got.contains(&b'\n') && got.len() < 512 {
        let n = s.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
    if line.starts_with("HTTP/1.") {
        Ok(line)
    } else {
        Err(ProbeError::Remote("no response through the server (check the server address, credentials and transport settings)".into()))
    }
}

/// Tries each target until one succeeds. `cancelled` is polled between attempts.
pub fn probe(socks_port: u16, targets: &[Target], per_target: Duration, cancelled: &dyn Fn() -> bool) -> Result<String, ProbeError> {
    let mut last = ProbeError::Remote("no probe targets".into());
    for t in targets {
        if cancelled() {
            return Err(ProbeError::Local("cancelled".into()));
        }
        match probe_once(socks_port, t, per_target) {
            Ok(l) => return Ok(l),
            Err(e @ ProbeError::Local(_)) => return Err(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}
