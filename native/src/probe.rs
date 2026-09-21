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

/// Performs one HTTP request through the local authenticated HTTP proxy inbound (exactly the
/// path the browser uses: the hostname goes to the proxy unresolved) and returns the status line.
pub fn probe_once(port: u16, auth: &crate::xrayconf::IdeAuth, t: &Target, timeout: Duration) -> Result<String, ProbeError> {
    use base64::Engine;
    let deadline = Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| ProbeError::Local(format!("local proxy not reachable: {e}")))?;
    s.set_nodelay(true).ok();
    let io = |e: std::io::Error| ProbeError::Remote(format!("connection through the server failed: {e}"));
    s.set_write_timeout(Some(remaining())).ok();
    s.set_read_timeout(Some(remaining())).ok();
    let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.user, auth.pass));
    let req = format!(
        "GET http://{h}:{p}{path} HTTP/1.1\r\nHost: {h}:{p}\r\nProxy-Authorization: Basic {cred}\r\nUser-Agent: {ua}\r\nConnection: close\r\n\r\n",
        h = t.host,
        p = t.port,
        path = t.path,
        ua = crate::subscription::USER_AGENT
    );
    s.write_all(req.as_bytes()).map_err(io)?;
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 256 {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => line.push(b[0]),
            Err(e) => return Err(io(e)),
        }
    }
    let line = String::from_utf8_lossy(&line).trim().to_string();
    let code = line.split_whitespace().nth(1).unwrap_or("");
    match code {
        "" => Err(ProbeError::Remote("no response through the server".into())),
        "407" => Err(ProbeError::Local("the local proxy rejected its own credentials".into())),
        "502" | "503" | "504" => Err(ProbeError::Remote(format!("the server could not reach the probe target ({line})"))),
        _ => Ok(line),
    }
}

pub fn probe(port: u16, auth: &crate::xrayconf::IdeAuth, targets: &[Target], per_target: Duration, cancelled: &dyn Fn() -> bool) -> Result<String, ProbeError> {
    let mut last = ProbeError::Remote("no probe targets".into());
    for t in targets {
        if cancelled() {
            return Err(ProbeError::Local("cancelled".into()));
        }
        match probe_once(port, auth, t, per_target) {
            Ok(l) => return Ok(l),
            Err(e @ ProbeError::Local(_)) => return Err(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}
