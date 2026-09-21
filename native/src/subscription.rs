//! Subscription fetching. The provider is an untrusted remote input.
//!
//! * HTTPS only (debug builds in test mode also accept plain HTTP to loopback test servers)
//! * destination policy (`netpolicy.rs`): no loopback, link-local/cloud-metadata, multicast or
//!   unspecified addresses; private networks only with the "Allow private-network subscription
//!   URLs" setting. Checked for the URL host, every redirect target, and, for direct fetches,
//!   every address the name resolves to (so DNS rebinding to 127.0.0.1 or 169.254.169.254 fails)
//! * no downgrade redirects, at most 5 redirects
//! * 10 s connect timeout, 20 s total timeout, 5 MiB body limit
//! * a fixed product User-Agent; no cookies, no machine identifiers
//! * fetched through the active tunnel when connected (`socks5h`, so DNS stays remote)

use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_BODY: u64 = crate::parse::MAX_INPUT_BYTES as u64;
pub const USER_AGENT: &str = concat!("PrivateProxy/", env!("CARGO_PKG_VERSION"));

/// Where a subscription may be fetched from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// Allow hosts on private networks (company-internal subscription servers).
    pub allow_private: bool,
}

fn is_loopback_host(u: &url::Url) -> bool {
    matches!(crate::netpolicy::classify_host(u.host_str().unwrap_or("")), crate::netpolicy::Class::Loopback)
}

/// Plain HTTP only to loopback test servers, only in debug test mode.
fn http_allowed(u: &url::Url) -> bool {
    is_loopback_host(u) && crate::test_flag("PRIVATE_PROXY_ALLOW_LOOPBACK")
}

fn check_target(u: &url::Url, policy: &Policy) -> Result<(), String> {
    match u.scheme() {
        "https" => {}
        "http" if http_allowed(u) => {}
        "http" => return Err("Subscription URL must use HTTPS".into()),
        _ => return Err("Subscription URL must start with https://".into()),
    }
    let host = u.host_str().filter(|h| !h.is_empty()).ok_or("Subscription URL has no host")?;
    crate::netpolicy::check_subscription_host(host, policy.allow_private)
}

/// Validates a subscription URL and returns it normalized.
pub fn validate_url(raw: &str, policy: &Policy) -> Result<url::Url, String> {
    let raw = raw.trim();
    if raw.len() > 4096 {
        return Err("Subscription URL is too long".into());
    }
    let u = url::Url::parse(raw).map_err(|_| "Subscription URL is not a valid URL".to_string())?;
    check_target(&u, policy)?;
    Ok(u)
}

/// Resolves names with the OS resolver and refuses the connection if any answer falls outside
/// the policy (DNS rebinding protection). Used for direct fetches only; through the tunnel the
/// name is resolved by the proxy server (socks5h).
struct GuardedResolver {
    policy: Policy,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = (host.as_str(), 0).to_socket_addrs()?.collect();
            check_resolved(&addrs, &policy)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn check_resolved(addrs: &[SocketAddr], policy: &Policy) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if addrs.is_empty() {
        return Err("Subscription host did not resolve".into());
    }
    for a in addrs {
        crate::netpolicy::check_subscription_ip(a.ip(), policy.allow_private)?;
    }
    Ok(())
}

pub fn display_host(u: &url::Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

pub fn fetch(raw_url: &str, via_socks_port: Option<u16>, policy: &Policy) -> Result<String, String> {
    fetch_with_timeout(raw_url, via_socks_port, policy, Duration::from_secs(20))
}

pub fn fetch_with_timeout(raw_url: &str, via_socks_port: Option<u16>, policy: &Policy, timeout: Duration) -> Result<String, String> {
    let u = validate_url(raw_url, policy)?;
    let pol = *policy;
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            attempt.error("too many redirects")
        } else if let Err(e) = check_target(attempt.url(), &pol) {
            attempt.error(e)
        } else {
            attempt.follow()
        }
    });
    let mut b = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10).min(timeout))
        .timeout(timeout)
        .redirect(redirect)
        .user_agent(USER_AGENT)
        .https_only(!http_allowed(&u));
    if let Some(port) = via_socks_port {
        let p = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        b = b.proxy(p);
    } else {
        // Direct: no system/env proxy, and every DNS answer is checked against the policy.
        b = b.no_proxy().dns_resolver(Arc::new(GuardedResolver { policy: *policy }));
    }
    let client = b.build().map_err(|e| format!("HTTP client error: {e}"))?;
    read_body(client.get(u).send().map_err(|e| describe(&e))?)
}

/// Status and size checks shared by every fetch.
fn read_body(resp: reqwest::blocking::Response) -> Result<String, String> {
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("Subscription server returned HTTP {}", status.as_u16()));
    }
    if resp.content_length().is_some_and(|l| l > MAX_BODY) {
        return Err("Subscription is too large".into());
    }
    let mut body = Vec::new();
    resp.take(MAX_BODY + 1).read_to_end(&mut body).map_err(|e| format!("Reading subscription failed: {e}"))?;
    if body.len() as u64 > MAX_BODY {
        return Err("Subscription is too large".into());
    }
    String::from_utf8(body).map_err(|_| "Subscription is not valid UTF-8 text".into())
}

fn describe(e: &reqwest::Error) -> String {
    // Surface our own policy refusals (from the resolver or redirect policy) verbatim.
    let mut src: Option<&dyn std::error::Error> = Some(e);
    while let Some(x) = src {
        let m = x.to_string();
        if m.starts_with("Subscription URL") || m.starts_with("Subscription host") {
            return m;
        }
        src = x.source();
    }
    if e.is_timeout() {
        "Subscription request timed out".into()
    } else if e.is_connect() {
        "Could not connect to the subscription server".into()
    } else if e.is_redirect() {
        "Subscription redirect was refused".into()
    } else {
        // reqwest errors can embed the URL (with its token); redact defensively.
        crate::log::redact(&format!("Subscription request failed: {e}"))
    }
}

/// Transfer limits without the URL policy, for the unit tests below (they use a plain-HTTP
/// server on 127.0.0.1, which the policy refuses outside test mode).
#[cfg(test)]
fn transfer(url: &str, timeout: Duration) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10).min(timeout))
        .timeout(timeout)
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    read_body(client.get(url).send().map_err(|e| describe(&e))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        let p = Policy::default();
        assert!(validate_url("https://sub.example.com/x?token=1", &p).is_ok());
        assert!(validate_url("http://sub.example.com/x", &p).is_err());
        assert!(validate_url("file:///etc/passwd", &p).is_err());
        assert!(validate_url("javascript:alert(1)", &p).is_err());
        assert!(validate_url("not a url", &p).is_err());
        // SSRF: local and metadata destinations (release policy; unit tests run without test mode).
        for u in [
            "http://127.0.0.1:8080/x",
            "https://127.0.0.1/x",
            "https://localhost/x",
            "https://[::1]/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://[fd00:ec2::254]/",
            "https://0.0.0.0/",
            "https://2130706433/", // 127.0.0.1 as a decimal integer (the URL parser normalizes it)
            "https://0x7f.1/",
        ] {
            assert!(validate_url(u, &p).is_err(), "{u}");
        }
        assert!(validate_url("https://10.0.0.8/sub", &p).unwrap_err().contains("private network"));
        assert!(validate_url("https://10.0.0.8/sub", &Policy { allow_private: true }).is_ok());
        assert!(validate_url("https://127.0.0.1/sub", &Policy { allow_private: true }).is_err());
    }

    #[test]
    fn dns_answers_are_checked() {
        let p = Policy::default();
        let a = |s: &str| -> SocketAddr { format!("{s}:0").parse().unwrap() };
        assert!(check_resolved(&[a("93.184.216.34")], &p).is_ok());
        assert!(check_resolved(&[a("93.184.216.34"), a("127.0.0.1")], &p).is_err());
        assert!(check_resolved(&[a("169.254.169.254")], &Policy { allow_private: true }).is_err());
        assert!(check_resolved(&[a("192.168.1.10")], &p).is_err());
        assert!(check_resolved(&[a("192.168.1.10")], &Policy { allow_private: true }).is_ok());
        assert!(check_resolved(&[], &p).is_err());
    }

    #[test]
    fn timeout_and_size_limit() {
        use std::io::Write;
        use std::net::TcpListener;
        // Server that accepts and never answers -> timeout.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _conns: Vec<_> = l.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let t = std::time::Instant::now();
        let e = transfer(&format!("http://127.0.0.1:{port}/sub"), Duration::from_secs(2)).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(6));

        // Oversized body.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = l.incoming().next() {
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                let chunk = vec![b'A'; 64 * 1024];
                for _ in 0..(MAX_BODY / chunk.len() as u64 + 2) {
                    if s.write_all(&chunk).is_err() {
                        break;
                    }
                }
            }
        });
        let e = transfer(&format!("http://127.0.0.1:{port}/sub"), Duration::from_secs(20)).unwrap_err();
        assert!(e.contains("too large"), "{e}");
    }
}
