//! Subscription fetching. The provider is an untrusted remote input.
//!
//! * HTTPS only (plain HTTP is allowed for loopback addresses, used by tests)
//! * no downgrade redirects, at most 5 redirects
//! * 10 s connect timeout, 20 s total timeout, 5 MiB body limit
//! * a fixed product User-Agent; no cookies, no machine identifiers
//! * fetched through the active tunnel when connected (`socks5h`, so DNS stays remote)

use std::io::Read;
use std::time::Duration;

pub const MAX_BODY: u64 = crate::parse::MAX_INPUT_BYTES as u64;
pub const USER_AGENT: &str = concat!("PrivateProxy/", env!("CARGO_PKG_VERSION"));

fn is_loopback_host(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Validates a subscription URL and returns it normalized.
pub fn validate_url(raw: &str) -> Result<url::Url, String> {
    let raw = raw.trim();
    if raw.len() > 4096 {
        return Err("Subscription URL is too long".into());
    }
    let u = url::Url::parse(raw).map_err(|_| "Subscription URL is not a valid URL".to_string())?;
    match u.scheme() {
        "https" => {}
        "http" if is_loopback_host(&u) => {}
        "http" => return Err("Subscription URL must use HTTPS".into()),
        _ => return Err("Subscription URL must start with https://".into()),
    }
    if u.host_str().is_none_or(|h| h.is_empty()) {
        return Err("Subscription URL has no host".into());
    }
    Ok(u)
}

pub fn display_host(u: &url::Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

pub fn fetch(raw_url: &str, via_socks_port: Option<u16>) -> Result<String, String> {
    fetch_with_timeout(raw_url, via_socks_port, Duration::from_secs(20))
}

pub fn fetch_with_timeout(raw_url: &str, via_socks_port: Option<u16>, timeout: Duration) -> Result<String, String> {
    let u = validate_url(raw_url)?;
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            attempt.error("too many redirects")
        } else if attempt.url().scheme() != "https" && !is_loopback_host(attempt.url()) {
            attempt.error("redirect to a non-HTTPS URL")
        } else {
            attempt.follow()
        }
    });
    let mut b = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10).min(timeout))
        .timeout(timeout)
        .redirect(redirect)
        .user_agent(USER_AGENT)
        .https_only(!is_loopback_host(&u));
    if let Some(port) = via_socks_port {
        let p = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        b = b.proxy(p);
    } else {
        b = b.no_proxy();
    }
    let client = b.build().map_err(|e| format!("HTTP client error: {e}"))?;
    let resp = client.get(u).send().map_err(|e| describe(&e))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert!(validate_url("https://sub.example.com/x?token=1").is_ok());
        assert!(validate_url("http://sub.example.com/x").is_err());
        assert!(validate_url("http://127.0.0.1:8080/x").is_ok());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
        assert!(validate_url("not a url").is_err());
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
        let e = fetch_with_timeout(&format!("http://127.0.0.1:{port}/sub"), None, Duration::from_secs(2)).unwrap_err();
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
        let e = fetch(&format!("http://127.0.0.1:{port}/sub"), None).unwrap_err();
        assert!(e.contains("too large"), "{e}");
    }
}
