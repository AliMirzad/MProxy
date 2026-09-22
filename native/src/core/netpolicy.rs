//! Destination policy for addresses that come from untrusted input (imported server addresses,
//! subscription URLs and their DNS answers). See docs/threat-model.md, "SSRF".
//!
//! | Class      | Examples                                          | Proxy server address | Subscription URL |
//! |------------|---------------------------------------------------|----------------------|------------------|
//! | Public     | 203.0.113.7, example.com                          | allowed              | allowed          |
//! | Private    | 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, `*.internal`, `*.local`, `*.lan` | allowed (company-hosted servers) | only with the "Allow private-network subscription URLs" setting |
//! | Loopback   | 127/8, ::1, `localhost`                           | rejected             | rejected         |
//! | Forbidden  | 0.0.0.0/8, ::, link-local 169.254/16 and fe80::/10 (cloud metadata 169.254.169.254, fd00:ec2::254), multicast, broadcast, reserved 240/4, `metadata.google.internal` | rejected | rejected |
//!
//! Loopback is allowed only by debug builds in test mode (`PRIVATE_PROXY_ALLOW_LOOPBACK=1`), because
//! the automated tests run their VLESS/VMess and subscription servers on 127.0.0.1.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Public,
    Private,
    Loopback,
    Forbidden(&'static str),
}

pub fn classify_ip(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Class {
    let o = ip.octets();
    match o {
        [0, ..] => Class::Forbidden("unspecified address"),
        [127, ..] => Class::Loopback,
        [169, 254, ..] => Class::Forbidden("link-local address (includes cloud metadata services)"),
        [255, 255, 255, 255] => Class::Forbidden("broadcast address"),
        [a, ..] if (224..=239).contains(&a) => Class::Forbidden("multicast address"),
        [a, ..] if a >= 240 => Class::Forbidden("reserved address"),
        [10, ..] | [192, 168, ..] => Class::Private,
        [172, b, ..] if (16..=31).contains(&b) => Class::Private,
        [100, b, ..] if (64..=127).contains(&b) => Class::Private, // carrier-grade NAT
        _ => Class::Public,
    }
}

fn classify_v6(ip: Ipv6Addr) -> Class {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Class::Forbidden("unspecified address");
    }
    if ip.is_loopback() {
        return Class::Loopback;
    }
    // Embedded IPv4: mapped ::ffff:a.b.c.d, NAT64 64:ff9b::/96, deprecated compatible ::a.b.c.d.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] || s[0..6] == [0, 0, 0, 0, 0, 0] {
        return classify_v4(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
    }
    if s[0] == 0x2002 {
        // 6to4 embeds the IPv4 address in segments 1-2.
        return classify_v4(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
    }
    if ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) {
        return Class::Forbidden("cloud metadata service");
    }
    match s[0] {
        x if x & 0xffc0 == 0xfe80 => Class::Forbidden("link-local address"),
        x if x & 0xff00 == 0xff00 => Class::Forbidden("multicast address"),
        x if x & 0xfe00 == 0xfc00 => Class::Private, // unique local
        x if x & 0xffc0 == 0xfec0 => Class::Private, // deprecated site-local
        _ => Class::Public,
    }
}

const METADATA_NAMES: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata", "instance-data", "instance-data.ec2.internal"];
const PRIVATE_SUFFIXES: &[&str] = &[".internal", ".local", ".lan", ".home.arpa", ".intranet", ".corp", ".localdomain", ".private"];

/// Classifies a host given as IP literal or DNS name (names are classified by well-known
/// patterns only; their DNS answers are checked separately where we resolve them).
pub fn classify_host(host: &str) -> Class {
    let h = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    if h == "localhost" || h.ends_with(".localhost") || h == "localhost.localdomain" || h == "ip6-localhost" || h == "ip6-loopback" {
        return Class::Loopback;
    }
    if METADATA_NAMES.contains(&h.as_str()) {
        return Class::Forbidden("cloud metadata service");
    }
    if !h.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s)) {
        return Class::Private; // single-label intranet names and private-use suffixes
    }
    Class::Public
}

fn loopback_allowed_for_tests() -> bool {
    crate::test_flag("PRIVATE_PROXY_ALLOW_LOOPBACK")
}

/// Proxy server addresses (VLESS/VMess `address`, XHTTP `downloadSettings.address`).
/// Private networks are allowed so company-hosted proxy servers work.
pub fn check_server_address(host: &str) -> Result<(), String> {
    match classify_host(host) {
        Class::Public | Class::Private => Ok(()),
        Class::Loopback if loopback_allowed_for_tests() => Ok(()),
        Class::Loopback => Err(format!("Server address \"{}\" points to this computer (loopback); refusing", crate::core::validate::truncate(host, 64))),
        Class::Forbidden(why) => Err(format!("Server address \"{}\" is not allowed: {why}", crate::core::validate::truncate(host, 64))),
    }
}

/// Subscription (control-plane) destinations: host literals and, when fetched directly, every
/// address the name resolves to.
pub fn check_subscription_host(host: &str, allow_private: bool) -> Result<(), String> {
    check_subscription_class(classify_host(host), allow_private)
}

pub fn check_subscription_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
    check_subscription_class(classify_ip(ip), allow_private)
}

fn check_subscription_class(c: Class, allow_private: bool) -> Result<(), String> {
    match c {
        Class::Public => Ok(()),
        Class::Private if allow_private => Ok(()),
        Class::Private => Err("Subscription URL points to a private network address. Enable \"Allow private-network subscription URLs\" in Settings if this is your company's server.".into()),
        Class::Loopback if loopback_allowed_for_tests() => Ok(()),
        Class::Loopback => Err("Subscription URL points to this computer (localhost); refusing".into()),
        Class::Forbidden(why) => Err(format!("Subscription URL is not allowed: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        use Class::*;
        for (h, want) in [
            ("8.8.8.8", Public),
            ("example.com", Public),
            ("10.1.2.3", Private),
            ("172.20.0.1", Private),
            ("192.168.1.1", Private),
            ("100.64.0.1", Private),
            ("fd12::1", Private),
            ("vpn.corp", Private),
            ("server.internal", Private),
            ("intranet-host", Private),
            ("127.0.0.1", Loopback),
            ("127.8.9.10", Loopback),
            ("::1", Loopback),
            ("[::1]", Loopback),
            ("localhost", Loopback),
            ("LOCALHOST.", Loopback),
            ("a.localhost", Loopback),
            ("::ffff:127.0.0.1", Loopback),
            ("64:ff9b::7f00:1", Loopback),
        ] {
            assert_eq!(classify_host(h), want, "{h}");
        }
        for h in [
            "0.0.0.0",
            "::",
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fe80::1",
            "fd00:ec2::254",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "240.0.0.1",
            "metadata.google.internal",
            "2002:a9fe:a9fe::1",
        ] {
            assert!(matches!(classify_host(h), Forbidden(_)), "{h}");
        }
    }

    #[test]
    fn policies() {
        // Test mode is off in unit tests, so loopback is refused like in release builds.
        assert!(check_server_address("10.0.0.5").is_ok());
        assert!(check_server_address("vpn.example.com").is_ok());
        assert!(check_server_address("127.0.0.1").is_err());
        assert!(check_server_address("localhost").is_err());
        assert!(check_server_address("169.254.169.254").is_err());
        assert!(check_subscription_host("sub.example.com", false).is_ok());
        assert!(check_subscription_host("10.0.0.5", false).is_err());
        assert!(check_subscription_host("10.0.0.5", true).is_ok());
        assert!(check_subscription_host("127.0.0.1", true).is_err());
        assert!(check_subscription_host("metadata.google.internal", true).is_err());
        assert!(check_subscription_ip("169.254.169.254".parse().unwrap(), true).is_err());
    }
}
