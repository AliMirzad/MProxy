//! Validation and normalization of individual fields and of whole servers.
//!
//! Everything here treats its input as hostile: imported links, JSON and subscription
//! bodies all end up in these functions before anything is stored or handed to Xray.

use crate::model::*;
use base64::Engine;
use serde_json::{Map, Value};

pub type VResult<T> = Result<T, String>;

pub const MAX_NAME_LEN: usize = 100;
const MAX_FIELD_LEN: usize = 1024;

/// Reject control characters and over-long values; trim whitespace.
pub fn clean_text(field: &str, v: &str, max: usize) -> VResult<String> {
    let v = v.trim();
    if v.chars().count() > max {
        return Err(format!("{field} is too long"));
    }
    if v.chars().any(|c| c.is_control()) {
        return Err(format!("{field} contains control characters"));
    }
    Ok(v.to_string())
}

pub fn opt_text(field: &str, v: Option<&str>, max: usize) -> VResult<Option<String>> {
    match v {
        None => Ok(None),
        Some(s) => {
            let s = clean_text(field, s, max)?;
            Ok(if s.is_empty() { None } else { Some(s) })
        }
    }
}

/// Display names: control characters are stripped rather than rejected, then truncated.
pub fn clean_name(v: &str, fallback: &str) -> String {
    let s: String = v.chars().filter(|c| !c.is_control()).collect();
    let s = s.trim();
    let s = if s.is_empty() { fallback } else { s };
    s.chars().take(MAX_NAME_LEN).collect()
}

/// Validates a server address. Returns the normalized form (IDN -> punycode, IPv6
/// without brackets, lowercase domain).
pub fn address(v: &str) -> VResult<String> {
    let v = v.trim();
    if v.is_empty() {
        return Err("Server address is empty".into());
    }
    if v.len() > 253 {
        return Err("Server address is too long".into());
    }
    let unbracketed = v.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    // Domain: url's host parser applies IDNA and rejects forbidden code points.
    match url::Host::parse(v) {
        Ok(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let ok = !d.is_empty()
                && d.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                });
            if ok {
                Ok(d)
            } else {
                Err(format!("\"{}\" is not a valid host name", truncate(v, 64)))
            }
        }
        Ok(url::Host::Ipv4(ip)) => Ok(ip.to_string()),
        Ok(url::Host::Ipv6(ip)) => Ok(ip.to_string()),
        Err(_) => Err(format!("\"{}\" is not a valid host name", truncate(v, 64))),
    }
}

pub fn port_from_str(v: &str) -> VResult<u16> {
    let v = v.trim();
    match v.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => Err(format!("Invalid port \"{}\"", truncate(v, 16))),
    }
}

pub fn port_from_json(v: &Value) -> VResult<u16> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .map(|p| p as u16)
            .ok_or_else(|| "Invalid port".to_string()),
        Value::String(s) => port_from_str(s),
        _ => Err("Invalid port".into()),
    }
}

/// VLESS/VMess user id: a UUID, or (Xray extension) any 1-30 byte string that Xray maps
/// to a UUIDv5.
pub fn user_id(v: &str) -> VResult<String> {
    let v = v.trim();
    if let Ok(u) = uuid::Uuid::parse_str(v) {
        return Ok(u.hyphenated().to_string());
    }
    if !v.is_empty() && v.len() <= 30 && !v.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Ok(v.to_string());
    }
    Err("Invalid user ID (expected a UUID)".into())
}

pub const FLOWS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp443"];

pub fn flow(v: &str) -> VResult<String> {
    let v = v.trim();
    if v.is_empty() || v == "none" {
        return Ok(String::new());
    }
    if FLOWS.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(format!("Unsupported flow \"{}\"", truncate(v, 40)))
    }
}

pub const VMESS_CIPHERS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"];

pub fn vmess_cipher(v: Option<&str>) -> VResult<String> {
    let v = v.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    if VMESS_CIPHERS.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(format!("Unsupported VMess security \"{}\"", truncate(v, 40)))
    }
}

/// `none`, or a VLESS Encryption client string (`mlkem768x25519plus.<mode>.<rtt>...` - dot
/// separated base64url/alnum segments).
pub fn vless_encryption(v: Option<&str>) -> VResult<Option<String>> {
    let v = match v.map(str::trim) {
        None | Some("") | Some("none") => return Ok(None),
        Some(v) => v,
    };
    if v.len() > 4096 {
        return Err("VLESS encryption value is too long".into());
    }
    if !v.starts_with("mlkem768x25519plus.") {
        return Err("Unsupported VLESS encryption".into());
    }
    if !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return Err("Malformed VLESS encryption value".into());
    }
    Ok(Some(v.to_string()))
}

const FINGERPRINTS: &[&str] = &[
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized",
    "randomizednoalpn", "unsafe",
];

pub fn fingerprint(v: Option<&str>, reality: bool) -> VResult<Option<String>> {
    let v = match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(None),
        Some(v) => v,
    };
    let lower = v.to_ascii_lowercase();
    if FINGERPRINTS.contains(&lower.as_str()) {
        if reality && lower == "unsafe" {
            return Err("REALITY does not support fingerprint \"unsafe\"".into());
        }
        return Ok(Some(lower));
    }
    // Native uTLS hello names, e.g. HelloChrome_106_Shuffle.
    if v.starts_with("Hello") && v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Ok(Some(v.to_string()));
    }
    Err(format!("Unsupported TLS fingerprint \"{}\"", truncate(v, 40)))
}

pub fn alpn_list(v: &str) -> VResult<Vec<String>> {
    let mut out = Vec::new();
    for a in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match a {
            "h2" | "http/1.1" | "h3" => {
                if !out.iter().any(|x: &String| x == a) {
                    out.push(a.to_string())
                }
            }
            _ => return Err(format!("Unsupported ALPN \"{}\"", truncate(a, 20))),
        }
    }
    Ok(out)
}

/// SNI / Host header: a hostname or IP. Empty -> None.
pub fn server_name(field: &str, v: Option<&str>) -> VResult<Option<String>> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => address(s).map(Some).map_err(|_| format!("Invalid {field} \"{}\"", truncate(s, 64))),
    }
}

/// HTTP Host header values may be a comma separated list for some transports; we keep the
/// first and validate it as a hostname (optionally with :port).
pub fn host_header(v: Option<&str>) -> VResult<Option<String>> {
    let v = match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(None),
        Some(v) => v.split(',').next().unwrap_or("").trim(),
    };
    if v.is_empty() {
        return Ok(None);
    }
    let (h, p) = match v.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (v, None),
    };
    let h = address(h).map_err(|_| format!("Invalid Host header \"{}\"", truncate(v, 64)))?;
    if let Some(p) = p {
        port_from_str(p)?;
        return Ok(Some(format!("{h}:{p}")));
    }
    Ok(Some(h))
}

/// URL path for ws/httpupgrade/xhttp. Adds a leading '/' and allows a query string
/// (Xray reads e.g. `?ed=2048` from the ws path).
pub fn http_path(v: Option<&str>) -> VResult<String> {
    let v = v.map(str::trim).unwrap_or("");
    if v.len() > MAX_FIELD_LEN {
        return Err("Path is too long".into());
    }
    if v.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Path contains invalid characters".into());
    }
    if v.is_empty() {
        return Ok("/".into());
    }
    no_path_tricks("Path", v)?;
    Ok(if v.starts_with('/') { v.to_string() } else { format!("/{v}") })
}

pub fn grpc_service_name(v: Option<&str>) -> VResult<String> {
    let v = v.map(str::trim).unwrap_or("");
    if v.len() > 512 || v.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Invalid gRPC service name".into());
    }
    no_path_tricks("gRPC service name", v)?;
    Ok(v.to_string())
}

pub const XHTTP_MODES: &[&str] = &["auto", "packet-up", "stream-up", "stream-one"];

pub fn xhttp_mode(v: Option<&str>) -> VResult<String> {
    let v = v.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    if XHTTP_MODES.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(format!("Unsupported XHTTP mode \"{}\"", truncate(v, 20)))
    }
}

/// REALITY public key: base64url (no padding) of a 32-byte x25519 key.
pub fn reality_password(v: Option<&str>) -> VResult<String> {
    let v = v.map(str::trim).unwrap_or("");
    if v.is_empty() {
        return Err("REALITY public key (pbk) is missing".into());
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(v.trim_end_matches('='))
        .map_err(|_| "REALITY public key is not valid base64url".to_string())?;
    if decoded.len() != 32 {
        return Err("REALITY public key must be 32 bytes".into());
    }
    Ok(v.trim_end_matches('=').to_string())
}

pub fn reality_short_id(v: Option<&str>) -> VResult<Option<String>> {
    let v = v.map(str::trim).unwrap_or("");
    if v.is_empty() {
        return Ok(None);
    }
    if v.len() > 16 || !v.len().is_multiple_of(2) || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("REALITY short ID must be an even-length hex string of at most 16 characters".into());
    }
    Ok(Some(v.to_ascii_lowercase()))
}

pub fn spider_x(v: Option<&str>) -> VResult<Option<String>> {
    let v = opt_text("spiderX", v, 256)?;
    if let Some(s) = &v {
        no_path_tricks("REALITY spiderX", s)?;
    }
    Ok(v.map(|s| if s.starts_with('/') { s } else { format!("/{s}") }))
}

pub fn mldsa65_verify(v: Option<&str>) -> VResult<Option<String>> {
    let v = match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(None),
        Some(v) => v,
    };
    if v.len() > 4096 || !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=')) {
        return Err("Invalid REALITY mldsa65Verify value".into());
    }
    Ok(Some(v.to_string()))
}

/// Comma separated hex SHA-256 pins; colons are accepted and removed.
pub fn cert_pins(v: Option<&str>) -> VResult<Option<String>> {
    let v = match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(None),
        Some(v) => v,
    };
    let mut pins = Vec::new();
    for p in v.split(',') {
        let p: String = p.trim().chars().filter(|c| *c != ':').collect();
        if p.len() != 64 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid certificate pin (expected SHA-256 hex)".into());
        }
        pins.push(p.to_ascii_lowercase());
    }
    Ok(Some(pins.join(",")))
}

pub fn ech_config_list(v: Option<&str>) -> VResult<Option<String>> {
    let v = match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(None),
        Some(v) => v,
    };
    if v.len() > 8192 || !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_' | ':' | '.')) {
        return Err("Invalid ECH config".into());
    }
    Ok(Some(v.to_string()))
}

const EXTRA_MAX_BYTES: usize = 16 * 1024;

/// Rejects values that look like filesystem paths or path traversal in fields that are not file
/// paths (URL paths, gRPC service names, XHTTP tuning strings): `..` segments, backslashes, UNC
/// or protocol-relative `//`, `file:` URLs, drive letters, and their percent-encoded forms.
/// None of these fields is ever used as a local path; this keeps hostile values out of the
/// generated config altogether.
pub fn no_path_tricks(field: &str, v: &str) -> VResult<()> {
    let l = v.to_ascii_lowercase();
    let drive = l.len() >= 2 && l.as_bytes()[0].is_ascii_alphabetic() && l.as_bytes()[1] == b':';
    let bad = l.contains('\\')
        || l.starts_with("//")
        || l.contains("file:")
        || l.contains("%2e%2e")
        || l.contains("%5c")
        || l.contains("%2f%2f")
        || l.split(['/', '?', '#', '&', '=']).any(|seg| seg == "..")
        || drive;
    if bad {
        Err(format!("{field} looks like a file path or path traversal"))
    } else {
        Ok(())
    }
}

fn is_range(o: &Map<String, Value>) -> bool {
    !o.is_empty() && o.len() <= 2 && o.keys().all(|k| k == "from" || k == "to") && o.values().all(|v| v.as_u64().is_some())
}

fn valid_header_name(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// One XHTTP tuning value: bool, non-negative integer, `{from,to}` range, or a short printable
/// token such as "100-1000", "header", "POST".
fn xhttp_scalar(k: &str, v: &Value) -> VResult<Value> {
    let ok = match v {
        Value::Bool(_) => true,
        Value::Number(n) => n.as_u64().is_some(),
        Value::Object(o) => is_range(o),
        Value::String(s) => s.len() <= 128 && s.chars().all(|c| c.is_ascii_graphic()) && no_path_tricks(k, s).is_ok(),
        _ => false,
    };
    if ok {
        Ok(v.clone())
    } else {
        Err(format!("Invalid value for XHTTP setting \"{}\"", truncate(k, 32)))
    }
}

fn xhttp_headers(v: &Value) -> VResult<Value> {
    let o = v.as_object().ok_or("XHTTP headers must be an object")?;
    let mut h = Map::new();
    for (hk, hv) in o {
        let s = hv.as_str().ok_or_else(|| format!("XHTTP header \"{}\" must be a string", truncate(hk, 32)))?;
        if !valid_header_name(hk) || s.len() > 1024 || s.chars().any(|c| c.is_control()) {
            return Err(format!("Invalid XHTTP header \"{}\"", truncate(hk, 32)));
        }
        h.insert(hk.clone(), Value::String(s.to_string()));
    }
    Ok(Value::Object(h))
}

fn xmux(v: &Value) -> VResult<Value> {
    let o = v.as_object().ok_or("XHTTP xmux must be an object")?;
    let mut m = Map::new();
    for (k, val) in o {
        if !crate::parse::fields::XMUX.contains(&k.as_str()) {
            return Err(format!("Unsupported XHTTP xmux field \"{}\"", truncate(k, 32)));
        }
        let ok = matches!(val, Value::Number(n) if n.as_u64().is_some())
            || matches!(val, Value::String(s) if s.len() <= 32 && s.chars().all(|c| c.is_ascii_digit() || c == '-'))
            || matches!(val, Value::Object(r) if is_range(r));
        if !ok {
            return Err(format!("Invalid value for XHTTP xmux \"{}\"", truncate(k, 32)));
        }
        m.insert(k.clone(), val.clone());
    }
    Ok(Value::Object(m))
}

/// Validates an XHTTP `extra` object against the allowlist in `parse/fields.rs` and returns the
/// normalized copy that is placed in the generated config. Unknown keys are rejected (not dropped),
/// and `downloadSettings` (a nested stream config) is rebuilt field by field, so fields such as
/// `masterKeyLog`, `certificates` or `sockopt` can never reach Xray through it.
pub fn sanitize_xhttp_extra(v: &Value, warnings: &mut Vec<String>) -> VResult<Option<Value>> {
    sanitize_extra(v, warnings, true)
}

fn sanitize_extra(v: &Value, warnings: &mut Vec<String>, allow_download: bool) -> VResult<Option<Value>> {
    let obj = match v {
        Value::Null => return Ok(None),
        Value::Object(o) => o,
        _ => return Err("XHTTP extra must be a JSON object".into()),
    };
    if serde_json::to_string(v).map(|s| s.len()).unwrap_or(usize::MAX) > EXTRA_MAX_BYTES {
        return Err("XHTTP extra is too large".into());
    }
    let mut out = Map::new();
    for (k, val) in obj {
        let key = k.as_str();
        if crate::parse::fields::XHTTP_SCALARS.contains(&key) {
            out.insert(k.clone(), xhttp_scalar(key, val)?);
            continue;
        }
        match key {
            "headers" => {
                out.insert(k.clone(), xhttp_headers(val)?);
            }
            "xmux" => {
                out.insert(k.clone(), xmux(val)?);
            }
            "downloadSettings" if allow_download => {
                let o = val.as_object().ok_or("XHTTP downloadSettings must be an object")?;
                out.insert(k.clone(), sanitize_download_settings(o, warnings)?);
            }
            "downloadSettings" => return Err("Nested XHTTP downloadSettings are not allowed".into()),
            "host" => {
                if let Some(h) = host_header(val.as_str())? {
                    out.insert(k.clone(), h.into());
                }
            }
            "path" => {
                out.insert(k.clone(), http_path(val.as_str())?.into());
            }
            "mode" => {
                out.insert(k.clone(), xhttp_mode(val.as_str())?.into());
            }
            "serverMaxHeaderBytes" => {} // server-side
            _ => return Err(format!("Unsupported XHTTP extra field \"{}\"", truncate(k, 32))),
        }
    }
    Ok(Some(Value::Object(out)))
}

fn sanitize_download_settings(o: &Map<String, Value>, warnings: &mut Vec<String>) -> VResult<Value> {
    use crate::parse::fields;
    fields::check(o, "downloadSettings", fields::DOWNLOAD_SETTINGS, warnings)?;
    let mut out = Map::new();
    if let Some(a) = o.get("address").and_then(Value::as_str) {
        let a = address(a)?;
        crate::netpolicy::check_server_address(&a)?;
        out.insert("address".into(), Value::String(a));
    }
    if let Some(p) = o.get("port") {
        out.insert("port".into(), Value::from(port_from_json(p)?));
    }
    let network = o.get("network").and_then(Value::as_str).unwrap_or("xhttp");
    if network != "xhttp" && network != "splithttp" {
        return Err("XHTTP downloadSettings must use the xhttp transport".into());
    }
    out.insert("network".into(), Value::String("xhttp".into()));
    let security = o.get("security").and_then(Value::as_str).unwrap_or("none");
    match security {
        "none" => {}
        "tls" => {
            let t = o.get("tlsSettings").and_then(Value::as_object).cloned().unwrap_or_default();
            fields::check(&t, "downloadSettings.tlsSettings", fields::TLS, warnings)?;
            let mut ts = Map::new();
            if let Some(s) = server_name("SNI", t.get("serverName").and_then(Value::as_str))? {
                ts.insert("serverName".into(), s.into());
            }
            if let Some(f) = fingerprint(t.get("fingerprint").and_then(Value::as_str), false)? {
                ts.insert("fingerprint".into(), f.into());
            }
            if let Some(Value::Array(a)) = t.get("alpn") {
                let joined = a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",");
                ts.insert("alpn".into(), alpn_list(&joined)?.into());
            }
            if let Some(p) = cert_pins(t.get("pinnedPeerCertSha256").and_then(Value::as_str))? {
                ts.insert("pinnedPeerCertSha256".into(), p.into());
            }
            out.insert("tlsSettings".into(), Value::Object(ts));
        }
        "reality" => {
            let r = o.get("realitySettings").and_then(Value::as_object).cloned().unwrap_or_default();
            fields::check(&r, "downloadSettings.realitySettings", fields::REALITY, warnings)?;
            let mut rs = Map::new();
            let sn = server_name("REALITY SNI", r.get("serverName").and_then(Value::as_str))?
                .ok_or("REALITY SNI is missing in downloadSettings")?;
            rs.insert("serverName".into(), sn.into());
            let fp = fingerprint(r.get("fingerprint").and_then(Value::as_str), true)?.unwrap_or_else(|| "chrome".into());
            rs.insert("fingerprint".into(), fp.into());
            let pw = r.get("password").or_else(|| r.get("publicKey")).and_then(Value::as_str);
            rs.insert("password".into(), reality_password(pw)?.into());
            if let Some(s) = reality_short_id(r.get("shortId").and_then(Value::as_str))? {
                rs.insert("shortId".into(), s.into());
            }
            if let Some(s) = spider_x(r.get("spiderX").and_then(Value::as_str))? {
                rs.insert("spiderX".into(), s.into());
            }
            out.insert("realitySettings".into(), Value::Object(rs));
        }
        other => return Err(format!("Unsupported downloadSettings security \"{}\"", truncate(other, 20))),
    }
    out.insert("security".into(), Value::String(security.into()));
    if let Some(x) = o.get("xhttpSettings").or_else(|| o.get("splithttpSettings")).and_then(Value::as_object) {
        let mut merged = Map::new();
        for (k, v) in x {
            if k == "extra" {
                if let Some(e) = v.as_object() {
                    merged.extend(e.clone());
                }
            } else if fields::XHTTP_SCALARS.contains(&k.as_str()) || fields::lookup(fields::XHTTP, k).is_some() {
                merged.insert(k.clone(), v.clone());
            } else {
                return Err(format!("Unsupported field downloadSettings.xhttpSettings.{}", truncate(k, 32)));
            }
        }
        let mut xs = Map::new();
        xs.insert("path".into(), http_path(merged.remove("path").as_ref().and_then(Value::as_str))?.into());
        if let Some(h) = host_header(merged.remove("host").as_ref().and_then(Value::as_str))? {
            xs.insert("host".into(), h.into());
        }
        xs.insert("mode".into(), xhttp_mode(merged.remove("mode").as_ref().and_then(Value::as_str))?.into());
        if let Some(Value::Object(e)) = sanitize_extra(&Value::Object(merged), warnings, false)? {
            if !e.is_empty() {
                xs.insert("extra".into(), Value::Object(e));
            }
        }
        out.insert("xhttpSettings".into(), Value::Object(xs));
    }
    Ok(Value::Object(out))
}

/// Cross-field validation of a complete parsed server. Called by every parser.
pub fn server(p: &mut ParsedServer) -> VResult<()> {
    let m = &p.meta;
    crate::netpolicy::check_server_address(&m.address)?;
    if let Security::Reality { .. } = m.security {
        if !matches!(m.transport, Transport::Raw { .. } | Transport::Xhttp { .. } | Transport::Grpc { .. }) {
            return Err(format!("REALITY cannot be used with the {} transport", m.transport.display()));
        }
        if p.secrets.reality_password.is_none() {
            return Err("REALITY public key (pbk) is missing".into());
        }
    }
    if !m.flow.is_empty() {
        if m.protocol != Protocol::Vless {
            return Err("flow is only valid for VLESS".into());
        }
        if !matches!(m.transport, Transport::Raw { .. }) || matches!(m.security, Security::None) && p.secrets.vless_encryption.is_none() {
            return Err("XTLS Vision flow requires the TCP (raw) transport with TLS or REALITY".into());
        }
    }
    if m.protocol == Protocol::Vless && matches!(m.security, Security::None) && p.secrets.vless_encryption.is_none() {
        p.warnings.push(
            "VLESS without TLS/REALITY is unencrypted; current Xray only allows it for private network addresses".into(),
        );
    }
    if let Transport::Raw { header: RawHeader::Http { .. } } = m.transport {
        if !matches!(m.security, Security::None) {
            return Err("TCP HTTP header obfuscation cannot be combined with TLS/REALITY".into());
        }
    }
    Ok(())
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn addresses() {
        assert_eq!(address("Example.COM").unwrap(), "example.com");
        assert_eq!(address("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(address("1.2.3.4").unwrap(), "1.2.3.4");
        assert_eq!(address("bücher.de").unwrap(), "xn--bcher-kva.de");
        assert!(address("").is_err());
        assert!(address("a b.com").is_err());
        assert!(address("-bad.com").is_err());
        assert!(address("evil.com/path").is_err());
        assert!(address(&"a".repeat(300)).is_err());
    }

    #[test]
    fn ports() {
        assert_eq!(port_from_str("443").unwrap(), 443);
        assert!(port_from_str("0").is_err());
        assert!(port_from_str("65536").is_err());
        assert!(port_from_str("abc").is_err());
        assert_eq!(port_from_json(&json!(8443)).unwrap(), 8443);
        assert_eq!(port_from_json(&json!("8443")).unwrap(), 8443);
        assert!(port_from_json(&json!(-1)).is_err());
    }

    #[test]
    fn user_ids() {
        assert_eq!(
            user_id("B831381D-6324-4D53-AD4F-8CDA48B30811").unwrap(),
            "b831381d-6324-4d53-ad4f-8cda48b30811"
        );
        assert_eq!(user_id("custom-id").unwrap(), "custom-id");
        assert!(user_id("").is_err());
        assert!(user_id(&"x".repeat(31)).is_err());
        assert!(user_id("has space").is_err());
    }

    #[test]
    fn reality_fields() {
        assert!(reality_password(Some("OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI")).is_ok());
        assert!(reality_password(Some("short")).is_err());
        assert!(reality_password(None).is_err());
        assert_eq!(reality_short_id(Some("AB12")).unwrap().unwrap(), "ab12");
        assert!(reality_short_id(Some("abc")).is_err());
        assert!(reality_short_id(Some("zz")).is_err());
        assert!(reality_short_id(Some("0123456789abcdef01")).is_err());
        assert_eq!(reality_short_id(Some("")).unwrap(), None);
    }

    #[test]
    fn tls_fields() {
        assert_eq!(fingerprint(Some("Chrome"), false).unwrap().unwrap(), "chrome");
        assert!(fingerprint(Some("unsafe"), true).is_err());
        assert!(fingerprint(Some("HelloChrome_106_Shuffle"), true).is_ok());
        assert!(fingerprint(Some("bogus"), false).is_err());
        assert_eq!(alpn_list("h2,http/1.1").unwrap(), vec!["h2", "http/1.1"]);
        assert!(alpn_list("spdy").is_err());
        assert!(cert_pins(Some("zz")).is_err());
        let pin = "E8:E2:D3:87:FD:BF:FE:B3:8E:9C:90:65:CF:30:A9:7E:E2:3C:0E:3D:32:EE:6F:78:FF:AE:40:96:6B:EF:CC:C9";
        assert_eq!(
            cert_pins(Some(pin)).unwrap().unwrap(),
            "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9"
        );
    }

    #[test]
    fn paths_and_hosts() {
        assert_eq!(http_path(Some("ws")).unwrap(), "/ws");
        assert_eq!(http_path(None).unwrap(), "/");
        assert_eq!(http_path(Some("/ws?ed=2048")).unwrap(), "/ws?ed=2048");
        assert!(http_path(Some("/a b")).is_err());
        assert_eq!(host_header(Some("cdn.example.com, other.com")).unwrap().unwrap(), "cdn.example.com");
        assert_eq!(host_header(Some("cdn.example.com:8080")).unwrap().unwrap(), "cdn.example.com:8080");
        assert!(host_header(Some("bad host")).is_err());
    }

    #[test]
    fn xhttp_extra_allowlist() {
        let mut w = vec![];
        let ok = json!({
            "xPaddingBytes": "100-1000",
            "noGRPCHeader": false,
            "scMaxEachPostBytes": {"from": 1, "to": 2},
            "headers": {"X-Test": "1"},
            "xmux": {"maxConcurrency": "16-32", "cMaxReuseTimes": 0},
            "downloadSettings": {
                "address": "dl.example.com", "port": 443, "network": "xhttp", "security": "tls",
                "tlsSettings": {"serverName": "dl.example.com"},
                "xhttpSettings": {"path": "/dl", "xPaddingBytes": "1-2"}
            }
        });
        let out = sanitize_xhttp_extra(&ok, &mut w).unwrap().unwrap();
        assert_eq!(out["xPaddingBytes"], "100-1000");
        assert_eq!(out["downloadSettings"]["tlsSettings"]["serverName"], "dl.example.com");
        assert_eq!(out["downloadSettings"]["xhttpSettings"]["extra"]["xPaddingBytes"], "1-2");

        // Every one of these must reject the entry (not be silently dropped or forwarded).
        let bad = [
            json!({"unknownKnob": 1}),
            json!({"headers": {"Bad Header": "x"}}),
            json!({"xmux": {"evil": {"nested": true}}}),
            json!({"xPaddingKey": "../../etc/passwd"}),
            json!({"xPaddingKey": "C:\\Windows"}),
            json!({"downloadSettings": {"address": "dl.example.com", "security": "tls", "tlsSettings": {"masterKeyLog": "/tmp/keys"}}}),
            json!({"downloadSettings": {"address": "dl.example.com", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/passwd"}]}}}),
            json!({"downloadSettings": {"address": "dl.example.com", "sockopt": {"dialerProxy": "x"}}}),
            json!({"downloadSettings": {"address": "127.0.0.1"}}),
            json!({"downloadSettings": {"address": "169.254.169.254"}}),
            json!({"downloadSettings": {"address": "dl.example.com", "xhttpSettings": {"extra": {"downloadSettings": {"address": "x.example.com"}}}}}),
        ];
        for b in bad {
            assert!(sanitize_xhttp_extra(&b, &mut w).is_err(), "accepted {b}");
        }
    }

    #[test]
    fn path_tricks_rejected() {
        for p in ["/../etc/passwd", "/a/..", "..\\x", "\\\\server\\share", "//evil.example/x", "file:///etc/passwd", "/%2e%2e/x", "C:/Windows", "/a%5cb"] {
            assert!(http_path(Some(p)).is_err(), "{p}");
        }
        for p in ["/ws", "/ws?ed=2048", "/a/b.c/d", "/..hidden-but-not-traversal"] {
            assert!(http_path(Some(p)).is_ok(), "{p}");
        }
        assert!(grpc_service_name(Some("../../x")).is_err());
        assert!(grpc_service_name(Some("my.Service/Tun")).is_ok());
        assert!(spider_x(Some("/../x")).is_err());
    }
}
