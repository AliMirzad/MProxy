//! Import parsers. Pure functions from untrusted text to [`ParsedServer`]s.
//!
//! * [`parse_vless_uri`] – `vless://uuid@host:port?params#name`
//! * [`parse_vmess_uri`] – `vmess://base64(json)` (v2rayN format)
//! * [`parse_xray_json`] – Xray/V2Ray client config, outbound object, or arrays of them
//! * [`parse_subscription`] – base64 / plain link list / JSON subscription body
//! * [`parse_qr_payload`] – decoded QR text (only proxy formats accepted)
//!
//! Every entry is parsed in isolation: one malformed line never aborts a batch.

pub mod fields;
mod json;
mod stream;
mod vless;
mod vmess;

pub use json::parse_xray_json;
pub use vless::parse_vless_uri;
pub use vmess::parse_vmess_uri;

use crate::core::profile::ParsedServer;
use base64::Engine;

pub const MAX_INPUT_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 2000;
pub const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntryError {
    /// 1-based entry number within the input.
    pub entry: usize,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ParseBatch {
    pub servers: Vec<ParsedServer>,
    pub errors: Vec<EntryError>,
    /// Entries skipped because the protocol (ss://, trojan://, ...) is not supported.
    pub unsupported: usize,
}

/// Parse a single share link of any supported scheme.
pub fn parse_link(link: &str) -> Result<ParsedServer, String> {
    let link = link.trim();
    if link.len() > MAX_LINE_BYTES {
        return Err("Link is too long".into());
    }
    let lower = link.get(..8).unwrap_or("").to_ascii_lowercase();
    if lower.starts_with("vless://") {
        parse_vless_uri(link)
    } else if lower.starts_with("vmess://") {
        parse_vmess_uri(link)
    } else {
        Err(unsupported_message(link))
    }
}

fn unsupported_message(link: &str) -> String {
    match link.split_once("://") {
        Some((scheme, _)) if scheme.len() <= 16 && scheme.chars().all(|c| c.is_ascii_alphanumeric()) => {
            format!("Unsupported protocol \"{}\" (only VLESS and VMess are supported)", scheme.to_ascii_lowercase())
        }
        _ => "Not a VLESS or VMess link".into(),
    }
}

fn is_supported_scheme(line: &str) -> bool {
    let l = line.get(..8).unwrap_or("").to_ascii_lowercase();
    l.starts_with("vless://") || l.starts_with("vmess://")
}

fn looks_like_link(line: &str) -> bool {
    matches!(line.split_once("://"), Some((s, _)) if !s.is_empty() && s.len() <= 16 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Tolerant base64 decoding: standard or URL-safe alphabet, with or without padding,
/// ignoring embedded whitespace. Used for subscription bodies and vmess:// payloads.
pub fn decode_base64_lenient(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let unpadded = cleaned.trim_end_matches('=');
    let url = unpadded.contains('-') || unpadded.contains('_');
    let engine = if url {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD
    };
    engine.decode(unpadded).ok()
}

/// Parse any import text: one or many links, a base64 subscription body, or JSON.
pub fn parse_subscription(body: &str) -> Result<ParseBatch, String> {
    if body.len() > MAX_INPUT_BYTES {
        return Err("Input is too large".into());
    }
    let body = body.trim_start_matches('\u{feff}').trim();
    if body.is_empty() {
        return Err("Input is empty".into());
    }
    if body.starts_with('{') || body.starts_with('[') {
        return parse_xray_json(body);
    }
    // A base64 body contains no "://". Decode it and parse the result as a link list.
    let decoded;
    let text = if !body.contains("://") {
        match decode_base64_lenient(body).and_then(|b| String::from_utf8(b).ok()) {
            Some(t) if t.contains("://") || t.trim_start().starts_with('{') || t.trim_start().starts_with('[') => {
                decoded = t;
                let t = decoded.trim();
                if t.starts_with('{') || t.starts_with('[') {
                    return parse_xray_json(t);
                }
                t
            }
            _ => return Err("Input is not a supported link, subscription or JSON configuration".into()),
        }
    } else {
        body
    };
    Ok(parse_link_list(text))
}

fn parse_link_list(text: &str) -> ParseBatch {
    let mut batch = ParseBatch::default();
    let mut entry = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        entry += 1;
        if entry > MAX_ENTRIES {
            batch.errors.push(EntryError { entry, message: format!("Too many entries; only the first {MAX_ENTRIES} were processed") });
            break;
        }
        if !is_supported_scheme(line) {
            if looks_like_link(line) {
                batch.unsupported += 1;
            } else {
                batch.errors.push(EntryError { entry, message: "Not a VLESS or VMess link".into() });
            }
            continue;
        }
        match parse_link(line) {
            Ok(s) => batch.servers.push(s),
            Err(message) => batch.errors.push(EntryError { entry, message }),
        }
    }
    batch
}

/// QR codes are arbitrary untrusted text. Only proxy configurations are accepted; any
/// other content (a web URL, Wi-Fi credentials, ...) is rejected and never acted upon.
pub fn parse_qr_payload(text: &str) -> Result<ParseBatch, String> {
    let t = text.trim();
    let is_proxy = is_supported_scheme(t)
        || t.starts_with('{')
        || (!t.contains("://") && decode_base64_lenient(t).and_then(|b| String::from_utf8(b).ok()).is_some_and(|d| d.lines().any(is_supported_scheme)));
    if !is_proxy {
        return Err("This QR code does not contain a VLESS or VMess configuration".into());
    }
    parse_subscription(t)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod security_tests;
