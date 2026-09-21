//! VLESS share links, following the XTLS share-link proposal
//! (https://github.com/XTLS/Xray-core/discussions/716):
//! `vless://<uuid>@<host>:<port>?type=..&security=..&...#<name>`

use super::stream::{self, StreamParams};
use crate::model::*;
use crate::validate as v;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;

fn pct(s: &str) -> Result<String, String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| "Link contains malformed percent-encoding".to_string())
}

/// Splits a query string without treating '+' as a space (share links are produced with
/// encodeURIComponent semantics). Duplicate keys: first wins.
pub(super) fn query_map(q: &str) -> Result<HashMap<String, String>, String> {
    let mut m = HashMap::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, val) = pair.split_once('=').unwrap_or((pair, ""));
        if !is_valid_pct(k) || !is_valid_pct(val) {
            return Err("Link contains malformed percent-encoding".into());
        }
        m.entry(pct(k)?).or_insert(pct(val)?);
    }
    Ok(m)
}

fn is_valid_pct(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)) {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

pub fn parse_vless_uri(link: &str) -> Result<ParsedServer, String> {
    let link = link.trim();
    let rest = link
        .get(8..)
        .filter(|_| link[..8].eq_ignore_ascii_case("vless://"))
        .ok_or("Not a vless:// link")?;
    if rest.chars().any(|c| c.is_control() || c == ' ') {
        return Err("Link contains whitespace or control characters".into());
    }
    let (rest, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    let authority = authority.trim_end_matches('/');
    let (userinfo, hostport) = authority.rsplit_once('@').ok_or("Link is missing the user ID")?;
    if !is_valid_pct(userinfo) {
        return Err("Link contains malformed percent-encoding".into());
    }
    let user = v::user_id(&pct(userinfo)?)?;
    let (host, port) = split_host_port(hostport)?;
    let address = v::address(&host)?;
    let port = v::port_from_str(&port)?;
    let q = query_map(query)?;
    let g = |k: &str| q.get(k).cloned();

    let mut warnings = Vec::new();
    let params = StreamParams {
        net: g("type"),
        header_type: g("headerType"),
        host: g("host"),
        path: g("path"),
        service_name: g("serviceName"),
        authority: g("authority"),
        mode: g("mode"),
        security: g("security"),
        sni: g("sni").or_else(|| g("peer")),
        alpn: g("alpn"),
        fp: g("fp"),
        pbk: g("pbk"),
        sid: g("sid"),
        spx: g("spx"),
        pqv: g("pqv"),
        pcs: g("pcs"),
        ech: g("ech"),
        extra: g("extra"),
        allow_insecure: matches!(g("allowInsecure").as_deref(), Some("1") | Some("true")),
    };
    let st = stream::build(&params, &mut warnings)?;
    let encryption = v::vless_encryption(g("encryption").as_deref())?;
    let flow = v::flow(g("flow").as_deref().unwrap_or(""))?;

    let fallback = format!("{address}:{port}");
    let name = match fragment {
        Some(f) => v::clean_name(&pct(f).unwrap_or_default(), &fallback),
        None => fallback,
    };
    let mut p = ParsedServer {
        meta: ServerMeta {
            id: String::new(),
            name,
            protocol: Protocol::Vless,
            address,
            port,
            transport: st.transport,
            security: st.security,
            flow,
            vmess_cipher: None,
            source: Source::Link,
            subscription_id: None,
            created_at: 0,
        },
        secrets: ServerSecrets {
            user_id: user,
            vless_encryption: encryption,
            reality_password: st.reality_password,
            reality_short_id: st.reality_short_id,
        },
        warnings,
    };
    v::server(&mut p)?;
    Ok(p)
}

/// Splits "host:port" / "[v6]:port".
pub(super) fn split_host_port(hp: &str) -> Result<(String, String), String> {
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or("Malformed IPv6 address")?;
        let p = after.strip_prefix(':').ok_or("Link is missing the port")?;
        return Ok((h.to_string(), p.to_string()));
    }
    let (h, p) = hp.rsplit_once(':').ok_or("Link is missing the port")?;
    if h.contains(':') {
        return Err("IPv6 addresses must be enclosed in brackets".into());
    }
    if !is_valid_pct(h) {
        return Err("Link contains malformed percent-encoding".into());
    }
    Ok((pct(h)?, p.to_string()))
}
