//! VMess links in the de-facto v2rayN format: `vmess://` + base64(JSON) where the JSON is
//! `{v, ps, add, port, id, aid, scy, net, type, host, path, tls, sni, alpn, fp, ...}`.
//! Values may be strings or numbers depending on the generator.

use super::stream::{self, StreamParams};
use crate::core::profile::*;
use crate::core::validate as v;
use serde_json::Value;

fn s(obj: &serde_json::Map<String, Value>, k: &str) -> Option<String> {
    match obj.get(k)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn parse_vmess_uri(link: &str) -> Result<ParsedServer, String> {
    let link = link.trim();
    let payload = link
        .get(8..)
        .filter(|_| link[..8].eq_ignore_ascii_case("vmess://"))
        .ok_or("Not a vmess:// link")?;
    // Some generators append "#name" or "?remarks" after the base64 blob.
    let payload = payload.split(['#', '?']).next().unwrap_or("");
    let bytes = super::decode_base64_lenient(payload).ok_or(
        "VMess link is not valid base64 (only the v2rayN JSON format is supported)",
    )?;
    let text = String::from_utf8(bytes).map_err(|_| "VMess link payload is not valid UTF-8".to_string())?;
    let json: Value = serde_json::from_str(text.trim()).map_err(|_| "VMess link payload is not valid JSON".to_string())?;
    let o = json.as_object().ok_or("VMess link payload must be a JSON object")?;

    let mut warnings = Vec::new();
    super::fields::check(o, "vmess", super::fields::VMESS_KEYS, &mut warnings)?;
    let address = v::address(&s(o, "add").ok_or("VMess link is missing the address (add)")?)?;
    let port = v::port_from_json(o.get("port").ok_or("VMess link is missing the port")?)?;
    let user = v::user_id(&s(o, "id").ok_or("VMess link is missing the user ID (id)")?)?;
    if let Some(aid) = s(o, "aid") {
        if aid.trim() != "0" && !aid.trim().is_empty() {
            warnings.push("alterId > 0 (legacy VMess MD5 auth) is not supported by Xray; using VMess AEAD".into());
        }
    }
    let cipher = v::vmess_cipher(s(o, "scy").as_deref())?;
    let tls = s(o, "tls").unwrap_or_default();
    let params = StreamParams {
        net: s(o, "net"),
        header_type: s(o, "type"),
        host: s(o, "host"),
        path: s(o, "path"),
        service_name: None,
        authority: s(o, "authority"),
        mode: s(o, "mode"),
        security: Some(if tls.is_empty() { "none".into() } else { tls }),
        sni: s(o, "sni"),
        alpn: s(o, "alpn"),
        fp: s(o, "fp"),
        pbk: s(o, "pbk"),
        sid: s(o, "sid"),
        spx: s(o, "spx"),
        pqv: None,
        pcs: s(o, "pcs"),
        ech: s(o, "ech"),
        extra: match o.get("extra") {
            Some(Value::Object(_)) => Some(o["extra"].to_string()),
            Some(Value::String(x)) => Some(x.clone()),
            _ => None,
        },
        allow_insecure: [s(o, "allowInsecure"), s(o, "insecure")].iter().any(|v| matches!(v.as_deref(), Some("1") | Some("true"))),
    };
    let st = stream::build(&params, &mut warnings)?;
    let fallback = format!("{address}:{port}");
    let name = v::clean_name(&s(o, "ps").unwrap_or_default(), &fallback);
    let mut p = ParsedServer {
        meta: ServerMeta {
            id: String::new(),
            name,
            protocol: Protocol::Vmess,
            address,
            port,
            transport: st.transport,
            security: st.security,
            flow: String::new(),
            vmess_cipher: Some(cipher),
            source: Source::Link,
            subscription_id: None,
            created_at: 0,
        },
        secrets: ServerSecrets {
            user_id: user,
            vless_encryption: None,
            reality_password: st.reality_password,
            reality_short_id: st.reality_short_id,
        },
        warnings,
    };
    v::server(&mut p)?;
    Ok(p)
}
