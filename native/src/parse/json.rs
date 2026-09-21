//! Xray / V2Ray JSON import.
//!
//! Accepted shapes: a full client config (`{"outbounds":[...]}`), a single outbound object
//! (`{"protocol":"vless",...}`), or a JSON array of either. Only VLESS/VMess outbounds are
//! extracted, and only the allow-listed fields are read. The imported JSON is never executed;
//! the Xray config is regenerated from the normalized model (see `xrayconf.rs`).

use super::stream::{self, StreamParams};
use super::{EntryError, ParseBatch, MAX_ENTRIES};
use crate::model::*;
use crate::validate as v;
use serde_json::{Map, Value};

type Obj = Map<String, Value>;

fn str_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn obj<'a>(o: &'a Obj, k: &str) -> Option<&'a Obj> {
    o.get(k).and_then(Value::as_object)
}

fn first_str_of_array_or_str(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Array(a) => a.first().and_then(|x| x.as_str()).map(String::from),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

pub fn parse_xray_json(text: &str) -> Result<ParseBatch, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e.to_string().chars().take(80).collect::<String>()))?;
    let mut candidates: Vec<(Obj, Option<String>)> = Vec::new();
    let mut collect = |item: &Value| -> Result<(), String> {
        let o = item.as_object().ok_or("JSON entries must be objects")?;
        if let Some(outs) = o.get("outbounds").and_then(Value::as_array) {
            let remarks = str_of(o.get("remarks"));
            for out in outs {
                if let Some(oo) = out.as_object() {
                    candidates.push((oo.clone(), remarks.clone()));
                }
            }
        } else if o.contains_key("protocol") {
            candidates.push((o.clone(), None));
        } else {
            return Err("JSON is neither an Xray config nor an outbound".into());
        }
        Ok(())
    };
    match &root {
        Value::Array(items) => {
            for it in items.iter().take(MAX_ENTRIES) {
                // Skip unrecognised array elements here; they surface as "no outbound found" if all fail.
                let _ = collect(it);
            }
        }
        other => collect(other)?,
    }

    let mut batch = ParseBatch::default();
    let mut entry = 0;
    for (o, remarks) in candidates {
        let proto = o.get("protocol").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        if proto != "vless" && proto != "vmess" {
            // freedom/blackhole/dns etc. are not servers; other proxies are unsupported.
            if !matches!(proto.as_str(), "freedom" | "blackhole" | "dns" | "loopback" | "") {
                batch.unsupported += 1;
            }
            continue;
        }
        entry += 1;
        match parse_outbound(&o, remarks.as_deref()) {
            Ok(p) => batch.servers.push(p),
            Err(message) => batch.errors.push(EntryError { entry, message }),
        }
    }
    if batch.servers.is_empty() && batch.errors.is_empty() {
        return Err("No VLESS or VMess outbound found in the JSON".into());
    }
    Ok(batch)
}

fn parse_outbound(o: &Obj, remarks: Option<&str>) -> Result<ParsedServer, String> {
    let protocol = match o.get("protocol").and_then(Value::as_str) {
        Some(p) if p.eq_ignore_ascii_case("vless") => Protocol::Vless,
        _ => Protocol::Vmess,
    };
    let settings = obj(o, "settings").ok_or("Outbound is missing \"settings\"")?;
    let mut warnings = Vec::new();

    // Either the classic vnext form or the flattened form accepted by newer Xray.
    let (server, user): (&Obj, &Obj) = match settings.get("vnext").and_then(Value::as_array) {
        Some(vnext) => {
            let srv = vnext.first().and_then(Value::as_object).ok_or("Outbound has an empty vnext")?;
            if vnext.len() > 1 {
                warnings.push("Only the first server of vnext was imported".into());
            }
            let users = srv.get("users").and_then(Value::as_array).ok_or("Outbound has no users")?;
            let u = users.first().and_then(Value::as_object).ok_or("Outbound has no users")?;
            (srv, u)
        }
        None => (settings, settings),
    };
    let address = v::address(&str_of(server.get("address")).ok_or("Outbound is missing the address")?)?;
    let port = v::port_from_json(server.get("port").ok_or("Outbound is missing the port")?)?;
    let user_id = v::user_id(&str_of(user.get("id")).ok_or("Outbound is missing the user ID")?)?;

    let ss = obj(o, "streamSettings").cloned().unwrap_or_default();
    let net = str_of(ss.get("network")).or_else(|| {
        str_of(ss.get("method")).map(|m| if m == "websocket" { "ws".into() } else { m })
    });
    let mut p = StreamParams { net: net.clone(), security: str_of(ss.get("security")), ..Default::default() };

    if let Some(t) = obj(&ss, "tlsSettings") {
        p.sni = str_of(t.get("serverName"));
        p.alpn = t.get("alpn").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","));
        p.fp = str_of(t.get("fingerprint"));
        p.pcs = str_of(t.get("pinnedPeerCertSha256"));
        p.ech = str_of(t.get("echConfigList"));
        p.allow_insecure = t.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false);
    }
    if let Some(r) = obj(&ss, "realitySettings") {
        p.sni = str_of(r.get("serverName"));
        p.fp = str_of(r.get("fingerprint"));
        p.pbk = str_of(r.get("password")).or_else(|| str_of(r.get("publicKey")));
        p.sid = str_of(r.get("shortId"));
        p.spx = str_of(r.get("spiderX"));
        p.pqv = str_of(r.get("mldsa65Verify"));
    }
    if let Some(w) = obj(&ss, "wsSettings") {
        p.path = str_of(w.get("path"));
        p.host = str_of(w.get("host")).or_else(|| obj(w, "headers").and_then(|h| str_of(h.get("Host"))));
    }
    if let Some(g) = obj(&ss, "grpcSettings") {
        p.service_name = str_of(g.get("serviceName"));
        p.authority = str_of(g.get("authority"));
        if g.get("multiMode").and_then(Value::as_bool) == Some(true) {
            p.mode = Some("multi".into());
        }
    }
    if let Some(h) = obj(&ss, "httpupgradeSettings") {
        p.path = str_of(h.get("path"));
        p.host = str_of(h.get("host"));
    }
    if let Some(x) = obj(&ss, "xhttpSettings").or_else(|| obj(&ss, "splithttpSettings")) {
        p.path = str_of(x.get("path"));
        p.host = str_of(x.get("host"));
        p.mode = str_of(x.get("mode"));
        p.extra = x.get("extra").filter(|e| e.is_object()).map(Value::to_string);
    }
    if let Some(t) = obj(&ss, "rawSettings").or_else(|| obj(&ss, "tcpSettings")) {
        if let Some(h) = obj(t, "header") {
            p.header_type = str_of(h.get("type"));
            if let Some(req) = obj(h, "request") {
                p.path = first_str_of_array_or_str(req.get("path"));
                p.host = obj(req, "headers").and_then(|hd| first_str_of_array_or_str(hd.get("Host")));
            }
        }
    }
    for ignored in ["sockopt", "finalmask"] {
        if ss.contains_key(ignored) {
            warnings.push(format!("Ignored streamSettings.{ignored}"));
        }
    }
    if o.contains_key("mux") || o.contains_key("proxySettings") {
        warnings.push("Ignored mux/proxySettings".into());
    }

    let st = stream::build(&p, &mut warnings)?;
    let (flow, vless_encryption, vmess_cipher) = match protocol {
        Protocol::Vless => (
            v::flow(&str_of(user.get("flow")).unwrap_or_default())?,
            v::vless_encryption(str_of(user.get("encryption")).as_deref())?,
            None,
        ),
        Protocol::Vmess => {
            if user.get("alterId").and_then(Value::as_u64).unwrap_or(0) > 0 {
                warnings.push("alterId > 0 (legacy VMess MD5 auth) is not supported by Xray; using VMess AEAD".into());
            }
            (String::new(), None, Some(v::vmess_cipher(str_of(user.get("security")).as_deref())?))
        }
    };
    let fallback = format!("{address}:{port}");
    let tag = str_of(o.get("tag")).filter(|t| !t.is_empty() && t != "proxy");
    let name = match (remarks, tag) {
        (Some(r), _) => v::clean_name(r, &fallback),
        (None, Some(t)) => v::clean_name(&t, &fallback),
        (None, None) => fallback,
    };
    let mut ps = ParsedServer {
        meta: ServerMeta {
            id: String::new(),
            name,
            protocol,
            address,
            port,
            transport: st.transport,
            security: st.security,
            flow,
            vmess_cipher,
            source: Source::Json,
            subscription_id: None,
            created_at: 0,
        },
        secrets: ServerSecrets {
            user_id,
            vless_encryption,
            reality_password: st.reality_password,
            reality_short_id: st.reality_short_id,
        },
        warnings,
    };
    v::server(&mut ps)?;
    Ok(ps)
}
