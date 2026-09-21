//! Xray / V2Ray JSON import.
//!
//! Accepted shapes: a full client config (`{"outbounds":[...]}`), a single outbound object
//! (`{"protocol":"vless",...}`), or a JSON array of either.
//!
//! A full config is **one server**: its main outbound is imported (Xray's default route: the first
//! outbound if it is VLESS/VMess, else the one tagged `proxy`, else the first VLESS/VMess one).
//! Subscriptions in Xray-JSON format often put many alternative paths to the same server
//! (different CDN fronts, load-balanced) into each config; importing every outbound would turn one
//! server into dozens of entries. Only VLESS/VMess outbounds are
//! extracted. Every key of every object that is read is checked against the tables in
//! `fields.rs`: unknown or dangerous keys reject the entry. The imported JSON is never executed
//! or forwarded; the Xray config is regenerated from the normalized model (see `xrayconf.rs`).

use super::fields::{self, check};
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

/// Only the Host header is used from ws/httpupgrade headers; say so if others were present.
fn warn_extra_headers(o: &Obj, ctx: &str, warnings: &mut Vec<String>) {
    if let Some(h) = obj(o, "headers") {
        for k in h.keys().filter(|k| !k.eq_ignore_ascii_case("host")) {
            warnings.push(format!("Ignored {ctx}.headers.{} (only Host is supported)", v::truncate(k, 40)));
        }
    }
}

pub fn parse_xray_json(text: &str) -> Result<ParseBatch, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e.to_string().chars().take(80).collect::<String>()))?;
    // (outbound, remarks, config had other sections, number of alternative proxy outbounds skipped)
    let mut candidates: Vec<(Obj, Option<String>, bool, usize)> = Vec::new();
    let mut configs_without_proxy = 0usize;
    let mut collect = |item: &Value| -> Result<(), String> {
        let o = item.as_object().ok_or("JSON entries must be objects")?;
        if let Some(outs) = o.get("outbounds").and_then(Value::as_array) {
            check(o, "config", fields::CONFIG, &mut Vec::new())?;
            let remarks = str_of(o.get("remarks"));
            // Sections other than outbounds are never read; tell the user they were not used.
            let has_other = o.iter().any(|(k, v)| k != "outbounds" && k != "remarks" && !fields::is_empty(v));
            let is_proxy = |v: &Value| matches!(v.get("protocol").and_then(Value::as_str).map(str::to_ascii_lowercase).as_deref(), Some("vless") | Some("vmess"));
            let proxies: Vec<&Obj> = outs.iter().filter(|v| is_proxy(v)).filter_map(Value::as_object).collect();
            let main = outs
                .first()
                .filter(|v| is_proxy(v))
                .and_then(Value::as_object)
                .or_else(|| proxies.iter().copied().find(|o| o.get("tag").and_then(Value::as_str) == Some("proxy")))
                .or_else(|| proxies.first().copied());
            match main {
                Some(m) => candidates.push((m.clone(), remarks, has_other, proxies.len() - 1)),
                None => configs_without_proxy += 1,
            }
        } else if o.contains_key("protocol") {
            candidates.push((o.clone(), None, false, 0));
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

    let mut batch = ParseBatch { unsupported: configs_without_proxy, ..Default::default() };
    let mut entry = 0;
    for (o, remarks, has_other, alternatives) in candidates {
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
            Ok(mut p) => {
                if alternatives > 0 {
                    p.warnings.push(format!(
                        "A config contained {} more alternative outbound(s) to the same server (load balancing / fallback); only its main outbound was imported",
                        alternatives
                    ));
                }
                if has_other {
                    p.warnings.push("Only the VLESS/VMess outbound was imported; the config's other sections (inbounds, routing, dns, ...) were not used".into());
                }
                batch.servers.push(p)
            }
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
    let mut warnings = Vec::new();
    // mux is performance tuning only; a disabled mux block is not worth a warning.
    let mut checked = o.clone();
    if checked.get("mux").and_then(|m| m.get("enabled")).and_then(Value::as_bool) != Some(true) {
        checked.remove("mux");
    }
    check(&checked, "outbound", fields::OUTBOUND, &mut warnings)?;
    let settings = obj(o, "settings").ok_or("Outbound is missing \"settings\"")?;
    check(settings, "settings", fields::PROXY_SETTINGS, &mut warnings)?;

    // Either the classic vnext form or the flattened form accepted by newer Xray.
    let (server, user): (&Obj, &Obj) = match settings.get("vnext").and_then(Value::as_array) {
        Some(vnext) => {
            let srv = vnext.first().and_then(Value::as_object).ok_or("Outbound has an empty vnext")?;
            check(srv, "vnext", fields::VNEXT, &mut warnings)?;
            if vnext.len() > 1 {
                warnings.push("Only the first server of vnext was imported".into());
            }
            let users = srv.get("users").and_then(Value::as_array).ok_or("Outbound has no users")?;
            let u = users.first().and_then(Value::as_object).ok_or("Outbound has no users")?;
            check(u, "users", fields::USER, &mut warnings)?;
            (srv, u)
        }
        None => (settings, settings),
    };
    let address = v::address(&str_of(server.get("address")).ok_or("Outbound is missing the address")?)?;
    let port = v::port_from_json(server.get("port").ok_or("Outbound is missing the port")?)?;
    let user_id = v::user_id(&str_of(user.get("id")).ok_or("Outbound is missing the user ID")?)?;

    let ss = obj(o, "streamSettings").cloned().unwrap_or_default();
    check(&ss, "streamSettings", fields::STREAM, &mut warnings)?;
    let net = str_of(ss.get("network")).or_else(|| {
        str_of(ss.get("method")).map(|m| if m == "websocket" { "ws".into() } else { m })
    });
    let mut p = StreamParams { net: net.clone(), security: str_of(ss.get("security")), ..Default::default() };

    if let Some(t) = obj(&ss, "tlsSettings") {
        check(t, "tlsSettings", fields::TLS, &mut warnings)?;
        p.sni = str_of(t.get("serverName"));
        p.alpn = t.get("alpn").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","));
        p.fp = str_of(t.get("fingerprint"));
        p.pcs = str_of(t.get("pinnedPeerCertSha256"));
        p.ech = str_of(t.get("echConfigList"));
        p.allow_insecure = t.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false);
    }
    if let Some(r) = obj(&ss, "realitySettings") {
        check(r, "realitySettings", fields::REALITY, &mut warnings)?;
        p.sni = str_of(r.get("serverName"));
        p.fp = str_of(r.get("fingerprint"));
        p.pbk = str_of(r.get("password")).or_else(|| str_of(r.get("publicKey")));
        p.sid = str_of(r.get("shortId"));
        p.spx = str_of(r.get("spiderX"));
        p.pqv = str_of(r.get("mldsa65Verify"));
    }
    if let Some(w) = obj(&ss, "wsSettings") {
        check(w, "wsSettings", fields::WS, &mut warnings)?;
        warn_extra_headers(w, "wsSettings", &mut warnings);
        p.path = str_of(w.get("path"));
        p.host = str_of(w.get("host")).or_else(|| obj(w, "headers").and_then(|h| str_of(h.get("Host"))));
    }
    if let Some(g) = obj(&ss, "grpcSettings") {
        check(g, "grpcSettings", fields::GRPC, &mut warnings)?;
        p.service_name = str_of(g.get("serviceName"));
        p.authority = str_of(g.get("authority"));
        if g.get("multiMode").and_then(Value::as_bool) == Some(true) {
            p.mode = Some("multi".into());
        }
    }
    if let Some(h) = obj(&ss, "httpupgradeSettings") {
        check(h, "httpupgradeSettings", fields::HTTPUPGRADE, &mut warnings)?;
        warn_extra_headers(h, "httpupgradeSettings", &mut warnings);
        p.path = str_of(h.get("path"));
        p.host = str_of(h.get("host"));
    }
    if let Some(x) = obj(&ss, "xhttpSettings").or_else(|| obj(&ss, "splithttpSettings")) {
        // Tuning keys may sit directly in xhttpSettings or inside "extra"; both are merged into one
        // extra object and validated against the same allowlist.
        let mut extra = Obj::new();
        for (k, v) in x {
            match k.as_str() {
                "path" | "host" | "mode" => {}
                "extra" => match v {
                    Value::Object(e) => extra.extend(e.clone()),
                    Value::Null => {}
                    _ => return Err("xhttpSettings.extra must be an object".into()),
                },
                k if fields::XHTTP_SCALARS.contains(&k) || fields::lookup(fields::XHTTP, k).is_some() => {
                    extra.insert(k.to_string(), v.clone());
                }
                _ => return Err(format!("Unsupported field xhttpSettings.{}", v::truncate(k, 40))),
            }
        }
        p.path = str_of(x.get("path"));
        p.host = str_of(x.get("host"));
        p.mode = str_of(x.get("mode"));
        p.extra = (!extra.is_empty()).then(|| Value::Object(extra).to_string());
    }
    if let Some(t) = obj(&ss, "rawSettings").or_else(|| obj(&ss, "tcpSettings")) {
        check(t, "rawSettings", fields::RAW, &mut warnings)?;
        if let Some(h) = obj(t, "header") {
            check(h, "rawSettings.header", fields::RAW_HEADER, &mut warnings)?;
            p.header_type = str_of(h.get("type"));
            if let Some(req) = obj(h, "request") {
                check(req, "rawSettings.header.request", fields::RAW_REQUEST, &mut warnings)?;
                p.path = first_str_of_array_or_str(req.get("path"));
                p.host = obj(req, "headers").and_then(|hd| first_str_of_array_or_str(hd.get("Host")));
            }
        }
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
