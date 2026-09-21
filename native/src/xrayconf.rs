//! Generates the Xray runtime configuration from the normalized model.
//!
//! Invariants enforced here (and asserted in tests):
//! * every inbound listens on 127.0.0.1 only;
//! * no access log (no browsing history on disk);
//! * `domainStrategy: AsIs` and IP-literal-only routing rules, so the client never resolves
//!   destination hostnames locally; the remote server resolves them (see docs/architecture.md#dns);
//! * no file paths, sockopt, API, or other fields that reach outside the proxy data path.

use crate::model::*;
use serde_json::{json, Map, Value};

pub const LOOPBACK: &str = "127.0.0.1";

/// Private / special-purpose ranges that bypass the tunnel. Matching is on IP literals only.
pub const PRIVATE_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JetbrainsPorts {
    pub socks: Option<u16>,
    pub http: Option<u16>,
}

/// Credentials required on the IDE inbounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdeAuth {
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Clone)]
pub struct RuntimePlan {
    /// Browser-facing SOCKS inbound; `None` in passthrough mode. Always without authentication:
    /// Chromium cannot send SOCKS credentials.
    pub browser_port: Option<u16>,
    pub jetbrains: JetbrainsPorts,
    /// `Some`: the IDE HTTP and SOCKS inbounds require these credentials.
    pub ide_auth: Option<IdeAuth>,
    pub log_level: &'static str,
}

fn socks_inbound(tag: &str, port: u16, auth: Option<&IdeAuth>) -> Value {
    let settings = match auth {
        Some(a) => json!({ "auth": "password", "accounts": [{ "user": a.user, "pass": a.pass }], "udp": false }),
        None => json!({ "auth": "noauth", "udp": false }),
    };
    json!({ "tag": tag, "listen": LOOPBACK, "port": port, "protocol": "socks", "settings": settings })
}

fn http_inbound(tag: &str, port: u16, auth: Option<&IdeAuth>) -> Value {
    let settings = match auth {
        Some(a) => json!({ "accounts": [{ "user": a.user, "pass": a.pass }], "allowTransparent": false }),
        None => json!({ "allowTransparent": false }),
    };
    json!({ "tag": tag, "listen": LOOPBACK, "port": port, "protocol": "http", "settings": settings })
}

fn inbounds(plan: &RuntimePlan) -> Vec<Value> {
    let mut v = Vec::new();
    if let Some(p) = plan.browser_port {
        v.push(socks_inbound("browser-socks", p, None));
    }
    if let Some(p) = plan.jetbrains.socks {
        v.push(socks_inbound("ide-socks", p, plan.ide_auth.as_ref()));
    }
    if let Some(p) = plan.jetbrains.http {
        v.push(http_inbound("ide-http", p, plan.ide_auth.as_ref()));
    }
    v
}

/// Ports of our own inbounds, as an Xray port list ("a,b,c").
fn own_ports(plan: &RuntimePlan) -> Option<String> {
    let ports: Vec<String> = [plan.browser_port, plan.jetbrains.socks, plan.jetbrains.http].into_iter().flatten().map(|p| p.to_string()).collect();
    (!ports.is_empty()).then(|| ports.join(","))
}

/// Blocks requests aimed back at our own inbounds (e.g. a web page or local program sending
/// `GET http://127.0.0.1:10809/` to the HTTP inbound). Without this, Xray would proxy the
/// request to itself recursively until it runs out of connections.
fn self_loop_rules(plan: &RuntimePlan) -> Vec<Value> {
    match own_ports(plan) {
        None => vec![],
        Some(ports) => vec![
            json!({ "type": "field", "ip": ["127.0.0.0/8", "::1/128"], "port": ports, "outboundTag": "block" }),
            json!({ "type": "field", "domain": ["full:localhost"], "port": ports, "outboundTag": "block" }),
        ],
    }
}

fn log(plan: &RuntimePlan) -> Value {
    json!({ "loglevel": plan.log_level, "access": "none", "dnsLog": false })
}

/// Tunnel mode: every inbound goes to the selected server, except private IP literals.
pub fn tunnel_config(meta: &ServerMeta, secrets: &ServerSecrets, plan: &RuntimePlan) -> Value {
    let mut rules = self_loop_rules(plan);
    rules.push(json!({ "type": "field", "domain": ["full:localhost"], "outboundTag": "direct" }));
    rules.push(json!({ "type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "direct" }));
    json!({
        "log": log(plan),
        "inbounds": inbounds(plan),
        "outbounds": [
            proxy_outbound(meta, secrets),
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    })
}

/// Passthrough mode (tunnel disconnected): the JetBrains endpoint stays up and connects directly.
pub fn passthrough_config(plan: &RuntimePlan) -> Value {
    json!({
        "log": log(plan),
        "inbounds": inbounds(plan),
        "outbounds": [
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": { "domainStrategy": "AsIs", "rules": self_loop_rules(plan) }
    })
}

pub fn proxy_outbound(meta: &ServerMeta, secrets: &ServerSecrets) -> Value {
    let settings = match meta.protocol {
        Protocol::Vless => {
            let mut user = Map::new();
            user.insert("id".into(), secrets.user_id.clone().into());
            user.insert(
                "encryption".into(),
                secrets.vless_encryption.clone().unwrap_or_else(|| "none".into()).into(),
            );
            if !meta.flow.is_empty() {
                user.insert("flow".into(), meta.flow.clone().into());
            }
            json!({ "vnext": [ { "address": meta.address, "port": meta.port, "users": [ Value::Object(user) ] } ] })
        }
        Protocol::Vmess => json!({
            "vnext": [ {
                "address": meta.address,
                "port": meta.port,
                "users": [ {
                    "id": secrets.user_id,
                    "security": meta.vmess_cipher.clone().unwrap_or_else(|| "auto".into())
                } ]
            } ]
        }),
    };
    json!({
        "tag": "proxy",
        "protocol": meta.protocol.as_str(),
        "settings": settings,
        "streamSettings": stream_settings(meta, secrets)
    })
}

fn put_opt(m: &mut Map<String, Value>, k: &str, v: &Option<String>) {
    if let Some(v) = v {
        m.insert(k.into(), Value::String(v.clone()));
    }
}

fn stream_settings(meta: &ServerMeta, secrets: &ServerSecrets) -> Value {
    let mut ss = Map::new();
    ss.insert("network".into(), meta.transport.name().into());
    ss.insert("security".into(), meta.security.name().into());
    match &meta.transport {
        Transport::Raw { header } => {
            if let RawHeader::Http { host, path } = header {
                let mut req = json!({ "path": if path.is_empty() { vec!["/".to_string()] } else { path.clone() } });
                if !host.is_empty() {
                    req["headers"] = json!({ "Host": host });
                }
                ss.insert("rawSettings".into(), json!({ "header": { "type": "http", "request": req } }));
            }
        }
        Transport::Ws { path, host } => {
            let mut w = Map::new();
            w.insert("path".into(), path.clone().into());
            put_opt(&mut w, "host", host);
            ss.insert("wsSettings".into(), Value::Object(w));
        }
        Transport::Grpc { service_name, authority, multi_mode } => {
            let mut g = Map::new();
            g.insert("serviceName".into(), service_name.clone().into());
            put_opt(&mut g, "authority", authority);
            if *multi_mode {
                g.insert("multiMode".into(), true.into());
            }
            ss.insert("grpcSettings".into(), Value::Object(g));
        }
        Transport::Httpupgrade { path, host } => {
            let mut h = Map::new();
            h.insert("path".into(), path.clone().into());
            put_opt(&mut h, "host", host);
            ss.insert("httpupgradeSettings".into(), Value::Object(h));
        }
        Transport::Xhttp { path, host, mode, extra } => {
            let mut x = Map::new();
            x.insert("path".into(), path.clone().into());
            put_opt(&mut x, "host", host);
            x.insert("mode".into(), mode.clone().into());
            if let Some(e) = extra {
                x.insert("extra".into(), e.clone());
            }
            ss.insert("xhttpSettings".into(), Value::Object(x));
        }
    }
    match &meta.security {
        Security::None => {}
        Security::Tls { server_name, alpn, fingerprint, pinned_peer_cert_sha256, ech_config_list } => {
            let mut t = Map::new();
            put_opt(&mut t, "serverName", server_name);
            if !alpn.is_empty() {
                t.insert("alpn".into(), alpn.clone().into());
            }
            put_opt(&mut t, "fingerprint", fingerprint);
            put_opt(&mut t, "pinnedPeerCertSha256", pinned_peer_cert_sha256);
            put_opt(&mut t, "echConfigList", ech_config_list);
            ss.insert("tlsSettings".into(), Value::Object(t));
        }
        Security::Reality { server_name, fingerprint, spider_x, mldsa65_verify } => {
            let mut r = Map::new();
            r.insert("serverName".into(), server_name.clone().into());
            r.insert("fingerprint".into(), fingerprint.clone().into());
            put_opt(&mut r, "password", &secrets.reality_password);
            r.insert("shortId".into(), secrets.reality_short_id.clone().unwrap_or_default().into());
            put_opt(&mut r, "spiderX", spider_x);
            put_opt(&mut r, "mldsa65Verify", mldsa65_verify);
            ss.insert("realitySettings".into(), Value::Object(r));
        }
    }
    Value::Object(ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_link;

    fn plan() -> RuntimePlan {
        RuntimePlan {
            browser_port: Some(50000),
            jetbrains: JetbrainsPorts { socks: Some(10808), http: Some(10809) },
            ide_auth: None,
            log_level: "warning",
        }
    }

    fn all_listen_loopback(cfg: &Value) -> bool {
        cfg["inbounds"].as_array().unwrap().iter().all(|i| i["listen"] == LOOPBACK)
    }

    #[test]
    fn reality_vision_config() {
        let p = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI&sid=ab12&type=tcp&flow=xtls-rprx-vision#DE").unwrap();
        let cfg = tunnel_config(&p.meta, &p.secrets, &plan());
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(out["settings"]["vnext"][0]["users"][0]["encryption"], "none");
        let rs = &out["streamSettings"]["realitySettings"];
        assert_eq!(rs["password"], "OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI");
        assert_eq!(rs["shortId"], "ab12");
        assert_eq!(out["streamSettings"]["network"], "raw");
        assert!(all_listen_loopback(&cfg));
        assert_eq!(cfg["log"]["access"], "none");
        assert_eq!(cfg["routing"]["domainStrategy"], "AsIs");
        assert!(cfg.get("dns").is_none());
        // self-loop protection comes first and covers all our inbound ports
        assert_eq!(cfg["routing"]["rules"][0]["outboundTag"], "block");
        assert_eq!(cfg["routing"]["rules"][0]["port"], "50000,10808,10809");
    }

    #[test]
    fn passthrough_has_only_direct() {
        let mut pl = plan();
        pl.browser_port = None;
        let cfg = passthrough_config(&pl);
        assert_eq!(cfg["outbounds"][0]["protocol"], "freedom");
        assert!(cfg["outbounds"].as_array().unwrap().iter().all(|o| o["protocol"] == "freedom" || o["protocol"] == "blackhole"));
        assert_eq!(cfg["routing"]["rules"][0]["outboundTag"], "block");
        assert_eq!(cfg["routing"]["rules"][0]["port"], "10808,10809");
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 2);
        assert!(all_listen_loopback(&cfg));
    }

    #[test]
    fn no_dangerous_fields() {
        let links = [
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls&type=ws&path=%2Fws&host=h.example.com&sni=h.example.com#a",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls&type=grpc&serviceName=svc&mode=multi#b",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls&type=xhttp&path=%2Fx&mode=packet-up#c",
        ];
        for l in links {
            let p = parse_link(l).unwrap();
            let s = tunnel_config(&p.meta, &p.secrets, &plan()).to_string();
            for bad in ["sockopt", "masterKeyLog", "certificateFile", "allowInsecure", "0.0.0.0\"", "\"api\"", "access.log"] {
                assert!(!s.contains(bad), "{bad} in {s}");
            }
        }
    }
}
