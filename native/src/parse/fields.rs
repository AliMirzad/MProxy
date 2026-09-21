//! Explicit field allowlists for every imported object.
//!
//! Imported configuration is data. Each object we read (JSON outbound, stream settings, share-link
//! query string, VMess link JSON, XHTTP `extra`) is checked key by key against a table:
//!
//! * `Used`      – read into the typed model (and validated there)
//! * `Silent`    – known, has no effect on a client connection (e.g. `level`, `email`); dropped
//! * `Ignored`   – known but not supported; dropped with a warning shown to the user
//! * `Dangerous` – could make Xray touch files, bind local interfaces, chain proxies, resolve
//!   names locally, or is server-side key material: the entry is **rejected**
//! * anything else – unknown: the entry is **rejected**
//!
//! Dropping is safe because nothing is forwarded: the Xray config is regenerated from the typed
//! model (`xrayconf.rs`). The tables follow the Xray-core v26.3.27 config structs
//! (`infra/conf/*.go`); keys were taken from the source at that tag.

use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Used,
    Silent,
    Ignored,
    Dangerous(&'static str),
}
use Kind::*;

pub type Table = &'static [(&'static str, Kind)];

/// Values that carry no setting (`null`, `false`, `""`, `0`, `{}`, `[]`) are accepted for any known
/// key, including dangerous ones: exporters often emit e.g. `"sockopt": {}`.
pub fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::String(s) => s.is_empty(),
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

pub fn lookup(table: Table, key: &str) -> Option<Kind> {
    table.iter().find(|(k, _)| *k == key).map(|(_, kind)| *kind)
}

/// Checks the keys of one JSON object. `ctx` names the object in messages.
pub fn check(obj: &Map<String, Value>, ctx: &str, table: Table, warnings: &mut Vec<String>) -> Result<(), String> {
    for (k, v) in obj {
        check_one(k, v, ctx, table, warnings)?;
    }
    Ok(())
}

pub fn check_one(k: &str, v: &Value, ctx: &str, table: Table, warnings: &mut Vec<String>) -> Result<(), String> {
    let name = || format!("{ctx}.{}", crate::validate::truncate(k, 40));
    match lookup(table, k) {
        Some(Used) | Some(Silent) => Ok(()),
        Some(Ignored) => {
            if !is_empty(v) {
                warnings.push(format!("Ignored {} (not supported)", name()));
            }
            Ok(())
        }
        Some(Dangerous(why)) => {
            if is_empty(v) {
                Ok(())
            } else {
                Err(format!("{} is not allowed: {why}", name()))
            }
        }
        None => Err(format!("Unsupported field {}", name())),
    }
}

/// Share-link query parameters: same classification, flat string values.
pub fn check_params<'a>(keys: impl Iterator<Item = (&'a String, &'a String)>, ctx: &str, table: Table, warnings: &mut Vec<String>) -> Result<(), String> {
    for (k, v) in keys {
        check_one(k, &Value::String(v.clone()), ctx, table, warnings)?;
    }
    Ok(())
}

const LOCAL_FILES: &str = "it makes Xray read or write local files";
const SOCKOPT: &str = "socket options can bind network interfaces, set routing marks or chain the connection through another outbound";
const SERVER_SIDE: &str = "it is a server-side setting (this looks like a server configuration, not a client link)";

/// Top level of a full Xray config. Only `outbounds` is imported; the other sections are never read
/// or forwarded (the import reports that they were not used).
pub const CONFIG: Table = &[
    ("outbounds", Used),
    ("remarks", Used),
    ("log", Silent),
    ("routing", Silent),
    ("dns", Silent),
    ("inbounds", Silent),
    ("policy", Silent),
    ("api", Silent),
    ("stats", Silent),
    ("metrics", Silent),
    ("observatory", Silent),
    ("burstObservatory", Silent),
    ("fakeDns", Silent),
    ("fakedns", Silent),
    ("reverse", Silent),
    ("transport", Silent),
    ("version", Silent),
];

pub const OUTBOUND: Table = &[
    ("protocol", Used),
    ("settings", Used),
    ("streamSettings", Used),
    ("tag", Used),
    ("mux", Ignored),
    ("sendThrough", Dangerous("it binds outgoing connections to a local address")),
    ("proxySettings", Dangerous("it chains the connection through another outbound")),
    ("targetStrategy", Dangerous("it makes Xray resolve destination names locally (DNS leak)")),
];

/// `settings` of a VLESS/VMess outbound: the classic `vnext` form or the flattened form.
pub const PROXY_SETTINGS: Table = &[
    ("vnext", Used),
    ("address", Used),
    ("port", Used),
    ("id", Used),
    ("flow", Used),
    ("encryption", Used),
    ("security", Used),
    ("alterId", Used),
    ("level", Silent),
    ("email", Silent),
    ("experiments", Ignored),
    ("reverse", Dangerous("VLESS reverse proxying exposes local services to the server")),
];

pub const VNEXT: Table = &[("address", Used), ("port", Used), ("users", Used)];

pub const USER: Table = &[
    ("id", Used),
    ("flow", Used),
    ("encryption", Used),
    ("security", Used),
    ("alterId", Used),
    ("level", Silent),
    ("email", Silent),
    ("experiments", Ignored),
];

pub const STREAM: Table = &[
    ("network", Used),
    ("method", Used),
    ("security", Used),
    ("tlsSettings", Used),
    ("realitySettings", Used),
    ("rawSettings", Used),
    ("tcpSettings", Used),
    ("wsSettings", Used),
    ("grpcSettings", Used),
    ("httpupgradeSettings", Used),
    ("xhttpSettings", Used),
    ("splithttpSettings", Used),
    // Settings blocks of transports we reject are harmless unless selected by `network`.
    ("kcpSettings", Silent),
    ("hysteriaSettings", Silent),
    ("quicSettings", Silent),
    ("httpSettings", Silent),
    ("sockopt", Dangerous(SOCKOPT)),
    ("finalmask", Dangerous("traffic masking (finalmask) is not supported")),
];

pub const TLS: Table = &[
    ("serverName", Used),
    ("alpn", Used),
    ("fingerprint", Used),
    ("pinnedPeerCertSha256", Used),
    ("echConfigList", Used),
    ("allowInsecure", Used),
    ("enableSessionResumption", Ignored),
    ("minVersion", Ignored),
    ("maxVersion", Ignored),
    ("cipherSuites", Ignored),
    ("curvePreferences", Ignored),
    ("echForceQuery", Ignored),
    ("disableSystemRoot", Ignored),
    ("verifyPeerCertByName", Ignored),
    ("verifyPeerCertInNames", Ignored),
    ("rejectUnknownSni", Silent),
    ("certificates", Dangerous(LOCAL_FILES)),
    ("masterKeyLog", Dangerous(LOCAL_FILES)),
    ("echServerKeys", Dangerous(SERVER_SIDE)),
    ("echSockopt", Dangerous(SOCKOPT)),
];

pub const REALITY: Table = &[
    ("serverName", Used),
    ("fingerprint", Used),
    ("password", Used),
    ("publicKey", Used),
    ("shortId", Used),
    ("spiderX", Used),
    ("mldsa65Verify", Used),
    ("show", Silent),
    ("masterKeyLog", Dangerous(LOCAL_FILES)),
    ("privateKey", Dangerous(SERVER_SIDE)),
    ("mldsa65Seed", Dangerous(SERVER_SIDE)),
    ("target", Dangerous(SERVER_SIDE)),
    ("dest", Dangerous(SERVER_SIDE)),
    ("type", Dangerous(SERVER_SIDE)),
    ("xver", Dangerous(SERVER_SIDE)),
    ("serverNames", Dangerous(SERVER_SIDE)),
    ("shortIds", Dangerous(SERVER_SIDE)),
    ("minClientVer", Dangerous(SERVER_SIDE)),
    ("maxClientVer", Dangerous(SERVER_SIDE)),
    ("maxTimeDiff", Dangerous(SERVER_SIDE)),
    ("limitFallbackUpload", Dangerous(SERVER_SIDE)),
    ("limitFallbackDownload", Dangerous(SERVER_SIDE)),
];

pub const WS: Table = &[
    ("path", Used),
    ("host", Used),
    ("headers", Used),
    ("heartbeatPeriod", Ignored),
    ("acceptProxyProtocol", Silent),
];

pub const HTTPUPGRADE: Table = &[("path", Used), ("host", Used), ("headers", Used), ("acceptProxyProtocol", Silent)];

pub const GRPC: Table = &[
    ("serviceName", Used),
    ("authority", Used),
    ("multiMode", Used),
    ("idle_timeout", Ignored),
    ("health_check_timeout", Ignored),
    ("permit_without_stream", Ignored),
    ("initial_windows_size", Ignored),
    ("user_agent", Ignored),
];

pub const RAW: Table = &[("header", Used), ("acceptProxyProtocol", Silent)];
pub const RAW_HEADER: Table = &[("type", Used), ("request", Used), ("response", Silent)];
pub const RAW_REQUEST: Table = &[("path", Used), ("headers", Used), ("version", Ignored), ("method", Ignored)];

/// XHTTP tuning keys, allowed in `xhttpSettings` and in its `extra` object. Scalars only; each is
/// validated by [`crate::validate::sanitize_xhttp_extra`].
pub const XHTTP_SCALARS: &[&str] = &[
    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
    "uplinkHTTPMethod",
    "sessionPlacement",
    "sessionKey",
    "seqPlacement",
    "seqKey",
    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",
    "noGRPCHeader",
    "noSSEHeader",
    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
];

/// Keys of `xhttpSettings` itself other than the scalars above.
pub const XHTTP: Table = &[
    ("path", Used),
    ("host", Used),
    ("mode", Used),
    ("extra", Used),
    ("headers", Used),
    ("xmux", Used),
    ("downloadSettings", Used),
    ("serverMaxHeaderBytes", Silent),
];

pub const XMUX: &[&str] = &["maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"];

pub const DOWNLOAD_SETTINGS: Table = &[
    ("address", Used),
    ("port", Used),
    ("network", Used),
    ("security", Used),
    ("tlsSettings", Used),
    ("realitySettings", Used),
    ("xhttpSettings", Used),
    ("splithttpSettings", Used),
    ("sockopt", Dangerous(SOCKOPT)),
    ("finalmask", Dangerous("traffic masking (finalmask) is not supported")),
];

/// `vless://` query parameters (XTLS share-link proposal, discussion #716).
pub const VLESS_PARAMS: Table = &[
    ("type", Used),
    ("headerType", Used),
    ("host", Used),
    ("path", Used),
    ("serviceName", Used),
    ("authority", Used),
    ("mode", Used),
    ("security", Used),
    ("sni", Used),
    ("peer", Used),
    ("alpn", Used),
    ("fp", Used),
    ("pbk", Used),
    ("sid", Used),
    ("spx", Used),
    ("pqv", Used),
    ("pcs", Used),
    ("ech", Used),
    ("extra", Used),
    ("allowInsecure", Used),
    ("insecure", Used),
    ("encryption", Used),
    ("flow", Used),
    // Parameters of transports that are rejected anyway (kcp/quic); harmless on their own.
    ("seed", Silent),
    ("quicSecurity", Silent),
    ("key", Silent),
    ("fm", Dangerous("traffic masking (finalmask) is not supported")),
];

/// Keys of the v2rayN `vmess://` JSON payload.
pub const VMESS_KEYS: Table = &[
    ("v", Silent),
    ("ps", Used),
    ("add", Used),
    ("port", Used),
    ("id", Used),
    ("aid", Used),
    ("scy", Used),
    ("net", Used),
    ("type", Used),
    ("host", Used),
    ("path", Used),
    ("tls", Used),
    ("sni", Used),
    ("alpn", Used),
    ("fp", Used),
    ("pbk", Used),
    ("sid", Used),
    ("spx", Used),
    ("pcs", Used),
    ("ech", Used),
    ("extra", Used),
    ("authority", Used),
    ("mode", Used),
    ("allowInsecure", Used),
    ("insecure", Used),
];
