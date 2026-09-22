//! Normalized server model.
//!
//! A server is split into [`ServerMeta`] (non-sensitive, stored in plaintext JSON and
//! summarised for the UI) and [`ServerSecrets`] (stored only in the encrypted store).
//! Every parser produces a [`ParsedServer`]; every consumer (store, Xray config generator)
//! works from these types, never from raw links or raw JSON.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RawHeader {
    #[default]
    None,
    /// HTTP header obfuscation of the RAW (TCP) transport.
    Http {
        #[serde(default)]
        host: Vec<String>,
        #[serde(default)]
        path: Vec<String>,
    },
}

/// Transport ("network" in Xray terms). New transports are new variants; the parsers and the
/// generator each have one match arm per variant.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    Raw {
        #[serde(default)]
        header: RawHeader,
    },
    Ws {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Grpc {
        service_name: String,
        #[serde(default)]
        authority: Option<String>,
        #[serde(default)]
        multi_mode: bool,
    },
    Httpupgrade {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Xhttp {
        path: String,
        #[serde(default)]
        host: Option<String>,
        mode: String,
        /// Sanitized `xhttpSettings.extra` object (see `validate::sanitize_xhttp_extra`).
        #[serde(default)]
        extra: Option<Value>,
    },
}

impl Transport {
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Raw { .. } => "raw",
            Transport::Ws { .. } => "ws",
            Transport::Grpc { .. } => "grpc",
            Transport::Httpupgrade { .. } => "httpupgrade",
            Transport::Xhttp { .. } => "xhttp",
        }
    }
    pub fn display(&self) -> &'static str {
        match self {
            Transport::Raw { header: RawHeader::Http { .. } } => "TCP (HTTP header)",
            Transport::Raw { .. } => "TCP",
            Transport::Ws { .. } => "WebSocket",
            Transport::Grpc { .. } => "gRPC",
            Transport::Httpupgrade { .. } => "HTTPUpgrade",
            Transport::Xhttp { .. } => "XHTTP",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Security {
    None,
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default)]
        fingerprint: Option<String>,
        /// Comma separated hex SHA-256 certificate pins (replacement for `allowInsecure`).
        #[serde(default)]
        pinned_peer_cert_sha256: Option<String>,
        #[serde(default)]
        ech_config_list: Option<String>,
    },
    Reality {
        server_name: String,
        fingerprint: String,
        #[serde(default)]
        spider_x: Option<String>,
        #[serde(default)]
        mldsa65_verify: Option<String>,
    },
}

impl Security {
    pub fn name(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls { .. } => "tls",
            Security::Reality { .. } => "reality",
        }
    }
    pub fn display(&self) -> &'static str {
        match self {
            Security::None => "None",
            Security::Tls { .. } => "TLS",
            Security::Reality { .. } => "REALITY",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Link,
    Json,
    Subscription,
}

/// Where a profile came from (provenance), as clients and future policy see it.
///
/// A `Managed` source (profiles delivered by a company policy) is a planned addition for the
/// corporate mode (docs/managed-deployment.md); it is not represented until something produces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSource {
    /// Imported by the user (link, QR, JSON, file).
    Manual,
    /// Delivered by the subscription with this id; replaced or removed by its refreshes.
    Subscription(String),
}

/// The connection profile's non-sensitive part ("ConnectionProfile" in docs/core-api.md):
/// id, display name, protocol, endpoint, transport, security and provenance. Safe to persist in
/// plaintext and to summarise in a UI. The credential material lives in [`ServerSecrets`],
/// stored encrypted and referenced by the same `id`.
///
/// Every field was produced by the strict import pipeline; `name` is sanitized there
/// (`validate::clean_name`: no control, bidi or zero-width characters).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerMeta {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub transport: Transport,
    pub security: Security,
    /// VLESS flow (`xtls-rprx-vision`), empty when unused.
    #[serde(default)]
    pub flow: String,
    /// VMess cipher (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`).
    #[serde(default)]
    pub vmess_cipher: Option<String>,
    pub source: Source,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

impl ServerMeta {
    pub fn source(&self) -> ProfileSource {
        match &self.subscription_id {
            Some(id) => ProfileSource::Subscription(id.clone()),
            None => ProfileSource::Manual,
        }
    }
}

/// Credentials and key material. Only ever persisted inside the encrypted secrets file.
#[derive(Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct ServerSecrets {
    /// VLESS / VMess user id (UUID or Xray's 1-30 byte custom id).
    pub user_id: String,
    /// VLESS Encryption setting (`none` or an ML-KEM client string).
    #[serde(default)]
    pub vless_encryption: Option<String>,
    /// REALITY x25519 public key ("password" in current Xray).
    #[serde(default)]
    pub reality_password: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
}

impl std::fmt::Debug for ServerSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSecrets { <redacted> }")
    }
}

/// Output of every parser before it is assigned an ID and persisted.
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedServer {
    pub meta: ServerMeta,
    pub secrets: ServerSecrets,
    /// Non-fatal notes for the user (e.g. "allowInsecure ignored").
    pub warnings: Vec<String>,
}

impl ParsedServer {
    /// Identity used to match servers across subscription refreshes.
    pub fn identity(&self) -> String {
        identity_of(&self.meta, &self.secrets)
    }
}

/// Two entries are the same server only if everything that decides where the connection really
/// goes matches: CDN-fronted subscriptions reuse one front address (e.g. a CDN hostname) for many
/// different servers and tell them apart by Host header, path, service name or SNI.
pub fn identity_of(meta: &ServerMeta, secrets: &ServerSecrets) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        meta.protocol.as_str(),
        meta.address.to_ascii_lowercase(),
        meta.port,
        secrets.user_id,
        serde_json::to_string(&meta.transport).unwrap_or_default(),
        serde_json::to_string(&meta.security).unwrap_or_default()
    )
}

/// What the extension sees for each server: no credentials, no key material.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub transport: String,
    pub transport_label: String,
    pub security: String,
    pub security_label: String,
    pub flow: Option<String>,
    pub subscription_id: Option<String>,
}

impl From<&ServerMeta> for ServerSummary {
    fn from(m: &ServerMeta) -> Self {
        ServerSummary {
            id: m.id.clone(),
            name: m.name.clone(),
            protocol: m.protocol,
            address: m.address.clone(),
            port: m.port,
            transport: m.transport.name().into(),
            transport_label: m.transport.display().into(),
            security: m.security.name().into(),
            security_label: m.security.display().into(),
            flow: if m.flow.is_empty() { None } else { Some(m.flow.clone()) },
            subscription_id: m.subscription_id.clone(),
        }
    }
}
