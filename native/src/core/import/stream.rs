//! Shared construction of transport + security from share-link style parameters.
//! Used by both the VLESS URI parser and the VMess JSON-link parser.

use crate::core::profile::{RawHeader, Security, Transport};
use crate::core::validate as v;

#[derive(Default, Debug, Clone)]
pub struct StreamParams {
    pub net: Option<String>,
    pub header_type: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub service_name: Option<String>,
    pub authority: Option<String>,
    pub mode: Option<String>,
    pub security: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub fp: Option<String>,
    pub pbk: Option<String>,
    pub sid: Option<String>,
    pub spx: Option<String>,
    pub pqv: Option<String>,
    pub pcs: Option<String>,
    pub ech: Option<String>,
    pub extra: Option<String>,
    pub allow_insecure: bool,
}

pub struct Stream {
    pub transport: Transport,
    pub security: Security,
    pub reality_password: Option<String>,
    pub reality_short_id: Option<String>,
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

pub fn build(p: &StreamParams, warnings: &mut Vec<String>) -> v::VResult<Stream> {
    let net = non_empty(&p.net).unwrap_or("tcp").to_ascii_lowercase();
    let transport = match net.as_str() {
        "tcp" | "raw" => {
            let header = match non_empty(&p.header_type).unwrap_or("none") {
                "none" => RawHeader::None,
                "http" => RawHeader::Http {
                    host: v::host_header(p.host.as_deref())?.into_iter().collect(),
                    path: vec![v::http_path(p.path.as_deref())?],
                },
                other => return Err(format!("Unsupported TCP header type \"{}\"", v::truncate(other, 20))),
            };
            Transport::Raw { header }
        }
        "ws" | "websocket" => Transport::Ws {
            path: v::http_path(p.path.as_deref())?,
            host: v::host_header(p.host.as_deref())?,
        },
        "grpc" | "gun" => {
            // In share links grpc uses `serviceName`; in VMess JSON links it is `path`.
            let svc = non_empty(&p.service_name).or(non_empty(&p.path));
            let mode = non_empty(&p.mode).or(non_empty(&p.header_type)).unwrap_or("gun");
            Transport::Grpc {
                service_name: v::grpc_service_name(svc)?,
                authority: v::server_name("gRPC authority", p.authority.as_deref())?,
                multi_mode: mode == "multi",
            }
        }
        "httpupgrade" => Transport::Httpupgrade {
            path: v::http_path(p.path.as_deref())?,
            host: v::host_header(p.host.as_deref())?,
        },
        "xhttp" | "splithttp" => {
            let extra = match non_empty(&p.extra) {
                None => None,
                Some(s) => {
                    let val: serde_json::Value =
                        serde_json::from_str(s).map_err(|_| "XHTTP extra is not valid JSON".to_string())?;
                    v::sanitize_xhttp_extra(&val, warnings)?
                }
            };
            Transport::Xhttp {
                path: v::http_path(p.path.as_deref())?,
                host: v::host_header(p.host.as_deref())?,
                mode: v::xhttp_mode(p.mode.as_deref())?,
                extra,
            }
        }
        "h2" | "http" => {
            return Err(
                "The HTTP/2 (h2) transport was removed from Xray-core; ask the server operator for an XHTTP configuration"
                    .into(),
            )
        }
        "quic" => {
            return Err("The QUIC transport was removed from Xray-core; ask the server operator for an XHTTP configuration".into())
        }
        "kcp" | "mkcp" => return Err("The mKCP transport is not supported in this version".into()),
        other => return Err(format!("Unsupported transport \"{}\"", v::truncate(other, 20))),
    };

    let sec = non_empty(&p.security).unwrap_or("none").to_ascii_lowercase();
    let (security, reality_password, reality_short_id) = match sec.as_str() {
        "none" | "" => (Security::None, None, None),
        "tls" | "xtls" => {
            if p.allow_insecure && p.pcs.is_none() {
                warnings.push(
                    "allowInsecure was removed from Xray-core; the certificate will be verified normally".into(),
                );
            }
            (
                Security::Tls {
                    server_name: v::server_name("SNI", p.sni.as_deref())?,
                    alpn: v::alpn_list(p.alpn.as_deref().unwrap_or(""))?,
                    fingerprint: v::fingerprint(p.fp.as_deref(), false)?,
                    pinned_peer_cert_sha256: v::cert_pins(p.pcs.as_deref())?,
                    ech_config_list: v::ech_config_list(p.ech.as_deref())?,
                },
                None,
                None,
            )
        }
        "reality" => {
            let server_name = v::server_name("REALITY SNI", p.sni.as_deref())?
                .ok_or_else(|| "REALITY SNI (sni) is missing".to_string())?;
            let fingerprint = v::fingerprint(p.fp.as_deref(), true)?.unwrap_or_else(|| "chrome".into());
            (
                Security::Reality {
                    server_name,
                    fingerprint,
                    spider_x: v::spider_x(p.spx.as_deref())?,
                    mldsa65_verify: v::mldsa65_verify(p.pqv.as_deref())?,
                },
                Some(v::reality_password(p.pbk.as_deref())?),
                v::reality_short_id(p.sid.as_deref())?,
            )
        }
        other => return Err(format!("Unsupported security \"{}\"", v::truncate(other, 20))),
    };
    Ok(Stream { transport, security, reality_password, reality_short_id })
}
