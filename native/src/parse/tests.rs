use super::*;
use crate::model::*;
use base64::Engine;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ------------------------------------------------------------------ VLESS

#[test]
fn vless_reality_vision() {
    let l = format!("vless://{UUID}@de.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#Germany%20Reality");
    let p = parse_vless_uri(&l).unwrap();
    assert_eq!(p.meta.name, "Germany Reality");
    assert_eq!(p.meta.protocol, Protocol::Vless);
    assert_eq!(p.meta.address, "de.example.com");
    assert_eq!(p.meta.port, 443);
    assert_eq!(p.meta.flow, "xtls-rprx-vision");
    assert_eq!(p.meta.transport, Transport::Raw { header: RawHeader::None });
    match &p.meta.security {
        Security::Reality { server_name, fingerprint, spider_x, .. } => {
            assert_eq!(server_name, "www.microsoft.com");
            assert_eq!(fingerprint, "chrome");
            assert_eq!(spider_x.as_deref(), Some("/"));
        }
        s => panic!("{s:?}"),
    }
    assert_eq!(p.secrets.user_id, UUID);
    assert_eq!(p.secrets.reality_password.as_deref(), Some(PBK));
    assert_eq!(p.secrets.reality_short_id.as_deref(), Some("6ba85179e30d4fc2"));
    assert_eq!(p.secrets.vless_encryption, None);
}

#[test]
fn vless_ws_tls() {
    let l = format!("vless://{UUID}@1.2.3.4:8443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox#WS");
    let p = parse_vless_uri(&l).unwrap();
    assert_eq!(p.meta.transport, Transport::Ws { path: "/ws?ed=2048".into(), host: Some("cdn.example.com".into()) });
    match &p.meta.security {
        Security::Tls { server_name, alpn, fingerprint, .. } => {
            assert_eq!(server_name.as_deref(), Some("cdn.example.com"));
            assert_eq!(alpn, &vec!["h2".to_string(), "http/1.1".to_string()]);
            assert_eq!(fingerprint.as_deref(), Some("firefox"));
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn vless_grpc_multi() {
    let l = format!("vless://{UUID}@g.example.com:443?security=tls&type=grpc&serviceName=my-svc&mode=multi&sni=g.example.com#G");
    let p = parse_vless_uri(&l).unwrap();
    assert_eq!(p.meta.transport, Transport::Grpc { service_name: "my-svc".into(), authority: None, multi_mode: true });
}

#[test]
fn vless_xhttp_reality_with_extra() {
    let extra = percent_encoding::utf8_percent_encode(r#"{"xPaddingBytes":"100-1000","noGRPCHeader":false}"#, percent_encoding::NON_ALPHANUMERIC).to_string();
    let l = format!("vless://{UUID}@x.example.com:443?security=reality&type=xhttp&path=%2Fxh&mode=stream-one&sni=www.apple.com&pbk={PBK}&sid=&extra={extra}#X");
    let p = parse_vless_uri(&l).unwrap();
    match &p.meta.transport {
        Transport::Xhttp { path, mode, extra, .. } => {
            assert_eq!(path, "/xh");
            assert_eq!(mode, "stream-one");
            assert_eq!(extra.as_ref().unwrap()["xPaddingBytes"], "100-1000");
        }
        t => panic!("{t:?}"),
    }
    assert_eq!(p.secrets.reality_short_id, None);
}

#[test]
fn vless_splithttp_alias_and_httpupgrade() {
    let p = parse_vless_uri(&format!("vless://{UUID}@x.example.com:443?security=tls&type=splithttp&path=%2Fs#S")).unwrap();
    assert_eq!(p.meta.transport.name(), "xhttp");
    let p = parse_vless_uri(&format!("vless://{UUID}@x.example.com:443?security=tls&type=httpupgrade&path=%2Fu&host=x.example.com#U")).unwrap();
    assert_eq!(p.meta.transport, Transport::Httpupgrade { path: "/u".into(), host: Some("x.example.com".into()) });
}

#[test]
fn vless_ipv6_and_idn_and_defaults() {
    let p = parse_vless_uri(&format!("vless://{UUID}@[2001:db8::1]:443?security=tls")).unwrap();
    assert_eq!(p.meta.address, "2001:db8::1");
    assert_eq!(p.meta.name, "2001:db8::1:443");
    assert_eq!(p.meta.transport.name(), "raw");
    let p = parse_vless_uri(&format!("VLESS://{UUID}@b%C3%BCcher.de:443?security=tls#n")).unwrap();
    assert_eq!(p.meta.address, "xn--bcher-kva.de");
}

#[test]
fn vless_plus_is_not_space() {
    // Share links use encodeURIComponent semantics: a raw '+' is a plus, not a space.
    let p = parse_vless_uri(&format!("vless://{UUID}@a.example.com:443?security=tls&type=ws&path=%2Fa+b#n")).unwrap();
    assert_eq!(p.meta.transport, Transport::Ws { path: "/a+b".into(), host: None });
    let p = parse_vless_uri(&format!("vless://{UUID}@a.example.com:443?security=tls&type=ws&path=%2Fa%2Bb#n")).unwrap();
    assert_eq!(p.meta.transport, Transport::Ws { path: "/a+b".into(), host: None });
}

#[test]
fn vless_rejections() {
    let cases = [
        (format!("vless://{UUID}@a.example.com?security=tls"), "port"),
        (format!("vless://{UUID}@a.example.com:0?security=tls"), "port"),
        (format!("vless://{UUID}@a.example.com:99999?security=tls"), "port"),
        ("vless://not-a-uuid-and-far-too-long-to-be-custom@a.example.com:443".to_string(), "user ID"),
        (format!("vless://{UUID}@a.example.com:443?security=reality&sni=x.com"), "pbk"),
        (format!("vless://{UUID}@a.example.com:443?security=reality&pbk={PBK}"), "SNI"),
        (format!("vless://{UUID}@a.example.com:443?security=reality&sni=x.com&pbk={PBK}&type=ws"), "REALITY cannot"),
        (format!("vless://{UUID}@a.example.com:443?security=reality&sni=x.com&pbk={PBK}&sid=abc"), "short ID"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&type=h2"), "HTTP/2"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&type=quic"), "QUIC"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&type=carrier-pigeon"), "Unsupported transport"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&flow=xtls-rprx-evil"), "flow"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&type=ws&flow=xtls-rprx-vision"), "Vision"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&fp=bogus"), "fingerprint"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&path=%ZZ"), "percent"),
        (format!("vless://{UUID}@a b.com:443?security=tls"), "whitespace"),
        (format!("vless://{UUID}@2001:db8::1:443"), "brackets"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&type=xhttp&extra=not-json"), "extra"),
        (format!("vless://{UUID}@a.example.com:443?security=ssl"), "security"),
        (format!("vless://{UUID}@a.example.com:443?security=tls&encryption=aes"), "encryption"),
    ];
    for (link, want) in cases {
        let e = parse_vless_uri(&link).expect_err(&link);
        assert!(e.contains(want), "{link}: error {e:?} should mention {want:?}");
    }
}

#[test]
fn vless_allow_insecure_warns() {
    let p = parse_vless_uri(&format!("vless://{UUID}@a.example.com:443?security=tls&allowInsecure=1#n")).unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("allowInsecure")));
}

#[test]
fn vless_none_security_warns() {
    let p = parse_vless_uri(&format!("vless://{UUID}@10.0.0.5:8080?type=tcp#lan")).unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("unencrypted")));
}

// ------------------------------------------------------------------ VMess

fn vmess(json: &str) -> String {
    format!("vmess://{}", b64(json))
}

#[test]
fn vmess_ws_tls() {
    let l = vmess(&format!(r#"{{"v":"2","ps":"Work Server","add":"vm.example.com","port":"443","id":"{UUID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vm","tls":"tls","sni":"vm.example.com","alpn":"http/1.1","fp":"chrome"}}"#));
    let p = parse_vmess_uri(&l).unwrap();
    assert_eq!(p.meta.name, "Work Server");
    assert_eq!(p.meta.protocol, Protocol::Vmess);
    assert_eq!(p.meta.port, 443);
    assert_eq!(p.meta.vmess_cipher.as_deref(), Some("auto"));
    assert_eq!(p.meta.transport, Transport::Ws { path: "/vm".into(), host: Some("vm.example.com".into()) });
    assert_eq!(p.meta.security.name(), "tls");
    assert!(p.warnings.is_empty(), "{:?}", p.warnings);
}

#[test]
fn vmess_numeric_fields_urlsafe_unpadded_grpc() {
    let json = format!(r#"{{"v":2,"ps":"g","add":"1.2.3.4","port":8443,"id":"{UUID}","aid":0,"net":"grpc","path":"svc","type":"multi","tls":"tls"}}"#);
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);
    let p = parse_vmess_uri(&format!("vmess://{enc}")).unwrap();
    assert_eq!(p.meta.port, 8443);
    assert_eq!(p.meta.transport, Transport::Grpc { service_name: "svc".into(), authority: None, multi_mode: true });
}

#[test]
fn vmess_tcp_http_header_and_legacy_aid() {
    let l = vmess(&format!(r#"{{"v":"2","ps":"h","add":"h.example.com","port":"80","id":"{UUID}","aid":"64","net":"tcp","type":"http","host":"www.baidu.com","path":"/","tls":""}}"#));
    let p = parse_vmess_uri(&l).unwrap();
    assert_eq!(p.meta.transport, Transport::Raw { header: RawHeader::Http { host: vec!["www.baidu.com".into()], path: vec!["/".into()] } });
    assert!(p.warnings.iter().any(|w| w.contains("alterId")));
}

#[test]
fn vmess_rejections() {
    assert!(parse_vmess_uri("vmess://%%%notbase64").unwrap_err().contains("base64"));
    assert!(parse_vmess_uri(&format!("vmess://{}", b64("not json"))).unwrap_err().contains("JSON"));
    assert!(parse_vmess_uri(&vmess(r#"{"add":"a.com","port":"443"}"#)).unwrap_err().contains("user ID"));
    assert!(parse_vmess_uri(&vmess(&format!(r#"{{"add":"a.com","port":"x","id":"{UUID}"}}"#))).unwrap_err().contains("port"));
    assert!(parse_vmess_uri(&vmess(&format!(r#"{{"add":"a.com","port":"443","id":"{UUID}","scy":"rc4"}}"#))).unwrap_err().contains("security"));
    assert!(parse_vmess_uri(&vmess(&format!(r#"{{"add":"a.com","port":"443","id":"{UUID}","net":"h2","tls":"tls"}}"#))).unwrap_err().contains("HTTP/2"));
    assert!(parse_vmess_uri(&vmess("[1,2]")).unwrap_err().contains("object"));
}

// ------------------------------------------------------------------ JSON

#[test]
fn json_full_config_and_outbound() {
    let cfg = format!(
        r#"{{
        "remarks": "NL",
        "log": {{"loglevel": "debug", "access": "/tmp/access.log"}},
        "inbounds": [{{"listen": "0.0.0.0", "port": 1080, "protocol": "socks"}}],
        "outbounds": [
          {{"tag": "proxy", "protocol": "vless",
            "settings": {{"vnext": [{{"address": "nl.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
            "streamSettings": {{"network": "tcp", "security": "reality",
               "realitySettings": {{"serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "{PBK}", "shortId": "ab"}},
               "sockopt": {{"dialerProxy": "x"}}}},
            "mux": {{"enabled": true}}}},
          {{"tag": "direct", "protocol": "freedom"}},
          {{"tag": "block", "protocol": "blackhole"}}
        ]}}"#
    );
    // sockopt.dialerProxy would chain the connection through another outbound: rejected.
    let b = parse_xray_json(&cfg).unwrap();
    assert!(b.servers.is_empty());
    assert!(b.errors[0].message.contains("streamSettings.sockopt is not allowed"), "{:?}", b.errors);

    let cfg = cfg.replace(r#""sockopt": {"dialerProxy": "x"}"#, r#""sockopt": {}"#);
    let b = parse_xray_json(&cfg).unwrap();
    assert_eq!(b.servers.len(), 1);
    assert!(b.errors.is_empty());
    let p = &b.servers[0];
    assert_eq!(p.meta.name, "NL");
    assert_eq!(p.meta.source, Source::Json);
    assert_eq!(p.secrets.reality_password.as_deref(), Some(PBK));
    assert!(p.warnings.iter().any(|w| w.contains("outbound.mux")), "{:?}", p.warnings);
    assert!(p.warnings.iter().any(|w| w.contains("other sections")), "{:?}", p.warnings);

    // Single outbound, flattened settings, vmess.
    let ob = format!(r#"{{"protocol":"vmess","tag":"Office","settings":{{"address":"o.example.com","port":"443","id":"{UUID}","security":"aes-128-gcm"}},"streamSettings":{{"network":"ws","security":"tls","wsSettings":{{"path":"/o","headers":{{"Host":"o.example.com"}}}},"tlsSettings":{{"serverName":"o.example.com","allowInsecure":true}}}}}}"#);
    let b = parse_xray_json(&ob).unwrap();
    let p = &b.servers[0];
    assert_eq!(p.meta.name, "Office");
    assert_eq!(p.meta.vmess_cipher.as_deref(), Some("aes-128-gcm"));
    assert_eq!(p.meta.transport, Transport::Ws { path: "/o".into(), host: Some("o.example.com".into()) });
    assert!(p.warnings.iter().any(|w| w.contains("allowInsecure")));
}

#[test]
fn json_array_isolates_bad_entries() {
    let arr = format!(
        r#"[
        {{"remarks":"ok","outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"a.example.com","port":443,"users":[{{"id":"{UUID}"}}]}}]}},"streamSettings":{{"security":"tls"}}}}]}},
        {{"remarks":"bad","outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"a.example.com","port":70000,"users":[{{"id":"{UUID}"}}]}}]}}}}]}},
        {{"remarks":"trojan","outbounds":[{{"protocol":"trojan","settings":{{}}}}]}}
    ]"#
    );
    let b = parse_xray_json(&arr).unwrap();
    assert_eq!(b.servers.len(), 1);
    assert_eq!(b.errors.len(), 1);
    assert_eq!(b.unsupported, 1);
}

#[test]
fn json_rejections() {
    assert!(parse_xray_json("{not json").is_err());
    assert!(parse_xray_json(r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap_err().contains("No VLESS"));
    assert!(parse_xray_json(r#"{"foo":1}"#).is_err());
}

// ------------------------------------------------------------------ subscriptions

#[test]
fn subscription_base64_mixed() {
    let vm = vmess(&format!(r#"{{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"{UUID}","net":"ws","path":"/","tls":"tls"}}"#));
    let body = format!(
        "vless://{UUID}@a.example.com:443?security=tls#A\n{vm}\nss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss\ntrojan://pw@t.example.com:443#t\nvless://broken\n\n"
    );
    let b = parse_subscription(&b64(&body)).unwrap();
    assert_eq!(b.servers.len(), 2);
    assert_eq!(b.unsupported, 2);
    assert_eq!(b.errors.len(), 1);
    assert_eq!(b.errors[0].entry, 5);
}

#[test]
fn subscription_plain_crlf_and_bom() {
    let body = format!("\u{feff}vless://{UUID}@a.example.com:443?security=tls#A\r\nvless://{UUID}@b.example.com:443?security=tls#B\r\n");
    let b = parse_subscription(&body).unwrap();
    assert_eq!(b.servers.len(), 2);
}

#[test]
fn subscription_base64_with_newlines_and_urlsafe() {
    let body = format!("vless://{UUID}@a.example.com:443?security=tls#A");
    let enc = base64::engine::general_purpose::URL_SAFE.encode(&body);
    let wrapped: String = enc.as_bytes().chunks(20).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
    assert_eq!(parse_subscription(&wrapped).unwrap().servers.len(), 1);
}

#[test]
fn subscription_json_body() {
    let body = format!(r#"[{{"remarks":"j","outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"a.example.com","port":443,"users":[{{"id":"{UUID}"}}]}}]}},"streamSettings":{{"security":"tls"}}}}]}}]"#);
    assert_eq!(parse_subscription(&body).unwrap().servers.len(), 1);
    assert_eq!(parse_subscription(&b64(&body)).unwrap().servers.len(), 1);
}

#[test]
fn subscription_garbage() {
    assert!(parse_subscription("").is_err());
    assert!(parse_subscription("<html><body>Login</body></html>").is_err());
    assert!(parse_subscription("!!!!").is_err());
    let huge = "a".repeat(MAX_INPUT_BYTES + 1);
    assert!(parse_subscription(&huge).unwrap_err().contains("too large"));
}

#[test]
fn subscription_entry_limit() {
    let line = format!("vless://{UUID}@a.example.com:443?security=tls#A\n");
    let body = line.repeat(MAX_ENTRIES + 5);
    let b = parse_subscription(&body).unwrap();
    assert_eq!(b.servers.len(), MAX_ENTRIES);
    assert!(b.errors.iter().any(|e| e.message.contains("Too many")));
}

// ------------------------------------------------------------------ QR

#[test]
fn qr_accepts_only_proxy_payloads() {
    assert_eq!(parse_qr_payload(&format!("vless://{UUID}@a.example.com:443?security=tls#A")).unwrap().servers.len(), 1);
    for bad in ["https://evil.example.com/phish", "WIFI:S:home;T:WPA;P:secret;;", "hello world", "javascript:alert(1)", "tel:+123"] {
        assert!(parse_qr_payload(bad).unwrap_err().contains("does not contain"), "{bad}");
    }
    let sub = b64(&format!("vless://{UUID}@a.example.com:443?security=tls#A"));
    assert_eq!(parse_qr_payload(&sub).unwrap().servers.len(), 1);
}

// ------------------------------------------------------------------ fuzz-ish robustness

#[test]
fn never_panics_on_garbage() {
    let seeds = [
        "vless://", "vless://@", "vless://@:", "vless://a@b:1?", "vless://a@[::1", "vless://a@[::1]:", "vless://%@a:1",
        "vmess://", "vmess://e30=", "vmess://W10=", "vless://a@b:1?type=xhttp&extra=%7B%22downloadSettings%22%3A5%7D",
        "vless://a@b:1?security=reality&sni=%00", "vless://\u{202e}@b:1", "vless://a@b:1#%FF",
    ];
    for s in seeds {
        let _ = parse_link(s);
        let _ = parse_subscription(s);
        let _ = parse_qr_payload(s);
    }
    // Simple deterministic mutation of a valid link.
    let base = format!("vless://{UUID}@a.example.com:443?security=reality&sni=x.com&pbk={PBK}&sid=ab&type=grpc&serviceName=s#n");
    let bytes = base.as_bytes();
    let mut x: u32 = 12345;
    for _ in 0..3000 {
        let mut m = bytes.to_vec();
        for _ in 0..3 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            let i = (x as usize >> 8) % m.len();
            m[i] = (x >> 16) as u8 & 0x7f;
        }
        let _ = parse_link(&String::from_utf8_lossy(&m));
    }
}

// ------------------------------------------------------------------ Xray-JSON subscriptions

/// Xray-JSON subscriptions put several alternative outbounds (CDN fronts, load-balanced) into each
/// config. Each config is one server; only its main outbound is imported.
#[test]
fn json_config_with_alternative_outbounds_is_one_server() {
    let ob = |addr: &str, tag: &str, host: &str| {
        format!(r#"{{"tag":"{tag}","protocol":"vless","settings":{{"vnext":[{{"address":"{addr}","port":443,"users":[{{"id":"{UUID}","encryption":"none"}}]}}]}},"streamSettings":{{"network":"ws","security":"tls","tlsSettings":{{"serverName":"{host}"}},"wsSettings":{{"path":"/ws","headers":{{"Host":"{host}"}}}}}}}}"#)
    };
    let cfg = |name: &str, host: &str| {
        format!(
            r#"{{"remarks":"{name}","outbounds":[{},{},{},{{"tag":"direct","protocol":"freedom"}}],"routing":{{"balancers":[{{"tag":"b","selector":["proxy"]}}]}}}}"#,
            ob("cdnjs.com", "proxy", host),
            ob("chatgpt.com", "proxy-2", host),
            ob("sourceforge.net", "proxy-3", host)
        )
    };
    let body = format!(
        r#"[{},{},{{"remarks":"trojan only","outbounds":[{{"protocol":"trojan","settings":{{}}}}]}}]"#,
        cfg("DE [CDN1]", "de.example.com"),
        cfg("FI [CDN1]", "fi.example.com")
    );
    let b = parse_subscription(&body).unwrap();
    assert_eq!(b.servers.len(), 2, "one server per config, not one per outbound");
    assert_eq!(b.unsupported, 1);
    assert_eq!(b.servers[0].meta.name, "DE [CDN1]");
    assert_eq!(b.servers[0].meta.address, "cdnjs.com", "the main (first) outbound");
    assert!(b.servers[0].warnings.iter().any(|w| w.contains("2 more alternative")), "{:?}", b.servers[0].warnings);
    // Same CDN front address, different Host/SNI: two different servers.
    assert_ne!(b.servers[0].identity(), b.servers[1].identity());
}
