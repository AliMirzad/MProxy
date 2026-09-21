//! Negative security tests: hostile imports must be rejected (or reduced to inert data), never
//! forwarded to Xray, and never crash the parser. Referenced from docs/security-gate.md.

use super::*;
use base64::Engine;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI";

fn outbound(extra_outbound: &str, extra_stream: &str, extra_tls: &str) -> String {
    format!(
        r#"{{"protocol":"vless"{extra_outbound},
            "settings":{{"vnext":[{{"address":"srv.example.com","port":443,"users":[{{"id":"{UUID}"}}]}}]}},
            "streamSettings":{{"network":"tcp","security":"tls"{extra_stream},
               "tlsSettings":{{"serverName":"srv.example.com"{extra_tls}}}}}}}"#
    )
}

fn json_err(text: &str) -> String {
    match parse_xray_json(text) {
        Ok(b) if b.servers.is_empty() => b.errors.first().map(|e| e.message.clone()).unwrap_or_default(),
        Ok(b) => panic!("accepted hostile JSON: {:?}", b.servers[0].meta),
        Err(e) => e,
    }
}

#[test]
fn dangerous_json_fields_reject_the_entry() {
    let cases = [
        (outbound(r#","sendThrough":"192.168.1.10""#, "", ""), "sendThrough"),
        (outbound(r#","proxySettings":{"tag":"other"}"#, "", ""), "proxySettings"),
        (outbound(r#","targetStrategy":"UseIPv4""#, "", ""), "targetStrategy"),
        (outbound("", r#","sockopt":{"interface":"eth0"}"#, ""), "sockopt"),
        (outbound("", r#","sockopt":{"dialerProxy":"x"}"#, ""), "sockopt"),
        (outbound("", r#","finalmask":{"x":1}"#, ""), "finalmask"),
        (outbound("", "", r#","masterKeyLog":"C:\\keys.log""#), "masterKeyLog"),
        (outbound("", "", r#","certificates":[{"certificateFile":"/etc/ssl/private/key.pem"}]"#), "certificates"),
        (outbound("", "", r#","echSockopt":{"mark":1}"#), "echSockopt"),
        // Unknown fields anywhere in the imported outbound.
        (outbound(r#","exec":"calc.exe""#, "", ""), "Unsupported field outbound.exec"),
        (outbound("", r#","scriptPath":"/bin/sh""#, ""), "Unsupported field streamSettings.scriptPath"),
        (outbound("", "", r#","keyLogFile":"x""#), "Unsupported field tlsSettings.keyLogFile"),
    ];
    for (json, want) in cases {
        let e = json_err(&json);
        assert!(e.contains(want), "expected {want:?} in {e:?}");
    }
    // Server-side REALITY material: this is a server config pasted as a client link.
    let reality = format!(
        r#"{{"protocol":"vless","settings":{{"address":"srv.example.com","port":443,"id":"{UUID}"}},
            "streamSettings":{{"network":"tcp","security":"reality",
              "realitySettings":{{"serverName":"www.example.com","password":"{PBK}","privateKey":"secret"}}}}}}"#
    );
    assert!(json_err(&reality).contains("server-side"));
    // VLESS reverse proxy would expose local services to the server.
    let reverse = format!(r#"{{"protocol":"vless","settings":{{"address":"srv.example.com","port":443,"id":"{UUID}","reverse":{{"tag":"r"}}}}}}"#);
    assert!(json_err(&reverse).contains("reverse"));
    // Unknown top-level section of a full config.
    let cfg = format!(r#"{{"outbounds":[{}],"plugins":[{{"path":"evil.dll"}}]}}"#, outbound("", "", ""));
    assert!(json_err(&cfg).contains("Unsupported field config.plugins"));
}

#[test]
fn empty_dangerous_fields_are_harmless() {
    let json = outbound(r#","sendThrough":"""#, r#","sockopt":{}"#, r#","masterKeyLog":"""#);
    assert_eq!(parse_xray_json(&json).unwrap().servers.len(), 1);
}

#[test]
fn unknown_link_parameters_are_rejected() {
    let base = format!("vless://{UUID}@srv.example.com:443?security=tls&sni=srv.example.com");
    assert!(parse_vless_uri(&base).is_ok());
    for (extra, want) in [
        ("&exec=calc.exe", "Unsupported field link parameter.exec"),
        ("&fm=%7B%7D", "finalmask"),
        ("&type=ws&path=%2F..%2F..%2Fetc%2Fpasswd", "path traversal"),
        ("&type=ws&path=%5C%5Cserver%5Cshare", "path traversal"),
        ("&type=ws&path=file%3A%2F%2F%2Fetc%2Fpasswd", "path traversal"),
        ("&type=grpc&serviceName=..%2F..%2Fx", "path traversal"),
    ] {
        let e = parse_vless_uri(&format!("{base}{extra}")).unwrap_err();
        assert!(e.contains(want), "{extra}: {e}");
    }
    let vm = |json: &str| format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
    let e = parse_vmess_uri(&vm(&format!(r#"{{"add":"srv.example.com","port":"443","id":"{UUID}","cmd":"rm -rf /"}}"#))).unwrap_err();
    assert!(e.contains("Unsupported field vmess.cmd"), "{e}");
}

#[test]
fn local_and_metadata_server_addresses_are_rejected() {
    // Unit tests run without test mode, i.e. with the release policy.
    for host in ["127.0.0.1", "localhost", "[::1]", "169.254.169.254", "0.0.0.0", "[fe80::1]", "224.0.0.1", "metadata.google.internal"] {
        let e = parse_vless_uri(&format!("vless://{UUID}@{host}:443?security=tls&sni=srv.example.com")).unwrap_err();
        assert!(e.contains("not allowed") || e.contains("loopback"), "{host}: {e}");
    }
    // Company-hosted servers on private networks remain importable.
    for host in ["10.20.30.40", "192.168.1.5", "vpn.corp", "[fd00::5]"] {
        assert!(parse_vless_uri(&format!("vless://{UUID}@{host}:443?security=tls&sni=srv.example.com")).is_ok(), "{host}");
    }
}

#[test]
fn command_injection_strings_stay_inert_data() {
    // A hostile display name is only ever data: stored and shown as text, never passed to a shell
    // (the helper starts exactly one program, Xray, with fixed arguments).
    let name = "$(rm -rf ~); `calc` | & > x %COMSPEC% ..\\..\\";
    let enc: String = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC).to_string();
    let p = parse_vless_uri(&format!("vless://{UUID}@srv.example.com:443?security=tls&sni=srv.example.com#{enc}")).unwrap();
    assert_eq!(p.meta.name, name);
    let cfg = crate::xrayconf::tunnel_config(&p.meta, &p.secrets, &crate::xrayconf::RuntimePlan {
        browser_port: Some(1080),
        jetbrains: crate::xrayconf::JetbrainsPorts { socks: None, http: None },
        log_level: "warning",
    });
    assert!(!cfg.to_string().contains("rm -rf"), "display names never reach the Xray config");
    // Shell metacharacters in network fields are rejected by the field validators.
    for host in ["srv.example.com;calc", "srv.example.com|id", "$(id).example.com", "`id`.example.com", "a&b.example.com"] {
        let e = parse_vless_uri(&format!("vless://{UUID}@{host}:443")).unwrap_err();
        assert!(e.contains("host") || e.contains("address") || e.contains("percent"), "{host}: {e}");
    }
    assert!(parse_vless_uri(&format!("vless://{UUID}@srv.example.com:443;calc")).is_err());
    assert!(parse_vless_uri(&format!("vless://{UUID}$(id)@srv.example.com:443")).is_err());
}

#[test]
fn malformed_and_oversized_inputs_fail_cleanly() {
    assert!(parse_subscription("!!!not base64 at all!!!").is_err());
    assert!(parse_subscription("dmxlc3M6Ly8=====garbage").is_err());
    assert!(parse_vmess_uri("vmess://%%%").is_err());
    assert!(parse_xray_json("{\"outbounds\": [").is_err());
    assert!(parse_xray_json(&"[".repeat(10_000)).is_err()); // deep nesting: serde's recursion limit
    let huge = "a".repeat(MAX_INPUT_BYTES + 1);
    assert!(parse_subscription(&huge).unwrap_err().contains("too large"));
    let many: String = (0..MAX_ENTRIES + 50).map(|i| format!("vless://{UUID}@s{i}.example.com:443?security=tls\n")).collect();
    let b = parse_subscription(&many).unwrap();
    assert_eq!(b.servers.len(), MAX_ENTRIES);
    assert!(b.errors.iter().any(|e| e.message.contains("Too many entries")));
    let long_line = format!("vless://{UUID}@srv.example.com:443?path={}", "a".repeat(MAX_LINE_BYTES));
    assert!(parse_link(&long_line).unwrap_err().contains("too long"));
}

#[test]
fn qr_payloads_other_than_proxy_configs_are_refused() {
    for payload in [
        "https://evil.example/download.exe",
        "WIFI:T:WPA;S:corp;P:secret;;",
        "javascript:alert(1)",
        "file:///C:/Windows/System32/calc.exe",
        "smb://attacker/share",
        "BEGIN:VCARD\nEND:VCARD",
    ] {
        assert!(parse_qr_payload(payload).is_err(), "{payload}");
    }
}

#[test]
fn random_input_never_panics() {
    // Deterministic xorshift "fuzz" over the parsers' entry points.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let alphabet = b"vlessmx:/@?&=#%[]{}\",:0123456789abcdef-._ \n\\$`|;<>ABCDEFGHIJKLMNOPQRSTUVWXYZ+";
    for _ in 0..3000 {
        let len = (x % 300) as usize;
        let mut s = String::from(match x % 4 {
            0 => "vless://",
            1 => "vmess://",
            2 => "{",
            _ => "",
        });
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push(alphabet[(x % alphabet.len() as u64) as usize] as char);
        }
        let _ = parse_subscription(&s);
        let _ = parse_qr_payload(&s);
        let _ = parse_link(&s);
        let _ = parse_xray_json(&s);
    }
}

#[test]
fn generated_config_contains_only_allowlisted_capabilities() {
    // A maximal valid import through every transport must still produce a config without any
    // file, API, interface-binding or non-loopback listener capability.
    let links = [
        format!("vless://{UUID}@srv.example.com:443?type=xhttp&security=reality&sni=www.example.com&pbk={PBK}&sid=ab&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"),
        format!("vless://{UUID}@srv.example.com:443?type=ws&security=tls&sni=srv.example.com&path=%2Fws&host=cdn.example.com"),
        format!("vless://{UUID}@srv.example.com:443?type=grpc&security=tls&serviceName=svc&mode=multi"),
    ];
    for l in links {
        let p = parse_vless_uri(&l).unwrap();
        let cfg = crate::xrayconf::tunnel_config(&p.meta, &p.secrets, &crate::xrayconf::RuntimePlan {
            browser_port: Some(1080),
            jetbrains: crate::xrayconf::JetbrainsPorts { socks: Some(10808), http: Some(10809) },
            log_level: "warning",
        });
        let s = cfg.to_string();
        for forbidden in ["sockopt", "masterKeyLog", "certificateFile", "keyFile", "\"api\"", "dialerProxy", "\"interface\"", "allowInsecure", "\"stats\"", "\"reverse\""] {
            assert!(!s.contains(forbidden), "{forbidden} in {s}");
        }
        for inbound in cfg["inbounds"].as_array().unwrap() {
            assert_eq!(inbound["listen"], "127.0.0.1");
        }
    }
}
