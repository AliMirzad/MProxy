//! The extension <-> helper message protocol (version [`crate::PROTOCOL_VERSION`]).
//!
//! The helper accepts only the closed set of commands below. Every argument struct uses
//! `deny_unknown_fields` and is validated before use. No command runs a program chosen by the
//! caller or touches a caller-chosen file path. See `shared/protocol/PROTOCOL.md`.
//!
//! Wire format:
//!   request  `{"id": <u32>, "cmd": "<name>", "args": {...}}`
//!   response `{"id": <u32>, "ok": true, "result": {...}}` | `{"id": <u32>, "ok": false, "error": {"code": "...", "message": "..."}}`
//!   event    `{"event": "status", "status": {...}}`

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ImportSource {
    Paste,
    Qr,
    File,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "cmd", content = "args", rename_all = "camelCase")]
pub enum Request {
    Hello(HelloArgs),
    GetStatus(Empty),
    ListServers(Empty),
    ImportText(ImportArgs),
    AddSubscription(AddSubscriptionArgs),
    UpdateSubscription(IdArgs),
    DeleteSubscription(DeleteSubscriptionArgs),
    RenameServer(RenameArgs),
    DeleteServer(IdArgs),
    SelectServer(IdArgs),
    Connect(ConnectArgs),
    Disconnect(Empty),
    GetSettings(Empty),
    SetSettings(SettingsPatch),
    GetDiagnostics(Empty),
    ResetAll(ResetArgs),
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HelloArgs {
    pub protocol_version: u32,
    pub extension_version: String,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImportArgs {
    pub text: String,
    pub source: ImportSource,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddSubscriptionArgs {
    pub name: String,
    pub url: String,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdArgs {
    pub id: String,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeleteSubscriptionArgs {
    pub id: String,
    pub delete_servers: bool,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenameArgs {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConnectArgs {
    pub server_id: String,
}

#[derive(Deserialize, Debug, PartialEq, Default, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SettingsPatch {
    pub jetbrains_enabled: Option<bool>,
    pub jetbrains_socks_port: Option<u16>,
    pub jetbrains_http_port: Option<u16>,
    pub passthrough_when_disconnected: Option<bool>,
    pub debug_logging: Option<bool>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResetArgs {
    pub confirm: bool,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidRequest,
    IncompatibleVersion,
    NotFound,
    InvalidConfig,
    XrayMissing,
    XrayFailed,
    XrayConfigRejected,
    PortUnavailable,
    ServerUnreachable,
    SubscriptionFailed,
    StoreError,
    SecureStorageUnavailable,
    Busy,
    Internal,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into() }
    }
}

pub type ApiResult = Result<Value, ApiError>;

/// Parses and structurally validates one inbound message.
/// Returns the request id (0 if absent/invalid) and the request or an error.
pub fn decode(bytes: &[u8]) -> (u32, Result<Request, ApiError>) {
    let bad = |m: &str| ApiError::new(ErrorCode::InvalidRequest, m);
    let v: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return (0, Err(bad("Message is not valid JSON"))),
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => return (0, Err(bad("Message must be a JSON object"))),
    };
    let id = obj.get("id").and_then(Value::as_u64).filter(|i| *i <= u32::MAX as u64).unwrap_or(0) as u32;
    if id == 0 {
        return (0, Err(bad("Missing or invalid id")));
    }
    if obj.keys().any(|k| k != "id" && k != "cmd" && k != "args") {
        return (id, Err(bad("Unexpected field in message")));
    }
    let cmd = match obj.get("cmd").and_then(Value::as_str) {
        Some(c) => c,
        None => return (id, Err(bad("Missing cmd"))),
    };
    let args = obj.get("args").cloned().unwrap_or_else(|| Value::Object(Default::default()));
    let tagged = serde_json::json!({ "cmd": cmd, "args": args });
    match serde_json::from_value::<Request>(tagged) {
        Ok(r) => (id, Ok(r)),
        Err(e) => {
            let msg = e.to_string();
            let msg = if msg.contains("unknown variant") { format!("Unknown command \"{}\"", crate::validate::truncate(cmd, 32)) } else { format!("Invalid arguments for {cmd}: {}", crate::validate::truncate(&msg, 120)) };
            (id, Err(bad(&msg)))
        }
    }
}

pub fn encode_response(id: u32, r: &ApiResult) -> Vec<u8> {
    let v = match r {
        Ok(result) => serde_json::json!({ "id": id, "ok": true, "result": result }),
        Err(e) => serde_json::json!({ "id": id, "ok": false, "error": e }),
    };
    serde_json::to_vec(&v).unwrap_or_default()
}

pub fn encode_event(name: &str, key: &str, payload: &Value) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("event".into(), name.into());
    m.insert(key.into(), payload.clone());
    serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_valid() {
        let (id, r) = decode(br#"{"id":3,"cmd":"connect","args":{"serverId":"abc"}}"#);
        assert_eq!(id, 3);
        assert_eq!(r.unwrap(), Request::Connect(ConnectArgs { server_id: "abc".into() }));
        let (_, r) = decode(br#"{"id":4,"cmd":"getStatus"}"#);
        assert_eq!(r.unwrap(), Request::GetStatus(Empty {}));
    }

    #[test]
    fn rejects_unknown_command_and_fields() {
        let (_, r) = decode(br#"{"id":1,"cmd":"exec","args":{"command":"rm -rf /"}}"#);
        assert!(r.unwrap_err().message.contains("Unknown command"));
        let (_, r) = decode(br#"{"id":1,"cmd":"connect","args":{"serverId":"a","path":"/bin/sh"}}"#);
        assert_eq!(r.unwrap_err().code, ErrorCode::InvalidRequest);
        let (_, r) = decode(br#"{"id":1,"cmd":"getStatus","args":{"x":1}}"#);
        assert!(r.is_err());
        let (_, r) = decode(br#"{"id":1,"cmd":"getStatus","extra":1}"#);
        assert!(r.is_err());
        let (id, r) = decode(br#"{"cmd":"getStatus"}"#);
        assert_eq!(id, 0);
        assert!(r.is_err());
        let (_, r) = decode(b"not json");
        assert!(r.is_err());
        let (_, r) = decode(br#"{"id":1,"cmd":"setSettings","args":{"jetbrainsSocksPort":70000}}"#);
        assert!(r.is_err());
    }

    #[test]
    fn encodes() {
        let s = String::from_utf8(encode_response(5, &Err(ApiError::new(ErrorCode::XrayMissing, "x")))).unwrap();
        assert!(s.contains("\"XRAY_MISSING\""));
        assert!(s.contains("\"ok\":false"));
    }
}
