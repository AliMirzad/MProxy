//! Connection state machine and command dispatch.
//!
//! A single service thread owns all mutable state. Stdin requests, a 500 ms tick (process
//! monitoring), and results from worker threads (connectivity probe, subscription fetch) all
//! arrive as [`Msg`]s on one channel, so there are no data races and no lock ordering to
//! reason about.
//!
//! ```text
//!   Disconnected ──connect──▶ Connecting(starting) ──xray listening──▶ Connecting(verifying)
//!        ▲                         │ failure                                │ probe ok
//!        │                         ▼                                        ▼
//!        └──────disconnect───── Error(code) ◀──crash, restarts exhausted── Connected
//!                                                                           │ crash (≤2/60s)
//!                                                     Connecting(restarting)◀┘
//! ```
//! Stale worker results are discarded by comparing their `attempt` number with the current one.

use crate::log;
use crate::model::{ServerMeta, ServerSecrets, ServerSummary};
use crate::parse;
use crate::ports;
use crate::probe;
use crate::protocol::*;
use crate::store::{self, Settings, Store, StoreError, SubscriptionMeta};
use crate::xray::{self, Running};
use crate::xrayconf::{self, JetbrainsPorts, RuntimePlan};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

pub enum Msg {
    Request(u32, Result<Request, ApiError>),
    Tick,
    ProbeDone { attempt: u64, result: Result<String, String> },
    SubscriptionDone { req_id: u32, job: SubJob, result: Result<String, String> },
    Shutdown,
}

pub struct SubJob {
    pub sub_id: String,
    pub name: String,
    pub url: String,
    pub is_new: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum ConnState {
    Disconnected,
    #[serde(rename_all = "camelCase")]
    Connecting { server_id: String, phase: &'static str },
    #[serde(rename_all = "camelCase")]
    Connected { server_id: String, port: u16, since: u64 },
    Disconnecting,
    #[serde(rename_all = "camelCase")]
    Error { code: ErrorCode, message: String, server_id: Option<String> },
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JetbrainsStatus {
    pub enabled: bool,
    /// "tunnel" | "direct" | "off"
    pub mode: &'static str,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub issue: Option<String>,
}

enum Mode {
    Off,
    Passthrough,
    Tunnel { server_id: String, port: u16, config: Vec<u8> },
}

pub struct Timing {
    pub listen_timeout: Duration,
    pub probe_timeout: Duration,
    pub max_restarts: usize,
    pub restart_window: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            listen_timeout: Duration::from_secs(6),
            probe_timeout: Duration::from_secs(8),
            max_restarts: 2,
            restart_window: Duration::from_secs(60),
        }
    }
}

pub struct Service {
    store: Store,
    xray_path: Option<PathBuf>,
    xray_version: Option<String>,
    run: Option<Running>,
    mode: Mode,
    state: ConnState,
    attempt: u64,
    restarts: Vec<Instant>,
    passthrough_failures: Vec<Instant>,
    jetbrains: JetbrainsStatus,
    last_xray_error: Vec<String>,
    out: Sender<Vec<u8>>,
    tx: Sender<Msg>,
    timing: Timing,
}

fn store_err(e: StoreError) -> ApiError {
    use crate::secrets::SecretError;
    match e {
        StoreError::Secret(SecretError::KeyMissing) | StoreError::Secret(SecretError::Corrupt) => ApiError::new(
            ErrorCode::SecureStorageUnavailable,
            "Saved credentials can't be decrypted. Use Settings → Remove all servers, then import them again.",
        ),
        StoreError::Secret(SecretError::Unavailable(m)) => ApiError::new(
            ErrorCode::SecureStorageUnavailable,
            format!("Secure storage is unavailable: {}", log::redact(&m)),
        ),
        StoreError::NotFound => ApiError::new(ErrorCode::NotFound, "Not found"),
        StoreError::Invalid(m) => ApiError::new(ErrorCode::InvalidConfig, m),
        StoreError::Io(m) => ApiError::new(ErrorCode::StoreError, format!("Local data error: {m}")),
    }
}

fn valid_id(id: &str) -> Result<(), ApiError> {
    if uuid::Uuid::parse_str(id).is_ok() {
        Ok(())
    } else {
        Err(ApiError::new(ErrorCode::InvalidRequest, "Invalid id"))
    }
}

impl Service {
    pub fn new(store: Store, xray_path: Option<PathBuf>, out: Sender<Vec<u8>>, tx: Sender<Msg>, timing: Timing) -> Service {
        // A binary that fails the pinned-hash check is reported as unavailable (and every launch
        // re-verifies, so it is never executed).
        let xray_version = xray_path.as_deref().and_then(|p| match xray::verify(p) {
            Ok(_) => Some(xray::PINNED_VERSION.trim_start_matches('v').to_string()),
            Err(e) => {
                log::error(format!("Xray unavailable: {e}"));
                None
            }
        });
        if let Some(p) = &xray_path {
            xray::reap_orphans(store.dir(), p);
        }
        Service {
            store,
            xray_path,
            xray_version,
            run: None,
            mode: Mode::Off,
            state: ConnState::Disconnected,
            attempt: 0,
            restarts: Vec::new(),
            passthrough_failures: Vec::new(),
            jetbrains: JetbrainsStatus { mode: "off", ..Default::default() },
            last_xray_error: Vec::new(),
            out,
            tx,
            timing,
        }
    }

    fn settings(&self) -> Settings {
        self.store.state().map(|s| s.settings).unwrap_or_default()
    }

    /// Runs until stdin closes. Always stops Xray before returning.
    pub fn run_loop(mut self, rx: Receiver<Msg>) {
        let s = self.settings();
        log::set_debug(s.debug_logging);
        self.ensure_passthrough();
        while let Ok(msg) = rx.recv() {
            match msg {
                Msg::Request(id, req) => {
                    let r = match req {
                        Ok(r) => self.handle(r, id),
                        Err(e) => Some(Err(e)),
                    };
                    if let Some(r) = r {
                        self.send(encode_response(id, &r));
                    }
                }
                Msg::Tick => self.check_process(),
                Msg::ProbeDone { attempt, result } => self.on_probe(attempt, result),
                Msg::SubscriptionDone { req_id, job, result } => {
                    let r = self.on_subscription(job, result);
                    self.send(encode_response(req_id, &r));
                }
                Msg::Shutdown => break,
            }
        }
        self.stop_xray();
        log::info("helper exiting");
    }

    fn send(&self, bytes: Vec<u8>) {
        let _ = self.out.send(bytes);
    }

    pub fn status_json(&self) -> Value {
        let mut v = serde_json::to_value(&self.state).unwrap_or(json!({"state":"error"}));
        let server_id = match &self.state {
            ConnState::Connecting { server_id, .. } | ConnState::Connected { server_id, .. } => Some(server_id.clone()),
            ConnState::Error { server_id, .. } => server_id.clone(),
            _ => None,
        };
        if let ConnState::Connected { port, .. } = &self.state {
            v["proxy"] = json!({ "scheme": "socks5", "host": xrayconf::LOOPBACK, "port": port });
        }
        if let ConnState::Error { code, message, .. } = &self.state {
            v["error"] = json!({ "code": code, "message": message });
        }
        if let Some(id) = server_id {
            v["serverId"] = json!(id);
        }
        v["jetbrains"] = serde_json::to_value(&self.jetbrains).unwrap_or(Value::Null);
        v["xrayAvailable"] = json!(self.xray_version.is_some());
        v
    }

    fn set_state(&mut self, s: ConnState) {
        if s != self.state {
            log::info(format!("state -> {}", serde_json::to_string(&s).unwrap_or_default()));
        }
        self.state = s;
        self.emit_status();
    }

    fn emit_status(&self) {
        self.send(encode_event("status", "status", &self.status_json()));
    }

    fn handle(&mut self, req: Request, id: u32) -> Option<ApiResult> {
        Some(match req {
            Request::Hello(a) => self.hello(a),
            Request::GetStatus(_) => Ok(self.status_json()),
            Request::ListServers(_) => self.list_servers(),
            Request::ImportText(a) => self.import_text(a),
            Request::AddSubscription(a) => return self.add_subscription(a, id),
            Request::UpdateSubscription(a) => return self.update_subscription(a, id),
            Request::DeleteSubscription(a) => self.delete_subscription(a),
            Request::RenameServer(a) => self.rename_server(a),
            Request::DeleteServer(a) => self.delete_server(a),
            Request::SelectServer(a) => self.select_server(a),
            Request::Connect(a) => self.connect(a),
            Request::Disconnect(_) => self.disconnect(),
            Request::GetSettings(_) => Ok(serde_json::to_value(self.settings()).unwrap_or(Value::Null)),
            Request::SetSettings(p) => self.set_settings(p),
            Request::GetDiagnostics(_) => Ok(self.diagnostics()),
            Request::ResetAll(a) => self.reset_all(a),
        })
    }

    fn hello(&mut self, a: HelloArgs) -> ApiResult {
        log::info(format!("hello from extension {} (protocol {})", crate::validate::truncate(&a.extension_version, 20), a.protocol_version));
        let info = json!({
            "nativeVersion": crate::NATIVE_VERSION,
            "protocolVersion": crate::PROTOCOL_VERSION,
            "xrayVersion": self.xray_version,
            "xrayAvailable": self.xray_version.is_some(),
            "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            "keyStorage": self.store.key_storage(),
        });
        if a.protocol_version != crate::PROTOCOL_VERSION {
            return Err(ApiError::new(
                ErrorCode::IncompatibleVersion,
                format!(
                    "The native runtime ({}) uses protocol v{} but the extension uses v{}. Update {}.",
                    crate::NATIVE_VERSION,
                    crate::PROTOCOL_VERSION,
                    a.protocol_version,
                    if a.protocol_version > crate::PROTOCOL_VERSION { "the native runtime" } else { "the extension" }
                ),
            ));
        }
        Ok(info)
    }

    fn list_servers(&self) -> ApiResult {
        let s = self.store.state().map_err(store_err)?;
        let servers: Vec<ServerSummary> = s.servers.iter().map(ServerSummary::from).collect();
        let subs: Vec<Value> = s
            .subscriptions
            .iter()
            .map(|sub| {
                json!({
                    "id": sub.id, "name": sub.name, "host": sub.host,
                    "lastUpdated": sub.last_updated, "lastError": sub.last_error,
                    "serverCount": s.servers.iter().filter(|m| m.subscription_id.as_deref() == Some(&sub.id)).count(),
                })
            })
            .collect();
        Ok(json!({ "servers": servers, "subscriptions": subs, "selectedServerId": s.selected_server_id }))
    }

    fn import_text(&mut self, a: ImportArgs) -> ApiResult {
        let batch = match a.source {
            ImportSource::Qr => parse::parse_qr_payload(&a.text),
            _ => parse::parse_subscription(&a.text),
        }
        .map_err(|m| ApiError::new(ErrorCode::InvalidConfig, m))?;
        if batch.servers.is_empty() {
            let msg = match (batch.errors.first(), batch.unsupported) {
                (Some(e), _) if batch.errors.len() == 1 => e.message.clone(),
                (Some(e), _) => format!("No valid servers found ({} rejected). First error: {}", batch.errors.len(), e.message),
                (None, n) if n > 0 => "Only VLESS and VMess configurations are supported".into(),
                _ => "No servers found".into(),
            };
            return Err(ApiError::new(ErrorCode::InvalidConfig, msg));
        }
        let mut warnings: Vec<String> = Vec::new();
        for w in batch.servers.iter().flat_map(|s| s.warnings.iter()) {
            if !warnings.contains(w) && warnings.len() < 10 {
                warnings.push(w.clone());
            }
        }
        let report = self
            .store
            .update_all(|st, sec| {
                let r = store::merge(st, sec, batch.servers, None)?;
                if st.selected_server_id.is_none() {
                    st.selected_server_id = r.server_ids.first().cloned();
                }
                Ok(r)
            })
            .map_err(store_err)?;
        log::info(format!("imported {} added / {} updated ({} rejected)", report.added, report.updated, batch.errors.len()));
        Ok(json!({
            "added": report.added, "updated": report.updated, "serverIds": report.server_ids,
            "errors": batch.errors.iter().take(20).collect::<Vec<_>>(), "rejected": batch.errors.len(),
            "unsupported": batch.unsupported, "warnings": warnings,
        }))
    }

    fn tunnel_port(&self) -> Option<u16> {
        match (&self.state, &self.mode) {
            (ConnState::Connected { .. }, Mode::Tunnel { port, .. }) => Some(*port),
            _ => None,
        }
    }

    fn spawn_subscription(&self, req_id: u32, job: SubJob) {
        let tx = self.tx.clone();
        let via = self.tunnel_port();
        std::thread::spawn(move || {
            let result = crate::subscription::fetch(&job.url, via);
            let _ = tx.send(Msg::SubscriptionDone { req_id, job, result });
        });
    }

    fn add_subscription(&mut self, a: AddSubscriptionArgs, req_id: u32) -> Option<ApiResult> {
        let u = match crate::subscription::validate_url(&a.url) {
            Ok(u) => u,
            Err(m) => return Some(Err(ApiError::new(ErrorCode::InvalidConfig, m))),
        };
        let host = crate::subscription::display_host(&u);
        let name = crate::validate::clean_name(&a.name, &host);
        log::info(format!("adding subscription from {host}"));
        self.spawn_subscription(req_id, SubJob { sub_id: uuid::Uuid::new_v4().to_string(), name, url: u.to_string(), is_new: true });
        None // answered in on_subscription
    }

    fn update_subscription(&mut self, a: IdArgs, req_id: u32) -> Option<ApiResult> {
        if let Err(e) = valid_id(&a.id) {
            return Some(Err(e));
        }
        let meta = match self.store.state().map_err(store_err) {
            Ok(s) => s.subscriptions.into_iter().find(|s| s.id == a.id),
            Err(e) => return Some(Err(e)),
        };
        let Some(meta) = meta else { return Some(Err(ApiError::new(ErrorCode::NotFound, "Subscription not found"))) };
        let url = match self.store.subscription_url(&a.id) {
            Ok(u) => u,
            Err(e) => return Some(Err(store_err(e))),
        };
        self.spawn_subscription(req_id, SubJob { sub_id: meta.id, name: meta.name, url, is_new: false });
        None
    }

    fn on_subscription(&mut self, job: SubJob, result: Result<String, String>) -> ApiResult {
        let parsed = result.and_then(|body| parse::parse_subscription(&body));
        let batch = match parsed {
            Ok(b) if !b.servers.is_empty() => b,
            Ok(b) => {
                let m = format!(
                    "The subscription contained no usable VLESS/VMess servers ({} rejected, {} unsupported)",
                    b.errors.len(),
                    b.unsupported
                );
                return self.subscription_failed(&job, m);
            }
            Err(m) => return self.subscription_failed(&job, m),
        };
        let rejected = batch.errors.len();
        let unsupported = batch.unsupported;
        let host = url::Url::parse(&job.url).map(|u| crate::subscription::display_host(&u)).unwrap_or_default();
        let report = self
            .store
            .update_all(|st, sec| {
                if job.is_new {
                    st.subscriptions.push(SubscriptionMeta { id: job.sub_id.clone(), name: job.name.clone(), host: host.clone(), last_updated: None, last_error: None });
                    sec.subscriptions.insert(job.sub_id.clone(), job.url.clone());
                } else if !st.subscriptions.iter().any(|s| s.id == job.sub_id) {
                    return Err(StoreError::NotFound); // deleted while fetching
                }
                let r = store::merge(st, sec, batch.servers, Some(&job.sub_id))?;
                if let Some(s) = st.subscriptions.iter_mut().find(|s| s.id == job.sub_id) {
                    s.last_updated = Some(store::now());
                    s.last_error = None;
                }
                if st.selected_server_id.is_none() {
                    st.selected_server_id = r.server_ids.first().cloned();
                }
                Ok(r)
            })
            .map_err(store_err)?;
        log::info(format!("subscription {host}: +{} ~{} -{} ({} rejected)", report.added, report.updated, report.removed, rejected));
        Ok(json!({
            "subscriptionId": job.sub_id, "added": report.added, "updated": report.updated,
            "removed": report.removed, "rejected": rejected, "unsupported": unsupported,
        }))
    }

    fn subscription_failed(&mut self, job: &SubJob, message: String) -> ApiResult {
        log::warn(format!("subscription update failed: {message}"));
        if !job.is_new {
            let m = message.clone();
            let _ = self.store.update_state(|st| {
                if let Some(s) = st.subscriptions.iter_mut().find(|s| s.id == job.sub_id) {
                    s.last_error = Some(m);
                }
                Ok(())
            });
        }
        Err(ApiError::new(ErrorCode::SubscriptionFailed, message))
    }

    fn delete_subscription(&mut self, a: DeleteSubscriptionArgs) -> ApiResult {
        valid_id(&a.id)?;
        let active = self.active_server_id();
        let removed_active = self
            .store
            .update_all(|st, _sec| {
                if !st.subscriptions.iter().any(|s| s.id == a.id) {
                    return Err(StoreError::NotFound);
                }
                st.subscriptions.retain(|s| s.id != a.id);
                let mut removed_active = false;
                if a.delete_servers {
                    removed_active = active.as_ref().is_some_and(|act| st.servers.iter().any(|m| &m.id == act && m.subscription_id.as_deref() == Some(&a.id)));
                    st.servers.retain(|m| m.subscription_id.as_deref() != Some(&a.id));
                    if st.selected_server_id.as_ref().is_some_and(|sel| !st.servers.iter().any(|m| &m.id == sel)) {
                        st.selected_server_id = None;
                    }
                } else {
                    for m in st.servers.iter_mut().filter(|m| m.subscription_id.as_deref() == Some(&a.id)) {
                        m.subscription_id = None;
                    }
                }
                Ok(removed_active)
            })
            .map_err(store_err)?;
        if removed_active {
            let _ = self.disconnect();
        }
        Ok(json!({}))
    }

    fn rename_server(&mut self, a: RenameArgs) -> ApiResult {
        valid_id(&a.id)?;
        let name = crate::validate::clean_name(&a.name, "");
        if name.is_empty() {
            return Err(ApiError::new(ErrorCode::InvalidRequest, "Name cannot be empty"));
        }
        self.store
            .update_state(|st| {
                let m = st.servers.iter_mut().find(|m| m.id == a.id).ok_or(StoreError::NotFound)?;
                m.name = name;
                Ok(())
            })
            .map_err(store_err)?;
        Ok(json!({}))
    }

    fn active_server_id(&self) -> Option<String> {
        match &self.state {
            ConnState::Connecting { server_id, .. } | ConnState::Connected { server_id, .. } => Some(server_id.clone()),
            _ => None,
        }
    }

    fn delete_server(&mut self, a: IdArgs) -> ApiResult {
        valid_id(&a.id)?;
        if self.active_server_id().as_deref() == Some(a.id.as_str()) {
            self.disconnect()?;
        }
        self.store
            .update_all(|st, _| {
                let before = st.servers.len();
                st.servers.retain(|m| m.id != a.id);
                if st.servers.len() == before {
                    return Err(StoreError::NotFound);
                }
                if st.selected_server_id.as_deref() == Some(a.id.as_str()) {
                    st.selected_server_id = st.servers.first().map(|m| m.id.clone());
                }
                Ok(())
            })
            .map_err(store_err)?;
        Ok(json!({}))
    }

    fn select_server(&mut self, a: IdArgs) -> ApiResult {
        valid_id(&a.id)?;
        self.store
            .update_state(|st| {
                if !st.servers.iter().any(|m| m.id == a.id) {
                    return Err(StoreError::NotFound);
                }
                st.selected_server_id = Some(a.id.clone());
                Ok(())
            })
            .map_err(store_err)?;
        Ok(json!({}))
    }

    fn set_settings(&mut self, p: SettingsPatch) -> ApiResult {
        for port in [p.jetbrains_socks_port, p.jetbrains_http_port].into_iter().flatten() {
            if port < 1024 {
                return Err(ApiError::new(ErrorCode::InvalidRequest, "Ports below 1024 are not allowed"));
            }
        }
        let new = self
            .store
            .update_state(|st| {
                let s = &mut st.settings;
                if let Some(v) = p.jetbrains_enabled { s.jetbrains_enabled = v; }
                if let Some(v) = p.jetbrains_socks_port { s.jetbrains_socks_port = v; }
                if let Some(v) = p.jetbrains_http_port { s.jetbrains_http_port = v; }
                if let Some(v) = p.passthrough_when_disconnected { s.passthrough_when_disconnected = v; }
                if let Some(v) = p.debug_logging { s.debug_logging = v; }
                if s.jetbrains_socks_port == s.jetbrains_http_port {
                    return Err(StoreError::Invalid("SOCKS and HTTP ports must differ".into()));
                }
                Ok(s.clone())
            })
            .map_err(store_err)?;
        log::set_debug(new.debug_logging);
        let mut reconnect_required = false;
        match self.mode {
            Mode::Tunnel { .. } => {
                reconnect_required = p.jetbrains_enabled.is_some() || p.jetbrains_socks_port.is_some() || p.jetbrains_http_port.is_some();
            }
            _ => {
                self.stop_xray();
                self.ensure_passthrough();
                self.emit_status();
            }
        }
        let mut v = serde_json::to_value(new).unwrap_or(Value::Null);
        v["reconnectRequired"] = json!(reconnect_required);
        Ok(v)
    }

    fn diagnostics(&self) -> Value {
        let debug = log::debug_enabled();
        json!({
            "nativeVersion": crate::NATIVE_VERSION,
            "protocolVersion": crate::PROTOCOL_VERSION,
            "xrayVersion": self.xray_version,
            "xrayPath": self.xray_path.as_ref().map(|p| p.display().to_string()),
            "dataDir": self.store.dir().display().to_string(),
            "logFile": log::log_path().map(|p| p.display().to_string()),
            "keyStorage": self.store.key_storage(),
            "xrayPid": self.run.as_ref().map(|r| r.pid),
            "xrayVerified": self.xray_version.is_some(),
            "xrayPinnedSha256": xray::PINNED_SHA256,
            "xrayIsolation": self.run.as_ref().and_then(|r| r.isolation()),
            "dataDirProtection": crate::harden::describe_dir(self.store.dir()),
            "debugLogging": debug,
            // Recent Xray output is shown only in debug mode (it can contain destinations).
            "recentXrayOutput": if debug { self.last_xray_error.clone() } else { vec![] },
        })
    }

    fn reset_all(&mut self, a: ResetArgs) -> ApiResult {
        if !a.confirm {
            return Err(ApiError::new(ErrorCode::InvalidRequest, "Confirmation required"));
        }
        let _ = self.disconnect();
        self.store.reset().map_err(store_err)?;
        log::info("all servers and credentials removed");
        Ok(json!({}))
    }

    // ---------------------------------------------------------------- lifecycle

    fn stop_xray(&mut self) {
        if let Some(r) = self.run.take() {
            self.last_xray_error = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
            r.stop();
        }
        self.mode = Mode::Off;
        self.jetbrains.mode = "off";
    }

    /// JetBrains ports for a new Xray instance; ports held by someone else are skipped.
    fn jetbrains_plan(&mut self, s: &Settings) -> JetbrainsPorts {
        self.jetbrains.enabled = s.jetbrains_enabled;
        self.jetbrains.socks_port = None;
        self.jetbrains.http_port = None;
        self.jetbrains.issue = None;
        if !s.jetbrains_enabled {
            return JetbrainsPorts { socks: None, http: None };
        }
        let mut busy = Vec::new();
        // A just-stopped Xray may hold the ports for a moment; wait briefly before declaring them busy.
        let wait = Duration::from_millis(1500);
        let socks = if ports::is_free_soon(s.jetbrains_socks_port, wait) { Some(s.jetbrains_socks_port) } else { busy.push(s.jetbrains_socks_port); None };
        let http = if ports::is_free_soon(s.jetbrains_http_port, wait) { Some(s.jetbrains_http_port) } else { busy.push(s.jetbrains_http_port); None };
        if !busy.is_empty() {
            let list = busy.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" and ");
            self.jetbrains.issue = Some(format!("Port {list} is in use by another program (or another browser running Private Proxy)"));
        }
        JetbrainsPorts { socks, http }
    }

    fn log_level() -> &'static str {
        if log::debug_enabled() { "info" } else { "warning" }
    }

    /// Starts the direct-passthrough instance when the tunnel is not active (if enabled).
    fn ensure_passthrough(&mut self) {
        if self.run.is_some() {
            return;
        }
        let s = self.settings();
        self.jetbrains.enabled = s.jetbrains_enabled;
        if !s.jetbrains_enabled || !s.passthrough_when_disconnected {
            self.jetbrains.mode = "off";
            self.jetbrains.issue = None;
            return;
        }
        let Some(xray_path) = self.xray_path.clone() else {
            self.jetbrains.issue = Some("Xray is not installed".into());
            return;
        };
        let jb = self.jetbrains_plan(&s);
        let Some(probe_port) = jb.http.or(jb.socks) else { return };
        let plan = RuntimePlan { browser_port: None, jetbrains: jb, log_level: Self::log_level() };
        let cfg = serde_json::to_vec(&xrayconf::passthrough_config(&plan)).unwrap_or_default();
        match xray::spawn(&xray_path, &cfg, self.store.dir()) {
            Ok(r) => {
                let ok = ports::wait_listening(probe_port, self.timing.listen_timeout, || r.try_exit().is_none());
                if ok {
                    self.jetbrains.socks_port = jb.socks;
                    self.jetbrains.http_port = jb.http;
                    self.jetbrains.mode = "direct";
                    self.run = Some(r);
                    self.mode = Mode::Passthrough;
                    log::info("passthrough endpoint started");
                } else {
                    self.last_xray_error = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
                    r.stop();
                    self.jetbrains.issue = Some("The local IDE proxy could not be started".into());
                    log::warn("passthrough instance failed to start");
                }
            }
            Err(e) => {
                self.jetbrains.issue = Some("The local IDE proxy could not be started".into());
                log::warn(format!("passthrough spawn failed: {e}"));
            }
        }
    }

    fn fail(&mut self, code: ErrorCode, message: impl Into<String>, server_id: Option<String>) {
        self.stop_xray();
        let message = message.into();
        log::warn(format!("connection failed: {code:?}: {message}"));
        // Restore passthrough first so the single emitted status is consistent.
        self.ensure_passthrough();
        self.set_state(ConnState::Error { code, message, server_id });
    }

    fn connect(&mut self, a: ConnectArgs) -> ApiResult {
        valid_id(&a.server_id)?;
        match &self.state {
            ConnState::Connecting { server_id, .. } | ConnState::Connected { server_id, .. } if *server_id == a.server_id => {
                return Ok(self.status_json()); // repeated click: idempotent
            }
            _ => {}
        }
        let (meta, secrets) = self.store.server_with_secrets(&a.server_id).map_err(|e| match e {
            StoreError::NotFound => ApiError::new(ErrorCode::NotFound, "Server not found"),
            e => store_err(e),
        })?;
        let _ = self.store.update_state(|st| {
            st.selected_server_id = Some(a.server_id.clone());
            Ok(())
        });
        self.attempt += 1;
        self.restarts.clear();
        self.stop_xray();
        self.set_state(ConnState::Connecting { server_id: a.server_id.clone(), phase: "starting" });
        self.start_tunnel(&meta, &secrets);
        Ok(self.status_json())
    }

    fn start_tunnel(&mut self, meta: &ServerMeta, secrets: &ServerSecrets) {
        let sid = meta.id.clone();
        let Some(xray_path) = self.xray_path.clone() else {
            return self.fail(ErrorCode::XrayMissing, "Xray is missing from the native runtime. Reinstall the runtime.", Some(sid));
        };
        if let Err(e) = xray::verify(&xray_path) {
            return self.fail(ErrorCode::XrayFailed, format!("Xray integrity check failed: {e}"), Some(sid));
        }
        let s = self.settings();
        let jb = self.jetbrains_plan(&s);
        let mut last_err = String::new();
        for try_no in 0..2 {
            let port = match ports::ephemeral_port() {
                Ok(p) => p,
                Err(e) => return self.fail(ErrorCode::PortUnavailable, format!("No free local port: {e}"), Some(sid)),
            };
            let plan = RuntimePlan { browser_port: Some(port), jetbrains: jb, log_level: Self::log_level() };
            let cfg = serde_json::to_vec(&xrayconf::tunnel_config(meta, secrets, &plan)).unwrap_or_default();
            if try_no == 0 {
                if let Err(reason) = xray::test_config(&xray_path, &cfg) {
                    return self.fail(ErrorCode::XrayConfigRejected, format!("Xray rejected this server's configuration: {reason}"), Some(sid));
                }
            }
            match xray::spawn(&xray_path, &cfg, self.store.dir()) {
                Ok(r) => {
                    if ports::wait_listening(port, self.timing.listen_timeout, || r.try_exit().is_none()) {
                        self.jetbrains.socks_port = jb.socks;
                        self.jetbrains.http_port = jb.http;
                        self.jetbrains.mode = "tunnel";
                        self.run = Some(r);
                        self.mode = Mode::Tunnel { server_id: sid.clone(), port, config: cfg };
                        self.set_state(ConnState::Connecting { server_id: sid, phase: "verifying" });
                        self.spawn_probe(port);
                        return;
                    }
                    let tail = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
                    r.stop();
                    last_err = tail.iter().rev().find(|l| !l.trim().is_empty()).cloned().unwrap_or_default();
                    self.last_xray_error = tail;
                    let bind_problem = last_err.contains("address already in use") || last_err.contains("Only one usage") || last_err.contains("bind");
                    if !bind_problem {
                        break;
                    }
                }
                Err(e) => {
                    last_err = e;
                    break;
                }
            }
        }
        let detail = last_err.rsplit(" > ").next().unwrap_or("").trim().to_string();
        let msg = if detail.is_empty() { "Xray failed to start".to_string() } else { format!("Xray failed to start: {}", crate::validate::truncate(&detail, 200)) };
        self.fail(ErrorCode::XrayFailed, msg, Some(sid));
    }

    fn spawn_probe(&self, port: u16) {
        let tx = self.tx.clone();
        let attempt = self.attempt;
        let per = self.timing.probe_timeout;
        std::thread::spawn(move || {
            let result = probe::probe(port, &probe::default_targets(), per, &|| false).map_err(|e| e.to_string());
            let _ = tx.send(Msg::ProbeDone { attempt, result });
        });
    }

    fn on_probe(&mut self, attempt: u64, result: Result<String, String>) {
        if attempt != self.attempt {
            return; // stale: user disconnected or switched servers meanwhile
        }
        let (sid, port) = match (&self.state, &self.mode) {
            (ConnState::Connecting { server_id, phase: "verifying" }, Mode::Tunnel { port, .. }) => (server_id.clone(), *port),
            _ => return,
        };
        match result {
            Ok(line) => {
                log::info(format!("connectivity verified ({line})"));
                self.set_state(ConnState::Connected { server_id: sid, port, since: store::now() });
            }
            Err(e) => {
                self.attempt += 1;
                // Technical detail goes to the log; the user gets a short, actionable message.
                log::warn(format!("connectivity probe failed: {e}"));
                self.fail(ErrorCode::ServerUnreachable, "Could not connect through this server.", Some(sid));
            }
        }
    }

    fn disconnect(&mut self) -> ApiResult {
        self.attempt += 1; // invalidates in-flight probes
        if matches!(self.mode, Mode::Tunnel { .. }) || matches!(self.state, ConnState::Connecting { .. } | ConnState::Connected { .. }) {
            self.set_state(ConnState::Disconnecting);
            self.stop_xray();
            self.ensure_passthrough();
            self.set_state(ConnState::Disconnected);
        } else if self.state != ConnState::Disconnected {
            self.set_state(ConnState::Disconnected); // clears a previous error
        }
        // else: repeated click, nothing to do (idempotent)
        Ok(self.status_json())
    }

    /// Called every 500 ms: detects Xray exiting unexpectedly.
    fn check_process(&mut self) {
        let exited = match &self.run {
            Some(r) => r.try_exit(),
            None => return,
        };
        let Some(how) = exited else { return };
        let r = self.run.take().expect("checked above");
        self.last_xray_error = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
        r.stop();
        log::warn(format!("Xray exited unexpectedly ({how})"));
        let last = self.last_xray_error.iter().rev().find(|l| !l.trim().is_empty()).cloned().unwrap_or_default();
        match std::mem::replace(&mut self.mode, Mode::Off) {
            Mode::Tunnel { server_id, port, config } => {
                let now = Instant::now();
                self.restarts.retain(|t| now.duration_since(*t) < self.timing.restart_window);
                let connected = matches!(self.state, ConnState::Connected { .. });
                if connected && self.restarts.len() < self.timing.max_restarts {
                    self.restarts.push(now);
                    self.set_state(ConnState::Connecting { server_id: server_id.clone(), phase: "restarting" });
                    if let Some(xp) = self.xray_path.clone() {
                        if let Ok(nr) = xray::spawn(&xp, &config, self.store.dir()) {
                            if ports::wait_listening(port, self.timing.listen_timeout, || nr.try_exit().is_none()) {
                                self.run = Some(nr);
                                self.mode = Mode::Tunnel { server_id: server_id.clone(), port, config };
                                self.jetbrains.mode = "tunnel";
                                log::info("Xray restarted after unexpected exit");
                                self.set_state(ConnState::Connected { server_id, port, since: store::now() });
                                return;
                            }
                            nr.stop();
                        }
                    }
                }
                self.attempt += 1;
                let msg = if last.is_empty() { "Xray stopped unexpectedly".to_string() } else { format!("Xray stopped unexpectedly: {}", crate::validate::truncate(last.rsplit(" > ").next().unwrap_or(&last), 160)) };
                self.fail(ErrorCode::XrayFailed, msg, Some(server_id));
            }
            Mode::Passthrough => {
                self.jetbrains.mode = "off";
                let now = Instant::now();
                self.passthrough_failures.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                self.passthrough_failures.push(now);
                if self.passthrough_failures.len() <= 2 {
                    self.ensure_passthrough();
                } else {
                    self.jetbrains.issue = Some("The local IDE proxy keeps stopping".into());
                }
                self.emit_status();
            }
            Mode::Off => {}
        }
    }
}
