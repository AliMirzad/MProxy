//! The Core API: the one surface clients use.
//!
//! The browser native-messaging adapter (`browser::adapter`) is the first client; a desktop
//! client would be a second one. Clients never launch Xray, touch the store directly or build
//! configuration: everything goes through [`Core`], which is therefore also the place where
//! future managed policy is enforced (below any UI, see docs/core-api.md#policy-enforcement-point).
//!
//! Concurrency model: a `Core` is owned by one thread. Slow work (health probe, subscription
//! download) runs on worker threads that post a [`CoreMsg`] back through the client-supplied
//! [`Poster`]; the client passes it to [`Core::handle`]. Everything that clients must react to is
//! queued as a [`CoreEvent`] and drained with [`Core::take_events`] after each call.

use crate::core::credentials::ProxyCredentials;
use crate::core::error::{CoreError, ErrorKind};
use crate::core::import::{self, EntryError};
use crate::core::probe;
use crate::core::profile::{ServerMeta, ServerSecrets, ServerSummary};
use crate::core::session::{ConnectionSession, LocalProxyEndpoint, RuntimeMode, SecretBytes, SessionState, StartPhase};
use crate::core::store::{self, Settings, Store, StoreError, SubscriptionMeta};
use crate::core::subscription;
use crate::core::xray_config::{self, JetbrainsPorts, RuntimePlan};
use crate::log;
use crate::runtime::{ports, xray};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Delivers a [`CoreMsg`] from a worker thread back to the thread that owns the `Core`.
pub type Poster = Arc<dyn Fn(CoreMsg) + Send + Sync>;

/// Correlates an asynchronous request (subscription add/refresh) with its completion event.
pub type Ticket = u64;

/// Internal messages that the owning thread feeds back into [`Core::handle`].
pub enum CoreMsg {
    /// Periodic supervision (every ~500 ms): detects Xray exiting unexpectedly.
    Tick,
    ProbeDone { attempt: u64, result: Result<String, String> },
    SubscriptionDone { ticket: Ticket, job: SubJob, result: Result<String, String> },
}

pub struct SubJob {
    sub_id: String,
    name: String,
    url: String,
    is_new: bool,
}

/// Something a client must react to.
#[derive(Debug)]
pub enum CoreEvent {
    /// The session or IDE-endpoint status changed. Snapshot taken at the time of the change.
    /// `browser_proxy` is set only while `Connected` (the browser client needs it to answer the
    /// local proxy's authentication challenge).
    StatusChanged { status: SessionStatus, browser_proxy: Option<LocalProxyEndpoint> },
    SubscriptionDone { ticket: Ticket, result: Result<RefreshReport, CoreError> },
}

pub struct Timing {
    pub listen_timeout: Duration,
    pub probe_timeout: Duration,
    pub max_restarts: usize,
    pub restart_window: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { listen_timeout: Duration::from_secs(6), probe_timeout: Duration::from_secs(8), max_restarts: 2, restart_window: Duration::from_secs(60) }
    }
}

// ---------------------------------------------------------------- API types

/// State of the local IDE (JetBrains and other apps) endpoint.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdeEndpointStatus {
    pub enabled: bool,
    /// "tunnel" | "direct" | "off"
    pub mode: &'static str,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub issue: Option<String>,
    /// The endpoint requires the credentials from [`Core::ide_credentials`].
    pub auth_required: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionStatus {
    pub state: SessionState,
    pub ide: IdeEndpointStatus,
    pub runtime_available: bool,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoreInfo {
    pub native_version: &'static str,
    pub xray_version: Option<String>,
    pub xray_available: bool,
    pub platform: String,
    pub key_storage: &'static str,
}

/// What this build and platform can actually do. Nothing is claimed that is not implemented.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilities {
    /// Authenticated loopback proxy for a browser.
    pub browser_proxy: bool,
    /// Authenticated loopback HTTP/SOCKS endpoint for IDEs and other proxy-aware apps.
    pub jetbrains_proxy: bool,
    /// Routing of selected applications without proxy support: not implemented (Phase 7).
    pub application_routing: bool,
    /// Data key in the OS credential store (not a file).
    pub secure_storage: bool,
    /// Xray runs under an OS isolation mechanism that is verified before it runs.
    pub runtime_isolation: bool,
}

#[derive(Debug, Clone)]
pub struct SubscriptionSummary {
    pub id: String,
    pub name: String,
    pub host: String,
    pub last_updated: Option<u64>,
    pub last_error: Option<String>,
    pub profile_count: usize,
}

#[derive(Debug, Clone)]
pub struct ProfileList {
    pub profiles: Vec<ServerSummary>,
    pub subscriptions: Vec<SubscriptionSummary>,
    pub selected_profile_id: Option<String>,
}

/// How pasted/scanned text should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// Links, a subscription body or supported JSON (paste, file).
    Text,
    /// A decoded QR payload: only proxy configurations are accepted (never URLs to open).
    Qr,
}

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub added: usize,
    pub updated: usize,
    pub profile_ids: Vec<String>,
    pub errors: Vec<EntryError>,
    pub rejected: usize,
    pub unsupported: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefreshReport {
    pub subscription_id: String,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub rejected: usize,
    pub unsupported: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsUpdate {
    pub jetbrains_enabled: Option<bool>,
    pub jetbrains_socks_port: Option<u16>,
    pub jetbrains_http_port: Option<u16>,
    pub passthrough_when_disconnected: Option<bool>,
    pub debug_logging: Option<bool>,
    pub allow_private_subscription_hosts: Option<bool>,
    pub ide_auth: Option<bool>,
}

/// Credentials of the IDE endpoint (shown to the user so they can configure their IDE).
#[derive(Clone)]
pub struct IdeCredentials {
    pub username: &'static str,
    pub password: String,
    pub required: bool,
    pub reconnect_required: bool,
}

impl std::fmt::Debug for IdeCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdeCredentials {{ username: {:?}, password: <redacted>, required: {} }}", self.username, self.required)
    }
}

/// Local diagnostics (never sent anywhere by the Core).
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub native_version: &'static str,
    pub xray_version: Option<String>,
    pub xray_path: Option<String>,
    pub data_dir: String,
    pub log_file: Option<String>,
    pub key_storage: &'static str,
    pub xray_pid: Option<u32>,
    pub xray_verified: bool,
    pub xray_pinned_sha256: &'static str,
    pub xray_isolation: Option<serde_json::Value>,
    pub data_dir_protection: Option<String>,
    pub debug_logging: bool,
    pub capabilities: RuntimeCapabilities,
    /// Recent Xray output, only in debug mode (it can contain destinations).
    pub recent_xray_output: Vec<String>,
}

fn not_found(what: &str) -> CoreError {
    CoreError::new(ErrorKind::NotFound, format!("{what} not found"))
}

fn valid_id(id: &str) -> Result<(), CoreError> {
    if uuid::Uuid::parse_str(id).is_ok() {
        Ok(())
    } else {
        Err(CoreError::new(ErrorKind::InvalidRequest, "Invalid id"))
    }
}

// ---------------------------------------------------------------- Core

pub struct Core {
    store: Store,
    xray_path: Option<PathBuf>,
    xray_version: Option<String>,
    session: ConnectionSession,
    passthrough_failures: Vec<Instant>,
    ide: IdeEndpointStatus,
    last_xray_error: Vec<String>,
    post: Poster,
    events: Vec<CoreEvent>,
    timing: Timing,
}

impl Core {
    pub fn new(store: Store, xray_path: Option<PathBuf>, post: Poster, timing: Timing) -> Core {
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
        Core {
            store,
            xray_path,
            xray_version,
            session: ConnectionSession::default(),
            passthrough_failures: Vec::new(),
            ide: IdeEndpointStatus { mode: "off", ..Default::default() },
            last_xray_error: Vec::new(),
            post,
            events: Vec::new(),
            timing,
        }
    }

    /// Applies logging settings and starts the IDE endpoint (if enabled). Call once.
    pub fn start(&mut self) {
        log::set_debug(self.settings().debug_logging);
        self.ensure_passthrough();
    }

    /// Stops Xray. Call before exiting.
    pub fn shutdown(&mut self) {
        self.stop_xray();
    }

    pub fn take_events(&mut self) -> Vec<CoreEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn handle(&mut self, msg: CoreMsg) {
        match msg {
            CoreMsg::Tick => self.check_process(),
            CoreMsg::ProbeDone { attempt, result } => self.on_probe(attempt, result),
            CoreMsg::SubscriptionDone { ticket, job, result } => {
                let result = self.on_subscription(job, result);
                self.events.push(CoreEvent::SubscriptionDone { ticket, result });
            }
        }
    }

    // ------------------------------------------------------------ info

    pub fn info(&self) -> CoreInfo {
        CoreInfo {
            native_version: crate::NATIVE_VERSION,
            xray_version: self.xray_version.clone(),
            xray_available: self.xray_version.is_some(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            key_storage: self.store.key_storage(),
        }
    }

    pub fn runtime_capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            browser_proxy: true,
            jetbrains_proxy: true,
            application_routing: false,
            secure_storage: self.store.key_storage() != "file",
            runtime_isolation: cfg!(any(windows, target_os = "macos")),
        }
    }

    pub fn settings(&self) -> Settings {
        self.store.state().map(|s| s.settings).unwrap_or_default()
    }

    pub fn session_status(&self) -> SessionStatus {
        SessionStatus { state: self.session.state().clone(), ide: self.ide.clone(), runtime_available: self.xray_version.is_some() }
    }

    /// The authenticated local proxy the browser must use; `None` unless `Connected`. The only
    /// accessor for the per-connection credentials.
    pub fn browser_proxy_endpoint(&self) -> Option<LocalProxyEndpoint> {
        self.session.browser_endpoint()
    }

    pub fn diagnostics(&self) -> Diagnostics {
        let debug = log::debug_enabled();
        Diagnostics {
            native_version: crate::NATIVE_VERSION,
            xray_version: self.xray_version.clone(),
            xray_path: self.xray_path.as_ref().map(|p| p.display().to_string()),
            data_dir: self.store.dir().display().to_string(),
            log_file: log::log_path().map(|p| p.display().to_string()),
            key_storage: self.store.key_storage(),
            xray_pid: self.session.run.as_ref().map(|r| r.pid),
            xray_verified: self.xray_version.is_some(),
            xray_pinned_sha256: xray::PINNED_SHA256,
            xray_isolation: self.session.run.as_ref().and_then(|r| r.isolation()),
            data_dir_protection: crate::platform::harden::describe_dir(self.store.dir()),
            debug_logging: debug,
            capabilities: self.runtime_capabilities(),
            recent_xray_output: if debug { self.last_xray_error.clone() } else { vec![] },
        }
    }

    // ------------------------------------------------------------ profiles

    pub fn list_profiles(&self) -> Result<ProfileList, CoreError> {
        let s = self.store.state()?;
        let subscriptions = s
            .subscriptions
            .iter()
            .map(|sub| SubscriptionSummary {
                id: sub.id.clone(),
                name: sub.name.clone(),
                host: sub.host.clone(),
                last_updated: sub.last_updated,
                last_error: sub.last_error.clone(),
                profile_count: s.servers.iter().filter(|m| m.subscription_id.as_deref() == Some(&sub.id)).count(),
            })
            .collect();
        Ok(ProfileList { profiles: s.servers.iter().map(ServerSummary::from).collect(), subscriptions, selected_profile_id: s.selected_server_id })
    }

    /// Imports untrusted text through the strict parser. Only validated, normalized profiles are
    /// stored; nothing of the input reaches Xray except through the trusted config generator.
    pub fn import_profiles(&mut self, text: &str, kind: ImportKind) -> Result<ImportReport, CoreError> {
        let batch = match kind {
            ImportKind::Qr => import::parse_qr_payload(text),
            ImportKind::Text => import::parse_subscription(text),
        }
        .map_err(|m| CoreError::new(ErrorKind::InvalidProfile, m))?;
        if batch.servers.is_empty() {
            let msg = match (batch.errors.first(), batch.unsupported) {
                (Some(e), _) if batch.errors.len() == 1 => e.message.clone(),
                (Some(e), _) => format!("No valid servers found ({} rejected). First error: {}", batch.errors.len(), e.message),
                (None, n) if n > 0 => "Only VLESS and VMess configurations are supported".into(),
                _ => "No servers found".into(),
            };
            return Err(CoreError::new(ErrorKind::InvalidProfile, msg));
        }
        let mut warnings: Vec<String> = Vec::new();
        for w in batch.servers.iter().flat_map(|s| s.warnings.iter()) {
            if !warnings.contains(w) && warnings.len() < 10 {
                warnings.push(w.clone());
            }
        }
        let report = self.store.update_all(|st, sec| {
            let r = store::merge(st, sec, batch.servers, None)?;
            if st.selected_server_id.is_none() {
                st.selected_server_id = r.server_ids.first().cloned();
            }
            Ok(r)
        })?;
        log::info(format!("imported {} added / {} updated ({} rejected)", report.added, report.updated, batch.errors.len()));
        Ok(ImportReport {
            added: report.added,
            updated: report.updated,
            profile_ids: report.server_ids,
            rejected: batch.errors.len(),
            errors: batch.errors.into_iter().take(20).collect(),
            unsupported: batch.unsupported,
            warnings,
        })
    }

    pub fn rename_profile(&mut self, id: &str, name: &str) -> Result<(), CoreError> {
        valid_id(id)?;
        let name = crate::core::validate::clean_name(name, "");
        if name.is_empty() {
            return Err(CoreError::new(ErrorKind::InvalidRequest, "Name cannot be empty"));
        }
        self.store.update_state(|st| {
            let m = st.servers.iter_mut().find(|m| m.id == id).ok_or(StoreError::NotFound)?;
            m.name = name;
            Ok(())
        })?;
        Ok(())
    }

    pub fn remove_profile(&mut self, id: &str) -> Result<(), CoreError> {
        valid_id(id)?;
        if self.session.state().active_profile_id() == Some(id) {
            self.stop_session();
        }
        self.store.update_all(|st, _| {
            let before = st.servers.len();
            st.servers.retain(|m| m.id != id);
            if st.servers.len() == before {
                return Err(StoreError::NotFound);
            }
            if st.selected_server_id.as_deref() == Some(id) {
                st.selected_server_id = st.servers.first().map(|m| m.id.clone());
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn select_profile(&mut self, id: &str) -> Result<(), CoreError> {
        valid_id(id)?;
        self.store.update_state(|st| {
            if !st.servers.iter().any(|m| m.id == id) {
                return Err(StoreError::NotFound);
            }
            st.selected_server_id = Some(id.to_string());
            Ok(())
        })?;
        Ok(())
    }

    /// Removes all profiles, subscriptions and credentials (and the data key).
    pub fn reset_all(&mut self) -> Result<(), CoreError> {
        self.stop_session();
        self.store.reset()?;
        log::info("all servers and credentials removed");
        Ok(())
    }

    // ------------------------------------------------------------ subscriptions

    fn subscription_policy(&self) -> subscription::Policy {
        subscription::Policy { allow_private: self.settings().allow_private_subscription_hosts }
    }

    /// While connected, fetches go through the tunnel's authenticated inbound (DNS on the server).
    fn tunnel_via(&self) -> Option<subscription::Via> {
        match (self.session.state(), &self.session.mode) {
            (SessionState::Connected { .. }, RuntimeMode::Tunnel { port, credentials, .. }) => Some(subscription::Via { port: *port, auth: credentials.clone() }),
            _ => None,
        }
    }

    fn spawn_subscription(&self, ticket: Ticket, job: SubJob) {
        let post = self.post.clone();
        let via = self.tunnel_via();
        let policy = self.subscription_policy();
        std::thread::spawn(move || {
            let result = subscription::fetch(&job.url, via.as_ref(), &policy);
            post(CoreMsg::SubscriptionDone { ticket, job, result });
        });
    }

    /// Validates the URL against the destination policy now and downloads it in the background;
    /// completes with [`CoreEvent::SubscriptionDone`].
    pub fn add_subscription(&mut self, name: &str, url: &str, ticket: Ticket) -> Result<(), CoreError> {
        let u = subscription::validate_url(url, &self.subscription_policy()).map_err(|m| CoreError::new(ErrorKind::InvalidProfile, m))?;
        let host = subscription::display_host(&u);
        let name = crate::core::validate::clean_name(name, &host);
        log::info(format!("adding subscription from {host}"));
        self.spawn_subscription(ticket, SubJob { sub_id: uuid::Uuid::new_v4().to_string(), name, url: u.to_string(), is_new: true });
        Ok(())
    }

    /// Re-downloads a subscription in the background; completes with [`CoreEvent::SubscriptionDone`].
    pub fn refresh_subscription(&mut self, id: &str, ticket: Ticket) -> Result<(), CoreError> {
        valid_id(id)?;
        let meta = self.store.state()?.subscriptions.into_iter().find(|s| s.id == id).ok_or_else(|| not_found("Subscription"))?;
        let url = self.store.subscription_url(id)?;
        self.spawn_subscription(ticket, SubJob { sub_id: meta.id, name: meta.name, url, is_new: false });
        Ok(())
    }

    fn on_subscription(&mut self, job: SubJob, result: Result<String, String>) -> Result<RefreshReport, CoreError> {
        let parsed = result.and_then(|body| import::parse_subscription(&body));
        let batch = match parsed {
            Ok(b) if !b.servers.is_empty() => b,
            Ok(b) => {
                let m = format!("The subscription contained no usable VLESS/VMess servers ({} rejected, {} unsupported)", b.errors.len(), b.unsupported);
                return Err(self.subscription_failed(&job, m));
            }
            Err(m) => return Err(self.subscription_failed(&job, m)),
        };
        let rejected = batch.errors.len();
        let unsupported = batch.unsupported;
        let host = url::Url::parse(&job.url).map(|u| subscription::display_host(&u)).unwrap_or_default();
        let report = self.store.update_all(|st, sec| {
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
        })?;
        log::info(format!("subscription {host}: +{} ~{} -{} ({} rejected)", report.added, report.updated, report.removed, rejected));
        Ok(RefreshReport { subscription_id: job.sub_id, added: report.added, updated: report.updated, removed: report.removed, rejected, unsupported })
    }

    fn subscription_failed(&mut self, job: &SubJob, message: String) -> CoreError {
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
        CoreError::new(ErrorKind::SubscriptionFailure, message)
    }

    /// Removes a subscription; its profiles are removed too, or kept as manual profiles.
    pub fn remove_subscription(&mut self, id: &str, remove_profiles: bool) -> Result<(), CoreError> {
        valid_id(id)?;
        let active = self.session.state().active_profile_id().map(str::to_string);
        let removed_active = self.store.update_all(|st, _sec| {
            if !st.subscriptions.iter().any(|s| s.id == id) {
                return Err(StoreError::NotFound);
            }
            st.subscriptions.retain(|s| s.id != id);
            let mut removed_active = false;
            if remove_profiles {
                removed_active = active.as_ref().is_some_and(|act| st.servers.iter().any(|m| &m.id == act && m.subscription_id.as_deref() == Some(id)));
                st.servers.retain(|m| m.subscription_id.as_deref() != Some(id));
                if st.selected_server_id.as_ref().is_some_and(|sel| !st.servers.iter().any(|m| &m.id == sel)) {
                    st.selected_server_id = None;
                }
            } else {
                for m in st.servers.iter_mut().filter(|m| m.subscription_id.as_deref() == Some(id)) {
                    m.subscription_id = None;
                }
            }
            Ok(removed_active)
        })?;
        if removed_active {
            self.stop_session();
        }
        Ok(())
    }

    // ------------------------------------------------------------ settings and IDE endpoint

    /// Returns the new settings and whether a reconnect is needed for them to take effect.
    pub fn update_settings(&mut self, p: SettingsUpdate) -> Result<(Settings, bool), CoreError> {
        for port in [p.jetbrains_socks_port, p.jetbrains_http_port].into_iter().flatten() {
            if port < 1024 {
                return Err(CoreError::new(ErrorKind::InvalidRequest, "Ports below 1024 are not allowed"));
            }
        }
        let new = self.store.update_state(|st| {
            let s = &mut st.settings;
            if let Some(v) = p.jetbrains_enabled { s.jetbrains_enabled = v; }
            if let Some(v) = p.jetbrains_socks_port { s.jetbrains_socks_port = v; }
            if let Some(v) = p.jetbrains_http_port { s.jetbrains_http_port = v; }
            if let Some(v) = p.passthrough_when_disconnected { s.passthrough_when_disconnected = v; }
            if let Some(v) = p.debug_logging { s.debug_logging = v; }
            if let Some(v) = p.allow_private_subscription_hosts { s.allow_private_subscription_hosts = v; }
            if let Some(v) = p.ide_auth { s.ide_auth = v; }
            if s.jetbrains_socks_port == s.jetbrains_http_port {
                return Err(StoreError::Invalid("SOCKS and HTTP ports must differ".into()));
            }
            Ok(s.clone())
        })?;
        log::set_debug(new.debug_logging);
        let mut reconnect_required = false;
        if self.session.is_tunnel() {
            reconnect_required = p.jetbrains_enabled.is_some() || p.jetbrains_socks_port.is_some() || p.jetbrains_http_port.is_some() || p.ide_auth.is_some();
        } else {
            self.stop_xray();
            self.ensure_passthrough();
            self.status_changed();
        }
        Ok((new, reconnect_required))
    }

    /// Credentials of the IDE endpoint (to show to the user). `regenerate` invalidates the old
    /// password immediately (the running endpoint is restarted, or a reconnect is requested).
    pub fn ide_credentials(&mut self, regenerate: bool) -> Result<IdeCredentials, CoreError> {
        let password = if regenerate { self.store.regenerate_ide_password() } else { self.store.ide_password() }?;
        if regenerate && self.settings().ide_auth {
            // Running inbounds still use the old password: restart them with the new one.
            if self.session.is_tunnel() {
                return Ok(IdeCredentials { username: store::IDE_USER, password, required: true, reconnect_required: true });
            }
            self.stop_xray();
            self.ensure_passthrough();
            self.status_changed();
        }
        Ok(IdeCredentials { username: store::IDE_USER, password, required: self.settings().ide_auth, reconnect_required: false })
    }

    /// Credentials the IDE inbounds must require, if enabled.
    fn ide_auth(&self, s: &Settings) -> Result<Option<ProxyCredentials>, String> {
        if !s.ide_auth {
            return Ok(None);
        }
        let pass = self.store.ide_password().map_err(|e| CoreError::from(e).message)?;
        Ok(Some(ProxyCredentials { user: store::IDE_USER.into(), pass }))
    }

    // ------------------------------------------------------------ session

    fn status_changed(&mut self) {
        let status = self.session_status();
        let browser_proxy = self.session.browser_endpoint();
        self.events.push(CoreEvent::StatusChanged { status, browser_proxy });
    }

    fn set_state(&mut self, s: SessionState) {
        if &s != self.session.state() {
            log::info(format!("state -> {}", describe_state(&s)));
        }
        self.session.state = s;
        self.status_changed();
    }

    fn stop_xray(&mut self) {
        if let Some(tail) = self.session.stop_runtime() {
            self.last_xray_error = tail;
        }
        self.ide.mode = "off";
    }

    /// IDE ports for a new Xray instance; ports held by someone else are skipped.
    fn jetbrains_plan(&mut self, s: &Settings) -> JetbrainsPorts {
        self.ide.enabled = s.jetbrains_enabled;
        self.ide.socks_port = None;
        self.ide.http_port = None;
        self.ide.issue = None;
        self.ide.auth_required = false;
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
            self.ide.issue = Some(format!("Port {list} is in use by another program (or another browser running Private Proxy)"));
        }
        JetbrainsPorts { socks, http }
    }

    fn log_level() -> &'static str {
        if log::debug_enabled() { "info" } else { "warning" }
    }

    /// Starts the direct IDE endpoint when the tunnel is not active (if enabled).
    fn ensure_passthrough(&mut self) {
        if self.session.run.is_some() {
            return;
        }
        let s = self.settings();
        self.ide.enabled = s.jetbrains_enabled;
        if !s.jetbrains_enabled || !s.passthrough_when_disconnected {
            self.ide.mode = "off";
            self.ide.issue = None;
            return;
        }
        let Some(xray_path) = self.xray_path.clone() else {
            self.ide.issue = Some("Xray is not installed".into());
            return;
        };
        if let Err(e) = crate::platform::harden::verify_private_dir(self.store.dir()) {
            self.ide.issue = Some(format!("Runtime security check failed: {e}"));
            log::error(format!("IDE endpoint not started: {e}"));
            return;
        }
        let jb = self.jetbrains_plan(&s);
        let Some(probe_port) = jb.http.or(jb.socks) else { return };
        let ide_auth = match self.ide_auth(&s) {
            Ok(a) => a,
            Err(e) => {
                // Never fall back to an open endpoint when a password is required.
                self.ide.issue = Some(format!("The local IDE proxy could not be started: {e}"));
                return;
            }
        };
        self.ide.auth_required = ide_auth.is_some();
        let plan = RuntimePlan { browser_port: None, browser_auth: None, jetbrains: jb, ide_auth, log_level: Self::log_level() };
        let cfg = SecretBytes(serde_json::to_vec(&xray_config::passthrough_config(&plan)).unwrap_or_default());
        match xray::spawn(&xray_path, &cfg.0, self.store.dir()) {
            Ok(r) => {
                if ports::wait_listening(probe_port, self.timing.listen_timeout, || r.try_exit().is_none()) {
                    self.ide.socks_port = jb.socks;
                    self.ide.http_port = jb.http;
                    self.ide.mode = "direct";
                    self.session.run = Some(r);
                    self.session.mode = RuntimeMode::Passthrough;
                    log::info("passthrough endpoint started");
                } else {
                    self.last_xray_error = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
                    r.stop();
                    self.ide.issue = Some("The local IDE proxy could not be started".into());
                    log::warn("passthrough instance failed to start");
                }
            }
            Err(e) => {
                self.ide.issue = Some(CoreError::from_runtime_security(&e).map(|c| c.message).unwrap_or_else(|| "The local IDE proxy could not be started".into()));
                log::warn(format!("passthrough spawn failed: {e}"));
            }
        }
    }

    fn fail(&mut self, error: CoreError, profile_id: Option<String>) {
        self.stop_xray();
        log::warn(format!("connection failed: {:?}: {}", error.kind, error.message));
        // Restore passthrough first so the single emitted status is consistent.
        self.ensure_passthrough();
        self.set_state(SessionState::Failed { error, profile_id });
    }

    /// Starts a tunnel through the profile. Returns once Xray is launched (or failed); the
    /// session becomes `Connected` only after the health probe through the server succeeds.
    pub fn start_session(&mut self, profile_id: &str) -> Result<(), CoreError> {
        valid_id(profile_id)?;
        if self.session.state().active_profile_id() == Some(profile_id) {
            return Ok(()); // repeated request: idempotent
        }
        let (meta, secrets) = self.store.server_with_secrets(profile_id).map_err(|e| match e {
            StoreError::NotFound => not_found("Server"),
            e => e.into(),
        })?;
        // Re-check the destination policy at connect time too (defence in depth for servers
        // stored by an older version or edited on disk).
        crate::core::netpolicy::check_server_address(&meta.address).map_err(|m| CoreError::new(ErrorKind::SecurityPolicyViolation, m))?;
        let _ = self.store.update_state(|st| {
            st.selected_server_id = Some(profile_id.to_string());
            Ok(())
        });
        self.session.attempt += 1;
        self.session.restarts.clear();
        self.stop_xray();
        self.set_state(SessionState::Starting { profile_id: profile_id.to_string(), phase: StartPhase::Launching });
        self.start_tunnel(&meta, &secrets);
        Ok(())
    }

    fn start_tunnel(&mut self, meta: &ServerMeta, secrets: &ServerSecrets) {
        let sid = meta.id.clone();
        let Some(xray_path) = self.xray_path.clone() else {
            return self.fail(CoreError::new(ErrorKind::RuntimeUnavailable, "Xray is missing from the native runtime. Reinstall the runtime."), Some(sid));
        };
        if let Err(e) = xray::verify(&xray_path) {
            return self.fail(CoreError::new(ErrorKind::RuntimeIntegrityFailure, format!("Xray integrity check failed: {e}")), Some(sid));
        }
        if let Err(e) = crate::platform::harden::verify_private_dir(self.store.dir()) {
            return self.fail(CoreError::new(ErrorKind::RuntimeIsolationFailure, format!("Runtime security check failed: {e}. The connection was not started.")), Some(sid));
        }
        let s = self.settings();
        let mut jb = self.jetbrains_plan(&s);
        let ide_auth = match self.ide_auth(&s) {
            Ok(a) => a,
            Err(e) => {
                // Never expose an open IDE endpoint when a password is required: run the tunnel
                // for the browser only and report the problem.
                self.ide.issue = Some(format!("The local IDE proxy is off: {e}"));
                jb = JetbrainsPorts { socks: None, http: None };
                None
            }
        };
        self.ide.auth_required = ide_auth.is_some();
        let browser_auth = ProxyCredentials::random_for_browser();
        let mut last_err = String::new();
        for try_no in 0..2 {
            let port = match ports::ephemeral_port() {
                Ok(p) => p,
                Err(e) => return self.fail(CoreError::new(ErrorKind::PortUnavailable, format!("No free local port: {e}")), Some(sid)),
            };
            let plan = RuntimePlan { browser_port: Some(port), browser_auth: Some(browser_auth.clone()), jetbrains: jb, ide_auth: ide_auth.clone(), log_level: Self::log_level() };
            let cfg = SecretBytes(serde_json::to_vec(&xray_config::tunnel_config(meta, secrets, &plan)).unwrap_or_default());
            if try_no == 0 {
                if let Err(reason) = xray::test_config(&xray_path, &cfg.0) {
                    let err = CoreError::from_runtime_security(&reason)
                        .unwrap_or_else(|| CoreError::new(ErrorKind::ConfigRejected, format!("Xray rejected this server's configuration: {reason}")));
                    return self.fail(err, Some(sid));
                }
            }
            match xray::spawn(&xray_path, &cfg.0, self.store.dir()) {
                Ok(r) => {
                    if ports::wait_listening(port, self.timing.listen_timeout, || r.try_exit().is_none()) {
                        self.ide.socks_port = jb.socks;
                        self.ide.http_port = jb.http;
                        self.ide.mode = "tunnel";
                        self.session.run = Some(r);
                        self.session.mode = RuntimeMode::Tunnel { profile_id: sid.clone(), port, config: cfg, credentials: browser_auth.clone() };
                        self.set_state(SessionState::Starting { profile_id: sid, phase: StartPhase::Verifying });
                        self.spawn_probe(port, browser_auth);
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
        let err = CoreError::from_runtime_security(&last_err).unwrap_or_else(|| {
            let msg = if detail.is_empty() { "Xray failed to start".to_string() } else { format!("Xray failed to start: {}", crate::core::validate::truncate(&detail, 200)) };
            CoreError::new(ErrorKind::RuntimeFailure, msg)
        });
        self.fail(err, Some(sid));
    }

    fn spawn_probe(&self, port: u16, auth: ProxyCredentials) {
        let post = self.post.clone();
        let attempt = self.session.attempt;
        let per = self.timing.probe_timeout;
        std::thread::spawn(move || {
            let result = probe::probe(port, &auth, &probe::default_targets(), per, &|| false).map_err(|e| e.to_string());
            post(CoreMsg::ProbeDone { attempt, result });
        });
    }

    fn on_probe(&mut self, attempt: u64, result: Result<String, String>) {
        if attempt != self.session.attempt {
            return; // stale: stopped or switched profiles meanwhile
        }
        let (sid, port) = match (self.session.state(), &self.session.mode) {
            (SessionState::Starting { profile_id, phase: StartPhase::Verifying }, RuntimeMode::Tunnel { port, .. }) => (profile_id.clone(), *port),
            _ => return,
        };
        match result {
            Ok(line) => {
                log::info(format!("connectivity verified ({line})"));
                self.set_state(SessionState::Connected { profile_id: sid, port, since: store::now() });
            }
            Err(e) => {
                self.session.attempt += 1;
                // Technical detail goes to the log; the user gets a short, actionable message.
                log::warn(format!("connectivity probe failed: {e}"));
                self.fail(CoreError::new(ErrorKind::ConnectionFailure, "Could not connect through this server."), Some(sid));
            }
        }
    }

    /// Stops the tunnel (idempotent). Xray is terminated and the per-connection credentials and
    /// generated config are dropped; the IDE endpoint returns to direct mode if enabled.
    pub fn stop_session(&mut self) {
        self.session.attempt += 1; // invalidates in-flight probes
        let active = matches!(self.session.state(), SessionState::Starting { .. } | SessionState::Connected { .. });
        if self.session.is_tunnel() || active {
            self.set_state(SessionState::Stopping);
            self.stop_xray();
            self.ensure_passthrough();
            self.set_state(SessionState::Disconnected);
        } else if self.session.state() != &SessionState::Disconnected {
            self.set_state(SessionState::Disconnected); // clears a previous failure
        }
    }

    /// Periodic supervision: detects Xray exiting unexpectedly.
    fn check_process(&mut self) {
        let exited = match &self.session.run {
            Some(r) => r.try_exit(),
            None => return,
        };
        let Some(how) = exited else { return };
        let r = self.session.run.take().expect("checked above");
        self.last_xray_error = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
        r.stop();
        log::warn(format!("Xray exited unexpectedly ({how})"));
        let last = self.last_xray_error.iter().rev().find(|l| !l.trim().is_empty()).cloned().unwrap_or_default();
        match std::mem::replace(&mut self.session.mode, RuntimeMode::Off) {
            RuntimeMode::Tunnel { profile_id, port, config, credentials } => {
                let now = Instant::now();
                let window = self.timing.restart_window;
                self.session.restarts.retain(|t| now.duration_since(*t) < window);
                let connected = matches!(self.session.state(), SessionState::Connected { .. });
                if connected && self.session.restarts.len() < self.timing.max_restarts {
                    self.session.restarts.push(now);
                    self.set_state(SessionState::Starting { profile_id: profile_id.clone(), phase: StartPhase::Restarting });
                    if let Some(xp) = self.xray_path.clone() {
                        if let Ok(nr) = xray::spawn(&xp, &config.0, self.store.dir()) {
                            if ports::wait_listening(port, self.timing.listen_timeout, || nr.try_exit().is_none()) {
                                self.session.run = Some(nr);
                                self.session.mode = RuntimeMode::Tunnel { profile_id: profile_id.clone(), port, config, credentials };
                                self.ide.mode = "tunnel";
                                log::info("Xray restarted after unexpected exit");
                                self.set_state(SessionState::Connected { profile_id, port, since: store::now() });
                                return;
                            }
                            nr.stop();
                        }
                    }
                }
                self.session.attempt += 1;
                let msg = if last.is_empty() {
                    "Xray stopped unexpectedly".to_string()
                } else {
                    format!("Xray stopped unexpectedly: {}", crate::core::validate::truncate(last.rsplit(" > ").next().unwrap_or(&last), 160))
                };
                self.fail(CoreError::new(ErrorKind::RuntimeFailure, msg), Some(profile_id));
            }
            RuntimeMode::Passthrough => {
                self.ide.mode = "off";
                let now = Instant::now();
                self.passthrough_failures.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                self.passthrough_failures.push(now);
                if self.passthrough_failures.len() <= 2 {
                    self.ensure_passthrough();
                } else {
                    self.ide.issue = Some("The local IDE proxy keeps stopping".into());
                }
                self.status_changed();
            }
            RuntimeMode::Off => {}
        }
    }
}

/// State for the log: ids and phases only, never credentials.
fn describe_state(s: &SessionState) -> String {
    match s {
        SessionState::Disconnected => "disconnected".into(),
        SessionState::Starting { phase, .. } => format!("starting ({phase:?})"),
        SessionState::Connected { port, .. } => format!("connected (local port {port})"),
        SessionState::Stopping => "stopping".into(),
        SessionState::Failed { error, .. } => format!("failed ({:?}: {})", error.kind, error.message),
    }
}
