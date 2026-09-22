//! Connection session: the runtime truth about the tunnel, independent of any client.
//!
//! ```text
//!   Disconnected ──start──▶ Starting(Launching) ──Xray listening──▶ Starting(Verifying)
//!        ▲                        │ failure                               │ probe ok
//!        │                        ▼                                       ▼
//!        └────────stop───── Failed(error) ◀──crash, restarts exhausted── Connected
//!                                                                         │ crash (≤2/60s)
//!                                                   Starting(Restarting) ◀┘
//! ```
//!
//! `Connected` is only ever set after the health probe succeeded through the server (or after a
//! crash restart of an already verified tunnel), never from a client's intent.
//! The session owns the sensitive runtime state of a tunnel: the per-connection browser
//! credentials and the generated config (which contains server secrets). Both are dropped (and
//! overwritten) when the tunnel ends, and neither is `Serialize` or printable with `{:?}`.

use crate::core::credentials::ProxyCredentials;
use crate::core::error::CoreError;
use crate::runtime::xray::Running;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartPhase {
    /// Xray is being started and must begin listening.
    Launching,
    /// Xray listens; the health probe through the server is running.
    Verifying,
    /// A verified tunnel's Xray exited unexpectedly and is being restarted.
    Restarting,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Disconnected,
    Starting { profile_id: String, phase: StartPhase },
    Connected { profile_id: String, port: u16, since: u64 },
    Stopping,
    Failed { error: CoreError, profile_id: Option<String> },
}

impl SessionState {
    /// The profile this state is about (also for a failure), if any.
    pub fn profile_id(&self) -> Option<&str> {
        match self {
            SessionState::Starting { profile_id, .. } | SessionState::Connected { profile_id, .. } => Some(profile_id),
            SessionState::Failed { profile_id, .. } => profile_id.as_deref(),
            _ => None,
        }
    }

    /// The profile that is starting or connected.
    pub fn active_profile_id(&self) -> Option<&str> {
        match self {
            SessionState::Starting { profile_id, .. } | SessionState::Connected { profile_id, .. } => Some(profile_id),
            _ => None,
        }
    }
}

/// Bytes that must not outlive their use or be printed (the generated tunnel config).
pub struct SecretBytes(pub Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// What the running Xray instance serves.
pub(crate) enum RuntimeMode {
    Off,
    /// Only the IDE endpoint, connecting directly (tunnel not active).
    Passthrough,
    /// The tunnel. `config` is kept in memory to restart Xray with identical listeners and
    /// credentials after a crash.
    Tunnel { profile_id: String, port: u16, config: SecretBytes, credentials: ProxyCredentials },
}

/// The local, authenticated proxy endpoint the browser must use while connected.
#[derive(Debug, Clone)]
pub struct LocalProxyEndpoint {
    pub host: &'static str,
    pub port: u16,
    pub credentials: ProxyCredentials,
}

pub struct ConnectionSession {
    pub(crate) state: SessionState,
    pub(crate) mode: RuntimeMode,
    pub(crate) run: Option<Running>,
    /// Incremented whenever in-flight work (probe) becomes stale.
    pub(crate) attempt: u64,
    pub(crate) restarts: Vec<Instant>,
}

impl Default for ConnectionSession {
    fn default() -> Self {
        ConnectionSession { state: SessionState::Disconnected, mode: RuntimeMode::Off, run: None, attempt: 0, restarts: Vec::new() }
    }
}

impl ConnectionSession {
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub(crate) fn is_tunnel(&self) -> bool {
        matches!(self.mode, RuntimeMode::Tunnel { .. })
    }

    /// The browser endpoint, only while the tunnel is verified (`Connected`).
    pub(crate) fn browser_endpoint(&self) -> Option<LocalProxyEndpoint> {
        match (&self.state, &self.mode) {
            (SessionState::Connected { .. }, RuntimeMode::Tunnel { port, credentials, .. }) => {
                Some(LocalProxyEndpoint { host: crate::core::xray_config::LOOPBACK, port: *port, credentials: credentials.clone() })
            }
            _ => None,
        }
    }

    /// Stops Xray (if any) and drops tunnel secrets. Returns Xray's recent output.
    pub(crate) fn stop_runtime(&mut self) -> Option<Vec<String>> {
        let tail = self.run.take().map(|r| {
            let tail = r.tail.lock().map(|t| t.lines()).unwrap_or_default();
            r.stop();
            tail
        });
        self.mode = RuntimeMode::Off; // drops (and overwrites) config and credentials
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_are_redacted() {
        let b = SecretBytes(b"{\"id\":\"5783a3e7-e373-51cd-8642-c83782b807c5\"}".to_vec());
        let s = format!("{b:?}");
        assert!(!s.contains("5783a3e7") && s.contains("redacted"), "{s}");
    }

    #[test]
    fn endpoint_only_while_connected_and_cleared_on_stop() {
        let mut s = ConnectionSession::default();
        let creds = ProxyCredentials::random_for_browser();
        s.mode = RuntimeMode::Tunnel { profile_id: "p".into(), port: 5555, config: SecretBytes(vec![1, 2, 3]), credentials: creds.clone() };
        s.state = SessionState::Starting { profile_id: "p".into(), phase: StartPhase::Verifying };
        assert!(s.browser_endpoint().is_none(), "no credentials before the tunnel is verified");
        s.state = SessionState::Connected { profile_id: "p".into(), port: 5555, since: 0 };
        let ep = s.browser_endpoint().unwrap();
        assert_eq!((ep.host, ep.port, &ep.credentials), ("127.0.0.1", 5555, &creds));
        assert!(!format!("{ep:?}").contains(&creds.pass));
        s.stop_runtime();
        assert!(s.browser_endpoint().is_none() && !s.is_tunnel(), "credentials dropped with the tunnel");
    }
}
