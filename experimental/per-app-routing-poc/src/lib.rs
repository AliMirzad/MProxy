//! EXPERIMENTAL — Phase 7 per-application routing PoC. Not shipped. See README.md.
//!
//! Two mechanisms are exercised:
//!
//! * [`AppConfiguredLauncher`]: APP-CONFIGURED PROXY. The selected program is started with proxy
//!   settings that point at the Core's authenticated loopback inbound. Nothing on the system
//!   changes, but only programs that honour the settings are routed.
//! * [`wfp::WfpEnforcement`] (Windows): FAIL-CLOSED ENFORCEMENT with user-mode WFP filters in a
//!   dynamic session. The selected executable (current user only) may connect to loopback only.
//!   It does not redirect anything.
//!
//! Neither is TRUE PER-PROCESS ROUTING; that needs a WFP connect-redirect callout driver
//! (docs/windows-per-app-routing-research.md).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub mod testkit;
#[cfg(windows)]
pub mod wfp;

/// How descendants of a selected application are treated (production policy undecided).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildPolicy {
    /// Only the selected executable itself.
    None,
    /// Whatever the mechanism propagates (environment inheritance for the launcher).
    Inherit,
}

/// What happens to a selected application when the tunnel is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// Selected application loses network access (except loopback) instead of going direct.
    Closed,
    /// Selected application goes direct (no enforcement).
    Open,
}

/// A selected application, bound to the exact executable content approved by the user.
#[derive(Debug, Clone)]
pub struct ApplicationTarget {
    pub stable_id: String,
    pub display_name: String,
    /// Canonical path (Windows: `\\?\C:\...`).
    pub executable: PathBuf,
    /// SHA-256 of the executable at approval time. Checked again right before use.
    pub sha256: String,
    pub children: ChildPolicy,
}

impl ApplicationTarget {
    pub fn approve(display_name: &str, exe: &Path, children: ChildPolicy) -> std::io::Result<ApplicationTarget> {
        let executable = std::fs::canonicalize(exe)?;
        let sha256 = sha256_file(&executable)?;
        Ok(ApplicationTarget { stable_id: format!("app-{}", &sha256[..16]), display_name: display_name.into(), executable, sha256, children })
    }

    /// The executable still is the approved one (path and content). There is still a window between
    /// this check and the OS opening the file (TOCTOU); production must bind to the file identity
    /// or the publisher signature, see docs/per-app-routing-decision.md.
    pub fn verify(&self) -> Result<(), String> {
        let now = sha256_file(&self.executable).map_err(|e| format!("cannot read {}: {e}", self.executable.display()))?;
        if now != self.sha256 {
            return Err(format!("{} changed since it was approved", self.display_name));
        }
        Ok(())
    }
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(std::fs::read(p)?);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Selected applications and how they are treated.
#[derive(Debug, Clone)]
pub struct ApplicationRoutingPolicy {
    pub targets: Vec<ApplicationTarget>,
    pub failure_mode: FailureMode,
}

/// Where selected traffic must enter Xray: the Core's authenticated loopback HTTP inbound.
#[derive(Clone)]
pub struct LocalEndpoint {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl std::fmt::Debug for LocalEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LocalEndpoint {{ port: {}, credentials: <redacted> }}", self.port)
    }
}

/// Routing lifecycle (Phase 7 design; see docs/per-app-routing-decision.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingState {
    Inactive,
    /// Fail-closed blocks are installed; nothing selected can reach the network yet.
    Prepared,
    Active,
    Failed(String),
}

/// What a provider can actually do on this machine, measured, not assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub redirects_traffic: bool,
    pub enforces_fail_closed: bool,
    pub needs_app_cooperation: bool,
}

/// The seam the Core would call (Phase 6's ApplicationRoutingProvider, refined).
pub trait ApplicationRoutingProvider {
    fn capabilities(&self) -> ProviderCapabilities;
    /// Before Xray starts: install whatever makes selected apps fail closed.
    fn prepare(&mut self, policy: &ApplicationRoutingPolicy) -> Result<(), String>;
    /// After Xray is verified: allow selected traffic into the local endpoint.
    fn activate(&mut self, endpoint: &LocalEndpoint) -> Result<(), String>;
    fn state(&self) -> RoutingState;
    /// Remove everything this provider installed. Must be idempotent.
    fn deactivate(&mut self) -> Result<(), String>;
}

/// APP-CONFIGURED PROXY: starts selected programs with proxy settings. It installs nothing, so
/// `prepare`/`deactivate` are no-ops, and it cannot enforce anything.
#[derive(Default)]
pub struct AppConfiguredLauncher {
    endpoint: Option<LocalEndpoint>,
    state: Option<RoutingState>,
}

/// How to tell a program about the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHint {
    /// `HTTP(S)_PROXY` / `ALL_PROXY` with credentials in the URL, `NO_PROXY` for loopback.
    Environment,
    /// Chromium/Electron `--proxy-server=http://127.0.0.1:<port>` (no way to pass credentials).
    ChromiumFlag,
}

impl AppConfiguredLauncher {
    pub fn launch(&self, target: &ApplicationTarget, args: &[&str], hint: ProxyHint) -> Result<Child, String> {
        let ep = self.endpoint.as_ref().ok_or("routing is not active")?;
        target.verify()?;
        let mut cmd = Command::new(&target.executable);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        match hint {
            ProxyHint::Environment => {
                let url = format!("http://{}:{}@127.0.0.1:{}", ep.user, ep.pass, ep.port);
                for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
                    cmd.env(k, &url);
                }
                cmd.env("NO_PROXY", "localhost,127.0.0.1,::1").env("no_proxy", "localhost,127.0.0.1,::1");
            }
            ProxyHint::ChromiumFlag => {
                cmd.arg(format!("--proxy-server=http://127.0.0.1:{}", ep.port));
            }
        }
        cmd.spawn().map_err(|e| e.to_string())
    }
}

impl ApplicationRoutingProvider for AppConfiguredLauncher {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities { redirects_traffic: false, enforces_fail_closed: false, needs_app_cooperation: true }
    }
    fn prepare(&mut self, policy: &ApplicationRoutingPolicy) -> Result<(), String> {
        for t in &policy.targets {
            t.verify()?;
        }
        self.state = Some(RoutingState::Prepared);
        Ok(())
    }
    fn activate(&mut self, endpoint: &LocalEndpoint) -> Result<(), String> {
        self.endpoint = Some(endpoint.clone());
        self.state = Some(RoutingState::Active);
        Ok(())
    }
    fn state(&self) -> RoutingState {
        self.state.clone().unwrap_or(RoutingState::Inactive)
    }
    fn deactivate(&mut self) -> Result<(), String> {
        self.endpoint = None;
        self.state = Some(RoutingState::Inactive);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha256_of_a_file() {
        let d = std::env::temp_dir().join(format!("poc-sha-{}", std::process::id()));
        std::fs::write(&d, b"abc").unwrap();
        assert_eq!(super::sha256_file(&d).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let _ = std::fs::remove_file(d);
    }
}
