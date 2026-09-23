//! EXPERIMENTAL minimal routing service (§14): the component that **owns** routing policy.
//!
//! Phase 7.5 proved that whoever owns the WFP filters owns the protection: when the owning process
//! was killed, the filters vanished and the application was silently direct again. So the rules
//! here are deliberately blunt:
//!
//! * the service owns the WFP session (BLOCK first), the driver target and the redirect filters;
//! * **`Protected` is a conclusion, never an assumption.** It requires the driver to be present,
//!   the redirect target to be set, the redirector to be alive and the BLOCK filters to exist. If
//!   any of those is missing the state is `Blocking` or `Failed` — never `Protected`;
//! * the API is four operations and nothing else: no command execution, no arbitrary rules, no file
//!   or registry access, no process control.
//!
//! This is a PoC: in the product it becomes a Windows service running as LocalSystem. Here it is a
//! library plus a self-test binary, so its state machine can be exercised without a driver.

use std::path::{Path, PathBuf};

use crate::driver::{Driver, DriverError, RedirectTarget, MPROXY_ABI_VERSION};

/// The only policy the service accepts. Explicit executables only (§35): no process-tree inheritance.
#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    pub targets: Vec<PathBuf>,
    pub redirector_pid: u32,
    pub redirector_port_v4: u16,
    /// 0 means "IPv6 is not redirected"; the BLOCK filters then deny it rather than letting it out.
    pub redirector_port_v6: u16,
}

/// What the UI is allowed to be told. There is no variant that means "probably protected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingState {
    /// No policy applied; applications are direct because nothing was asked for.
    Inactive,
    /// BLOCK filters are in place: selected applications cannot leak, but they are not routed yet.
    Blocking { reason: String },
    /// Driver redirecting, redirector alive, filters present. Only this may be shown as "Protected".
    Protected { targets: usize },
    /// Something failed after policy was requested. Selected applications stay blocked.
    Failed { error: String },
}

impl RoutingState {
    /// The single place that decides whether a UI may display "Protected".
    pub fn is_protected(&self) -> bool {
        matches!(self, RoutingState::Protected { .. })
    }
    pub fn label(&self) -> &'static str {
        match self {
            RoutingState::Inactive => "Not protected",
            RoutingState::Blocking { .. } => "Blocked (not routed)",
            RoutingState::Protected { .. } => "Protected",
            RoutingState::Failed { .. } => "Not protected",
        }
    }
}

pub const MAX_TARGETS: usize = 32;

/// Canonical paths come back in `\\?\` verbatim form on Windows while ordinary paths do not.
/// Comparisons between the two forms fail silently, so every path comparison goes through this.
pub fn normalize(p: &Path) -> PathBuf {
    let s = p.display().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    PathBuf::from(s.to_lowercase())
}

/// Validation happens in the service, before anything reaches the kernel.
pub fn validate(policy: &RoutingPolicy, install_dir: &Path) -> Result<(), String> {
    if policy.targets.is_empty() {
        return Err("policy has no targets".into());
    }
    if policy.targets.len() > MAX_TARGETS {
        return Err(format!("too many targets: {} (max {MAX_TARGETS})", policy.targets.len()));
    }
    if policy.redirector_pid == 0 {
        return Err("redirector pid is zero".into());
    }
    if policy.redirector_port_v4 == 0 {
        return Err("redirector IPv4 port is zero".into());
    }
    let install_dir = normalize(install_dir);
    for t in &policy.targets {
        if !t.is_absolute() {
            return Err(format!("target is not an absolute path: {}", t.display()));
        }
        let canonical = normalize(&t.canonicalize().map_err(|e| format!("target {}: {e}", t.display()))?);
        // Loop prevention, third layer (§27): never route our own components, or an attacker could
        // make Xray's or the redirector's traffic loop back into the redirector.
        //
        // Both sides are normalized first: `canonicalize` returns a `\\?\` verbatim path while the
        // install directory usually is not, and comparing the two raw forms silently never matches.
        if canonical.starts_with(&install_dir) {
            return Err(format!("refusing to route a component of the product itself: {}", canonical.display()));
        }
        let name = canonical.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        if matches!(name.as_str(), "xray.exe" | "redirector.exe" | "private-proxy-host.exe" | "mproxy-service.exe") {
            return Err(format!("refusing to route a product component by name: {name}"));
        }
    }
    Ok(())
}

pub struct RoutingService {
    install_dir: PathBuf,
    state: RoutingState,
    driver: Option<Driver>,
    #[cfg(windows)]
    filters: Option<per_app_routing_poc::wfp::WfpEnforcement>,
}

impl RoutingService {
    pub fn new(install_dir: impl Into<PathBuf>) -> RoutingService {
        RoutingService {
            install_dir: install_dir.into(),
            state: RoutingState::Inactive,
            driver: None,
            #[cfg(windows)]
            filters: None,
        }
    }

    pub fn query_state(&self) -> &RoutingState {
        &self.state
    }

    /// Driver state, straight from the kernel. `None` when no driver is present.
    pub fn query_driver_state(&self) -> Option<Result<crate::driver::DriverState, String>> {
        #[cfg(windows)]
        {
            return self.driver.as_ref().map(|d| d.query_state().map_err(|e| e.to_string()));
        }
        #[allow(unreachable_code)]
        None
    }

    /// Applies a policy. Order is fixed and fail-closed (§37): **block first, redirect second.**
    pub fn set_app_policy(&mut self, policy: &RoutingPolicy) -> &RoutingState {
        if let Err(e) = validate(policy, &self.install_dir) {
            self.state = RoutingState::Failed { error: e };
            return &self.state;
        }

        // 1. BLOCK. From here a selected application cannot reach the network at all, whatever
        //    happens next. This step is the one Phase 7.5 verified at runtime.
        #[cfg(windows)]
        {
            match self.install_block_filters(policy) {
                Ok(()) => {}
                Err(e) => {
                    self.state = RoutingState::Failed { error: format!("could not install BLOCK filters: {e}") };
                    return &self.state;
                }
            }
        }
        self.state = RoutingState::Blocking { reason: "redirect not active yet".into() };

        // 2. Tell the driver where the redirector is. No driver ⇒ stay blocked; never "protected",
        //    and never direct.
        let target = RedirectTarget {
            version: MPROXY_ABI_VERSION,
            redirector_pid: policy.redirector_pid,
            port_v4: policy.redirector_port_v4,
            port_v6: policy.redirector_port_v6,
            reserved: 0,
        };
        match Driver::open() {
            Ok(driver) => match driver.set_target(&target) {
                Ok(()) => {
                    self.driver = Some(driver);
                }
                Err(e) => {
                    self.state = RoutingState::Blocking { reason: format!("driver rejected the redirect target: {e}") };
                    return &self.state;
                }
            },
            Err(DriverError::NotPresent(e)) => {
                self.state = RoutingState::Blocking { reason: format!("callout driver not present ({e}); selected applications are blocked, not routed") };
                return &self.state;
            }
            Err(e) => {
                self.state = RoutingState::Blocking { reason: format!("driver unavailable: {e}") };
                return &self.state;
            }
        }

        // 3. Only now may the state say Protected, and only if the redirector is actually alive.
        if !process_alive(policy.redirector_pid) {
            self.state = RoutingState::Blocking { reason: "redirector process is not running".into() };
            return &self.state;
        }
        self.state = RoutingState::Protected { targets: policy.targets.len() };
        &self.state
    }

    /// Removes the redirect first, then the BLOCK filters: at no point is a selected application
    /// both unredirected and unblocked.
    pub fn clear_app_policy(&mut self) -> &RoutingState {
        #[cfg(windows)]
        {
            if let Some(d) = &self.driver {
                let _ = d.clear();
            }
        }
        self.driver = None;
        #[cfg(windows)]
        {
            self.filters = None; // Drop removes the filters and closes the session.
        }
        self.state = RoutingState::Inactive;
        &self.state
    }

    #[cfg(windows)]
    fn install_block_filters(&mut self, policy: &RoutingPolicy) -> Result<(), String> {
        use per_app_routing_poc::wfp::WfpEnforcement;
        use per_app_routing_poc::{ApplicationRoutingPolicy, ApplicationRoutingProvider, ApplicationTarget, ChildPolicy, FailureMode, LocalEndpoint};

        let targets = policy
            .targets
            .iter()
            .map(|p| ApplicationTarget::approve("selected", p, ChildPolicy::None).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut w = WfpEnforcement::open()?;
        w.prepare(&ApplicationRoutingPolicy { targets, failure_mode: FailureMode::Closed })?;
        w.activate(&LocalEndpoint { port: policy.redirector_port_v4, user: String::new(), pass: String::new() })?;
        self.filters = Some(w);
        Ok(())
    }
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        CloseHandle(h);
        true
    }
}

#[cfg(not(windows))]
fn process_alive(_pid: u32) -> bool {
    false
}
