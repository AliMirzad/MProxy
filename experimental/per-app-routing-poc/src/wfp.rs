//! EXPERIMENTAL — user-mode WFP fail-closed enforcement (no driver, no redirection).
//!
//! Everything lives in one **dynamic** WFP session: when this object is dropped, or the process
//! exits or crashes, BFE deletes every filter and the sublayer. Nothing is persistent.
//!
//! Filters (own sublayer, `ALE_AUTH_CONNECT_V4/V6`: TCP connect and first UDP packet per remote):
//! * BLOCK  app == selected executable AND user == current user                       (prepare)
//! * PERMIT app == selected executable AND user == current user AND remote ∈ loopback  (activate)
//!
//! So a selected app can only talk to loopback (our proxy inbound, local dev servers): no direct
//! IPv4/IPv6, TCP/UDP, DNS or QUIC. Unselected apps and other users are untouched. WFP arbitration
//! lets a BLOCK in any sublayer win over PERMITs in other sublayers, so another product's permit
//! cannot re-open the leak (a hard permit/callout veto from a driver could).
//!
//! Scope limits by design: no callouts, no other layers, no persistent objects, no generic filter
//! API. Adding objects needs Administrators or Network Configuration Operators (default BFE DACL).

use crate::{ApplicationRoutingPolicy, ApplicationRoutingProvider, LocalEndpoint, ProviderCapabilities, RoutingState};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

const RPC_C_AUTHN_WINNT: u32 = 10;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// WFP / Win32 status as text.
pub fn describe(code: u32) -> String {
    match code {
        5 => "ERROR_ACCESS_DENIED (adding WFP objects needs Administrators or Network Configuration Operators)".into(),
        c => format!("0x{c:08x}"),
    }
}

fn session_guid() -> GUID {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    GUID::from_u128(t ^ ((std::process::id() as u128) << 64) ^ 0x5050_4150_5052_4f58_595f_504f_435f_5057)
}

/// SID of the user running this process, e.g. `S-1-5-21-…`.
pub fn current_user_sid() -> Result<String, String> {
    let whoami = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32").join("whoami.exe");
    let out = std::process::Command::new(whoami).args(["/user", "/fo", "csv", "/nh"]).output().map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&out.stdout).to_string();
    line.split(',').nth(1).map(|s| s.trim().trim_matches('"').to_string()).filter(|s| s.starts_with("S-1-")).ok_or_else(|| format!("unexpected whoami output: {line}"))
}

pub struct WfpEnforcement {
    engine: HANDLE,
    sublayer: GUID,
    app_ids: Vec<*mut FWP_BYTE_BLOB>,
    user_sd: PSECURITY_DESCRIPTOR,
    user_sd_blob: Box<FWP_BYTE_BLOB>,
    filters: Vec<u64>,
    state: RoutingState,
}

impl WfpEnforcement {
    /// Opens a dynamic session (works for any user: everyone has FWPM_ACTRL_OPEN).
    pub fn open() -> Result<WfpEnforcement, String> {
        let name = wide("MProxy per-app PoC (dynamic)");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = name.as_ptr() as *mut u16;
        let mut engine: HANDLE = std::ptr::null_mut();
        let rc = unsafe { FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine) };
        if rc != 0 {
            return Err(format!("FwpmEngineOpen0: {}", describe(rc)));
        }
        let sid = current_user_sid()?;
        let sddl = wide(&format!("D:(A;;CC;;;{sid})"));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, std::ptr::null_mut()) } == 0 {
            unsafe { FwpmEngineClose0(engine) };
            return Err("cannot build the user security descriptor".into());
        }
        let len = unsafe { GetSecurityDescriptorLength(sd) };
        let user_sd_blob = Box::new(FWP_BYTE_BLOB { size: len, data: sd as *mut u8 });
        Ok(WfpEnforcement { engine, sublayer: session_guid(), app_ids: Vec::new(), user_sd: sd, user_sd_blob, filters: Vec::new(), state: RoutingState::Inactive })
    }

    fn add_sublayer(&mut self) -> Result<(), String> {
        let name = wide("MProxy per-app PoC");
        let mut sl: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sl.subLayerKey = self.sublayer;
        sl.displayData.name = name.as_ptr() as *mut u16;
        sl.weight = 0x8000;
        let rc = unsafe { FwpmSubLayerAdd0(self.engine, &sl, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(format!("FwpmSubLayerAdd0: {}", describe(rc)));
        }
        Ok(())
    }

    fn add_filter(&mut self, layer: GUID, action: FWP_ACTION_TYPE, weight: u8, conds: &mut [FWPM_FILTER_CONDITION0]) -> Result<(), String> {
        let name = wide(if action == FWP_ACTION_BLOCK { "MProxy PoC: block selected app" } else { "MProxy PoC: permit selected app to loopback" });
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.displayData.name = name.as_ptr() as *mut u16;
        f.layerKey = layer;
        f.subLayerKey = self.sublayer;
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = weight;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = conds.as_mut_ptr();
        f.action.r#type = action;
        let mut id = 0u64;
        let rc = unsafe { FwpmFilterAdd0(self.engine, &f, std::ptr::null_mut(), &mut id) };
        if rc != 0 {
            return Err(format!("FwpmFilterAdd0: {}", describe(rc)));
        }
        self.filters.push(id);
        Ok(())
    }

    fn base_conditions(&self, app: *mut FWP_BYTE_BLOB) -> [FWPM_FILTER_CONDITION0; 2] {
        let mut c: [FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };
        c[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        c[0].matchType = FWP_MATCH_EQUAL;
        c[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        c[0].conditionValue.Anonymous.byteBlob = app;
        c[1].fieldKey = FWPM_CONDITION_ALE_USER_ID;
        c[1].matchType = FWP_MATCH_EQUAL;
        c[1].conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
        c[1].conditionValue.Anonymous.sd = &*self.user_sd_blob as *const FWP_BYTE_BLOB as *mut FWP_BYTE_BLOB;
        c
    }

    /// Number of filters currently installed by this session.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }
}

impl ApplicationRoutingProvider for WfpEnforcement {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities { redirects_traffic: false, enforces_fail_closed: true, needs_app_cooperation: true }
    }

    fn prepare(&mut self, policy: &ApplicationRoutingPolicy) -> Result<(), String> {
        let r = (|| {
            self.add_sublayer()?;
            for t in &policy.targets {
                t.verify()?;
                let path = t.executable.display().to_string();
                let dos = path.strip_prefix(r"\\?\").unwrap_or(&path).to_string();
                let w = wide(&dos);
                let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
                if rc != 0 {
                    return Err(format!("FwpmGetAppIdFromFileName0({dos}): {}", describe(rc)));
                }
                self.app_ids.push(blob);
                for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                    let mut c = self.base_conditions(blob);
                    self.add_filter(layer, FWP_ACTION_BLOCK, 1, &mut c)?;
                }
            }
            Ok(())
        })();
        self.state = match &r {
            Ok(()) => RoutingState::Prepared,
            Err(e) => RoutingState::Failed(e.clone()),
        };
        r
    }

    fn activate(&mut self, _endpoint: &LocalEndpoint) -> Result<(), String> {
        let mut v4 = FWP_V4_ADDR_AND_MASK { addr: 0x7f00_0000, mask: 0xff00_0000 };
        let mut v6addr = [0u8; 16];
        v6addr[15] = 1;
        let mut v6 = FWP_V6_ADDR_AND_MASK { addr: v6addr, prefixLength: 128 };
        let apps = self.app_ids.clone();
        let r: Result<(), String> = (|| {
            for app in apps {
                for (layer, is_v4) in [(FWPM_LAYER_ALE_AUTH_CONNECT_V4, true), (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false)] {
                    let base = self.base_conditions(app);
                    let mut remote: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    remote.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    remote.matchType = FWP_MATCH_EQUAL;
                    if is_v4 {
                        remote.conditionValue.r#type = FWP_V4_ADDR_MASK;
                        remote.conditionValue.Anonymous.v4AddrMask = &mut v4;
                    } else {
                        remote.conditionValue.r#type = FWP_V6_ADDR_MASK;
                        remote.conditionValue.Anonymous.v6AddrMask = &mut v6;
                    }
                    let mut c = [base[0], base[1], remote];
                    self.add_filter(layer, FWP_ACTION_PERMIT, 10, &mut c)?;
                }
            }
            Ok(())
        })();
        self.state = match &r {
            Ok(()) => RoutingState::Active,
            Err(e) => RoutingState::Failed(e.clone()),
        };
        r
    }

    fn state(&self) -> RoutingState {
        self.state.clone()
    }

    fn deactivate(&mut self) -> Result<(), String> {
        for id in std::mem::take(&mut self.filters) {
            unsafe { FwpmFilterDeleteById0(self.engine, id) };
        }
        unsafe { FwpmSubLayerDeleteByKey0(self.engine, &self.sublayer) };
        self.state = RoutingState::Inactive;
        Ok(())
    }
}

impl Drop for WfpEnforcement {
    fn drop(&mut self) {
        let _ = self.deactivate();
        for b in self.app_ids.drain(..) {
            let mut p = b as *mut core::ffi::c_void;
            unsafe { FwpmFreeMemory0(&mut p) };
        }
        unsafe {
            // Closing a dynamic session deletes anything left.
            FwpmEngineClose0(self.engine);
            LocalFree(self.user_sd as _);
        }
    }
}
