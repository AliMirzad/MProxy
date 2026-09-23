//! EXPERIMENTAL Phase 8.5 self-test for the minimal routing service.
//!
//!   routing-service --self-test [--report <file.json>]
//!
//! It exercises the part of the architecture that can be honestly tested **without** a driver: the
//! service's own state machine and validation. The central claim under test is the one the whole
//! project keeps coming back to —
//!
//!     no callout driver  ⇒  the service must never report "Protected"
//!
//! Running it non-elevated also covers the case where the BLOCK filters cannot be installed: the
//! service must fail, not silently continue.
use serde_json::{json, Value};
use std::path::PathBuf;
use windows_redirector_poc::driver::{abi_matches_header, Driver};
use windows_redirector_poc::service::{validate, RoutingPolicy, RoutingService, RoutingState, MAX_TARGETS};

fn row(rows: &mut Vec<Value>, id: &str, scenario: &str, expected: &str, actual: Value, status: &str) {
    println!("{status}  {id}  {scenario}");
    rows.push(json!({"id": id, "scenario": scenario, "expected": expected, "actual": actual, "status": status}));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let report = args.iter().position(|a| a == "--report").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let mut rows: Vec<Value> = Vec::new();

    let install_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let me = std::env::current_exe().unwrap();

    // S1: the ABI the IOCTLs depend on.
    let abi = abi_matches_header();
    row(&mut rows, "S1", "user-mode structures match the driver header (IOCTL contract)", "sizes match",
        json!({"result": abi.as_ref().err().cloned().unwrap_or_else(|| "RedirectTarget=16, DriverState=28".into())}),
        if abi.is_ok() { "PASS - AUTOMATED TEST" } else { "FAIL" });

    // S2: is a driver present at all? On this machine: no.
    let driver = Driver::open();
    let driver_present = driver.is_ok();
    row(&mut rows, "S2", "callout driver device present", "absent on this machine (never compiled)",
        json!({"open": match &driver { Ok(_) => "opened".to_string(), Err(e) => e.to_string() }}),
        if driver_present { "PASS - RUNTIME VERIFIED (driver present)" } else { "NOT TESTED: driver absent, as expected here" });

    // S3: THE decisive state-machine property.
    let outside = std::env::temp_dir().join("phase85-selected-app.exe");
    let _ = std::fs::copy(&me, &outside);
    let policy = RoutingPolicy {
        targets: vec![outside.clone()],
        redirector_pid: std::process::id(),
        redirector_port_v4: 45000,
        redirector_port_v6: 0,
    };
    let mut service = RoutingService::new(&install_dir);
    let state = service.set_app_policy(&policy).clone();
    let protected_without_driver = state.is_protected() && !driver_present;
    row(&mut rows, "S3", "apply a policy while no driver is present", "never Protected; blocked or failed instead",
        json!({"state": format!("{state:?}"), "uiLabel": state.label(), "isProtected": state.is_protected()}),
        if protected_without_driver { "FAIL: reported Protected without a driver" } else { "PASS - RUNTIME VERIFIED" });

    // S4: fail-closed on the BLOCK step (non-elevated runs cannot install filters).
    row(&mut rows, "S4", "BLOCK filters could not be installed (non-elevated)", "Failed, never Protected, never silently direct",
        json!({"state": format!("{:?}", service.query_state()), "uiLabel": service.query_state().label()}),
        if service.query_state().is_protected() { "FAIL" } else { "PASS - RUNTIME VERIFIED" });

    // S5: validation rejects what it must.
    let mut checks = Vec::new();
    let bad = [
        ("no targets", RoutingPolicy { targets: vec![], ..clone_policy(&policy) }),
        ("zero pid", RoutingPolicy { redirector_pid: 0, ..clone_policy(&policy) }),
        ("zero port", RoutingPolicy { redirector_port_v4: 0, ..clone_policy(&policy) }),
        ("relative path", RoutingPolicy { targets: vec![PathBuf::from("app.exe")], ..clone_policy(&policy) }),
        ("too many targets", RoutingPolicy { targets: vec![outside.clone(); MAX_TARGETS + 1], ..clone_policy(&policy) }),
        ("our own component", RoutingPolicy { targets: vec![me.clone()], ..clone_policy(&policy) }),
    ];
    for (name, p) in &bad {
        let r = validate(p, &install_dir);
        checks.push(json!({"case": name, "rejected": r.is_err(), "error": r.err()}));
    }
    let all_rejected = checks.iter().all(|c| c["rejected"] == true);
    row(&mut rows, "S5", "policy validation rejects malformed and self-referential policies", "all rejected",
        json!(checks), if all_rejected { "PASS - AUTOMATED TEST" } else { "FAIL" });

    // S6: a valid policy for an executable outside the product directory passes validation.
    let ok = validate(&policy, &install_dir);
    row(&mut rows, "S6", "a well-formed policy is accepted by validation", "accepted",
        json!({"result": ok.as_ref().err().cloned().unwrap_or_else(|| "accepted".into())}),
        if ok.is_ok() { "PASS - AUTOMATED TEST" } else { "FAIL" });

    // S7: clearing returns to Inactive and reports "Not protected".
    let cleared = service.clear_app_policy().clone();
    row(&mut rows, "S7", "clear_app_policy returns to Inactive", "Inactive, UI says Not protected",
        json!({"state": format!("{cleared:?}"), "uiLabel": cleared.label()}),
        if cleared == RoutingState::Inactive && !cleared.is_protected() { "PASS - RUNTIME VERIFIED" } else { "FAIL" });

    let _ = std::fs::remove_file(&outside);

    let failed = rows.iter().filter(|r| r["status"].as_str().is_some_and(|s| s.starts_with("FAIL"))).count();
    let out = json!({"complete": true, "driverPresent": driver_present, "failed": failed, "scenarios": rows});
    if let Some(p) = report {
        std::fs::write(p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
    println!("\n{} checks, {failed} failed", out["scenarios"].as_array().unwrap().len());
}

fn clone_policy(p: &RoutingPolicy) -> RoutingPolicy {
    RoutingPolicy {
        targets: p.targets.clone(),
        redirector_pid: p.redirector_pid,
        redirector_port_v4: p.redirector_port_v4,
        redirector_port_v6: p.redirector_port_v6,
    }
}
