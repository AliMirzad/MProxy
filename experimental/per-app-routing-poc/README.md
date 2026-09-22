# Per-application routing PoC — EXPERIMENTAL, NEVER SHIPPED

Phase 7 proof of concept. Not production code:

* not a workspace member of `native/`, not built by `scripts/package.mjs`, not in any release;
* depends on the Shared Core (`native/`, debug build) through a path dependency;
* adds no new crates (uses the `windows-sys` version the product already locks, with extra features).

What it tests (see `docs/per-app-routing-decision.md`):

| Part | Mechanism | Class |
|---|---|---|
| `AppConfiguredLauncher` | launches a selected program with proxy settings (environment / Chromium flag) pointing at the Core's authenticated local inbound | APP-CONFIGURED PROXY |
| `WfpEnforcement` (Windows) | user-mode WFP filters in a **dynamic session**: the selected executable (per user) may reach loopback only; every other IPv4/IPv6 TCP/UDP connect is blocked | fail-closed ENFORCEMENT (no redirection) |

Run (from the repo root):

```bash
node scripts/cargo.mjs build --manifest-path ../experimental/per-app-routing-poc/Cargo.toml
target/debug/poc-harness.exe --report <file.json>        # (target dir: $CARGO_TARGET_DIR)
```

`WfpEnforcement` needs the right to add WFP filters (Administrators or Network Configuration
Operators). Run as a normal user, the harness records the access-denied result; the enforcement
scenarios run only in an elevated shell **started by the user**. Filters live in a dynamic WFP
session and disappear when the harness exits or crashes.

Scope limits of the WFP part, by design: only `ALE_AUTH_CONNECT_V4/V6` PERMIT/BLOCK filters in its
own sublayer, only for the one executable and the current user; no callouts, no drivers, no
persistent objects, no other firewall changes.
