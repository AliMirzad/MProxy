# Final security gate (V1)

Date: 2026-09-21. Environment: Windows 11 Pro x64 (domain-joined), Brave 1.95 (Chromium 153), pinned
Xray-core v26.3.27, local Xray test server (no real VLESS/VMess server, no Mac available).
Threat analysis: [threat-model.md](threat-model.md).

Status values:
* **PASS**: tested at runtime, with the evidence named
* **FAIL**: known problem (with severity)
* **NOT TESTED**: implementation exists, but it was not exercised at runtime here
* **NOT APPLICABLE**: with justification

Test suites referenced below:

| Suite | Command | Result |
|---|---|---|
| Native unit tests (incl. `parse/security_tests.rs`, `netpolicy`, `harden`, `winproc`) | `node scripts/cargo.mjs test --lib` | 70/70 |
| Native integration tests (real helper process, real restricted Xray, local Xray server) | `node scripts/cargo.mjs test --test integration` | 13/13 |
| Extension unit + security tests (`tests/security.test.ts`) | `npm --prefix extension test` | 47/47 |
| Real-browser E2E (Brave, real installer, attacker page + attacker extension) | `npm run test:e2e` | 41/41 |
| `cargo clippy -D warnings` (Windows x64, macOS arm64 + x64) | `npm run lint` | clean |
| `cargo audit` (1,253 advisories, 171 crates) / `npm audit` | — | 0 / 0 |

## A. Network privacy

| # | Property | Status | Evidence |
|---|---|---|---|
| A1 | Browser DNS for proxied traffic is resolved by the server, not locally | **PASS** | E2E: `probe.test` (resolvable only in the server's DNS) is reachable through REALITY, VLESS-WS and VMess-WS and unreachable before connecting and after disconnecting. Integration `all_transports_end_to_end` covers 9 protocol/transport combinations |
| A2 | IDE HTTP endpoint resolves names remotely | **PASS** | Integration (all transports via the IDE HTTP port) and E2E "JetBrains HTTP endpoint tunnels (remote DNS)" |
| A3 | IDE SOCKS endpoint resolves names remotely | **PASS** for clients sending hostnames (SOCKS5 ATYP=domain, integration test). Clients that resolve locally before using SOCKS are outside our control, as documented in jetbrains.md |
| A4 | IPv4 behaviour (proxied, bypass for private ranges) | **PASS** | E2E: bypass list read back from the browser equals the documented list; traffic tests |
| A5 | IPv6 destinations go through the proxy | **NOT TESTED** | Chromium `fixed_servers` proxies IPv6 literals like any destination (bypass only `[::1]`, `fc00::/7`, `fe80::/10`). There was no IPv6 test network |
| A6 | WebRTC protection on by default while connected | **PASS** | E2E: `webRTCIPHandlingPolicy = disable_non_proxied_udp` while connected, restored after disconnect |
| A7 | No real-IP leak from an actual WebRTC/STUN page | **NOT TESTED** | Needs a STUN server and a public IP comparison |
| A8 | No hidden fallback: the UI never says "Connected" while traffic goes direct | **PASS** | Unit (controller): helper death → proxy cleared + error; restart keeps the dead-port proxy (fail closed during restart). E2E: **real proxy takeover** by a second extension → tunnel disconnected, "Browser proxy blocked" shown; Xray crash → restart |
| A9 | OS proxy settings are never changed (no unintended app proxying) | **PASS** (Windows) | E2E: `HKCU\…\Internet Settings` proxy values identical before and during connection. macOS (`scutil --proxy`): **NOT TESTED** |
| A10 | No stale browser proxy after a crash or restart | **PASS** | E2E "no stale proxy after browser restart" |
| A11 | Public IP changes to the server's IP with a real server | **NOT TESTED** | No real server available |
| A12 | Private ranges and plain host names go direct | **PASS** (by design, documented) | E2E bypass-list check. Documented in README, threat model and troubleshooting |

## B. Host security

| # | Property | Status | Evidence |
|---|---|---|---|
| B1 | Imported configuration cannot inject Xray features (config is data, regenerated) | **PASS** | `security_tests::dangerous_json_fields_reject_the_entry`, `generated_config_contains_only_allowlisted_capabilities`, `validate::xhttp_extra_allowlist`. Integration `malicious_subscription_bodies` (1 clean imported, 3 hostile rejected) |
| B2 | Unknown fields are rejected, not silently passed | **PASS** | Same tests (`Unsupported field …` for outbound, streamSettings, tlsSettings, link parameters, VMess keys, XHTTP extra, config sections) |
| B3 | No remote code execution through the helper (no generic OS operations) | **PASS** | Integration `hostile_native_messages`: 14 generic commands (`exec`, `runProcess`, `shell`, `powershell`, `writeFile`, …) → `INVALID_REQUEST`. Protocol unit tests |
| B4 | No command injection | **PASS** | No shell anywhere. Xray has fixed arguments. `command_injection_strings_stay_inert_data`: metacharacters in names stay literal, and in hosts are rejected. Hostile name via real helper stored literally |
| B5 | No arbitrary file access via the helper | **PASS** | No command takes a path. Path-like IDs rejected (`hostile_native_messages`). Release binary ignores `PRIVATE_PROXY_DATA_DIR` (manual run: real data dir used, temp dir untouched) |
| B6 | Path traversal in non-path fields rejected | **PASS** | `validate::path_tricks_rejected`, `security_tests::unknown_link_parameters_are_rejected` (`../`, `..\`, UNC, `file:`, `%2e%2e`, drive letters) |
| B7 | Native messaging abuse: malformed, oversized, unknown | **PASS** | Integration: malformed frames → `protocolError`, helper survives. >8 MiB frame → helper exits and Xray stops. Extra fields (`xrayPath`, `dataDir`, `xrayArgs`) → `INVALID_REQUEST` |
| B8 | Other extensions cannot use the native host or our extension | **PASS** | E2E attacker extension: "Access to the specified native messaging host is forbidden"; `sendMessage`/`connect` to our ID fail. Integration `unauthorized_callers_are_rejected` (wrong origin → exit 3, no output) |
| B9 | Extension identity cannot be spoofed by another locally loaded **unpacked** extension | **FAIL: MEDIUM** | Unpacked IDs derive from the public key in the manifest. A malicious unpacked extension could reuse it. Mitigation for rollout: policy force-installed CRX + Developer mode disabled by policy (threat-model #10) |
| B10 | Web pages cannot reach the extension or the helper | **PASS** | E2E hostile page: no `chrome.runtime`, extension resources blocked, IDE endpoint not usable as a relay. Manifest test: no content scripts, `externally_connectable` or web-accessible resources |
| B11 | Listeners bound to loopback only; no unexpected sockets | **PASS** | Integration `xray_isolation_and_listeners`: netstat enumeration shows exactly 3 TCP listeners (browser, IDE SOCKS, IDE HTTP) on 127.0.0.1, no UDP, and the helper listens on nothing. Generated-config tests assert `listen: 127.0.0.1` |
| B12 | Local listeners usable only by the intended user | **FAIL: MEDIUM** (accepted for single-user machines) | Listeners are unauthenticated (Chrome cannot pass SOCKS credentials). On multi-user hosts, disable the IDE endpoint |
| B13 | Xray isolated from the host (Low integrity, no child processes, job, mitigations) | **PASS** (Windows) | Integration + E2E (installed runtime): OS reports `integrity=low`, `childProcessesBlocked`, `extensionPointsDisabled`, `remoteImagesBlocked` |
| B13m | Same on macOS | **FAIL: MEDIUM** | Not implemented. Xray runs as the user with a cleared environment only (see the isolation evaluation in threat-model.md) |
| B14 | A compromised Xray cannot read stored credentials or write user files | **PASS** (Windows) | Integration: a Low-integrity process under the same token cannot `type secrets.bin` (Medium control can) and cannot write into `%USERPROFILE%`. macOS: covered by B13m (**FAIL**) |
| B15 | No privilege escalation; runtime never runs as admin/root | **PASS** (Windows) | Install and run in E2E without elevation. Helper at Medium, Xray at Low. macOS `.pkg` (root only during install): **NOT TESTED** |
| B16 | Xray binary integrity verified before every launch | **PASS** | Integration `tampered_xray_is_never_executed`: 1-bit-modified Xray and a foreign executable are both refused, never started, `xrayAvailable=false`. The installer refuses to install a non-pinned Xray |
| B17 | Xray artifacts are official and pinned | **PASS** | Zip SHA-256 values match upstream `.dgst` for all 4 platforms (checked 2026-09-21). Binary SHA-256 pinned in `xray.lock.json` |
| B18 | Product-owned Xray only (no PATH search, env override ignored in release) | **PASS** | Release binary with `PRIVATE_PROXY_XRAY=cmd.exe` → "xray: not found" |
| B19 | DLL search-order hijacking | **PASS** | Integration `planted_dlls_are_not_loaded`. Control: the V1 helper (DependentLoadFlags=0) failed to start with a planted `secur32.dll`; the fixed one runs |
| B20 | Installer tools called by absolute path (cmd, PING, powershell, chmod, awk) | **NOT TESTED** at runtime | Code change only (`install.rs`, `Install.cmd`, `install.sh`, `build-pkg.sh`) |
| B21 | Install directory not writable by other users | **PASS** (Windows) | E2E `icacls`: user, SYSTEM and Administrators only, protected |
| B22 | Data directory private + unreadable to Low integrity | **PASS** (Windows) | `dataDirProtection` = `D:P(user)(SYSTEM)` + ML `NR NW NX` (integration). Unit `harden::private_dir_and_link_detection`. macOS 0700: **NOT TESTED** |
| B23 | Symlink/junction attacks on the data dir | **PASS** | Integration `linked_data_dir_is_refused`: junction → exit 4, nothing written through it (found and fixed a log-dir-first bug during this test) |
| B24 | SSRF from subscriptions (loopback, metadata, private, DNS rebinding) | **PASS** | Integration `subscription_ssrf_is_blocked`: 11 blocked URLs, 0 connections reached the local service, DNS rebinding via `localtest.me` refused. Unit `url_rules`, `dns_answers_are_checked` |
| B25 | Server addresses cannot target loopback or metadata | **PASS** | `local_and_metadata_server_addresses_are_rejected`; integration import refused; connect-time re-check |
| B26 | Secrets encrypted at rest | **PASS** | Unit `store::secrets_not_in_plaintext_files` |
| B27 | Secrets never returned by status/metadata APIs | **PASS** | Integration `hostile_native_messages` (listServers, getStatus, getSettings, getDiagnostics contain no UUID or REALITY key). E2E "popup does not expose the user ID" |
| B28 | Logs redacted | **PASS** | Unit `log::redacts_secrets` |
| B29 | No dynamic code in the extension (eval, remote scripts) | **PASS** | `security.test.ts` scans the release bundle. The CSP has no `unsafe-*` or remote sources |
| B30 | Dependencies free of known vulnerabilities | **PASS** | `cargo audit` 0, `npm audit` 0 (2026-09-21) |
| B31 | Builds reproducible from lockfiles | **NOT TESTED** in CI | `--locked` in package.mjs and CI, `npm ci`. The CI workflow has not been run |
| B32 | Release builds ignore test hooks | **PASS** | Manual run with every `PRIVATE_PROXY_*` variable set: real data dir, no Xray override. The debug binary honours them only in test mode |
| B33 | Uninstall does not execute or follow imported data | **PASS** | Uninstall deletes fixed paths. E2E runs `uninstall --purge`. Links removed without following (code). The delayed `cmd` removal branch: **NOT TESTED** |
| B34 | Signed binaries (Authenticode / Developer ID + notarization) | **FAIL: MEDIUM** | V1 builds are unsigned. Required before company-wide rollout (installation.md) |

## Result

* **CRITICAL / HIGH unresolved: none.**
* **FAIL, MEDIUM:**
  * B9: unpacked extension ID spoofing
  * B12: unauthenticated loopback listeners on multi-user machines
  * B13m/B14 (macOS): no OS isolation for Xray
  * B34: unsigned builds
* **NOT TESTED (runtime):**
  * everything on macOS
  * IPv6
  * real WebRTC leak test
  * real servers / public IP change
  * the Windows installer's absolute-path invocation
  * CI

**Designation:** the **Windows** build meets the gate for **controlled company pilot use**, on two conditions:
1. The extension is distributed as a policy-installed CRX with Developer mode disabled (closes B9).
2. The runtime is deployed only on single-user machines, or with the IDE endpoint disabled (B12).

Signing (B34) is required before broad rollout. The **macOS** build is **not company-ready** until the
macOS items are validated on real hardware and B13m is addressed.

This result does not claim the product cannot be attacked or observed. It documents a minimized,
tested attack surface, and the residual risks listed above and in the threat model.
