# Security gate

Date: 2026-09-22 (adversarial review; supersedes the 2026-09-21 gate, whose "no HIGH or CRITICAL"
conclusion was re-verified and **did not hold**: see [adversarial-testing.md](adversarial-testing.md#findings)).
Environment: Windows 11 Pro x64 (domain-joined, Kaspersky Endpoint Security active), Brave (Chromium
153), Xray-core v26.3.27, local Xray test server. No Mac, no real VLESS/VMess server, no admin rights
for browser policies. Threat analysis: [threat-model.md](threat-model.md).

## Status values

| Status | Meaning |
|---|---|
| **PASS: runtime verified** | an attack or check was executed against the real binaries/OS/browser and observed |
| **PASS (CODE REVIEW ONLY)** | enforced in code and reviewed; not exercised at runtime |
| **FAIL** | known problem, with severity |
| **NOT TESTED** | could have been run here but was not |
| **ENVIRONMENT UNAVAILABLE** | needs hardware, rights or services this environment does not have |
| **PASS: AUTOMATED TEST** (added in Phase 6) | unit / in-process test of the logic, no real OS boundary involved |
| **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD** (added in Phase 6) | the release helper is removed by the company EDR before it can run |

## Phase 7 per-app routing research (branch `phase-7-per-app-routing-poc`)

Additional statuses used: **RESEARCH ONLY**, **EXPERIMENTAL**. The product is unchanged: no routing
code runs in the browser product. Full results: [per-app-routing-decision.md](per-app-routing-decision.md).

| Property (experimental PoC) | Status |
|---|---|
| Selected app that honours a proxy setting → through Xray; control app direct | PASS: RUNTIME VERIFIED (S1–S3, R1/R2, R4) |
| Selected app without proxy support is routed | **FAIL**: silent direct bypass (S4, R3); true routing needs a WFP callout driver: ENVIRONMENT UNAVAILABLE |
| Selected app: no direct IPv4/IPv6/UDP/DNS | **FAIL** with app-configuration alone (S5–S8); WFP enforcement written, **NOT TESTED** (needs admin) |
| Chromium/Electron app through the authenticated inbound | **FAIL**: cannot answer 407 (R5) |
| Unrelated child not proxied | **FAIL** with environment inheritance (C3) |
| Fail closed when Xray or the helper dies (cooperating apps) | PASS: RUNTIME VERIFIED (F1–F3) |
| No system side effects (proxy, routes, DNS, adapters, firewall rules, drivers, services) | PASS: RUNTIME VERIFIED (snapshots identical) |
| Normal user cannot add WFP filters | PASS: RUNTIME VERIFIED (`ERROR_ACCESS_DENIED`) |
| macOS per-app routing | RESEARCH ONLY; ENVIRONMENT UNAVAILABLE |

## Phase 7.5 Windows routing validation (branch `phase-7.5-windows-routing-validation`)

The Phase 7 rows marked "WFP enforcement written, NOT TESTED" were exercised with administrator
rights on 2026-09-23. Evidence: [windows-routing-validation.md](windows-routing-validation.md).
The product is still unchanged: `RuntimeCapabilities.application_routing` is `false`, no routing code
ships, and the PoC is rejected by the packaging guard.

| Property (experimental PoC, elevated) | Status |
|---|---|
| Selected app cannot reach the network directly over IPv4 TCP | PASS: RUNTIME VERIFIED (T2, T10–T12) |
| Selected app cannot leak over UDP | PASS: RUNTIME VERIFIED (T4: datagram dropped, listener received nothing) |
| Unselected apps unaffected (same bytes, other path) | PASS: RUNTIME VERIFIED (T3, T5) |
| Loopback stays reachable for selected apps | PASS: RUNTIME VERIFIED (T9) |
| No direct fallback when Xray dies; recovery afterwards | PASS: RUNTIME VERIFIED (T16) |
| Complete teardown, no persistent WFP objects, no system change | PASS: RUNTIME VERIFIED (T18 + before/after snapshot) |
| Selected app without proxy support is routed | **FAIL by design**: it is blocked, not routed (Track B required) |
| Selected app: no DNS metadata leak | **FAIL**: resolved by the DNS Client service (T8) |
| IPv6 enforcement | **NOT TESTED: ENVIRONMENT LIMITATION** (no IPv6 route on the machine) |
| Protection survives the death of the process owning the filters | **FAIL**: dynamic session removed, app fails open (T17) → production requires a service |
| Child processes covered automatically | **FAIL by design**: no process-tree condition in WFP; explicit executable listing works (T13–T15) |
| Repeated WFP session open/apply/close in one elevated process | PASS: RUNTIME VERIFIED (`--wfp-cycle 3`: all calls `0x0`, 0 objects left) |
| Enforcer terminated by endpoint security during validation | **OBSERVED, NOT PROVEN**: two runs ended at `0x40000015` with a correlated EDR event; a later identical run completed. No evasion attempted; remedy is signing + allowlisting (F12) |
| Track B callout driver | RESEARCH ONLY; ENVIRONMENT UNAVAILABLE (no WDK; machine security settings untouched) |

Regression re-run on this branch (2026-09-23): native unit 84/84, architecture 4/4, Core API 8/8,
integration 20/20, extension 56/56 + typecheck, real-browser E2E 82/82, packaged runtime adversarial
11/11, clippy clean (product and PoC), `cargo audit` and `npm audit` 0 findings. In this run the
release helper was **not** removed by the endpoint product, unlike the Phase 6 run.

## Phase 6 re-verification (2026-09-22, branch `phase-6-core-modularization`)

The code was restructured into a Shared Core with the browser as a thin client
([module-boundaries.md](module-boundaries.md)). Every suite below was **re-run on the refactored code**.
Protection-by-protection mapping and verification levels are in
[phase6-security-preservation.md](phase6-security-preservation.md).

| Suite | Result after Phase 6 |
|---|---|
| Native unit | 84/84 (was 76; new: credentials, session, error, adapter mapping, config determinism) |
| Architecture (layer rule, `tests/architecture.rs`) | 4/4 (new) |
| Core API in-process (`tests/core_api.rs`) | 8/8 (new) |
| Native integration (all Phase 5 adversarial tests through the new adapter → Core path) | 20/20 |
| Extension | 56/56, typecheck clean |
| Real-browser E2E | 82/82 |
| Packaged runtime adversarial | 10/10; release helper execution **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD** |
| Clippy (Windows x64, macOS arm64/x64) | clean |
| `cargo audit` / `npm audit` | 0 / 0 (no dependency changes) |

Every B-item below that was **PASS: runtime verified** in Phase 5 was re-verified by the same
tests after the refactor. Nothing changed status, except:
* the release-execution part of B19c is now reported as **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD**;
* the intermittent integration failure is explained (test-environment load; serial runs 0/6 failures).

Open items are unchanged:
* **B9 / F7** (HIGH, unmanaged installs);
* **B34 / F12** (unsigned, quarantined by EDR);
* macOS (ENVIRONMENT UNAVAILABLE).

## Test suites (Phase 5 gate)

| Suite | Command | Result |
|---|---|---|
| Native unit tests | `node scripts/cargo.mjs test --lib` | 76/76 |
| Native integration (real helper, real restricted Xray, local server) | `node scripts/cargo.mjs test --test integration` | 20/20 (intermittent: 1 failure in 5 full runs of `ide_endpoint_requires_password` under parallel load; passes alone; see adversarial-testing.md) |
| Extension unit + security | `npm --prefix extension test` | 56/56 |
| Real-browser E2E incl. hostile page + hostile extension fixtures | `npm run test:e2e` | 82/82 |
| Packaged runtime adversarial test | `node scripts/test-package-adversarial.mjs` | 10/10, 1 ENVIRONMENT UNAVAILABLE |
| Impersonation experiment | `node extension/tests/e2e/experiments/impersonation-experiment.mjs` | attack **succeeds** (expected; see B9) |
| Clippy `-D warnings` (Windows, macOS arm64/x64) | `npm run lint` | clean |
| `cargo audit` (1,261 advisories, 171 crates) / `npm audit` | — | 0 / 0 |

## A. Network privacy

| # | Property | Status | Evidence |
|---|---|---|---|
| A1 | Browser DNS for proxied traffic resolved by the server | **PASS: runtime verified** | E2E `probe.test` only resolvable on the server; 9 transports in integration |
| A2 | IDE HTTP endpoint resolves remotely | **PASS: runtime verified** | integration + E2E |
| A3 | IDE SOCKS endpoint resolves remotely (for clients sending hostnames) | **PASS: runtime verified** | integration (ATYP=domain) |
| A4 | Bypass list exactly the documented private ranges | **PASS: runtime verified** | E2E reads it back from the browser |
| A5 | IPv6 destinations proxied | **ENVIRONMENT UNAVAILABLE** | no IPv6 network |
| A6 | WebRTC protection on while connected | **PASS: runtime verified** | E2E policy read-back; hostile page gathers **0** ICE candidates |
| A6b | WebRTC protection cannot be silently overridden by another extension | **PASS: runtime verified** (fixed in this review) | E2E: override → tunnel disconnected with a WebRTC reason; reconnects when released |
| A7 | No real-IP leak through STUN (srflx) | **ENVIRONMENT UNAVAILABLE** | no STUN server / public IP comparison; host candidates: none |
| A8 | Never "Connected" while traffic goes direct | **PASS: runtime verified** | E2E takeover, takeover racing connect, 25× flapping: invariant held |
| A9 | OS proxy settings never changed | **PASS: runtime verified** (Windows); macOS **ENVIRONMENT UNAVAILABLE** | E2E registry compare |
| A10 | No stale proxy after browser crash | **PASS: runtime verified** | E2E |
| A11 | Public IP changes with a real server | **ENVIRONMENT UNAVAILABLE** | no real server |
| A12 | Subscription refresh while connected goes through the tunnel | **PASS: runtime verified** (regression fixed in this review) | integration `subscription_update_while_connected` fails on the old code, passes now |
| A13 | No telemetry, analytics or unexpected third parties | **PASS: runtime verified** (extension CSP) + **PASS (CODE REVIEW ONLY)** (helper/Xray egress) | [data-leak-review.md](data-leak-review.md) |

## B. Host security

| # | Property | Status | Evidence |
|---|---|---|---|
| B1 | Imported config cannot inject Xray features | **PASS: runtime verified** | unit allowlist tests; integration hostile bodies + corpus (`08-unknown-xray-fields`, `09-full-client-config`) |
| B2 | Unknown fields rejected | **PASS: runtime verified** | same |
| B3 | No generic OS operations through the helper | **PASS: runtime verified** | `hostile_native_messages` |
| B4 | No command injection (names, links, installer) | **PASS: runtime verified** | corpus `01-command-injection`; `Install.cmd` folder-name injection: previous line **injectable** (reproduced), fixed line not |
| B5 | No arbitrary file access via the helper | **PASS: runtime verified** | no path arguments; release ignores test hooks |
| B6 | Path traversal in fields rejected | **PASS: runtime verified** | unit + corpus `02-path-traversal` |
| B7 | Native messaging abuse | **PASS: runtime verified** | integration malformed/oversized frames |
| B8 | Other extensions cannot use the host or our extension | **PASS: runtime verified** | E2E fixture: port + one-shot native messaging forbidden; 3 message types + popup port refused; files unreadable |
| **B9** | Extension identity cannot be impersonated | **FAIL: HIGH** (unmanaged install) | impersonation experiment: our `key` → our ID → IDE password read, IDE auth disabled, attacker server imported. Closed only by [managed deployment](managed-deployment.md) (policy CRX, developer mode off); policy enforcement itself: **ENVIRONMENT UNAVAILABLE** (needs admin) |
| B10 | Web pages cannot reach extension/helper/ports | **PASS: runtime verified** | E2E hostile page (public origin) |
| B11 | Listeners loopback only | **PASS: runtime verified** | socket enumeration |
| B12 | IDE endpoint needs the password; brute force, malformed auth | **PASS: runtime verified** | `ide_auth_adversarial`: 20 regenerations distinct/24 chars/57-symbol alphabet; 13 malformed `Proxy-Authorization` + 5 malformed SOCKS auth refused; 1,000 guesses → 0 accepted in 140 ms, same Xray PID after |
| B12b | Browser tunnel port usable only by the browser | **PASS: runtime verified** (fixed in this review) | E2E + integration: 407 without / with guessed credentials; IDE password rejected there and vice versa |
| B12c | Credentials never logged or stored in plaintext; never shown to the UI (browser credentials) | **PASS: runtime verified** | `ide_auth_adversarial` scans helper log, `state.json`, `secrets.bin`; E2E: popup state has no credentials; other extension's `webRequest` `extraHeaders` never sees `Proxy-Authorization`; trap proxy never received them |
| B13 | Xray isolation (Windows) | **PASS: runtime verified** | `xray_sandbox_probe` (restricted vs control), E2E installed runtime |
| B13a | Mandatory isolation failure blocks the connection | **PASS: runtime verified** | `mandatory_protection_failure_blocks_connection`, `weakened_data_folder_blocks_connection` |
| B13m | macOS Seatbelt sandbox, fail-closed | **ENVIRONMENT UNAVAILABLE** | implemented; unit-tested profile; compiles for macOS; `sandbox-exec` is deprecated (see adversarial-testing.md §3) |
| B14 | Compromised Xray cannot read user files or secrets, or write anywhere persistent | **PASS: runtime verified** (Windows; fixed in this review: Low IL alone still allowed reading Documents) | probe reads/writes |
| B15 | No elevation | **PASS: runtime verified** (Windows) | E2E install without admin |
| B16 | Xray integrity before every launch | **PASS: runtime verified** | `tampered_xray_is_never_executed` |
| B17 | Xray provenance pinned | **PASS: runtime verified** | zip + binary SHA-256 re-verified by `fetch-xray.mjs`; release manifest |
| B18 | No PATH search / env override in release | **PASS (CODE REVIEW ONLY)** this round (runtime-verified in the 2026-09-21 gate; code unchanged) | `xray.rs` resolves only its own directory; release ignores `PRIVATE_PROXY_XRAY` |
| B19 | DLL planting, static imports | **PASS: runtime verified** | release PE from the zip: `DependentLoadFlags=0x800`; integration planted-DLL test |
| B19b | DLL planting, runtime loads (Schannel, DNS, Credential Manager, Xray) | **PASS: runtime verified** (debug build, same flags) | marker DLLs under 62 names next to helper and Xray; control program loads them; full session loads none |
| B19c | DLL planting with the **packaged release** helper executing | **ENVIRONMENT UNAVAILABLE** | endpoint security deletes the unsigned release helper after extraction |
| B20 | Installer uses absolute tool paths | **PASS: runtime verified** (fixed in this review: the shipped `Install.cmd` had lost its backslashes, so the Mark-of-the-Web step never ran) | package test runs the fixed script |
| B21 | Install dir not writable by others | **PASS: runtime verified** | E2E icacls |
| B22 | Data dir private, not readable at Low IL | **PASS: runtime verified** (Windows); macOS **ENVIRONMENT UNAVAILABLE** | integration |
| B23 | Junction/symlink data or install dir refused | **PASS: runtime verified** (data dir) / **PASS (CODE REVIEW ONLY)** (install target, `install.rs` `is_link`) | `linked_data_dir_is_refused` |
| B24 | Subscription SSRF incl. redirects and rebinding | **PASS: runtime verified** | `subscription_ssrf_is_blocked`, corpus redirects (metadata, private, downgrade, file, ftp, fe80, 0.0.0.0, loop) |
| B25 | Server addresses cannot target loopback/metadata | **PASS: runtime verified** | corpus `06-internal-targets` on a production-like helper |
| B26–B28 | Secrets encrypted, not in APIs, logs redacted | **PASS: runtime verified** | unit + integration |
| B29 | No dynamic code in the extension | **PASS: runtime verified** | bundle scan, CSP |
| B30 | Dependencies without known vulnerabilities | **PASS: runtime verified** | audits 2026-09-22 |
| B31 | Reproducible builds | **NOT TESTED** | manifest records inputs; no second independent build compared |
| B32 | Release ignores test hooks | **PASS (CODE REVIEW ONLY)** this round (runtime in the previous gate; code unchanged) | `lib.rs test_hook` |
| B33 | Uninstall safe with hostile paths | **PASS (CODE REVIEW ONLY)** | `install.rs remove_files` refuses `" % & \| ^ < > !`, System32-absolute `cmd`/`PING` |
| B34 | Signed binaries | **FAIL: MEDIUM** → deployment blocker | unsigned; quarantined by EDR on this machine |
| B35 | Test fixtures/binaries never shipped | **PASS: runtime verified** | `package.mjs assertNoTestArtifacts` ran on this build |
| B36 | Deceptive server names (bidi/zero-width) | **PASS: runtime verified** (fixed in this review) | unit + corpus `05-unicode` |

## Result

* **CRITICAL:** none found.
* **HIGH:**
  * B9 extension impersonation in developer mode, **open** for unmanaged installs (closed by managed deployment).
  * Fixed in this review: Xray could read the user's documents (Low IL without deny-only SID).
* **MEDIUM open:** B34 unsigned binaries (blocked by EDR).
* **MEDIUM fixed in this review:**
  * silent downgrade of isolation;
  * macOS unsandboxed fallback;
  * browser port open to other local users;
  * WebRTC override by other extensions.
* **LOW fixed:**
  * `Install.cmd` path and folder-name injection;
  * subscription refresh while connected;
  * deceptive names.
* **ENVIRONMENT UNAVAILABLE:**
  * macOS (all items);
  * IPv6;
  * STUN;
  * real server;
  * browser policies (admin);
  * packaged-release execution (EDR).

**Designation:**
* **Not approved for company workstations as currently distributed.**
* **Windows** is acceptable for a **controlled pilot** only when all of these hold:
  * the binaries are signed and allowlisted by IT;
  * the extension is force-installed as a CRX with developer mode blocked;
  * the native host is installed machine-wide ([managed-deployment.md](managed-deployment.md)).
* **macOS** is not company-ready until it is validated on hardware.

This gate documents a tested, minimized attack surface. It does not claim the product cannot be attacked or observed.
