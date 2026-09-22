# Phase 6: security preservation record

Phase 6 turned the native helper into a Shared Core with the browser as a thin client. This record
shows, for every Phase 5 protection, where it lived, where it lives now, whether behaviour changed,
and what evidence was produced after the refactor.

* Branch: `phase-6-core-modularization`. Base (Phase 5 final): `caa8a75`.
* Machine: Windows 11 x64, Brave, Kaspersky Endpoint Security active. No Mac.
* Paths are relative to `native/src` unless stated.

Verification levels:

| Level | Meaning |
|---|---|
| **PASS: RUNTIME VERIFIED** | the protection was attacked/observed with real binaries, OS, browser |
| **PASS: AUTOMATED TEST** | unit/in-process test of the logic |
| **PASS: CODE REVIEW ONLY** | not exercised here |
| **FAIL** | known problem |
| **NOT TESTED** | could have run, did not |
| **ENVIRONMENT UNAVAILABLE** | needs hardware or rights not available |
| **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD** | the release helper is removed by Kaspersky before it can run |

## Protections

| Protection | Phase 5 location | Phase 6 location | Behaviour changed? | Tests (run after the refactor) | Verification |
|---|---|---|---|---|---|
| **F3** restricted Xray isolation (deny-only user SID, Low IL, no privileges, job, child-process block, handle list, `SystemRoot`-only env, no reads of documents/secrets/temp, no persistent writes, no registry writes) | `winproc.rs` | `platform/winproc.rs` (launched only via `runtime/xray.rs`) | **YES, hardened**: token information is now read through an 8-byte-aligned buffer (it was a `Vec<u8>` cast to `TOKEN_*` structs). Restrictions themselves unchanged | integration `xray_sandbox_probe` (restricted vs control), `xray_isolation_and_listeners`; E2E "installed Xray runs at Low integrity, child processes blocked" | **PASS: RUNTIME VERIFIED** |
| Fail-closed pre-run verification | `winproc.rs verify_suspended`, `service.rs security_failure`, `xray.rs` (macOS) | `platform/winproc.rs verify_suspended`, `core/error.rs CoreError::from_runtime_security` (`RuntimeIsolationFailure`), `runtime/xray.rs` | NO (error is now typed; wire code still `XRAY_FAILED`, same message) | integration `mandatory_protection_failure_blocks_connection`, `weakened_data_folder_blocks_connection`; core `weakened_data_directory_blocks_the_session` | **PASS: RUNTIME VERIFIED** |
| **F5** authenticated browser proxy (random per-connection credentials, delivered only to the extension, never logged or stored) | `xrayconf.rs IdeAuth`, `service.rs` | `core/credentials.rs ProxyCredentials` (redacted `Debug`, zeroed on drop, not `Serialize`), `core/session.rs` (dropped at stop), `core/xray_config.rs`, `core/api.rs browser_proxy_endpoint` (only while `Connected`), `browser/adapter.rs status_json` | **YES, hardened**: same behaviour; credentials can no longer be printed with `{:?}` (before, `RuntimePlan`'s derived `Debug` would have printed them) and are cleared when the session ends | E2E "another local process cannot use the browser tunnel port (407)", "guessed credentials are refused", "credentials never reach the popup"; core `session_lifecycle_credentials_and_cleanup` (407 without/wrong, new credentials per connection, old endpoint unusable after stop, not in `Debug`/diagnostics); adapter unit `status_json_…only_when_connected`; config unit `…every_listener_is_authenticated_on_loopback` | **PASS: RUNTIME VERIFIED** |
| IDE endpoint authentication | `service.rs`, `store.rs` | `core/api.rs ide_credentials / ide_auth`, `core/store.rs` | NO | integration `ide_auth_adversarial` (1,000 brute-force attempts, 18 malformed auth, no plaintext in log/files), `ide_endpoint_requires_password`; core `ide_credentials_are_redacted_in_debug_output` | **PASS: RUNTIME VERIFIED** |
| Loopback-only listeners | `xrayconf.rs` | `core/xray_config.rs` | NO | integration `xray_isolation_and_listeners` (socket enumeration); config unit test | **PASS: RUNTIME VERIFIED** |
| **F6** WebRTC protection integrity | extension `controller.ts`, `chrome-adapters.ts` | unchanged (browser-UI side of the browser client) | NO | extension `controller.test.ts` (56/56); E2E "WebRTC protection overridden by another extension → tunnel disconnected" | **PASS: RUNTIME VERIFIED** |
| **F8** subscription refresh while connected through the authenticated tunnel | `service.rs tunnel_via`, `subscription.rs Via` | `core/api.rs tunnel_via`, `core/subscription.rs` | NO | integration `subscription_update_while_connected` | **PASS: RUNTIME VERIFIED** |
| **F9/F10** installer paths and folder-name injection | `installers/windows/Install.cmd` | unchanged | NO | `scripts/test-package-adversarial.mjs`: fixed script not injectable, previous line injectable (control) | **PASS: RUNTIME VERIFIED** |
| **F11** display-name sanitization (control, bidi, zero-width) at the trust boundary | `validate.rs clean_name` | `core/validate.rs clean_name`, used by every Core import/rename path | NO | unit `names_lose_invisible_and_bidi_characters`; integration `malicious_subscription_corpus` (05-unicode); core `imports_normalize_vless_and_vmess_and_keep_provenance` (RLO and zero-width stripped via `Core`) | **PASS: RUNTIME VERIFIED** (through the real helper) |
| Import trust boundary (no raw config to Xray, allowlists) | `parse/*`, `validate.rs`, `xrayconf.rs` | `core/import/*`, `core/validate.rs`, `core/xray_config.rs` | NO | unit `security_tests`; integration `malicious_subscription_bodies`, corpus; core `hostile_imports_are_rejected_as_data` | **PASS: RUNTIME VERIFIED** |
| SSRF / redirects / DNS rebinding | `subscription.rs`, `netpolicy.rs` | `core/subscription.rs`, `core/netpolicy.rs` | NO | integration `subscription_ssrf_is_blocked` (rebinding via `localtest.me`, which resolves to loopback here), corpus redirects; core subscription test (metadata/private/downgrade/file redirects) | **PASS: RUNTIME VERIFIED** |
| Xray integrity (pinned SHA-256 before every launch) | `xray.rs verify` | `runtime/xray.rs verify`; `Core` refuses with `RuntimeIntegrityFailure` | NO | integration `tampered_xray_is_never_executed`; core `tampered_runtime_is_never_started` | **PASS: RUNTIME VERIFIED** |
| DLL loading hardening (`DependentLoadFlags=0x800`, `SetDefaultDllDirectories`) | `harden.rs`, `.cargo/config.toml` | `platform/harden.rs`, `.cargo/config.toml` | NO | integration `planted_dlls_are_not_loaded`; package test: marker DLLs (62 names) with the debug helper through a full session, static PE checks of the release helper | **PASS: RUNTIME VERIFIED** (debug build + static release checks); release execution **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD** |
| Private data directory (verified before use), link refusal | `harden.rs`, `main.rs` | `platform/harden.rs`, `main.rs` | NO | integration `linked_data_dir_is_refused`, `weakened_data_folder_blocks_connection` | **PASS: RUNTIME VERIFIED** |
| Secret storage (encrypted secrets, key in OS store, per-directory entry) | `secrets.rs`, `store.rs` | `core/secrets.rs` (`KeyProvider` = secret-store boundary), `core/store.rs` | NO | unit `secrets_not_in_plaintext_files`, `missing_key_is_reported`, `each_data_dir_has_its_own_credential_entry`, `roundtrip_and_tamper`; E2E real Credential Manager entry per test dir | **PASS: RUNTIME VERIFIED** (Windows); macOS Keychain **ENVIRONMENT UNAVAILABLE** |
| Native Messaging authorization (`allowed_origins`, origin re-check, closed command set) | `main.rs`, `install.rs`, `protocol.rs` | `main.rs`, `browser/install.rs`, `browser/protocol.rs` | NO | integration `unauthorized_callers_are_rejected`, `hostile_native_messages`; E2E hostile extension refused | **PASS: RUNTIME VERIFIED** |
| **F7** extension impersonation (developer mode) | deployment | deployment ([managed-deployment.md](managed-deployment.md)) | NO | experiment (Phase 5) | **OPEN**: not fixed by the refactor |
| **F12** unsigned release quarantined by EDR | — | — | NO | package test: release helper removed after extraction (again on 2026-09-22) | **OPEN**: **BLOCKED BY ENDPOINT SECURITY: UNSIGNED BUILD**; needs signing + IT allowlisting |
| macOS Seatbelt, fail closed | `macsandbox.rs`, `xray.rs` | `platform/macsandbox.rs`, `runtime/xray.rs` | NO | clippy for `aarch64-apple-darwin` and `x86_64-apple-darwin` (compiles, no warnings); unit profile tests | **PASS: CODE REVIEW ONLY**; real hardware **ENVIRONMENT UNAVAILABLE** |

## Flaky test investigation (`ide_endpoint_requires_password`)

Baseline on `caa8a75`: the first full `npm test` failed in this test. Investigation, with evidence:

1. **Not an authentication defect.** Every failure happened at *connect*, before any auth
   assertion. The state was `SERVER_UNREACHABLE`: the health probe got `503` from our Xray. The same
   failure hit other tunnel tests (`subscription_update_while_connected`, `all_transports_end_to_end`,
   `failures_and_idempotency`). It is not specific to IDE auth.
2. **No shared state or port collision.** Every test starts its own Xray server, target and data
   directory on fresh ports.
3. **Root cause 1 (test fixture):** the local HTTP target dropped its socket with unread request
   bytes. On Windows that sends RST instead of FIN and can discard the `204` in flight; server-side
   Xray logs (new opt-in `PP_TEST_SERVER_LOG`) showed the connection torn down ~8 ms after it opened.
   Fixed with a graceful close.
4. **Test not equivalent to production:** production probes two targets (gstatic, then
   Cloudflare), while the test hook replaced them with a single target, removing the product's own retry.
   The hook now lists the local target twice.
5. **Found on the way:** `xray_sandbox_probe` once reported `integrityRid = 0xc2d76e2c` while every
   restriction held. That was a use-after-free in the probe fixture (it copied the token buffer and
   followed SID pointers into the freed original). Fixed. The product's own token reads were sound, but
   relied on heap alignment; they now use an aligned buffer.

| Configuration | Full-suite runs | Failed runs |
|---|---|---|
| Base `caa8a75`, parallel | 16 | 7 (~45%) |
| + graceful target close, parallel | 21 | 2 |
| + production-equivalent probe attempts, parallel | 12 | 1 (the probe-fixture UAF, item 5) |
| + aligned buffers / UAF fix, parallel | 15 | 1 (first request after a crash-restart got `503`) |
| same code, **serial** (`--test-threads=1`) | 6 × 20 tests | **0** |

Conclusion: a residual rate of about 1 failed run in 15 remains under 20-way parallel load on this
EDR-protected machine. It is always the first request through a freshly started VLESS-WebSocket tunnel
returning `503`, with the server closing the WebSocket normally. It never occurs serially. This is
recorded as test-environment load, not a product or authentication defect. It is not hidden, and
the connect-failure log tail now makes any recurrence diagnosable.

## Test results after the refactor

| Suite | Result |
|---|---|
| Native unit (`cargo test --lib`) | 84/84 |
| Architecture (layer rule) | 4/4 |
| Core API in-process | 8/8 |
| Native integration (real helper + restricted Xray + adversarial tests) | 20/20 |
| Extension typecheck + unit/security | clean, 56/56 |
| Real-browser E2E incl. hostile page / extension | 82/82 |
| Packaged runtime adversarial | 10/10 (+ release execution BLOCKED BY ENDPOINT SECURITY) |
| Clippy `-D warnings` (Windows x64, macOS arm64, macOS x64) | clean |
| `cargo audit` / `npm audit` | 0 / 0; no dependency changes since `caa8a75` |

## Known regressions

None found. The native-messaging protocol (v3), the extension, the installer and every Phase 5 test are unchanged.
