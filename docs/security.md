# Security

> Host-compromise analysis: [threat-model.md](threat-model.md). Final gate with PASS/FAIL per property:
> [security-gate.md](security-gate.md). Dependencies: [dependencies.md](dependencies.md). The table below is
> the original V1 review, updated for the hardening pass.

## Threat model (V1)

**Protected:**
* VLESS/VMess credentials, REALITY keys and subscription URLs at rest.
* The native helper, a privileged local program, against misuse by web content or other extensions.
* The user's browsing privacy in logs and on disk.
* Other applications, which must not be affected.

**Out of scope:** malware already running as the same OS user. It can read process memory,
talk to the loopback proxy, and read the OS keychain entry the same way the helper does. A
compromised browser profile or extension is also out of scope, as is protection against the
remote VPN server itself.

## Review results

| Area | Finding / design | Status |
|---|---|---|
| **Native messaging authorization** | Host manifest `allowed_origins` lists only the pinned extension ID (no wildcards possible). The helper also checks the origin passed in `argv[1]` against its compiled-in allow-list and exits otherwise. | OK |
| **Extension message surface** | No content scripts, no `externally_connectable`. The service worker accepts messages only from this extension's own pages (`sender.id` + `sender.url`) and forwards only allow-listed commands (`UI_COMMANDS`). | OK |
| **Command validation** | Closed command set, serde `deny_unknown_fields`, UUID-validated IDs, 8 MiB message cap. There is no exec, no arbitrary path, and no arbitrary host (except the HTTPS-validated subscription URL). Tested with malformed JSON, unknown commands (`exec`), path-like IDs, extra fields and out-of-range ports. | OK |
| **Imported configuration** | Never executed or forwarded. Every imported object is checked against allowlists taken from the Xray v26.3.27 source (`parse/fields.rs`): dangerous fields (`masterKeyLog`, `certificates`, `sockopt`, `sendThrough`, `proxySettings`, `targetStrategy`, VLESS `reverse`, server-side REALITY keys) and **unknown fields reject the entry**. XHTTP `extra` is rebuilt from an allowlist. URL-path fields reject traversal/UNC/`file:` forms. The Xray config is regenerated from the typed model. | OK (hardened) |
| **Xray process** | Fixed arguments `run -c stdin: -format json` (plus `-test`). The environment is cleared (`SystemRoot` only). The binary SHA-256 is verified before every launch. Windows: Low integrity, mitigation policies, no child processes, restricted job assigned before start, and `DETACHED_PROCESS`. | OK (hardened) |
| **Temporary config files** | None. The config (with credentials) goes over the child's stdin. | OK |
| **Orphaned processes** | Windows: Job Object with `KILL_ON_JOB_CLOSE`. macOS: signal handlers plus PID-file reaping on next start. Verified on Windows by E2E and integration tests: after the browser closes, and after a disconnect during startup, the ports are closed. | OK (macOS path needs real-device validation) |
| **Secret storage** | `secrets.bin` uses XChaCha20-Poly1305 (RustCrypto). The 256-bit key is in Windows Credential Manager / macOS login Keychain via `keyring`. `state.json` holds no credentials (tested). If the key is lost, the helper reports it and "Remove all servers" recovers. The E2E test ran against the real Windows Credential Manager. | OK |
| **Secrets reaching the extension** | `listServers` returns summaries only (no UUID, keys or subscription URL). Asserted in integration and E2E tests. | OK |
| **Log redaction** | Logs contain events and error codes, not payloads. Every line passes through `redact()` (UUIDs, `vless://`/`vmess://` links, URL paths and queries, 32+ char tokens), which is unit tested. Logs are rotated (512 KiB × 4). Xray access logging is disabled (`access: none`). Xray's own output reaches disk **only** when the user enables verbose diagnostics. | OK |
| **Browsing information** | No URL or domain tracking, no history, no telemetry. Destinations can appear in logs only with verbose diagnostics enabled (Xray info level). This is documented in the UI and in troubleshooting. | OK |
| **Localhost exposure** | All inbounds are `127.0.0.1` only (asserted in tests). The generator has no code path to another listen address. | OK |
| **Proxy self-loop / local DoS** | *Found during review:* a request to `http://127.0.0.1:10809/` through the IDE HTTP inbound made Xray proxy to itself recursively. **Fixed:** routing rules block loopback destinations on our own inbound ports. An integration test asserts it fails fast and the endpoint survives. | Fixed |
| **Unauthenticated local proxy** | Any process of any local user can use the loopback endpoints (and therefore the tunnel) while they are up. This is accepted for V1: the typical deployment is a single-user workstation, and Chrome's proxy API cannot pass SOCKS credentials. On shared machines, disable the IDE endpoint. The browser port is ephemeral but also unauthenticated. | Accepted risk |
| **Subscription handling** | HTTPS only (plain HTTP to loopback only in debug test mode). Destination policy on the URL, redirects and every DNS answer: no loopback, link-local/metadata, multicast; private networks only with an opt-in setting (`netpolicy.rs`). Downgrade redirects are refused, with at most 5 redirects. Timeouts are 10 s connect and 20 s total. The body is capped at 5 MiB and entries at 2,000, and each entry is isolated. A fixed User-Agent is sent with no cookies or identifiers. The URL is stored encrypted, shown only as its host, and redacted in errors. Fetches go through the tunnel when connected (`socks5h`, remote DNS). All of this is tested. | OK |
| **QR codes** | Decoded locally with bundled jsQR. The payload is accepted only if it is a VLESS/VMess link, a base64 list or JSON, and is then parsed like any import. URLs in QR codes are never opened. The screenshot for "Scan current tab" uses `activeTab` (granted only by the user's click) and is never stored. | OK |
| **Extension permissions** | `proxy`, `storage`, `nativeMessaging`, `activeTab`, `privacy` (WebRTC protection, on by default). There are no host permissions, and a proxy takeover by another extension disconnects the tunnel. CSP for extension pages is `script-src 'self'; object-src 'none'; connect-src 'self' data:`. | OK |
| **UI injection** | All helper-provided strings (server names, messages) are rendered with `textContent` or `value`. No `innerHTML` is used with data. | OK |
| **Installer** | Per-user and writes only product-owned locations. System tools are called by absolute path, link targets are refused, the install dir gets a private ACL, only the pinned Xray is installed, and `DependentLoadFlags=System32` defeats DLL planting (a real V1 issue, fixed and regression-tested). It writes: its install dir, HKCU native messaging keys and HKCU Uninstall entry (Windows), and NativeMessagingHosts manifests (macOS). The Windows Mark-of-the-Web is stripped from installed binaries. The installer cannot be triggered by the browser (Chromium passes only the origin argument). | OK |
| **Dependency vulnerabilities** | `cargo audit` (RustSec, 1,253 advisories, 171 crates): **0 findings**. `npm audit`: **0 vulnerabilities**. Xray is pinned by version and SHA-256. TLS comes from the OS (SChannel / Security.framework); OpenSSL is not linked. | OK (2026-09-21) |

## Residual risks and notes

* **Unsigned V1 builds.** Windows SmartScreen and macOS Gatekeeper warn or block unsigned binaries.
  Internal distribution should sign builds: Authenticode for Windows, Developer ID + notarization for macOS
  (see [installation.md](installation.md)). The per-user runtime directory is user-writable, so another process
  running as the same user could replace the helper binary. That is inside the out-of-scope threat.
  The macOS `.pkg` installs root-owned binaries if this matters.
* **Keychain prompts on macOS.** An unsigned helper that is updated (new binary hash) may make macOS ask
  once whether it may access the "com.privateproxy.host" keychain item. That is the reason for a single
  data key instead of one item per server.
* **WebRTC.** Protection is on by default. If the user switches it off, sites can learn the real IP through WebRTC UDP.
* **Fail-open by design.** There is no kill switch. On failure the browser goes direct (and the popup shows it).
* **VLESS without TLS/REALITY** is unencrypted. Import warns, and current Xray allows it only to private
  addresses unless VLESS Encryption is used.
* **`allowInsecure` links** are imported with certificate verification **enabled** (Xray removed the
  option). The user sees a warning; pinning (`pcs`) is supported.

## Reporting

Internal project: report issues to the maintainers. Never paste real links, UUIDs or subscription URLs into
tickets. "Copy diagnostics" output contains no credentials.
