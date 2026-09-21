# Threat model: host compromise and data leakage

Scope: Private Proxy V1 on company computers (Windows, macOS), browsers Chrome/Brave/Chromium.
Goal: no remote input (proxy server, subscription, imported link/JSON/QR, web page) and no local
caller (other extension, other process) can turn the product into a way to compromise the host.
Every remote input is treated as hostile.

The test and evidence status of each property is in [security-gate.md](security-gate.md).
File references point at the code that enforces a control.

## Components and trust boundaries

```
 web pages ──X── extension (MV3, privileged) ──native messaging (stdio, allowed_origins)──▶ helper (Rust, user, Medium IL)
                         │ chrome.proxy                                                     │ stdin config, fixed args
                         ▼                                                                   ▼
                 browser ──SOCKS5 127.0.0.1:eph──▶ Xray (Low IL, restricted job, no children)──▶ VLESS/VMess server ──▶ Internet
 JetBrains/other local apps ──HTTP/SOCKS 127.0.0.1:10809/10808──▶ Xray
 subscription provider ◀── HTTPS (helper; destination policy, size/time limits)
```

| Boundary | Crossed by | Enforced in |
|---|---|---|
| Web page → extension | nothing (no content scripts, no `externally_connectable`, no web-accessible resources) | `extension/manifest/manifest.json`, `tests/security.test.ts`, E2E |
| Other extension → extension / helper | nothing (sender checks; `allowed_origins` = pinned ID; helper re-checks `argv[1]`) | `service-worker.ts` `fromOwnPage`, `install.rs manifest_json`, `main.rs run_host` |
| Extension → helper | closed, typed command set | `protocol.rs` (`deny_unknown_fields`, UUID ids), `service.rs` |
| Imported data → Xray config | typed model only; config regenerated | `parse/*`, `parse/fields.rs`, `validate.rs`, `xrayconf.rs` |
| Helper → Xray | fixed arguments, config via stdin, minimal environment, pinned binary | `xray.rs`, `winproc.rs` |
| Xray → host | Low integrity (Windows), no child processes, job limits | `winproc.rs`, `harden.rs` |
| Helper → network (subscriptions) | destination policy, HTTPS, limits | `subscription.rs`, `netpolicy.rs` |
| Local processes → proxy listeners | loopback only, **unauthenticated** | `xrayconf.rs` (listen `127.0.0.1`) |

## Attackers

### 1. Malicious VLESS/VMess server (operator acts in bad faith)
* **Attack surface:** all proxied traffic; responses to Xray's protocol handshake; content of plain-HTTP
  sites; DNS answers for proxied names (resolved on the server); timing.
* **Possible impact:** observe and manipulate traffic metadata; tamper with plaintext HTTP; send
  malformed protocol data to exploit a bug in Xray (memory-safe Go, but logic or parser bugs are
  possible); deliver hostile web content (same as any network attacker).
* **Existing mitigation:** HTTPS/TLS end to end for web content (browser verifies certificates;
  the proxy can't read or alter HTTPS content without a certificate error). REALITY/TLS
  authenticates the server to Xray. No inbound from the server exists: Xray only opens outbound
  connections, with no VLESS reverse proxy (rejected at import, `fields.rs PROXY_SETTINGS.reverse`)
  and no mux.
* **Additional mitigation (this hardening):** Xray runs at **Low integrity** with creation-time
  mitigation policies, **no child-process creation**, an explicit handle list, a minimal
  environment, and a kill-on-close job with a 2 GiB memory cap (`winproc.rs`). A compromised Xray
  cannot read the credential store (the data dir has a no-read-up label, `harden.rs`), cannot write
  to the user profile or registry, cannot inject into Medium processes, and cannot start programs.
  All of this was verified at runtime (`xray_isolation_and_listeners`).
* **Residual risk:** a server operator always sees metadata (see "What a proxy operator can
  observe" below). On macOS Xray runs as the user without OS isolation: Xray code execution
  there would have the user's file access (**gap, see security-gate B13/B14**). Browser exploits
  delivered through plain-HTTP content are outside this product's control. Keep the browser updated.

### 2. Compromised proxy server (a legitimate server taken over)
Same capabilities as attacker 1, gained without the user's knowledge. Additionally, a compromised
server of a **subscription-managed** list can't change the client's configuration. Only the
subscription provider can (attacker 3). Mitigations and residual risk are as for attacker 1.

### 3. Malicious subscription provider
* **Attack surface:** the subscription body (up to 5 MiB), HTTP status/redirects, and when refreshes happen.
* **Possible impact:** hostile configs (file-writing fields, interface binding, proxy chaining,
  local DNS), huge or malformed bodies (DoS), redirects to internal services (SSRF), steering the user
  to attacker-operated servers, tracking refresh times and the client IP.
* **Existing mitigation:** HTTPS only, no downgrade redirects, at most 5 redirects, 10 s connect / 20 s
  total timeout, 5 MiB cap, 2,000 entries cap, per-entry isolation, fixed User-Agent, no cookies.
  The last good list survives failed refreshes. Refresh is manual only.
* **Additional mitigation:** strict field allowlists reject dangerous or unknown fields
  (`fields.rs`). Destination policy for the subscription URL, every redirect, and **every DNS
  answer** (`netpolicy.rs`, `subscription.rs GuardedResolver`). Server addresses in the body are also
  checked: no loopback, link-local or metadata, multicast or unspecified addresses.
* **Residual risk:** the provider decides which servers the user can pick (a trust decision by the
  user/company). It learns the client's public IP (or the tunnel's egress IP when refreshed while
  connected) and refresh times.

### 4. Compromised subscription URL (token leaked, or DNS/hosting hijacked)
* **Attack surface:** as attacker 3, plus an attacker-chosen body served at a trusted URL.
* **Existing/additional mitigation:** as for attacker 3. The URL (with its token) is stored encrypted,
  never shown in the UI (host only), and redacted from logs and errors (`log::redact`). HTTPS
  certificate validation uses the OS store (SChannel / Security.framework).
* **Residual risk:** a hijacked HTTPS origin with a valid certificate can serve hostile server
  lists. These are limited to the allowlisted configuration surface.

### 5. Malicious `vless://` URI
* **Attack surface:** userinfo, host, port, query parameters, fragment (name).
* **Possible impact:** config injection, path traversal, shell injection, SSRF to local services,
  UI injection through the name.
* **Mitigation:** strict percent-decoding (`vless.rs query_map`). Parameters are checked against
  `fields::VLESS_PARAMS`, and unknown or dangerous ones (e.g. `fm`) reject the link. Host must be a
  valid hostname/IP (IDNA via `url::Host`, label rules, `validate::address`) and pass the destination
  policy. Port 1–65535. UUID or 1–30-byte id. Each value has a validator: `http_path`,
  `grpc_service_name` and `spider_x` also reject `..`, backslashes, `//`, `file:`, drive letters and
  their %-encodings (`validate::no_path_tricks`). The fingerprint and ALPN come from fixed lists. Pins
  are 64-hex. ECH and mldsa65 use restricted alphabets. Names are free text but are only ever
  rendered with `textContent` and never reach the Xray config (`security_tests.rs`). **Nothing is
  passed to a shell**: the helper starts exactly one program (Xray) with fixed arguments.
* **Residual risk:** a well-formed link to an attacker-operated server (attacker 1). That is the
  user's choice of server.

### 6. Malicious `vmess://` URI
* **Attack surface:** base64(JSON) payload.
* **Mitigation:** lenient base64 decoding, JSON parsing (serde; recursion limit), key allowlist
  `fields::VMESS_KEYS` (unknown keys reject), then the same validators as VLESS. `alterId > 0`
  is imported as AEAD with a warning. Legacy MD5 auth is never enabled.
* **Residual risk:** as for attacker 5.

### 7. Malicious JSON configuration (pasted, file, subscription)
* **Attack surface:** full Xray configs, single outbounds, arrays. Any key at any depth.
* **Possible impact** (if it were forwarded): `tlsSettings.masterKeyLog` writes TLS keys to any
  path. `certificates[].certificateFile/keyFile` reads local files. `sockopt` binds interfaces,
  sets marks or chains through `dialerProxy`. `sendThrough` binds a local address. `proxySettings`
  chains outbounds. `targetStrategy` causes local DNS. VLESS `reverse` exposes local services.
  `inbounds` could listen on `0.0.0.0`, and `api` would expose a control plane.
* **Mitigation:** **imported JSON is never forwarded.** Only VLESS/VMess outbounds are read, and
  every object's keys are checked against a table taken from the Xray v26.3.27 source
  (`fields.rs`). Dangerous keys (the list above) and unknown keys **reject the entry**. Known
  harmless keys are dropped with a warning. Top-level sections other than `outbounds` are never
  read, and unknown sections reject the config. The XHTTP `extra` object is rebuilt from an
  allowlist, and its nested `downloadSettings` is rebuilt field by field
  (`validate::sanitize_xhttp_extra`). The Xray config is **regenerated** by `xrayconf.rs` from the
  typed model. Every generated config is additionally validated by `xray run -test` before use.
* **Residual risk:** a new Xray field that our allowlist does not know rejects the entry rather
  than working. That is deliberate. Updating Xray requires reviewing `fields.rs` (see development.md).

### 8. Malicious QR code
* **Attack surface:** decoded QR text, image decoding (jsQR, in the extension).
* **Mitigation:** decoded locally in the popup (no network). The payload is accepted only if it is a
  VLESS/VMess link, JSON, or base64 of links (`parse_qr_payload`). URLs, Wi-Fi or vCard payloads are
  refused and **never opened**. Then the full import pipeline applies. "Scan current tab" uses
  `activeTab` (only on the user's click), and the screenshot is not stored. jsQR runs under the
  extension CSP (no eval).
* **Residual risk:** a bug in jsQR's image decoding could only affect the popup page, which holds no
  secrets (the extension never receives credentials).

### 9. Malicious website opened in the browser
* **Attack surface:** page JavaScript, navigation, WebRTC, requests to `localhost`.
* **Possible impact:** messaging the extension or helper, reading extension resources, using the
  IDE proxy as a relay or causing a proxy loop, learning the real IP through WebRTC.
* **Mitigation:** no content scripts, no `externally_connectable`, and no web-accessible resources. The
  service worker accepts messages only from its own pages (`fromOwnPage`). The helper is reachable
  only through native messaging from the pinned extension. A self-loop through our own inbound ports
  is blocked by a routing rule. Chromium's Private Network Access limits public-site requests
  to loopback. **WebRTC protection is on by default** (`webRTCIPHandlingPolicy =
  disable_non_proxied_udp` while connected). E2E checks this.
* **Residual risk:** proxied web content is subject to normal browser security. Sites see the proxy
  server's IP, and WebRTC can use TCP through the proxy (by design). If the user disables WebRTC
  protection, UDP may reveal the real IP.

### 10. Another malicious browser extension
* **Attack surface:** `chrome.runtime.sendMessage/connect` to our ID, `connectNative` to our host,
  `chrome.proxy` (proxy takeover), and the ability to spoof our extension ID.
* **Mitigation:** there are no external message handlers; messages from other extensions never
  reach our listeners. The host manifest `allowed_origins` lists only our pinned ID. The browser
  refuses others ("Access to the specified native messaging host is forbidden", E2E), and the helper
  re-checks `argv[1]` and exits with code 3. **Proxy takeover:** `chrome.proxy.settings.onChange` is
  monitored. If our setting is no longer in effect, the tunnel is disconnected and the popup says so,
  and it never keeps showing "Connected" (E2E: real takeover by a second extension).
* **Residual risk (identity):** an **unpacked** extension's ID is derived from the public key in its
  manifest, which is not secret. A malicious extension that the user loads unpacked in Developer
  mode could reuse our key, obtain our ID, and then talk to the native host. Packed/CRX and
  policy-installed extensions are signature-bound to the ID, so this does not apply there.
  **Company mitigation:** distribute the extension as a policy force-installed CRX and disable
  Developer mode by policy (`ExtensionDeveloperModeSettings`, `ExtensionInstallBlocklist: *` +
  allowlist). The helper still exposes only the typed command set.

### 11. Local unprivileged process
* **Attack surface:** the loopback listeners (browser SOCKS on an ephemeral port while connected;
  IDE HTTP 10809 and SOCKS 10808 while the browser runs); files in the data and install directories;
  the helper's stdio (not reachable: an anonymous pipe owned by the browser).
* **Possible impact:** using the tunnel (egress through the company's proxy server), reading stored
  credentials, replacing binaries.
* **Mitigation:** listeners bind `127.0.0.1` only and never the LAN (asserted in generated-config tests and by
  runtime socket enumeration). There is no control API on any socket. The data directory has a
  protected DACL (user + SYSTEM) and a no-read-up label (Windows) or 0700 (macOS). Secrets are
  encrypted with a key in Credential Manager/Keychain. The install directory has a private ACL, and
  the macOS `.pkg` installs root-owned binaries.
* **Residual risk:** the proxy listeners are **unauthenticated**. Any local process, including
  processes of other users on a shared machine, can use them while they exist. Chrome cannot pass
  SOCKS credentials. On multi-user machines (terminal servers), disable the IDE endpoint. Processes
  of the **same user** are out of scope: they can read the user's keychain, the browser's memory,
  and so on.

### 12. Compromised or outdated Xray binary
* **Attack surface:** the executable the helper launches.
* **Mitigation:** official GitHub release artifacts only. The zip SHA-256 is pinned and matched against
  upstream `.dgst` (build time, `scripts/fetch-xray.mjs`). The **extracted binary's SHA-256** is pinned
  per platform and compiled into the helper (`build.rs`). The helper **verifies it before every launch**
  while holding a deny-write handle (`xray::verify`), refuses anything else, and never searches PATH.
  The installer installs only the pinned binary. Release builds ignore the `PRIVATE_PROXY_XRAY`
  override. Updates are manual: a maintainer bumps the version and hashes, and nothing is downloaded at
  runtime. The binary runs isolated (attacker 1).
* **Residual risk:** vulnerabilities in the pinned Xray version until the maintainers update it.
  Watch Xray-core security releases.

### 13. Supply-chain compromise of dependencies
* **Attack surface:** crates (171 in `Cargo.lock`), npm packages (1 runtime: jsQR; dev: build and
  test tools), Xray, toolchains.
* **Mitigation:** lockfiles, with CI and packaging using `--locked` and `npm ci`. `cargo audit`
  and `npm audit` show 0 advisories (2026-09-21). There are few direct dependencies from established
  maintainers (RustCrypto, serde, reqwest, keyring). TLS comes from the OS, not a bundled OpenSSL.
  npm lifecycle scripts are not auto-approved (npm's script approval). No code is downloaded at
  runtime, and the extension has no remote code (CSP `script-src 'self'`). Inventory:
  [dependencies.md](dependencies.md).
* **Residual risk:** a malicious update of a pinned dependency can only enter through a deliberate
  lockfile change, so review lockfile diffs. Toolchains (rustc, Node, esbuild) are trusted build inputs.

## What a proxy operator can observe

A VLESS/VMess server operator (or anyone controlling that server) **can** observe:
* the client's public IP address and when and how long it is connected (the VLESS/VMess user ID identifies the user);
* every destination hostname or IP and port (the browser sends hostnames; the server resolves them),
  hence the sites visited, and all DNS lookups for proxied traffic;
* for HTTPS: the TLS SNI (unless the site uses ECH), certificate exchange metadata, and traffic volume and timing;
* for plain HTTP: full request and response content, which it can also modify;
* traffic from JetBrains IDEs and any other app pointed at the IDE endpoint.

It **cannot**, through this product: read HTTPS content without a browser certificate error, open
connections into the client (no reverse proxy, no inbound listener reachable from it), access
files, extension storage, the OS keychain or the helper's control interface, or run commands
on the client. On Windows this still holds if it exploits Xray, subject to the OS's
Low-integrity boundary.

## Process isolation evaluation

| Mechanism | Helper | Xray | Decision |
|---|---|---|---|
| Runs as normal user, never admin/root | yes | yes | **Applied.** Install is per-user without elevation; the macOS `.pkg` elevates only during installation (postinstall registers as the console user via `sudo -u`) |
| Low integrity token (Windows) | no: needs Credential Manager and the data dir | **yes** | **Applied** to Xray. The helper stays Medium (CredRead and data-dir writes need it) |
| Job object | n/a | kill-on-close, active processes = 1, die on unhandled exception, 2 GiB memory, UI restrictions | **Applied**, assigned while suspended |
| Child process policy (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) | no | **yes** | **Applied.** Required `DETACHED_PROCESS` instead of `CREATE_NO_WINDOW` (a console conhost would be blocked) |
| Mitigation policies: extension points off, no remote or low-label images, prefer System32, font loading off, heap terminate, forced ASLR | image/extension-point subset | **full set** | **Applied** |
| Arbitrary Code Guard / dynamic code prohibited | evaluated | evaluated | **Not applied**: endpoint-security (EDR/AV) products on company machines inject hooks that need dynamic code; enforcing ACG risks crashes on exactly the target machines |
| Microsoft-signed-only images, Win32k lockdown | evaluated | evaluated | **Not applied**: same EDR compatibility concern (vendor-signed DLL injection) |
| Safe DLL loading | `DependentLoadFlags=System32` + `SetDefaultDllDirectories` | prefer-System32 policy (Go loads System32 DLLs by absolute path) | **Applied**; a planted-DLL test proves the V1 build was affected and the current one is not |
| Restrictive ACLs | data dir: user + SYSTEM, no-read-up label; install dir: user + SYSTEM + Administrators | — | **Applied** |
| Environment | — | cleared (`SystemRoot` only) | **Applied** |
| macOS App Sandbox / `sandbox-exec` for Xray | evaluated | evaluated | **Not applied in V1**: `sandbox-exec` is deprecated, and without a Mac to validate network, loopback-listen and Keychain behaviour it would be an untested mechanism. Recommended as the first macOS hardening item |
| macOS hardened runtime + Developer ID signing + notarization | — | — | **Documented, not performed** (needs certificates; see installation.md) |
| Core dumps disabled, `umask 077` (Unix) | yes | inherited | **Applied** |

## Filesystem

* Data: `%LOCALAPPDATA%\PrivateProxy` / `~/Library/Application Support/PrivateProxy` (+ `~/Library/Logs/PrivateProxy`).
  Contents: `state.json`, `secrets.bin` (encrypted), `store.lock`, `logs/` and Unix PID files. No generated
  Xray config is ever written to disk (it goes over stdin).
* All paths are fixed by the helper. No command takes a path, and IDs must be UUIDs. Release builds ignore the
  `PRIVATE_PROXY_DATA_DIR` override. Remote input never names a file.
* Links: the helper refuses a data or log directory that is a symlink or junction (checked before anything is
  created), temp files are created fresh (`create_new`), and uninstall/purge removes links without following them.
* Windows ACL of the data dir: `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)S:(ML;OICI;NRNWNX;;;ME)`.

## SSRF and internal destinations

| Destination class | Subscription / control-plane URLs | Proxy server address |
|---|---|---|
| Public | allowed | allowed |
| Private (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, single-label names, `.internal/.local/.lan/.corp/...`) | **blocked by default**; allowed with Settings → "Allow private-network subscription URLs" | **allowed** (company-hosted servers must work) |
| Loopback (127/8, ::1, `localhost`, mapped/NAT64 forms, decimal/hex encodings) | blocked | blocked |
| Link-local incl. cloud metadata (169.254/16, fe80::/10, fd00:ec2::254, `metadata.google.internal`) | blocked | blocked |
| Unspecified, multicast, broadcast, reserved | blocked | blocked |

Subscription checks apply to the URL host, every redirect target, and, for direct fetches, every DNS answer
(DNS rebinding: `localtest.me` → 127.0.0.1 is refused, tested). When fetched through the tunnel (`socks5h`),
the name is resolved by the proxy server, and only the name and literal checks apply locally.
Proxy server hostnames that *resolve* to loopback are resolved by Xray and are not re-checked. The impact is
limited to Xray sending a VLESS/VMess handshake to a local port (residual, low).

## Local listeners

See the table in [architecture.md](architecture.md#local-listeners). All are Xray TCP listeners on `127.0.0.1`.
The helper listens on nothing. There is no HTTP control server, no Xray API and no UDP listener.

## Corporate safety behaviour (fail-safe states)

| Situation | Browser traffic | UI |
|---|---|---|
| Connecting (starting/verifying) | direct (no proxy set yet) | "Connecting" |
| Connected (probe through the server succeeded) | through the tunnel | "Connected" |
| Xray crashes while connected | proxy kept on the same port, so requests **fail** (not direct) during ≤2 automatic restarts | "Connecting (restarting)" |
| Restarts exhausted / helper dies / browser crash | proxy **cleared → direct** | error with reason, never "Connected" |
| Another extension or policy takes over the proxy | whatever the other setting says; our tunnel is disconnected | "Browser proxy blocked", explanation |
| Server stops forwarding while Xray runs | requests fail (not direct) | stays "Connected" (no periodic probe in V1) |
| Private ranges / plain host names | always direct (bypass list, documented) | — |

There is no hidden fallback: the only path to direct networking is a visible state change. V1 has no kill switch,
so after a failure the browser goes direct *and says so*.
