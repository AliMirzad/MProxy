# Architecture

## Components

```
┌──────────────────────────── Chromium browser (Chrome / Brave / Chromium / Edge) ───────────────────────────┐
│  Popup (popup.html/js)  ──runtime messages──▶  Service worker (background.js)                              │
│   UI only, untrusted       (own pages only)      • owns the native port                                    │
│   data rendered as text                          • mirrors helper state into chrome.proxy                  │
│                                                  • command allow-list                                      │
└───────────────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                            │ native messaging (stdin/stdout, JSON)
                                                            ▼
                              private-proxy-host  (Rust, no UI, started by the browser)
                               • strict typed protocol       • encrypted server store (+ OS keychain key)
                               • import parsers/validators   • subscription fetcher
                               • Xray config generator       • connection state machine + process monitor
                                                            │ stdin (config) / Job Object / signals
                                                            ▼
                              xray (official Xray-core release, unmodified)
                               127.0.0.1:<ephemeral>  SOCKS5  ◀── browser (chrome.proxy fixed_servers)
                               127.0.0.1:10809        HTTP    ◀── JetBrains IDE (manual proxy setting)
                               127.0.0.1:10808        SOCKS5  ◀── JetBrains IDE (alternative)
                                                            │ VLESS / VMess over raw|ws|grpc|httpupgrade|xhttp + TLS|REALITY
                                                            ▼
                                                    remote server → Internet
```

Nothing else on the computer is touched. There is no system proxy, TUN, DNS change, service,
tray icon, login item or Dock icon.

## Repository layout

| Path | Contents |
|---|---|
| `extension/` | MV3 extension: `src/background` (service worker, controller), `src/popup` (UI, QR), `src/shared` (view model), `manifest/`, `tests/` (vitest unit tests, `e2e/` real-browser test) |
| `native/` | Rust helper: `src/parse` (importers), `validate.rs`, `xrayconf.rs`, `xray.rs` (process), `service.rs` (state machine), `store.rs`/`secrets.rs`, `install.rs`, `tests/integration.rs` |
| `native/xray/xray.lock.json` | Pinned Xray-core version + SHA-256 per platform |
| `shared/protocol/` | Protocol spec + TypeScript types. `shared/extension-id.txt` holds the pinned extension ID |
| `installers/` | Windows `Install.cmd`/`Uninstall.cmd`, macOS `install.sh`/`uninstall.sh`/`build-pkg.sh` |
| `scripts/` | build/test/package tooling (Node, no extra deps) |
| `docs/`, `LICENSES/` | Documentation, third-party licenses |

## Process lifetime

1. The browser starts → the service worker starts (`runtime.onStartup`) → it **clears** any
   proxy setting left over from before, then calls `connectNative`.
2. The browser starts `private-proxy-host chrome-extension://<id>/`. The helper checks the origin,
   opens the store, and (if the IDE passthrough is enabled) starts Xray in *direct* mode.
3. The open native port keeps the MV3 service worker alive (Chrome ≥ 105).
4. The browser exits or the extension reloads → the port closes → the helper reads EOF on stdin,
   kills Xray, and exits. On Windows, Xray is also inside a kill-on-close Job Object. On macOS
   there are signal handlers plus a PID file that the next helper start uses to reap orphans.

So the local proxy exists exactly as long as the browser runs. That is a deliberate trade-off
(TD-2): no separate background application.

## Connection state machine (helper)

```
DISCONNECTED ──connect──▶ CONNECTING(starting) ──Xray listening──▶ CONNECTING(verifying)
     ▲   ▲                    │ config rejected / Xray won't start       │ probe OK         │ probe fails
     │   │                    ▼                                          ▼                  ▼
     │   └──── disconnect ── ERROR(code) ◀── restarts exhausted ── CONNECTED     ERROR(SERVER_UNREACHABLE)
     │                                                                  │ Xray died (≤2 per 60 s)
     └──────── disconnect ◀── DISCONNECTING ◀── disconnect ──────        ▼
                                                                  CONNECTING(restarting) → CONNECTED (same port)
```

* **starting:** build the config, run `xray run -test` (Xray's own validation), spawn, and wait until
  the browser port accepts connections. A port collision retries once with a new port.
* **verifying:** an HTTP request through the local SOCKS5 inbound to
  `www.gstatic.com/generate_204` (fallback `cp.cloudflare.com`), with the hostname sent
  unresolved. **Connected is only reported after this succeeds**, so it proves the whole
  path through the selected server.
* Every step can be cancelled by `disconnect`. Results of stale attempts are ignored by
  comparing attempt numbers.
* A second `connect` for the active server is a no-op, and repeated `disconnect`s are no-ops.
* Switching servers restarts Xray with a new config.

## Browser proxy (extension)

The service worker mirrors the helper's status (see `controller.ts`):

| Helper state | Browser |
|---|---|
| `connected` + port | `chrome.proxy.settings.set(fixed_servers, socks5://127.0.0.1:port, bypass <local>/private ranges)` |
| `connecting/restarting` while already proxied | unchanged (same port) |
| anything else, helper exit, SW start | `chrome.proxy.settings.clear()` → direct |

After setting the proxy, `levelOfControl` is checked. If another extension or a policy
controls the proxy, the tunnel is disconnected and the popup says so, instead of claiming
"Connected".

**Failure policy (no kill switch):** if Xray dies and two restarts fail, if the helper dies, or if
the browser crashes, the browser falls back to **direct**. The popup shows the error. The browser
is never left pointing at a dead proxy.

## DNS

* Browser → SOCKS5 with **hostname** → Xray (`domainStrategy: AsIs`) → VLESS/VMess carries the
  hostname → the **server** resolves it.
* Routing rules only match IP literals (private ranges → direct) or `localhost`. Nothing
  forces a local lookup. No Xray `dns` block is configured, because none is needed.
* The only local DNS query is for the VPN server's own hostname, which is needed to dial it.
* IDE: the HTTP endpoint (`CONNECT host:port` / absolute URI) also carries hostnames.
* **Verified by tests.** `probe.test` is resolvable only through the test server's DNS config. The
  browser and IDE endpoint reach it only through the tunnel, and fail after disconnect (see
  `native/tests/integration.rs`, `extension/tests/e2e/browser.e2e.mjs`).
* Not covered by the proxy: WebRTC UDP. "Block WebRTC" is **on by default** and sets
  `webRTCIPHandlingPolicy = disable_non_proxied_udp` while connected (verified by E2E).

## Local listeners

Every listening socket the product creates (verified by socket enumeration in
`native/tests/integration.rs xray_isolation_and_listeners`: exactly these three, TCP only):

| Process | Protocol | Address | Port strategy | Purpose | Who can connect | Security boundary |
|---|---|---|---|---|---|---|
| Xray | SOCKS5 (TCP, UDP off) | 127.0.0.1 | ephemeral: an OS-assigned free port per connection | browser proxy | any local process (unauthenticated) while connected | loopback only; the tunnel is the only thing behind it |
| Xray | HTTP proxy (TCP) | 127.0.0.1 | 10809, configurable (≥1024) | JetBrains/IDE endpoint | any local process while the browser runs | loopback only; self-loop to our ports blocked |
| Xray | SOCKS5 (TCP, UDP off) | 127.0.0.1 | 10808, configurable (≥1024) | IDE endpoint (alternative) | same | same |
| Helper | — | — | none | control goes over the native-messaging stdio pipe from the browser | only the pinned extension | no socket at all |

There is no control API on any socket: no localhost HTTP server, no Xray `api`/`stats` inbound. The
helper binds `127.0.0.1:0` for a moment only to pick a free port and releases it.

**Manual verification** that nothing listens outside loopback while connected:

* Windows (PowerShell): `Get-NetTCPConnection -State Listen -OwningProcess (Get-Process xray).Id`
  and `Get-NetUDPEndpoint -OwningProcess (Get-Process xray).Id`. Every `LocalAddress` must be
  `127.0.0.1`, and there must be no UDP endpoints. `Get-NetTCPConnection -State Listen -OwningProcess (Get-Process private-proxy-host).Id` must return nothing.
* macOS: `lsof -nP -a -p $(pgrep -x xray) -iTCP -sTCP:LISTEN` (only `127.0.0.1:…`), `lsof -nP -a -p $(pgrep -x xray) -iUDP` (empty).
* From another machine on the LAN: `Test-NetConnection <laptop-ip> -Port 10809` / `nc -vz <laptop-ip> 10809` must fail.
* Popup → Settings → Copy diagnostics shows `xrayIsolation` (Windows: `integrity: low`) and `dataDirProtection`.

## Ports

| Endpoint | Port | Lifetime |
|---|---|---|
| Browser SOCKS5 | ephemeral, chosen per connection | while connected |
| IDE HTTP | 10809 (configurable) | while the browser runs (tunnel or direct passthrough) |
| IDE SOCKS5 | 10808 (configurable) | same |

Everything binds to `127.0.0.1` only. If an IDE port is busy (another program, or a second
browser running this product), the tunnel still works for the browser and the popup names the
busy port. Routing rules block requests aimed back at our own inbounds, which prevents
proxy self-loops (e.g. a page requesting `http://127.0.0.1:10809/`).

## Storage

| Data | Where | Protection |
|---|---|---|
| Server metadata, subscriptions (without URL), settings | `state.json` in the data dir | user-only directory (0700 on macOS, user profile ACL on Windows) |
| UUIDs, REALITY keys/short IDs, VLESS encryption, subscription URLs | `secrets.bin` | XChaCha20-Poly1305; 256-bit key in Credential Manager / Keychain |
| UI preferences (WebRTC toggle, default on) | `chrome.storage.local` | no secrets |
| Logs | `logs/helper.log` (+3 rotations of 512 KiB) | redacted; no browsing history unless verbose mode |

Data dir: `%LOCALAPPDATA%\PrivateProxy` (Windows), `~/Library/Application Support/PrivateProxy`
(macOS). Logs on macOS: `~/Library/Logs/PrivateProxy`. The store is shared by all browsers of the
same OS user. It uses a file lock and atomic writes.

## Import pipeline

```
text (paste / file / QR / subscription body)
  → format detection (JSON? base64? link list?)
  → per-entry parser (vless:// | vmess:// | Xray JSON outbound)   ← errors isolated per entry
  → StreamParams → transport + security builders (validate.rs)
  → cross-field validation (REALITY transports, Vision requirements, …)
  → ParsedServer { meta, secrets, warnings }
  → store merge (dedupe by protocol+address+port+user+transport; subscriptions update in place)
```

Supported: VLESS and VMess over raw/TCP (incl. HTTP header), WebSocket, gRPC (gun/multi),
HTTPUpgrade, XHTTP/SplitHTTP (with a sanitized `extra`), security none/TLS (SNI, ALPN,
fingerprint, certificate pinning, ECH)/REALITY (incl. Vision, spiderX, ML-DSA-65 verify), and VLESS
Encryption. Rejected with a clear message: HTTP/2 (`h2`) and QUIC (removed from Xray-core), mKCP, and
non-VLESS/VMess protocols.
Adding a transport means adding a `Transport` variant, a parse arm in `stream.rs`, and a generator arm in
`xrayconf.rs`.

## Process isolation (summary)

* The helper runs as the user (Windows: Medium integrity). DLL search is restricted to System32, and extension
  points and remote/low-label images are disabled. It has no sockets.
* Xray (Windows) is started suspended with a **Low-integrity** token, creation-time mitigation policies,
  child-process creation blocked, an explicit handle list and a minimal environment. It is assigned to a restricted
  kill-on-close job before it runs. Its binary must match the pinned SHA-256.
* macOS: Xray runs as the user with a cleared environment. OS sandboxing is not implemented yet
  ([threat-model.md](threat-model.md#process-isolation-evaluation)).
