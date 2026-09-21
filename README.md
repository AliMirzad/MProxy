# Private Proxy

A private/internal VLESS/VMess proxy client for Chromium browsers, powered by
[Xray-core](https://github.com/XTLS/Xray-core) and controlled entirely from a browser extension.

* Import `vless://` / `vmess://` links, Xray JSON, QR codes or subscription URLs.
* Pick a server, click **Connect**: the browser is routed through Xray, and DNS is resolved on the server side.
* **Disconnect:** the browser returns to direct networking.
* A stable local endpoint (`127.0.0.1:10809` HTTP / `:10808` SOCKS5) for JetBrains IDEs, which keeps
  working (direct) while disconnected.
* No system-wide VPN, no TUN, no system proxy or DNS changes, no tray/desktop app, no accounts, no
  telemetry. Other applications are unaffected.

Targets: **Windows** and **macOS**; **Chrome, Brave, Chromium** (Edge/Vivaldi registered, untested).

> Status: V1. Validated on Windows 11 + Brave with real Xray against a local Xray server. macOS and
> real-server validation are still pending. See [docs/validation.md](docs/validation.md).

## How it works

```
Popup ─▶ Service worker ──native messaging──▶ private-proxy-host (Rust) ──stdin config──▶ xray
          │ chrome.proxy                                                                 │ 127.0.0.1 SOCKS5 (browser, random port)
          ▼                                                                              │ 127.0.0.1 HTTP 10809 / SOCKS5 10808 (IDE)
       Browser ─────────────────── socks5://127.0.0.1:<port> ─────────────────────────────▶ VLESS / VMess ─▶ server ─▶ Internet
```

* The **extension** (MV3; permissions `proxy`, `storage`, `nativeMessaging`, `activeTab`, `privacy` for WebRTC protection)
  is the only UI.
* The **native helper** has no UI. The browser starts it and it exits with the browser. It parses and validates
  imports, stores servers (credentials encrypted with a key held in Windows Credential Manager / macOS Keychain),
  generates the Xray config, runs Xray, verifies the connection end to end, and restarts Xray if it crashes.
* **Xray-core** (official release, pinned by SHA-256) does all protocol work: VLESS, VMess, REALITY, TLS, XHTTP…

Details: [docs/architecture.md](docs/architecture.md) · decisions and verified assumptions:
[docs/technical-decisions.md](docs/technical-decisions.md) · protocol: [shared/protocol/PROTOCOL.md](shared/protocol/PROTOCOL.md)

## Supported configurations

| | Supported |
|---|---|
| Protocols | VLESS (incl. XTLS Vision flow, VLESS Encryption), VMess (AEAD) |
| Transports | TCP/raw (incl. HTTP header), WebSocket, gRPC (gun/multi), HTTPUpgrade, XHTTP/SplitHTTP |
| Security | none, TLS (SNI, ALPN, uTLS fingerprint, certificate pinning `pcs`, ECH), REALITY (incl. spiderX, ML-DSA-65) |
| Import | share links, v2rayN VMess links, Xray/V2Ray JSON (full config, outbound, arrays), base64/plain subscription, QR (file, paste, current tab) |
| Not supported | HTTP/2 (`h2`) and QUIC transports (removed from Xray-core, so use XHTTP), mKCP, Shadowsocks/Trojan/Hysteria (skipped on import), `allowInsecure` (removed from Xray; imported with verification on) |

## Requirements

* **Users:** Windows 10/11 or macOS 12+, and Chrome, Brave or Chromium (version 110 or newer).
* **Developers:** Node.js ≥ 20, Rust stable, and a platform linker (Visual Studio Build Tools *or* llvm-mingw on
  Windows; Xcode CLT on macOS). See [docs/development.md](docs/development.md).

## Development setup

```bash
npm run setup          # extension deps + pinned Xray (SHA-256 verified)
npm run build          # helper (debug) + extension -> extension/dist
npm run runtime:install  # register your local build as the per-user runtime
npm test               # native unit+integration tests, extension typecheck+tests
```
Then load `extension/dist` unpacked (below). Other commands: `npm run dev` (watch), `npm run test:e2e`
(real browser), `npm run lint`, `npm run package`.

## Building

```bash
npm run build:release   # release helper + minified extension
npm run package         # tests + dist/PrivateProxy-extension-<v>.zip + runtime package for this OS
```
The helper links OS frameworks, so build Windows packages on Windows and macOS packages on macOS (arm64 and x64).
`.github/workflows/build.yml` does all three in CI. On macOS, `npm run package -- --pkg` also builds a `.pkg`.

## Installing the native runtime

* **Windows:** extract `PrivateProxy-runtime-windows-x64-<v>.zip` and double-click **Install.cmd** (per user, no admin).
* **macOS:** extract the tarball and run `./install.sh` (per user, no sudo; start your browsers once first).

This registers the native messaging host for Chrome, Chromium, Brave and Edge. Full details, the registry keys and
paths, the `.pkg`, and signing/notarization are in [docs/installation.md](docs/installation.md).

## Loading the extension

1. Extract `PrivateProxy-extension-<v>.zip` to a permanent folder (or use `extension/dist` when developing).
2. `chrome://extensions` (or `brave://extensions`) → enable **Developer mode** → **Load unpacked** → select the folder.
3. Confirm the ID is `pmagpgfembejahekgbdifepphmaigngl` and pin the extension.

## Importing a server

Popup → **+ Import**:
* **Link / JSON:** paste one or more `vless://`/`vmess://` links, a subscription body, or Xray JSON (or open a `.json` file).
* **QR code:** choose an image, paste one (Ctrl/⌘+V), or **Scan current tab**. Decoding is local, and URLs in QR codes are never opened.
* **Subscription:** name + HTTPS URL. It is fetched immediately; refresh later in Settings → Subscriptions → **Update** (manual only).

Per-entry errors are listed. Other entries still import. Servers can be renamed or deleted from the list.

## Connecting

Select a server → **Connect**. The popup shows *Connecting* (starting Xray, then verifying through the server)
and switches to **Connected** only after a real request through the server succeeded. **Disconnect** returns the
browser to direct networking. Picking another server while connected switches to it.

If the tunnel fails (server down, Xray crash that doesn't recover, runtime exits, browser crash), the browser goes
**direct** and the popup explains why. V1 intentionally has no kill switch.

## IntelliJ / JetBrains setup

Settings → Appearance & Behavior → System Settings → HTTP Proxy → Manual → **HTTP**, `127.0.0.1`, `10809` → Check
connection. Git, Gradle, Maven, npm, Docker and terminals have their own proxy settings. See
[docs/jetbrains.md](docs/jetbrains.md).

## Windows notes

* Installs to `%LOCALAPPDATA%\Programs\PrivateProxy`. Data is in `%LOCALAPPDATA%\PrivateProxy`, and the data key is in
  Credential Manager ("com.privateproxy.host").
* Xray runs hidden (no console window) inside a Job Object, so it cannot outlive the helper.
* Unsigned V1 builds may trigger SmartScreen. Uninstall via Settings → Apps.

## macOS notes

* Per-user install to `~/Library/Application Support/PrivateProxy/runtime`. Logs are in `~/Library/Logs/PrivateProxy`, and
  the data key is in the login Keychain.
* No Dock icon, menu bar item or login item. `install.sh` removes the quarantine attribute, since unsigned builds are
  otherwise blocked by Gatekeeper. Signing/notarization steps are in docs/installation.md.
* **Not yet validated on a real Mac** (compiles; CI provided).

## Security considerations

* Native messaging is restricted to the pinned extension ID. The helper accepts only a closed, typed command
  set, and there is no exec or file-path access from the extension.
* Imported configs are never executed. They are normalized and the Xray config is regenerated (dangerous fields
  such as `masterKeyLog`/`sockopt` cannot get in). Xray gets its config over stdin: no temp files, and no secrets in
  the process arguments.
* Credentials are encrypted at rest (XChaCha20-Poly1305, key in the OS keychain) and never sent to the extension UI.
  Logs are redacted and there is no browsing history.
* Everything listens on `127.0.0.1` only. The local endpoints are unauthenticated: any local process can use them
  while the browser runs. That is acceptable on single-user machines; disable the IDE endpoint on shared ones.
* Imported configurations are data: strict field allowlists, and unknown or dangerous fields are rejected.
  Loopback, cloud-metadata and (by default) private-network destinations are refused for subscriptions.
* Windows: Xray runs at Low integrity in a restricted job without the ability to start programs, and its binary is
  hash-verified before every launch.
* Full review: [docs/security.md](docs/security.md), [threat model](docs/threat-model.md),
  [security gate](docs/security-gate.md) (Windows: pilot-ready with conditions; macOS: not yet validated).

## Known limitations

* The proxy (including the IDE endpoint) exists only while the browser is running.
* Only one browser at a time can own the IDE ports. Browser tunnels work in several browsers at once.
* Private IP ranges and plain host names always go direct (no intranet-through-VPN in V1).
* WebRTC protection is on by default. If the user disables it, WebRTC can reveal the real IP. UDP is not proxied.
* No automatic server selection, no scheduled subscription refresh, no auto-update, no kill switch (by design).
* Branded Chrome ≥ 137 cannot be automated with `--load-extension`, so E2E automation uses Brave/Chromium.
* macOS, Chrome-specific and real-server behaviour still need validation ([docs/validation.md](docs/validation.md)).

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md). The popup's status line and **Settings → Copy diagnostics**
are the first stops. The helper log is `%LOCALAPPDATA%\PrivateProxy\logs\helper.log` /
`~/Library/Logs/PrivateProxy/helper.log`.

## Licenses

Third-party components and their licenses: [LICENSES/THIRD-PARTY.md](LICENSES/THIRD-PARTY.md). Xray-core (MPL-2.0)
is shipped unmodified. jsQR is Apache-2.0. The project's own license is up to its owner.
