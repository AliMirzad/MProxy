# Validation status and checklists

## What was validated in the development environment (2026-09-21)

Environment: **Windows 11 Pro x64** only. Browsers used: Brave 1.95 (Chromium 153) for automation. Google
Chrome is installed but ignores `--load-extension` in branded builds ≥ 137, so it was not automated. No
macOS machine and **no real VLESS/VMess server** were available. The "remote server" in every test below is
a second, local Xray process configured as a VLESS/VMess server.

| Test layer | Result |
|---|---|
| Native unit tests (parsers, validation, config generation, store/secrets, framing, protocol, redaction) | **53/53 pass** |
| Native integration tests against real Xray v26.3.27 (see list below) | **5/5 pass**, repeated 7× incl. parallel stress runs. One earlier run under heavy CPU load (a concurrent cargo build) saw a single HTTP 503 from the IDE endpoint right after a server switch. Not reproducible afterwards; noted as a watch item |
| Extension unit tests (controller, view model, QR round-trip) + `tsc --noEmit` | **30/30 pass**, typecheck clean |
| Real-browser E2E (Brave, Windows, real installer, real Credential Manager) | **24/24 checks pass**, with debug and release helper |
| macOS: `cargo check --all-targets` for `aarch64-apple-darwin` and `x86_64-apple-darwin` | compiles, zero warnings (**not run**) |
| `cargo clippy -D warnings` | clean |
| `cargo audit` / `npm audit` | 0 vulnerabilities |

Integration coverage (native ↔ Xray ↔ Xray server): VLESS raw, VLESS WS, VLESS gRPC, VLESS HTTPUpgrade,
VLESS XHTTP, VMess WS, VMess raw, **VLESS WS + TLS with certificate pinning**, **VLESS REALITY + XTLS
Vision**. Each goes through the browser SOCKS port, the IDE HTTP port and the IDE SOCKS port, with remote
DNS asserted (`probe.test` is resolvable only on the server). Failure coverage: wrong UUID, dead server, Xray
missing, config rejected by `xray -test`, occupied IDE port, Xray killed (restart on the same port), repeated
crashes (→ `XRAY_FAILED`), repeated Connect/Disconnect clicks, stdin closed during startup (no orphan),
malformed/unknown/hostile messages, and proxy self-loop. Subscriptions: add, update (add/update/remove),
provider HTTP 500, HTML body, non-HTTPS, delete with servers, plus timeout and size-limit unit tests.

E2E checks (Brave): installer registers → pinned extension ID loads → native hello → starts direct → IDE
passthrough listening → import 4 servers through the popup UI → names shown, no UUID in UI → `probe.test`
unreachable before connecting → unreachable server shows "Server unreachable" and the browser stays direct →
browsing through REALITY, VLESS-WS and VMess-WS (remote DNS) → `chrome.proxy` is loopback SOCKS5 and controlled
by this extension → badge ON → IDE HTTP endpoint tunnels → Xray killed → auto-restart, still browsing →
disconnect restores direct (`mode: system`) → `probe.test` unreachable → IDE endpoint direct and not tunnelled
→ closing the browser closes helper + Xray (ports closed) → restarting the browser leaves no stale proxy →
uninstall --purge.

## What still requires real-world validation

| Item | Why it could not be validated here |
|---|---|
| **Any real VLESS/VMess server** (REALITY against a real target site, TLS with a public CA cert, CDN-fronted WS/XHTTP, gRPC through a reverse proxy) | No server or credentials were provided. The tests use a local Xray server, which exercises the same protocol code in Xray but not real networks, CDNs or censorship conditions |
| **Public IP change** in the browser | Needs a real remote server |
| **Everything on macOS** (build, Keychain storage and prompts, `install.sh`, `.pkg`, Gatekeeper/quarantine, signal handling and orphan reaping, NativeMessagingHosts paths for Chrome/Brave/Chromium/Edge) | No Mac available. The code compiles for both macOS architectures, and CI (`.github/workflows/build.yml`) builds, tests and packages on macOS runners, but that workflow has not been run yet |
| **Google Chrome (Windows)** interactive use | Automation cannot load unpacked extensions into branded Chrome ≥ 137. The same registry key and APIs were exercised via Brave; a manual run is needed |
| Brave reading only its own registry key vs. Chrome's | Both keys are written. Brave worked, but it was not isolated which key it used |
| **Edge**, Vivaldi | Registered but not tested |
| **IntelliJ IDEA** "Check connection" and real IDE traffic | No IDE automation. The endpoint was tested with raw HTTP-proxy and SOCKS5 clients |
| Windows SmartScreen / antivirus behaviour for unsigned builds | Needs a clean machine and the packaged zip downloaded from a URL (Mark of the Web) |
| Long-running stability (sleep/resume, network changes, hours of use) | Not feasible in this session |
| Windows on ARM | Xray arm64 is pinned; the helper was not built for arm64 |

## Manual end-to-end checklist

Run for each combination: **Chrome + Windows, Brave + Windows, Chrome + macOS, Brave + macOS**.
Use a real server. Do at least one run with a VLESS REALITY link and one with a VMess link.

| # | Step | Expected |
|---|---|---|
| 1 | Install the runtime (Install.cmd / install.sh) | Success message lists the browser. `private-proxy-host status` shows it registered |
| 2 | Load the extension unpacked | ID `pmagpgfembejahekgbdifepphmaigngl`. Popup shows **Disconnected** (not "Native runtime missing") |
| 3 | Import a valid VLESS link (+ Import → paste) | "Imported: 1 new". The server appears with the protocol line (e.g. VLESS · REALITY · TCP · Vision) |
| 3b | Import the same server from a QR image, a subscription URL and a JSON file | Imports work; re-importing updates instead of duplicating |
| 4 | Select the server → **Connect** | Connecting → Connected within a few seconds. Badge ON |
| 5 | Open <https://ifconfig.me> (or similar) | Shows the **server's** IP, not yours |
| 6 | DNS: DNS-leak test site, and/or `chrome://net-export` (see troubleshooting.md) | Resolvers belong to the server side. No local DNS jobs for proxied hosts |
| 6b | `chrome://net-internals/#proxy` | Effective proxy `http://127.0.0.1:<port>` (authenticated; protocol v3) |
| 7 | **Disconnect** | Disconnected. Badge cleared |
| 8 | Reload ifconfig.me | Your own IP again. `chrome://net-internals/#proxy` shows direct/system |
| 9 | Configure IntelliJ (docs/jetbrains.md), HTTP 127.0.0.1:10809 | — |
| 10 | Connect, then IntelliJ → HTTP Proxy → **Check connection** with `https://ifconfig.me/ip` | Succeeds, shows the server IP. Disconnect → still succeeds (direct), shows your IP |
| 11 | With the tunnel connected, check another app (e.g. `curl https://ifconfig.me` in a terminal without proxy variables, or another browser) | Shows **your own** IP. The OS proxy settings are unchanged |
| 12 | VMess link: repeat 3–8 | Same results |
| 13 | Failure: kill `xray` in Task Manager / Activity Monitor while connected | Popup flips to Connecting (restarting) and back to Connected. After 3 kills within a minute: "Xray failed", browser direct |
| 14 | Failure: quit the browser while connected, start it again | Starts **direct**, popup Disconnected, no `xray`/`private-proxy-host` processes left in between |
| 15 | Uninstall (Apps / uninstall.sh) | Registration gone. Popup shows "Native runtime missing". Servers kept unless purge was chosen |

Record OS version, browser version, runtime/Xray versions (Settings → About) and results for each run.
