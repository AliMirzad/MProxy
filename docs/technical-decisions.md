# Technical Decisions (Phase 0)

This file records the major decisions and the assumptions behind them, as verified on
2026-09-21. The *source of truth* for Xray behaviour is the pinned binary itself
(`native/xray/xray.lock.json`, currently **Xray-core v26.3.27**, the latest non-prerelease),
checked with `xray run -test`.

## TD-1 Native helper language: Rust

| Criterion | Rust | Go |
|---|---|---|
| Self-contained binary, no runtime | yes (~3–5 MB) | yes (~8–10 MB) |
| Process management (Job Objects, signals) | `windows-sys`, `libc` | good |
| OS secret stores | `keyring` (Credential Manager / Keychain) | `go-keyring` |
| Toolchain available in this dev environment | **yes** (1.97) | no |

Rust was chosen: smaller binaries, strong typing for the untrusted-input parsers (URI/JSON/
subscription), and it was the toolchain available for building *and testing* here.
All parsing happens in the helper, so a single implementation serves every browser.

## TD-2 Extension ↔ helper: one long-lived `connectNative` port

* The MV3 service worker opens `chrome.runtime.connectNative("com.privateproxy.host")`.
  Since Chrome 105 an open native-messaging port keeps the service worker alive, so the
  port (and therefore the helper and Xray) lives as long as the browser profile runs.
* When the port closes (browser exits, extension reloads, crash), the helper sees EOF on
  stdin, kills Xray, and exits. **No orphaned processes.** On Windows Xray is additionally
  placed in a Job Object with `KILL_ON_JOB_CLOSE`, so it dies even if the helper is killed.
  On macOS a PID file lets the next helper start reap a stray Xray left by a `SIGKILL`.
* Consequence: the local proxy (including the JetBrains endpoint) is available while the
  browser is running. This is intentional: the product has no background app of its own.
* Chrome passes the caller origin as `argv[1]`; the helper checks it against the allow-list
  baked in at install time (defence in depth; Chrome already enforces `allowed_origins`).
* Size limits: messages to the helper ≤ 64 MiB, messages from the helper ≤ 1 MB (Chrome
  limits). The helper caps inbound messages at 8 MiB (imports are limited to 5 MiB of text) and never sends anything near 1 MB.

## TD-3 Xray process model

* Config is passed on **stdin** (`xray run -c stdin: -format json`), so credentials never
  touch disk in plaintext and never appear in process arguments (verified with v26.3.27).
* Every generated config is first checked with `xray run -test -c stdin:`.
* The helper does not run imported JSON. Imports are parsed into a normalized model, and the
  config is **regenerated** from an allow-list of fields.
* Two runtime modes:
  * **Tunnel**: browser SOCKS inbound on a fresh loopback port, plus the stable JetBrains
    SOCKS/HTTP inbounds → selected VLESS/VMess outbound. Private/loopback IP literals → direct.
  * **Passthrough** (optional, on by default): only the JetBrains inbounds → `freedom`. This
    keeps IntelliJ working when the tunnel is disconnected, without any system proxy. The browser
    is set to *direct* in this mode; only apps explicitly configured with the endpoint use it.
* Unexpected exit while connected: up to 2 automatic restarts in 60 s on the same port
  (the browser proxy stays valid). If that fails, the state becomes `ERROR/XRAY_FAILED` and the
  extension **clears the browser proxy** (fail-open to direct, as there is no kill switch).

## TD-4 Verified Xray facts (v26.3.27)

| Topic | Finding (verified with `xray run -test`) | Consequence |
|---|---|---|
| `streamSettings.network` | `raw`/`tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`/`splithttp` accepted | generator uses `network` |
| HTTP/2 transport (`h2`/`http`) | **removed** – "migrated to XHTTP" | imports with `type=h2/http` are rejected with a clear message |
| QUIC transport | **removed** | rejected |
| ws, grpc, httpupgrade | accepted with deprecation warning | supported |
| `tlsSettings.allowInsecure` | **removed** – use `pinnedPeerCertSha256` | `allowInsecure=1` links are imported *without* it; `pcs`/pin is honoured |
| REALITY client key | `password` (new name) and `publicKey` both accepted | generator emits `password` |
| REALITY transports | raw, xhttp, grpc only | validated |
| VLESS + `security=none` | "can connect only to private network addresses" unless VLESS Encryption is enabled | warned in validation |
| VMess `alterId > 0` | legacy MD5 auth removed years ago | imported as AEAD (alterId ignored) with a note |

The upstream docs (Xray-docs-next, Sept 2026) describe a newer `streamSettings.method` key
used by prereleases. v26.3.27 does **not** recognise it: it silently ignores it and falls back to raw.
We therefore pin the release and generate `network`.

## TD-5 Browser proxy

* `chrome.proxy.settings.set({scope:"regular", value:{mode:"fixed_servers", rules:{singleProxy:{scheme:"http",host:"127.0.0.1",port}, bypassList:["<local>", ...private ranges]}}})`.
* Protocol v3: the inbound is an **authenticated HTTP proxy** with per-connection random credentials, answered in
  `webRequest.onAuthRequired` (needs `webRequest`, `webRequestAuthProvider` and `<all_urls>` host permissions; the CSP still
  forbids contacting any origin). Chromium cannot send SOCKS credentials, so the former SOCKS5 inbound was usable by every
  local process and user (adversarial review F5).
* An HTTP proxy receives hostnames unresolved (`CONNECT host:443`, absolute-form URIs), so there is no local DNS for proxied requests.
* `regular`-scope settings **persist across browser restarts**. The service worker therefore
  clears the setting on `runtime.onStartup`/`onInstalled` and whenever the helper is not connected.
  This guarantees no stale proxy.
* If `levelOfControl` shows another extension controls the proxy, we report it instead of
  pretending to be connected.
* WebRTC can reveal the real IP outside the proxy. *(Superseded by TD-20: protection is now on by default.)* Originally the optional `privacy` permission was requested only
  when the user enabled "Block WebRTC IP leak" (sets `webRTCIPHandlingPolicy =
  disable_non_proxied_udp` while connected, restores on disconnect).

## TD-6 DNS

* Browser → SOCKS5 with hostname → Xray `domainStrategy: AsIs` → VLESS/VMess carries the domain → the **server**
  resolves it. The client Xray performs no DNS lookups for proxied traffic.
* The only local lookup is the VPN server's own hostname (unavoidable, needed to dial it).
* Routing rules match only *IP literals* (private ranges), never domains that need resolving.
  So `IPIfNonMatch`/`IPOnDemand` (which would resolve locally) are not used.
* JetBrains is told to use the **HTTP** endpoint by default. `CONNECT host:port` always carries the
  hostname, so the IDE never needs local DNS for proxied requests.
* An integration test proves remote resolution. It uses a hostname that only the *server-side* Xray can
  resolve (a `dns.hosts` entry on the test server). The client can reach it only through remote DNS.

## TD-7 Secret storage

* `state.json`: metadata only (name, protocol, host, port, transport, security, subscription id).
* `secrets.bin`: VLESS/VMess ids, REALITY password/shortId, subscription URLs, encrypted with
  **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`, no custom crypto).
* The 256-bit data key is stored in the OS store through `keyring`:
  **Windows Credential Manager** (DPAPI-protected, per user) / **macOS login Keychain**.
* Why not one keychain item per server? Subscriptions can hold hundreds of servers. On macOS each
  item gets its own ACL, and an unsigned helper update would re-prompt for every item. One key
  means at most one prompt.
* The extension stores only UI preferences in `chrome.storage.local`, never credentials.

## TD-8 Ports

* Browser inbound: a fresh ephemeral port on `127.0.0.1` for each session (bind `:0`, read the port, release,
  pass to Xray, then verify Xray is listening). A collision is impossible to go unnoticed: Xray would fail to start and we retry once with a new port.
* JetBrains inbounds: stable, configurable (default SOCKS `10808`, HTTP `10809`). If busy, the
  tunnel still connects for the browser and the popup shows *"JetBrains port 10808 is in use"*.
* All inbounds listen on `127.0.0.1` only. The generator refuses any other listen address.

## TD-9 Native messaging registration (per user, no admin)

| Browser | Windows (HKCU key → manifest path) | macOS (per-user manifest dir) |
|---|---|---|
| Chrome | `Software\Google\Chrome\NativeMessagingHosts\<name>` | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Chromium | `Software\Chromium\NativeMessagingHosts\<name>` | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Brave | `Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\<name>` **and** the Chrome key | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Edge | `Software\Microsoft\Edge\NativeMessagingHosts\<name>` | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` |

Public sources disagree on whether Brave/Windows reads its own key or Chrome's. We register both,
which is harmless. `allowed_origins` cannot contain wildcards, so the extension has a **fixed ID**:
a public `key` in `manifest.json`, generated by `scripts/generate-extension-key.mjs`.

## TD-10 Installation

The helper binary contains its own `install` / `uninstall` logic: copy files, write manifests,
registry entries, and the Windows "Apps" uninstall entry. It is invoked by thin wrappers:
`Install.cmd` (Windows zip) and `install.sh` / `.pkg` (macOS). Chrome can never trigger these
paths: it only passes the origin (and `--parent-window` on Windows) as arguments.

## TD-11 QR decoding

QR images are decoded in the extension with the bundled `jsQR` library (Apache-2.0).
`BarcodeDetector` is not available in desktop Chrome on Windows. Sources are a file picker, a
pasted image, or a capture of the visible tab (`activeTab`, granted only by the user
clicking the toolbar button). The decoded text is only ever passed to the import parser.
URLs in QR codes are never opened.

## TD-12 Subscriptions

Fetched by the helper (so the tokenised URL stays in the encrypted store): HTTPS required
(plain HTTP only for loopback test servers), 20 s timeout, 5 MiB body cap, ≤ 2000 entries,
≤ 5 redirects, generic `User-Agent`, and fetched through the tunnel when connected. Formats: base64 or
plain line lists of `vless://`/`vmess://` links, or JSON (single Xray config or an array of them).
Refresh is manual. Servers keep their IDs across refreshes when (protocol, address, port, user id)
match, so the selection survives.

## Findings during implementation

| # | Finding | Decision |
|---|---|---|
| TD-13 | `rustls` pulls in `ring`, which needs a C compiler; the dev machine had none | `reqwest` uses **native-tls** (SChannel on Windows, Security.framework on macOS). That means no C toolchain, and corporate root CAs from the OS trust store work |
| TD-14 | No MSVC Build Tools available; the `windows-gnu` toolchain's bundled `dlltool` needs an assembler | Windows builds use **MSVC when present, otherwise `x86_64-pc-windows-gnullvm` + llvm-mingw** (`scripts/cargo.mjs`). `+crt-static` links libunwind/CRT statically, so the helper imports only OS DLLs (checked with `llvm-objdump`) |
| TD-15 | A request to the IDE HTTP inbound for `http://127.0.0.1:10809/` made Xray proxy to itself recursively (local DoS) | Routing rules block loopback destinations on our own inbound ports (tested) |
| TD-16 | Branded Google Chrome ≥ 137 ignores `--load-extension` | Automated E2E uses Brave/Chromium. Chrome is covered by the manual checklist. The product itself is unaffected: users load it via Developer mode |
| TD-17 | On Windows a just-killed Xray can hold its listening ports for a moment | Port checks retry for up to 1.5 s before declaring an IDE port "in use" |
| TD-18 | `chrome.proxy` `regular`-scope settings survive browser restarts | The service worker clears the setting on every start. The E2E test kills the browser while connected and asserts no stale proxy after restart |
| TD-19 | Raw OS errors (e.g. "os error 10054") are meaningless to users | The helper maps failures to short messages plus error codes. Details go to the redacted log |

## Security hardening pass (host-compromise prevention)

| # | Decision |
|---|---|
| TD-20 | WebRTC protection on by default; `privacy` became a required permission (safe defaults win) |
| TD-21 | Imported config: strict allowlists; dangerous and **unknown** fields reject the entry (`core/import/fields.rs`) |
| TD-22 | Destination policy (`netpolicy.rs`): loopback, link-local/metadata etc. refused; private networks allowed for proxy servers and opt-in for subscriptions; DNS answers checked for direct subscription fetches |
| TD-23 | Xray on Windows: Low integrity, mitigations, no child processes, restricted job, minimal environment (`winproc.rs`). ACG and signed-only images rejected for EDR compatibility |
| TD-24 | Pinned Xray **binary** SHA-256, verified before every launch; geo data files dropped |
| TD-25 | Test hooks only in debug builds with `PRIVATE_PROXY_TEST_MODE=1`; E2E and integration use debug builds |
| TD-26 | `DependentLoadFlags=System32`: fixes DLL planting found in the V1 build |
| TD-27 | Proxy-takeover monitoring via `chrome.proxy.settings.onChange` |
