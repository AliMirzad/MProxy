# Data flow

Every network connection MProxy's components can make, and every place data is stored. The
privacy review of these flows is in [data-leak-review.md](data-leak-review.md).

Classes: **USER TRAFFIC** (what the user browses or sends through the IDE endpoint),
**SUBSCRIPTION**, **HEALTH CHECK**, **UPDATE**, **OTHER**.

## Network requests

| # | From | To | When | Class | Route | Content |
|---|---|---|---|---|---|---|
| 1 | Browser (all tabs, other extensions' requests too) | the selected VLESS/VMess server, via the local authenticated HTTP inbound | while Connected | USER TRAFFIC | browser → 127.0.0.1:eph (HTTP proxy, per-connection credentials) → Xray → server → destination | the user's web traffic; hostnames sent unresolved (DNS on the server) |
| 2 | Browser | destination, **direct** | while Connected, for `localhost`, plain host names and private ranges (bypass list) | USER TRAFFIC | OS network | intranet traffic; never proxied (documented) |
| 3 | JetBrains / other local apps configured to use 127.0.0.1:10809/10808 | server (Connected) or destination directly (Disconnected, "passthrough") | whenever the IDE endpoint is on | USER TRAFFIC | app → Xray (password) → server / direct | the app's traffic |
| 4 | Xray | the **server hostname's DNS** via the OS resolver | at connect | OTHER (DNS) | OS resolver / company DNS | the server's hostname only |
| 5 | Xray | private IP literals and `localhost` | when a proxied client targets them | USER TRAFFIC | direct (`freedom`) | e.g. IDE access to intranet hosts |
| 6 | Helper | **subscription URL** (user-entered, HTTPS) | only on "Add subscription" / "Update" (manual; no schedule) | SUBSCRIPTION | Disconnected: direct, OS DNS with the rebinding check. Connected: through the tunnel inbound (CONNECT host:443, DNS on the server) | `GET` with `User-Agent: PrivateProxy/<version>`; no cookies, no identifiers; the URL's own token (if any) |
| 7 | Helper | `http://www.gstatic.com/generate_204`, then `http://cp.cloudflare.com/generate_204` if the first fails | once per connect (and after an automatic Xray restart) | HEALTH CHECK | **through the tunnel** (never direct) | `GET` + `User-Agent: PrivateProxy/<version>`; Google/Cloudflare see the **server's** egress IP, not the user's |
| 8 | Helper | `127.0.0.1:<port>` | port checks, probe connection | OTHER (loopback) | loopback | none |
| 9 | Extension | nothing | — | — | CSP `connect-src 'self' data:` blocks all origins; the only `fetch` is of a `data:` URL (QR image decoding) | — |
| 10 | Extension ↔ helper | native messaging (stdio pipe) | always | OTHER (local IPC) | anonymous pipe owned by the browser | commands/status |
| — | any component | update servers, analytics, telemetry, crash reporting | **never** | UPDATE: none | — | there is no auto-update; Xray is pinned; updates are manual releases |

Build time only (developer machine, not the product): `scripts/fetch-xray.mjs` downloads the
pinned Xray release from GitHub and verifies zip and binary SHA-256. `cargo`/`npm` fetch
dependencies from their registries against lockfiles.

## Storage

| What | Where | Protection |
|---|---|---|
| Server list metadata, settings | `%LOCALAPPDATA%\PrivateProxy\state.json` / `~/Library/Application Support/PrivateProxy` | private directory (DACL user/SYSTEM/Admins + no-read-up label; 0700) |
| Server credentials, subscription URLs, IDE password | `secrets.bin` in the same directory | ChaCha20-Poly1305; key in Credential Manager / Keychain (one entry per data directory) |
| Browser tunnel credentials | helper memory and extension service-worker memory | never stored, new for every connection |
| Logs | `logs/helper.log` | redacted (no credentials, URLs with tokens, UUIDs) |
| Extension storage | `chrome.storage.local` | UI preferences only (e.g. WebRTC toggle); no secrets |
| Xray config | never on disk | passed on stdin |

## What a proxy operator sees

* the user's public IP, connection times, the VLESS/VMess user ID;
* every destination host and port, and DNS lookups of proxied names;
* for HTTPS: SNI (unless ECH), traffic volume and timing;
* for plain HTTP: full content, which it can modify;
* IDE-endpoint traffic;
* the health-check requests (flow 7) and subscription refreshes made while connected (flow 6).

It cannot read HTTPS content without a certificate error, connect into the client, or reach files,
the keychain or the helper's interface. Recommendation for companies: operate the servers yourself;
see [managed-deployment.md](managed-deployment.md#corporate-mode-design).
