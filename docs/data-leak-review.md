# Data leak review

Date: 2026-09-22. Question: can MProxy send data anywhere the user does not expect? Flows are
enumerated in [data-flow.md](data-flow.md). Method: code review of every network call site, plus
runtime checks listed below.

## Call-site inventory (code review)

| Component | Network call sites | Result |
|---|---|---|
| Extension (`extension/src`) | one `fetch`, of a `data:` URL (`popup/qr.ts`); no XHR, WebSocket, `sendBeacon`, `EventSource`, remote script, `setUninstallURL`, `identity`/`gcm` | no network egress |
| Extension manifest | no `update_url`, `homepage_url`, content scripts, `externally_connectable`, web-accessible resources; CSP `connect-src 'self' data:` | **PASS: runtime verified**: CSP test + E2E (other origins blocked) |
| Helper (`native/src`) | `reqwest` in `subscription.rs` only; `TcpStream` in `probe.rs` (loopback) and `ports.rs` (loopback); no UDP | subscription + health check only |
| Xray config (`xrayconf.rs`) | outbounds: the selected server, `freedom` (private literals/localhost only), `blackhole`; no `dns`, `api`, `stats`, `observatory`, `metrics`, `reverse`; access log `none` | only the user's server |
| Build scripts | `fetch-xray.mjs` (GitHub, pinned hashes); not part of the product | build time only |

## Classification

| Flow | Class | Third party? | Expected by the user? | Notes |
|---|---|---|---|---|
| Browser / IDE via server | USER TRAFFIC | the server operator | yes | the whole point of the product |
| Bypass (private ranges, plain names) | USER TRAFFIC | none | documented | intranet stays direct |
| Server hostname DNS | OTHER | local/company DNS | implicit | reveals which server is used, not browsing |
| Subscription refresh | SUBSCRIPTION | the provider | yes (user-entered URL, manual) | fixed User-Agent with version, no cookies |
| Health check | HEALTH CHECK | **Google and Cloudflare** | documented, not configurable | through the tunnel only: they see the server's IP; UA reveals "PrivateProxy/<version>" |
| Updates | UPDATE | — | — | none |
| Analytics/telemetry/crash reports | — | — | — | **none** |

## Runtime evidence

* **PASS: runtime verified.** The extension's CSP forbids every origin (`connect-src 'self' data:`;
  manifest test). **NOT TESTED:** an assertion over a full request log proving that the extension issued no request.
* **PASS: runtime verified.** Tunnel credentials never leave the machine. Another extension with
  `extraHeaders` never sees `Proxy-Authorization`. A trap proxy and a 401 phishing site received none.
* **PASS: runtime verified.** Credentials are not in logs or files: `ide_auth_adversarial`.
* **PASS: runtime verified.** Subscription refresh while connected goes through the tunnel: `subscription_update_while_connected`.
* **PASS (CODE REVIEW ONLY).** Xray opens no connections besides flows 1, 3, 4, 5. The integration
  environment is loopback-only, so a runtime capture of Xray's egress to real destinations was not
  possible. **ENVIRONMENT UNAVAILABLE** for a packet capture against a real server.

## Findings

| Finding | Severity | Status |
|---|---|---|
| Health check contacts Google/Cloudflare (through the tunnel) with a product User-Agent | LOW (privacy) | documented; the corporate mode design lets a company use its own probe URL |
| Subscription/probe User-Agent reveals product and version | INFO | documented |
| Local DNS sees the server hostname | INFO | documented; use IP-literal server addresses if this matters |
| No analytics, telemetry, auto-update or unexpected endpoints found | — | PASS |
