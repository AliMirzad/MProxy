# Security boundaries (Phase 6 architecture)

Where each trust boundary sits in the layered code. The threat analysis is in
[threat-model.md](threat-model.md); evidence is in [security-gate.md](security-gate.md).

```text
 UNTRUSTED                       CORE (trusted code)                       RUNTIME / PLATFORM
 vless:// vmess:// QR JSON  ──►  core::import (strict parsers, allowlists)
 subscription bodies               │
                                   ▼
                                 core::validate / core::netpolicy (fields, names F11, destinations)
                                   │
                                   ▼
                                 normalized profile (core::profile)  ── stored ──► core::store (+ secrets.bin, KeyProvider)
                                   │
                                   ▼
                                 core::xray_config (trusted generator; no passthrough)
                                   │ bytes
                                   ▼
                                 runtime::xray: pinned SHA-256 → `xray run -test` → launch ─► platform::winproc / macsandbox
                                                                                              restricted token, Low IL, job,
                                                                                              verified before it runs (F3)
                                                                                                        │
                                                                                                       Xray
```

Imported content is always **data**. There is no path from raw imported configuration to Xray:
* `core::import` reads only VLESS/VMess outbound fields from tables taken from the Xray source.
* `core::xray_config` writes every field itself.
* The generated config is tested by Xray and passed on stdin, never written to disk.

## Boundaries

| # | Boundary | Enforced in (native/src) | Notes |
|---|---|---|---|
| 1 | Imported text → profile | `core/import/*`, `core/validate.rs`, `core/netpolicy.rs` | unknown/dangerous fields reject the entry; names sanitized (F11) |
| 2 | Profile → Xray config | `core/xray_config.rs` | deterministic, loopback-only, every listener authenticated |
| 3 | Subscription URL → network | `core/subscription.rs`, `core/netpolicy.rs` | HTTPS, redirects re-checked, DNS answers checked (direct), through the authenticated tunnel when connected (F8) |
| 4 | Client → Core | `core/api.rs` | typed API; UUID ids; policy enforcement point (future corporate rules) |
| 5 | Browser → client adapter | `browser/protocol.rs`, `browser/nm.rs`, `main.rs` | closed command set, `deny_unknown_fields`, 8 MiB frames, origin re-check |
| 6 | Browser identity | Chromium `allowed_origins` + `main.rs` | **F7 open** for developer-mode installs; closed only by managed deployment |
| 7 | Core → runtime | `runtime/xray.rs` | hash before every launch, config test, no PATH, no env override in release |
| 8 | Runtime → OS isolation | `platform/winproc.rs`, `platform/macsandbox.rs` | fail closed; verified on the suspended process (Windows) / self-test (macOS) |
| 9 | Local processes / other users → listeners | `core/xray_config.rs`, `core/credentials.rs`, `core/session.rs` | loopback, per-connection browser credentials (F5), IDE password |
| 10 | Core data at rest | `core/store.rs`, `core/secrets.rs`, `platform/harden.rs` | encrypted secrets, key in the OS store, private directory verified before use |
| 11 | Browser UI integrity | extension controller (`proxyControlChanged`) | proxy takeover and WebRTC override → fail closed (F6); browser-side by nature |

## Sensitive runtime state

| Item | Type / place | Lifetime | Exposure |
|---|---|---|---|
| Browser credentials | `ProxyCredentials` in `ConnectionSession` (`RuntimeMode::Tunnel`) | one connection; zeroed on drop at stop/failure | `browser_proxy_endpoint()` only while `Connected` |
| Generated tunnel config (contains server secrets and credentials) | `SecretBytes` in the session | one connection (kept for crash restarts) | never; stdin of Xray only |
| IDE password | encrypted in `secrets.bin` | until regenerated | `ide_credentials()` |
| Data key | OS credential store via `KeyProvider` | installation | never |

`Debug` of all of these is redacted, none of them is `Serialize`, and `core_api.rs` asserts that
neither `Debug` dumps nor diagnostics contain the live credentials.

## F7 trust chain (managed deployment)

The Core cannot fix extension impersonation: it does not know who is calling. The chain that closes it:

```text
Managed Chromium (policy)
    ↓  ExtensionSettings: force-installed signed CRX, everything else blocked, developer mode off
Policy-installed extension (ID bound to the CRX signature)
    ↓  native messaging; NativeMessagingUserLevelHosts=false, allowlist com.privateproxy.host
Authorized native host (machine-wide registration, admin-only install directory)
    ↓  in-process
Shared Core (policy enforcement point)
    ↓
Signed helper / runtime (Authenticode / Developer ID; EDR allowlisted: F12)
    ↓
Pinned Xray (hash verified before every launch)
```

Each arrow is a control outside the Core, except the last two. Phase 6 adds no code for these
and claims no fix. See [managed-deployment.md](managed-deployment.md).

## macOS

macOS runtime isolation: **IMPLEMENTED / CODE REVIEWED. REAL HARDWARE VERIFICATION: PENDING.**
The Seatbelt mechanism (`sandbox-exec`) is deprecated. It is isolated in `platform/macsandbox.rs`
(and its use in `runtime/xray.rs`), so replacing it, e.g. with an App-Sandbox-signed Xray, does not
touch the Core. The fail-closed rule stays: no sandbox, no connection.

## Per-application routing boundary (Phase 7: EXPERIMENTAL, not in the product)

```text
selected app ──(its own proxy setting)──► authenticated loopback inbound ──► Xray   [EXPERIMENTAL: W6]
selected app ──(anything else)──────────► WFP BLOCK (dynamic session, per user)    [EXPERIMENTAL: W5, needs admin; NOT TESTED]
unselected apps ────────────────────────► unchanged system path                    [runtime: system snapshot unchanged]
arbitrary app without proxy support ────► needs a WFP redirect callout driver      [RESEARCH ONLY]
```

The boundary between a future privileged routing service and the user session is a fixed command
set over an ACL'd IPC channel ([per-app-routing-corporate-impact.md](per-app-routing-corporate-impact.md)).
It does not exist in code yet.
