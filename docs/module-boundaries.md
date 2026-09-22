# Module boundaries

The native crate (`native/`, library `ppcore`, binary `private-proxy-host`) is split into four layers.
Dependencies point downwards only:

```text
browser   →   core   →   runtime   →   platform          (log: shared by every layer)
```

One crate, not four: the boundaries are enforced by an automated test instead of crate splits
(`native/tests/architecture.rs`; it runs with every `cargo test`). That test fails when:

* anything under `core/` names `crate::browser`, the protocol types (`protocol::`, `ApiError`,
  `ErrorCode`, `encode_response`, `encode_event`), `chrome-extension`, `nativeMessaging`,
  `PROTOCOL_VERSION` or `HOST_NAME`;
* anything under `runtime/` names `crate::core` or `crate::browser`;
* anything under `platform/` names `crate::core`, `crate::runtime` or `crate::browser`;
* anything under `core/` or `browser/` starts a process (`Command::new`, `spawn_with`,
  `CreateProcess`, `winproc::`). The only exception is the installer, which runs fixed System32
  tools / `xattr`.

## Layers

### `core/`: Shared Core

Everything a client needs; nothing about how a client talks to it.

| Module | Responsibility |
|---|---|
| `api.rs` | `Core`: the only client-facing API (profiles, imports, subscriptions, sessions, settings, IDE endpoint, diagnostics, capabilities); event queue; policy enforcement point |
| `session.rs` | `ConnectionSession`, `SessionState`, `StartPhase`, `LocalProxyEndpoint`, `SecretBytes` |
| `credentials.rs` | `ProxyCredentials`: local listener credentials (redacted `Debug`, zeroed on drop, not `Serialize`) |
| `error.rs` | `CoreError` / `ErrorKind`: client-safe error model |
| `profile.rs` | profile domain: `ServerMeta` (non-secret profile), `ServerSecrets` (credential material, redacted `Debug`), `ProfileSource`, `ServerSummary` |
| `import/` | strict parsers: `vless`, `vmess`, `json`, `stream`, `fields` (allowlists from the Xray source), QR, subscription bodies |
| `validate.rs` | field validators, `clean_name` (control / bidi / zero-width stripping, F11) |
| `netpolicy.rs` | destination policy (loopback, link-local/metadata, private, multicast) |
| `subscription.rs` | URL policy, redirect policy, DNS-rebinding resolver, limits, fetch (direct or through the authenticated tunnel inbound, F8) |
| `xray_config.rs` | trusted Xray config generator: typed profile + `RuntimePlan` → JSON; loopback-only, authenticated listeners |
| `probe.rs` | health check through the tunnel |
| `store.rs`, `secrets.rs` | persistence (`state.json`, encrypted `secrets.bin`); `KeyProvider` = secret-store boundary |

### `runtime/`: Xray runtime boundary

| Module | Responsibility |
|---|---|
| `xray.rs` | locate the pinned binary, SHA-256 verification with a deny-write handle, `xray run -test`, restricted launch, stdout/stderr tail, termination, orphan reaping, isolation report, macOS sandbox requirement |
| `ports.rs` | ephemeral ports, readiness wait |

Receives configuration as bytes. It knows nothing about profiles or clients.

### `platform/`: OS security primitives

| Module | Responsibility |
|---|---|
| `winproc.rs` | Windows: restricted token (user SID deny-only, `DISABLE_MAX_PRIVILEGE`), Low integrity, job limits, child-process policy, mitigation policies, handle list, minimal environment, **verification on the suspended process** before it runs (F3) |
| `macsandbox.rs` | macOS: Seatbelt profile and self-test (implemented / code reviewed; real hardware pending) |
| `harden.rs` | process hardening (DLL search order, mitigations), private-directory ACL/mode and its verification, link detection |
| `paths.rs` | data, log and install locations |

### `browser/`: Chromium native-messaging client adapter

| Module | Responsibility |
|---|---|
| `nm.rs` | stdio framing, 8 MiB limit |
| `protocol.rs` | closed command set, `deny_unknown_fields`, wire error codes |
| `adapter.rs` | command → Core API mapping; Core state → protocol-v3 JSON; `CoreError` → wire code |
| `install.rs` | runtime install and native-messaging registration for browsers |

`main.rs` (binary) wires the browser adapter to stdio and provides the installer CLI. Crate-root
constants (`PROTOCOL_VERSION`, `HOST_NAME`, allowed extension IDs, test-hook switches) live in `lib.rs`.

## Where Phase 5 code moved

| Phase 5 file | Phase 6 location |
|---|---|
| `service.rs` | split: `core/api.rs` (logic), `core/session.rs` (state), `core/error.rs` (errors), `browser/adapter.rs` (protocol mapping) |
| `model.rs` | `core/profile.rs` (+ `ProfileSource`) |
| `parse/*` | `core/import/*` |
| `validate.rs`, `netpolicy.rs`, `subscription.rs`, `probe.rs`, `store.rs`, `secrets.rs` | `core/…` (same names) |
| `xrayconf.rs` | `core/xray_config.rs` (`IdeAuth` → `core/credentials.rs ProxyCredentials`) |
| `xray.rs`, `ports.rs` | `runtime/…` |
| `winproc.rs`, `macsandbox.rs`, `harden.rs`, `paths.rs` | `platform/…` |
| `protocol.rs`, `nm.rs`, `install.rs` | `browser/…` |

Behaviour-preserving moves, with two hardenings found during the move (see
[phase6-security-preservation.md](phase6-security-preservation.md)): aligned token buffers in
`winproc.rs`, and zero-on-drop / redacted-`Debug` wrappers for credentials and the in-memory tunnel config.

## Extension side

The extension (`extension/`) is unchanged in Phase 6. Its service worker and controller are the
browser-UI half of the browser client; they talk to `browser::adapter` through protocol v3 only.
