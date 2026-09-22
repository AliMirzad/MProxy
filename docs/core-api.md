# Core API

`ppcore::core::api::Core` is the single surface every client uses. Source: `native/src/core/api.rs`.
Clients never launch Xray, touch the store, or build configuration themselves.

## Lifecycle and concurrency

```rust
let post: Poster = Arc::new(move |m: CoreMsg| { let _ = tx.send(m); }); // worker results back to the owner
let mut core = Core::new(store, xray::locate(), post, Timing::default());
core.start();                         // applies settings, starts the IDE endpoint if enabled
loop {
    // … client requests → core.method(…)
    // … messages from `post` and a ~500 ms tick → core.handle(msg)
    for ev in core.take_events() { /* StatusChanged / SubscriptionDone */ }
}
core.shutdown();                      // stops Xray
```

* One thread owns the `Core` (no locks, no races). Slow work (health probe, subscription download)
  runs on worker threads that post a `CoreMsg` back; the owner passes it to `Core::handle`.
* `CoreMsg::Tick` drives supervision (detects Xray exiting; restarts a verified tunnel ≤ 2 times per 60 s).
* Everything a client must react to is queued as a `CoreEvent` and drained with `take_events()`:
  * `StatusChanged { status, browser_proxy }`: a snapshot at the time of the change.
  * `SubscriptionDone { ticket, result }`: completes `add_subscription` / `refresh_subscription`.

## Methods

| Area | Method | Returns |
|---|---|---|
| Info | `info()` | `CoreInfo` (versions, Xray availability, platform, key storage) |
| | `runtime_capabilities()` | `RuntimeCapabilities` (see below) |
| | `diagnostics()` | `Diagnostics` (local only; includes isolation report and capabilities) |
| Profiles | `list_profiles()` | `ProfileList` (summaries without secrets, subscriptions, selection) |
| | `import_profiles(text, ImportKind::{Text,Qr})` | `ImportReport` |
| | `rename_profile(id, name)`, `remove_profile(id)`, `select_profile(id)` | `()` |
| | `reset_all()` | `()`: profiles, subscriptions, credentials and the data key |
| Subscriptions | `add_subscription(name, url, ticket)` | `()` now (URL policy checked synchronously), `SubscriptionDone` later |
| | `refresh_subscription(id, ticket)` | same |
| | `remove_subscription(id, remove_profiles)` | `()` |
| Session | `start_session(profile_id)` | `()`; progress via `StatusChanged` |
| | `stop_session()` | idempotent; Xray terminated, credentials and config dropped |
| | `session_status()` | `SessionStatus { state, ide, runtime_available }`, **no credentials** |
| | `browser_proxy_endpoint()` | `Option<LocalProxyEndpoint>`: host, port, credentials, **only while `Connected`** |
| Settings / IDE | `settings()`, `update_settings(SettingsUpdate)` | `Settings` (+ reconnect flag) |
| | `ide_credentials(regenerate)` | `IdeCredentials` (redacted `Debug`) |

IDs are UUIDs; anything else is `InvalidRequest`. Profile names are sanitized in the Core
(`validate::clean_name`), so every client gets F11's protection.

## Types

* `SessionState`: `Disconnected`, `Starting { profile_id, phase: Launching | Verifying | Restarting }`,
  `Connected { profile_id, port, since }`, `Stopping`, `Failed { error: CoreError, profile_id }`.
  **`Connected` is set only after the health probe succeeded through the server** (or when a verified
  tunnel's Xray was restarted after a crash), never from a client's intent.
* `ProfileSource`: `Manual` | `Subscription(id)` (`ServerMeta::source()`). A `Managed` variant is
  reserved for corporate mode and is not implemented.
* `RuntimeCapabilities`:
  * `browser_proxy`: true.
  * `jetbrains_proxy`: true.
  * `application_routing`: **false** (not implemented; Phase 7).
  * `secure_storage`: true unless the development file key is used.
  * `runtime_isolation`: true on Windows and macOS. On macOS this is **implemented and code-reviewed;
    real-hardware verification is pending**.

## Errors

`CoreError { kind: ErrorKind, message }`. `message` is user-safe: fixed text plus redacted or
truncated details. It never contains proxy credentials, server secrets, subscription URLs (only their
host), authentication headers or configuration.

| `ErrorKind` | Meaning | Protocol v3 code |
|---|---|---|
| `InvalidRequest` | bad arguments / id | `INVALID_REQUEST` |
| `NotFound` | unknown profile/subscription | `NOT_FOUND` |
| `InvalidProfile` | import or subscription URL failed parsing/validation | `INVALID_CONFIG` |
| `SecurityPolicyViolation` | forbidden destination (loopback, metadata…) | `INVALID_CONFIG` |
| `SubscriptionFailure` | download/parse of a subscription failed | `SUBSCRIPTION_FAILED` |
| `RuntimeUnavailable` | Xray not installed | `XRAY_MISSING` |
| `RuntimeIntegrityFailure` | Xray hash mismatch (never executed) | `XRAY_FAILED` |
| `RuntimeIsolationFailure` | a MANDATORY protection could not be applied/verified ("Runtime security check failed…") | `XRAY_FAILED` |
| `RuntimeFailure` | Xray did not start / stopped | `XRAY_FAILED` |
| `ConfigRejected` | `xray run -test` rejected the generated config | `XRAY_CONFIG_REJECTED` |
| `PortUnavailable` | no free local port | `PORT_UNAVAILABLE` |
| `ConnectionFailure` | Xray runs, but no traffic passes through the server | `SERVER_UNREACHABLE` |
| `SecureStorageUnavailable` | data key unavailable | `SECURE_STORAGE_UNAVAILABLE` |
| `Storage` | local file error | `STORE_ERROR` |

## Credential exposure

| Secret | Leaves the Core only through | Never in |
|---|---|---|
| Browser per-connection credentials | `browser_proxy_endpoint()` and `StatusChanged.browser_proxy`, only while `Connected` | `session_status()`, errors, diagnostics, logs, `Debug`, files |
| IDE password | `ide_credentials()` | status, settings, diagnostics, logs, `Debug` |
| Server secrets (user id, REALITY keys) | nowhere (only into the generated config on stdin) | summaries, events, errors, logs |
| Subscription URL/token | nowhere (only the host) | summaries, errors, logs |

The browser adapter forwards the endpoint credentials only in the `proxy` object of a `connected`
status, because Chromium needs them to answer the local proxy's 407 challenge. A desktop client would
use the same accessor, or not need it at all.

## Policy enforcement point

All mutating operations go through `Core` methods (import, subscriptions, settings, session start).
That makes `Core` the place where future managed policy is enforced, **below every client**. A modified
or malicious UI (or any second client) cannot skip a check that lives there. Today the Core enforces:
* the destination policy;
* the URL/redirect/DNS policy for subscriptions;
* the strict import allowlists;
* the pinned Xray hash;
* the mandatory isolation checks;
* authenticated listeners.

The corporate-mode rules (manual import off, trusted subscriptions only, server allowlist, settings
locks, company health-check URL) are designed in [managed-deployment.md](managed-deployment.md#corporate-mode-design)
and would be checked at the start of the corresponding `Core` methods. **Not implemented in Phase 6.**

What Core policy cannot do: prove *which* client is calling. Caller authorization belongs to the
transport. For the browser client that is native messaging `allowed_origins` plus the origin check in
`main.rs`, which is spoofable by an unpacked extension in developer mode (F7). Managed deployment closes that.

## Browser adapter mapping (protocol v3 → Core)

| Command | Core call |
|---|---|
| `hello` | `info()` (+ protocol version check, adapter-only) |
| `getStatus` | `session_status()` + `browser_proxy_endpoint()` |
| `listServers` | `list_profiles()` |
| `importText` | `import_profiles(text, Qr if source == "qr" else Text)` |
| `addSubscription` / `updateSubscription` | `add_subscription` / `refresh_subscription` (ticket = request id) |
| `deleteSubscription` | `remove_subscription(id, deleteServers)` |
| `renameServer` / `deleteServer` / `selectServer` | `rename_profile` / `remove_profile` / `select_profile` |
| `connect` / `disconnect` | `start_session` / `stop_session` |
| `getSettings` / `setSettings` | `settings` / `update_settings` |
| `getIdeCredentials` / `regenerateIdeCredentials` | `ide_credentials(false / true)` |
| `getDiagnostics` | `diagnostics()` (+ protocol version) |
| `resetAll` | confirmation checked by the adapter, then `reset_all()` |

Anything else was already rejected by `protocol::decode` (closed command set, `deny_unknown_fields`).
