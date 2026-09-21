# Extension ↔ native helper protocol (v1)

Transport: Chromium native messaging. Each message is a 32-bit length in native byte order
followed by UTF-8 JSON. The extension's service worker holds one long-lived
`chrome.runtime.connectNative("com.privateproxy.host")` port.

Implementations: [`native/src/protocol.rs`](../../native/src/protocol.rs) (authoritative),
[`types.ts`](types.ts) (TypeScript mirror).

## Envelope

```jsonc
// request (extension -> helper)
{ "id": 7, "cmd": "connect", "args": { "serverId": "3f0c…" } }
// response (helper -> extension), exactly one per request id
{ "id": 7, "ok": true,  "result": { … } }
{ "id": 7, "ok": false, "error": { "code": "NOT_FOUND", "message": "Server not found" } }
// event (helper -> extension, unsolicited)
{ "event": "status", "status": { … } }
{ "event": "protocolError", "error": { … } }   // a message without a usable id
```

Rules enforced by the helper:

* `id` is a positive u32. Top-level keys other than `id`, `cmd` and `args` are rejected.
* `cmd` must be one of the commands below. Unknown commands get `INVALID_REQUEST`.
* Every `args` object is strictly typed (`deny_unknown_fields`). IDs must be UUIDs.
* Messages over 8 MiB close the connection. Import text is capped at 5 MiB.
* No command executes a caller-chosen program, reads or writes a caller-chosen path, or
  contacts a caller-chosen host. The one exception is `addSubscription`, whose URL is
  validated (HTTPS only) and fetched with strict limits.

## Commands

| cmd | args | result |
|---|---|---|
| `hello` | `{protocolVersion, extensionVersion}` | `{nativeVersion, protocolVersion, xrayVersion, xrayAvailable, platform, keyStorage}`. `INCOMPATIBLE_VERSION` if the protocol versions differ |
| `getStatus` | `{}` | Status (below) |
| `listServers` | `{}` | `{servers: ServerSummary[], subscriptions: SubscriptionSummary[], selectedServerId}`. **Never contains credentials** |
| `importText` | `{text, source: "paste"\|"qr"\|"file"}` | `{added, updated, serverIds, errors[], rejected, unsupported, warnings[]}` |
| `addSubscription` | `{name, url}` | `{subscriptionId, added, updated, removed, rejected, unsupported}` (answered after the fetch) |
| `updateSubscription` | `{id}` | same as above |
| `deleteSubscription` | `{id, deleteServers}` | `{}` |
| `renameServer` | `{id, name}` | `{}` |
| `deleteServer` | `{id}` | `{}` (disconnects first if it is the active server) |
| `selectServer` | `{id}` | `{}` |
| `connect` | `{serverId}` | Status (immediately; progress arrives as `status` events). Repeating it for the active or connecting server is a no-op |
| `disconnect` | `{}` | Status. Idempotent |
| `getSettings` | `{}` | Settings |
| `setSettings` | partial Settings | Settings + `reconnectRequired` |
| `getDiagnostics` | `{}` | versions, paths, `xrayPid`, key storage; recent Xray output only when debug logging is on |
| `resetAll` | `{confirm: true}` | `{}`. Deletes all servers, subscriptions, secrets and the data key |

## Status

```jsonc
{
  "state": "disconnected" | "connecting" | "connected" | "disconnecting" | "error",
  "phase": "starting" | "verifying" | "restarting",      // connecting only
  "serverId": "…",
  "proxy": { "scheme": "socks5", "host": "127.0.0.1", "port": 53123 },  // connected only
  "error": { "code": "SERVER_UNREACHABLE", "message": "…" },            // error only
  "jetbrains": { "enabled": true, "mode": "tunnel"|"direct"|"off", "socksPort": 10808, "httpPort": 10809, "issue": null },
  "xrayAvailable": true
}
```

The browser proxy is applied **only** in `connected` with a `proxy` port. It is kept during
`connecting/restarting` (same port). In every other state it is cleared.

## Error codes

`INVALID_REQUEST`, `INCOMPATIBLE_VERSION`, `NOT_FOUND`, `INVALID_CONFIG`, `XRAY_MISSING`,
`XRAY_FAILED`, `XRAY_CONFIG_REJECTED`, `PORT_UNAVAILABLE`, `SERVER_UNREACHABLE`,
`SUBSCRIPTION_FAILED`, `STORE_ERROR`, `SECURE_STORAGE_UNAVAILABLE`, `BUSY`, `INTERNAL`.

Messages are short and meant for the user. Technical detail goes to the helper log.

## Versioning

`PROTOCOL_VERSION` (currently 1) changes on any incompatible change. The extension sends
its version in `hello`. On a mismatch the helper answers `INCOMPATIBLE_VERSION`, naming
the side to update, and the popup shows **Update required**.
