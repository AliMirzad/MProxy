# EXPERIMENTAL: MProxy WFP connect-redirect callout driver

**STATUS: SOURCE ONLY — never compiled, never loaded, never signed, never executed.**
No WDK, no Visual Studio and no disposable VM exist in the validation environment, and the company
workstation's Secure Boot, driver-signing enforcement and endpoint protection are not to be changed
([../../docs/driver-build-environment.md](../../docs/driver-build-environment.md)).

Everything below is **CODE REVIEW ONLY**. None of it is runtime evidence.

## What this component is for

It is the one piece of the product goal that cannot be done in user mode: rewriting the destination
of a connection so that an application with no proxy support is transparently carried through Xray.

```text
selected app ──connect(example:443)──► [kernel] ALE_CONNECT_REDIRECT callout
                                          │ destination → 127.0.0.1:<redirector>
                                          │ original destination → local redirect context
                                          ▼
                                    redirector (user mode)
                                          │ SOCKS5 + credentials
                                          ▼
                                        Xray ──► server
```

## Deliberate minimalism

The kernel knows **only** where the redirector listens and which process it is:

```c
struct MPROXY_REDIRECT_TARGET { ULONG Version; ULONG RedirectorPid; USHORT PortV4; USHORT PortV6; ULONG Reserved; };
```

Which applications are routed is expressed as **WFP filter conditions** (`ALE_APP_ID` + `ALE_USER_ID`)
installed from user mode by the routing service, on filters that reference this callout. So the
driver holds no application list, no paths, no SIDs, no credentials and no configuration, and a
compromised service cannot make the driver do anything it does not already do.

Not present in the driver: VLESS, VMess, subscriptions, HTTP, JSON, UI, server management, secrets,
traffic logging, config import, application discovery.

## Device interface

| Property | Value |
|---|---|
| Device | `\Device\MProxyWfpRedirect` |
| ACL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` — SYSTEM and Administrators only, protected (no inherited ACEs) |
| Open semantics | `FILE_DEVICE_SECURE_OPEN`, so the ACL also applies to opens by relative name |
| IOCTLs | `SET_TARGET`, `CLEAR`, `QUERY_STATE` — three fixed-size structures, `METHOD_BUFFERED` |

`METHOD_BUFFERED` with fixed-size structures means the driver never dereferences a user-mode pointer,
and there is no length arithmetic to get wrong: a request whose input length is not exactly
`sizeof(MPROXY_REDIRECT_TARGET)` is rejected before anything is read.

## Loop prevention

Three independent mechanisms, because a redirect loop is the failure that hangs the machine:

1. `FwpsQueryConnectionRedirectState0` — a flow already redirected by us is left alone (mandatory
   since Windows 8);
2. the redirector's own PID is never redirected, even before it has redirect records;
3. the redirector sets `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on its outbound socket, which links
   the proxied connection to the original and makes mechanism 1 effective for Xray's traffic.

The service additionally refuses to select any executable inside the product's own install directory.

## Review points before a first VM run

* **Ownership of `localRedirectContext`.** The driver allocates it and hands it to WFP with the
  modified layer data. Whether WFP frees it, and with which tag, must be confirmed against
  `ClassifyFunctions_ProxyCallouts.cpp` in the WFP driver sample. A wrong assumption is a per-connection
  leak or a double free. This is marked in the source.
* **Callout GUIDs are placeholders** and must be regenerated.
* **Byte order** of `IP_REMOTE_ADDRESS`/`IP_REMOTE_PORT` at the redirect layers must be re-checked
  against the header definitions when the code first compiles.
* **`FwpsCalloutRegister3` vs `FwpsCalloutRegister1`**: register version must match the `classifyFn`
  signature actually used.
* The driver must be exercised under **Driver Verifier** (scoped to this driver only) in the VM.

## Build

See [../../docs/driver-build-environment.md](../../docs/driver-build-environment.md). Nothing in this
directory is referenced by the product build or by `npm run package`, and the packaging guard rejects
experimental paths.
