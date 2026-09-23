# Phase 8: true per-app routing — driver PoC and evidence

**Question:** can MProxy transparently route an arbitrary Windows application (ChatGPT, Claude,
Cursor…) through Xray when that application has no proxy support, leaving everything else direct?

**Answer after Phase 8:** the architecture is validated end to end **except the one piece that needs
a kernel driver**. Everything downstream of the kernel was built and proven at runtime; the kernel
callout is written but **NOT COMPILED, NOT LOADED, NOT TESTED** — no WDK and no safe VM exist here
([driver-build-environment.md](driver-build-environment.md)).

## Architecture

```text
selected app ──connect(a.b.c.d:443)──►  [KERNEL] ALE_CONNECT_REDIRECT_V4/V6 callout   SOURCE ONLY
                                              │  destination → 127.0.0.1:<redirector>
                                              │  original destination → redirect context
                                              ▼
                                        redirector (user mode)                        RUNTIME TESTED
                                              │  CONNECT <original dest> + credentials
                                              ▼
                                   authenticated local inbound → Xray                 RUNTIME TESTED
                                              │  VLESS / VMess
                                              ▼
                                            server → Internet                         RUNTIME TESTED
unselected app ─────────────────────────────────────────────────────────────────────► DIRECT
```

| Component | State | Where |
|---|---|---|
| WFP callout driver (`mproxy-wfp.sys`) | **SOURCE ONLY** | `experimental/windows-wfp-driver/` |
| Local redirector | **COMPILED + RUNTIME TESTED** | `experimental/windows-redirector/` |
| Phase 8 harness and proxy-unaware client | **COMPILED + RUNTIME TESTED** | same crate |
| Routing service (policy owner) | **DESIGN ONLY** | described below and in [future-desktop-architecture.md](future-desktop-architecture.md) |
| Shared Core + pinned Xray | **PRODUCTION** (unchanged) | `native/` |

## What the kernel is allowed to know

The driver holds **no policy**. Which applications are routed is expressed as WFP filter conditions
(`ALE_APP_ID` + `ALE_USER_ID`) installed from user mode — the same mechanism Phase 7.5 verified at
runtime. The kernel is told only:

```c
struct MPROXY_REDIRECT_TARGET { ULONG Version; ULONG RedirectorPid; USHORT PortV4; USHORT PortV6; ULONG Reserved; };
```

Three fixed-size `METHOD_BUFFERED` IOCTLs (`SET_TARGET`, `CLEAR`, `QUERY_STATE`) on a device whose
ACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. No user-mode pointer is ever dereferenced, there is no
variable-length data, and no IOCTL can express "route this application" — so a compromised service
cannot widen what the driver does.

## Evidence (runtime, 2026-09-23, non-elevated, user-mode path)

Ground truth (§13, §39): no public IP checks. The simulated original destination is **192.0.2.7:80**
(TEST-NET-1, documentation-only). The test server's Xray uses a `freedom` outbound with `redirect`,
so anything that traverses the tunnel lands on a controlled endpoint, which reports **which local
process opened each connection**. Client return codes are never the evidence by themselves.

| # | Scenario | Expected | Actual | Verdict |
|---|---|---|---|---|
| R1 | proxy-unaware client → redirector, destination 192.0.2.7:80 | PROXY | marker delivered, connection at the endpoint **opened by `xray.exe`**, 11 ms | **PASS — RUNTIME VERIFIED** (user-mode path; interception simulated) |
| R2 | control client straight to 192.0.2.7:80 | unreachable | connection timed out, endpoint saw nothing | **PASS — RUNTIME VERIFIED** (proves R1 really went through the tunnel) |
| R3 | unselected client → controlled endpoint | DIRECT | delivered, opened by **`unaware-client.exe`** | **PASS — RUNTIME VERIFIED** |
| R4 | the routed client must be genuinely proxy-unaware | no proxy env used | `proxyEnvPresent: []`, and the binary contains no proxy client code | **PASS — RUNTIME VERIFIED** |
| R5 | redirector reachable from a LAN address? | refused | connection to `<lan>:<port>` timed out; it binds 127.0.0.1 only | **PASS — RUNTIME VERIFIED** |
| R6 | client sends proxy-looking bytes ("CONNECT evil.example:443") | payload, not destination control | delivered verbatim to the configured destination; nothing smuggled elsewhere | **PASS — RUNTIME VERIFIED** |
| R7 | loop prevention (user-mode half) | only client connections enter the redirector | `accepted = 2` for exactly 2 client connections; no connection from Xray, the helper or itself | **PASS — RUNTIME VERIFIED**; kernel-side loop prevention **CODE REVIEW ONLY** |
| R8 | Xray/session stopped mid-use | BLOCK, never direct | client got `10054`; redirector logged `10061` to the inbound; endpoint received nothing | **PASS — RUNTIME VERIFIED (fails closed)** |
| R9 | redirector killed | BLOCK | client connection failed; endpoint received nothing | **PASS — RUNTIME VERIFIED** |
| R14 | routed app restarted / several instances | all routed | both instances delivered | **PASS — RUNTIME VERIFIED** |
| X1 | connection setup cost | observation | routed 5.5 ms vs direct 3.0 ms (loopback + tunnel, same host) | **OBSERVED** |
| R15 | system side effects | no global change | adapters, DNS, drivers, firewall rules, routes, services, system proxy, WFP objects **all unchanged** | **PASS — RUNTIME VERIFIED** (no driver or service installed in this run) |
| R10 | selected TCP IPv6 | PROXY or BLOCK | v6 path compiled, no IPv6 route on this machine | **NOT TESTED: ENVIRONMENT LIMITATION** |
| R11 | selected UDP | BLOCK for V1 | not redirected by design; Windows drops connected UDP redirected to a local proxy | **RESEARCH ONLY** (blocking itself: PASS — RUNTIME VERIFIED in Phase 7.5 T4) |
| R12 | DNS metadata of a routed application | documented | unchanged by redirection: names resolve in the DNS Client service before any connect | **FAIL: DNS METADATA STILL LEAKS** |
| R13 | kernel connect-redirect callout | redirects a real app with no simulation | no WDK, no VM; workstation security untouched | **NOT TESTED: ENVIRONMENT UNAVAILABLE** |

Report: `phase8-harness --report <file.json>`.

## What is simulated, precisely

Only one thing: **who tells the redirector the original destination.** In production the kernel
callout supplies it through the WFP redirect context; in this run the harness supplied it. The
code path that reads the real context (`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`) is compiled and
tried first on every connection — it simply finds no context, because no driver exists.

Consequently R1 does **not** prove that Windows will hand us a real application's connection. It
proves that once a connection arrives, everything from there to the server works, fails closed, and
cannot be abused as an open proxy.

## Authentication: why the inbound stays closed (§33, Phase 5 F5)

A transparently redirected application cannot answer a proxy challenge — it does not know it is
being proxied. The redirector answers on its behalf: it holds the credentials and performs
`CONNECT` against the **existing authenticated inbound**. No unauthenticated endpoint is created, and
an unrelated local process that finds the port still cannot use it. R6 shows the redirector is not an
open proxy either: the destination comes from the kernel context or configuration, never from the
client's bytes.

## Failure model (§18)

| Condition | Selected application | Evidence |
|---|---|---|
| Driver loaded, service healthy, Xray healthy | **PROXY** | R1 (user-mode half) |
| Xray dead | **BLOCK** (connection fails) | R8, runtime |
| Redirector dead | **BLOCK** (connection refused) | R9, runtime |
| Service dead, driver loaded | **BLOCK** — driver keeps its last target, but WFP BLOCK filters owned by the service disappear with it unless they are persistent; this is the Phase 7.5 T17 problem and is why the service, not the UI, must own them | design |
| Desktop UI dead | **unchanged** — the UI is display only | design |
| Driver not loaded | **BLOCK or DIRECT — must be BLOCK**: the service must refuse to report "protected" and keep BLOCK filters in place | design |
| User logs out / shutdown | policy removed with the session; nothing persistent | design (Phase 7.5 T18 for the user-mode half) |

Unexpected **DIRECT** is a failure in every row. The lifecycle is therefore: **BLOCK first, then
redirect** (§37) — install Track A's BLOCK filters, start Xray and the redirector, add the redirect
filters, and only then report Protected.

## Application identity (§10)

PoC: canonical path + current user SID, as WFP filter conditions. **EXPERIMENTAL and not sufficient
for production** — Phase 7.5 showed per-user install directories are user-writable, so a same-user
program can replace the executable at a selected path. Production must additionally verify the
Authenticode publisher at every new process of that path, and treat file identity changes as a
re-verification trigger. Package identity is the robust option for MSIX apps.

## Children (§23)

`EXPLICIT_EXECUTABLES` only. WFP has no parent-process condition (Phase 7.5 T13/T15), so a process
tree is not expressible in the filter layer, and unbounded tree inheritance was already rejected in
Phase 7 after it proxied unrelated tools.

## Real-application test (§24)

**Not attempted.** Without the driver, a real application could only be "routed" by configuring it,
which is exactly what this phase is meant to avoid substituting for routing. Attempting it would
produce a misleading demo, not evidence.

## Remaining blockers

1. No WDK/Visual Studio, and no disposable VM ⇒ driver unbuilt and untested.
2. Production driver signing: EV certificate, Partner Center hardware account, HLK submission
   ([driver-signing-and-release.md](driver-signing-and-release.md)).
3. DNS metadata leak — unsolved by redirection.
4. IPv6 unverified anywhere in the project.
5. UDP not routable; blocking is the only safe answer for V1.
6. Routing service (policy owner, fail-closed lifecycle) is design only.
7. Redirect-context ownership and a few field-level details in the driver source need first-compile
   verification (listed in the component README).
