# Track A validation: fail-closed protected apps on Windows (runtime evidence)

**Phase 7.5. Mechanism: app-configured proxy (W6) + user-mode WFP fail-closed filters (W5). No driver,
no redirection, no injection.** The harness is EXPERIMENTAL and never packaged; the decision it feeds
is in [per-app-routing-decision.md](per-app-routing-decision.md), the driver alternative in
[wfp-driver-feasibility.md](wfp-driver-feasibility.md).

## What was validated

One test process (`track-a`) starts a local HTTP target, a pinned Xray through the Shared Core, and a
test client. The **selected** application is a copy of that client at one path; the **control** is a
byte-identical copy at another path, so every result separates policy-by-path from anything else.
Ground truth is not "the request succeeded": each scenario checks *which* listener received the
connection, and blocking is only recorded when the client gets `WSAEACCES` (os 10013) **and** the
listener received nothing.

Run it (the elevated run is done by the machine owner; nothing here elevates itself):

```powershell
# full matrix
C:\Users\amirzad\.private-proxy-target\debug\track-a.exe --report <path>\track-a-admin.json
# lifecycle-only diagnostic: open / apply / close a WFP session N times, no network tests
C:\Users\amirzad\.private-proxy-target\debug\track-a.exe --report <path>\track-a-cycle.json --wfp-cycle 3
```

Each run writes `<report>.json` incrementally plus a `<report>.log` trace of every WFP call.

Environment: Windows 11 Pro 22621, company workstation, Secure Boot on, Kaspersky Endpoint Security
active, no test-signing. Evidence below is from the complete elevated run of 2026-09-23
(`"complete": true`, exit 0), except where a row says otherwise.

## Results

Evidence levels: **runtime** = observed in this run; **runtime (error code)** = the OS refusal code is
evidence but the destination was never reachable; **NOT TESTED** = the environment could not produce
the condition.

| # | Scenario | Expected | Actual | Evidence | Verdict |
|---|---|---|---|---|---|
| W0 | open dynamic WFP session, add sublayer + filters, as admin | succeeds | session opened, 4 filters per target | runtime | **PASS** |
| T1 | selected **proxy-aware** app → approved proxy → `probe.test` | proxied | `HTTP/1.1 200 OK` via proxy, 9 ms | runtime | **PASS** |
| T2 | selected **proxy-unaware** app, direct TCP to the machine's own LAN address | blocked | os 10013, listener hits 0 | runtime | **PASS** |
| T3 | unselected app (same bytes, other path), direct TCP | direct | connected, listener hits 1 | runtime | **PASS** |
| T4 | selected app, direct UDP | blocked | `send_to` reports 3 bytes, listener hits **0** (silently dropped) | runtime | **PASS** |
| T5 | unselected app, direct UDP | direct | listener hits 1 | runtime | **PASS** |
| T6 | selected app, direct TCP IPv6 | blocked | os 10051 (network unreachable) | runtime (error code) | **NOT TESTED** (no IPv6 route on this machine) |
| T7 | unselected app, direct TCP IPv6 | attempted | os 10051 | runtime (error code) | **NOT TESTED** (same) |
| T8 | selected app resolves a unique hostname | defined | resolved, and the name appears in the **DNS Client cache** | runtime (resolver cache) | **FAIL: DNS metadata leaks** |
| T9 | selected app → `127.0.0.1` and `::1` | permitted | both reachable (this is how the proxy hop works) | runtime | **PASS** |
| T10 | selected app → `10/8`, `172.16/12` | blocked | os 10013 for selected; control times out (destination unreachable) | runtime (error code) | **PASS** |
| T11 | selected app restarted (new PID, same path) | still blocked | os 10013 | runtime | **PASS** |
| T12 | two concurrent instances of the selected executable | both blocked | os 10013 for both | runtime | **PASS** |
| T13 | child processes, `include_children = false` | defined | child of the **same path** blocked; child at another path **direct** | runtime | **OBSERVED: no process-tree inheritance** |
| T14 | `include_children = true` prototype (explicit executable allowlist) | child blocked | os 10013 for the other-path child once it is listed by path | runtime | **PASS (only by explicit listing)** |
| T15 | NEGATIVE: selected → `cmd.exe` → `curl.exe` (unrelated program) | must not be silently counted as protected | neither proxied nor blocked; hit the direct listener | runtime | **OBSERVED: no inheritance (by design of WFP app matching)** |
| T16 | Xray killed while the selected app runs | no direct fallback, then recovery | during the crash: proxy `10061`, direct `10013`; after restart `HTTP/1.1 200 OK` | runtime | **PASS: fails closed** |
| T17 | enforcer process crash-killed (`taskkill /F`) | defined | while alive: blocked; after the kill: **connected** | runtime | **OBSERVED: FAILS OPEN** |
| T18 | normal teardown | policy gone, app direct again, nothing left behind | connected again; `MProxy PoC filters: 0` | runtime | **PASS** |
| X1 | latency, selected via proxy vs direct (local server) | observation | proxy 3.2 ms vs direct 4.45 ms (same host, noise-level) | runtime | **OBSERVED** |

System side effects, snapshot before vs after the complete run: adapters, DNS, drivers, firewall
rules, routes, services, system proxy and WFP objects **all unchanged**.

## What this proves, and what it does not

**Proved at runtime:**
1. A selected application **cannot bypass** the proxy over direct IPv4 TCP or UDP, including to LAN
   and intranet ranges, across restarts, for every instance, whether or not Xray is alive.
2. Unselected applications and other paths are untouched; the policy is exactly scoped.
3. Teardown is complete: no filters, no persistent WFP objects, no system changes.

**Not proved / known gaps:**
1. **Proxy-unaware apps are not routed, they are blocked.** Only applications that honour proxy
   settings (T1) actually reach the Internet. This is a containment control, not transparent routing.
2. **DNS metadata leaks (T8).** Name resolution is performed by the Windows DNS Client service, not by
   the app's own process, so an app-path filter never sees it. The selected app's *connections* are
   blocked, but the *names it looks up* still go to the system resolver and out to the configured DNS
   server.
3. **IPv6 is unverified (T6/T7).** The filters are installed at `ALE_AUTH_CONNECT_V6`, but this machine
   has no IPv6 route, so no IPv6 connection ever left the host. This must be re-run on a v6-capable
   network before any release claim.
4. **Crash of the enforcer fails open (T17).** The WFP session is *dynamic*: BFE deletes the filters
   when the owning process dies, and the selected app is immediately direct again. That is correct
   for not leaving stale state behind, and wrong for a security guarantee.
5. **No automatic child inheritance (T13/T15).** WFP matches an executable path; there is no
   parent-process filtering condition. Children are covered only when their executable is listed
   explicitly (T14).

## The T17 fail-open problem (must be fixed before any product use)

Killing the process that owns the filters removes the protection within about a second. A future
product cannot hold the policy in a user-visible helper. Required design:

* a **service** owns the WFP session, so killing the UI or the helper changes nothing;
* the service is protected as a normal Windows service (SYSTEM-owned, stop rights to admins only);
* the UI shows **Protected** only while it can confirm with the service that the filters exist, and
  reverts to **Not protected** immediately otherwise. A stale "Protected ✓" is the failure this
  phase exists to prevent.

Even then, an administrator can stop the service. Per-app enforcement on Windows is protection
against *the application's own behaviour*, never against a local administrator.

## Enforcer terminations during elevated runs (recorded, not worked around)

Two of the elevated runs ended abruptly with exit code `0x40000015` (`STATUS_FATAL_APP_EXIT`) at the
same place: the point where the test process opens a **second** WFP session in its own lifetime
(scenario T14). No Rust panic was logged, and no Windows Error Reporting event was created.

Investigated and ruled out as the cause:

| Hypothesis | Finding |
|---|---|
| double close / handle reuse | the engine handle is closed once, in `Drop`; a taken session is replaced by an error marker so it cannot drop twice |
| stale objects from the first session | the trace shows every filter deleted, the sublayer deleted and `FwpmEngineClose0 = 0x0` before the second open |
| FFI pointer / SD lifetimes | all buffers outlive their calls; the app-id blobs are freed with `FwpmFreeMemory0` and the security descriptor with `LocalFree`, both after the engine closes |
| transaction teardown order | no WFP transactions are used |
| cleanup ordering | filters → sublayer → engine, which is the documented order |
| **lifecycle defect in general** | the `--wfp-cycle 3` diagnostic opened, applied and closed three complete sessions **in one elevated process**, all returning `0x0`, leaving 0 objects, exit code 0 |

What remains: Kaspersky Endpoint Security logged event 4662 against this binary at the exact second
of one termination, and a later identical run of the same binary completed normally with exit code 0.
That pattern — intermittent, external, no in-process fault, correlated with an EDR event — is
**consistent with termination by endpoint security**, and it is *not proven*; the security product's
own logs would be needed to confirm it.

No evasion was attempted and none should be: an unsigned, self-built binary that opens firewall
sessions from an elevated process is exactly what an EDR should look at twice. The remedy for the
product is Authenticode signing with a reputable certificate, plus IT allowlisting of the service and
helper (F12) — the same conclusion as [per-app-routing-corporate-impact.md](per-app-routing-corporate-impact.md).

**This did not affect T1–T13**, which completed in earlier runs and again in the complete run, with
identical results in both.

## Sources

* [Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-) (`ALE_APP_ID`, `ALE_USER_ID`; no parent-process condition)
* [FWPM_SESSION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0) (dynamic sessions and automatic object removal)
* [ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
