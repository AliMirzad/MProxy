# Track B: true per-app routing with a WFP callout driver (feasibility)

**Status: RESEARCH ONLY, DEFERRED. No driver was built or run. Phase 7.5 outcome below.**

This workstation:
* has no Windows Driver Kit or Visual Studio;
* is a company machine with Secure Boot, Kaspersky and no test-signing, and those settings stay as they are.

Loading any development driver here would require either changing those settings (forbidden) or
Microsoft-signed binaries (not available). All sources are Microsoft Learn, retrieved 2026-09-22.

## Question

```text
proxy-unaware selected app ──connect()──► WFP ALE_CONNECT_REDIRECT callout (kernel)
                                             │ rewrites destination → 127.0.0.1:<redirector>
                                             ▼
                                   local redirector (user mode, ours)
                                             │ reads original destination (redirect context)
                                             ▼
                                   Xray (restricted, pinned) ──VLESS/VMess──► server
unselected apps ──► untouched
```

## What Windows provides (documented facts)

| Topic | Fact | Source |
|---|---|---|
| Layers | `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` rewrite remote address/port for one connection; `ALE_BIND_REDIRECT_V4/V6` rewrite the local address for a socket. Windows 7+ | ALE layers; Using bind or connect redirection |
| Kernel only | Redirection is done in a callout's `classifyFn` (registered with `FwpsCalloutRegister1`+) using `FwpsAcquireClassifyHandle0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0` | Using bind or connect redirection |
| Local proxy | Windows 8+: `FwpsRedirectHandleCreate0` handle in `localRedirectHandle`; proxy PID in `localRedirectTargetPID`; original destination in `localRedirectContext` | same |
| Proxy side (user mode) | on the accepted socket: `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` (original destination) and `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS`; on the proxy's outbound socket: `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`. Windows 8+ | SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS |
| Loop prevention | `FwpsQueryConnectionRedirectState0`: `REDIRECTED_BY_SELF` → permit; `PREVIOUSLY_REDIRECTED_BY_SELF` → must not redirect again. Redirect records link the proxied connection to the original | Using proxied connections tracking |
| Original app identity | `ALE_ORIGINAL_APP_ID` is the originating app of a proxied connection | Using proxied connections tracking |
| Protocols | redirection supports TCP, UDP, raw UDPv4 (no header include), raw ICMP | Using bind or connect redirection |
| UDP caveat | connected UDP (`connect` + `send`) redirected to a local proxy is **dropped**; only `sendto` works (Microsoft troubleshooting article) | Failed to redirect connected UDP traffic |
| Classification data | app path (`ALE_APP_ID`), user (`ALE_USER_ID`), package SID; the process ID is available as classify metadata in the kernel; **no parent-process condition** | Filtering condition identifiers |

## Signing and release chain (the real process)

| Stage | What loads it | Requirements |
|---|---|---|
| Developer build on a dev/test VM | a VM with test-signing enabled (VM only; never this workstation) **or** a VM provisioned for **preproduction signing** (Secure Boot stays on) | WDK + Visual Studio; preproduction signing needs Hardware Dev Center access and device provisioning |
| **Attestation-signed** driver | Windows 10/11 desktop with Secure Boot | Hardware Developer Program + **EV code-signing certificate** + CAB submission. Microsoft (docs dated 2026-03/04) describes attestation signing as **"for testing purposes only"**, not Windows Certified, not publishable to Windows Update for retail; WDAC policies may require more |
| **Production** (Windows-certified) driver | all supported Windows client/server | **HLK testing** (Hardware Lab Kit) + dashboard submission (Windows Hardware Compatibility Program), EV certificate for the account |
| Enterprise | WDAC can require at least attestation signing; IT may add its own policy | IT decision |

"Sign the driver" therefore means:
1. Buy an EV certificate (hardware token, organisation validation).
2. Register a Partner Center hardware account.
3. For production, pass the HLK tests for a WFP callout driver.
4. Submit, then let Microsoft re-sign.

In addition, the user-mode helper/service/redirector need Authenticode signing, and EDR allowlisting (F12) applies to all of them.

## Minimal architecture

| Component | Mode | Responsibility | Must NOT contain |
|---|---|---|---|
| `mproxy-wfp.sys` | kernel | callout at `ALE_CONNECT_REDIRECT_V4/V6` + `ALE_AUTH_CONNECT_V4/V6`; match (app path + user SID + target list pushed by the service); redirect TCP to `127.0.0.1:<redirector>` with the original destination in the redirect context; BLOCK everything else of a selected app that cannot be redirected (UDP, IPv6 if unsupported); loop check via redirect state | protocols, JSON, subscriptions, credentials, UI, HTTP, file I/O beyond its own config |
| routing service | user, LocalSystem | the only client of the driver's IOCTL; validates targets (path + Authenticode signer + user SID); owns the policy lifetime; fixed command set | command execution, arbitrary rules, arbitrary files/registry |
| redirector | user, **not** SYSTEM | accepts redirected sockets, reads `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, forwards to Xray's authenticated SOCKS/HTTP inbound with the original destination; sets redirect records on its outbound socket | anything else |
| Shared Core + Xray | user | unchanged (profiles, config, restricted Xray) | — |

Service IPC (named pipe, ACL: the interactive user plus SYSTEM):
* `SetPolicy(targets[])`: each target `{ canonical path, signer thumbprint, user SID }`, validated by the service;
* `ClearPolicy()`;
* `QueryState()`.

Nothing else.

Loop prevention, in order:
1. Redirect state (`PREVIOUSLY_REDIRECTED_BY_SELF`).
2. Exclude the redirector's and Xray's PIDs via the redirect records on the proxied socket.
3. Never select our own executables: the service refuses targets under the product install directory, checked by signer, not only by path.

## Requirement by requirement

| Requirement | Achievable with W1? | Notes |
|---|---|---|
| TCP IPv4 / IPv6 | **yes (design)** | both redirect layers exist; NOT TESTED |
| UDP | **not realistically, for now** | connected UDP to a local proxy is dropped by Windows (documented); QUIC and many apps use connected UDP. Plan: **BLOCK** selected apps' UDP, so apps fall back to TCP (QUIC falls back to HTTP/2). UDP support deferred |
| DNS | **metadata leak remains** unless an extra component | lookups are made by the DNS Client service (runtime evidence T8), so an app-path callout never sees them. Options: (a) accept and document; (b) DNS policy per app is impossible without a DNS component; (c) system-wide DNS proxy (global change, rejected) |
| IPv6 fail-closed | yes | block V6 if V6 redirect is not implemented |
| Other users | yes | match `ALE_USER_ID` / token SID in the callout |
| `include_children` | **only via user-mode process tracking** | no parent condition; the driver can receive process-creation notifications (`PsSetCreateProcessNotifyRoutineEx`), or the service adds child executables explicitly. Race: a child connecting before it is classified. Explicit executable lists are reliable; unbounded trees are not wanted (Phase 7 C3) |
| Process start race | yes, with **launch-through-MProxy** or path-based policy active before launch | a path-based rule applies from the first connect of any instance. PID-based policies have a race; launching the app from MProxy after the policy is active avoids it |
| Fail closed | yes (design) | if the redirector or Xray is down, redirected connects fail (connection refused), never direct. If the service dies, the driver keeps its last policy (configurable). If the driver fails to load, the service must refuse to report "protected" |
| No stale state | design | policy in driver memory only (cleared on unload/reboot), no persistent WFP objects |

## Performance

NOT TESTED. WFP redirection adds a kernel classification at connect time plus one extra loopback hop.
Track A measured the loopback proxy hop at about +1 ms per request against a local server.

## Feasibility verdict

* **Technically:** feasible for TCP IPv4/IPv6 using documented, supported APIs. This is the architecture
  used by commercial per-app proxy tools on Windows.
* **UDP:** block, don't route. **DNS:** metadata leak unless extra work.
* **Operationally expensive** for this product. It needs:
  * an EV certificate;
  * a Partner Center hardware account;
  * HLK certification for production (attestation is test-only per current docs);
  * kernel-driver development and review;
  * a VM test lab (preproduction signing or test-signing inside the VM only);
  * IT approval of a new kernel driver (EDR scrutiny);
  * ongoing maintenance per Windows release.
* **Not validated at runtime** anywhere in this project (ENVIRONMENT UNAVAILABLE).

## Phase 7.5 outcome: deferred, not rejected

Track A's elevated validation ([windows-routing-validation.md](windows-routing-validation.md)) settled
what user-mode WFP can and cannot do, and that fixes this document's role: **Track B is the only way
to reach "select any application and have it transparently proxied".** It remains unbuilt.

| Question | Answer after Phase 7.5 |
|---|---|
| Is the driver required for the full product? | **Yes.** Track A blocks proxy-unaware applications; it never routes them |
| Is the driver required for a limited V1? | **No.** The chosen OPTION 2 ships protection without any driver |
| Was any driver built or loaded? | **No.** No WDK, no test machine; the workstation's Secure Boot, signing policy and EDR stay untouched |
| Would it solve DNS? | **No.** Name resolution happens in the DNS Client service; a connect-redirect callout sees only resolved addresses |
| Would it solve UDP? | **No.** Connected UDP redirected to a local proxy is dropped by Windows (documented); the plan is to block UDP for selected apps |
| What does it cost to even try? | EV certificate, Partner Center hardware account, HLK-tested submission, a VM lab, kernel development and review, IT driver approval, maintenance per Windows release |

Before any Phase 7b spike is funded, the VM test plan below must run to completion in a disposable
VM, and the driver must be exercised with Driver Verifier. Nothing about that work belongs on a
company workstation.

## VM test plan (for a future Phase 7b, not executed)

1. A disposable Windows 11 VM (Hyper-V/VMware), no company data, snapshot before each run.
2. Either enable test-signing **inside the VM only**, or provision the VM for preproduction signing (Secure Boot stays on).
3. Build the minimal callout from Microsoft's WFP sample (`ClassifyFunctions_ProxyCallouts.cpp`) with WDK.
4. Run the same Track A matrix plus:
   * a proxy-unaware client redirected to the redirector → Xray → test server (`probe.test` ground truth);
   * control direct;
   * IPv6 via a VM-internal IPv6 network;
   * UDP blocked;
   * redirector / Xray / service kill → fail closed;
   * driver unload → no stale policy;
   * Driver Verifier on.
5. Measure connect latency and CPU with/without the callout.
6. Record which EDR (if any) flags the driver in a corporate-like VM image.

## Sources

* [ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
* [Using bind or connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
* [Using proxied connections tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking)
* [SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-records)
* [Failed to redirect connected UDP traffic](https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/redirection-connected-udp-traffic-local-proxy-fail)
* [Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
* [Driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
* [Driver signing options (attestation for testing only; HLK; preproduction)](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)
* [Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
