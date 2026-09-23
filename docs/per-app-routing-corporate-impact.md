# Per-application routing: corporate impact

What each candidate mechanism would introduce on a company workstation, and what IT would have to
approve. Nothing in Phase 7 evades or modifies endpoint security. The status of each mechanism is in
[per-app-routing-decision.md](per-app-routing-decision.md).

## What IT would see

| Mechanism | New on the machine | Visible to EDR / IT as | Signing / approval needed |
|---|---|---|---|
| **W6 app-configured** (PoC, EXPERIMENTAL) | nothing: selected apps are started with proxy flags/environment | child processes with proxy environment variables; loopback connections | helper signing as today (F12) |
| **W5 WFP fail-closed filters** (PoC, EXPERIMENTAL) | WFP sublayer + PERMIT/BLOCK filters (dynamic: exist only while the owner runs); in production a **Windows service** running as LocalSystem or with Network Configuration Operators rights | WFP filter changes (visible in `netsh wfp show filters`, Windows event auditing if "Filtering Platform Policy Change" is enabled); a new service | Authenticode-signed service; IT approval of a network-policy service; install requires admin |
| **W1 WFP callout driver** (RESEARCH ONLY) | kernel-mode driver + service + WFP callouts/filters | **new kernel driver**: highest scrutiny; EDR products inspect drivers that redirect traffic | **EV code-signing certificate** + Microsoft Hardware Dev Center signing: HLK-tested for production (attestation is documented as testing-only since the 2026 docs; see Phase 7.5); IT driver approval; WDAC/HVCI compatibility |
| W2 WinDivert (rejected) | third-party packet driver | packet-capture driver commonly associated with malware/cheats | vendor-signed; likely blocked by corporate EDR policy |
| W3 TUN (rejected) | virtual adapter, default route and DNS changes | new network adapter; routing table changes | vendor-signed Wintun; IT approval of a VPN-like client |
| macOS `NETransparentProxyProvider` (RESEARCH ONLY) | system extension + transparent proxy configuration | System Settings → Network Extensions entry; MDM can pre-approve | Apple Developer Program, NE entitlement, Developer ID signing, notarization |

## Privileges

| | Install | Run a session | Add/remove a selected app | Stop routing |
|---|---|---|---|---|
| W6 | none | normal user | normal user | normal user |
| W5 (production design: service) | admin | normal user (via service) | normal user (service validates the target) | normal user |
| W5 (PoC tool, measured) | none | **admin required**: `FwpmSubLayerAdd0` → `ERROR_ACCESS_DENIED` for a normal user | admin | closing the process removes everything |
| W1 | admin | normal user (via service) | normal user (via service) | normal user |

Intended outcome, which W1/W5 would meet with a service: **install needs elevation, normal runtime
does not**. That is not verified (no service built in Phase 7).

## Privileged service requirements (if W5 or W1 is built)

The service must not become a generic privileged control plane. Allowed:
* apply/remove the routing policy for **validated** targets (canonical path + publisher signature);
* report status.

**Forbidden** (and absent from the design):
* executing commands, starting arbitrary processes;
* injecting into processes;
* adding arbitrary WFP/firewall rules;
* arbitrary registry or file writes;
* driver control beyond its own driver.

The caller is authorized by the service's own IPC ACL (the interactive user who owns the session).
Its filters are scoped to that user (`ALE_USER_ID`), so one user cannot route or block another user's apps.

## Recommendation to IT

* W6 alone is **not** a security control. It leaks by design for non-cooperating apps, UDP and DNS.
* W5 gives a real guarantee: selected apps are either proxied or blocked, never direct. It uses
  documented user-mode APIs, needs no driver, and needs a signed, narrowly scoped service.
* W1 is the only way to route apps that have no proxy support. It is a kernel driver and needs a
  Microsoft-signed build and a driver approval process.
* In all cases the product binaries must be signed and allowlisted (F12). Extension deployment stays
  managed (F7, [managed-deployment.md](managed-deployment.md)).

## Phase 7.5 update: what IT would need for each Windows mode

Evidence: [windows-routing-validation.md](windows-routing-validation.md) (Track A) and
[wfp-driver-feasibility.md](wfp-driver-feasibility.md) (Track B).

| Item | Limited protected-app mode (Track A) | True per-app routing (Track B) |
|---|---|---|
| Kernel driver | no | **yes**: a WFP callout driver |
| Driver signing | — | EV certificate + Partner Center hardware account; **HLK-tested submission for production** (Microsoft documents attestation signing as testing-only, not Windows-certified) |
| Windows service | yes (holds WFP filters; LocalSystem or Network Configuration Operators) | yes (the only driver client) |
| Admin install | yes | yes |
| Admin at runtime | no (via service) | no (via service) |
| Signed binaries | helper, service (Authenticode) | helper, service, redirector, driver (Microsoft-signed) |
| EDR allowlisting | helper, service, Xray hash | the same, plus **driver approval** |
| Visible system change | WFP filters of our sublayer | WFP callouts + filters; a kernel driver |
| Managed browser extension | still required if browser mode is also used (F7) | same |

None of this is approved by IT. Both modes are designs with evidence levels given in the documents above.

## Phase 8 update: what IT would see with the driver

Once the driver exists, "no system changes" stops being true, and the documentation must say so
plainly ([phase8-driver-poc.md](phase8-driver-poc.md), section 40 of the phase brief):

> No global route, proxy or DNS changes; **one Microsoft-signed kernel driver and one Windows service installed**.

| What is installed | Visible to IT/EDR as | Approval needed |
|---|---|---|
| `mproxy-wfp.sys` | a new kernel driver that redirects network connections; device restricted to SYSTEM/Administrators | Microsoft (HLK) signature + IT driver approval |
| routing service | a Windows service holding WFP filters and callout filters | Authenticode signature + allowlisting |
| redirector | a user-mode process listening on loopback | Authenticode signature |
| WFP objects | our sublayer with BLOCK/PERMIT filters plus callout filters | visible in `netsh wfp show filters` |
| helper + Xray | unchanged from today | unchanged |

Nothing is hidden, nothing is obfuscated, and no evasion technique is used anywhere in this design.
The Phase 7.5 experience (an unsigned test binary terminated by endpoint security) is the reason
signing and allowlisting come before any pilot.

## Phase 8.5 note: the test environment IT would have to allow

Validating the driver needs a machine where **CPU virtualization is enabled in firmware** and a
disposable VM can run. On this workstation `VirtualizationFirmwareEnabled` is `False` and no
hypervisor is installed, so the work cannot happen here without an IT firmware change - which is a
security-relevant setting and therefore an IT decision, not something to be worked around locally.
The alternative is a personal or lab machine that never holds company data.
