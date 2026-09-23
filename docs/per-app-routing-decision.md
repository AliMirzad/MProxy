# Per-application routing: decision record (Phase 7)

**Question:** Can Private Proxy safely and maintainably proxy arbitrary selected desktop applications
while leaving the rest of the system direct?

**Phase 7.5 (2026-09-23) validated Track A at runtime with administrator rights and settled this
decision. Read section 14 first; sections 1-13 are the Phase 7 record that led to it.**

**Short answer:**
* On Windows, **true per-process routing needs a WFP connect-redirect kernel callout driver**
  (Microsoft-signed, EV certificate, admin install). That could not be built or validated on this
  machine: **ENVIRONMENT UNAVAILABLE**.
* Everything that works **without** a driver is either app-configured (and demonstrably leaks), or
  enforcement-only (it can block, not route).
* On macOS, the supported route is a `NETransparentProxyProvider` system extension (entitlement,
  Developer ID, user approval): **RESEARCH ONLY**, no Mac available.
* Recommendation for Phase 8: **CONDITIONAL** (see the end).

Sources and candidate details: [windows-per-app-routing-research.md](windows-per-app-routing-research.md),
[macos-per-app-routing-research.md](macos-per-app-routing-research.md). PoC code (EXPERIMENTAL, never
shipped): `experimental/per-app-routing-poc/`.

## 1. Requirements

* Selected applications (e.g. ChatGPT, Claude, Cursor, IntelliJ + children) → Xray → server; everything else DIRECT.
* Must work for applications **without** proxy settings.
* No change to the system proxy, default route, global DNS, adapters or browser settings.
* No silent bypass for selected apps (IPv4/IPv6, TCP/UDP, DNS), fail-closed option, clean removal.
* Phase 5 protections stay: authenticated loopback listeners, restricted Xray, no generic privileged API.

## 2. Windows candidates

| # | Mechanism | Class | Verdict |
|---|---|---|---|
| W1 | WFP ALE connect-redirect **callout driver** + local proxy service | TRUE PER-PROCESS ROUTING | **only supported true per-process option**; ENVIRONMENT UNAVAILABLE here |
| W2 | WinDivert packet NAT | per-process (packet level, racy) | rejected: admin at runtime, EDR-flagged third-party driver |
| W3 | TUN (Wintun) + user-mode stack dispatching by process | SYSTEM-WIDE TUNNEL WITH PROCESS DISPATCH | rejected as primary: global routes/DNS, all traffic through our process |
| W4 | Windows VPN platform + app traffic filters | interface filter | rejected: filters only permit/deny on the VPN interface; needs a packaged plug-in / MDM |
| W5 | user-mode WFP filters (no driver) | ENFORCEMENT ONLY | **kept** as the fail-closed layer |
| W6 | app-configured proxy (environment, `--proxy-server`) | APP-CONFIGURED PROXY | measured; **not routing**, leaks |
| W7 | DLL injection / hooking / LSP | — | rejected by project rule |

## 3. macOS candidates

| Mechanism | Status |
|---|---|
| `NETransparentProxyProvider` system extension, per flow by source app signing identity | **POSSIBLE WITH ENTITLEMENT**, best candidate |
| Per-app VPN (app rules) | **POSSIBLE ONLY IN MANAGED ENVIRONMENT** (MDM, managed apps) |
| Packet tunnel + dispatch | UNSUITABLE (system-wide) |
| Content filter | enforcement only |
| Anything without Developer ID + entitlement | UNSUITABLE |

## 4. Security comparison

| | W1 callout driver | W3 TUN | W5 WFP filters | W6 app-configured |
|---|---|---|---|---|
| New kernel code | **yes (ours)** | 3rd-party driver | no | no |
| Unselected traffic touches our code | no | **yes, all of it** | no (kernel filter match only) | no |
| Silent bypass for selected apps | no, if UDP/DNS are also handled | no | **no (blocked)** | **yes (measured)** |
| Local listener exposure | transparent inbound (loopback) | TUN | none | authenticated inbound; env credentials |
| Privileged component | driver + service | service | service (or elevated tool) | none |
| Crash leaves state | driver/filters persist unless session-scoped | routes/DNS may stay changed | **no (dynamic session)** | no |

## 5. Deployment comparison

| | W1 | W3 | W5 | W6 |
|---|---|---|---|---|
| Admin install | yes | yes | yes (service) | no |
| Admin runtime | no (service) | no (service) | no (service) | no |
| Signing beyond the helper | **EV cert + a Microsoft-signed driver: HLK-tested submission for production** (attestation signing is documented as testing-only) | none | none | none |
| What IT sees | new kernel driver + service + WFP objects | TUN adapter, route/DNS changes | WFP filters from a service | nothing |

## 6. Chosen Windows PoC mechanism and why

W1 is the right production candidate. It cannot be exercised here:
* kernel drivers need Microsoft signing or test-signing mode, which is a machine security setting and out of scope;
* this session has no Administrator shell.

The PoC therefore tests the two driver-free building blocks honestly:
* **W6 app-configured proxy** against a synthetic client and real third-party programs, to measure where it works and where it leaks;
* **W5 user-mode WFP enforcement** (dynamic session, per executable and per user). The code is present; non-admin denial is runtime-verified; the enforcement itself requires an elevated run by the user.

Both attach at the Phase 6 seam as `ApplicationRoutingProvider` implementations, using the real
Shared Core session (debug build) and its authenticated local inbound.

## 7. Rejected alternatives and reasons

* **W2** (WinDivert): third-party packet driver loaded on demand, Administrator needed whenever it runs, and commonly flagged by EDR.
* **W3** (TUN + dispatch): changes default route and DNS globally, puts every unselected app's traffic through our process, and a crash can leave the machine's routing broken. It is "system-wide with exclusions", not per-app.
* **W4** (VPN platform): not per-app routing (interface permit/deny); needs a restricted-capability packaged plug-in or MDM.
* **W7** (injection/hooks/LSP): host-compromise risk, EDR alerts, unmaintainable; forbidden.

## 8. PoC results (Windows, 2026-09-22, `poc-harness`, non-elevated)

Ground truth: `probe.test` resolves **only** in the test server's DNS. A request that reaches
`http://probe.test:<port>/` went through Xray and the server; a direct attempt fails name resolution.
Direct attempts to documentation addresses (TEST-NET 192.0.2.1, 2001:db8::1) show whether traffic
leaves directly (timeout/unreachable = attempted; `WSAEACCES` 10013 = blocked locally).

| ID | Scenario | Expected | Observed | Status |
|---|---|---|---|---|
| S1 | selected app that honours proxy env → probe.test | PROXY | `200` via proxy | PASS: RUNTIME VERIFIED |
| S2 | same executable, started normally | DIRECT | name not resolvable | PASS: RUNTIME VERIFIED |
| S3 | control → direct test server | DIRECT | `200` direct | PASS: RUNTIME VERIFIED |
| S4 | selected app **without** proxy support | not direct | resolved locally, went direct | **FAIL: silent direct bypass** |
| S5 | selected app direct IPv4 TCP | blocked | SYN sent (timeout) | **FAIL: not blocked** |
| S6 | selected app direct IPv6 TCP | blocked | attempted; failed only because this machine has no IPv6 route | **FAIL: not blocked** |
| S7 | selected app UDP (QUIC/DNS-like) | blocked or proxied | datagram sent directly | **FAIL** |
| S8 | selected app system-resolver lookup | no local lookup | lookup attempted (the query leaves via the DNS Client service) | **FAIL** |
| C1 | child (honours env) of selected app | PROXY | `200` via proxy (env inherited) | PASS: RUNTIME VERIFIED |
| C2 | child without proxy support | defined | direct | **FAIL** |
| C3 | NEGATIVE: selected → `cmd.exe` → `curl.exe` (unrelated) | not proxied | **proxied** (`200`): environment inheritance reaches unrelated tools | **FAIL** |
| P1 | selected app restarted through the launcher | PROXY | `200` | PASS: RUNTIME VERIFIED |
| P2 | second instance started outside the launcher | defined | DIRECT: selection is per launch, not per executable | OBSERVED |
| L1 | selected app → 127.0.0.1 (`NO_PROXY`) | DIRECT | `200` direct | PASS: RUNTIME VERIFIED |
| L2 | selected app → 10.255.255.1 (private) | defined | sent to the proxy; Xray dials private literals directly (product rule), timeout | OBSERVED |
| R1 | `curl.exe` (Windows) selected | PROXY | `200` | PASS: RUNTIME VERIFIED |
| R2 | `curl.exe` control | DIRECT | `000` (unresolvable) | PASS: RUNTIME VERIFIED |
| R3 | `node.exe` fetch, env (default) | PROXY | `ENOTFOUND`: Node ignores the proxy env | **FAIL: silent bypass** |
| R4 | `node.exe --use-env-proxy` | PROXY | `200` | PASS: RUNTIME VERIFIED |
| R5 | Chromium app (Brave, the class Electron apps belong to) with `--proxy-server` to the authenticated inbound | PROXY | `ERR_INVALID_AUTH_CREDENTIALS`: reached our proxy, cannot answer 407; control: `ERR_NAME_NOT_RESOLVED` | **FAIL: cannot authenticate** |
| F1 | Xray killed while selected app active | fail, then recover | connection refused during restart; `200` after automatic restart | PASS: RUNTIME VERIFIED (only for apps that honour the proxy) |
| F2 | routing stopped, app still configured | fails closed | connection refused | PASS: RUNTIME VERIFIED |
| F3 | helper (Core + Xray) crash-killed (`taskkill /F`) | selected app fails closed; no orphans | refused after the kill; no orphan Xray (job kill-on-close) | PASS: RUNTIME VERIFIED |
| W1 | WFP enforcement as a normal user | admin needed | `FwpmSubLayerAdd0: ERROR_ACCESS_DENIED` | PASS: RUNTIME VERIFIED (privilege boundary); **enforcement NOT TESTED** |
| X1 | request latency inside the client (loopback test server) | observation | proxied 5.9 ms vs direct 3.2 ms; launcher 735 ms per launch (debug-build re-hash of the executable) | OBSERVED |
| — | system side effects (proxy, routes, DNS, adapters, firewall rule count, drivers, services) | unchanged | **all unchanged** before vs after | PASS: RUNTIME VERIFIED |

What the PoC does **not** show:
* true per-process routing of an app without proxy support (needs W1);
* the WFP enforcement behaviour (needs an elevated run, see `experimental/per-app-routing-poc/README.md`);
* a public-IP change through a real server (NOT TESTED: no real server);
* sleep/wake and network changes (NOT TESTED);
* reboot persistence (not applicable to W5/W6: nothing persistent is created).

## 9. Findings in detail

### TCP / UDP / IPv6
* **TCP:** app-configured routing works only for cooperating apps (S1, R1, R4). Non-cooperating apps go direct (S4, R3).
* **UDP:** never covered by app-configured HTTP/SOCKS settings (S7). QUIC/HTTP-3, WebRTC, DNS, VoIP go
  direct unless blocked. W1 has a documented limitation for connected UDP to a local proxy. W5
  `ALE_AUTH_CONNECT` sees the first UDP packet per remote and can block it.
* **IPv6:** a selected app attempts IPv6 directly (S6). Any production mechanism must redirect or block
  `ALE_*_V6` as well. W5's filters cover V4 and V6.

### DNS
* An app that sends hostnames to the proxy (HTTP CONNECT / absolute URI / SOCKS5h) gets remote DNS (S1: `probe.test` resolved by the server).
* Apps that call the system resolver first (S4, S8) disclose the name to the local/company DNS before
  any interception. W1 sees only the resolved IP at connect time.
* Name lookups through `getaddrinfo` are performed by the **DNS Client service** (`svchost`, Dnscache), not
  by the app's process, so per-app WFP filters cannot block the app's DNS leak.
  **PASS: CODE REVIEW ONLY** (Windows resolver architecture); not measured here.
* Production needs one of:
  * accept the leak (document it);
  * a W1 driver that also redirects UDP/53 and DoH endpoints of the selected app;
  * name-based routing (the app talks to a proxy).

### Child processes
* WFP conditions have **no parent/process-tree condition**. `ALE_APP_ID` is a path, so each child
  (node.exe, git.exe, java.exe) is matched only if its own path is selected.
* A W1 driver can implement tree policies via kernel process-creation notifications.
* Environment-based configuration propagates to **all** descendants, including unrelated tools started from a shell (C3), while children that ignore the environment go direct (C2).
* Policies for a production decision:

| Policy | Behaviour | Risk |
|---|---|---|
| `DIRECT_CHILDREN_ONLY` | only immediate children | misses `IDE → gradle daemon → java` chains |
| `PROCESS_TREE` | all descendants | IDE → terminal → unrelated program gets proxied (C3 shows it happens) |
| `KNOWN_TOOLCHAIN_CHILDREN` | descendants whose executable is on a vendor list (git, node, java…) | list maintenance; a known tool is also used by unrelated work |
| `EXPLICIT_EXECUTABLE_ALLOWLIST` | each executable selected individually (path + signer) | UX burden; the only one W5 can express today |

  No production policy is selected. Evidence so far favours `EXPLICIT_EXECUTABLE_ALLOWLIST`
  (+ optionally `KNOWN_TOOLCHAIN_CHILDREN` with W1), never unbounded `PROCESS_TREE`.

### Application identity (Windows)
* What WFP matches: `ALE_APP_ID`, the lower-case device path. **Every** process of that path matches
  (all instances, restarts), scoped per user with `ALE_USER_ID`. There is no PID-level selection
  with user-mode WFP.
* **Spoofing / TOCTOU:** per-user installs (Cursor, Claude Desktop, ChatGPT live under `%LOCALAPPDATA%`)
  are writable by the user, so any same-user program can replace the executable at the selected path
  and inherit the selection. A hash binding breaks at every auto-update.
* **Production requirement:** bind to path **and** Authenticode publisher (`WinVerifyTrust` + signer
  subject/thumbprint), re-verified when the service sees a new process of that path. The file identity
  (volume + file ID) catches swaps between checks. The PoC binds path + SHA-256 and re-checks before each
  launch (window remains).
* Package identity (`ALE_PACKAGE_ID` / package family name) is robust for MSIX-packaged apps.

### Fail-closed vs fail-open
* App-configured apps **fail closed when our endpoint disappears** (F1–F3): they get "connection refused", not direct.
* Their non-cooperating traffic (UDP, direct sockets, non-honouring children) is **always open**.
* Real fail-closed for a selected app requires W5 (or W1 with block-on-no-proxy). Then:
  * Xray down → selected app has loopback only;
  * provider down → dynamic filters vanish, so it **fails open** unless the filters are persistent and
    owned by a service (trade-off: stale state after crashes);
  * app started before routing → blocked by `prepare` (filters exist before Xray starts);
  * sleep/wake and network change → filters are not tied to interfaces, so expected to survive (**NOT TESTED**).

### Multi-user
* WFP filters are machine-wide objects. The PoC scopes them to the current user with `ALE_USER_ID`, so the
  same executable run by another user is not affected (code; **NOT TESTED** here, single-user machine).
* A W1 driver must apply the same scoping.

### Loopback and private networks
* Loopback must stay direct for selected apps (local dev servers). Measured with `NO_PROXY` (L1); W5 permits loopback.
* Private ranges: an app-configured app sends them to the proxy, and the product's Xray config dials
  private literals directly (L2), i.e. from the machine, not through the server.
* This needs an explicit product decision (corporate intranet vs. strict tunnelling); it is not decided here.

## 10. Routing lifecycle and session semantics

Proposed order, fail-closed first:

```text
Validate targets (path, signer/hash)          RoutingInactive
      ↓
Prepare provider: BLOCK selected apps          Preparing   (selected apps now have loopback only)
      ↓
Start Xray, verify through the server          (session Starting / Verifying)
      ↓
Activate: permit/redirect selected → inbound   Active
      ↓
Verify routing (a probe from the selected identity, or provider self-check)
      ↓
READY: session Connected
```

Stop: deactivate (redirect off, keep BLOCK while tearing down) → stop Xray → remove BLOCK (or keep, if
policy says "blocked while disconnected").

Phase 6 API adjustment needed for Phase 8 (not done in Phase 7):
* `SessionState::Connected` must mean "Xray healthy **and** routing provider Active **and** policy
  applied". The Core would gain a routing sub-state (`Inactive / Preparing / Active / Deactivating /
  Failed`) and call the provider inside `start_session` / `stop_session` / crash handling.
* `RuntimeCapabilities.application_routing` stays `false` until a provider is verified on the machine.

## 11. Known limitations (of what exists)

* No true per-process routing on any platform (driver / system extension not built).
* App-configured routing leaks: UDP, IPv6, local DNS, non-cooperating apps and children.
* Chromium/Electron apps cannot use the authenticated inbound without app code (R5). Giving them an
  unauthenticated inbound would reopen Phase 5's F5, unless the inbound is restricted by WFP to the
  selected app and user (design option: BLOCK `connect 127.0.0.1:<port>` for every app ≠ selected;
  **NOT TESTED**, needs admin).
* Environment credentials are visible to every descendant and to same-user processes.
* WFP enforcement is untested beyond the privilege check.

## 12. Recommendation for Phase 8

**Is the Phase 7 PoC mechanism suitable as the basis for the Phase 8 desktop client? NO as is,
CONDITIONAL for a restricted design:**

* **NO** for "arbitrary applications" using app-configured proxying alone. It silently bypasses (S4, S7,
  R3, C2), proxies unrelated children (C3), and cannot authenticate Chromium apps (R5).
* **CONDITIONAL: "Protected applications" without a driver (W5 + W6).** Selected apps either use the proxy
  or are **blocked** (never leaked), via a narrowly scoped privileged Windows service holding WFP filters.
  Conditions:
  1. an elevated validation run of W5 on a test machine (enforcement, IPv6, UDP, other users, sleep/wake);
  2. an admin-installed service with a fixed command set (apply/remove policy for validated targets; nothing else);
  3. publisher-signature binding of targets;
  4. a WFP-restricted per-app inbound, so Chromium/Electron apps can connect without credentials but only they can;
  5. the UX states plainly: apps that do not support a proxy lose network access instead of being routed;
  6. DNS leak for apps that resolve locally is documented;
  7. signed helper + service and IT allowlisting (F12).
* **CONDITIONAL: true per-app routing (W1 WFP callout driver).** Prerequisites before Phase 8:
  1. EV certificate + a Partner Center hardware account, and HLK testing for a production-signed driver (attestation signing is testing-only per the current Microsoft docs);
  2. driver design and security review (redirect loop handling, UDP/DNS policy, crash behaviour);
  3. a signed test environment (VM);
  4. IT acceptance of a kernel driver on company machines.
  A time-boxed **Phase 7b spike** should validate W1 in a VM before Phase 8 depends on it.
* **macOS:** `NETransparentProxyProvider` with Developer ID + entitlement; validate on a real Mac first.

## 13. Minimum interface Phase 8 should consume (if a condition above is met)

```rust
// Core-owned intent; platform-owned mechanism. No generic firewall or process API.
pub struct ApplicationTarget {
    pub stable_id: String,
    pub display_name: String,                  // sanitized (F11)
    pub executable: PathBuf,                   // canonical
    pub publisher: Option<PublisherIdentity>,  // Authenticode signer / macOS Team ID
    pub children: ChildPolicy,                 // ExplicitOnly | KnownToolchain (no unbounded tree)
}
pub struct ApplicationRoutingPolicy { pub targets: Vec<ApplicationTarget>, pub failure_mode: FailureMode }

pub trait ApplicationRoutingProvider {
    fn capabilities(&self) -> ProviderCapabilities;              // measured: redirects? enforces? needs cooperation?
    fn prepare(&mut self, policy: &ApplicationRoutingPolicy) -> Result<(), CoreError>;  // fail-closed first
    fn activate(&mut self, inbound: &LocalInbound) -> Result<(), CoreError>;
    fn state(&self) -> RoutingState;                             // Inactive | Prepared | Active | Failed
    fn deactivate(&mut self) -> Result<(), CoreError>;           // idempotent; also called on crash recovery
}
```

The experimental implementation of this seam is in `experimental/per-app-routing-poc/src/lib.rs`.

## 14. Phase 7.5 decision (final)

Evidence: [windows-routing-validation.md](windows-routing-validation.md) (Track A, complete elevated
run 2026-09-23) and [wfp-driver-feasibility.md](wfp-driver-feasibility.md) (Track B, research only).

### 14.1 What the elevated run changed

Phase 7 left W5 enforcement unverified ("admin needed, NOT TESTED"). It is now measured:

| Phase 7 open question | Phase 7.5 answer |
|---|---|
| Does W5 actually block a selected app's direct traffic? | **Yes.** Direct IPv4 TCP and UDP blocked (T2, T4), including LAN and private ranges (T10), across restarts (T11) and for every instance (T12) |
| Does it leave unselected apps alone? | **Yes.** A byte-identical copy at another path stays direct (T3, T5) |
| Does it fail closed when Xray dies? | **Yes.** No direct fallback during the crash; recovery after restart (T16) |
| Does it clean up? | **Yes.** No filters, no WFP objects, no system change (T18 and the before/after snapshot) |
| Does it route proxy-unaware apps? | **No.** They are blocked, not routed. Only proxy-aware apps reach the Internet (T1) |
| DNS? | **Leaks (T8).** Resolution happens in the DNS Client service, outside any app-path filter |
| IPv6? | **Unverified (T6/T7):** no IPv6 route on the test machine |
| Children? | **No inheritance (T13/T15).** Only explicit executable listing works (T14) |
| Enforcer crash? | **Fails open (T17).** A dynamic session dies with its owner |

### 14.2 The decision

**OPTION 2: a limited "protected applications" Desktop, and only when the conditions below are met.
Not OPTION 1, not OPTION 3.**

* **Not OPTION 1** (true per-app Desktop): transparent routing of proxy-unaware applications needs the
  Track B callout driver. It is technically feasible on documented APIs, but it is unbuilt, unvalidated,
  and gated behind an EV certificate, a Partner Center hardware account and an HLK-tested submission.
  Nothing in Phase 7.5 moved it closer to existing.
* **Not OPTION 3** (build nothing): Track A is now a measured, meaningful guarantee — a selected
  application cannot silently bypass the proxy — with clean teardown and no system-wide changes. That
  is worth shipping, provided it is named honestly.
* **OPTION 2**, with the vocabulary fixed: the feature is **"protect this app"**, never "route this app".

### 14.3 Conditions for OPTION 2 (all mandatory)

1. **A service owns the filters.** T17 showed that a user-killable owner fails open. The service must be
   SYSTEM-owned with a fixed command set (apply/remove policy for validated targets, report state).
2. **The UI never claims more than it can verify.** "Protected" is displayed only while the service
   confirms that live filters exist, and only for applications that are actually proxy-aware. A
   proxy-unaware selected app is shown as **Blocked**, never as Protected.
3. **Target binding by path *and* Authenticode publisher**, re-verified for each new process of that path.
4. **The DNS leak is stated in the UI**, not only in documentation.
5. **IPv6 re-validated on a v6-capable network** before any release claim.
6. **Children require explicit selection**; no unbounded process-tree inheritance.
7. **Signed helper and service, plus IT allowlisting** (F12). Unsigned builds are terminated by
   endpoint security, as observed during this validation.

Until 1–7 exist, `RuntimeCapabilities.application_routing` stays **false** and no Desktop UI is built.

### 14.4 Track B: still required for the full product

"Select any application and have it transparently proxied" is not achievable with anything validated
here. It needs the WFP callout driver, and even then UDP would be blocked rather than routed, and DNS
metadata would still need separate handling. Track B stays a costed, deferred option — see the
[feasibility record](wfp-driver-feasibility.md) and its VM test plan.
