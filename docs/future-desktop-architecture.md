# Future desktop client and per-application routing (design only)

**Nothing in this document is implemented.** Phase 6 prepared the structure. There is no desktop
executable, no application picker, and no per-application routing in the code, and
`RuntimeCapabilities.application_routing` is `false`.

## Desktop client on the Shared Core

```text
Desktop UI
    ↓
Desktop adapter  (new; next to browser/adapter.rs)
    ↓
Shared Core      (core::api::Core, unchanged)
    ↓
Platform application routing   (new; Phase 7/8)
    ↓
Runtime → Xray
```

What a desktop client reuses without duplication: profiles and provenance, VLESS/VMess parsing
and all import allowlists, subscriptions (URL policy, redirect/DNS checks, tunnel refresh),
validation and name sanitization, the trusted config generator, the session state machine and
health probe, the Xray runtime (hash, restricted launch, supervision), secure storage and the error model.

How: a desktop adapter creates a `Core` exactly like `browser::adapter` does (a `Poster` back to its UI
thread, a periodic `CoreMsg::Tick`) and maps its UI actions onto the same methods
([core-api.md](core-api.md)). It needs no native messaging and no browser credentials. If it shows
the local endpoint to the user, it calls `browser_proxy_endpoint()` / `ide_credentials()` like any client.

Two things differ and belong to the desktop adapter, not the Core:
* the process model: a long-running app instead of a browser-launched helper;
* its own caller authentication, if it exposes any local interface.

## Phase 7 hook: application routing

Phase 7 researches routing for applications without proxy support (e.g. ChatGPT Desktop, Claude
Desktop, Cursor, IntelliJ and its child processes). The integration point:

```text
core::api::Core::start_session
    └─ builds RuntimePlan (core/xray_config.rs)         ← routing intent enters here
         └─ runtime::xray launches Xray
    └─ [future] ApplicationRoutingProvider::apply(plan, targets)   ← platform layer
```

A future trait in the platform layer, selected per OS:

```rust
// NOT IMPLEMENTED: sketch for Phase 7.
trait ApplicationRoutingProvider {
    fn capabilities(&self) -> AppRoutingCapabilities;          // what this OS/build can do
    fn apply(&mut self, local_inbound: SocketAddr, targets: &[ApplicationTarget]) -> Result<(), CoreError>;
    fn remove(&mut self) -> Result<(), CoreError>;             // must always restore the system
}
// WindowsApplicationRoutingProvider, MacOSApplicationRoutingProvider: later.
```

* The Core would own the *intent* (which applications, which session) and its lifecycle: apply after
  `Connected`, remove on stop/failure (fail closed, like the browser proxy).
* The platform provider owns the *mechanism*. Candidates for Phase 7 research: WFP/redirect drivers,
  Network Extension, per-app VPN. None of these are chosen or implemented.
* `RuntimeCapabilities.application_routing` becomes true only when a provider actually works on
  the platform.
* A new `RuntimePlan` routing field would be added then, not before. Today `RuntimePlan` describes the
  browser inbound and the IDE inbounds.

## Future domain type: ApplicationTarget

```rust
// NOT IMPLEMENTED: Phase 7/8.
struct ApplicationTarget {
    identifier: String,              // stable id
    display_name: String,            // sanitized like profile names (F11)
    executable_identity: ExecutableIdentity, // path + signer/team id + optionally hash; never a bare name
    include_child_processes: bool,
}
```

### Child processes

Many applications do their networking in helpers:

```text
Cursor                 IntelliJ
 ├─ node                ├─ java
 ├─ git                 ├─ gradle
 └─ extension-host      ├─ git
                        └─ node
```

`include_child_processes` would decide whether descendants inherit the routing. That requires the
platform provider to track process trees, and a policy for helpers that are shared system tools
(`git`, `node`): route only when started by the target. No process enumeration, interception or
child tracking exists in Phase 6.

## Corporate mode for desktop

The same policy enforcement point (`Core` methods) applies to the desktop client, so managed
restrictions hold for every client ([core-api.md](core-api.md#policy-enforcement-point)).

## Phase 7 findings (EXPERIMENTAL / RESEARCH ONLY)

Phase 7 researched and prototyped the routing seam; see
[per-app-routing-decision.md](per-app-routing-decision.md). What changed in this document's assumptions:

| Assumption (Phase 6) | Phase 7 evidence | Status |
|---|---|---|
| Apply routing after `Connected` | wrong order for fail-closed: `prepare` (block selected apps) must happen **before** Xray starts; `Connected` only after routing is Active and verified | RESEARCH ONLY |
| `ApplicationRoutingProvider { capabilities, apply, remove }` | refined to `capabilities / prepare / activate / state / deactivate` | EXPERIMENTAL (`experimental/per-app-routing-poc`) |
| `include_child_processes: bool` | a bool is not enough: `ExplicitOnly` / `KnownToolchain`; unbounded tree inheritance proxies unrelated programs (runtime C3) | EXPERIMENTAL evidence |
| `ExecutableIdentity` | path + publisher signature (Windows) / Team ID + code signature (macOS); path or hash alone is unsafe | RESEARCH ONLY |
| Windows mechanism "WFP / redirect drivers" | true per-process routing = WFP connect-redirect **callout driver** (EV + Microsoft signing); user-mode WFP can only **block** | RESEARCH ONLY; driver NOT IMPLEMENTED |
| macOS mechanism "Network Extension" | `NETransparentProxyProvider` system extension (entitlement, Developer ID); per-app VPN needs MDM | RESEARCH ONLY |

`RuntimeCapabilities.application_routing` remains **false** in the product. Nothing of Phase 7 is PRODUCTION.

## Phase 7.5: what a limited Desktop V1 would look like (still not built)

Track A is now runtime-verified with administrator rights
([windows-routing-validation.md](windows-routing-validation.md)), and the decision is **OPTION 2: a
limited "protected applications" Desktop**, conditional on the list in
[per-app-routing-decision.md](per-app-routing-decision.md) section 14.3. No Desktop UI is built in
this phase.

### Component shape (Windows)

```text
Desktop UI (user)  ──IPC──►  MProxy helper (user, Shared Core + Xray)
        │                             ▲
        │ fixed command set           │ endpoint + session state
        ▼                             │
   routing service (LocalSystem)  ────┘
        │  owns the WFP dynamic session for the interactive user's SID
        ▼
   WFP filters: BLOCK selected app ≠ loopback │ PERMIT selected app → loopback inbound
```

Why the service exists at all: T17 showed that when the process holding the filters is killed, the
filters disappear within about a second and the selected application is direct again. Protection
whose lifetime equals a user-killable process is not protection.

### State model the UI must obey

| Service reports | Application is proxy-aware | UI shows |
|---|---|---|
| filters present, session Connected | yes | **Protected** |
| filters present, session Connected | no | **Blocked (this app cannot use a proxy)** |
| filters present, session down | either | **Blocked** |
| filters absent / service unreachable | either | **Not protected** |

There is no state in which the UI shows Protected without a live confirmation from the service. This
is the rule the phase exists to enforce: never display Protected for an application that can still
bypass MProxy.

### What such a V1 would *not* do

* route applications that have no proxy support (they are blocked; Track B is required for routing);
* protect DNS metadata (T8);
* inherit to child processes automatically (T13/T15; explicit executables only, T14);
* claim IPv6 coverage until it is re-validated on a v6-capable network (T6/T7).

`RuntimeCapabilities.application_routing` stays **false** until the service, the signature binding
and the UI state model above exist and are verified on a machine.

## Phase 8: components for transparent routing (design + what exists)

Runtime evidence and labels: [phase8-driver-poc.md](phase8-driver-poc.md).

```text
Desktop UI (user, display only)            ── not built, not started ──
        │ query state, never assume
        ▼
Shared Core (existing)
        │
        ▼
routing service (LocalSystem)              DESIGN ONLY
        │ set_app_policy / clear_app_policy / query_policy_state / query_driver_state
        ├───► WFP filters: BLOCK selected app, PERMIT loopback, CALLOUT for redirect
        └───► driver IOCTL: redirector port + PID only
                    │
                    ▼
          mproxy-wfp.sys (kernel)          SOURCE ONLY
                    │ rewrites destination, passes the original along
                    ▼
            redirector (user)              RUNTIME TESTED
                    │ CONNECT + credentials
                    ▼
        authenticated inbound → Xray       PRODUCTION
```

### Service API, and what it must never become

Allowed: `set_app_policy(targets)`, `clear_app_policy()`, `query_policy_state()`,
`query_driver_state()`. Targets are validated by the service: canonical path, Authenticode publisher,
and the SID of the caller's own session.

Forbidden, and absent by construction: executing processes or shell commands, loading arbitrary
drivers, writing arbitrary files or registry keys, adding arbitrary firewall rules, injecting into
processes, reading user files. The service is not a SYSTEM-level control plane with a routing
feature; it is a routing component that happens to need SYSTEM.

### Lifecycle (fail-closed first, §37)

```text
Disconnected
  → PreparingRouting   install BLOCK filters for the selected apps      (they now have loopback only)
  → StartingXray       start and verify the tunnel
  → ActivatingRouting  start the redirector, set the driver target, add the redirect filters
  → Protected          only when Xray, redirector, driver and filters are all confirmed live
  → Stopping / Failed  remove redirect filters first, BLOCK filters last
```

`Protected` is never derived from the UI's own belief. If the service cannot confirm all four
conditions, the state is `Failed` and the UI says **Not protected** — the rule carried over from
Phase 7.5, where killing the filter owner silently returned an application to direct.

### Process start race (§16)

Policy is installed **before** the application is launched, and the BLOCK filters are path-based, so
they apply from the first connect of any instance — including instances started later by the user.
Discovering already-running processes and attaching to them is a race by construction; launching
through MProxy (or requiring a restart of the application) avoids it. For already-running processes
the honest UI answer is "restart this app to protect it", not a silent partial state.
