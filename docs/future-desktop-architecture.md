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
