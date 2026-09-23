# Threat model: host compromise and data leakage

Scope: MProxy (native protocol v3) on company computers (Windows, macOS), browsers Chrome/Brave/Chromium.
Goal: no remote input (proxy server, subscription, imported link/JSON/QR, web page) and no local
caller (other extension, other process, other user) can turn the product into a way to compromise
the host or leak data. Every remote input is treated as hostile.

Revised 2026-09-22 after the adversarial review. The status of each property is in
[security-gate.md](security-gate.md), the attacks that were run are in
[adversarial-testing.md](adversarial-testing.md), and network flows are in [data-flow.md](data-flow.md).
File references point at the code that enforces a control (paths relative to `native/src`; Phase 6
layout: `core/`, `runtime/`, `platform/`, `browser/`, see [module-boundaries.md](module-boundaries.md)).

## Components and trust boundaries

```
 web pages ──X── extension (MV3, privileged) ──native messaging (stdio, allowed_origins)──▶ helper (Rust, user, Medium IL)
                         │ chrome.proxy + onAuthRequired                                    │ stdin config, fixed args
                         ▼                                                                   ▼
   browser ──HTTP proxy 127.0.0.1:eph (per-connection user/password)──▶ Xray (restricted token, Low IL, job, no children)──▶ VLESS/VMess server ──▶ Internet
   JetBrains/other local apps ──HTTP/SOCKS 127.0.0.1:10809/10808 (password)──▶ Xray
   subscription provider ◀── HTTPS (helper; destination policy, limits; through the tunnel when connected)
```

| Boundary | Crossed by | Enforced in |
|---|---|---|
| Web page → extension | nothing (no content scripts, no `externally_connectable`, no web-accessible resources) | `manifest.json`, `tests/security.test.ts`, E2E hostile page |
| Other extension → extension / helper | nothing (sender checks; `allowed_origins` = pinned ID; helper re-checks `argv[1]`) | `service-worker.ts fromOwnPage`, `install.rs`, `main.rs` |
| **Extension identity** | an unpacked copy with our public `key` gets our ID (developer mode) | not enforceable by the product: [managed-deployment.md](managed-deployment.md) |
| Extension → helper | closed, typed command set, mapped onto the Core API | `browser/protocol.rs` (`deny_unknown_fields`, UUID ids), `browser/adapter.rs` → `core/api.rs` |
| Imported data → Xray config | typed model only; config regenerated | `core/import/*`, `core/import/fields.rs`, `validate.rs`, `xray_config.rs` |
| Helper → Xray | fixed arguments, config via stdin, `SystemRoot`-only environment, pinned binary verified before every launch | `xray.rs`, `winproc.rs` |
| Xray → host | restricted token (user SID deny-only, no privileges) + Low IL, job, no child processes, mitigations; verified **before** Xray runs, else not started | `winproc.rs` |
| Helper → network | subscription fetch only (destination policy, HTTPS, limits) | `subscription.rs`, `netpolicy.rs` |
| Local processes / other users → proxy listeners | loopback only, **every listener needs credentials** | `core/xray_config.rs`, `core/credentials.rs`, `core/api.rs` |

## Protection levels (fail-closed policy)

Every protection is in one of three classes. A MANDATORY protection that cannot be applied or
verified stops the connection with **"Runtime security check failed: … The connection was not
started."** and nothing runs without it (`core/error.rs CoreError::from_runtime_security`,
`platform/winproc.rs verify_suspended`, `runtime/xray.rs` on macOS).

| Class | Protection | On failure |
|---|---|---|
| **MANDATORY** | Pinned Xray SHA-256 (verified with a deny-write handle before every launch) | not started |
| MANDATORY | Windows: restricted token (user SID deny-only, `DISABLE_MAX_PRIVILEGE`), Low integrity, job (kill-on-close, 1 active process, die on unhandled exception, memory cap), `CHILD_PROCESS_RESTRICTED`, explicit handle list, `SystemRoot`-only environment; all **re-read from the suspended process** (integrity RID, deny-only SID, ≤ 1 privilege, job membership and limits) | not started |
| MANDATORY | macOS: Seatbelt sandbox self-test passes (no fork, exec only Xray, no writes, no reads in the home folder) | not started (the former unsandboxed fallback is removed) |
| MANDATORY | Data directory private (Windows: protected DACL user/SYSTEM/Admins + no-read-up label; Unix: 0700), not a link | not started |
| MANDATORY | Every loopback listener authenticated (browser: per-connection random credentials; IDE: stored password, on by default) | IDE: endpoint stays off; browser: always generated |
| MANDATORY | Browser proxy and WebRTC setting are ours while "Connected" | tunnel disconnected with a reason |
| BEST EFFORT | Process mitigation attribute set (extension points off, no remote/low-label images, prefer System32, fonts off, heap terminate, forced ASLR) | retried without the attribute only; everything MANDATORY still enforced and verified; Diagnostics shows `mitigationsApplied:false` |
| BEST EFFORT | `SetDefaultDllDirectories(System32)` + `DependentLoadFlags=0x800` in the helper | n/a (link-time + startup; verified in the release PE) |
| OPTIONAL | WebRTC protection (user can switch it off in Settings); IDE endpoint password (user can switch it off) | as configured; defaults are on |

## Attackers

### 1. Malicious VLESS/VMess server (operator acts in bad faith)
* **Surface:** all proxied traffic; Xray's protocol handshake; plain-HTTP content; DNS for proxied names; timing.
* **Mitigation:** TLS end to end for HTTPS content (browser verifies certificates). No inbound from
  the server (no reverse, no mux). If a server exploits Xray, the process has **no access to the
  user's files** (deny-only user SID: runtime-verified that it cannot read a document in the profile,
  secrets, temp; cannot write profile, temp, LocalLow, install or data dir, `HKCU\Software`), cannot
  start programs (`CreateProcess` → error 367), cannot open its own token, has no privileges and a
  2 GiB cap. See [adversarial-testing.md](adversarial-testing.md#1-windows-xray-isolation).
* **Residual:** metadata (see [data-flow.md](data-flow.md#what-a-proxy-operator-sees)); Xray can still
  make network connections (it must); a kernel or sandbox-escape exploit is out of scope. macOS
  sandbox not validated on hardware.

### 2. Compromised proxy server
As attacker 1, without the user's knowledge. Recommendation for companies: only company-operated
servers delivered by a company subscription ([managed-deployment.md](managed-deployment.md#corporate-mode-design)).

### 3. Malicious subscription provider / 4. compromised subscription URL
* **Mitigation:** HTTPS only, no downgrade, ≤ 5 redirects each re-checked, destination policy on
  URL, redirects and every DNS answer (direct fetch), 10 s/20 s timeouts, 5 MiB, 2,000 entries,
  per-entry isolation, strict field allowlists, JSON recursion limit, names stripped of control,
  bidi and zero-width characters. Corpus of 11 hostile bodies + 10 hostile redirects tested.
* **Residual:** the provider chooses the servers (trust decision); it learns the client IP (or the
  tunnel egress IP when refreshed while connected) and refresh times. A subscription fetched through
  the tunnel has its name resolved by the server, so the local DNS-rebinding check does not apply there.

### 5–8. Malicious `vless://`, `vmess://`, JSON, QR
Unchanged design: strict parsing, allowlists, config regenerated from a typed model and checked with
`xray run -test`; nothing is passed to a shell; QR payloads other than proxy configs are refused.
New: display names lose bidi overrides/isolates and zero-width characters (U+202E made `gnp.exe`
display as `exe.png`), `validate.rs clean_name`.

### 9. Malicious website
* **Tested attacks** (fixture page on a public origin): extension messaging, extension resources
  (fetch/script/iframe), localhost port reads and WebSockets against the tunnel and IDE ports,
  timing, WebRTC candidate harvesting, custom-scheme imports, HTTP-auth credential phishing.
  All failed; WebRTC returned **no candidates** while connected.
* **Residual:** a page cannot read the ports, but coarse port detection by timing cannot be ruled out
  in general (not observed: all ports errored in 2–14 ms like a closed port). Plain-HTTP content is
  visible to the proxy operator.

### 10. Another malicious browser extension
* **Tested attacks** (fixture extension with `nativeMessaging`, `proxy`, `privacy`, `webRequest`,
  `webRequestAuthProvider`, `<all_urls>`): native messaging (port and one-shot), messaging and popup
  spoofing, reading our files, localhost scan, header sniffing with `extraHeaders`, proxy takeover to a
  trap proxy that demands credentials, takeover racing a connect, 25× flapping, WebRTC override.
* **Result:** all refused, except that it **could silently override WebRTC protection** while the UI
  kept saying "Connected" (MEDIUM, **fixed**: WebRTC control is now monitored like the proxy
  setting and the tunnel fails closed). Our credentials are answered only to `127.0.0.1:<our port>`
  while our setting is in effect; the trap proxy never received them (races included).
* **Residual:** a malicious extension with `proxy`/`webRequest` controls the victim's browsing
  anyway (it could proxy everything itself); it can ride our tunnel with its own requests (all
  browser requests go through the tunnel by design) and can jam our 407 answer (denial of service).

### 10b. Extension impersonation (developer mode)
* **Tested:** an unpacked extension with our manifest `key` and its own code gets our ID. Loaded
  alone, or loaded after the real one (the later load wins), the native host accepts it: it read the
  IDE password, **turned IDE authentication off**, allowed private subscription hosts, imported an
  attacker server. HTTPS-only and SSRF policies still applied; no command gives file or process access.
* **Severity: HIGH for the current distribution model** (users install with "Load unpacked", so
  developer mode is on by design). The previous report rated this MEDIUM; that was too low.
* **Mitigation:** only by deployment: CRX force-installed by policy from a company update URL,
  developer mode and unpacked extensions blocked, native host installed machine-wide.
  [managed-deployment.md](managed-deployment.md). Not enforceable in code: native messaging tells the
  host only the caller's origin.

### 11. Local process of another user / same user
* **Other users** (multi-user machines, terminal servers): every listener now requires credentials
  (browser: random per connection, ~140 bits; IDE: 24-character password). Runtime-verified: 407 /
  SOCKS refused without them; 1,000 brute-force attempts accepted 0 and did not destabilize Xray.
  Previously the browser SOCKS port was open to every local user (fixed).
* **Same user:** out of scope as an attacker class. It can read Credential Manager/Keychain (and
  therefore decrypt `secrets.bin`), the browser's memory and the IDE password. Documented, not mitigated.

### 12. Compromised Xray binary / 13. supply chain
Pinned hashes (zip + binary), verified before every launch; release manifest with SHA-256 of every
shipped file ([release-integrity.md](release-integrity.md)); `cargo audit` 0 (1,261 advisories),
`npm audit` 0 (2026-09-22). Test fixtures and test binaries are refused by the packaging script.

### 14. Endpoint security (new, operational)
Kaspersky Endpoint Security on the test workstation **removes the current unsigned release helper**
seconds after it is written to disk. This is a deployment blocker, not a vulnerability: releases must be
code-signed and allowlisted by IT. The product does nothing to evade detection.

## Process isolation (Windows, runtime-verified)

| Mechanism | Xray | Verified by |
|---|---|---|
| Restricted token: user SID deny-only, `DISABLE_MAX_PRIVILEGE` (only `SeChangeNotifyPrivilege` left) | yes | probe: `userSidDenyOnly:true`, `privileges ≤ 1`, cannot open own token |
| Low integrity (S-1-16-4096) | yes | probe `integrityRid=0x1000` |
| Job: kill-on-close, active processes 1, die on unhandled exception, 2 GiB, UI restrictions 0xff, no breakaway | yes | probe job limits |
| Child processes blocked | yes | probe `CreateProcess` → 367 |
| Handle list / inherited handles | only stdio | probe: inherited handle unusable |
| Environment | `SystemRoot` only | probe env |
| Filesystem | cannot read Documents, secrets, temp; cannot write profile, temp, LocalLow, install, data dir; can read `hosts` | probe reads/writes, control run shows the same accesses succeed otherwise |
| Registry | cannot write `HKCU\Software` or AppDataLow | probe |
| Mitigation policies | best effort; applied on this machine | `mitigationsApplied:true` |
| Pre-run verification | integrity, deny-only SID, privileges, job, limits read from the suspended process | integration `mandatory_protection_failure_blocks_connection` (test hook breaks isolation → not started) |

ACG, signed-only images and Win32k lockdown are still not applied (EDR hook compatibility).

## SSRF and internal destinations

| Destination class | Subscription URLs (+ redirects, + DNS answers when direct) | Proxy server address |
|---|---|---|
| Public | allowed | allowed |
| Private ranges, single-label, `.internal/.local/...` | blocked unless "Allow private-network subscription URLs" | allowed |
| Loopback incl. decimal/hex/mapped forms | blocked | blocked |
| Link-local incl. cloud metadata | blocked | blocked |
| Unspecified, multicast, reserved | blocked | blocked |

## Corporate safety behaviour (fail-safe states)

| Situation | Browser traffic | UI |
|---|---|---|
| Connecting | direct (no proxy set yet) | "Connecting" |
| Mandatory protection cannot be applied/verified | direct; Xray never started | "Runtime security check failed: …" |
| Connected | through the tunnel, authenticated | "Connected" |
| Xray crashes | proxy kept, requests fail during ≤ 2 restarts | "Connecting (restarting)" |
| Restarts exhausted / helper or browser dies | proxy cleared → direct | error, never "Connected" |
| Another extension/policy takes the proxy **or the WebRTC setting** | tunnel disconnected | reason shown |
| Server stops forwarding | requests fail | stays "Connected" (no periodic probe) |

There is no kill switch: after a failure the browser goes direct and says so.

## Per-application routing (Phase 7: EXPERIMENTAL / RESEARCH ONLY, not in the product)

Nothing below ships. It frames the design of a future desktop client; evidence is in
[per-app-routing-decision.md](per-app-routing-decision.md).

| Actor / event | Risk | Mitigation (design) | Evidence |
|---|---|---|---|
| Malicious **selected** app | uses the tunnel for anything; exfiltrates through the company server | inherent: the user selected it; server-side policy; per-app inbound so traffic is attributable | design |
| Malicious **unselected** app | connects to the selected app's local inbound to ride the tunnel | authenticated inbound (PoC); for credential-less Chromium apps, WFP BLOCK of `connect 127.0.0.1:<port>` for every app except the selected one | auth: runtime (R5/F2); WFP restriction NOT TESTED |
| Malicious local process, same user | reads proxy credentials from a selected app's environment; swaps a user-writable executable at a selected path | publisher-signature binding re-checked per process; per-app inbounds; environment-based configuration only for cooperative tools | env exposure and path semantics: runtime/code review |
| App identity spoofing | another binary at the selected path, or claiming a bundle ID | bind to path + Authenticode signer (Windows) / Team ID + audit-token code signature (macOS); never name-only | code review |
| Executable replacement (TOCTOU) | approved file replaced after the check | file-identity + signer re-verification by the privileged service at process start | PoC re-hash before launch only |
| Routing-rule tampering | another admin tool removes/overrides our WFP filters | BLOCK in our own sublayer wins over other sublayers' PERMITs; a driver's hard permit/veto can override; the service monitors its filters | code review |
| Privileged routing service compromise | a service API becomes a generic firewall/process tool | fixed command set, validated targets only, user-scoped filters, no command execution | design (corporate-impact doc) |
| Stale routing state | filters or routes left after a crash block or leak traffic | dynamic WFP session (auto-removed on crash); no route/DNS changes; driver design must be session-scoped | dynamic-session semantics documented; no persistent state created by the PoC (system snapshot unchanged) |
| Malicious child process | unrelated program inherits routing (C3), or a child bypasses (C2) | no unbounded process-tree inheritance; explicit executable allowlist | **runtime: C2/C3 both observed** |
| Xray crash | selected apps fall back to direct | cooperating apps fail closed (connection refused); non-cooperating ones need WFP blocking | runtime F1–F3 |
| Routing component crash | dynamic filters vanish (fail open) or persistent filters strand (fail closed) | explicit policy choice; corporate mode prefers fail-closed persistent filters owned by a service | design |
| Other users on the machine | filters apply machine-wide | `ALE_USER_ID` condition per user | code; NOT TESTED (single-user machine) |

### Phase 7.5 additions (Track A validated / Track B RESEARCH ONLY)

| Actor / event | Risk | Mitigation (design) | Evidence |
|---|---|---|---|
| WFP callout driver bug (Track B) | kernel crash (BSOD) or privilege escalation from any process that reaches its IOCTL | minimal driver (classify + redirect only), device ACL = routing service only, Driver Verifier + fuzzing in the VM lab, HLK | RESEARCH ONLY |
| Routing service compromise (A and B) | becomes a SYSTEM-level network control plane | fixed command set (SetPolicy / ClearPolicy / QueryState), validated targets (path + signer + user SID), no command/file/registry/rule primitives | design |
| Redirect loop (Track B) | Xray's own connection redirected back into itself | redirect state + redirect records + excluding our signed executables | design (documented WFP mechanism) |
| DNS metadata of a protected app | hostname reaches system/company DNS via the DNS Client service even when the app is blocked or redirected | none in Track A/B; documented as a known leak | runtime (T8: resolver cache) |
| Enforcer crash with dynamic WFP session (Track A) | filters vanish, selected app **fails open** | production: a service that owns the filters and restarts; or persistent filters with explicit cleanup | see windows-routing-validation.md T17 |
| Endpoint security terminates the enforcer | an unsigned or unknown binary that opens WFP sessions is killed by EDR; protection disappears while the UI may still claim it | signed service + helper, vendor reputation, IT allowlisting (F12); the UI derives "Protected" from a live service confirmation, never from its own assumption | runtime: observed twice during elevated validation (exit 0x40000015, correlated EDR event; not proven) |
| UI overstating protection | a user trusts "Protected" for an app that is in fact bypassing (proxy-unaware, DNS, IPv6 untested, filters gone) | the state model in future-desktop-architecture.md: Protected only for a proxy-aware app with confirmed live filters; otherwise Blocked or Not protected | design, from runtime T1/T8/T17 |

### Phase 8 additions: kernel driver and redirector attack surface (SOURCE ONLY / EXPERIMENTAL)

Kernel code is the highest-risk component in this product. None of it has been compiled or loaded,
so every mitigation below is **design or code review**, never runtime evidence
([phase8-driver-poc.md](phase8-driver-poc.md)).

| Actor / event | Risk | Mitigation (design) | Evidence |
|---|---|---|---|
| Malformed IOCTL | kernel memory corruption from length or type confusion | three fixed-size `METHOD_BUFFERED` structures; input length must equal `sizeof` exactly; version and reserved fields checked; no variable-length data, no embedded pointers, no user-mode pointer ever dereferenced | code review |
| Unprivileged device access | any local process reprograms the redirect target and captures other applications' traffic | device ACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (SYSTEM + Administrators, protected), `FILE_DEVICE_SECURE_OPEN` so relative opens are covered too | code review |
| Policy spoofing through the driver | a caller makes the driver route an application of its choosing | **the driver cannot express that**: application matching lives in user-mode WFP filter conditions; the IOCTL carries only a port and a PID | code review (design property) |
| Integer overflow / buffer lifetime | classic kernel bugs | no arithmetic on user input; the only allocation is one fixed-size redirect context per connection | code review; **open item**: ownership of `localRedirectContext` must be confirmed against the WFP sample before the first VM run |
| Race conditions | target read while being updated | target snapshot under `EX_SPIN_LOCK`; classify never touches the live structure | code review |
| Use-after-free on unload | classify running against freed state | unload clears the target first, then unregisters callouts, then destroys the redirect handle, then closes the engine | code review |
| Redirect loop | the redirector's or Xray's own traffic redirected back into the redirector | three layers: `FwpsQueryConnectionRedirectState0`, the redirector's PID excluded, and redirect records set on the proxied socket; the service also refuses targets inside the product directory | kernel part: code review; user-mode half: **runtime (R7)** |
| Service impersonation | a process pretends to be the routing service | device ACL plus the service's own IPC ACL; the driver accepts commands only from handles that passed the device ACL | code review |
| Malicious **selected** application | tries to reach the network outside the redirect | Track A BLOCK filters remain the fail-closed layer: anything not redirected is blocked (**runtime verified in Phase 7.5**) | runtime + design |
| Malicious **unselected** application | connects to the redirector to get free tunnelling | the redirector never takes a destination from the stream (**runtime R6**), and production restricts the redirect inbound to redirected flows | runtime (R6) |
| Application identity replacement | another binary is dropped at a selected path | PoC binds path + user SID only (**insufficient**); production must verify the Authenticode publisher per process start | code review |
| Driver unload while flows exist | stranded redirects | redirect handle destroyed after callouts are unregistered; dynamic filters are removed with the owning session | code review |
| Driver bug reaching users | BSOD or escalation on customer machines | HLK certification, Driver Verifier in a VM, minimal kernel surface, no traffic content handling in kernel | design |
