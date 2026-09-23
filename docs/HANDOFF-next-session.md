# Handoff: what the next session must do

**Read this file first. It is written for a fresh Claude Code session on a different machine.**
Date of handoff: 2026-09-23. Repository copied to `F:\private-proxy` (full working tree including
`.git`, so every branch and all history are present).

## 1. Where the project stands

MProxy (formerly "Private Proxy") by Ali Mirzad: a Chromium MV3 extension + a Rust native helper
(crate `private-proxy-host`, lib `ppcore`) + pinned Xray-core v26.3.27.

| Phase | Branch | Result |
|---|---|---|
| 5 Security hardening | merged history | done |
| 6 Shared Core | `phase-6-core-modularization` | done |
| 7 Per-app routing research | `phase-7-per-app-routing-poc` | done |
| 7.5 Elevated user-mode WFP validation | `phase-7.5-windows-routing-validation` | done — blocking works, verified as administrator |
| 8 Driver architecture + user-mode PoC | `phase-8-true-per-app-driver-poc` | RESULT B: architecture valid, kernel hop unproven |
| **8.5 Driver build & runtime validation** | **`phase-8.5-driver-runtime-validation`** ← current | **NOT YET VERIFIED — safe test environment unavailable** |

Nothing of this is in the product. `RuntimeCapabilities.application_routing` is **false**, no routing
code ships, and `npm run package` refuses every `experimental/` path.

**The one open question of the whole project:** can an arbitrary Windows application that has no
proxy support be transparently routed through Xray, while unselected applications stay direct?
Everything except the kernel interception step is built and runtime-verified. The kernel callout has
never been compiled or loaded.

## 2. Read these, in this order

1. `docs/phase8.5-driver-runtime-validation.md` — current state, the blocker, the settled ownership
   contract, the static review, the routing service.
2. `docs/phase8-driver-poc.md` — the architecture and what is already runtime verified.
3. `docs/driver-build-environment.md` — exact environment requirements (this is your setup guide).
4. `docs/windows-routing-validation.md` — Phase 7.5 elevated evidence (blocking works).
5. `docs/driver-signing-and-release.md` — signing chain; do not confuse development with production.
6. `docs/threat-model.md`, `docs/security-boundaries.md` — the rules the design must keep.

Code to inspect: `experimental/windows-wfp-driver/` (driver, SOURCE ONLY) and
`experimental/windows-redirector/` (redirector, routing service, harness — all compiled and tested).

## 3. The hard safety rules (unchanged, non-negotiable)

* Never disable Secure Boot, driver-signing enforcement, Defender, Kaspersky or any EDR.
* Never enable test signing on a real workstation. **VM only.**
* Never load an unsigned driver outside a disposable VM.
* No process/DLL injection, no packers, no obfuscation, no hiding from security tools, no evasion.
  If a security product flags something, that is a finding to record, not an obstacle to bypass.
* Never report source code or design as runtime evidence. Use only these labels:
  `PASS — RUNTIME VERIFIED`, `PASS — AUTOMATED TEST`, `PASS — CODE REVIEW ONLY`, `FAIL`,
  `NOT TESTED`, `ENVIRONMENT UNAVAILABLE`, `BLOCKED`.
* Do not destroy work: no `git reset --hard`, no `git clean -fd` without explicit permission.
* Do not build the Desktop UI yet.

## 4. Why Phase 8.5 stopped, and what must be true to continue

The work machine had: no WDK, no Visual Studio C++ toolchain, **no hypervisor**, **CPU
virtualization disabled in UEFI** (`VirtualizationFirmwareEnabled = False`), and 4.1 GB free on C:.
Two independent blockers, so no driver could be compiled or loaded.

The next machine needs:

* virtualization enabled in firmware (check `(Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled`);
* ≥ 60 GB free disk;
* a hypervisor (Hyper-V, VMware Workstation or VirtualBox);
* a **disposable Windows 11 VM** with snapshots and no personal or company data.

Inside that VM only: Visual Studio 2022 + Desktop C++ workload + Windows SDK + WDK, and test signing
(`bcdedit /set testsigning on`) or preproduction-signing provisioning.

## 5. Exactly what to do next (Phase 8.5 continuation)

Work on the existing branch `phase-8.5-driver-runtime-validation`, or branch from it.

### Step 1 — set up the VM (host untouched)
Follow `docs/driver-build-environment.md`. Take a snapshot named `clean` before anything else.

### Step 2 — first compile of the driver
Create a **Kernel Mode Driver, Empty (KMDF)** project from the WDK template, add
`experimental/windows-wfp-driver/mproxy-wfp.c` and `.h`, then build x64.

Settle these before loading (all are marked in the source and in the component README):
1. regenerate the two placeholder callout GUIDs;
2. confirm field byte order of `IP_REMOTE_ADDRESS` / `IP_REMOTE_PORT` at the redirect layers;
3. confirm the `FwpsCalloutRegister3` / `classifyFn3` pairing against `fwpsk.h`;
4. confirm the busy-unload handling (`STATUS_DEVICE_BUSY`) with live flows.

Record: compiler version, WDK version, target architecture, **every warning**, and the binary
SHA-256. Do not silence warnings to get a clean build.

**Already settled — do not re-litigate:** WFP takes ownership of `localRedirectContext` at
hand-over and frees it when the proxied flow is removed. The driver frees it only on failure paths
before hand-over. Source carries the citation.

### Step 3 — load the driver in the VM
Snapshot first. Enable Driver Verifier **scoped to this driver only**:
`verifier /standard /driver mproxy-wfp.sys`. Verify: loads, callouts register, device opens, the
service can talk to it, unloads cleanly, no BSOD, no verifier violation, **no WFP objects left after
unload**.

### Step 4 — wire the service to the driver
`experimental/windows-redirector/src/service.rs` already implements the lifecycle
(BLOCK filters → driver target → redirector alive → `Protected`). Add the filters that reference the
driver's callout GUID. Keep the API to four operations; add nothing else.

### Step 5 — run the real test
Use `phase8-harness` but with the **real** redirect instead of `--simulate-destination`. The
evidence method is already built and must be kept:

* destination `192.0.2.7:80` (TEST-NET-1) is unreachable except through the tunnel;
* the test server's Xray uses a `freedom` outbound with `redirect`, so only tunnelled traffic reaches
  the controlled endpoint;
* the endpoint reports **which local process opened each connection** (`xray.exe` vs the client).

Required evidence chain for success — no single observation is enough:
client initiated → driver classified/redirected (driver counters via `query_driver_state`) →
redirector accepted → Xray processed → controlled endpoint received.

Then run the full matrix: control app direct, IPv6, UDP blocked, DNS, loop prevention, Xray crash,
redirector crash, **service crash**, app restart, multiple instances, startup race, explicit child,
localhost, LAN, multi-user, cleanup, reboot, performance.

### Step 6 — the real application test
ChatGPT Desktop / Claude Desktop / Cursor, inside the VM, **without configuring anything in the
app**, against a harmless controlled destination only. Never capture real payload or use real
accounts.

### Step 7 — report
Answer the six gate questions (A–F in `docs/phase8.5-driver-runtime-validation.md`), update the
documents listed in section 47 of the Phase 8.5 brief, and only then recommend whether Phase 9
(Desktop client) may start.

## 6. How to build and test this repo

```bash
# one-time
npm run setup                 # extension deps + fetch pinned Xray (hash-verified)

# put the build output off the system drive if space is tight
export CARGO_TARGET_DIR='F:\pp-target'     # bash
$env:CARGO_TARGET_DIR = 'F:\pp-target'     # PowerShell

npm test                      # native (84 unit, 4 architecture, 8 Core API, 20 integration) + extension 56
npm run lint
npm run test:e2e              # 82 real-browser checks
npm run package               # refuses experimental paths
node scripts/test-package-adversarial.mjs    # 11 checks

# experimental crates
node scripts/cargo.mjs build --manifest-path ../experimental/windows-redirector/Cargo.toml
node scripts/cargo.mjs build --manifest-path ../experimental/per-app-routing-poc/Cargo.toml
```

Useful binaries after building (`<target>/debug/`):

| Binary | What it does |
|---|---|
| `routing-service --self-test --report <f.json>` | service state machine: 7 checks, all pass today |
| `phase8-harness --report <f.json>` | full user-mode routing matrix (R1–R15) |
| `redirector --upstream <port> --user <u> --pass-env <ENV> ...` | the local redirector |
| `unaware-client <ip:port> <marker>` | proxy-unaware test client |
| `track-a --report <f.json>` | Phase 7.5 blocking matrix (needs an elevated shell) |
| `track-a --report <f.json> --wfp-cycle 3` | WFP session lifecycle diagnostic |

**Run the integration tests serially if the machine is loaded** (`--test-threads=1`); parallel runs
under load produce spurious `SERVER_UNREACHABLE` failures. Also make sure no orphaned `xray.exe`
from an earlier harness run is still alive.

## 7. Known gaps that no driver will fix

* **DNS metadata leaks** — names resolve in the Windows DNS Client service before any connect, so an
  app-path callout never sees them. Runtime verified in Phase 7.5 (T8). Must be stated in any UI.
* **UDP is not routable** — Windows drops connected UDP redirected to a local proxy. V1 must block
  selected UDP (blocking itself is runtime verified).
* **IPv6 is unverified everywhere** — implemented, never exercised; must be blocked until proven.
* **Children are not inherited** — WFP has no parent-process condition; explicit executables only.
* **Production shipping needs** an EV certificate, a Partner Center hardware account and an
  HLK-tested submission. Attestation signing is documented as testing-only.

## 8. The rule that governs the UI, whenever it is built

> The Desktop UI must never display **Protected ✓** for an application that can still bypass MProxy.

The routing service is the only authority on that status, and it may only conclude `Protected` when
the driver is present, the filters exist and the redirector is alive. A UI renders that string; it
never derives it.
