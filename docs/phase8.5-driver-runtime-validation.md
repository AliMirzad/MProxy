# Phase 8.5: driver build and runtime validation

**Outcome: NOT YET VERIFIED — SAFE TEST ENVIRONMENT UNAVAILABLE.**

The question this phase existed to answer — *can an arbitrary proxy-unaware Windows application be
transparently routed through Xray?* — still has no runtime answer, because the driver could not be
compiled or loaded anywhere safe. What did move: the one open correctness question from Phase 8 is
settled from Microsoft documentation, a static review found and fixed two real defects, and the
routing service now exists with the property that matters most, verified at runtime.

## 1. The blocker, exactly

Probed on the validation workstation, 2026-09-23:

| Requirement | State | Evidence |
|---|---|---|
| Windows Driver Kit | **absent** | no `Windows Kits` directory at all |
| Visual Studio C++ toolchain | **absent** | `Microsoft Visual Studio\2022` exists but contains no `VC\Tools\MSVC`; no `cl.exe`, no `msbuild.exe` |
| Hyper-V | **absent** | no `vmms` service, no `Get-VM` |
| VMware / VirtualBox / QEMU | **absent** | no `vmrun.exe`, `VBoxManage.exe`, `qemu-system-x86_64.exe` |
| Windows Sandbox | **absent** | `WindowsSandbox.exe` not present |
| **CPU virtualization** | **disabled in firmware** | `Win32_Processor.VirtualizationFirmwareEnabled = False`, `HypervisorPresent = False` (SLAT is supported, so the hardware is capable) |
| Free space on C: | **4.1 GB** | VS + SDK + WDK need roughly 15–20 GB; a Windows VM needs 40 GB+ |
| Machine posture | Secure Boot on, Kaspersky Endpoint Security active, test signing off | unchanged, and staying unchanged |

Two independent blockers, either of which alone is sufficient: **no hypervisor can run** (VT-x is
turned off in UEFI, which is a firmware security setting on a company machine), and **there is not
enough disk space** for the toolchain or a VM image. Installing a WDK on the workstation would not
help either: a development driver still could not be loaded without disabling driver-signing
enforcement, which is forbidden.

No workaround was attempted. Loading unsigned kernel code on a company workstation is precisely the
thing this project has refused to do at every phase, and a proof obtained that way would be worth
less than the machine it damaged.

## 2. What a valid test environment requires

The full setup is in [driver-build-environment.md](driver-build-environment.md). The short list:

1. A machine where **VT-x/AMD-V can be enabled in firmware** (a personal machine, or IT enabling it
   here), with ≥ 60 GB free.
2. **Hyper-V, VMware Workstation or VirtualBox**, and a **disposable Windows 11 VM** with snapshots.
3. Inside the VM only: **Visual Studio 2022 + Desktop C++ workload + Windows SDK + WDK**.
4. Inside the VM only: test signing (`bcdedit /set testsigning on`) **or** preproduction signing
   provisioning, which keeps Secure Boot enabled.
5. **Driver Verifier scoped to `mproxy-wfp.sys` only** (`verifier /standard /driver mproxy-wfp.sys`),
   with a snapshot taken first.

Everything else needed for the test — the redirector, the routing service, the proxy-unaware client,
the harness, the controlled endpoints and the evidence method — already exists and is runtime tested.

## 3. Settled: ownership of `localRedirectContext` (Phase 8's open item)

Microsoft's `FWPS_CONNECT_REQUEST0` reference answers it without ambiguity:

* the callout allocates it — *"a callout driver context area that the callout driver allocated by
  calling the ExAllocatePoolWithTag function"*;
* **WFP takes ownership on hand-over** — *"Starting with Windows 8, memory allocated for
  localRedirectContext will have its ownership taken by WFP, and will be freed when the proxied flow
  is removed."*

Therefore the contract the driver must implement, and now does:

| Path | Who frees |
|---|---|
| context attached and `FwpsApplyModifiedLayerData0` succeeded | **WFP**, when the proxied flow is removed. The driver must not touch it again |
| allocation succeeded but a later step failed before hand-over | **the driver**, in its cleanup block |
| allocation failed | nothing to free; the connection is not redirected, and the service's BLOCK filters deny it (fail closed) |

The source now carries this contract as a comment with the citation, and the pointer is set to `NULL`
at the moment of hand-over so the cleanup block cannot double-free it. Evidence level:
**PASS — CODE REVIEW ONLY**. It is correct against the documentation; it has never executed.

Also settled from the same documentation: `FwpsQueryConnectionRedirectState0(redirectRecords,
redirectHandle, redirectContext)` — the parameter order used in the driver is correct, and
`PREVIOUSLY_REDIRECTED_BY_SELF` *"must not perform redirection"*, which the code now honours by
treating every state other than `NOT_REDIRECTED` as hands-off.

## 4. Static review before load (§10), with two defects fixed

| Area | Finding |
|---|---|
| IOCTL buffer lengths | OK — fixed-size `METHOD_BUFFERED` structures, exact-length check, version and reserved fields validated, no user-mode pointer dereferenced |
| Device ACL | OK — `D:P(A;;GA;;;SY)(A;;GA;;;BA)` plus `FILE_DEVICE_SECURE_OPEN` |
| Pool allocation / lifetime | **fixed** — ownership contract above; allocation now matches the documented call |
| Spin locks / IRQL | OK — `EX_SPIN_LOCK` snapshot, all classify work ≤ DISPATCH_LEVEL |
| Unload path | **fixed (real defect)** — the FWPM callout *objects* were added but never deleted, so an unload would have left stale WFP objects behind. Now the engine session is dynamic **and** the callouts are deleted explicitly, management objects before kernel registrations |
| Callout unregistration | **improved** — `FwpsCalloutUnregisterById0` returns `STATUS_DEVICE_BUSY` while flows still reference the callout; the code no longer assumes success, and the remaining work (tracking completion via `notifyFn`) is marked as a review item for the first VM run |
| Redirect handle lifetime | OK — created once in `DriverEntry`, destroyed in unload after unregistration |
| Loop prevention | OK — redirect state, redirector PID, redirect records, plus the service refusing product components |
| Integer overflow | none — no arithmetic on input |
| Error cleanup | OK — every failure path frees what it owns and leaves the flow unredirected (and therefore blocked) |

Remaining review items, to be settled at first compile in the VM: regenerate the placeholder callout
GUIDs, confirm field byte order at the redirect layers against `fwpsk.h`, confirm the
`FwpsCalloutRegister3`/`classifyFn3` pairing, and confirm the busy-unload handling under Driver
Verifier with live flows.

## 5. The minimal routing service (§14), and what it proves today

`experimental/windows-redirector/src/service.rs` — four operations and nothing else:
`set_app_policy`, `clear_app_policy`, `query_state`, `query_driver_state`. No command execution, no
arbitrary rules, no file or registry access, no process control.

The lifecycle is **BLOCK first, redirect second**, and the state machine has no "probably protected"
state:

```text
Inactive  ──set_app_policy──►  BLOCK filters installed  ──►  Blocking
                                                               │ driver present AND target set
                                                               │ AND redirector alive
                                                               ▼
                                                           Protected
```

| # | Scenario | Expected | Result |
|---|---|---|---|
| S1 | user-mode structures match the driver header | sizes match the IOCTL contract | **PASS — AUTOMATED TEST** |
| S2 | callout driver device present | absent here | **NOT TESTED** (no driver exists) |
| S3 | apply a policy with no driver present | never `Protected` | **PASS — RUNTIME VERIFIED** (state `Failed`, UI label "Not protected") |
| S4 | BLOCK filters cannot be installed (non-elevated) | fail, never `Protected`, never silently direct | **PASS — RUNTIME VERIFIED** |
| S5 | validation rejects malformed and self-referential policies | all rejected | **PASS — AUTOMATED TEST** |
| S6 | a well-formed policy is accepted | accepted | **PASS — AUTOMATED TEST** |
| S7 | `clear_app_policy` returns to `Inactive` | "Not protected" | **PASS — RUNTIME VERIFIED** |

Run it with `routing-service --self-test --report <file.json>`.

**S5 found a real bug.** The loop-prevention check that refuses to route the product's own
executables compared a `\\?\`-verbatim canonical path against a non-verbatim install directory, so
it silently never matched — the guard existed and did nothing. Both sides are now normalised. This is
the kind of defect that only shows up when someone actually runs the check, which is the argument for
building the service before the UI rather than after.

## 6. What is still unproven

Everything that requires the kernel: interception of a real application's connection, IPv6
redirection, UDP behaviour under the driver, loop prevention in the kernel, driver load/unload,
reboot behaviour, Driver Verifier results, BSOD-freedom, multi-user scoping with the driver active,
and the real-application test (ChatGPT/Claude/Cursor). None of these may be reported as anything but
**NOT TESTED** until the VM exists.

The user-mode half remains runtime verified from Phase 8
([phase8-driver-poc.md](phase8-driver-poc.md)) and was re-run unchanged in this phase.
