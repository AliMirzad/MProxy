# Driver build and test environment (what is missing, and exactly what is needed)

The Phase 8 callout driver source exists ([../experimental/windows-wfp-driver/](../experimental/windows-wfp-driver/))
and **has never been compiled**. This document states why, and what has to be true before it can be.

Nothing here was installed on the validation workstation. Installing a WDK, changing Secure Boot,
enabling test signing or touching endpoint protection on a company machine is out of scope by rule.

## What this machine has (probed 2026-09-23)

| Requirement | Present? | Evidence |
|---|---|---|
| Visual Studio 2022 (with C++ workload) | **no** | the `Microsoft Visual Studio\2022` folder exists but contains no `VC\Tools\MSVC`; no `vswhere.exe`, no `cl.exe`, no `msbuild.exe` on PATH |
| Windows SDK | **no** | `C:\Program Files (x86)\Windows Kits` does not exist |
| Windows Driver Kit (WDK) | **no** | no `Windows Kits\10\Include\*\km\fwpsk.h` |
| Hyper-V | **no** | no `vmms` service, no `Get-VM` cmdlet |
| VMware / VirtualBox | **no** | no `vmrun.exe`, no `VBoxManage.exe` |
| Windows Sandbox | **no** | `WindowsSandbox.exe` absent (and it cannot load a test-signed driver anyway) |
| WSL distribution | **no** | `wsl -l` lists none (irrelevant for kernel drivers, checked for completeness) |
| Machine security posture | Secure Boot on, Kaspersky Endpoint Security active, test signing off | unchanged, and to stay unchanged |

Conclusion: **BLOCKED BY TEST ENVIRONMENT.** The driver cannot be built here, and there is nowhere
safe to load it.

## To compile the driver (no security change needed)

1. Visual Studio 2022 with the **Desktop development with C++** workload.
2. The matching **Windows SDK**, then the **WDK** (installs the VS driver templates and `fwpsk.h`/`fwpmk.h`).
3. Open `experimental/windows-wfp-driver/` as a KMDF driver project, or build with
   `msbuild mproxy-wfp.vcxproj /p:Configuration=Debug /p:Platform=x64`.
4. Expect first-compile work: the placeholder callout GUIDs must be regenerated, and the review
   points listed in the component README (redirect-context ownership, field byte order, callout
   registration version) must be settled against `fwpsk.h` and the WFP driver sample.

Compiling changes nothing on the machine's security configuration — it is loading that does.

## To run the driver (needs a disposable VM, never this workstation)

1. A **disposable Windows 11 VM** (Hyper-V on a personal machine, or any hypervisor), no company data,
   snapshot before every run.
2. Inside that VM only, either:
   * enable test signing (`bcdedit /set testsigning on`) — VM only, never a real workstation; or
   * provision the VM for **preproduction signing**, which keeps Secure Boot enabled
     ([Microsoft: driver signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)).
3. Install the driver as a service, load it, and run the Phase 8 matrix with a real proxy-unaware
   application.
4. Enable **Driver Verifier for this driver only** (`verifier /standard /driver mproxy-wfp.sys`),
   never `/all`, and never on the workstation.
5. Record what the VM's endpoint protection says about the driver, without changing its settings.

## Why no attempt was made to work around this

A kernel driver that redirects network traffic is exactly the kind of component endpoint protection
is built to scrutinise, and a company workstation is exactly the kind of machine where that
scrutiny matters. Turning off Secure Boot or driver-signing enforcement to make a proof of concept
run would trade a real security property for a demo. The honest result is
**NOT TESTED: ENVIRONMENT UNAVAILABLE**, which is what Phase 8 reports.

## Cost summary for the decision

| Item | Needed for compile | Needed for runtime proof | Needed to ship |
|---|---|---|---|
| VS 2022 + SDK + WDK | yes | yes | yes |
| Disposable VM | no | **yes** | yes (test lab) |
| Test signing / preproduction provisioning | no | **yes (VM only)** | preproduction for lab |
| EV certificate | no | no | **yes** |
| Partner Center hardware account | no | no | **yes** |
| HLK-tested submission | no | no | **yes** (attestation is testing-only) |
| IT approval of a kernel driver | no | no | **yes** |

Signing details: [driver-signing-and-release.md](driver-signing-and-release.md).
