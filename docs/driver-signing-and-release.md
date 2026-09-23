# Driver signing and release (Windows kernel driver)

What it takes to ship `mproxy-wfp.sys` to a user's machine. Sources are Microsoft Learn, retrieved
2026-09-23; the pages are dated 2026-03/04, and they correct assumptions made in Phase 7.

## The three signing offerings, as Microsoft defines them

| Offering | What it is for | Loads where | Requirements |
|---|---|---|---|
| **HLK-tested, dashboard signed** (Windows Hardware Compatibility Program) | **production** | Windows Vista and later, **including Windows Server** | Hardware Lab Kit test pass + Partner Center submission; EV certificate on the account |
| **Attestation signed** | **"For testing purposes only"** | Windows 10 desktop and later only | Partner Center + **EV code-signing certificate**; cannot be published to Windows Update for retail; **not Windows Certified**; **Windows Server 2016+ will not load it** |
| **Preproduction signed** | early development and validation | only devices explicitly **provisioned** to trust it; Secure Boot stays **on** | Partner Center access + device provisioning |

Two sentences worth keeping verbatim in front of any planning discussion:

> "For testing purposes only, you can submit your drivers for attestation signing, which doesn't
> require HLK testing."

> "When a driver receives attestation signing, it's not Windows Certified."

**Correction to Phase 7:** the earlier wording "EV + Microsoft attestation/WHQL" implied attestation
was a shipping path. It is not. Phase 7.5 corrected the decision document; this file is the record.

## The release chain for this product

1. **EV code-signing certificate** issued to the legal entity (hardware token, organisation
   validation). Required even for attestation submissions.
2. **Partner Center hardware account** (Hardware Dev Center), which the EV certificate enrols.
3. **Development**: build with the WDK, test in a VM — test signing inside the VM, or preproduction
   signing if Secure Boot must stay enabled ([driver-build-environment.md](driver-build-environment.md)).
4. **HLK testing** for a WFP callout driver, on the supported platforms, producing the submission
   package.
5. **Submit** to Partner Center; Microsoft re-signs the package.
6. **Ship** the Microsoft-signed `.cab`/driver package inside the product installer, which installs
   it as a service (admin at install time only).
7. **Authenticode-sign** the user-mode parts as well: helper, routing service, redirector. This is
   F12 and applies regardless of the driver.
8. **IT allowlisting**: endpoint products will see a new kernel driver that redirects network
   traffic. That is expected and correct; the answer is signing, reputation and an explicit
   allowlist entry, never evasion ([per-app-routing-corporate-impact.md](per-app-routing-corporate-impact.md)).

## Enterprise variations

* **WDAC**: an enterprise can require at least attestation signing, or pin its own policy. A
  customer's WDAC policy can block a correctly signed driver, so deployment documentation must state
  the signer identity.
* **Windows Server**: attestation is not accepted at all; HLK is the only route.
* **HVCI / Kernel-mode code integrity**: the driver must be HVCI-compatible; preproduction signing
  exists precisely to test these interactions with Secure Boot on.

## What this means for the schedule

Nothing about the driver can reach a user before steps 1–5 are complete, and steps 1, 2 and 4 are
procurement and certification work measured in weeks, not an afternoon. Any roadmap that puts a
Desktop client with transparent per-app routing in front of users must start the certificate and
Partner Center work **before** the engineering, not after.

## Sources

* [Driver signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)
* [Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
* [Windows HLK getting started](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/getstarted/windows-hlk-getting-started)
* [Kernel-mode code signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
