# Managed deployment (company workstations)

Why this exists: in the personal installation the user loads the extension with **Load unpacked**,
so developer mode is on. In that mode, any unpacked extension that copies MProxy's public manifest
`key` gets MProxy's extension ID. The native host cannot tell the two apart: native messaging only
passes the caller's origin. The impersonation experiment
(`extension/tests/e2e/experiments/impersonation-experiment.mjs`) confirmed that such a copy can:

* read the IDE password;
* switch IDE authentication off;
* allow private subscription hosts;
* import attacker servers.

When both copies are loaded, **the one loaded last wins the ID**. This is **HIGH** for unmanaged
installs ([security-gate.md](security-gate.md) B9) and can only be closed by deployment policy.

Status of this document:
* The model is **PASS (CODE REVIEW ONLY)**, based on Chromium's documented policies.
* Enforcing the policies was **ENVIRONMENT UNAVAILABLE** (it needs administrator rights and a
  managed test machine).
* IT must validate it on a pilot machine with the checks in [Verification](#verification).

## Personal vs managed

| | Personal (current) | Managed (required for company use) |
|---|---|---|
| Extension | unpacked folder, developer mode | **CRX, force-installed by policy** from a company update URL; signature binds the ID |
| Developer mode | on | **off by policy**; unpacked extensions and `--load-extension` blocked |
| Other extensions | anything the user installs | **blocklist `*`**, allowlist of approved IDs |
| Native host registration | per user (HKCU / `~/Library/...`) | **machine-wide** (HKLM / `/Library/Google/Chrome/NativeMessagingHosts`), user-level hosts disabled |
| Runtime binaries | user folder, unsigned | `%ProgramFiles%\MProxy` (admin-writable only), **Authenticode / Developer ID signed**, allowlisted in EDR |
| Servers | anything the user imports | company subscription only (see corporate mode) |

## Policies

Keys: Chrome `HKLM\SOFTWARE\Policies\Google\Chrome`, Chromium `HKLM\SOFTWARE\Policies\Chromium`,
Brave `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`, Edge `HKLM\SOFTWARE\Policies\Microsoft\Edge`.
macOS: configuration profile for `com.google.Chrome` / `org.chromium.Chromium` /
`com.brave.Browser` / `com.microsoft.Edge` delivered by MDM.

| Policy | Value | Closes |
|---|---|---|
| `ExtensionInstallForcelist` | `pmagpgfembejahekgbdifepphmaigngl;https://it.example.com/mproxy/updates.xml` | the real extension is always present, from a signed CRX |
| `ExtensionInstallBlocklist` | `*` | no other extension can be installed (incl. an impersonator) |
| `ExtensionInstallAllowlist` | MProxy ID + other approved IDs | — |
| `ExtensionDeveloperModeSettings` | `1` (not allowed) | Load unpacked / developer mode |
| `ExtensionSettings` | `{"*": {"installation_mode": "blocked", "blocked_install_message": "…"}, "pmagpgfembejahekgbdifepphmaigngl": {"installation_mode": "force_installed", "update_url": "https://it.example.com/mproxy/updates.xml", "toolbar_pin": "force_pinned"}}` | same as the three above, in one policy; prefer this |
| `NativeMessagingUserLevelHosts` | `false` | ignores per-user host registrations, so a user-level `com.privateproxy.host` pointing at another program cannot be used |
| `NativeMessagingAllowlist` | `["com.privateproxy.host"]` (+ other approved hosts) | — |
| `NativeMessagingBlocklist` | `["*"]` | other native hosts |
| `DeveloperToolsAvailability` | `2` (optional, stricter) | inspecting/altering the extension's service worker |
| `ProxySettings` | **do not set** | a policy proxy would override MProxy (the tunnel would then report "Browser proxy blocked") |
| `WebRtcIPHandling` | `disable_non_proxied_udp` (optional) | makes the WebRTC protection mandatory even if a user turns it off |

Signed CRX: pack `extension/dist` with the private key that matches `extension/manifest.key.json`
(the key that yields ID `pmagpgfembejahekgbdifepphmaigngl`). Keep that private key offline. Its
compromise equals being able to publish MProxy. Host `updates.xml` and the CRX on an internal HTTPS
server.

## Machine-wide native host

1. Install the runtime to `%ProgramFiles%\MProxy` as administrator. The directory must be writable
   only by Administrators/SYSTEM.
2. Register `com.privateproxy.host` under
   `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.privateproxy.host` (and the Chromium/Brave/Edge
   equivalents). Point it at a manifest in that directory with `allowed_origins` = only
   `chrome-extension://pmagpgfembejahekgbdifepphmaigngl/`.
3. Set `NativeMessagingUserLevelHosts=false`.

The current installer registers per user. A machine-wide installer (MSI/`.pkg` for MDM) is a
packaging task for IT. It is not a product feature and is not implemented in this phase.

## Verification

On a pilot machine with the policies applied:

1. `brave://policy` / `chrome://policy` shows the policies with status OK.
2. `node extension/tests/e2e/experiments/impersonation-experiment.mjs --browser <path>` with the
   managed profile: loading the impersonator must be refused (developer mode unavailable). The
   script uses a throwaway profile, so adapt it to the managed profile or repeat the steps manually.
3. Manually try "Load unpacked": the button must be absent or disabled.
4. Put a user-level registration for `com.privateproxy.host` pointing at `notepad.exe` into HKCU:
   the extension must still reach the machine-wide helper (the Diagnostics path shows `%ProgramFiles%`).
5. EDR: the signed helper and Xray must run without quarantine (see below).

## Endpoint security

On the review machine, Kaspersky Endpoint Security removed the **unsigned** release helper seconds
after it was written to disk. The older installed build (protocol 2) and the debug build were not
removed. Required for company use:

* sign `private-proxy-host.exe` (Authenticode; `PRIVATE_PROXY_SIGN_THUMBPRINT` in `scripts/package.mjs`);
* have IT allowlist the signer or the hashes from `RELEASE-MANIFEST.json`;
* Xray keeps its official, unmodified signature status: allowlist it by the pinned SHA-256.

The product must not be modified to evade detection.

## Corporate mode design

This is a design only. Nothing here is implemented in this phase.

A corporate build differs from the personal one only by a **read-only policy file** shipped in the
machine-wide install directory, for example `%ProgramFiles%\MProxy\policy.json`, or the macOS
configuration profile `com.mproxy.policy`. The helper reads it at start. Users cannot change it,
because the directory is admin-only. Missing file = personal mode.

```jsonc
{
  "version": 1,
  "approvedExtensionIds": ["pmagpgfembejahekgbdifepphmaigngl"],   // helper refuses any other argv origin
  "subscriptions": [                                              // the only allowed sources
    { "name": "Company", "url": "https://vpn.example.com/sub/<per-user token or SSO>", "pinnedSpkiSha256": ["…"] }
  ],
  "allowManualImport": false,          // importText / QR disabled
  "allowUserSubscriptions": false,     // addSubscription disabled for other URLs
  "allowedServerSuffixes": [".vpn.example.com"],  // servers outside these are rejected at import and connect
  "requireIdeAuth": true,              // setSettings cannot switch it off
  "requireWebrtcProtection": true,
  "probeUrl": "http://probe.vpn.example.com/generate_204",   // company-owned health check (data-flow flow 7)
  "xray": { "version": "v26.3.27", "sha256": "15c2d0…" },    // must equal the compiled-in pin, else refuse
  "allowPrivateSubscriptionHosts": true
}
```

Enforcement points:

| Control | Where it would be enforced |
|---|---|
| Approved extension IDs | `main.rs` origin check (in addition to `allowed_origins`) |
| Trusted subscriptions only | `service.rs` import/subscription commands return `POLICY_DENIED` |
| Server allowlist | `validate::address` + connect-time re-check |
| Settings locks | `setSettings` rejects locked keys; UI shows them as managed |
| Health-check target | `probe::default_targets` |
| Pinned Xray | already compiled in. The policy can only confirm it, never change it |
| Signed binaries | OS/EDR (WDAC/AppLocker allow rules by publisher) |
| Browser side | the policies above |

Personal use stays unchanged: no policy file means today's behaviour, documented in [installation.md](installation.md).
