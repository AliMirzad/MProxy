# macOS per-application routing: research

**macOS: RESEARCHED. CODE REVIEWED: n/a (no macOS code in Phase 7). REAL-MACHINE VERIFIED: NO** (no Mac available).
Sources: Apple developer documentation (JSON API of developer.apple.com) and Apple Platform
Deployment guides, 2026-09-22.

## Facts from Apple documentation

1. **`NEAppProxyProvider`** (app proxy provider extension, macOS 10.11+):
   * Receives each flow of apps that match the **app rules** of the configuration, as `NEAppProxyFlow`.
   * Returning `false` from `handleNewFlow` **closes** the flow.
   * Requires the Network Extension entitlement.
   * DNS: apps using high-level APIs hand the provider a hostname; low-level DNS APIs produce UDP DNS flows.
2. **Per-app VPN** (app rules → VPN), per Apple deployment documentation, "can only be deployed to a
   **managed** environment". Apps are mapped via MDM payloads (`AppLayerVPN`,
   `AppToAppLayerVPNMapping`), and the apps are managed apps.
3. **`NETransparentProxyProvider`** (macOS 11+, subclass of `NEAppProxyProvider`):
   * Returning `false` from `handleNewFlow` / `handleNewUDPFlow` makes the flow **proceed directly to its
     destination** (instead of being closed).
   * Matching is by `includedNetworkRules` (network rules, not app rules).
   * Uses the system's DNS/proxy settings; "connect by name" flows don't bypass DNS resolution.
4. **`NEFlowMetaData`** carries `sourceAppSigningIdentifier`, `sourceAppUniqueIdentifier` (hash) and
   `sourceAppAuditToken` of the flow's source app.
5. **Entitlement** `com.apple.developer.networking.networkextension`:
   * `app-proxy-provider-systemextension`, `packet-tunnel-provider-systemextension`,
     `content-filter-provider-systemextension` and `dns-proxy-systemextension` are the values
     "when signed with a Developer ID profile".
   * They are enabled for the team in Certificates, Identifiers & Profiles.
6. **System extensions** ship inside the app bundle (`Contents/Library/SystemExtensions`), are activated
   from the app with `OSSystemExtensionRequest`, and the app must be installed in `/Applications`.
   The system verifies the code signature and that the entitlements match the team's grants.

## Candidates

| Mechanism | Per-app for unmanaged desktop apps? | Class | Requirements | Verdict |
|---|---|---|---|---|
| Per-app VPN (`NEAppProxyProvider` / `NEPacketTunnelProvider` with app rules) | **no**: managed apps + MDM only | per-app | MDM, managed apps, NE entitlement | **POSSIBLE ONLY IN MANAGED ENVIRONMENT** |
| **`NETransparentProxyProvider`** system extension, deciding per flow by `sourceAppSigningIdentifier` / audit token | **yes**: sees flows of all apps matching network rules; returns `false` for unselected apps (go direct) | **TRUE PER-FLOW, BY APP IDENTITY** (unselected flows are presented to the extension, then released) | Apple Developer Program, Developer ID signing, notarization, NE `app-proxy-provider-systemextension` entitlement, system-extension activation with user approval | **POSSIBLE WITH ENTITLEMENT** (best candidate) |
| `NEPacketTunnelProvider` (full tunnel) + dispatch | yes, but all traffic enters the tunnel | SYSTEM-WIDE + DISPATCH | same signing/entitlement; routes/DNS | UNSUITABLE (global) |
| Content filter (`NEFilterDataProvider`) | can only allow/drop, not redirect | enforcement | entitlement + system extension | useful for fail-closed; not routing |
| `sandbox-exec` / pf rules / `route` | pf redirection by user/group, not app; needs root | global/root | root | UNSUITABLE |
| App-configured proxy (flags/env) | same limits as on Windows | APP-CONFIGURED | none | not routing |

## Open questions (UNKNOWN / REQUIRES REAL MAC)

* Exact approval UX on current macOS for a transparent proxy system extension (System Settings prompt, admin credentials), and MDM pre-approval payloads for company Macs.
* Whether `sourceAppSigningIdentifier` is reliable for child processes (helpers are usually separately signed with their own identifiers), so a process-tree policy would need the audit token → PID → parent lookup.
* UDP/QUIC behaviour of `handleNewUDPFlow` with Xray behind it, and IPv6.
* Whether Xray can run inside, or be spawned by, the system extension under its sandbox. A separate
  app-group helper might be needed, which interacts with the Phase 5 Seatbelt design.

## Identity model on macOS

* Prefer the **code-signing identity**: signing identifier + Team ID, checked against the audit
  token's code signature (`SecCodeCopyGuestWithAttributes` with the audit token). That is more robust
  than a path or bundle ID alone.
* **Spoofing:** an unsigned or ad-hoc-signed binary can claim any bundle identifier. Requiring a
  Team ID (Developer ID or App Store) prevents that for signed apps. Unsigned apps cannot be
  identified robustly and should not be selectable.

## Deployment summary

| Requirement | Needed for the transparent-proxy approach |
|---|---|
| Apple Developer Program | yes |
| Network Extension entitlement (`app-proxy-provider-systemextension`) | yes |
| System extension | yes |
| Developer ID signing + notarization | yes |
| User approval | yes (system-extension activation, and possibly allowing the proxy configuration) |
| Administrator | likely, for approval (UNKNOWN, requires a Mac) |
| MDM | no for the transparent proxy; **yes** for Apple's per-app VPN |
| Special Apple approval | Network Extension capability for Developer ID (portal); no separate request documented |

## Sources

* [NEAppProxyProvider](https://developer.apple.com/documentation/networkextension/neappproxyprovider)
* [NEAppProxyProvider.handleNewFlow](https://developer.apple.com/documentation/networkextension/neappproxyprovider/handlenewflow(_:))
* [NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
* [NEFlowMetaData](https://developer.apple.com/documentation/networkextension/neflowmetadata)
* [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
* [Installing system extensions and drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)
* [VPN overview for Apple device deployment](https://support.apple.com/en-lb/guide/deployment/depae3d361d0/web)
* [AppLayerVPN payload](https://support.apple.com/guide/deployment/applayervpn-payload-settings-dep0323d652d/web)
* [AppToAppLayerVPNMapping](https://developer.apple.com/documentation/devicemanagement/apptoapplayervpnmapping)
