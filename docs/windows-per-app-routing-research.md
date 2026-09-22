# Windows per-application routing: research

Status: **RESEARCH ONLY** unless a row says otherwise. Date: 2026-09-22. Sources are Microsoft
Learn and vendor pages (listed at the end); nothing here relies on blog posts alone.

## The requirement

```text
selected app (e.g. ChatGPT.exe, Cursor.exe + children) → Xray → VLESS/VMess → Internet
every other process (Chrome, Spotify, Windows Update)  → DIRECT
```

This must work for apps with **no** proxy settings. It must not change the system proxy,
default route, global DNS or adapters, unless no alternative exists (then it is a major downside).

Three things must not be confused:

| Class | Meaning |
|---|---|
| **TRUE PER-PROCESS ROUTING** | the OS/network stack decides per connection by process identity; unselected traffic never touches the tunnel |
| **SYSTEM-WIDE TUNNEL WITH PROCESS DISPATCH/EXCLUSIONS** | all traffic enters a tunnel (routes/DNS changed); software then sends some processes out directly |
| **APP-CONFIGURED PROXY** | the app itself is told to use a proxy (setting, flag, environment); the OS does not enforce it |

## What Windows offers (facts from the documentation)

1. **WFP connect/bind redirection exists only for kernel-mode callout drivers.**
   * `FwpsRedirectHandleCreate0`, `FWPS_CONNECT_REQUEST0`, `FwpsApplyModifiedLayerData0` are `fwpsk.h` (kernel) APIs.
   * The local proxy recovers the original destination with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, and must set `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on its outbound socket to avoid loops.
   * Supported for TCP, UDP, raw UDPv4, raw ICMP. Microsoft documents that **connected UDP redirected to a local proxy is dropped** (workaround: the app must use `sendto`; it cannot be changed from outside).
2. **User-mode WFP (`Fwpm*`) can add filters but cannot redirect.**
   * Filters PERMIT/BLOCK at `ALE_AUTH_CONNECT_V4/V6` (TCP connect, first UDP packet per remote tuple) with conditions such as:
     * `FWPM_CONDITION_ALE_APP_ID` (lower-case device path from `FwpmGetAppIdFromFileName0`);
     * `ALE_USER_ID` (security descriptor, so per user);
     * `ALE_PACKAGE_ID` (AppContainer SID);
     * remote address/port, protocol.
   * **There is no process-ID, parent-process or process-tree condition.**
3. **Adding WFP objects needs rights that normal users do not have.** The default engine DACL grants
   `GENERIC_ALL` to Administrators, read/write to Network Configuration Operators and some services,
   and only OPEN + CLASSIFY to everyone. Filters added in a **dynamic session** disappear when that
   session closes, including when its process dies (automatic crash cleanup).
4. **Kernel drivers**: since Windows 10 1607, new kernel drivers load only if signed through the
   Microsoft Hardware Dev Center portal (attestation or WHQL). **An EV code-signing certificate is required to
   open the portal account.** Test-signing mode is a machine security setting (not acceptable on company machines).
5. **Windows VPN platform** (built-in VPN, VPNv2 CSP, UWP VPN plug-in):
   * *App-based traffic filters* "only allow traffic originating from the apps to the VPN interface". They permit/deny on the interface.
   * Which interface a flow takes is still decided by **routes** (force tunnel = VPN default routes; split tunnel = destination routes).
   * A custom protocol needs a packaged UWP VPN plug-in with the **restricted** capability `networkingVpnProvider`; deployment is typically via MDM ProfileXML.
6. **Third-party drivers**:
   * **Wintun**: signed L3 TUN adapter, GPLv2 source, permissive license for the signed binaries.
   * **WinDivert**: signed packet capture/re-injection driver, LGPLv3/GPLv2. It needs Administrator every time a handle is opened (driver loads on demand); its FLOW/SOCKET layers report process IDs, with a documented race at process exit.
7. **Apps ignore proxy environment variables more often than not.** Node.js does **not** honor
   `HTTP(S)_PROXY` unless `NODE_USE_ENV_PROXY=1` / `--use-env-proxy` is set. Chromium/Electron apps honor
   `--proxy-server`, but cannot answer an HTTP 407 without app code and cannot send SOCKS credentials.

## Candidates

### W1. WFP ALE connect-redirect callout driver + user-mode proxy service
Kernel callout at `ALE_CONNECT_REDIRECT_V4/V6` rewrites the destination of selected apps' connections
to a local proxy. The proxy reads the original destination and forwards it through Xray.
* The driver sees the PID in classify metadata and can track process creation (`PsSetCreateProcessNotifyRoutineEx`), so child-process policies are implementable, **in kernel code**.
* Identity: app path + user SID from WFP, plus whatever the driver/service verifies (signature, hash).
* **TRUE PER-PROCESS ROUTING.** This is how commercial per-app proxy tools on Windows work.

### W2. WinDivert packet NAT to a local proxy
User-mode process captures selected flows (PID from FLOW/SOCKET events, matched to packets by 5-tuple)
and NATs them to a local transparent inbound.
* Per-process, but packet-level and racy, and an **Administrator process is needed at runtime** (or a privileged service).
* Third-party kernel driver that EDR products commonly flag, because the same driver is popular in malware and game cheats.

### W3. TUN adapter (Wintun) + user-mode stack with process dispatch (sing-box/Clash style)
Default route (or large split routes) and DNS pointed at the TUN. A user-mode TCP/IP stack maps each
flow to a PID (e.g. `GetExtendedTcpTable`) and sends selected ones to Xray, others out directly
(needs its own "direct" binding/loop avoidance).
* **SYSTEM-WIDE TUNNEL WITH PROCESS DISPATCH.** Every unselected app's traffic is inside our process.
* Global route and DNS changes; a crash can leave routes/DNS broken until cleanup.

### W4. Windows VPN platform + app traffic filters
* Needs a packaged VPN plug-in (restricted capability) or a built-in protocol that Xray does not speak.
* App filters restrict the VPN interface. They do not make unselected apps go direct when routes point into the VPN.
* **Not per-app routing for our purpose**; deployment via MDM. RESEARCH ONLY.

### W5. User-mode WFP filters (no driver): enforcement only
PERMIT selected app → `127.0.0.1:<its proxy port>`; BLOCK selected app → everything else
(IPv4, IPv6, TCP, UDP).
* **Cannot route.** It can make an app-configured proxy **fail closed** (no silent direct bypass, including IPv6/UDP/QUIC/WebRTC).
* Scoped per user via `ALE_USER_ID`. Dynamic session gives automatic cleanup on crash.

### W6. App-configured proxy (launch the app with a proxy flag/environment)
* No privileges, no system change.
* **APP-CONFIGURED PROXY**, and only for apps that honor the setting.
* Chromium/Electron: `--proxy-server`, but no way to supply our listener credentials, so an authenticated inbound fails (407). An unauthenticated inbound would re-open Phase 5's F5 hole.
* Many apps and children (Node tools, Go/Rust binaries, git) ignore it silently.

### W7. Injection / hooking / Winsock LSP
DLL injection or API hooks into target apps. LSPs are deprecated. **Rejected by project rule** (host
compromise risk, EDR alerts, maintenance). Not evaluated further.

## Decision matrix

| | W1 WFP callout | W2 WinDivert | W3 TUN + dispatch | W4 VPN platform | W5 WFP user filters | W6 app-configured |
|---|---|---|---|---|---|---|
| Officially supported | yes (documented WFP) | third-party | third-party driver, documented routing | yes | yes | n/a |
| Mode | kernel + user | kernel (3rd) + user | kernel (3rd) + user | OS + packaged plug-in | user | user |
| Driver required | **yes, ours** | yes (3rd party) | yes (Wintun) | no (plug-in) | **no** | no |
| New signing needs | **EV cert + MS HDC signing** | none (vendor-signed) | none (vendor-signed) | Store/restricted capability | none | none |
| Admin install | yes | yes | yes | yes/MDM | yes (service) | no |
| Admin runtime | no, via a service | **yes** (or service) | no, via a service | no | no, via a service | no |
| Per-process identity | path, user, PID in kernel | PID (racy) | PID by socket-table lookup (racy) | path/package | path, user, package | whoever is launched |
| Child processes | implementable (kernel process notify) | racy | racy | no | by path only | inherits env/flags only if the child honors them |
| TCP | yes | yes | yes | yes | enforce only | app-dependent |
| UDP | partial (connected UDP to local proxy broken) | yes | yes | yes | enforce only | mostly no |
| IPv4 / IPv6 | both layers | both | both (if routed) | both | both | app-dependent |
| DNS | app resolves locally before connect (leak unless UDP 53/DoH also handled) | same | TUN can capture DNS (global DNS change) | VPN DNS | can block direct DNS of the app | remote DNS if the app sends hostnames (CONNECT/SOCKS5h) |
| Loopback | must exclude | must exclude | excluded by routes | n/a | must permit | n/a |
| Crash cleanup | filters/driver persist unless session-scoped; proxy down means connections fail | driver unloads when handles close | **routes/DNS may be left changed** | OS-managed | dynamic session auto-removes | nothing to clean |
| System-wide side effects | driver + service + WFP objects | driver | **routes, DNS, adapter** | VPN profile, interface | WFP filters (session) | none |
| Security risk | kernel code (bugs = BSOD/escalation); privileged service API | admin packet access; EDR alerts | all traffic through our process | low | privileged service API | **open or credential-less proxy; silent bypass** |
| EDR implication | new kernel driver: high scrutiny | commonly flagged | TUN adapter visible | normal VPN | WFP filters visible | none |
| Complexity | high (driver dev, HLK/attestation, loop handling) | medium | high | high + packaging | low | low |
| Maintainability | good once built (stable APIs since Win 8) | depends on 3rd party | medium | Windows-VPN-specific | good | poor (per-app quirks) |
| Class | **TRUE PER-PROCESS** | per-process (packet) | **SYSTEM-WIDE + DISPATCH** | interface filter | enforcement | **APP-CONFIGURED** |

## Conclusion from research (before any PoC)

* The **only** supported way to get true per-process routing on Windows without global route/DNS
  changes is **W1, a WFP connect-redirect callout driver**. It requires writing kernel code,
  Microsoft signing with an EV certificate, admin installation and a narrowly scoped privileged service.
* **W5** (user-mode WFP filters, no driver) is the supported way to make routing **fail closed** per app,
  with automatic crash cleanup. It needs admin rights or a privileged service to add filters.
* **W3** works technically but is a system-wide tunnel. **W2** relies on a driver EDR products flag.
  **W4** does not fit. **W7** is rejected.
* **W6** needs no privileges, but it is not routing and, as documented above, leaks by default.

What can be verified on this machine (no Administrator shell, no test-signing, and changing security
settings is out of scope):

| Question | Can be runtime-verified here? |
|---|---|
| W1 driver behaviour | **ENVIRONMENT UNAVAILABLE** (kernel driver needs WDK, Microsoft signing or test-signing, admin) |
| W5 filter behaviour | only by the user, in an elevated shell they start themselves |
| W5 privilege requirement (non-admin denied) | **yes** |
| W6 behaviour of real apps (honor / ignore / fail with auth) | **yes** |

This defines the Phase 7 PoC scope; see [per-app-routing-decision.md](per-app-routing-decision.md).

## Sources

* [ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
* [Using bind or connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
* [FwpsRedirectHandleCreate0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandlecreate0)
* [Failed to redirect connected UDP traffic](https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/redirection-connected-udp-traffic-local-proxy-fail)
* [WFP access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)
* [Filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
* [Driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
* [VPN routing decisions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-routing)
* [VPN security features (traffic filters)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-security-features)
* [VPNv2 CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/vpnv2-csp)
* [Windows.Networking.Vpn (networkingVpnProvider)](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn)
* [Wintun](https://www.wintun.net/)
* [WinDivert documentation](https://reqrypt.org/windivert-doc.html)
* [Node.js CLI (`--use-env-proxy`)](https://nodejs.org/api/cli.html)
