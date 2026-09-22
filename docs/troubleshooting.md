# Troubleshooting

Start with the popup: the status line is designed to say what is wrong. **Settings → About** shows the
extension, runtime, Xray and protocol versions. **Copy diagnostics** puts a credential-free report on the
clipboard.

## Popup messages

| Popup shows | Meaning | Fix |
|---|---|---|
| **Native runtime missing** – "Native runtime is not installed." | The browser found no native messaging registration for `com.privateproxy.host` | Run the runtime installer (Install.cmd / install.sh), then click **Retry**. macOS: start the browser once before `install.sh`, or use `./install.sh --all-browsers` |
| **Native runtime not authorized** | The manifest's `allowed_origins` does not list this extension's ID | Check the ID on `chrome://extensions` is `pmagpgfembejahekgbdifepphmaigngl`, and reinstall the runtime from the matching release |
| **Native runtime stopped** (with retry countdown) | The helper exited or could not start (e.g. blocked by Gatekeeper/antivirus, or a missing file) | Reinstall the runtime. macOS: make sure the quarantine attribute was removed (`install.sh` does it). Check the helper log |
| **Update required** | Extension and runtime speak different protocol versions | Update the component named in the message ([installation.md](installation.md#updating-manual)) |
| **Server unreachable** | Xray started, but a test request through the server failed | Server offline, wrong/expired credentials, blocked by the network, or a transport mismatch. Re-import a fresh link or refresh the subscription |
| **Invalid configuration** | The link is malformed, or Xray's own validation rejected the config (the message quotes the reason) | Ask the provider for a current link. `h2`/`http`/`quic` transports were removed from Xray-core; use XHTTP |
| **Xray failed** | Xray could not start or kept crashing (two automatic restarts failed) | Try again. If it repeats, enable verbose diagnostics and read the log |
| **Browser proxy blocked** | Another extension (or policy) controls the browser proxy | Disable other proxy/VPN extensions, or ask IT about the proxy policy |
| **Secure storage unavailable** / "The key that protects your saved servers is missing" | The Credential Manager/Keychain item that decrypts saved servers is missing, replaced or inaccessible. (Before this fix, the automated browser test shared that item with the real installation and deleted it; each data directory now has its own item) | macOS: allow keychain access when asked. Otherwise use Settings → **Remove all servers** and add the subscription/links again |
| **Subscription update failed** (in Settings) | Provider unreachable, HTTP error, not HTTPS, over 5 MiB, or no VLESS/VMess entries | Check the URL in a browser, try again while connected (the fetch goes through the tunnel) |
| **Xray failed: "Xray integrity check failed"** | The installed Xray does not match the pinned release (modified, corrupted, or replaced) | Reinstall the runtime from the official package. Treat an unexpected change as a security incident |
| Import error **"… is not allowed: …"** / **"Unsupported field …"** | The configuration contains a field that could touch local files, bind interfaces, chain proxies or resolve names locally, or that this version does not know | Ask the provider for a plain client link. The message names the field |
| **"Server address … points to this computer"** / **"not allowed: link-local"** | The link targets localhost, a cloud metadata address or a similar local destination | These are refused by design |
| **"Subscription URL points to a private network address"** | The subscription server is on an internal network | If it is your company's server: Settings → Subscriptions → "Allow private-network subscription URLs" |
| **Browser proxy blocked** after being connected | Another extension (or policy) took over the browser proxy, so the tunnel was disconnected | Disable the other proxy extension and connect again |
| IDE line: **Port 10809 is in use** | Another program or another browser running Private Proxy holds the IDE port | Close it, or choose other ports in Settings (and update the IDE) |

## Common questions

**Is my whole computer proxied?** No. Only this browser profile is (and whatever you explicitly point at
`127.0.0.1:10809/10808`). System proxy, DNS and other apps are untouched.

**Connected, but a site shows my real IP.** The site may use WebRTC. Check that **Settings → Privacy → Block
WebRTC** is enabled (it is on by default). Also check `chrome://net-internals/#proxy`: the effective proxy should be
`http://127.0.0.1:<port>` (protocol v3). If it is not, another extension may be winning; the popup would say so.

**"Runtime security check failed".** A mandatory protection (Xray integrity, Xray isolation, private data folder,
sandbox on macOS) could not be applied or verified, so the connection was not started. Copy the diagnostics. Typical causes:
a changed ACL on `%LOCALAPPDATA%\PrivateProxy`, security software interfering with process creation, or (macOS)
`sandbox-exec` unavailable. Do not work around it; report it to IT.

**Disconnected: "Another extension changed the WebRTC setting".** Another extension or a policy controls WebRTC, so the
real IP could leak. Remove the other extension, or turn off WebRTC protection in Settings if you accept that risk.

**Everything went direct after an error.** That is the V1 design (no kill switch): if the tunnel fails, the
browser returns to direct networking instead of breaking. The popup shows the error.

**Local/intranet sites.** Plain host names, `localhost`, and private ranges (10/8, 172.16/12,
192.168/16, …) bypass the tunnel. Private-IP intranet resources are therefore **not** reached through the
VPN server in V1.

**Incognito windows.** The proxy setting applies to incognito windows as well. The extension does not need
to be allowed in incognito for that.

**Browser closed → IDE lost connectivity.** The runtime lives with the browser. Keep the browser running,
or enable "Continue running background apps" in its settings.

**A subscription shows far more servers than it has.** Versions before this fix imported every outbound of
an Xray-JSON subscription (each config contains several alternative CDN paths to the same server). Now each
config is one server. Choose the subscription in **Show**, then click **Update subscription**: the extra entries
are removed.

## Verifying DNS behaviour yourself

1. Connect, open `chrome://net-export`, record for a minute of browsing, stop, and load the file in
   <https://netlog-viewer.appspot.com>. Proxied requests show `SOCKS5` connect jobs with **hostnames**, and there are no
   `HOST_RESOLVER` jobs for those hosts.
2. Or use a DNS-leak test site. It should report the resolver of your VPN server's network, not your ISP.

## Collecting logs for a bug report

1. Settings → enable **Verbose diagnostics log**, reproduce, then disable it again.
2. Attach `helper.log` (Windows: `%LOCALAPPDATA%\PrivateProxy\logs\`, macOS: `~/Library/Logs/PrivateProxy/`) and
   the **Copy diagnostics** output. Both are redacted, but review them before sharing. Verbose logs can
   contain the hostnames you visited.
3. Never share links, UUIDs or subscription URLs.

## Low-level checks

```bash
# versions and registration
"%LOCALAPPDATA%\Programs\PrivateProxy\private-proxy-host.exe" status
~/Library/Application\ Support/PrivateProxy/runtime/private-proxy-host --version

# is the IDE endpoint up? (expect an HTTP response)
curl -x http://127.0.0.1:10809 -I https://www.jetbrains.com
```
