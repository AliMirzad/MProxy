# JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, …)

Private Proxy exposes a **stable local proxy endpoint** that you configure once in the IDE.
The IDE settings are never modified automatically.

| Endpoint | Default | Recommended |
|---|---|---|
| HTTP proxy | `127.0.0.1:10809` | **yes**: hostnames always go to the proxy, so there is no local DNS for proxied requests |
| SOCKS5 proxy | `127.0.0.1:10808` | alternative |

Both ports can be changed in the extension: **Settings → JetBrains / IDE proxy**.

## Behaviour

| Extension state | What the IDE gets through 127.0.0.1:10809 |
|---|---|
| Connected | traffic goes through the selected VLESS/VMess server |
| Disconnected, "Keep the endpoint working (direct) while disconnected" **on** (default) | direct Internet access. The IDE keeps working without changing its settings |
| Disconnected, that option **off** | nothing is listening; the IDE reports connection errors |
| Browser not running | nothing is listening (the runtime lives with the browser, see below) |

The endpoint is provided by the browser's native runtime, so **it exists only while the
browser (with the extension) is running**. Chrome/Brave can keep running in the background
after the last window closes if "Continue running background apps when … is closed" is
enabled in the browser settings.

Private IP ranges (10/8, 172.16/12, 192.168/16, 127/8, link-local, CGNAT, IPv6 ULA) always go
direct, even when connected.

## One-time setup

1. In the extension popup, check the line under the Connect button, for example:
   *IDE proxy (direct): HTTP 127.0.0.1:10809 · SOCKS 127.0.0.1:10808*.
   If it says a port is in use, pick other ports in **Settings** and use those below.
2. In the IDE, open **Settings** (macOS: **IntelliJ IDEA → Settings…**)
   → **Appearance & Behavior → System Settings → HTTP Proxy**.
3. Select **Manual proxy configuration**, then:
   * **HTTP**
   * Host name: `127.0.0.1`
   * Port number: `10809`
   * No proxy for: `localhost, 127.0.0.1, ::1` (plus your intranet hosts if they must stay direct)
   * Leave **Proxy authentication** unchecked (the endpoint is loopback-only and has no password).
4. Click **Check connection**, enter `https://www.jetbrains.com`, and confirm it succeeds.
   To confirm the tunnel is used, connect in the extension first, then check a URL that is only
   reachable through your server (or compare the IP reported by `https://ifconfig.me/ip`).
5. Click **OK**. Some components pick up proxy changes only after an IDE restart.

SOCKS alternative: choose **SOCKS**, host `127.0.0.1`, port `10808`. With SOCKS, some Java
networking paths may resolve hostnames locally before connecting. Prefer HTTP if DNS
privacy matters.

## What the IDE proxy setting does and does not cover

The IDE proxy applies to **network requests made by the IDE process itself**, for example:
plugin repository and plugin downloads, IDE and plugin updates, JetBrains account/licensing,
Settings Sync, JetBrains AI and other built-in cloud features, and IDE features that document
"use IDE proxy settings".

It **does not automatically apply** to separate programs the IDE starts. They use their own
proxy configuration:

| Tool | How to point it at the endpoint (examples) |
|---|---|
| Git (command-line git used by the IDE) | `git config --global http.proxy http://127.0.0.1:10809` (remove with `--unset`) |
| Gradle | IntelliJ may offer to copy the IDE proxy into `gradle.properties`; or set `systemProp.http(s).proxyHost=127.0.0.1` / `systemProp.http(s).proxyPort=10809` |
| Maven | `<proxies>` in `~/.m2/settings.xml` (host `127.0.0.1`, port `10809`) |
| npm / yarn / pnpm | `npm config set proxy http://127.0.0.1:10809` and `https-proxy` |
| Docker (daemon pulls) | Docker's own proxy settings (Docker Desktop → Settings → Resources → Proxies) |
| Terminal tab, run configurations, tests | environment variables such as `HTTPS_PROXY=http://127.0.0.1:10809`, or JVM options (`-Dhttps.proxyHost=…`) |

These per-tool settings are the user's choice. The product does not change them, and it
never changes the operating system proxy. Remember that a tool pointed at the endpoint fails
when the browser is not running.

## Troubleshooting

* **Check connection fails with "Connection refused":** the browser is not running, the IDE
  endpoint is disabled, or the port differs. Open the popup and read the IDE proxy line.
* **Popup says "Port 10809 is in use":** another program (e.g. another proxy client) or a
  second browser running Private Proxy holds the port. Only one browser can own the IDE ports.
  Pick different ports in Settings, or close the other program.
* **Works when connected, fails when disconnected:** enable "Keep the endpoint working
  (direct) while disconnected".
