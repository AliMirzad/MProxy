Private Proxy - native runtime for Windows
==========================================

1. Close Chrome/Brave/Edge completely (or restart them after installing).
2. Double-click Install.cmd.
   - Installs to %LOCALAPPDATA%\Programs\PrivateProxy (per user, no admin rights).
   - Registers the native messaging host for Chrome, Chromium, Brave and Edge.
   - Does NOT change system proxy, DNS, VPN or any other system settings.
3. Load the extension (see "Loading the extension" in the project README).

Uninstall: Settings > Apps > "Private Proxy (browser runtime)", or run Uninstall.cmd.

If Windows SmartScreen warns about Install.cmd or private-proxy-host.exe: these V1 builds are
not code-signed. Choose "More info" > "Run anyway" only if you obtained this package from your
internal distribution.
