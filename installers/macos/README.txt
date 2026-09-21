Private Proxy - native runtime for macOS
========================================

1. Open Terminal in this folder and run:   ./install.sh
   - Installs to ~/Library/Application Support/PrivateProxy/runtime (per user, no sudo).
   - Registers the native messaging host for installed Chromium browsers.
   - Does NOT change system proxy, DNS, VPN or any other system settings.
   - No Dock icon, no menu bar item, no login item.
2. Restart the browser and load the extension (see the project README).

Uninstall:  ./uninstall.sh  (add --purge to also delete servers and credentials)

These V1 builds are not signed/notarized. install.sh removes the quarantine attribute from this
folder so Gatekeeper does not block the helper. See docs/installation.md for details.
