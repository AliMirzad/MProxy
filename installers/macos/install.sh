#!/bin/sh
# Private Proxy - install the native runtime for the current user (no sudo needed).
# Installs to ~/Library/Application Support/PrivateProxy/runtime and registers the native
# messaging host for Chrome, Chromium, Brave, Edge and Vivaldi (browsers that exist).
# Pass --all-browsers to also register browsers that have not been started yet.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
# Gatekeeper blocks quarantined unsigned binaries; this package is for internal distribution.
/usr/bin/xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true
chmod +x "$DIR/private-proxy-host" "$DIR/xray/xray"
exec "$DIR/private-proxy-host" install "$@"
