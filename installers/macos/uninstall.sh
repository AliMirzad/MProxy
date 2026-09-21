#!/bin/sh
# Private Proxy - remove the native runtime and browser registration.
#   ./uninstall.sh           keep imported servers (can be reused after reinstalling)
#   ./uninstall.sh --purge   also delete servers, credentials (Keychain item) and logs
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
/usr/bin/xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true
exec "$DIR/private-proxy-host" uninstall "$@"
