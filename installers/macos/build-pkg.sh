#!/bin/sh
# Builds a macOS installer package (.pkg) from a staged runtime folder.
# Must run on macOS (uses pkgbuild/productbuild from Xcode command line tools).
#
#   installers/macos/build-pkg.sh <staged-runtime-dir> <version> <out.pkg>
#
# The package installs the runtime system-wide (root-owned, so users cannot tamper with the
# binaries) to /Library/Application Support/PrivateProxy/runtime and, in postinstall, registers
# native messaging for the user logged in at the console. Other users on the Mac run:
#   "/Library/Application Support/PrivateProxy/runtime/private-proxy-host" install --register-only \
#       --target "/Library/Application Support/PrivateProxy/runtime"
#
# Signing: set PKG_SIGN_IDENTITY="Developer ID Installer: ..." to sign; notarize separately
# (see docs/installation.md). Unsigned packages must be opened with right-click > Open.
set -eu
SRC="$1"; VERSION="$2"; OUT="$3"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root/Library/Application Support/PrivateProxy/runtime"
mkdir -p "$ROOT" "$WORK/scripts"
cp -R "$SRC/private-proxy-host" "$SRC/xray" "$ROOT/"
[ -d "$SRC/LICENSES" ] && cp -R "$SRC/LICENSES" "$ROOT/"
chmod 755 "$ROOT/private-proxy-host" "$ROOT/xray/xray"
cat > "$WORK/scripts/postinstall" <<'POST'
#!/bin/sh
RT="/Library/Application Support/PrivateProxy/runtime"
/usr/bin/xattr -dr com.apple.quarantine "$RT" 2>/dev/null || true
CONSOLE_USER="$(/usr/bin/stat -f%Su /dev/console)"
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  USER_HOME="$(/usr/bin/dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | /usr/bin/awk '{print $2}')"
  /usr/bin/sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$RT/private-proxy-host" install --register-only --target "$RT" || true
fi
exit 0
POST
chmod 755 "$WORK/scripts/postinstall"
SIGN=""
[ -n "${PKG_SIGN_IDENTITY:-}" ] && SIGN="--sign $PKG_SIGN_IDENTITY"
# shellcheck disable=SC2086
pkgbuild --root "$WORK/root" --scripts "$WORK/scripts" --identifier com.privateproxy.runtime \
  --version "$VERSION" --install-location / $SIGN "$OUT"
echo "built $OUT"
