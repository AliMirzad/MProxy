# Installation, updates and removal

Private Proxy has two parts. The user interacts only with the first.

1. **The browser extension**, loaded unpacked (V1 is not in any web store).
2. **The native runtime**: `private-proxy-host` plus the bundled Xray-core. It has no window, tray
   icon or Dock icon, and the browser starts and stops it.

Release artifacts (from `node scripts/package.mjs`, or from CI):

| File | Contents |
|---|---|
| `PrivateProxy-extension-<ver>.zip` | the unpacked extension |
| `PrivateProxy-runtime-windows-x64-<ver>.zip` | helper, Xray, `Install.cmd`, `Uninstall.cmd`, licenses |
| `PrivateProxy-runtime-macos-<arm64\|x64>-<ver>.tar.gz` | helper, Xray, `install.sh`, `uninstall.sh`, licenses |
| `PrivateProxy-runtime-macos-<arch>-<ver>.pkg` | optional system-wide macOS installer (built on macOS) |

## Windows (Chrome, Brave, Chromium, Edge)

### Install the runtime
1. Extract `PrivateProxy-runtime-windows-x64-<ver>.zip` anywhere (e.g. Downloads).
2. Double-click **Install.cmd**. No administrator rights are needed. It:
   * copies the runtime to `%LOCALAPPDATA%\Programs\PrivateProxy\`,
   * writes `com.privateproxy.host.json` there,
   * registers the host under `HKCU\Software\<browser>\NativeMessagingHosts\com.privateproxy.host`
     for Google Chrome, Chromium, BraveSoftware\Brave-Browser and Microsoft Edge,
   * adds "Private Proxy (browser runtime)" to **Settings → Apps** for uninstalling.
3. If SmartScreen warns (V1 builds are unsigned), choose *More info → Run anyway* only for
   packages from your internal distribution.

### Load the extension
1. Extract `PrivateProxy-extension-<ver>.zip` to a **permanent** folder, for example
   `%USERPROFILE%\PrivateProxy-extension`. The browser loads it from there every time. Do not
   use `%LOCALAPPDATA%\PrivateProxy`, the data folder that a purge removes.
2. Open `chrome://extensions` (Brave: `brave://extensions`, Edge: `edge://extensions`).
3. Enable **Developer mode** → **Load unpacked** → select the extracted folder.
4. The card must show ID **`pmagpgfembejahekgbdifepphmaigngl`**. The runtime only accepts this
   ID, and it is fixed by the `key` in the manifest.
5. Pin the extension (puzzle icon → pin) and open it. It should show **Disconnected**, not
   "Native runtime missing".

The browser needs no restart after installing the runtime. If the popup says "Native runtime
missing", click **Retry**.

## macOS (Chrome, Brave, Chromium, Edge, Vivaldi)

### Install the runtime (per user, recommended)
1. Extract the tarball: `tar -xzf PrivateProxy-runtime-macos-arm64-<ver>.tar.gz`
   (use `-x64-` on Intel Macs).
2. Start each browser you want to use at least once, so its profile folder exists.
3. `cd PrivateProxy-runtime-macos-*/ && ./install.sh`. It:
   * removes the quarantine attribute from the extracted files,
   * copies the runtime to `~/Library/Application Support/PrivateProxy/runtime/`,
   * writes `com.privateproxy.host.json` into each existing browser's
     `~/Library/Application Support/<Google/Chrome | Chromium | BraveSoftware/Brave-Browser | Microsoft Edge | Vivaldi>/NativeMessagingHosts/`.
   * Run `./install.sh --all-browsers` to also register browsers that have not been started yet.
4. No sudo, no Dock icon, no menu bar item, no login item, no system settings.

### Alternative: `.pkg` (system-wide, root-owned binaries)
`node scripts/package.mjs --pkg` on a Mac produces a `.pkg`. It installs to
`/Library/Application Support/PrivateProxy/runtime/` and registers the logged-in user. Other
users of the Mac run:
`"/Library/Application Support/PrivateProxy/runtime/private-proxy-host" install --register-only --target "/Library/Application Support/PrivateProxy/runtime"`.

### Load the extension
Same as on Windows: open `chrome://extensions` → Developer mode → Load unpacked. Keep the folder
in a permanent place, e.g. `~/PrivateProxy-extension` (not inside the data folder
`~/Library/Application Support/PrivateProxy`, which a purge removes).

### Gatekeeper, signing and notarization
* V1 development builds are **not signed or notarized**. `install.sh` removes the
  `com.apple.quarantine` attribute. Without that, Gatekeeper would block the helper when the
  browser starts it, and the popup would show "Native runtime stopped".
* On Apple silicon every binary must carry at least an ad-hoc signature. The Rust linker and
  the official Xray release both provide one.
* For wider distribution: sign both binaries with a *Developer ID Application* certificate and the
  hardened runtime (`codesign --options runtime --timestamp`), sign the `.pkg` with *Developer ID
  Installer* (`PKG_SIGN_IDENTITY=… installers/macos/build-pkg.sh`), then notarize with
  `xcrun notarytool submit … --wait` and `xcrun stapler staple`.
* The first time the helper stores its data key, macOS may ask to allow access to the
  "com.privateproxy.host" Keychain item. After an update of an unsigned helper it may ask once more.

## Native messaging registration reference

| Browser | Windows (HKCU) | macOS (per user) |
|---|---|---|
| Chrome | `Software\Google\Chrome\NativeMessagingHosts\com.privateproxy.host` | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Chromium | `Software\Chromium\NativeMessagingHosts\…` | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Brave | `Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\…` (+ the Chrome key) | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Edge | `Software\Microsoft\Edge\NativeMessagingHosts\…` | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` |
| Vivaldi | not registered separately (reportedly reads the Chrome key; unverified) | `~/Library/Application Support/Vivaldi/NativeMessagingHosts/` |

`private-proxy-host status` prints which browsers are registered.

## Updating (manual)

Versions: extension, runtime and protocol version are shown in **Settings → About**. The runtime
reports `nativeVersion`, `xrayVersion` and `protocolVersion`. If extension and runtime speak
different protocol versions, the popup shows **Update required** and says which side to update.

| Component | How |
|---|---|
| Extension | Replace the files in the extension folder with the new zip's contents, then click the reload ↻ icon on `chrome://extensions` (or restart the browser). The ID stays the same. |
| Runtime (helper + Xray) | Run the new package's `Install.cmd` / `install.sh`. Servers and settings are kept. On Windows the installer can replace files while the browser is running (old files are moved aside), but restart the browser afterwards so the new helper is used. |
| Xray only | Xray is always shipped inside the runtime package. Maintainers bump `native/xray/xray.lock.json` (version + SHA-256), run the test suites, and publish a new runtime package. |

Recommended order: runtime first, then extension. Within a protocol version, any combination works.

## Security notes for company deployment

* Distribute the extension as a **policy force-installed CRX** and disable Developer mode by policy
  (`ExtensionDeveloperModeSettings`, `ExtensionInstallBlocklist: ["*"]` + `ExtensionInstallAllowlist`). Unpacked
  extensions can claim any ID whose public key they copy (security-gate B9).
* Sign the helper and Xray (Authenticode / Developer ID + notarization) before broad rollout (B34).
* On multi-user machines (terminal servers), disable the IDE endpoint: loopback listeners are unauthenticated (B12).
* The runtime verifies the Xray binary against the pinned SHA-256 before every launch. Never replace
  `xray.exe`/`xray` by hand.
* No step needs administrator rights except the optional macOS `.pkg` (only during installation).

## Uninstalling

* **Windows:** Settings → Apps → "Private Proxy (browser runtime)" → Uninstall, or `Uninstall.cmd`.
* **macOS:** `./uninstall.sh`, or `./uninstall.sh --purge`. For the `.pkg`, also run
  `sudo rm -rf "/Library/Application Support/PrivateProxy/runtime"`.

Uninstall removes the native messaging registration, the helper, the bundled Xray, and the Windows Apps entry.
Imported servers and credentials are **kept** unless you confirm (Windows prompt) or pass `--purge`.
Purge deletes `%LOCALAPPDATA%\PrivateProxy` / `~/Library/Application Support/PrivateProxy` and the logs,
plus the Credential Manager / Keychain item. Remove the extension on `chrome://extensions`. Removing
it also removes its proxy setting.

## Why not the Chrome Web Store / force-install now?

Out of scope for V1. The unpacked workflow above works in all target browsers. Managed
fleets can later force-install a self-hosted CRX with the `ExtensionInstallForcelist` policy. The
pinned key keeps the same extension ID, so the runtime works unchanged.
