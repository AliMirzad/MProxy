# MProxy

MProxy is a Chromium extension paired with a Windows native runtime. It provides
private VLESS/VMess (Xray) proxy support for the browser and a local endpoint for
JetBrains IDEs.

## Repository layout

- `extension/` — Chromium Manifest V3 extension.
- `runtime/` — Windows native-messaging runtime, installer, and Xray files.

## Install from a release

1. Download and extract `MProxy-runtime-windows-<version>.zip`.
2. Run `Install.cmd`, then restart the browser completely.
3. Download and extract `MProxy-extension-<version>.zip`.
4. Open `chrome://extensions`, enable **Developer mode**, select **Load unpacked**,
   and choose the extracted extension folder.

## Development

Keep the extension version in `extension/manifest.json` synchronized with the
runtime version in `runtime/VERSION.txt`. Do not commit real proxy profiles,
credentials, private keys, or private server addresses.

## Release process

See [RELEASING.md](RELEASING.md).
