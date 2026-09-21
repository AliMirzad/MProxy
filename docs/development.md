# Development

## Requirements

| Tool | Version used | Notes |
|---|---|---|
| Node.js | ≥ 20 (tested with 24) | build scripts, extension tooling |
| Rust | stable (tested with 1.97) | native helper |
| Windows linker | **either** Visual Studio Build Tools (C++ workload) **or** [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) + `rustup toolchain install stable-x86_64-pc-windows-gnullvm` | `scripts/cargo.mjs` picks MSVC when present, otherwise gnullvm (set `LLVM_MINGW=<dir>`). Both produce self-contained binaries (static CRT/libunwind, see `native/.cargo/config.toml`) |
| macOS | Xcode command line tools | for linking and `pkgbuild` |
| A Chromium browser | Brave / Chromium for automated E2E | branded Google Chrome ≥ 137 ignores `--load-extension`, so use it for manual tests only |

No C compiler is needed beyond the linker. TLS uses the OS (SChannel / Security.framework).

## Commands (from the repository root)

| Command | What it does |
|---|---|
| `npm run setup` | install extension dependencies, download + SHA-256-verify the pinned Xray for this OS |
| `npm run build` | debug build of helper + extension (`extension/dist`) |
| `npm run build:release` | release builds |
| `npm run dev` | rebuild the extension on change (then click ↻ on `chrome://extensions`) |
| `npm run runtime:install` | install **your local build** of the helper as the per-user runtime (same code path as the real installer) |
| `npm run runtime:uninstall` | remove it (`-- --purge` to also delete data) |
| `npm test` | native unit + integration tests, extension typecheck + unit tests |
| `npm run test:e2e` | real-browser E2E (see below) |
| `npm run lint` | clippy with warnings as errors |
| `npm run licenses` | regenerate `LICENSES/THIRD-PARTY.md` |
| `npm run package` | tests + release packages into `dist/` |

## Typical loop

```bash
npm run setup
npm run build
npm run runtime:install
```
Then load `extension/dist` unpacked in the browser (Developer mode). The dev and release builds share the
pinned extension ID, so the registered runtime accepts both. After a helper change: `npm run build`,
`npm run runtime:install`, then reload the extension (this restarts the helper).

## Tests

| Layer | Where | Runs |
|---|---|---|
| Parser, validation, config generation, store, secrets, framing, protocol, redaction, hostile-input suite (`parse/security_tests.rs`), destination policy, ACLs, Xray under restrictions | `native/src/**` `#[cfg(test)]` | `cargo test` (70 tests) |
| Helper ↔ real Xray ↔ local Xray "server" (9 protocol/transport/security combos, DNS, IDE endpoints, crash restart, failures, subscriptions) + security (isolation, listeners, hostile messages, unauthorized origins, tampered Xray, junctions, SSRF, malicious subscriptions, DLL planting) | `native/tests/integration.rs` | `cargo test` (13 tests; needs `native/xray/dist/<platform>`) |
| Extension controller (proxy mirroring, fail-safe, takeover, allow-list, timeouts), view model, QR round-trip, manifest/CSP/bundle security scan | `extension/tests/*.test.ts` | `vitest` (47 tests) |
| **Real browser**: installer → extension → native messaging → Xray → server; import, connect, 3 servers, DNS, IDE endpoint, crash, disconnect, no orphans, no stale proxy after restart | `extension/tests/e2e/browser.e2e.mjs` | `npm run test:e2e [-- --browser <path>] [--headed] [--screenshots <dir>]` |

The E2E test installs the runtime into a temp dir and registers native messaging for the current user
(HKCU / `~/Library/...`). The registration is removed again at the end (`uninstall --purge`). It uses a
throwaway browser profile and never touches your own.

Environment hooks, **for tests and development only**. They work only in **debug builds** and only when
`PRIVATE_PROXY_TEST_MODE=1` is also set (`ppcore::test_hook`). Release builds ignore all of them. The E2E test
therefore uses the debug helper.

| Variable | Effect |
|---|---|
| `PRIVATE_PROXY_TEST_MODE=1` | enables the hooks below (debug builds only) |
| `PRIVATE_PROXY_ALLOW_LOOPBACK=1` | allow 127.0.0.1 proxy servers and plain-HTTP loopback subscriptions (test servers) |
| `PRIVATE_PROXY_DATA_DIR` | use another data/log directory |
| `PRIVATE_PROXY_INSECURE_FILE_KEY=1` | keep the data key in a file instead of Credential Manager/Keychain (CI) |
| `PRIVATE_PROXY_XRAY` | path to the Xray binary (must still match the pinned SHA-256) |
| `PRIVATE_PROXY_PROBE_URL=host:port/path` | connectivity-probe target |

## Diagnostics while debugging

* **Helper log:** `%LOCALAPPDATA%\PrivateProxy\logs\helper.log` (Windows),
  `~/Library/Logs/PrivateProxy/helper.log` (macOS). Rotated at 512 KiB (`.log.1` … `.log.3`), and redacted.
* **Verbose mode:** popup → Settings → "Verbose diagnostics log". This adds Xray's info-level output to the
  log (it can contain destination hostnames) and to "Copy diagnostics". Turn it off afterwards.
* **Service worker console:** `chrome://extensions` → Private Proxy → "service worker" link.
* **Popup:** right-click the popup → Inspect, or open `chrome-extension://pmagpgfembejahekgbdifepphmaigngl/popup.html` in a tab.
* **Registration:** `private-proxy-host status` and `private-proxy-host --version`.
* **Native messaging launch errors:** start the browser with `--enable-logging=stderr --v=1` and
  look for `native_messaging` lines.
* **Talk to the helper by hand:** it speaks length-prefixed JSON on stdin/stdout. See
  `Host` in `native/tests/integration.rs` for a minimal client.

## Changing things safely

* **Protocol:** edit `native/src/protocol.rs` + `shared/protocol/types.ts` + `PROTOCOL.md`. Bump
  `PROTOCOL_VERSION` in both `native/src/lib.rs` and `shared/protocol/types.ts` for incompatible changes.
* **New transport:** add a `Transport` variant (`model.rs`), parse it in `parse/stream.rs` (and `json.rs`),
  generate it in `xrayconf.rs`, add an inbound to the integration test server, and run the tests.
* **Xray upgrade:** update `native/xray/xray.lock.json` (version + SHA-256 from the release `.dgst` files),
  run `node scripts/fetch-xray.mjs all`, run the full test suite, and check the release notes for removed
  config fields (see TD-4 in technical-decisions.md for how field support was verified with `xray run -test`).
* **Extension key:** `scripts/generate-extension-key.mjs --force` rotates the ID. Every installed runtime
  must then be reinstalled.

## Build notes

* **Target directory.** If the repository path is long (Windows `MAX_PATH`), `scripts/cargo.mjs` builds into
  `~/.private-proxy-target` (see `scripts/target-dir.mjs`; override with `CARGO_TARGET_DIR`).
* **Xray upgrade checklist:**
  1. Update `version` and the zip `sha256` values (from the release `.dgst` files) in `native/xray/xray.lock.json`.
  2. Delete the `binarySha256` entries, then run `node scripts/fetch-xray.mjs --record all`.
  3. Review `native/src/parse/fields.rs` against `infra/conf/*.go` at the new tag.
  4. Run all test suites.
* **Security gate:** re-run the suites listed in [security-gate.md](security-gate.md) and update it for every release.
