# Release integrity

How a release is produced, what it contains, and how anyone can check it.

## Components

| Component | Version | Source | Integrity |
|---|---|---|---|
| Native helper `private-proxy-host(.exe)` | = `native/Cargo.toml` | this repository, `cargo build --release --locked` | SHA-256 in `RELEASE-MANIFEST.json`; Authenticode / Developer ID signature when a certificate is configured |
| Xray-core | `native/xray/xray.lock.json` (v26.3.27) | official GitHub release asset only | zip SHA-256 (= upstream `.dgst`) and **binary** SHA-256 pinned in the lock file; re-verified at build (`fetch-xray.mjs`), compiled into the helper (`build.rs`), and re-verified by the helper **before every launch** |
| Extension | = `extension/package.json` | this repository, `extension/scripts/build.mjs --release` (esbuild) | `SHA256SUMS.txt`; ID pinned by the manifest `key` |
| Rust crates | `native/Cargo.lock` (171) | crates.io | lockfile hashes, `--locked` |
| npm packages | `extension/package-lock.json` | npm registry | lockfile integrity hashes, `npm ci`; runtime: jsQR only |
| Installer scripts | repository | `installers/` | in `RELEASE-MANIFEST.json` |

## No uncontrolled executable fetches

Verified 2026-09-22 by searching every script and the product code:

* The **product** never downloads code. It has no auto-update. The only runtime HTTP clients are
  the subscription fetch (data, parsed with allowlists) and the health check.
* **Build** scripts: `scripts/fetch-xray.mjs` is the only download of an executable. It is
  hash-pinned twice (zip and extracted binary), and a mismatch deletes the output and fails.
  `--record` (adding a hash for a new platform) is a maintainer action and never runs implicitly.
* No `curl | sh`, no `npx <remote>`, and no install scripts that fetch binaries (npm lifecycle scripts are not auto-approved).
* Test-only binaries (`native/examples/sandbox_probe.rs`) and hostile fixtures
  (`extension/tests/fixtures/`, marker `PP-ADVERSARIAL-FIXTURE`) are **refused by `package.mjs`**
  if they appear in anything being shipped (`assertNoTestArtifacts`).

## Audits (2026-09-22)

| Tool | Result |
|---|---|
| `cargo audit` (advisory DB: 1,261 advisories; 171 crates) | 0 vulnerabilities (exit 0) |
| `npm audit` (extension, incl. dev) | 0 vulnerabilities |
| `npm ls --omit=dev` | `jsqr@1.4.0` only |

## Release manifest

`node scripts/package.mjs` writes `RELEASE-MANIFEST.json` into the runtime bundle, plus
`dist/<bundle>.manifest.json` and `dist/SHA256SUMS.txt` (the archives). Example from this review's build:

| Component | File | Version | Source | SHA-256 |
|---|---|---|---|---|
| native helper | `private-proxy-host.exe` | 1.0.0 | repo @ f8d5402 (+ uncommitted changes), `cargo build --release --locked` | `e591b81e39fcd6d09018a1ef856e1bffdd63a0560400ca3360f6d304864e3d7f` |
| Xray-core | `xray/xray.exe` | v26.3.27 | github.com/XTLS/Xray-core release v26.3.27 | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` |
| installer | `Install.cmd` | 1.0.0 | repo | `46f045bafdf26bf133ed93127c1c7286894e68c52acb88f592242fcb53bc5542` |
| installer | `Uninstall.cmd` | 1.0.0 | repo | `be95a227d4b8954914618bc7911bfaca835a2239848667191c1575ce2e938101` |
| archive | `PrivateProxy-runtime-windows-x64-1.0.0.zip` | 1.0.0 | `SHA256SUMS.txt` | `d6d7bd5b26a4ec30bb1b12f0b41a21947a25eaeba3227a8be67feac7aaad7bf0` |
| archive | `PrivateProxy-extension-1.0.0.zip` | 1.0.0 | `SHA256SUMS.txt` | `eab7c89e063e51e13ebcc72e3efbf5e3a182385faacd5a67cc0126d9cd013037` |

The manifest records `gitRevision` and `gitDirty`. **Release builds must be made from a clean
commit (`gitDirty: false`).** The build above was a review build (`gitDirty: true`) and must not be
distributed.

## Verifying a release

```powershell
Get-FileHash .\PrivateProxy-runtime-windows-x64-<ver>.zip -Algorithm SHA256   # compare with SHA256SUMS.txt
Get-AuthenticodeSignature .\private-proxy-host.exe                           # Valid, company/publisher certificate
Get-FileHash .\xray\xray.exe -Algorithm SHA256                                # = xray.lock.json binarySha256
.\private-proxy-host.exe --version                                           # prints the Xray hash it verified
```

`node scripts/test-package-adversarial.mjs` additionally checks the release PE:

* `DependentLoadFlags = 0x800`;
* the `SetDefaultDllDirectories` import;
* ASLR/high-entropy ASLR/DEP;
* the manifest hash matches the helper inside the zip.

## Open items

| Item | Status |
|---|---|
| Code signing | **FAIL: MEDIUM**, no certificate. Unsigned helper quarantined by endpoint security on the review machine |
| Reproducible build (two independent builds, identical hashes) | **NOT TESTED** |
| CI build of the release | **NOT TESTED** (workflow present, not run) |
| SBOM in a standard format (CycloneDX/SPDX) | not produced. `LICENSES/THIRD-PARTY.md` + lockfiles are the inventory |
