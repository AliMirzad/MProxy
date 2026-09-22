# Adversarial testing

Review of 2026-09-21/22. The previous report's claim "no HIGH or CRITICAL issues remain" was
treated as untrusted, and the protections were re-tested by attacking them. Each section lists
what was attempted, the result, and how to reproduce it. Statuses follow
[security-gate.md](security-gate.md).

## Findings

| # | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| F1 | Xray isolation silently degraded: if the mitigation attribute failed, the retry also dropped the child-process policy, and the UI still showed a normal connection | MEDIUM | fixed: only the best-effort attribute is dropped; mandatory controls are verified | 835f8b6 |
| F2 | Nothing verified the isolation of the running Xray process; a failed API call could leave it unprotected | MEDIUM | fixed: token integrity, deny-only SID, privileges, job and limits are read from the **suspended** process; any mismatch → "Runtime security check failed", Xray never runs | 835f8b6 |
| F3 | Low integrity alone still let a compromised Xray **read the user's documents** (no-read-up applies only to labelled objects); the previous gate tested only secrets and writes | **HIGH** | fixed: restricted token with the user SID deny-only; runtime-verified Documents/secrets/temp unreadable | 835f8b6 |
| F4 | macOS: if the Seatbelt self-test failed, Xray ran unsandboxed | MEDIUM | fixed: fail closed | 835f8b6 |
| F5 | Browser tunnel port (SOCKS, no auth) usable by every local process **and other users** while connected | MEDIUM | fixed: authenticated HTTP proxy with per-connection credentials answered in `onAuthRequired` | a6b2100 |
| F6 | Another extension could silently override WebRTC protection while the UI said "Connected" | MEDIUM | fixed: WebRTC control monitored; fail closed | c6bbe93 |
| F7 | Extension impersonation in developer mode: copied `key` → our ID → native host fully usable (IDE password, disable IDE auth, import servers) | **HIGH** (unmanaged) | **open**: deployment control only ([managed-deployment.md](managed-deployment.md)) | — |
| F8 | Subscription refresh while connected broken since F5's fix (unauthenticated SOCKS against the HTTP inbound) | LOW (availability; fails closed, no leak) | fixed + regression test | 394815c |
| F9 | Shipped `Install.cmd` had lost its backslashes: the PowerShell path was invalid, and Mark-of-the-Web removal never ran | LOW | fixed | 394815c |
| F10 | `Install.cmd` design interpolated the folder path into PowerShell code: folder `x';New-Item pwned;#` executed code (reproduced with the intended path; the shipped copy was accidentally non-exploitable because of F9) | LOW (attacker must name the extraction folder) | fixed: path passed via environment variable | 394815c |
| F11 | Server names kept bidi overrides / zero-width characters (`\u202Egnp.exe` displayed as `exe.png`) | LOW | fixed: stripped in `clean_name` | f8d5402 |
| F12 | Unsigned release helper is removed by the company EDR (Kaspersky) after extraction | deployment blocker | open: sign + allowlist | — |
| F13 | E2E test deleted the user's real Credential Manager key; test data now uses its own entry (found earlier in this phase) | MEDIUM (test hygiene / data loss) | fixed | a284479 |

## 1. Windows Xray isolation

Method: `native/examples/sandbox_probe.rs` (a test fixture, never packaged) is launched through the
**real** launch path (`winproc.rs`) instead of Xray, once restricted and once as a control, and
reports what it can do. Test: integration `xray_sandbox_probe`.

| Check | Restricted (Xray) | Control |
|---|---|---|
| Integrity level | Low (0x1000) | Medium |
| User SID | deny-only | enabled |
| Privileges | ≤ 1 (`SeChangeNotifyPrivilege`) | several |
| Open own token (`OpenProcessToken`) | **denied** | allowed |
| Job | yes: active processes 1, kill-on-close, die on unhandled exception, 2 GiB, UI restrictions 0xff, no breakaway | — |
| Mitigations | child process blocked, extension points off, image load 7, fonts off | — |
| Inherited handle usable | no | — |
| `CreateProcess` | **fails, error 367** | succeeds |
| Environment | `SystemRoot` only | (same list: unconditional) |
| Read a document in the profile / `secrets.bin` / user temp | **denied** | allowed |
| Read `C:\Windows\System32\drivers\etc\hosts` | allowed (needed, harmless) | allowed |
| Write profile, temp, LocalLow, install dir, data dir | **denied** | allowed |
| Write `HKCU\Software`, AppDataLow key | **denied** | allowed |

Fail-closed tests:
* `mandatory_protection_failure_blocks_connection`: a debug-only hook breaks the isolation. Result:
  "Runtime security check failed", Xray is not started, and the browser stays direct.
* `weakened_data_folder_blocks_connection`: `icacls` grants Everyone read. Result: connection refused.

All 9 transports work under the restricted token (`all_transports_end_to_end`).

## 2. Browser tunnel port (item 4)

| Aspect | Result |
|---|---|
| Entropy | username `b` + 10 chars, password 24 chars from a 57-symbol alphabet (`OsRng`): ~140 bits in the password |
| Lifetime | new credentials for every connect; kept across automatic Xray restarts; memory only (helper + service worker) |
| Discovery | the **port** is not secret: any local process sees listening sockets, and any extension can read `chrome.proxy.settings`. The credentials are never in a command line (Xray config on stdin), never in files, never in the popup's state, and not visible to other extensions (`webRequest` with `extraHeaders`: no `Proxy-Authorization`) |
| Process inspection | same-user processes can read helper/browser memory (out of scope). Other users cannot open another user's processes |
| Scanning / other users | runtime: 407 without credentials, 407 with guessed ones; the IDE password is refused there and the browser credentials are refused on the IDE port |
| Loopback only | yes (socket enumeration) |
| Why HTTP + Basic | Chromium cannot send SOCKS credentials, Unix sockets are not supported for proxies, and TLS to a loopback proxy adds nothing against local attackers. Per-connection credentials answered only to `127.0.0.1:<our port>` while our proxy setting is in effect are the strongest Chromium-compatible option (experiment `e2e/experiments/proxy-auth-experiment.mjs`: `onAuthRequired` needs `webRequest`, `webRequestAuthProvider` and host permissions) |
| Residual | the extension now holds `<all_urls>` host permission (needed for `onAuthRequired`); the CSP still forbids it to contact any origin. A malicious extension can jam the 407 answer (DoS) and can use the tunnel for its own requests like any browser request |

## 3. macOS `sandbox-exec` evaluation (item 3)

**ENVIRONMENT UNAVAILABLE:** no Mac was available, so nothing here is validated on hardware.

* **Supported versions.** `sandbox-exec(1)` has been marked deprecated in its man page for years.
  It still ships and works on macOS 14, 15 and 26: Apple's own services and browsers use Seatbelt
  profiles. No removal date is announced. The SBPL profile language is undocumented and could change.
* **Boundary.** The profile (`macsandbox.rs`) does the following:
  * denies `process-fork`;
  * allows `process-exec` only for the Xray binary;
  * denies all `file-write*`;
  * denies reads under the home folder, except Xray's directory;
  * allows network (required).

  It is enforced by the kernel (Sandbox.kext) for Xray and its descendants.
* **Limitations.**
  * Network access is unrestricted, as it must be.
  * Reads outside the home folder are allowed (system files, other volumes, `/tmp`).
  * The profile is untested against real Xray behaviour, so a denied operation Xray needs would
    fail the connection (closed, not open).
  * The self-test runs once per session.
  * There are no job-object equivalents except `RLIMIT` settings.
* **Signing / hardened runtime.**
  * Seatbelt via `sandbox-exec` needs no entitlement and works with the unmodified, pinned Xray
    (hash unchanged).
  * The hardened runtime applies to the helper (signing with `--options runtime`). It restricts
    injection and DYLD variables, but it is not a sandbox.
* **Supported alternative.** App Sandbox requires the `com.apple.security.app-sandbox` entitlement
  **in Xray's code signature**. That means re-signing Xray, which changes its hash. The pinning
  would have to move to "our signature over the official binary", and Xray would need file
  exceptions. It is feasible but a release-engineering project: recommended for a macOS company
  release.
* **Decision.** Keep Seatbelt, fail closed (F4), and validate on a Mac before any macOS company
  use: run the E2E, check that Xray works for all transports, and try the sandbox probe equivalent
  (writes, home reads, exec).

## 4. IDE endpoint authentication (item 5)

Test: integration `ide_auth_adversarial`.

| Attack | Result |
|---|---|
| Randomness | 20 regenerations: all distinct, 24 chars, only the 57-symbol alphabet |
| Malformed `Proxy-Authorization` | 13 variants refused, including: `Basic`, empty, non-base64, no colon, empty user or password, one char short or long, `Bearer`, 64 KiB header, NUL suffix, wrong case of the password |
| Malformed SOCKS5 username/password auth | 5 malformed sub-negotiations refused |
| Brute force | 8 threads, 1,000 wrong guesses (HTTP + SOCKS) in 140 ms: **0 accepted**; same Xray PID afterwards; correct credentials still work |
| Logging / plaintext | IDE password and browser password absent from `helper.log` (debug logging on), `state.json` and raw `secrets.bin`; absent from `getSettings`, `getDiagnostics` and `listServers` |
| Regeneration | the old password stops working immediately (`ide_endpoint_requires_password`) |

**Who can retrieve the IDE credentials**
* The MProxy extension, through native messaging (`getIdeCredentials`; shown in Settings on "Show").
* Any extension that obtains MProxy's ID (F7; closed by managed deployment).
* Any process of the **same user**, by reading the data key from Credential Manager / Keychain and
  decrypting `secrets.bin`.
* **Not** other users (private DACL / 0700) and **not** Xray (restricted token cannot read the data
  directory).

Intermittent result: in 1 of 5 full parallel integration runs, `ide_endpoint_requires_password`
failed an equality assertion. It passes alone (3/3) and in 3/3 later full runs. The likely cause is
load from `ide_auth_adversarial`'s brute force running in parallel, which makes Xray's outbound dial
fail (503) beyond the test's bounded retry. This is recorded as a test-stability issue. It is not
evidence of an authentication failure: an accepted wrong credential would fail a different assertion.

## 5. Hostile web page (item 7)

The fixture `extension/tests/fixtures/malicious-page/` is served as `http://evil.example/` (public
origin) while connected.

| Attempt | Result |
|---|---|
| `chrome.runtime.sendMessage` / `connect` / `connectNative` | APIs absent |
| Extension resources via fetch / `<script>` / `<iframe>` | blocked / blocked / not readable |
| Read tunnel/IDE ports (CORS and `no-cors`), WebSocket | all fail |
| Port detection by timing | 2–14 ms like a closed port (9 ms): not distinguishable in this run (not proof for every browser) |
| WebRTC ICE candidates (no STUN) | **none** |
| HTTP-auth phishing (401 via the tunnel) | the site received no credentials |
| `vless://` / `web+vless://` navigation | nothing imported |
| Tunnel state afterwards | still Connected |

## 6. Hostile extension (item 8)

The fixture `extension/tests/fixtures/malicious-extension/` has `nativeMessaging`, `proxy`,
`privacy`, `webRequest`, `webRequestAuthProvider` and `<all_urls>`.

| Attempt | Result |
|---|---|
| `connectNative` + `sendNativeMessage` to our host | "Access to the specified native messaging host is forbidden" |
| `sendMessage` (disconnect, getState, getIdeCredentials) and a port named `popup` | "Receiving end does not exist" |
| Read our `manifest.json` | blocked |
| `chrome.proxy.settings.get` | reveals host/port/scheme only, no credentials |
| Localhost scan of tunnel + IDE ports (with host permissions) | fetch fails; no 2xx, no content |
| Header sniffing (`onSendHeaders` + `extraHeaders`) while browsing through the tunnel | headers observed, **no** `Proxy-Authorization` |
| Observe `onAuthRequired` | sees our challenger `127.0.0.1:<port>`: information only |
| Ride the tunnel with its own `fetch` | works (by design: all browser traffic is tunneled) |
| Takeover to a trap proxy that demands credentials | tunnel disconnected with a reason; the trap received **no** credentials |
| Takeover racing a connect click | never "Connected" without our proxy in effect |
| 25× set/clear flapping | state consistent; still no credentials at the trap |
| Override WebRTC protection | **succeeded before the fix (F6)**; now disconnects with a WebRTC reason |

## 7. Extension impersonation (item 6)

Experiment: `extension/tests/e2e/experiments/impersonation-experiment.mjs` (fixture
`extension/tests/fixtures/impersonator/`).

| Scenario | Loaded with MProxy's ID | Native host |
|---|---|---|
| A: impersonator alone | impersonator | **accepted**. `getIdeCredentials` returned the password; `setSettings` turned `ideAuth` off and `allowPrivateSubscriptionHosts` on; `importText` added a server at 203.0.113.66; `addSubscription` to `http://169.254.169.254/` refused (policy still applies) |
| B: real, then impersonator | impersonator (later load wins) | accepted (same results) |
| C: impersonator, then real | real MProxy | — |

Conclusion: HIGH for unmanaged installs, and not fixable in code. See [managed-deployment.md](managed-deployment.md).

## 8. Malicious subscription corpus (item 9)

Files: `native/tests/fixtures/subscriptions/`. Test: integration `malicious_subscription_corpus`.
Every file goes through a real `addSubscription` (loopback-allowed test helper) and then through
`importText` on a production-like helper (no loopback allowance).

| File | Result |
|---|---|
| `01-command-injection` (`$(…)`, backticks, `;`, `\|`, `%0A` in names, SNI, path, host) | 2 imported with names as inert text; 3 rejected |
| `02-path-traversal` (`../` names, WS path, gRPC service name, host) | 1 imported (name is text only); 3 rejected |
| `03-nested-base64` (base64 ×3) | refused as a whole ("not a supported … subscription") |
| `04-duplicates` (same server ×3, upper-case host) | 1 server |
| `05-unicode` (RLO, zero-width, BOM, Arabic + emoji + NUL, punycode, Cyrillic homoglyph host, 5,000-char name) | 6 imported. Control/bidi/zero-width stripped (F11); homoglyph host stored as punycode (`xn--pple-43d.com`); name truncated to 100 |
| `06-internal-targets` (metadata IP and name, loopback in 6 encodings, `0.0.0.0`, multicast) | production-like helper: only the one valid server imported |
| `07-unexpected-protocols` (trojan, ss, hysteria2, wireguard, socks, http, file, javascript, data) | 1 VMess imported; 7 unsupported, 2 rejected |
| `08-unknown-xray-fields` (mux, proxySettings, sendThrough, sockopt, unknown TLS field, dialerProxy, freedom redirect, blackhole, dns, loopback, inbounds, vnext to metadata) | 1 clean imported, 6 rejected, others ignored |
| `09-full-client-config` (debug log to a file, API, `0.0.0.0` dokodemo inbound) | only the outbound imported; log/API/inbounds never read |
| `10-deep-nesting` (100,000 nested arrays) | "recursion limit exceeded", no crash |
| `11-mixed-garbage` (CRLF, empty, bad port, bad encryption, control chars) | valid entries imported, rest rejected |
| Redirects to: metadata IP, metadata name, 10/8, 192.168/16, `http://` downgrade, `file:`, `ftp:`, `fe80::`, `0.0.0.0`, endless loop | all refused with a specific reason |

Every file completed in under 1 s. The helper stayed healthy throughout.

## 9. Malicious proxy server model (item 10)

A VLESS/VMess server is a man-in-the-middle for everything sent through it. What it can do, and what limits it:

| Capability | Limit |
|---|---|
| **Metadata:** client IP, VLESS/VMess user ID, connect times, every destination host:port, volumes, timing | none; inherent to a proxy |
| **HTTPS content** | unreadable and unmodifiable without a certificate error (the browser verifies). It sees SNI unless ECH is used |
| **Plain HTTP** | fully readable and **modifiable** (script injection into HTTP pages). The browser is the only defence (HTTPS-First mode is recommended) |
| **DNS** | resolves every proxied name; it can answer falsely (for HTTPS a false answer only leads to a certificate error; for HTTP, to spoofing) |
| **Timing / fingerprinting** | traffic analysis of browsing |
| **Health check and subscription refresh while connected** | sees them; could make the probe fail (the connection then shows an error) |
| **Local access** | none: no inbound path to the client. An Xray exploit lands in the restricted, Low-IL, job-confined process (§1) |
| **Steering** | cannot change the client's configuration; only the subscription provider can |

Recommendation:
* For company use, operate the servers and the subscription on **company infrastructure**, deliver
  them only through a company subscription, and disable manual imports ([corporate mode](managed-deployment.md#corporate-mode-design)).
* Treat any third-party server as able to see all browsing metadata and all plain-HTTP content.

## 10. Packaged runtime and installer (item 12)

Test: `node scripts/test-package-adversarial.mjs`, run on the built `dist/` zip. The test
extracts it into a folder named `Downloads & x';New-Item pwned-by-folder-name;#`.

| Attack | Result |
|---|---|
| Control: an unhardened program next to a planted `version.dll` | loads it: the harness detects loads |
| Release helper PE (read from the zip into memory) | `DependentLoadFlags=0x800`, imports `SetDefaultDllDirectories`, ASLR/high-entropy/DEP on, hash = manifest |
| Planted marker DLLs (62 names incl. schannel, sspicli, ncrypt, dnsapi, dpapi, userenv, version, winhttp) next to the helper and Xray, full session (Credential Manager, import, restricted Xray launch, real HTTPS subscription fetch) | **no planted DLL loaded**; Xray not killed |
| Same with the packaged **release** helper executing | **ENVIRONMENT UNAVAILABLE**: EDR removed the unsigned file (F12) |
| `Install.cmd` folder-name injection | previous line: **code executed** (file created); fixed script: not executed, install step reached |
| Path replacement / executable replacement | install dir private ACL (E2E `icacls`); Xray hash verified before every launch (`tampered_xray_is_never_executed`); helper replacement by the same user is out of scope |
| Junction/symlink | data dir junction refused (integration); install target link refused (`install.rs`, code review) |
| PATH hijack | helper and installers call `cmd`, `PING`, `powershell` by absolute System32 path; Xray is never searched on PATH (code review + earlier runtime test) |
| Temp races | no temp files for config (stdin); state files created with `create_new` (code review) |
| Uninstall command injection | delayed `rmdir` refuses targets containing `" % & \| ^ < > !` (code review) |

## 11. Reproducing

```bash
node scripts/cargo.mjs build --example sandbox_probe
node scripts/cargo.mjs test                 # unit + integration (incl. probe, IDE auth, corpus)
npm --prefix extension test
npm run test:e2e                            # hostile page + hostile extension (Brave/Chromium)
node extension/tests/e2e/experiments/impersonation-experiment.mjs
node scripts/package.mjs --skip-tests && node scripts/test-package-adversarial.mjs
```

The fixtures in `extension/tests/fixtures/` and `native/examples/sandbox_probe.rs` are hostile or
test-only by design. `package.mjs` refuses to ship them.
