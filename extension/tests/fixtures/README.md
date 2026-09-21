# Adversarial test fixtures — NEVER SHIP

Everything in this folder is hostile on purpose. It exists only for the security tests in
`extension/tests/e2e/` and is never built into `extension/dist` or any release artifact:
`scripts/package.mjs` refuses to package when the marker `PP-ADVERSARIAL-FIXTURE` appears in
anything it is about to ship (see `docs/adversarial-testing.md`).

- `malicious-extension/`: a second extension that tries native messaging to our host, external
  messaging and popup spoofing, proxy takeover (also racing a connect), localhost scanning with host
  permissions, credential discovery (webRequest header sniffing, a trap proxy that challenges for
  credentials), riding the tunnel, and turning WebRTC protection off.
- `malicious-page/`: a web page on a public origin that tries extension APIs and resources,
  localhost port detection and use, WebSocket, WebRTC address discovery, custom-scheme imports, and
  credential phishing through HTTP authentication.
- `impersonator/`: used by `e2e/experiments/impersonation-experiment.mjs`: an unpacked extension
  that copies our manifest `key` (so it gets our extension ID) with its own code.
