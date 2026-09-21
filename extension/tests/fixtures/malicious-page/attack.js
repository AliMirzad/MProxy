// PP-ADVERSARIAL-FIXTURE — hostile web page used only by the E2E security tests. Never ship.
// window.attack(cfg) runs every attempt and returns what the page could learn or do.
// cfg: { extId, ports: number[], authUrl }
window.attack = async (cfg) => {
  const out = {};
  const timeout = (ms) => new Promise((r) => setTimeout(() => r('timeout'), ms));

  // 1. Extension APIs from a web page.
  out.chromeRuntime = typeof window.chrome?.runtime?.sendMessage;
  try {
    await window.chrome.runtime.sendMessage(cfg.extId, { type: 'request', cmd: 'disconnect', args: {} });
    out.sendMessage = 'sent';
  } catch (e) {
    out.sendMessage = 'error: ' + e.message;
  }
  try {
    window.chrome.runtime.connect(cfg.extId);
    out.connect = 'connected';
  } catch (e) {
    out.connect = 'error: ' + e.message;
  }
  out.connectNative = typeof window.chrome?.runtime?.connectNative;
  window.postMessage({ type: 'request', cmd: 'disconnect', args: {} }, '*');

  // 2. Extension resources (fetch, script, iframe).
  try {
    await fetch(`chrome-extension://${cfg.extId}/manifest.json`);
    out.resourceFetch = 'readable';
  } catch {
    out.resourceFetch = 'blocked';
  }
  out.resourceScript = await Promise.race([
    new Promise((r) => {
      const s = document.createElement('script');
      s.src = `chrome-extension://${cfg.extId}/background.js`;
      s.onload = () => r('loaded');
      s.onerror = () => r('blocked');
      document.head.appendChild(s);
    }),
    timeout(3000),
  ]);
  out.resourceIframe = await Promise.race([
    new Promise((r) => {
      const f = document.createElement('iframe');
      f.src = `chrome-extension://${cfg.extId}/popup.html`;
      f.onload = () => {
        try {
          r(f.contentDocument && f.contentDocument.getElementById('primary') ? 'LOADED AND READABLE' : 'loaded:opaque-or-error-page');
        } catch {
          r('loaded:opaque-or-error-page');
        }
      };
      document.body.appendChild(f);
    }),
    timeout(3000),
  ]);

  // 3. Localhost ports: can the page detect them, read from them, or use them?
  out.ports = {};
  for (const p of cfg.ports) {
    const r = {};
    try {
      const res = await Promise.race([fetch(`http://127.0.0.1:${p}/`, { cache: 'no-store' }), timeout(3000)]);
      r.cors = res === 'timeout' ? 'timeout' : `READABLE ${res.status} ${(await res.text()).slice(0, 40)}`;
    } catch (e) {
      r.cors = 'error: ' + e.message;
    }
    const t0 = performance.now();
    try {
      const res = await Promise.race([fetch(`http://127.0.0.1:${p}/`, { mode: 'no-cors', cache: 'no-store' }), timeout(3000)]);
      r.noCors = res === 'timeout' ? 'timeout' : `opaque (${res.type})`;
    } catch (e) {
      r.noCors = 'error: ' + e.message;
    }
    r.ms = Math.round(performance.now() - t0);
    r.ws = await Promise.race([
      new Promise((res) => {
        try {
          const ws = new WebSocket(`ws://127.0.0.1:${p}/`);
          ws.onopen = () => {
            ws.close();
            res('OPEN');
          };
          ws.onerror = () => res('error');
        } catch (e) {
          res('threw: ' + e.message);
        }
      }),
      timeout(3000),
    ]);
    out.ports[p] = r;
  }
  // Closed-port baseline for the timing comparison.
  {
    const t0 = performance.now();
    try {
      await Promise.race([fetch('http://127.0.0.1:9/', { mode: 'no-cors' }), timeout(3000)]);
      out.closedPort = 'resolved';
    } catch {
      out.closedPort = 'error';
    }
    out.closedPortMs = Math.round(performance.now() - t0);
  }

  // 4. WebRTC address discovery (host candidates need no STUN server).
  try {
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('x');
    const cands = [];
    pc.onicecandidate = (e) => {
      if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate);
    };
    await pc.setLocalDescription(await pc.createOffer());
    await timeout(2500);
    pc.close();
    out.webrtcCandidates = cands;
  } catch (e) {
    out.webrtcCandidates = ['error: ' + e.message];
  }

  // 5. Credential phishing: a site that asks for HTTP authentication (401) must never receive the
  //    tunnel credentials (the extension answers only proxy challenges from its own inbound).
  try {
    const r = await Promise.race([fetch(cfg.authUrl, { cache: 'no-store' }), timeout(4000)]);
    out.auth401 = r === 'timeout' ? 'timeout' : String(r.status);
  } catch (e) {
    out.auth401 = 'error: ' + e.message;
  }

  // 6. Custom-scheme "imports" (the extension registers no protocol handlers). Last: may navigate.
  try {
    const w = window.open('web+vless://x');
    out.webVlessNav = w ? 'opened' : 'null';
  } catch (e) {
    out.webVlessNav = 'error: ' + e.message;
  }
  try {
    location.assign('vless://00000000-0000-4000-8000-000000000000@203.0.113.1:443?encryption=none#page-injected');
    out.vlessNav = 'attempted';
  } catch (e) {
    out.vlessNav = 'error: ' + e.message;
  }
  return out;
};
