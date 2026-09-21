// Popup UI. All data from the helper (server names, messages) is untrusted and is only
// ever written with textContent / value, never as HTML.
import type { CommandName, Commands, ImportResult, NativeResponse, ServerList, ServerSummary, Settings, SubscriptionResult } from '../../../shared/protocol/types';
import type { AppState, SwPush } from '../shared/app-state';
import { currentServerId, deriveView, protocolLine } from '../shared/view';
import { captureVisibleTab, decodeQrFromBlob, looksLikeProxyConfig } from './qr';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

let app: AppState | null = null;
let list: ServerList = { servers: [], subscriptions: [], selectedServerId: null };
let view: 'main' | 'import' | 'settings' = 'main';
let busyAction = false;

function request<K extends CommandName>(cmd: K, args: Commands[K]): Promise<NativeResponse> {
  return chrome.runtime.sendMessage({ type: 'request', cmd, args }) as Promise<NativeResponse>;
}

function toast(msg: string) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  setTimeout(() => (t.hidden = true), 3500);
}

function showResult(el: HTMLElement, text: string, isError: boolean) {
  el.textContent = text;
  el.classList.toggle('error', isError);
  el.hidden = false;
}

// ------------------------------------------------------------------ navigation

function setView(v: typeof view) {
  view = v;
  $('view-main').hidden = v !== 'main';
  $('view-import').hidden = v !== 'import';
  $('view-settings').hidden = v !== 'settings';
  $('nav-back').hidden = v === 'main';
  $('nav-settings').hidden = v !== 'main';
  $('title').textContent = v === 'main' ? 'Private Proxy' : v === 'import' ? 'Import' : 'Settings';
  $('import-result').hidden = true;
  $('settings-result').hidden = true;
  if (v === 'settings') void loadSettings();
}

// ------------------------------------------------------------------ rendering

async function refreshList() {
  if (app?.runtime.kind !== 'ready') return;
  const r = await request('listServers', {});
  if (r.ok) {
    list = r.result as ServerList;
    render();
  }
}

function render() {
  if (!app) return;
  const v = deriveView(app);
  const dot = $('status-dot');
  dot.className = `dot ${v.tone}`;
  $('status-label').textContent = v.label;
  const detail = $('status-detail');
  detail.textContent = v.detail ?? '';
  detail.hidden = !v.detail;
  const hint = $('status-hint');
  hint.textContent = v.hint ?? '';
  hint.hidden = !v.hint;

  const ready = app.runtime.kind === 'ready';
  $('server-block').hidden = !ready;
  $('servers-section').hidden = !ready;
  $('nav-settings').hidden = view !== 'main' || !ready;

  // Server selector
  const sel = $<HTMLSelectElement>('server-select');
  const current = currentServerId(app, list.selectedServerId);
  sel.replaceChildren(
    ...list.servers.map((s) => {
      const o = document.createElement('option');
      o.value = s.id;
      o.textContent = s.name;
      return o;
    }),
  );
  if (list.servers.length === 0) {
    const o = document.createElement('option');
    o.textContent = 'No servers';
    o.value = '';
    sel.append(o);
  }
  sel.value = current ?? '';
  const st = app.status?.state;
  sel.disabled = !ready || st === 'connecting' || st === 'disconnecting' || list.servers.length === 0;
  const server = list.servers.find((s) => s.id === current);
  $('protocol-line').textContent = server ? `${protocolLine(server)} · ${server.address}:${server.port}` : '';

  // Primary button
  const btn = $<HTMLButtonElement>('primary');
  btn.classList.toggle('disconnect', v.action === 'disconnect' || v.action === 'cancel');
  btn.hidden = v.action === 'none' && app.runtime.kind !== 'ready';
  switch (v.action) {
    case 'connect':
      btn.textContent = 'Connect';
      btn.disabled = busyAction || !current;
      break;
    case 'disconnect':
      btn.textContent = 'Disconnect';
      btn.disabled = busyAction;
      break;
    case 'cancel':
      btn.textContent = 'Cancel';
      btn.disabled = busyAction;
      break;
    case 'retry':
      btn.textContent = 'Retry';
      btn.disabled = false;
      break;
    default:
      btn.textContent = 'Please wait…';
      btn.disabled = true;
  }

  // IDE endpoint line
  const jb = app.status?.jetbrains;
  const ide = $('ide-line');
  if (ready && jb?.enabled) {
    const eps = [jb.httpPort ? `HTTP 127.0.0.1:${jb.httpPort}` : null, jb.socksPort ? `SOCKS 127.0.0.1:${jb.socksPort}` : null].filter(Boolean).join(' · ');
    const mode = jb.mode === 'tunnel' ? 'via tunnel' : jb.mode === 'direct' ? 'direct' : 'off';
    ide.textContent = jb.issue ? `IDE proxy: ${jb.issue}` : eps ? `IDE proxy (${mode}): ${eps}` : 'IDE proxy: off while disconnected';
    ide.hidden = false;
  } else {
    ide.hidden = true;
  }

  renderServerList(current);
}

function renderServerList(current: string | null) {
  const ul = $('server-list');
  const activeId = app?.status && (app.status.state === 'connected' || app.status.state === 'connecting') ? app.status.serverId : null;
  const subs = new Map(list.subscriptions.map((s) => [s.id, s.name]));
  ul.replaceChildren(...list.servers.map((s) => serverItem(s, s.id === current, s.id === activeId, subs.get(s.subscriptionId ?? '') ?? null)));
  $('empty-servers').hidden = list.servers.length > 0;
}

function serverItem(s: ServerSummary, selected: boolean, active: boolean, subName: string | null): HTMLLIElement {
  const li = document.createElement('li');
  li.tabIndex = 0;
  li.className = selected ? 'selected' : '';
  const grow = document.createElement('div');
  grow.className = 'grow';
  const name = document.createElement('div');
  name.className = 'name';
  name.textContent = s.name;
  const sub = document.createElement('div');
  sub.className = 'sub';
  sub.textContent = protocolLine(s);
  grow.append(name, sub);
  li.append(grow);
  if (active) {
    const m = document.createElement('span');
    m.className = 'active-mark';
    m.textContent = app?.status?.state === 'connected' ? '● active' : '…';
    li.append(m);
  }
  if (subName) {
    const b = document.createElement('span');
    b.className = 'badge';
    b.textContent = subName;
    b.title = 'From subscription';
    li.append(b);
  }
  const actions = document.createElement('div');
  actions.className = 'actions';
  const rename = document.createElement('button');
  rename.className = 'link';
  rename.textContent = 'Rename';
  rename.onclick = (e) => {
    e.stopPropagation();
    startRename(li, name, s);
  };
  const del = document.createElement('button');
  del.className = 'link';
  del.textContent = 'Delete';
  del.onclick = async (e) => {
    e.stopPropagation();
    if (del.dataset.armed !== '1') {
      del.dataset.armed = '1';
      del.textContent = 'Confirm?';
      setTimeout(() => {
        del.dataset.armed = '';
        del.textContent = 'Delete';
      }, 3000);
      return;
    }
    const r = await request('deleteServer', { id: s.id });
    if (!r.ok) toast(r.error.message);
    await refreshList();
  };
  actions.append(rename, del);
  li.append(actions);
  const choose = async () => {
    if (app?.status?.state === 'connecting' || app?.status?.state === 'disconnecting') return;
    const r = await request('selectServer', { id: s.id });
    if (r.ok) {
      list.selectedServerId = s.id;
      // Switching servers while connected reconnects to the new one.
      if (app?.status?.state === 'connected' && app.status.serverId !== s.id) await connect(s.id);
      render();
    }
  };
  li.onclick = choose;
  li.onkeydown = (e) => {
    if (e.key === 'Enter') void choose();
  };
  return li;
}

function startRename(li: HTMLLIElement, nameEl: HTMLElement, s: ServerSummary) {
  const input = document.createElement('input');
  input.type = 'text';
  input.value = s.name;
  input.maxLength = 100;
  input.className = 'rename-input';
  nameEl.replaceWith(input);
  input.focus();
  input.select();
  input.onclick = (e) => e.stopPropagation();
  const finish = async (save: boolean) => {
    input.onblur = null;
    if (save && input.value.trim() && input.value.trim() !== s.name) {
      const r = await request('renameServer', { id: s.id, name: input.value.trim() });
      if (!r.ok) toast(r.error.message);
    }
    await refreshList();
  };
  input.onkeydown = (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') void finish(true);
    if (e.key === 'Escape') void finish(false);
  };
  input.onblur = () => void finish(true);
  void li;
}

// ------------------------------------------------------------------ actions

async function connect(serverId: string) {
  busyAction = true;
  render();
  const r = await request('connect', { serverId });
  busyAction = false;
  if (!r.ok) toast(r.error.message);
  render();
}

async function onPrimary() {
  if (!app) return;
  const v = deriveView(app);
  if (v.action === 'retry') {
    await chrome.runtime.sendMessage({ type: 'retryNative' });
    return;
  }
  if (v.action === 'disconnect' || v.action === 'cancel') {
    busyAction = true;
    render();
    const r = await request('disconnect', {});
    busyAction = false;
    if (!r.ok) toast(r.error.message);
    render();
    return;
  }
  if (v.action === 'connect') {
    const id = $<HTMLSelectElement>('server-select').value;
    if (id) await connect(id);
  }
}

function summarizeImport(r: ImportResult): string {
  const lines = [`Imported: ${r.added} new, ${r.updated} updated.`];
  if (r.rejected) lines.push(`${r.rejected} entr${r.rejected === 1 ? 'y was' : 'ies were'} rejected:`, ...r.errors.slice(0, 5).map((e) => `  #${e.entry}: ${e.message}`));
  if (r.unsupported) lines.push(`${r.unsupported} unsupported entr${r.unsupported === 1 ? 'y' : 'ies'} skipped (only VLESS/VMess).`);
  if (r.warnings.length) lines.push('Notes:', ...r.warnings.map((w) => `  • ${w}`));
  return lines.join('\n');
}

async function importText(text: string, source: 'paste' | 'qr' | 'file') {
  const out = $('import-result');
  if (!text.trim()) {
    showResult(out, 'Nothing to import.', true);
    return;
  }
  showResult(out, 'Importing…', false);
  const r = await request('importText', { text, source });
  if (r.ok) {
    showResult(out, summarizeImport(r.result as ImportResult), false);
    $<HTMLTextAreaElement>('import-text').value = '';
    await refreshList();
  } else {
    showResult(out, r.error.message, true);
  }
}

async function importQrBlob(blob: Blob) {
  const out = $('import-result');
  try {
    showResult(out, 'Reading QR code…', false);
    const text = await decodeQrFromBlob(blob);
    if (!text) {
      showResult(out, 'No QR code found in the image.', true);
      return;
    }
    if (!looksLikeProxyConfig(text)) {
      showResult(out, 'This QR code does not contain a VLESS or VMess configuration.', true);
      return;
    }
    await importText(text, 'qr');
  } catch (e) {
    showResult(out, `Could not read the image: ${(e as Error).message}`, true);
  }
}

async function addSubscription() {
  const out = $('import-result');
  const url = $<HTMLInputElement>('sub-url').value.trim();
  const name = $<HTMLInputElement>('sub-name').value.trim();
  if (!url) {
    showResult(out, 'Enter the subscription URL.', true);
    return;
  }
  showResult(out, 'Fetching subscription…', false);
  const r = await request('addSubscription', { name, url });
  if (r.ok) {
    const s = r.result as SubscriptionResult;
    showResult(out, `Subscription added: ${s.added} server(s).${s.rejected ? ` ${s.rejected} rejected.` : ''}${s.unsupported ? ` ${s.unsupported} unsupported skipped.` : ''}`, false);
    $<HTMLInputElement>('sub-url').value = '';
    $<HTMLInputElement>('sub-name').value = '';
    await refreshList();
  } else {
    showResult(out, r.error.message, true);
  }
}

// ------------------------------------------------------------------ settings

async function loadSettings() {
  const r = await request('getSettings', {});
  if (r.ok) {
    const s = r.result as Settings;
    $<HTMLInputElement>('jb-enabled').checked = s.jetbrainsEnabled;
    $<HTMLInputElement>('jb-http').value = String(s.jetbrainsHttpPort);
    $<HTMLInputElement>('jb-socks').value = String(s.jetbrainsSocksPort);
    $<HTMLInputElement>('jb-passthrough').checked = s.passthroughWhenDisconnected;
    $<HTMLInputElement>('debug-log').checked = s.debugLogging;
  }
  const { webrtcProtection } = await chrome.storage.local.get('webrtcProtection');
  const granted = await chrome.permissions.contains({ permissions: ['privacy'] });
  $<HTMLInputElement>('webrtc').checked = webrtcProtection === true && granted;
  const jb = app?.status?.jetbrains;
  $('jb-status').textContent = jb?.issue ?? '';
  if (app?.runtime.kind === 'ready') {
    const h = app.runtime.hello;
    $('versions').textContent = `Extension ${app.extensionVersion} · Runtime ${h.nativeVersion} · Xray ${h.xrayVersion ?? 'missing'} · Protocol v${h.protocolVersion} · Secrets: ${h.keyStorage}`;
  }
  renderSubscriptions();
}

function renderSubscriptions() {
  const ul = $('sub-list');
  ul.replaceChildren(
    ...list.subscriptions.map((s) => {
      const li = document.createElement('li');
      const grow = document.createElement('div');
      grow.className = 'grow';
      const n = document.createElement('div');
      n.className = 'name';
      n.textContent = `${s.name} (${s.serverCount})`;
      const d = document.createElement('div');
      d.className = 'sub';
      d.textContent = s.lastError ? `Update failed: ${s.lastError}` : s.lastUpdated ? `${s.host} · updated ${new Date(s.lastUpdated * 1000).toLocaleString()}` : s.host;
      grow.append(n, d);
      const upd = document.createElement('button');
      upd.className = 'link';
      upd.textContent = 'Update';
      upd.onclick = async () => {
        upd.disabled = true;
        upd.textContent = 'Updating…';
        const r = await request('updateSubscription', { id: s.id });
        const out = $('settings-result');
        if (r.ok) {
          const x = r.result as SubscriptionResult;
          showResult(out, `${s.name}: ${x.added} added, ${x.updated} updated, ${x.removed} removed${x.rejected ? `, ${x.rejected} rejected` : ''}.`, false);
        } else {
          showResult(out, `Subscription update failed: ${r.error.message}`, true);
        }
        await refreshList();
        renderSubscriptions();
      };
      const del = document.createElement('button');
      del.className = 'link';
      del.textContent = 'Remove';
      del.onclick = async () => {
        if (del.dataset.armed !== '1') {
          del.dataset.armed = '1';
          del.textContent = 'Remove with its servers?';
          return;
        }
        const r = await request('deleteSubscription', { id: s.id, deleteServers: true });
        if (!r.ok) toast(r.error.message);
        await refreshList();
        renderSubscriptions();
      };
      li.append(grow, upd, del);
      return li;
    }),
  );
  $('empty-subs').hidden = list.subscriptions.length > 0;
}

async function saveJetbrains() {
  const http = Number($<HTMLInputElement>('jb-http').value);
  const socks = Number($<HTMLInputElement>('jb-socks').value);
  const out = $('settings-result');
  if (!Number.isInteger(http) || !Number.isInteger(socks) || http < 1024 || socks < 1024 || http > 65535 || socks > 65535 || http === socks) {
    showResult(out, 'Ports must be different numbers between 1024 and 65535.', true);
    return;
  }
  const r = await request('setSettings', {
    jetbrainsEnabled: $<HTMLInputElement>('jb-enabled').checked,
    jetbrainsHttpPort: http,
    jetbrainsSocksPort: socks,
    passthroughWhenDisconnected: $<HTMLInputElement>('jb-passthrough').checked,
  });
  if (r.ok) {
    const needs = (r.result as { reconnectRequired?: boolean }).reconnectRequired;
    showResult(out, needs ? 'Saved. Reconnect to apply the new ports.' : 'Saved.', false);
  } else {
    showResult(out, r.error.message, true);
  }
}

async function toggleWebrtc(e: Event) {
  const box = e.target as HTMLInputElement;
  if (box.checked) {
    // Must be called from a user gesture.
    const granted = await chrome.permissions.request({ permissions: ['privacy'] });
    if (!granted) {
      box.checked = false;
      return;
    }
  }
  await chrome.storage.local.set({ webrtcProtection: box.checked });
  if (!box.checked) {
    const net = (chrome as unknown as { privacy?: typeof chrome.privacy }).privacy?.network;
    await net?.webRTCIPHandlingPolicy.clear({}).catch(() => undefined);
  }
  showResult($('settings-result'), box.checked ? 'WebRTC protection is applied on the next connect.' : 'WebRTC protection disabled.', false);
}

async function copyDiagnostics() {
  const r = await request('getDiagnostics', {});
  const diag = r.ok ? r.result : { error: r.error };
  const text = JSON.stringify({ extension: app?.extensionVersion, runtime: app?.runtime, status: app?.status, diagnostics: diag }, null, 2);
  await navigator.clipboard.writeText(text);
  showResult($('settings-result'), 'Diagnostics copied to the clipboard (contains no credentials).', false);
}

async function resetAll(btn: HTMLButtonElement) {
  if (btn.dataset.armed !== '1') {
    btn.dataset.armed = '1';
    btn.textContent = 'Click again to remove ALL servers and credentials';
    return;
  }
  const r = await request('resetAll', { confirm: true });
  btn.dataset.armed = '';
  btn.textContent = 'Remove all servers';
  showResult($('settings-result'), r.ok ? 'All servers, subscriptions and credentials were removed.' : r.error.message, !r.ok);
  await refreshList();
}

// ------------------------------------------------------------------ wiring

function wire() {
  $('nav-settings').onclick = () => setView('settings');
  $('nav-import').onclick = () => setView('import');
  $('nav-back').onclick = () => setView('main');
  $('primary').onclick = () => void onPrimary();
  $<HTMLSelectElement>('server-select').onchange = async (e) => {
    const id = (e.target as HTMLSelectElement).value;
    if (!id) return;
    const r = await request('selectServer', { id });
    if (r.ok) list.selectedServerId = id;
    if (app?.status?.state === 'connected' && app.status.serverId !== id) await connect(id);
    render();
  };

  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tabs [role=tab]')) {
    tab.onclick = () => {
      for (const t of document.querySelectorAll<HTMLButtonElement>('.tabs [role=tab]')) t.setAttribute('aria-selected', String(t === tab));
      for (const p of document.querySelectorAll<HTMLElement>('[data-panel]')) p.hidden = p.dataset.panel !== tab.dataset.tab;
      $('import-result').hidden = true;
    };
  }
  $('import-btn').onclick = () => void importText($<HTMLTextAreaElement>('import-text').value, 'paste');
  $('import-file-btn').onclick = () => $('import-file').click();
  $<HTMLInputElement>('import-file').onchange = async (e) => {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) {
      showResult($('import-result'), 'File is too large (max 5 MB).', true);
      return;
    }
    await importText(await f.text(), 'file');
    (e.target as HTMLInputElement).value = '';
  };
  $('qr-file-btn').onclick = () => $('qr-file').click();
  $<HTMLInputElement>('qr-file').onchange = async (e) => {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) await importQrBlob(f);
    (e.target as HTMLInputElement).value = '';
  };
  $('qr-tab-btn').onclick = async () => {
    try {
      await importQrBlob(await captureVisibleTab());
    } catch (err) {
      showResult($('import-result'), `Could not capture the current tab: ${(err as Error).message}`, true);
    }
  };
  document.addEventListener('paste', (e) => {
    if (view !== 'import') return;
    const item = [...(e.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
    const blob = item?.getAsFile();
    if (blob) {
      e.preventDefault();
      void importQrBlob(blob);
    }
  });
  $('sub-add-btn').onclick = () => void addSubscription();
  $('jb-save').onclick = () => void saveJetbrains();
  $<HTMLInputElement>('webrtc').onchange = (e) => void toggleWebrtc(e);
  $<HTMLInputElement>('debug-log').onchange = async (e) => {
    const r = await request('setSettings', { debugLogging: (e.target as HTMLInputElement).checked });
    if (!r.ok) toast(r.error.message);
  };
  $('copy-diag').onclick = () => void copyDiagnostics();
  $('reset-all').onclick = (e) => void resetAll(e.target as HTMLButtonElement);
}

function main() {
  wire();
  setView('main');
  const port = chrome.runtime.connect({ name: 'popup' });
  let wasReady = false;
  port.onMessage.addListener((m: SwPush) => {
    if (m?.type !== 'state') return;
    app = m.state;
    const ready = app.runtime.kind === 'ready';
    if (ready && !wasReady) void refreshList();
    wasReady = ready;
    render();
  });
}

main();
