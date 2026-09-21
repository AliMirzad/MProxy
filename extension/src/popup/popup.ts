// Popup UI. All data from the helper (server names, messages) is untrusted and is only
// ever written with textContent / value, never as HTML.
import type { CommandName, Commands, IdeCredentials, ImportResult, NativeResponse, ServerList, Settings, SubscriptionResult } from '../../../shared/protocol/types';
import type { AppState, SwPush } from '../shared/app-state';
import { currentServerId, deriveView, filterOptions, filterServers, normalizeFilter, protocolLine, type ServerFilter } from '../shared/view';
import { captureVisibleTab, decodeQrFromBlob, looksLikeProxyConfig } from './qr';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

let app: AppState | null = null;
let list: ServerList = { servers: [], subscriptions: [], selectedServerId: null };
let view: 'main' | 'import' | 'settings' = 'main';
let busyAction = false;
let serverFilter: ServerFilter = 'all';
let renaming = false;

/** The server shown as selected in the dropdown (what Rename/Delete/Connect act on). */
function selectedServer() {
  const id = $<HTMLSelectElement>('server-select').value || list.selectedServerId;
  return list.servers.find((s) => s.id === id) ?? null;
}

/** The subscription chosen in the "Show" filter, if any. */
function filteredSubscription() {
  return serverFilter.startsWith('sub:') ? list.subscriptions.find((x) => `sub:${x.id}` === serverFilter) ?? null : null;
}

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
  $('title').textContent = v === 'main' ? 'MProxy' : v === 'import' ? 'Import' : 'Settings';
  $('credit').hidden = v !== 'main';
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
  $('status-card').dataset.tone = v.tone;
  $('status-label').textContent = v.label;
  const detail = $('status-detail');
  detail.textContent = v.detail ?? '';
  detail.hidden = !v.detail;
  const hint = $('status-hint');
  hint.textContent = v.hint ?? '';
  hint.hidden = !v.hint;

  const ready = app.runtime.kind === 'ready';
  $('server-block').hidden = !ready;
  $('nav-settings').hidden = view !== 'main' || !ready;

  // Filter: all / manually added / one subscription.
  serverFilter = normalizeFilter(list, serverFilter);
  const filterSel = $<HTMLSelectElement>('server-filter');
  filterSel.replaceChildren(
    ...filterOptions(list).map((f) => {
      const o = document.createElement('option');
      o.value = f.value;
      o.textContent = f.label;
      return o;
    }),
  );
  filterSel.value = serverFilter;
  filterSel.disabled = !ready || list.servers.length === 0;

  // Server selector (only the servers of the chosen filter; the active server always stays visible).
  const sel = $<HTMLSelectElement>('server-select');
  const current = currentServerId(app, list.selectedServerId);
  const shown = filterServers(list, serverFilter);
  const currentServer = list.servers.find((s) => s.id === current);
  const options = currentServer && !shown.includes(currentServer) ? [currentServer, ...shown] : shown;
  const activeId = app.status && (app.status.state === 'connected' || app.status.state === 'connecting') ? app.status.serverId : null;
  sel.replaceChildren(
    ...options.map((s) => {
      const o = document.createElement('option');
      o.value = s.id;
      o.textContent = s.id === activeId && app?.status?.state === 'connected' ? `● ${s.name}` : s.name;
      return o;
    }),
  );
  if (options.length === 0) {
    const o = document.createElement('option');
    o.textContent = list.servers.length === 0 ? 'No servers' : 'No servers in this group';
    o.value = '';
    sel.append(o);
  }
  sel.value = current && options.some((s) => s.id === current) ? current : '';
  const st = app.status?.state;
  const locked = !ready || st === 'connecting' || st === 'disconnecting';
  sel.disabled = locked || options.length === 0;
  sel.hidden = renaming;
  $('rename-row').hidden = !renaming;
  const server = list.servers.find((s) => s.id === current);
  const subName = server?.subscriptionId ? list.subscriptions.find((x) => x.id === server.subscriptionId)?.name : null;
  $('protocol-line').textContent = server
    ? `${protocolLine(server)} · ${server.address}:${server.port}${subName ? ` · from "${subName}"` : ''}`
    : '';
  // No delete on the main page: subscriptions (with their servers) are removed in Settings.
  const busy = locked || renaming;
  $<HTMLButtonElement>('server-rename').disabled = busy || !server;
  $('sub-update').hidden = !filteredSubscription();
  $<HTMLButtonElement>('sub-update').disabled = busy;
  $('empty-servers').hidden = list.servers.length > 0;

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
    const lock = jb.authRequired ? ' · password required' : '';
    ide.textContent = jb.issue ? `IDE proxy: ${jb.issue}` : eps ? `IDE proxy (${mode}): ${eps}${lock}` : 'IDE proxy: off while disconnected';
    ide.hidden = false;
  } else {
    ide.hidden = true;
  }

}

async function selectServer(id: string) {
  const r = await request('selectServer', { id });
  if (r.ok) list.selectedServerId = id;
  // Switching servers while connected reconnects to the new one.
  if (app?.status?.state === 'connected' && app.status.serverId !== id) await connect(id);
  render();
}

async function onFilterChange(value: string) {
  serverFilter = normalizeFilter(list, value);
  try {
    await chrome.storage.local.set({ serverFilter });
  } catch {
    /* preference only */
  }
  // While disconnected, pick the first server of the new group so "Connect" uses it.
  const shown = filterServers(list, serverFilter);
  const st = app?.status?.state;
  const idle = st !== 'connected' && st !== 'connecting' && st !== 'disconnecting';
  if (idle && shown.length && !shown.some((x) => x.id === list.selectedServerId)) {
    await selectServer(shown[0].id);
    return;
  }
  render();
}

function startRename() {
  const server = selectedServer();
  if (!server) return;
  renaming = true;
  renameTarget = server.id;
  render();
  const input = $<HTMLInputElement>('rename-input');
  input.value = server.name;
  input.focus();
  input.select();
}

let renameTarget: string | null = null;
async function finishRename(save: boolean) {
  const server = list.servers.find((s) => s.id === renameTarget) ?? selectedServer();
  const name = $<HTMLInputElement>('rename-input').value.trim();
  renaming = false;
  if (save && server && name && name !== server.name) {
    const r = await request('renameServer', { id: server.id, name });
    if (!r.ok) toast(r.error.message);
  }
  await refreshList();
  render();
}

async function updateFilteredSubscription() {
  const sub = filteredSubscription();
  if (!sub) return;
  const btn = $<HTMLButtonElement>('sub-update');
  btn.disabled = true;
  btn.textContent = 'Updating…';
  const r = await request('updateSubscription', { id: sub.id });
  btn.textContent = 'Update';
  if (r.ok) {
    const x = r.result as SubscriptionResult;
    toast(`Updated: ${x.added} new, ${x.updated} updated, ${x.removed} removed`);
  } else {
    toast(r.error.message);
  }
  await refreshList();
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
    $<HTMLInputElement>('sub-private').checked = s.allowPrivateSubscriptionHosts;
    $<HTMLInputElement>('jb-auth').checked = s.ideAuth;
    await loadIdeCredentials(s.ideAuth);
  }
  const { webrtcProtection } = await chrome.storage.local.get('webrtcProtection');
  $<HTMLInputElement>('webrtc').checked = webrtcProtection !== false; // on by default
  const jb = app?.status?.jetbrains;
  $('jb-status').textContent = jb?.issue ?? '';
  if (app?.runtime.kind === 'ready') {
    const h = app.runtime.hello;
    $('versions').textContent = `Extension ${app.extensionVersion} · Runtime ${h.nativeVersion} · Xray ${h.xrayVersion ?? 'missing'} · Protocol v${h.protocolVersion} · Secrets: ${h.keyStorage}`;
  }
  renderSubscriptions();
  renderServerSettings();
}

let settingsFilter: ServerFilter = 'all';

/** Settings → Servers: every server with a Remove button (single-server delete lives here only). */
function renderServerSettings() {
  settingsFilter = normalizeFilter(list, settingsFilter);
  const sel = $<HTMLSelectElement>('srv-filter');
  sel.replaceChildren(
    ...filterOptions(list).map((f) => {
      const o = document.createElement('option');
      o.value = f.value;
      o.textContent = f.label;
      return o;
    }),
  );
  sel.value = settingsFilter;
  const subs = new Map(list.subscriptions.map((s) => [s.id, s.name]));
  const shown = filterServers(list, settingsFilter);
  $('srv-list').replaceChildren(
    ...shown.map((s) => {
      const li = document.createElement('li');
      const grow = document.createElement('div');
      grow.className = 'grow';
      const n = document.createElement('div');
      n.className = 'name';
      n.textContent = s.name;
      const d = document.createElement('div');
      d.className = 'sub';
      const origin = s.subscriptionId ? `subscription "${subs.get(s.subscriptionId) ?? '?'}"` : 'added manually';
      d.textContent = `${protocolLine(s)} · ${origin}`;
      grow.append(n, d);
      const del = document.createElement('button');
      del.className = 'link danger';
      del.textContent = 'Remove';
      del.title = 'Remove this server';
      del.onclick = async () => {
        if (del.dataset.armed !== '1') {
          // Second click within 4 s confirms.
          del.dataset.armed = '1';
          del.textContent = 'Remove?';
          setTimeout(() => {
            del.dataset.armed = '';
            del.textContent = 'Remove';
          }, 4000);
          return;
        }
        const r = await request('deleteServer', { id: s.id });
        showResult($('settings-result'), r.ok ? `Removed server "${s.name}".` : r.error.message, !r.ok);
        await refreshList();
        renderServerSettings();
        renderSubscriptions();
      };
      li.append(grow, del);
      return li;
    }),
  );
  $('empty-srv').hidden = shown.length > 0;
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
      del.className = 'link danger';
      del.textContent = 'Remove';
      del.title = 'Remove this subscription and all its servers';
      del.onclick = async () => {
        if (del.dataset.armed !== '1') {
          // Second click within 4 s confirms.
          del.dataset.armed = '1';
          del.textContent = `Remove with its ${s.serverCount} servers?`;
          setTimeout(() => {
            del.dataset.armed = '';
            del.textContent = 'Remove';
          }, 4000);
          return;
        }
        const r = await request('deleteSubscription', { id: s.id, deleteServers: true });
        showResult($('settings-result'), r.ok ? `Removed subscription "${s.name}" and its servers.` : r.error.message, !r.ok);
        await refreshList();
        renderSubscriptions();
        renderServerSettings();
      };
      li.append(grow, upd, del);
      return li;
    }),
  );
  $('empty-subs').hidden = list.subscriptions.length > 0;
}

let idePassword = '';

async function loadIdeCredentials(required: boolean) {
  $('jb-cred').hidden = !required;
  const err = $('jb-cred-error');
  err.hidden = true;
  if (!required) return;
  $('jb-user').textContent = '…';
  $('jb-pass').textContent = '…';
  idePassword = '';
  const r = await request('getIdeCredentials', {});
  if (!r.ok) {
    // Shown in the box itself, so an empty username/password is never silent.
    err.textContent = `Could not load the credentials: ${r.error.message}`;
    err.hidden = false;
    $('jb-user').textContent = '—';
    $('jb-pass').textContent = '—';
    return;
  }
  const c = r.result as IdeCredentials;
  $('jb-user').textContent = c.username;
  idePassword = c.password;
  $('jb-pass').textContent = '••••••••';
  $('jb-show-pass').textContent = 'Show';
}

async function copyText(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copied`);
  } catch {
    toast('Could not copy');
  }
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
    ideAuth: $<HTMLInputElement>('jb-auth').checked,
  });
  if (r.ok) await loadIdeCredentials($<HTMLInputElement>('jb-auth').checked);
  if (r.ok) {
    const needs = (r.result as { reconnectRequired?: boolean }).reconnectRequired;
    showResult(out, needs ? 'Saved. Reconnect to apply the new ports.' : 'Saved.', false);
  } else {
    showResult(out, r.error.message, true);
  }
}

async function toggleWebrtc(e: Event) {
  const box = e.target as HTMLInputElement;
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
  $<HTMLSelectElement>('server-select').onchange = (e) => {
    const id = (e.target as HTMLSelectElement).value;
    if (id) void selectServer(id);
  };
  $<HTMLSelectElement>('server-filter').onchange = (e) => void onFilterChange((e.target as HTMLSelectElement).value);
  $('server-rename').onclick = () => startRename();
  $('sub-update').onclick = () => void updateFilteredSubscription();
  $<HTMLSelectElement>('srv-filter').onchange = (e) => {
    settingsFilter = (e.target as HTMLSelectElement).value;
    renderServerSettings();
  };
  $('rename-save').onclick = () => void finishRename(true);
  $('rename-cancel').onclick = () => void finishRename(false);
  $<HTMLInputElement>('rename-input').onkeydown = (e) => {
    if (e.key === 'Enter') void finishRename(true);
    if (e.key === 'Escape') void finishRename(false);
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
  $<HTMLInputElement>('sub-private').onchange = async (e) => {
    const r = await request('setSettings', { allowPrivateSubscriptionHosts: (e.target as HTMLInputElement).checked });
    if (!r.ok) toast(r.error.message);
  };
  // Applies immediately (no Save needed) and shows/hides the credentials.
  $<HTMLInputElement>('jb-auth').onchange = async (e) => {
    const box = e.target as HTMLInputElement;
    const r = await request('setSettings', { ideAuth: box.checked });
    if (!r.ok) {
      box.checked = !box.checked;
      showResult($('settings-result'), r.error.message, true);
      return;
    }
    await loadIdeCredentials(box.checked);
    const needs = (r.result as { reconnectRequired?: boolean }).reconnectRequired;
    showResult(
      $('settings-result'),
      box.checked
        ? `Password required for the IDE proxy.${needs ? ' Reconnect to apply.' : ''}`
        : `Password turned off: any program on this computer can now use the IDE proxy.${needs ? ' Reconnect to apply.' : ''}`,
      !box.checked,
    );
  };
  $('jb-copy-user').onclick = () => void copyText($('jb-user').textContent ?? '', 'Username');
  $('jb-copy-pass').onclick = () => void copyText(idePassword, 'Password');
  $('jb-show-pass').onclick = () => {
    const shown = $('jb-show-pass').textContent === 'Hide';
    $('jb-pass').textContent = shown ? '••••••••' : idePassword;
    $('jb-show-pass').textContent = shown ? 'Show' : 'Hide';
  };
  $('jb-new-pass').onclick = async () => {
    const r = await request('regenerateIdeCredentials', {});
    if (!r.ok) {
      toast(r.error.message);
      return;
    }
    const c = r.result as IdeCredentials;
    idePassword = c.password;
    $('jb-pass').textContent = '••••••••';
    $('jb-show-pass').textContent = 'Show';
    showResult($('settings-result'), c.reconnectRequired ? 'New password created. Reconnect to apply it, then update the IDE.' : 'New password created. Update it in the IDE.', false);
  };
  $('copy-diag').onclick = () => void copyDiagnostics();
  $('reset-all').onclick = (e) => void resetAll(e.target as HTMLButtonElement);
}

async function loadFilter() {
  try {
    const { serverFilter: saved } = await chrome.storage.local.get('serverFilter');
    if (typeof saved === 'string') serverFilter = saved;
  } catch {
    /* storage unavailable: default "all" */
  }
}

function main() {
  wire();
  void loadFilter().then(() => render());
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
