#!/usr/bin/env node
// Real-browser end-to-end test (Chrome/Brave/Chromium/Edge on the current OS).
//
//   node extension/tests/e2e/browser.e2e.mjs [--browser <path>] [--headed]
//
// What it does, with nothing mocked:
//  1. installs the native runtime with the real installer (`private-proxy-host install`) into a
//     temp dir; this registers native messaging for all supported browsers (per user);
//  2. starts a local Xray "remote server" (VLESS REALITY+Vision, VLESS WS, VMess WS) and an
//     HTTP target reachable only as http://probe.test:<port>/ via the server's DNS;
//  3. launches the browser with a throwaway profile and the unpacked extension;
//  4. drives the real popup: import links, connect, switch servers, JetBrains settings, disconnect;
//  5. verifies browser traffic, chrome.proxy state, crash recovery, the no-stale-proxy-after-browser-crash
//     guarantee, and that no helper/Xray survives browser exit;
//  6. uninstalls (--purge) and removes all temp data, including the Credential Manager/Keychain key.
//
// The user's own browser profile is never touched.
import { chromium } from 'playwright-core';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import http from 'node:http';
import { hostCandidates } from '../../../scripts/target-dir.mjs';
import { startTestServer, freePort, MARKER } from '../../../scripts/lib/test-server.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const args = process.argv.slice(2);
const headed = args.includes('--headed');
const shotDir = args.includes('--screenshots') ? args[args.indexOf('--screenshots') + 1] : null;
async function shot(page, name) {
  if (shotDir) await page.screenshot({ path: join(shotDir, `${name}.png`), fullPage: true });
}
const win = process.platform === 'win32';
const plat = `${win ? 'windows' : 'macos'}-${process.arch === 'arm64' ? 'arm64' : 'x64'}`;
const xrayDir = join(root, 'native/xray/dist', plat);
const xray = join(xrayDir, win ? 'xray.exe' : 'xray');
const extId = readFileSync(join(root, 'shared/extension-id.txt'), 'utf8').trim();
const extDist = join(root, 'extension/dist');

// The E2E test needs the debug helper: its data-dir / probe-target overrides are test hooks
// that release builds ignore (see ppcore::test_hook).
function findHost() {
  const f = hostCandidates('debug').find(existsSync);
  if (f) return f;
  throw new Error('Build the native helper first: node scripts/cargo.mjs build');
}

function findBrowser() {
  const i = args.indexOf('--browser');
  if (i >= 0) return args[i + 1];
  const c = win
    ? [
        // Branded Chrome 137+ ignores --load-extension, so prefer Chromium/Brave for automation.
        `${process.env.LOCALAPPDATA}\\Chromium\\Application\\chrome.exe`,
        `${process.env.ProgramFiles}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
        `${process.env.LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
        `${process.env.ProgramFiles}\\Google\\Chrome\\Application\\chrome.exe`,
        `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
      ]
    : ['/Applications/Chromium.app/Contents/MacOS/Chromium', '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'];
  const f = c.find((p) => p && existsSync(p));
  if (!f) throw new Error('No Chromium browser found; pass --browser <path>');
  return f;
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` - ${detail}` : ''}`);
  if (!ok) throw new Error(`check failed: ${name} ${detail}`);
}

const portOpen = (port) =>
  new Promise((res) => {
    const s = net.connect(port, '127.0.0.1');
    s.once('connect', () => (s.destroy(), res(true)));
    s.once('error', () => res(false));
    setTimeout(() => (s.destroy(), res(false)), 800);
  });

/** GET an absolute URL through an HTTP proxy, like an IDE configured with an HTTP proxy. */
// IDE endpoint credentials (the endpoint requires a password by default); set after reading them
// from the extension.
let ideCred = null;
function viaHttpProxy(proxyPort, url, cred = ideCred) {
  return new Promise((res) => {
    const u = new URL(url);
    const auth = cred ? `Proxy-Authorization: Basic ${Buffer.from(`${cred.username}:${cred.password}`).toString('base64')}\r\n` : '';
    const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`GET ${url} HTTP/1.1\r\nHost: ${u.host}\r\n${auth}Connection: close\r\n\r\n`));
    let buf = '';
    s.on('data', (d) => (buf += d));
    s.on('end', () => res(buf));
    s.on('error', (e) => res(String(e)));
    setTimeout(() => (s.destroy(), res(buf)), 10000);
  });
}

async function waitFor(fn, what, ms = 30000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`timeout waiting for ${what}`);
}

const tmp = mkdtempSync(join(tmpdir(), 'pp-e2e-'));
const runtimeDir = join(tmp, 'runtime');
const dataDir = join(tmp, 'data');
const profileDir = join(tmp, 'profile');
const host = findHost();
const browserPath = findBrowser();
const env = { ...process.env, PRIVATE_PROXY_TEST_MODE: '1', PRIVATE_PROXY_ALLOW_LOOPBACK: '1', PRIVATE_PROXY_DATA_DIR: dataDir };
let server;
let context;

// A second, hostile extension loaded next to ours. It tries every way an extension could reach
// the privileged side: native messaging to our host, runtime messages and a port to our
// extension (pretending to be the popup).
const attackerDir = join(tmp, 'attacker-ext');
mkdirSync(attackerDir, { recursive: true });
writeFileSync(join(attackerDir, 'manifest.json'), JSON.stringify({
  manifest_version: 3, name: 'E2E attacker', version: '1.0', permissions: ['nativeMessaging', 'proxy'], background: { service_worker: 'sw.js' },
}));
writeFileSync(join(attackerDir, 'sw.js'), `
const VICTIM = ${JSON.stringify(extId)};
globalThis.attack = async () => {
  const out = {};
  await new Promise((resolve) => {
    try {
      const p = chrome.runtime.connectNative('com.privateproxy.host');
      p.onMessage.addListener(() => { out.native = 'GOT A MESSAGE FROM THE HOST'; });
      p.onDisconnect.addListener(() => { out.native = out.native || ('disconnected: ' + (chrome.runtime.lastError?.message || '')); resolve(); });
      p.postMessage({ id: 1, cmd: 'connect', args: { serverId: '00000000-0000-4000-8000-000000000000' } });
    } catch (e) { out.native = 'threw: ' + e.message; resolve(); }
    setTimeout(resolve, 5000);
  });
  try {
    out.message = JSON.stringify(await chrome.runtime.sendMessage(VICTIM, { type: 'request', cmd: 'disconnect', args: {} }));
  } catch (e) { out.message = 'error: ' + e.message; }
  await new Promise((resolve) => {
    try {
      const port = chrome.runtime.connect(VICTIM, { name: 'popup' });
      port.onMessage.addListener(() => { out.port = 'GOT STATE FROM VICTIM'; resolve(); });
      port.onDisconnect.addListener(() => { out.port = out.port || ('disconnected: ' + (chrome.runtime.lastError?.message || '')); resolve(); });
      port.postMessage({ type: 'request', cmd: 'disconnect', args: {} });
    } catch (e) { out.port = 'threw: ' + e.message; resolve(); }
    setTimeout(resolve, 3000);
  });
  return out;
};
globalThis.takeOver = async () => {
  await chrome.proxy.settings.set({ value: { mode: 'fixed_servers', rules: { singleProxy: { scheme: 'http', host: '127.0.0.1', port: 9 } } }, scope: 'regular' });
  return (await chrome.proxy.settings.get({})).levelOfControl;
};
globalThis.release = async () => chrome.proxy.settings.clear({ scope: 'regular' });
`);

async function launch() {
  const ctx = await chromium.launchPersistentContext(profileDir, {
    executablePath: browserPath,
    headless: !headed,
    env,
    args: [`--disable-extensions-except=${extDist},${attackerDir}`, `--load-extension=${extDist},${attackerDir}`, '--no-first-run', '--no-default-browser-check', '--disable-features=BraveRewards'],
  });
  const deadline = Date.now() + 15000;
  let sw = null;
  while (!sw && Date.now() < deadline) {
    sw = ctx.serviceWorkers().find((w) => w.url().includes(extId)) ?? null;
    if (!sw) await ctx.waitForEvent('serviceworker', { timeout: 2000 }).catch(() => null);
  }
  if (!sw || !sw.url().includes(extId)) {
    await ctx.close();
    throw new Error(`The extension did not load (expected ID ${extId}). This browser may ignore --load-extension (Chrome 137+ branded builds do); use Chromium/Brave or load it manually.`);
  }
  return { ctx, sw };
}

async function popupState(page) {
  return page.evaluate(() => document.getElementById('status-label')?.textContent);
}

try {
  console.log(`browser: ${browserPath}\nhelper:  ${host}\ntemp:    ${tmp}`);
  execFileSync(process.execPath, [join(root, 'extension/scripts/build.mjs')], { stdio: 'ignore' });

  // 1. Install with the real installer.
  const inst = spawnSync(host, ['install', '--source', xrayDir, '--target', runtimeDir, '--all-browsers'], { env, encoding: 'utf8' });
  check('installer succeeds', inst.status === 0, (inst.stderr || '').trim());
  check('installer registered at least one browser', /Registered for/.test(inst.stdout));

  // 2. Remote side.
  server = await startTestServer(xray, tmp);
  const jbHttp = await freePort();
  const jbSocks = await freePort();

  // 3. Browser.
  let { ctx, sw } = await launch();
  context = ctx;
  check('extension loaded with pinned ID', sw.url().startsWith(`chrome-extension://${extId}/`), sw.url());

  const popup = await ctx.newPage();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await waitFor(async () => (await popupState(popup)) === 'Disconnected', 'Disconnected state', 20000);
  await shot(popup, '01-empty');
  check('native runtime reachable from the extension (hello)', true);
  const proxy0 = await sw.evaluate(() => chrome.proxy.settings.get({}));
  check('browser starts direct', proxy0.value.mode !== 'fixed_servers', JSON.stringify(proxy0.value));
  // The operating system proxy configuration must never be touched.
  const sysProxy = () => process.platform === 'win32'
    ? spawnSync(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe'), ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'], { encoding: 'utf8' }).stdout.split(/\r?\n/).filter((l) => /Proxy|AutoConfig/i.test(l)).join('|')
    : spawnSync('/usr/sbin/scutil', ['--proxy'], { encoding: 'utf8' }).stdout;
  const sysProxyBefore = sysProxy();

  // JetBrains ports (avoid touching real 10808/10809).
  await popup.click('#nav-settings');
  await popup.fill('#jb-http', String(jbHttp));
  await popup.fill('#jb-socks', String(jbSocks));
  await popup.click('#jb-save');
  await waitFor(async () => (await popup.textContent('#settings-result'))?.includes('Saved'), 'settings saved');
  check('IDE endpoint (direct passthrough) listening while disconnected', await waitFor(() => portOpen(jbHttp), 'jb port', 10000));
  const credR = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'request', cmd: 'getIdeCredentials', args: {} }));
  ideCred = credR.result;
  check('IDE endpoint password is on by default', credR.ok && ideCred.required === true && ideCred.password.length >= 20);
  const noPass = await viaHttpProxy(jbHttp, `http://127.0.0.1:${server.targetPort}/`, null);
  check('IDE endpoint refuses requests without the password (407)', /^HTTP\/1\.[01] 407/.test(noPass), noPass.split('\r\n')[0]);
  const withPass = await viaHttpProxy(jbHttp, `http://127.0.0.1:${server.targetPort}/`);
  check('IDE endpoint works with the password', withPass.includes(MARKER), withPass.split('\r\n')[0]);
  await popup.click('#nav-back');

  // 4. Import via the UI.
  await popup.click('#nav-import');
  const deadLink = `vless://5783a3e7-e373-51cd-8642-c83782b807c5@127.0.0.1:${await freePort()}?type=tcp&security=none#E2E%20Dead%20Server`;
  await popup.fill('#import-text', [server.links.reality, server.links.vlessWs, server.links.vmess, deadLink].join('\n'));
  await popup.click('#import-btn');
  const imported = await waitFor(async () => {
    const t = await popup.textContent('#import-result');
    return t && !t.startsWith('Importing') ? t : null;
  }, 'import result');
  check('import 4 servers via popup', imported.includes('Imported: 4 new'), imported);
  await shot(popup, '02-import');
  await popup.click('#nav-back');
  const names = await popup.$$eval('#server-select option', (els) => els.map((e) => e.textContent.replace(/^● /, '')));
  check('no server list below the dropdowns (dropdown only)', (await popup.$('#server-list')) === null);
  const filters = await popup.$$eval('#server-filter option', (els) => els.map((e) => e.textContent));
  check('filter dropdown offers all / manually added', filters[0] === 'All servers (4)' && filters[1] === 'Manually added (4)', filters.join(', '));
  check('server list shows imported names', names.includes('E2E Reality') && names.includes('E2E VMess WS'), names.join(', '));
  const listText = await popup.evaluate(() => document.body.innerText);
  check('popup does not expose the user ID', !listText.includes('5783a3e7'));

  const probe = await ctx.newPage();
  async function browserReachesProbe() {
    try {
      await probe.goto(server.probeUrl, { timeout: 10000 });
      return (await probe.textContent('body'))?.includes(MARKER) ?? false;
    } catch {
      return false;
    }
  }
  check('probe.test is NOT reachable before connecting (no local DNS for it)', !(await browserReachesProbe()));

  // Unreachable server: clear error in the popup, browser stays direct.
  {
    const id = await popup.$eval('#server-select', (sel) => [...sel.options].find((o) => o.textContent === 'E2E Dead Server')?.value);
    await popup.selectOption('#server-select', id);
    await popup.click('#primary');
    await waitFor(async () => (await popupState(popup)) === 'Server unreachable', 'error state', 30000);
    await shot(popup, '04-error');
    const st = await sw.evaluate(() => chrome.proxy.settings.get({}));
    check('unreachable server -> "Server unreachable" shown, browser stays direct', st.value.mode !== 'fixed_servers');
  }

  // Server management through the real popup buttons.
  {
    const optionNames = () => popup.$$eval('#server-select option', (els) => els.map((e) => e.textContent.replace(/^● /, '')));
    check('main page has no delete buttons', (await popup.$('#server-delete')) === null && (await popup.$('#sub-delete')) === null);
    // Subscription: add, filter, update, delete with its servers.
    let subBody = ['A', 'B'].map((n) => `vless://5783a3e7-e373-51cd-8642-c83782b807c5@sub${n.toLowerCase()}.example.com:443?security=tls&sni=sub.example.com#Sub%20${n}`).join('\n');
    const subSrv = http.createServer((_q, res) => res.end(Buffer.from(subBody).toString('base64'))).listen(0, '127.0.0.1');
    await new Promise((r) => subSrv.once('listening', r));
    await popup.click('#nav-import');
    await popup.click('[data-tab="sub"]');
    await popup.fill('#sub-name', 'E2E Sub');
    await popup.fill('#sub-url', `http://127.0.0.1:${subSrv.address().port}/sub`);
    await popup.click('#sub-add-btn');
    await waitFor(async () => /Subscription added|new/i.test((await popup.textContent('#import-result')) ?? ''), 'subscription added', 15000).catch(() => undefined);
    await popup.click('#nav-back');
    const filterValues = await popup.$$eval('#server-filter option', (els) => els.map((e) => [e.value, e.textContent]));
    const subOpt = filterValues.find(([, t]) => t.startsWith('Subscription: E2E Sub'));
    check('filter lists the subscription with its server count', !!subOpt && subOpt[1] === 'Subscription: E2E Sub (2)', filterValues.map((x) => x[1]).join(', '));
    await popup.selectOption('#server-filter', subOpt[0]);
    await popup.waitForTimeout(300);
    check('filtering by subscription shows only its servers', JSON.stringify(await optionNames()) === JSON.stringify(['Sub A', 'Sub B']), (await optionNames()).join(', '));
    await popup.selectOption('#server-filter', 'manual');
    await popup.waitForTimeout(300);
    check('"Manually added" shows only hand-imported servers', !(await optionNames()).some((n) => n.startsWith('Sub ')) && (await optionNames()).length === 4, (await optionNames()).join(', '));
    await popup.selectOption('#server-filter', subOpt[0]);
    await popup.waitForTimeout(300);
    check('Update subscription appears when a subscription is chosen', await popup.isVisible('#sub-update'));
    subBody += '\nvless://5783a3e7-e373-51cd-8642-c83782b807c5@subc.example.com:443?security=tls&sni=sub.example.com#Sub%20C';
    await popup.click('#sub-update');
    await waitFor(async () => (await optionNames()).includes('Sub C'), 'subscription updated', 15000).catch(() => undefined);
    check('Update subscription fetches the new server list', (await optionNames()).includes('Sub C'), (await optionNames()).join(', '));
    // Remove the subscription (and its servers) from Settings.
    await popup.click('#nav-settings');
    await popup.waitForTimeout(300);
    const removeBtn = popup.locator('#sub-list li', { hasText: 'E2E Sub' }).locator('button', { hasText: 'Remove' });
    await removeBtn.click();
    const armed = await removeBtn.textContent();
    check('Settings Remove asks for confirmation with the server count', /Remove with its 3 servers\?/.test(armed ?? ''), armed);
    await removeBtn.click();
    await waitFor(async () => /Removed subscription "E2E Sub"/.test((await popup.textContent('#settings-result')) ?? ''), 'subscription removed', 10000).catch(() => undefined);
    await popup.click('#nav-back');
    await popup.waitForTimeout(300);
    const afterFilters = await popup.$$eval('#server-filter option', (els) => els.map((e) => e.textContent));
    check('Removing the subscription in Settings deletes it and all its servers', !(await optionNames()).some((n) => n.startsWith('Sub ')) && !afterFilters.some((t) => t.includes('E2E Sub')) && (await popup.$eval('#server-filter', (e) => e.value)) === 'all', `${(await optionNames()).join(', ')} | ${afterFilters.join(', ')}`);
    subSrv.close();
  }

  // 5. Connect each server and browse through it.
  for (const name of ['E2E Reality', 'E2E VLESS WS', 'E2E VMess WS']) {
    const id = await popup.$eval('#server-select', (sel, n) => [...sel.options].find((o) => o.textContent === n)?.value, name);
    await popup.selectOption('#server-select', id);
    const label = await popupState(popup);
    if (label !== 'Connected') await popup.click('#primary');
    await waitFor(async () => (await popupState(popup)) === 'Connected' && (await popup.textContent('#protocol-line'))?.length, `Connected (${name})`, 30000);
    await waitFor(async () => {
      const st = await sw.evaluate(() => chrome.proxy.settings.get({}));
      return st.value.mode === 'fixed_servers' && st.levelOfControl === 'controlled_by_this_extension';
    }, 'proxy applied', 10000);
    const reached = await waitFor(browserReachesProbe, `browse via ${name}`, 15000).catch(() => false);
    check(`browser traffic goes through ${name} (remote DNS)`, reached);
  }
  await shot(popup, '03-connected');
  const pst = await sw.evaluate(() => chrome.proxy.settings.get({}));
  check('chrome.proxy uses loopback SOCKS5', pst.value.rules.singleProxy.host === '127.0.0.1' && pst.value.rules.singleProxy.scheme === 'socks5', JSON.stringify(pst.value.rules.singleProxy));
  const expectedBypass = ['<local>', 'localhost', '127.0.0.0/8', '[::1]', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', 'fc00::/7', 'fe80::/10'];
  check('bypass list is exactly the documented local/private ranges', JSON.stringify(pst.value.rules.bypassList) === JSON.stringify(expectedBypass), JSON.stringify(pst.value.rules.bypassList));
  const badge = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('toolbar badge shows ON', badge === 'ON');
  const rtc = await sw.evaluate(() => chrome.privacy.network.webRTCIPHandlingPolicy.get({}));
  check('WebRTC leak protection active by default while connected', rtc.value === 'disable_non_proxied_udp', JSON.stringify(rtc));
  check('operating system proxy settings unchanged while connected', sysProxy() === sysProxyBefore, sysProxy());

  // Security: the installed runtime (not the build tree) runs Xray verified and isolated.
  {
    const d0 = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'request', cmd: 'getDiagnostics', args: {} }));
    check('installed Xray verified against the pinned SHA-256', d0.result.xrayVerified === true);
    if (process.platform === 'win32') {
      const iso = d0.result.xrayIsolation || {};
      check('installed Xray runs at Low integrity, child processes blocked', iso.integrity === 'low' && iso.childProcessesBlocked === true, JSON.stringify(iso));
      const acl = spawnSync(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'icacls.exe'), [runtimeDir], { encoding: 'utf8' }).stdout || '';
      const broad = /(Everyone|BUILTIN\\Users|Authenticated Users|NT AUTHORITY\\INTERACTIVE):/i.test(acl);
      check('runtime directory is not writable by other users (private ACL)', !broad && /SYSTEM/.test(acl), acl.replace(/\s+/g, ' ').slice(0, 200));
    }
  }

  // Security: a hostile web page cannot reach the extension or drive the tunnel.
  {
    const evil = await ctx.newPage();
    await evil.goto(`http://127.0.0.1:${server.targetPort}/`);
    const r = await evil.evaluate(async ({ id, jb }) => {
      const out = {};
      out.runtime = typeof globalThis.chrome?.runtime?.sendMessage;
      try {
        await globalThis.chrome.runtime.sendMessage(id, { type: 'request', cmd: 'disconnect', args: {} });
        out.send = 'sent';
      } catch (e) { out.send = 'error: ' + e.message; }
      try { await fetch(`chrome-extension://${id}/popup.html`); out.resource = 'readable'; } catch { out.resource = 'blocked'; }
      try { const t = await (await fetch(`http://127.0.0.1:${jb}/`)).text(); out.ide = t.slice(0, 40); } catch { out.ide = 'blocked'; }
      window.postMessage({ type: 'request', cmd: 'disconnect', args: {} }, '*');
      return out;
    }, { id: extId, jb: jbHttp });
    await evil.close();
    check('web page has no chrome.runtime messaging channel to the extension', r.runtime !== 'function' || r.send.startsWith('error'), JSON.stringify(r));
    check('web page cannot load extension resources', r.resource === 'blocked', r.resource);
    check('web page cannot use the IDE endpoint as a relay to the extension or helper', !String(r.ide).includes(MARKER), String(r.ide));
    await popup.waitForTimeout(500);
    check('tunnel unaffected by the hostile page', (await popupState(popup)) === 'Connected');
  }

  // Security: a second, hostile extension cannot use our native host or our extension.
  {
    const attacker = ctx.serviceWorkers().find((w) => !w.url().includes(extId));
    check('attacker extension loaded next to ours', !!attacker, ctx.serviceWorkers().map((w) => w.url()).join(' '));
    if (attacker) {
      const r = await attacker.evaluate(() => globalThis.attack());
      check('other extension is refused by the native host (allowed_origins)', /forbidden/i.test(r.native) && !r.native.includes('GOT'), r.native);
      check('other extension cannot message our extension', String(r.message).startsWith('error') || r.message === undefined || r.message === 'undefined', r.message);
      check('other extension cannot connect to our extension as the popup', !String(r.port).includes('GOT'), r.port);
      await popup.waitForTimeout(500);
      check('tunnel unaffected by the hostile extension', (await popupState(popup)) === 'Connected');
    }
  }

  // IDE endpoint through the tunnel.
  const viaIde = await viaHttpProxy(jbHttp, server.probeUrl);
  check('JetBrains HTTP endpoint tunnels to the server (remote DNS)', viaIde.includes(MARKER), viaIde.slice(0, 80));

  // 6. Crash recovery: kill Xray, expect automatic restart.
  const diag = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'request', cmd: 'getDiagnostics', args: {} }));
  const pid = diag.result.xrayPid;
  process.kill(pid);
  await waitFor(async () => {
    const d = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'request', cmd: 'getDiagnostics', args: {} }));
    return d.result.xrayPid && d.result.xrayPid !== pid && (await popupState(popup)) === 'Connected';
  }, 'xray restart', 20000);
  check('Xray crash -> automatic restart, still browsing', await waitFor(browserReachesProbe, 'browse after restart', 15000).catch(() => false));

  await popup.click('#nav-settings');
  await popup.waitForTimeout(500);
  await waitFor(async () => (await popup.textContent('#jb-user')) === 'privateproxy', 'credentials shown', 5000).catch(() => undefined);
  check('Settings shows the IDE username', (await popup.textContent('#jb-user')) === 'privateproxy', await popup.textContent('#jb-user'));
  await popup.click('#jb-show-pass');
  const shownPass = await popup.textContent('#jb-pass');
  check('Settings shows the IDE password on "Show"', shownPass === ideCred.password, `${shownPass?.length} chars`);
  await popup.click('#jb-show-pass');
  await shot(popup, '05-settings');
  await popup.click('#nav-back');

  // 7. Disconnect.
  await popup.click('#primary');
  await waitFor(async () => (await popupState(popup)) === 'Disconnected', 'Disconnected', 15000);
  const after = await sw.evaluate(() => chrome.proxy.settings.get({}));
  check('disconnect restores direct browser networking', after.value.mode !== 'fixed_servers' && after.levelOfControl === 'controllable_by_this_extension', JSON.stringify(after));
  check('probe.test unreachable after disconnect', !(await browserReachesProbe()));
  const rtcAfter = await sw.evaluate(() => chrome.privacy.network.webRTCIPHandlingPolicy.get({}));
  check('WebRTC policy restored after disconnect', rtcAfter.value !== 'disable_non_proxied_udp', JSON.stringify(rtcAfter));
  const direct = await viaHttpProxy(jbHttp, `http://127.0.0.1:${server.targetPort}/`);
  check('JetBrains endpoint keeps working (direct) after disconnect', direct.includes(MARKER));
  const directProbe = await viaHttpProxy(jbHttp, server.probeUrl);
  check('JetBrains endpoint is really direct after disconnect (probe.test unresolvable)', !directProbe.includes(MARKER));

  // Security: another extension takes over the browser proxy while we are connected. The popup
  // must never keep saying "Connected" when our setting is no longer in effect.
  {
    await popup.click('#primary');
    await waitFor(async () => (await popupState(popup)) === 'Connected', 'Connected before takeover', 30000);
    const attacker = ctx.serviceWorkers().find((w) => !w.url().includes(extId));
    const lvl = await attacker.evaluate(() => globalThis.takeOver());
    const ours = await sw.evaluate(() => chrome.proxy.settings.get({}));
    if (ours.levelOfControl === 'controlled_by_this_extension') {
      check('proxy takeover by another extension: ours keeps precedence', true, lvl);
    } else {
      const label = await waitFor(async () => {
        const l = await popupState(popup);
        return l !== 'Connected' ? l : null;
      }, 'takeover detected', 15000).catch(() => 'still Connected');
      const shown = await popup.evaluate(() => document.body.innerText);
      check('proxy takeover by another extension -> tunnel disconnected, UI no longer says Connected', label !== 'still Connected' && /another extension/i.test(shown), `${label}; attacker=${lvl}`);
    }
    await attacker.evaluate(() => globalThis.release());
    await popup.waitForTimeout(500);
    if ((await popupState(popup)) === 'Connected') {
      await popup.click('#primary');
      await waitFor(async () => (await popupState(popup)) !== 'Connected', 'disconnect after takeover test', 15000);
    }
  }

  // 8. Browser killed while connected -> on next start there is no stale proxy.
  await popup.click('#primary');
  await waitFor(async () => (await popupState(popup)) === 'Connected', 'Connected again', 30000);
  await ctx.close(); // closes the native port: helper must exit and take Xray with it
  check('helper + Xray exit with the browser (no orphans)', await waitFor(async () => !(await portOpen(jbHttp)), 'ports closed', 10000).catch(() => false));

  ({ ctx, sw } = await launch());
  context = ctx;
  await new Promise((r) => setTimeout(r, 1500));
  const restarted = await sw.evaluate(() => chrome.proxy.settings.get({}));
  check('no stale proxy after browser restart', restarted.value.mode !== 'fixed_servers', JSON.stringify(restarted.value));
  await ctx.close();
  context = null;
} catch (e) {
  console.error(`\nE2E FAILED: ${e.message}`);
  process.exitCode = 1;
} finally {
  if (context) await context.close().catch(() => undefined);
  server?.stop();
  const un = spawnSync(host, ['uninstall', '--purge', '--target', runtimeDir], { env, encoding: 'utf8' });
  console.log(`uninstall: ${un.status === 0 ? 'ok' : un.stderr}`);
  rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
  const passed = results.filter((r) => r.ok).length;
  console.log(`\n${passed}/${results.length} checks passed`);
}
