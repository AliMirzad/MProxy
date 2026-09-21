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
import { existsSync, mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
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

function findHost() {
  for (const p of ['release', 'debug']) {
    for (const t of ['', 'x86_64-pc-windows-gnullvm/']) {
      const f = join(root, 'native/target', t, p, win ? 'private-proxy-host.exe' : 'private-proxy-host');
      if (existsSync(f)) return f;
    }
  }
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
function viaHttpProxy(proxyPort, url) {
  return new Promise((res) => {
    const u = new URL(url);
    const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`GET ${url} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\n\r\n`));
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
const env = { ...process.env, PRIVATE_PROXY_DATA_DIR: dataDir };
let server;
let context;

async function launch() {
  const ctx = await chromium.launchPersistentContext(profileDir, {
    executablePath: browserPath,
    headless: !headed,
    env,
    args: [`--disable-extensions-except=${extDist}`, `--load-extension=${extDist}`, '--no-first-run', '--no-default-browser-check', '--disable-features=BraveRewards'],
  });
  const sw = ctx.serviceWorkers().find((w) => w.url().includes(extId)) ?? (await ctx.waitForEvent('serviceworker', { timeout: 15000 }).catch(() => null));
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

  // JetBrains ports (avoid touching real 10808/10809).
  await popup.click('#nav-settings');
  await popup.fill('#jb-http', String(jbHttp));
  await popup.fill('#jb-socks', String(jbSocks));
  await popup.click('#jb-save');
  await waitFor(async () => (await popup.textContent('#settings-result'))?.includes('Saved'), 'settings saved');
  check('IDE endpoint (direct passthrough) listening while disconnected', await waitFor(() => portOpen(jbHttp), 'jb port', 10000));
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
  const names = await popup.$$eval('#server-list .name', (els) => els.map((e) => e.textContent));
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
  const badge = await sw.evaluate(() => chrome.action.getBadgeText({}));
  check('toolbar badge shows ON', badge === 'ON');

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
  await shot(popup, '05-settings');
  await popup.click('#nav-back');

  // 7. Disconnect.
  await popup.click('#primary');
  await waitFor(async () => (await popupState(popup)) === 'Disconnected', 'Disconnected', 15000);
  const after = await sw.evaluate(() => chrome.proxy.settings.get({}));
  check('disconnect restores direct browser networking', after.value.mode !== 'fixed_servers' && after.levelOfControl === 'controllable_by_this_extension', JSON.stringify(after));
  check('probe.test unreachable after disconnect', !(await browserReachesProbe()));
  const direct = await viaHttpProxy(jbHttp, `http://127.0.0.1:${server.targetPort}/`);
  check('JetBrains endpoint keeps working (direct) after disconnect', direct.includes(MARKER));
  const directProbe = await viaHttpProxy(jbHttp, server.probeUrl);
  check('JetBrains endpoint is really direct after disconnect (probe.test unresolvable)', !directProbe.includes(MARKER));

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
