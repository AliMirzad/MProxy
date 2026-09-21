#!/usr/bin/env node
// EXPERIMENT (security review): can an MV3 extension route the browser through an HTTP proxy that
// REQUIRES a password, answering the proxy's 407 challenge itself, and with which permissions?
// Uses a throwaway profile; touches nothing else.
//
//   node extension/tests/e2e/experiments/proxy-auth-experiment.mjs [--host-permissions]
import { chromium } from 'playwright-core';
import http from 'node:http';
import net from 'node:net';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const withHostPerms = process.argv.includes('--host-permissions');
const USER = 'u', PASS = 'p4ss';
const expected = 'Basic ' + Buffer.from(`${USER}:${PASS}`).toString('base64');

// Target web server, reachable only as http://probe.test/ through the proxy.
const target = http.createServer((q, r) => r.end('TARGET-OK')).listen(0, '127.0.0.1');
await new Promise((r) => target.once('listening', r));
let challenges = 0, authorized = 0, unauthorized = 0;
// Minimal forward proxy with Basic auth (absolute-URI requests and CONNECT).
const proxy = http.createServer((q, r) => {
  if (q.headers['proxy-authorization'] !== expected) {
    challenges++;
    r.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="mproxy"' });
    return r.end();
  }
  authorized++;
  const u = new URL(q.url);
  const up = http.request({ host: '127.0.0.1', port: target.address().port, path: u.pathname, method: q.method, headers: q.headers }, (ur) => {
    r.writeHead(ur.statusCode, ur.headers);
    ur.pipe(r);
  });
  q.pipe(up);
});
proxy.on('connect', (q, sock) => {
  if (q.headers['proxy-authorization'] !== expected) {
    unauthorized++;
    sock.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="mproxy"\r\n\r\n');
    return;
  }
  sock.end('HTTP/1.1 502 no tls target\r\n\r\n');
});
proxy.listen(0, '127.0.0.1');
await new Promise((r) => proxy.once('listening', r));

const tmp = mkdtempSync(join(tmpdir(), 'pp-exp-'));
const ext = join(tmp, 'ext');
mkdirSync(ext);
writeFileSync(join(ext, 'manifest.json'), JSON.stringify({
  manifest_version: 3, name: 'proxy-auth-experiment', version: '1.0',
  permissions: ['proxy', 'webRequest', 'webRequestAuthProvider'],
  ...(withHostPerms ? { host_permissions: ['<all_urls>'] } : {}),
  background: { service_worker: 'sw.js' },
}));
writeFileSync(join(ext, 'sw.js'), `
let answered = 0;
chrome.webRequest.onAuthRequired.addListener(
  (d, cb) => { if (d.isProxy) { answered++; cb({ authCredentials: { username: ${JSON.stringify(USER)}, password: ${JSON.stringify(PASS)} } }); } else cb({}); },
  { urls: ['<all_urls>'] }, ['asyncBlocking']);
globalThis.setup = (port) => chrome.proxy.settings.set({ value: { mode: 'fixed_servers', rules: { singleProxy: { scheme: 'http', host: '127.0.0.1', port } } }, scope: 'regular' });
globalThis.answered = () => answered;
`);
const browser = process.env.BRAVE || 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe';
const ctx = await chromium.launchPersistentContext(join(tmp, 'profile'), {
  executablePath: browser, headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-first-run'],
});
try {
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
  await sw.evaluate((p) => globalThis.setup(p), proxy.address().port);
  const page = await ctx.newPage();
  let body = '';
  try {
    await page.goto('http://probe.test/', { timeout: 10000 });
    body = (await page.textContent('body')) ?? '';
  } catch (e) {
    body = 'ERROR ' + e.message.split('\n')[0];
  }
  const answered = await sw.evaluate(() => globalThis.answered());
  console.log(JSON.stringify({ hostPermissions: withHostPerms, pageBody: body, proxyChallenges: challenges, proxyAuthorized: authorized, extensionAnswered: answered }));
} finally {
  await ctx.close();
  proxy.close();
  target.close();
  rmSync(tmp, { recursive: true, force: true });
}
