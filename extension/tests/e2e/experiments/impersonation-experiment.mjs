#!/usr/bin/env node
// EXPERIMENT (security review, item "extension impersonation"): an unpacked extension that copies
// MProxy's public manifest `key` gets MProxy's extension ID. What can it do with the native host?
//
//   node extension/tests/e2e/experiments/impersonation-experiment.mjs [--browser <path>]
//
// Scenarios (each with a throwaway profile, a temp runtime install and a temp data directory):
//   A. impersonator loaded alone (developer mode / --load-extension)
//   B. impersonator loaded together with the real MProxy (same ID twice)
// The user's browser profile and real MProxy data are never touched.
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostCandidates } from '../../../../scripts/target-dir.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../..');
const args = process.argv.slice(2);
const win = process.platform === 'win32';
const plat = `${win ? 'windows' : 'macos'}-${process.arch === 'arm64' ? 'arm64' : 'x64'}`;
const xrayDir = join(root, 'native/xray/dist', plat);
const extId = readFileSync(join(root, 'shared/extension-id.txt'), 'utf8').trim();
const extDist = join(root, 'extension/dist');
const host = hostCandidates('debug').find(existsSync);
if (!host) throw new Error('build the helper first');
const browserPath = args.includes('--browser')
  ? args[args.indexOf('--browser') + 1]
  : [`${process.env.ProgramFiles}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`, `${process.env.LOCALAPPDATA}\\Chromium\\Application\\chrome.exe`].find(existsSync);
if (!existsSync(join(extDist, 'manifest.json'))) spawnSync(process.execPath, [join(root, 'extension/scripts/build.mjs')], { stdio: 'ignore' });

const tmp = mkdtempSync(join(tmpdir(), 'pp-imp-'));
const env = { ...process.env, PRIVATE_PROXY_TEST_MODE: '1', PRIVATE_PROXY_DATA_DIR: join(tmp, 'data') };
const runtimeDir = join(tmp, 'runtime');
const results = {};
try {
  const inst = spawnSync(host, ['install', '--source', xrayDir, '--target', runtimeDir, '--all-browsers'], { env, encoding: 'utf8' });
  if (inst.status !== 0) throw new Error('install failed: ' + inst.stderr);

  // The impersonator: MProxy's public key (it is in every copy of the extension), attacker code.
  const imp = join(tmp, 'impersonator');
  cpSync(join(root, 'extension/tests/fixtures/impersonator'), imp, { recursive: true });
  const key = JSON.parse(readFileSync(join(extDist, 'manifest.json'), 'utf8')).key;
  writeFileSync(join(imp, 'manifest.json'), JSON.stringify({ manifest_version: 3, name: 'IMPERSONATOR (test fixture)', version: '9.9.9', key, permissions: ['nativeMessaging'], background: { service_worker: 'sw.js' } }));

  for (const [label, dirs] of [['A_alone', [imp]], ['B_with_real_extension', [extDist, imp]], ['C_real_first_then_impersonator_reversed', [imp, extDist]]]) {
    const ctx = await chromium.launchPersistentContext(join(tmp, 'profile-' + label), {
      executablePath: browserPath, headless: true, env,
      args: [`--disable-extensions-except=${dirs.join(',')}`, `--load-extension=${dirs.join(',')}`, '--no-first-run'],
    });
    try {
      const deadline = Date.now() + 10000;
      while (!ctx.serviceWorkers().length && Date.now() < deadline) await ctx.waitForEvent('serviceworker', { timeout: 2000 }).catch(() => null);
      await new Promise((r) => setTimeout(r, 1000));
      const workers = ctx.serviceWorkers().map((w) => w.url());
      const sw = ctx.serviceWorkers().find((w) => w.url().includes(extId));
      const isImpersonator = sw ? await sw.evaluate(() => typeof globalThis.steal === 'function') : false;
      results[label] = { workers, loadedWithMProxyId: isImpersonator ? 'impersonator' : sw ? 'real MProxy' : 'none' };
      if (isImpersonator) results[label].attack = await sw.evaluate(() => globalThis.steal());
    } finally {
      await ctx.close();
    }
  }
} finally {
  spawnSync(host, ['uninstall', '--purge', '--target', runtimeDir], { env });
  rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
}
console.log(JSON.stringify(results, null, 2));
