// EXPERIMENTAL: does a Chromium-based app (the class Electron apps like ChatGPT/Claude/Cursor
// belong to) work through the authenticated local inbound when told only `--proxy-server`?
// Throwaway profile; prints one JSON line.   node chromium-check.mjs <proxyPort|none> <url>
import { chromium } from '../../extension/node_modules/playwright-core/index.mjs';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [port, url] = process.argv.slice(2);
const browser = [
  `${process.env.ProgramFiles}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
  `${process.env.LOCALAPPDATA}\\Chromium\\Application\\chrome.exe`,
].find((p) => p && existsSync(p));
if (!browser) {
  console.log(JSON.stringify({ result: 'ENVIRONMENT UNAVAILABLE: no Chromium browser' }));
  process.exit(0);
}
const dir = mkdtempSync(join(tmpdir(), 'poc-chromium-'));
const args = ['--no-first-run'];
if (port !== 'none') args.push(`--proxy-server=http://127.0.0.1:${port}`);
const ctx = await chromium.launchPersistentContext(dir, { executablePath: browser, headless: true, args });
let result;
try {
  const page = await ctx.newPage();
  const r = await page.goto(url, { timeout: 10000 });
  result = { status: r?.status() ?? null, body: ((await page.textContent('body')) ?? '').slice(0, 60) };
} catch (e) {
  result = { error: e.message.split('\n')[0] };
} finally {
  await ctx.close();
  rmSync(dir, { recursive: true, force: true });
}
console.log(JSON.stringify({ browser: browser.split('\\').pop(), proxyFlag: port !== 'none', ...result }));
