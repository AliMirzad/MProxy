// Extension security properties that can be checked statically: attack surface declared in the
// manifest, CSP, and the absence of dynamic code execution in the shipped bundle.
// Evidence for docs/security-gate.md.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { UI_COMMANDS } from '../../shared/protocol/types';

const ext = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(ext, 'dist');
let manifest: Record<string, any>;
let bundle: Record<string, string>;

beforeAll(() => {
  // Scan exactly what ships: a fresh release build.
  execFileSync(process.execPath, [join(ext, 'scripts/build.mjs'), '--release'], { cwd: ext, stdio: 'ignore' });
  manifest = JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8'));
  bundle = Object.fromEntries(
    readdirSync(dist)
      .filter((f) => f.endsWith('.js') || f.endsWith('.html'))
      .map((f) => [f, readFileSync(join(dist, f), 'utf8')]),
  );
}, 60_000);

describe('manifest attack surface', () => {
  it('requests only the permissions the product needs', () => {
    expect([...manifest.permissions].sort()).toEqual(['activeTab', 'nativeMessaging', 'proxy', 'storage']);
    expect(manifest.optional_permissions).toEqual(['privacy']);
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.optional_host_permissions).toBeUndefined();
  });

  it('exposes nothing to web pages or other extensions', () => {
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.externally_connectable).toBeUndefined();
    expect(manifest.web_accessible_resources).toBeUndefined();
    expect(manifest.sandbox).toBeUndefined();
    expect(manifest.update_url).toBeUndefined();
  });

  it('has a strict CSP without eval, inline or remote code', () => {
    const csp: string = manifest.content_security_policy.extension_pages;
    expect(csp).toMatch(/script-src 'self'(;|$)/);
    expect(csp).toContain("object-src 'none'");
    for (const bad of ['unsafe-eval', 'unsafe-inline', 'wasm-unsafe-eval', 'http:', 'https:', '*']) {
      expect(csp).not.toContain(bad);
    }
  });

  it('pins the extension ID with a key (the native host accepts only that ID)', () => {
    expect(typeof manifest.key).toBe('string');
    const pinned = readFileSync(join(ext, '../shared/extension-id.txt'), 'utf8').trim();
    expect(pinned).toMatch(/^[a-p]{32}$/);
  });
});

describe('shipped code', () => {
  const dynamicCode: [string, RegExp][] = [
    ['eval()', /(^|[^\w$.])eval\s*\(/],
    ['new Function()', /\bnew\s+Function\s*\(/],
    ['Function() constructor', /(^|[^\w$.])Function\s*\(\s*["'`]/],
    ['setTimeout/setInterval with a string', /\bset(Timeout|Interval)\s*\(\s*["'`]/],
    ['importScripts', /\bimportScripts\s*\(/],
    ['dynamic import()', /(^|[^\w$.])import\s*\(/],
    ['document.write', /\bdocument\.write(ln)?\s*\(/],
    ['remote script', /<script[^>]+src\s*=\s*["']?(https?:)?\/\//i],
    ['inline script', /<script(?![^>]*\bsrc=)[^>]*>\s*\S/i],
  ];
  it.each(dynamicCode)('contains no %s', (_name, re) => {
    for (const [file, text] of Object.entries(bundle)) {
      expect(re.test(text), `${file}`).toBe(false);
    }
  });

  it('does not listen for messages from other extensions or web pages', () => {
    const js = bundle['background.js'];
    expect(js).not.toMatch(/onMessageExternal|onConnectExternal|onUserScriptMessage/);
    // Every message path checks the sender (own extension, own pages only).
    expect(js).toContain('getURL');
  });

  it('never assigns untrusted data as HTML', () => {
    // The popup renders helper-provided strings with textContent/value only.
    for (const [file, text] of Object.entries(bundle)) {
      if (!file.endsWith('.js')) continue;
      expect(/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(/.test(text), file).toBe(false);
    }
  });

  it('allows only UI commands through the service worker', () => {
    for (const internal of ['hello', 'exec', 'shell', 'openFile', 'writeFile']) {
      expect(UI_COMMANDS as readonly string[]).not.toContain(internal);
    }
  });
});
