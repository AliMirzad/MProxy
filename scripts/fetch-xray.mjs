#!/usr/bin/env node
// Downloads the pinned Xray-core release for one or more platforms and verifies
// it against the SHA-256 recorded in native/xray/xray.lock.json.
//
// Usage: node scripts/fetch-xray.mjs [platform ...]
//   platform: windows-x64 | windows-arm64 | macos-x64 | macos-arm64 | host | all
// Output:   native/xray/dist/<platform>/{xray[.exe],LICENSE,geoip.dat,geosite.dat}
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const lock = JSON.parse(readFileSync(join(root, 'native/xray/xray.lock.json'), 'utf8'));

function hostPlatform() {
  const os = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : null;
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : null;
  if (!os || !arch) throw new Error(`Unsupported host ${process.platform}/${process.arch}`);
  return `${os}-${arch}`;
}

async function fetchOne(platform) {
  const asset = lock.assets[platform];
  if (!asset) throw new Error(`Unknown platform "${platform}"`);
  const outDir = join(root, 'native/xray/dist', platform);
  const exe = platform.startsWith('windows') ? 'xray.exe' : 'xray';
  const stamp = join(outDir, '.version');
  if (existsSync(join(outDir, exe)) && existsSync(stamp) && readFileSync(stamp, 'utf8').trim() === `${lock.version} ${asset.sha256}`) {
    console.log(`[fetch-xray] ${platform}: ${lock.version} already present`);
    return;
  }
  const url = `${lock.source}/${lock.version}/${asset.file}`;
  console.log(`[fetch-xray] downloading ${url}`);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const digest = createHash('sha256').update(buf).digest('hex');
  if (digest !== asset.sha256) {
    throw new Error(`SHA-256 mismatch for ${asset.file}: expected ${asset.sha256}, got ${digest}`);
  }
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const zipPath = join(outDir, asset.file);
  writeFileSync(zipPath, buf);
  // bsdtar (Windows 10+ and macOS) extracts zip archives natively.
  // On Windows, call System32 tar explicitly: Git Bash puts GNU tar (no zip support) first on PATH.
  const tar = process.platform === 'win32' ? join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  execFileSync(tar, ['-xf', asset.file], { cwd: outDir, stdio: 'inherit' });
  rmSync(zipPath);
  for (const f of readdirSync(outDir)) {
    if (![exe, 'LICENSE', 'geoip.dat', 'geosite.dat'].includes(f)) rmSync(join(outDir, f), { recursive: true, force: true });
  }
  if (!existsSync(join(outDir, exe))) throw new Error(`${exe} missing from archive`);
  writeFileSync(stamp, `${lock.version} ${asset.sha256}\n`);
  console.log(`[fetch-xray] ${platform}: OK (${lock.version})`);
}

let targets = process.argv.slice(2);
if (targets.length === 0) targets = ['host'];
if (targets.includes('all')) targets = Object.keys(lock.assets);
targets = targets.map((t) => (t === 'host' ? hostPlatform() : t));
for (const t of targets) await fetchOne(t);
