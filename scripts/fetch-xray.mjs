#!/usr/bin/env node
// Downloads the pinned Xray-core release for one or more platforms from the official GitHub
// release (never a mirror) and verifies two pinned SHA-256 values from
// native/xray/xray.lock.json:
//   * sha256        - the release zip (matches the upstream "<asset>.dgst" SHA2-256 line)
//   * binarySha256  - the extracted xray executable (also compiled into the helper, which
//                     re-verifies the installed binary before every launch)
//
// Usage: node scripts/fetch-xray.mjs [--record] [platform ...]
//   platform: windows-x64 | windows-arm64 | macos-x64 | macos-arm64 | host | all
//   --record: after the zip hash verifies, write missing binarySha256 values into the lock
//             (maintainers only, when bumping the Xray version)
// Output:   native/xray/dist/<platform>/{xray[.exe],LICENSE}
//   geoip.dat/geosite.dat are deliberately not kept: generated configs never reference them.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const lockPath = join(root, 'native/xray/xray.lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
const record = process.argv.includes('--record');
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

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
  if (asset.binarySha256 && existsSync(join(outDir, exe)) && existsSync(stamp) && readFileSync(stamp, 'utf8').trim() === `${lock.version} ${asset.sha256}`) {
    const have = sha256(readFileSync(join(outDir, exe)));
    if (have !== asset.binarySha256) throw new Error(`${platform}: extracted ${exe} does not match binarySha256 (expected ${asset.binarySha256}, got ${have}); delete native/xray/dist and re-run`);
    console.log(`[fetch-xray] ${platform}: ${lock.version} already present (verified)`);
    return;
  }
  const url = `${lock.source}/${lock.version}/${asset.file}`;
  console.log(`[fetch-xray] downloading ${url}`);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const digest = sha256(buf);
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
    if (![exe, 'LICENSE'].includes(f)) rmSync(join(outDir, f), { recursive: true, force: true });
  }
  if (!existsSync(join(outDir, exe))) throw new Error(`${exe} missing from archive`);
  const bin = sha256(readFileSync(join(outDir, exe)));
  if (!asset.binarySha256) {
    if (!record) throw new Error(`${platform}: no binarySha256 pinned in xray.lock.json (maintainers: re-run with --record)`);
    asset.binarySha256 = bin;
    writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\n');
    console.log(`[fetch-xray] ${platform}: recorded binarySha256 ${bin}`);
  } else if (bin !== asset.binarySha256) {
    rmSync(outDir, { recursive: true, force: true });
    throw new Error(`${platform}: extracted ${exe} does not match binarySha256 (expected ${asset.binarySha256}, got ${bin})`);
  }
  writeFileSync(stamp, `${lock.version} ${asset.sha256}\n`);
  console.log(`[fetch-xray] ${platform}: OK (${lock.version})`);
}

let targets = process.argv.slice(2).filter((a) => a !== '--record');
if (targets.length === 0) targets = ['host'];
if (targets.includes('all')) targets = Object.keys(lock.assets);
targets = targets.map((t) => (t === 'host' ? hostPlatform() : t));
for (const t of targets) await fetchOne(t);
