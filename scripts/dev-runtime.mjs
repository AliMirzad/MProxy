#!/usr/bin/env node
// Installs (or removes) the locally built native helper + pinned Xray as the per-user runtime,
// exactly like the release installer does, so a dev build of the extension can talk to it.
//
//   node scripts/dev-runtime.mjs install [--release]
//   node scripts/dev-runtime.mjs uninstall [--purge]
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostCandidates } from './target-dir.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const [cmd, ...rest] = process.argv.slice(2);
const win = process.platform === 'win32';
const plat = `${win ? 'windows' : 'macos'}-${process.arch === 'arm64' ? 'arm64' : 'x64'}`;
const profile = rest.includes('--release') ? 'release' : 'debug';
const exe = win ? 'private-proxy-host.exe' : 'private-proxy-host';
const host = hostCandidates(profile).find(existsSync);

if (cmd === 'install') {
  if (!host) throw new Error(`build first: node scripts/cargo.mjs build${profile === 'release' ? ' --release' : ''}`);
  const xray = join(root, 'native/xray/dist', plat);
  if (!existsSync(xray)) throw new Error('fetch Xray first: node scripts/fetch-xray.mjs');
  const r = spawnSync(host, ['install', '--source', xray], { stdio: 'inherit' });
  process.exit(r.status ?? 1);
} else if (cmd === 'uninstall') {
  const installed = join(
    win ? join(process.env.LOCALAPPDATA, 'Programs', 'PrivateProxy') : join(process.env.HOME, 'Library/Application Support/PrivateProxy/runtime'),
    exe,
  );
  const bin = host ?? installed;
  const r = spawnSync(bin, ['uninstall', ...rest.filter((a) => a === '--purge')], { stdio: 'inherit' });
  process.exit(r.status ?? 1);
} else {
  console.error('usage: node scripts/dev-runtime.mjs install [--release] | uninstall [--purge]');
  process.exit(2);
}
