#!/usr/bin/env node
// Builds release artifacts into dist/:
//   PrivateProxy-extension-<ver>.zip                 unpacked extension (Load unpacked)
//   PrivateProxy-runtime-windows-x64-<ver>.zip       on Windows
//   PrivateProxy-runtime-macos-<arch>-<ver>.tar.gz   on macOS (+ .pkg with --pkg)
//
//   node scripts/package.mjs [--target macos-arm64|macos-x64] [--pkg] [--skip-tests]
//
// The native helper must be built on the target OS (it links OS frameworks for secure
// storage), so Windows packages are built on Windows and macOS packages on macOS
// (see .github/workflows/build.yml for CI builds of both).
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostCandidates } from './target-dir.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const argVal = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const version = JSON.parse(readFileSync(join(root, 'extension/package.json'), 'utf8')).version;
const cargoVersion = /^version = "(.+)"/m.exec(readFileSync(join(root, 'native/Cargo.toml'), 'utf8'))[1];
if (version !== cargoVersion) throw new Error(`version mismatch: extension ${version} vs native ${cargoVersion}`);

const win = process.platform === 'win32';
const hostArch = process.arch === 'arm64' ? 'arm64' : 'x64';
const platform = argVal('--target') ?? `${win ? 'windows' : 'macos'}-${hostArch}`;
const rustTarget = { 'macos-arm64': 'aarch64-apple-darwin', 'macos-x64': 'x86_64-apple-darwin' }[platform];
const dist = join(root, 'dist');
mkdirSync(dist, { recursive: true });

const run = (cmd, a, opts = {}) => {
  console.log(`$ ${cmd} ${a.join(' ')}`);
  const r = spawnSync(cmd, a, { stdio: 'inherit', cwd: root, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} failed`);
};
const node = (script, a = [], cwd = root) => run(process.execPath, [join(root, script), ...a], { cwd });

// 1. Tests (unless skipped)
if (!args.includes('--skip-tests')) {
  node('scripts/cargo.mjs', ['test', '--release']);
  run(win ? 'npx.cmd' : 'npx', ['vitest', 'run'], { cwd: join(root, 'extension'), shell: win });
}

// 2. Extension
node('extension/scripts/build.mjs', ['--release'], join(root, 'extension'));
const extZip = join(dist, `PrivateProxy-extension-${version}.zip`);
rmSync(extZip, { force: true });
zip(join(root, 'extension/dist'), extZip);

// 3. Xray + native helper
node('scripts/fetch-xray.mjs', [platform]);
const cargoArgs = ['build', '--release', ...(rustTarget ? ['--target', rustTarget] : [])];
node('scripts/cargo.mjs', cargoArgs);
const exe = win ? 'private-proxy-host.exe' : 'private-proxy-host';
const candidates = hostCandidates('release', rustTarget);
const hostBin = candidates.find(existsSync);
if (!hostBin) throw new Error('release binary not found');

// 4. Stage runtime bundle
const name = `PrivateProxy-runtime-${platform}-${version}`;
const stage = join(dist, name);
rmSync(stage, { recursive: true, force: true });
mkdirSync(join(stage, 'xray'), { recursive: true });
cpSync(hostBin, join(stage, exe));
const xdir = join(root, 'native/xray/dist', platform);
cpSync(join(xdir, win ? 'xray.exe' : 'xray'), join(stage, 'xray', win ? 'xray.exe' : 'xray'));
cpSync(join(xdir, 'LICENSE'), join(stage, 'xray', 'LICENSE'));
cpSync(join(root, 'LICENSES'), join(stage, 'LICENSES'), { recursive: true });
const inst = join(root, 'installers', win ? 'windows' : 'macos');
for (const f of readdirSync(inst)) if (f !== 'build-pkg.sh') cpSync(join(inst, f), join(stage, f));
if (!win) for (const f of ['install.sh', 'uninstall.sh', exe, 'xray/xray']) chmodSync(join(stage, f), 0o755);
writeFileSync(
  join(stage, 'VERSION.txt'),
  `Private Proxy runtime ${version}\nprotocol ${readProtocolVersion()}\nxray ${JSON.parse(readFileSync(join(root, 'native/xray/xray.lock.json'), 'utf8')).version}\nextension id ${readFileSync(join(root, 'shared/extension-id.txt'), 'utf8').trim()}\n`,
);

// 5. Archive
if (win) {
  const out = join(dist, `${name}.zip`);
  rmSync(out, { force: true });
  zip(stage, out, name);
  console.log(`\n${out}\n${extZip}`);
} else {
  const out = join(dist, `${name}.tar.gz`);
  execFileSync('tar', ['-czf', out, '-C', dist, name]);
  console.log(`\n${out}\n${extZip}`);
  if (args.includes('--pkg')) {
    run('sh', [join(root, 'installers/macos/build-pkg.sh'), stage, version, join(dist, `${name}.pkg`)]);
  }
}

function readProtocolVersion() {
  return /PROTOCOL_VERSION: u32 = (\d+)/.exec(readFileSync(join(root, 'native/src/lib.rs'), 'utf8'))[1];
}

/** Zip a directory. `prefix` puts the contents inside a top-level folder. */
function zip(dir, out, prefix) {
  const tar = win ? join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  if (prefix) execFileSync(tar, ['-a', '-cf', out, '-C', dirname(dir), prefix]);
  else execFileSync(tar, ['-a', '-cf', out, '-C', dir, '.']);
}
