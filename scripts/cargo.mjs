#!/usr/bin/env node
// Runs cargo for the native helper with a working toolchain.
//
// Windows: uses the MSVC toolchain when Visual Studio Build Tools are installed; otherwise
// the `x86_64-pc-windows-gnullvm` toolchain with llvm-mingw (set LLVM_MINGW=<dir> or put
// llvm-mingw's bin on PATH). macOS: the default toolchain.
//
// Usage: node scripts/cargo.mjs <cargo args...>     e.g.  node scripts/cargo.mjs test
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const env = { ...process.env };
let toolchain = [];

function hasMsvcLinker() {
  try {
    const vswhere = join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
    if (!existsSync(vswhere)) return false;
    const out = execSync(`"${vswhere}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`, { encoding: 'utf8' });
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

function findLlvmMingw() {
  const candidates = [];
  if (process.env.LLVM_MINGW) candidates.push(process.env.LLVM_MINGW);
  for (const base of [join(process.env.TEMP || '', 'claude-tools'), join(root, '.tools'), 'C:\\llvm-mingw']) {
    if (existsSync(base)) {
      for (const d of readdirSync(base)) if (d.startsWith('llvm-mingw')) candidates.push(join(base, d));
      if (base.endsWith('llvm-mingw')) candidates.push(base);
    }
  }
  return candidates.map((c) => (c.endsWith('bin') ? c : join(c, 'bin'))).find((b) => existsSync(join(b, 'x86_64-w64-mingw32-clang.exe')));
}

if (process.platform === 'win32' && !env.PRIVATE_PROXY_FORCE_DEFAULT_TOOLCHAIN) {
  if (!hasMsvcLinker()) {
    const bin = findLlvmMingw();
    if (!bin) {
      console.error('No MSVC Build Tools and no llvm-mingw found. Install "Visual Studio Build Tools (C++)" or download llvm-mingw and set LLVM_MINGW.');
      process.exit(1);
    }
    env.PATH = bin + delimiter + env.PATH;
    toolchain = ['+stable-x86_64-pc-windows-gnullvm'];
  }
}

// Run inside native/ so native/.cargo/config.toml (static CRT/libunwind) applies.
const r = spawnSync('cargo', [...toolchain, ...args], { stdio: 'inherit', env, shell: false, cwd: join(root, 'native') });
process.exit(r.status ?? 1);
