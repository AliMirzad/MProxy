#!/usr/bin/env node
// ADVERSARIAL TEST of the packaged Windows runtime (test-only; never shipped).
//
//   node scripts/package.mjs --skip-tests      (build dist/ first)
//   node scripts/test-package-adversarial.mjs
//
// 1. DLL planting against the PACKAGED helper and Xray: real DLLs that record every load
//    (DllMain) are planted under ~50 non-KnownDLL names next to both executables, in a folder
//    whose name is hostile. A control loader proves the planted DLLs are picked up by an
//    unhardened program.
//    - release helper (from the zip): --version, and it must not load anything planted
//    - debug helper (same link flags and startup hardening) through a full native-messaging
//      session in a temp data dir: Credential Manager, settings, import, Xray launch (restricted),
//      HTTPS subscription fetch (Schannel, DNS), diagnostics, reset.
// 2. Install.cmd command injection through the extraction folder name (fixed script vs. the
//    previous line, which interpolated the folder into PowerShell code).
// Nothing here touches the user's browsers, registration or MProxy data.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostCandidates } from './target-dir.mjs';

if (process.platform !== 'win32') {
  console.log('ENVIRONMENT UNAVAILABLE: Windows-only test');
  process.exit(0);
}
const root = join(fileURLToPath(import.meta.url), '../..');
const sys32 = join(process.env.SystemRoot || 'C:\\Windows', 'System32');
const version = JSON.parse(readFileSync(join(root, 'extension/package.json'), 'utf8')).version;
const zip = join(root, 'dist', `PrivateProxy-runtime-windows-x64-${version}.zip`);
if (!existsSync(zip)) throw new Error(`${zip} missing: run node scripts/package.mjs --skip-tests`);
const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` - ${detail}` : ''}`);
};

// Outside %TEMP%: endpoint security (seen: Kaspersky) removes unsigned executables extracted there.
const workBase = process.env.PP_ADV_WORKDIR || join(homedir(), '.private-proxy-target');
mkdirSync(workBase, { recursive: true });
const tmp = mkdtempSync(join(workBase, 'pp-pkg-adv-'));
const markerDir = join(tmp, 'markers');
mkdirSync(markerDir);
// Low-integrity Xray may not be able to write the marker; then the DLL kills the process (exit 0xDEAD),
// which the session detects as an Xray failure.
spawnSync(join(sys32, 'icacls.exe'), [markerDir, '/grant', '*S-1-1-0:(OI)(CI)M', '/setintegritylevel', '(OI)(CI)L'], { stdio: 'ignore' });
const hits = () => readdirSync(markerDir).flatMap((f) => readFileSync(join(markerDir, f), 'utf8').split(/\r?\n/).filter(Boolean));

// ---------------------------------------------------------------- toolchain for the marker DLL
const llvm = [join(homedir(), '.private-proxy-tools'), 'C:\\llvm-mingw']
  .flatMap((b) => (existsSync(b) ? readdirSync(b).map((d) => join(b, d, 'bin')).concat(join(b, 'bin')) : []))
  .find((b) => existsSync(join(b, 'x86_64-w64-mingw32-clang.exe')));
if (!llvm) {
  console.log('ENVIRONMENT UNAVAILABLE: llvm-mingw not found (needed to build the marker DLL)');
  process.exit(0);
}
const cc = join(llvm, 'x86_64-w64-mingw32-clang.exe');
const markerFile = join(markerDir, 'hits.txt').replace(/\\/g, '\\\\');
writeFileSync(join(tmp, 'plant.c'), `#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
  if (reason == DLL_PROCESS_ATTACH) {
    char mod[MAX_PATH], line[2 * MAX_PATH + 64], exe[MAX_PATH];
    GetModuleFileNameA(h, mod, MAX_PATH);
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    wsprintfA(line, "%s loaded by %s\\r\\n", mod, exe);
    HANDLE f = CreateFileA("${markerFile}", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, 0, 0);
    if (f == INVALID_HANDLE_VALUE) ExitProcess(0xDEAD);
    DWORD w; WriteFile(f, line, lstrlenA(line), &w, 0); CloseHandle(f);
  }
  return TRUE;
}
`);
writeFileSync(join(tmp, 'control.c'), `#include <windows.h>
int main(void) { return LoadLibraryA("version.dll") ? 0 : 1; }
`);
const build = (args) => {
  const r = spawnSync(cc, args, { cwd: tmp, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
};
build(['-shared', '-O1', '-o', 'plant.dll', 'plant.c']);
build(['-O1', '-o', 'control.exe', 'control.c']);

const PLANT = ['version', 'winhttp', 'secur32', 'sspicli', 'schannel', 'ncrypt', 'ncryptsslp', 'dpapi', 'cryptbase', 'cryptsp', 'rsaenh', 'bcrypt',
  'bcryptprimitives', 'crypt32', 'cryptnet', 'wintrust', 'credui', 'vaultcli', 'dnsapi', 'iphlpapi', 'winnsi', 'mswsock', 'rasadhlp', 'fwpuclnt',
  'netapi32', 'netutils', 'srvcli', 'wkscli', 'samcli', 'logoncli', 'userenv', 'profapi', 'wldp', 'dbghelp', 'dbgcore', 'powrprof', 'umpdc', 'uxtheme',
  'propsys', 'winmm', 'wtsapi32', 'mpr', 'gpapi', 'webio', 'kerberos', 'msv1_0', 'ntmarta', 'dsreg', 'windows.storage', 'wininet', 'urlmon', 'iertutil',
  'napinsp', 'pnrpnsp', 'wshbth', 'nlaapi', 'winrnr', 'dhcpcsvc', 'dhcpcsvc6', 'ondemandconnroutehelper', 'uiautomationcore', 'textinputframework'];
const plant = (dir) => {
  for (const n of PLANT) cpSync(join(tmp, 'plant.dll'), join(dir, `${n}.dll`));
};

// ---------------------------------------------------------------- control: the harness detects loads
{
  const d = join(tmp, 'control');
  mkdirSync(d);
  cpSync(join(tmp, 'control.exe'), join(d, 'control.exe'));
  plant(d);
  spawnSync(join(d, 'control.exe'), [], { cwd: d });
  check('control: an unhardened program loads a planted version.dll (harness works)', hits().some((h) => h.includes('control.exe')), hits().join(' | '));
  rmSync(join(markerDir, 'hits.txt'), { force: true });
}

// ---------------------------------------------------------------- the packaged runtime in a hostile folder
const hostile = join(tmp, "Downloads & x';New-Item pwned-by-folder-name;#");
mkdirSync(hostile);
spawnSync(join(sys32, 'tar.exe'), ['-xf', zip, '-C', hostile], { stdio: 'inherit' });
const pkg = join(hostile, readdirSync(hostile).find((d) => d.startsWith('PrivateProxy-runtime')));
plant(pkg);
plant(join(pkg, 'xray'));
{
  // A freshly extracted unsigned executable is briefly locked by the antivirus scan: retry.
  let r;
  for (let i = 0; i < 30; i++) {
    r = spawnSync(join(pkg, 'private-proxy-host.exe'), ['--version'], { cwd: pkg, encoding: 'utf8' });
    if (!r.error) break;
    await new Promise((res) => setTimeout(res, 1000));
  }
  if (r.error) console.log('  spawn error: ' + r.error.message);
  if (r.error && !existsSync(join(pkg, 'private-proxy-host.exe'))) {
    console.log('ENVIRONMENT UNAVAILABLE  packaged helper execution: the unsigned release binary was removed by endpoint security after extraction (see docs/adversarial-testing.md); verified statically and with the debug build instead');
  } else {
    check('packaged helper runs next to ~60 planted DLLs', r.status === 0 && /private-proxy-host/.test(r.stdout), `${r.status} ${(r.stdout || '').trim()}`);
  }
  const x = spawnSync(join(pkg, 'xray', 'xray.exe'), ['version'], { cwd: join(pkg, 'xray'), encoding: 'utf8' });
  console.log(`  (info) packaged Xray started directly next to planted DLLs: exit ${x.status}`);
}

// ---------------------------------------------------------------- static: release helper PE hardening
{
  const entry = spawnSync(join(sys32, 'tar.exe'), ['-tf', zip], { encoding: 'utf8' }).stdout.split(/\r?\n/).find((l) => l.endsWith('/private-proxy-host.exe'));
  const pe = spawnSync(join(sys32, 'tar.exe'), ['-xOf', zip, entry], { maxBuffer: 64 << 20 }).stdout;
  const peOff = pe.readUInt32LE(0x3c);
  const nsec = pe.readUInt16LE(peOff + 6);
  const optSize = pe.readUInt16LE(peOff + 20);
  const opt = peOff + 24;
  const is64 = pe.readUInt16LE(opt) === 0x20b;
  const dd = opt + (is64 ? 112 : 96);
  const lcRva = pe.readUInt32LE(dd + 10 * 8);
  const secs = opt + optSize;
  let lcOff = -1;
  for (let i = 0; i < nsec; i++) {
    const sh = secs + i * 40;
    const va = pe.readUInt32LE(sh + 12), vsize = pe.readUInt32LE(sh + 8), raw = pe.readUInt32LE(sh + 20);
    if (lcRva >= va && lcRva < va + Math.max(vsize, pe.readUInt32LE(sh + 16))) lcOff = raw + (lcRva - va);
  }
  const dlf = lcOff >= 0 && is64 ? pe.readUInt16LE(lcOff + 0x4e) : -1;
  const dllChars = pe.readUInt16LE(opt + 70);
  check('release helper (from the zip): DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32', dlf === 0x800, `0x${dlf.toString(16)}`);
  check('release helper imports SetDefaultDllDirectories (runtime search order)', pe.includes('SetDefaultDllDirectories'));
  check('release helper: ASLR, high-entropy ASLR and DEP enabled', (dllChars & 0x0040) !== 0 && (dllChars & 0x0100) !== 0 && (dllChars & 0x0020) !== 0, `DllCharacteristics=0x${dllChars.toString(16)}`);
  const manifest = JSON.parse(spawnSync(join(sys32, 'tar.exe'), ['-xOf', zip, entry.replace('private-proxy-host.exe', 'RELEASE-MANIFEST.json')], { encoding: 'utf8' }).stdout);
  const sha = createHash('sha256').update(pe).digest('hex');
  check('release manifest checksum matches the helper in the zip', manifest.components.find((c) => c.file === 'private-proxy-host.exe')?.sha256 === sha, sha);
}

// ---------------------------------------------------------------- full session: debug helper, same hardening
const debugHost = hostCandidates('debug').find(existsSync);
if (!debugHost) {
  check('full-session DLL planting (debug helper)', false, 'NOT TESTED: build the debug helper (node scripts/cargo.mjs build)');
} else {
  const d = join(hostile, 'session');
  mkdirSync(join(d, 'xray'), { recursive: true });
  cpSync(debugHost, join(d, 'private-proxy-host.exe'));
  cpSync(join(pkg, 'xray', 'xray.exe'), join(d, 'xray', 'xray.exe'));
  plant(d);
  plant(join(d, 'xray'));
  const data = join(tmp, 'data');
  const env = { ...process.env, PRIVATE_PROXY_TEST_MODE: '1', PRIVATE_PROXY_DATA_DIR: data, PRIVATE_PROXY_XRAY: join(d, 'xray', 'xray.exe') };
  const extId = readFileSync(join(root, 'shared/extension-id.txt'), 'utf8').trim();
  const child = spawn(join(d, 'private-proxy-host.exe'), [`chrome-extension://${extId}/`], { cwd: d, env, stdio: ['pipe', 'pipe', 'inherit'] });
  let buf = Buffer.alloc(0);
  const waiters = new Map();
  const events = [];
  child.stdout.on('data', (c) => {
    buf = Buffer.concat([buf, c]);
    while (buf.length >= 4) {
      const n = buf.readUInt32LE(0);
      if (buf.length < 4 + n) break;
      const m = JSON.parse(buf.subarray(4, 4 + n).toString('utf8'));
      buf = buf.subarray(4 + n);
      if (m.id && waiters.has(m.id)) waiters.get(m.id)(m);
      else events.push(m);
    }
  });
  let id = 0;
  const call = (cmd, args = {}, ms = 30000) =>
    new Promise((res) => {
      const i = ++id;
      waiters.set(i, res);
      const body = Buffer.from(JSON.stringify({ id: i, cmd, args }));
      const len = Buffer.alloc(4);
      len.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([len, body]));
      setTimeout(() => res({ ok: false, error: { message: 'timeout' } }), ms);
    });
  const hello = await call('hello', { protocolVersion: 3, extensionVersion: 'adversarial-test' });
  const creds = await call('getIdeCredentials');
  const imp = await call('importText', { text: 'vless://5783a3e7-e373-51cd-8642-c83782b807c5@203.0.113.1:443?security=tls&sni=example.com&type=tcp#dead', source: 'paste' });
  const sid = imp.result?.serverIds?.[0];
  await call('connect', { serverId: sid });
  await new Promise((r) => setTimeout(r, 4000)); // Xray starts (restricted) and the probe runs
  const diag = await call('getDiagnostics');
  const status = await call('getStatus');
  await call('disconnect');
  const sub = await call('addSubscription', { name: 'tls', url: 'https://example.com/' }, 40000); // Schannel + DNS
  await call('resetAll', { confirm: true });
  child.stdin.end();
  await new Promise((r) => child.once('exit', r));
  const xrayStarted = !!diag.result?.xrayPid || /Xray/i.test(JSON.stringify(status)) || events.some((e) => JSON.stringify(e).includes('verifying'));
  console.log(`  session: hello=${hello.ok} creds=${creds.ok} import=${imp.ok} xrayStarted=${xrayStarted} subscription=${sub.ok ? 'ok' : sub.error?.message}`);
  console.log(`  status events: ${events.map((e) => e.status?.state + (e.status?.phase ? '/' + e.status.phase : '') + (e.status?.error ? ':' + e.status.error.message : '')).join(', ')}`);
  const lastErr = events.map((e) => e.status?.error?.message).filter(Boolean).join(' | ');
  check('full session ran (Credential Manager, import, Xray launch, HTTPS fetch)', hello.ok && creds.ok && imp.ok && xrayStarted, lastErr);
  check('Xray was not killed by a planted DLL (no 0xDEAD exit)', !/57005|0xdead|exit code 0x0000dead/i.test(lastErr), lastErr);
  check('no planted DLL loaded by the helper or Xray during the session', hits().length === 0, hits().join(' | '));
}

// ---------------------------------------------------------------- Install.cmd folder-name injection
{
  const fixed = readFileSync(join(pkg, 'Install.cmd'), 'utf8').replace(/^"%~dp0private-proxy-host\.exe" install.*$/m, 'echo INSTALL-STEP-REACHED');
  // The line shipped before this review (with its intended absolute path), for comparison.
  const previous = fixed
    .replace(/^set "PP_INSTALL_DIR=.*\r?\n/m, '')
    .replace(/-LiteralPath \$env:PP_INSTALL_DIR/, "-LiteralPath '%~dp0'");
  for (const [label, script, expectInjection] of [['fixed Install.cmd', fixed, false], ['previous Install.cmd line', previous, true]]) {
    const f = join(hostile, 'Install-test.cmd');
    writeFileSync(f, script);
    rmSync(join(hostile, 'pwned-by-folder-name'), { force: true });
    // Exactly how Explorer starts a double-clicked .cmd: cmd /c ""<path>" " (verbatim).
    const r = spawnSync(join(sys32, 'cmd.exe'), ['/d', '/c', `""${f}" "`], { cwd: hostile, encoding: 'utf8', windowsVerbatimArguments: true });
    const injected = existsSync(join(hostile, 'pwned-by-folder-name'));
    if (expectInjection) check(`${label}: the same folder name DOES inject (proves the test detects it)`, injected);
    else check(`${label}: folder name cannot inject PowerShell code`, !injected && r.stdout.includes('INSTALL-STEP-REACHED'), r.stdout.trim().split(/\r?\n/).pop());
  }
}

rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exitCode = failed ? 1 : 0;
