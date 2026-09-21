// Local "remote side" for end-to-end tests: an Xray server with VLESS (REALITY+Vision, WS),
// VMess (WS) inbounds, and an HTTP target reachable as `probe.test`, a name that only the
// server's DNS config can resolve. Reaching http://probe.test:<port>/ therefore proves both
// the tunnel and remote DNS resolution.
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { createServer as netServer } from 'node:net';
import { join } from 'node:path';

export const TEST_UUID = '5783a3e7-e373-51cd-8642-c83782b807c5';
export const MARKER = 'PRIVATE-PROXY-E2E-OK';

export function freePort() {
  return new Promise((res) => {
    const s = netServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

export async function startTestServer(xray, workDir) {
  const target = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });
    res.end(`${MARKER} ${req.headers.host}`);
  });
  await new Promise((r) => target.listen(0, '127.0.0.1', r));
  const targetPort = target.address().port;

  const x25519 = execFileSync(xray, ['x25519'], { encoding: 'utf8' });
  const field = (p) => x25519.split('\n').find((l) => l.startsWith(p)).split(':')[1].trim();
  const priv = field('PrivateKey');
  const pub = field('Password');
  execFileSync(xray, ['tls', 'cert', '--domain=tls.test', '--name=tls.test', '--file=srv'], { cwd: workDir });

  const ports = { reality: await freePort(), realityTarget: await freePort(), ws: await freePort(), vmessWs: await freePort() };
  const crt = join(workDir, 'srv.crt');
  const key = join(workDir, 'srv.key');
  const cfg = {
    log: { loglevel: 'warning' },
    dns: { hosts: { 'probe.test': '127.0.0.1' } },
    inbounds: [
      { listen: '127.0.0.1', port: ports.ws, protocol: 'vless', settings: { clients: [{ id: TEST_UUID }], decryption: 'none' }, streamSettings: { network: 'ws', wsSettings: { path: '/ws' } } },
      { listen: '127.0.0.1', port: ports.vmessWs, protocol: 'vmess', settings: { clients: [{ id: TEST_UUID }] }, streamSettings: { network: 'ws', wsSettings: { path: '/vm' } } },
      {
        listen: '127.0.0.1', port: ports.realityTarget, protocol: 'vless', settings: { clients: [{ id: '00000000-0000-0000-0000-000000000001' }], decryption: 'none' },
        streamSettings: { network: 'raw', security: 'tls', tlsSettings: { alpn: ['h2', 'http/1.1'], certificates: [{ certificateFile: crt, keyFile: key }] } },
      },
      {
        listen: '127.0.0.1', port: ports.reality, protocol: 'vless', settings: { clients: [{ id: TEST_UUID, flow: 'xtls-rprx-vision' }], decryption: 'none' },
        streamSettings: { network: 'raw', security: 'reality', realitySettings: { target: `127.0.0.1:${ports.realityTarget}`, serverNames: ['tls.test'], privateKey: priv, shortIds: ['ab12'] } },
      },
    ],
    outbounds: [{ protocol: 'freedom', settings: { domainStrategy: 'UseIP' } }],
  };
  const proc = spawn(xray, ['run', '-c', 'stdin:', '-format', 'json'], { stdio: ['pipe', 'ignore', 'ignore'] });
  proc.stdin.end(JSON.stringify(cfg));
  await new Promise((r) => setTimeout(r, 800));

  const vmess = Buffer.from(JSON.stringify({ v: '2', ps: 'E2E VMess WS', add: '127.0.0.1', port: String(ports.vmessWs), id: TEST_UUID, aid: '0', scy: 'auto', net: 'ws', path: '/vm', tls: '' })).toString('base64');
  const links = {
    reality: `vless://${TEST_UUID}@127.0.0.1:${ports.reality}?type=tcp&security=reality&sni=tls.test&fp=chrome&pbk=${pub}&sid=ab12&flow=xtls-rprx-vision#E2E%20Reality`,
    vlessWs: `vless://${TEST_UUID}@127.0.0.1:${ports.ws}?type=ws&path=%2Fws&security=none#E2E%20VLESS%20WS`,
    vmess: `vmess://${vmess}`,
  };
  return {
    targetPort,
    links,
    probeUrl: `http://probe.test:${targetPort}/`,
    stop() {
      proc.kill();
      target.close();
    },
  };
}
