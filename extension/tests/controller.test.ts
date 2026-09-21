import { describe, expect, it, beforeEach } from 'vitest';
import { Controller, classifyDisconnect, type Deps, type PortLike } from '../src/background/controller';
import type { NativeStatus } from '../../shared/protocol/types';
import type { AppState } from '../src/shared/app-state';

class FakePort implements PortLike {
  sent: any[] = [];
  private msgL: ((m: unknown) => void)[] = [];
  private discL: (() => void)[] = [];
  disconnected = false;
  onMessage = { addListener: (cb: (m: unknown) => void) => this.msgL.push(cb) };
  onDisconnect = { addListener: (cb: () => void) => this.discL.push(cb) };
  postMessage(m: unknown) {
    this.sent.push(m);
    this.auto?.(m as any);
  }
  disconnect() {
    this.disconnected = true;
  }
  /** Optional auto-responder. */
  auto?: (m: { id: number; cmd: string; args: any }) => void;
  deliver(m: unknown) {
    this.msgL.forEach((l) => l(m));
  }
  kill() {
    this.discL.forEach((l) => l());
  }
}

const hello = { nativeVersion: '1.0.0', protocolVersion: 3, xrayVersion: '26.3.27', xrayAvailable: true, platform: 'windows-x86_64', keyStorage: 'x' };
const jb = { enabled: true, mode: 'direct' as const, socksPort: 10808, httpPort: 10809, issue: null, authRequired: true };
const status = (s: Partial<NativeStatus>): NativeStatus => ({ state: 'disconnected', jetbrains: jb, xrayAvailable: true, ...s });

function setup(opts: { proxyError?: string | null; connectThrows?: boolean; lastError?: string; helloError?: { code: string; message: string } } = {}) {
  let controlProblem: string | null = null;
  let webrtcProblem: string | null = null;
  const ports: FakePort[] = [];
  const log: string[] = [];
  const timers: { cb: () => void; ms: number }[] = [];
  const states: AppState[] = [];
  let lastError = opts.lastError;
  const deps: Deps = {
    connectNative: () => {
      if (opts.connectThrows) throw new Error('boom');
      const p = new FakePort();
      p.auto = (m) => {
        if (m.cmd === 'hello') queueMicrotask(() => p.deliver(opts.helloError ? { id: m.id, ok: false, error: opts.helloError } : { id: m.id, ok: true, result: hello }));
        if (m.cmd === 'getStatus') queueMicrotask(() => p.deliver({ id: m.id, ok: true, result: status({}) }));
      };
      ports.push(p);
      return p;
    },
    lastError: () => lastError,
    proxy: {
      set: async (port) => {
        log.push(`set:${port}`);
        return opts.proxyError ?? null;
      },
      clear: async () => {
        log.push('clear');
      },
      controlProblem: async () => controlProblem,
    },
    webrtc: { apply: async (p) => void log.push(`webrtc:${p}`), problem: async () => webrtcProblem },
    webrtcEnabled: async () => true,
    broadcast: (s) => states.push(s),
    extensionVersion: '1.0.0',
    setTimer: (cb, ms) => {
      const t = { cb, ms };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => {
      const i = timers.indexOf(t as any);
      if (i >= 0) timers.splice(i, 1);
    },
  };
  const c = new Controller(deps);
  return { c, ports, log, timers, states, setLastError: (e: string) => (lastError = e), setControlProblem: (p: string | null) => (controlProblem = p), setWebrtcProblem: (p: string | null) => (webrtcProblem = p) };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe('Controller', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it('clears any stale proxy on start, then says hello', async () => {
    await env.c.start();
    await tick();
    expect(env.log[0]).toBe('clear');
    expect(env.ports[0].sent[0]).toMatchObject({ cmd: 'hello', args: { protocolVersion: 3 } });
    expect(env.c.state.runtime.kind).toBe('ready');
  });

  it('sets the browser proxy only when connected, and clears it on disconnect', async () => {
    await env.c.start();
    await tick();
    env.log.length = 0;
    env.ports[0].deliver({ event: 'status', status: status({ state: 'connecting', phase: 'starting', serverId: 'a' }) });
    await env.c.idle();
    expect(env.log).toEqual([]); // still direct while connecting
    env.ports[0].deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    expect(env.log).toEqual(['set:5555', 'webrtc:true']);
    expect(env.c.state.browserProxied).toBe(true);
    env.ports[0].deliver({ event: 'status', status: status({ state: 'disconnected' }) });
    await env.c.idle();
    expect(env.log.slice(2)).toEqual(['clear', 'webrtc:false']);
    expect(env.c.state.browserProxied).toBe(false);
  });

  it('keeps the proxy during an Xray restart, clears it when the restart fails', async () => {
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    env.log.length = 0;
    p.deliver({ event: 'status', status: status({ state: 'connecting', phase: 'restarting', serverId: 'a' }) });
    await env.c.idle();
    expect(env.log).toEqual([]);
    p.deliver({ event: 'status', status: status({ state: 'error', error: { code: 'XRAY_FAILED', message: 'x' } }) });
    await env.c.idle();
    expect(env.log).toEqual(['clear', 'webrtc:false']);
  });

  it('fails safe when the native host dies while connected', async () => {
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    env.log.length = 0;
    env.setLastError('Native host has exited.');
    p.kill();
    await env.c.idle();
    expect(env.log).toContain('clear');
    expect(env.c.state.browserProxied).toBe(false);
    expect(env.c.state.runtime.kind).toBe('crashed');
    // schedules a reconnect with backoff
    expect(env.timers.some((t) => t.ms === 1000)).toBe(true);
  });

  it('reports a missing runtime without retry loops', async () => {
    const e = setup({ lastError: 'Specified native messaging host not found.' });
    await e.c.start();
    e.ports[0].kill();
    await e.c.idle();
    expect(e.c.state.runtime).toEqual({ kind: 'missing', message: 'Native runtime is not installed.' });
    expect(e.timers.filter((t) => t.ms >= 1000 && t.ms !== 60000)).toHaveLength(0);
  });

  it('when another extension controls the proxy it disconnects the tunnel and reports it', async () => {
    const e = setup({ proxyError: 'Another extension controls the browser proxy.' });
    await e.c.start();
    await tick();
    const p = e.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await e.c.idle();
    expect(e.c.state.proxyError).toMatch(/Another extension/);
    expect(e.c.state.browserProxied).toBe(false);
    expect(p.sent.some((m) => m.cmd === 'disconnect')).toBe(true);
  });

  it('never keeps showing connected after another extension takes over the proxy', async () => {
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    // Our own change (set) fires onChange too: nothing happens while we are in control.
    env.c.proxyControlChanged();
    await env.c.idle();
    expect(env.c.state.browserProxied).toBe(true);
    expect(p.sent.some((m) => m.cmd === 'disconnect')).toBe(false);
    // Another extension takes over.
    env.setControlProblem('Another extension controls the browser proxy.');
    env.log.length = 0;
    env.c.proxyControlChanged();
    await env.c.idle();
    expect(env.c.state.browserProxied).toBe(false);
    expect(env.c.state.proxyError).toMatch(/Another extension.*disconnected/);
    expect(env.log).toEqual(['clear', 'webrtc:false']);
    expect(p.sent.some((m) => m.cmd === 'disconnect')).toBe(true);
  });

  it('disconnects when another extension overrides the WebRTC leak protection', async () => {
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    expect(env.c.state.browserProxied).toBe(true);
    env.setWebrtcProblem('Another extension changed the WebRTC setting, so your real IP address could leak.');
    env.log.length = 0;
    env.c.proxyControlChanged();
    await env.c.idle();
    expect(env.c.state.browserProxied).toBe(false);
    expect(env.c.state.proxyError).toMatch(/WebRTC.*disconnected/);
    expect(env.log).toEqual(['clear', 'webrtc:false']);
    expect(p.sent.some((m) => m.cmd === 'disconnect')).toBe(true);
    expect(env.c.proxyCredentials({ host: '127.0.0.1', port: 5555 })).toBeNull();
  });

  it('refuses to report connected when WebRTC protection cannot be applied', async () => {
    env.setWebrtcProblem('Another extension changed the WebRTC setting, so your real IP address could leak.');
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    expect(env.c.state.browserProxied).toBe(false);
    expect(env.c.state.proxyError).toMatch(/WebRTC/);
    expect(p.sent.some((m) => m.cmd === 'disconnect')).toBe(true);
  });

  it('keeps the browser proxy credentials out of the UI and answers only its own tunnel', async () => {
    await env.c.start();
    await tick();
    const p = env.ports[0];
    p.deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await env.c.idle();
    // Never in the state broadcast to the popup.
    expect(JSON.stringify(env.states.at(-1))).not.toContain('bPass');
    expect(env.c.state.status?.proxy).toEqual({ scheme: 'http', host: '127.0.0.1', port: 5555 });
    // Only 127.0.0.1 and exactly the tunnel port.
    expect(env.c.proxyCredentials({ host: '127.0.0.1', port: 5555 })).toEqual({ username: 'bUser', password: 'bPass' });
    expect(env.c.proxyCredentials({ host: '127.0.0.1', port: 5556 })).toBeNull();
    expect(env.c.proxyCredentials({ host: 'proxy.evil.example', port: 5555 })).toBeNull();
    expect(env.c.proxyCredentials({ host: 'localhost', port: 5555 })).toBeNull();
    // Gone after disconnect.
    p.deliver({ event: 'status', status: status({ state: 'disconnected' }) });
    await env.c.idle();
    expect(env.c.proxyCredentials({ host: '127.0.0.1', port: 5555 })).toBeNull();
  });

  it('does not answer challenges while another extension controls the proxy', async () => {
    const e = setup({ proxyError: 'Another extension controls the browser proxy.' });
    await e.c.start();
    await tick();
    e.ports[0].deliver({ event: 'status', status: status({ state: 'connected', serverId: 'a', proxy: { scheme: 'http', host: '127.0.0.1', port: 5555, username: 'bUser', password: 'bPass' } }) });
    await e.c.idle();
    expect(e.c.proxyCredentials({ host: '127.0.0.1', port: 5555 })).toBeNull();
  });

  it('enforces the command allow-list', async () => {
    await env.c.start();
    await tick();
    const r = await env.c.request('hello', {});
    expect(r.ok).toBe(false);
    const r2 = await env.c.request('exec', { command: 'x' });
    expect(r2).toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } });
    const r3 = await env.c.request('connect', 'not-an-object' as any);
    expect(r3.ok).toBe(false);
    expect(env.ports[0].sent.every((m: any) => m.cmd !== 'exec')).toBe(true);
  });

  it('rejects requests when the runtime is unavailable', async () => {
    const e = setup({ lastError: 'Specified native messaging host not found.' });
    await e.c.start();
    e.ports[0].kill();
    const r = await e.c.request('listServers', {});
    expect(r).toMatchObject({ ok: false, error: { message: 'Native runtime is not installed.' } });
  });

  it('fails pending requests when the host dies', async () => {
    await env.c.start();
    await tick();
    const pending = env.c.request('listServers', {}); // FakePort does not answer listServers
    env.ports[0].kill();
    const r = await pending;
    expect(r.ok).toBe(false);
  });

  it('marks an incompatible helper and closes the port', async () => {
    const e = setup({ helloError: { code: 'INCOMPATIBLE_VERSION', message: 'Update the extension.' } });
    await e.c.start();
    const p = e.ports[0];
    await tick();
    expect(e.c.state.runtime).toEqual({ kind: 'incompatible', message: 'Update the extension.' });
    expect(p.disconnected).toBe(true);
  });

  it('times out requests the helper never answers', async () => {
    await env.c.start();
    await tick();
    const pending = env.c.request('listServers', {});
    const t = env.timers.find((x) => x.ms === 60000)!;
    t.cb();
    const r = await pending;
    expect(r).toMatchObject({ ok: false, error: { message: expect.stringMatching(/did not respond/) } });
  });
});

describe('classifyDisconnect', () => {
  it('maps Chromium error strings', () => {
    expect(classifyDisconnect('Specified native messaging host not found.').kind).toBe('missing');
    expect(classifyDisconnect('Access to the specified native messaging host is forbidden.').kind).toBe('forbidden');
    expect(classifyDisconnect('Native host has exited.').kind).toBe('crashed');
    expect(classifyDisconnect(undefined).kind).toBe('crashed');
  });
});
