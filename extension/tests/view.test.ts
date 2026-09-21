import { describe, expect, it } from 'vitest';
import { deriveView, protocolLine, currentServerId, filterOptions, filterServers, normalizeFilter } from '../src/shared/view';
import { BYPASS_LIST, controlProblem, proxyConfig } from '../src/background/chrome-adapters';
import type { AppState } from '../src/shared/app-state';
import type { NativeStatus, ServerSummary } from '../../shared/protocol/types';

const hello = { nativeVersion: '1.0.0', protocolVersion: 1, xrayVersion: '26.3.27', xrayAvailable: true, platform: 'x', keyStorage: 'x' };
const jb = { enabled: true, mode: 'direct' as const, socksPort: 10808, httpPort: 10809, issue: null, authRequired: true };
const app = (status: Partial<NativeStatus> | null, extra: Partial<AppState> = {}): AppState => ({
  runtime: { kind: 'ready', hello },
  status: status ? { state: 'disconnected', jetbrains: jb, xrayAvailable: true, ...status } : null,
  proxyError: null,
  browserProxied: false,
  extensionVersion: '1.0.0',
  ...extra,
});

describe('deriveView covers every UI state', () => {
  it('Disconnected', () => expect(deriveView(app({}))).toMatchObject({ label: 'Disconnected', action: 'connect', tone: 'idle' }));
  it('Connecting', () => expect(deriveView(app({ state: 'connecting', phase: 'verifying' }))).toMatchObject({ label: 'Connecting', detail: 'Verifying connection…', action: 'cancel' }));
  it('Connected', () => expect(deriveView(app({ state: 'connected' }))).toMatchObject({ label: 'Connected', tone: 'ok', action: 'disconnect' }));
  it('Disconnecting', () => expect(deriveView(app({ state: 'disconnecting' }))).toMatchObject({ label: 'Disconnecting', action: 'none' }));
  it('Xray Failed', () =>
    expect(deriveView(app({ state: 'error', error: { code: 'XRAY_FAILED', message: 'Xray stopped unexpectedly' } }))).toMatchObject({ label: 'Xray failed', tone: 'error', action: 'connect' }));
  it('Invalid Configuration', () =>
    expect(deriveView(app({ state: 'error', error: { code: 'XRAY_CONFIG_REJECTED', message: 'bad' } }))).toMatchObject({ label: 'Invalid configuration' }));
  it('Server unreachable', () =>
    expect(deriveView(app({ state: 'error', error: { code: 'SERVER_UNREACHABLE', message: 'x' } })).hint).toMatch(/server is online/));
  it('Native Runtime Missing', () => {
    const v = deriveView(app(null, { runtime: { kind: 'missing', message: 'Native runtime is not installed.' } }));
    expect(v).toMatchObject({ label: 'Native runtime missing', detail: 'Native runtime is not installed.', action: 'retry', interactive: false });
  });
  it('Incompatible', () => expect(deriveView(app(null, { runtime: { kind: 'incompatible', message: 'Update' } }))).toMatchObject({ label: 'Update required' }));
  it('Crashed with retry countdown', () =>
    expect(deriveView(app(null, { runtime: { kind: 'crashed', message: 'x', retryInMs: 3000 } })).hint).toBe('Retrying in 3 s…'));
  it('Proxy blocked by another extension', () =>
    expect(deriveView(app({ state: 'disconnected' }, { proxyError: 'Another extension controls the browser proxy.' }))).toMatchObject({ label: 'Browser proxy blocked', tone: 'error' }));
});

describe('helpers', () => {
  const s: ServerSummary = {
    id: '1', name: 'DE', protocol: 'vless', address: 'a', port: 443, transport: 'raw', transportLabel: 'TCP',
    security: 'reality', securityLabel: 'REALITY', flow: 'xtls-rprx-vision', subscriptionId: null,
  };
  it('protocol line', () => expect(protocolLine(s)).toBe('VLESS · REALITY · TCP · Vision'));
  it('current server follows the active tunnel', () => {
    expect(currentServerId(app({ state: 'connected', serverId: 'x' }), 'y')).toBe('x');
    expect(currentServerId(app({ state: 'disconnected' }), 'y')).toBe('y');
  });
  it('proxy config is loopback SOCKS5 with private bypass', () => {
    const c = proxyConfig(4321);
    expect(c.mode).toBe('fixed_servers');
    expect(c.rules?.singleProxy).toEqual({ scheme: 'socks5', host: '127.0.0.1', port: 4321 });
    expect(BYPASS_LIST).toContain('<local>');
    expect(BYPASS_LIST).toContain('192.168.0.0/16');
  });
  it('control problems', () => {
    expect(controlProblem('controlled_by_other_extensions')).toMatch(/Another extension/);
    expect(controlProblem('not_controllable')).toMatch(/policy/);
    expect(controlProblem('controllable_by_this_extension')).toBeNull();
  });
});

describe('server filter', () => {
  const srv = (id: string, subscriptionId: string | null) => ({
    id, name: id, protocol: 'vless' as const, address: 'a', port: 1, transport: 'raw', transportLabel: 'TCP',
    security: 'tls', securityLabel: 'TLS', flow: null, subscriptionId,
  });
  const list = {
    servers: [srv('m1', null), srv('w1', 's1'), srv('w2', 's1'), srv('h1', 's2')],
    subscriptions: [
      { id: 's1', name: 'Work', host: 'w', lastUpdated: null, lastError: null, serverCount: 2 },
      { id: 's2', name: 'Home', host: 'h', lastUpdated: null, lastError: null, serverCount: 1 },
    ],
    selectedServerId: 'm1',
  };

  it('offers all, manual and one entry per subscription with counts', () => {
    expect(filterOptions(list).map((o) => o.label)).toEqual([
      'All servers (4)', 'Manually added (1)', 'Subscription: Work (2)', 'Subscription: Home (1)',
    ]);
  });

  it('filters by origin', () => {
    expect(filterServers(list, 'all').map((s) => s.id)).toEqual(['m1', 'w1', 'w2', 'h1']);
    expect(filterServers(list, 'manual').map((s) => s.id)).toEqual(['m1']);
    expect(filterServers(list, 'sub:s1').map((s) => s.id)).toEqual(['w1', 'w2']);
  });

  it('falls back to all for unknown or deleted subscriptions', () => {
    expect(normalizeFilter(list, 'sub:gone')).toBe('all');
    expect(normalizeFilter(list, undefined)).toBe('all');
    expect(normalizeFilter(list, 'manual')).toBe('manual');
    expect(normalizeFilter(list, 'sub:s2')).toBe('sub:s2');
  });
});
