// Real implementations of the Controller dependencies on top of chrome.* APIs.
import type { ProxyControl, WebRtcControl } from './controller';

/** Destinations that never go through the tunnel (mirrors native/src/xrayconf.rs PRIVATE_CIDRS). */
export const BYPASS_LIST = [
  '<local>',
  'localhost',
  '127.0.0.0/8',
  '[::1]',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '100.64.0.0/10',
  'fc00::/7',
  'fe80::/10',
];

export function proxyConfig(port: number): chrome.proxy.ProxyConfig {
  return {
    mode: 'fixed_servers',
    rules: {
      singleProxy: { scheme: 'socks5', host: '127.0.0.1', port },
      bypassList: BYPASS_LIST,
    },
  };
}

type LevelOfControl = 'not_controllable' | 'controlled_by_other_extensions' | 'controllable_by_this_extension' | 'controlled_by_this_extension';

export function controlProblem(level: LevelOfControl | string): string | null {
  switch (level) {
    case 'not_controllable':
      return "The browser's proxy settings are managed by policy and cannot be changed by the extension.";
    case 'controlled_by_other_extensions':
      return 'Another extension controls the browser proxy. Disable it, then connect again.';
    default:
      return null;
  }
}

export const chromeProxy: ProxyControl = {
  async set(port) {
    const before = await chrome.proxy.settings.get({ incognito: false });
    const problem = controlProblem(before.levelOfControl);
    if (problem) return problem;
    await chrome.proxy.settings.set({ value: proxyConfig(port), scope: 'regular' });
    const after = await chrome.proxy.settings.get({ incognito: false });
    if (after.levelOfControl !== 'controlled_by_this_extension') {
      return controlProblem(after.levelOfControl) ?? 'Could not apply the browser proxy settings.';
    }
    return null;
  },
  async clear() {
    await chrome.proxy.settings.clear({ scope: 'regular' });
  },
  async controlProblem() {
    const now = await chrome.proxy.settings.get({ incognito: false });
    if (now.levelOfControl === 'controlled_by_this_extension') return null;
    return controlProblem(now.levelOfControl) ?? 'The browser proxy setting is no longer controlled by Private Proxy.';
  },
};

export const chromeWebRtc: WebRtcControl = {
  async apply(protect) {
    // chrome.privacy exists only after the optional "privacy" permission was granted.
    const net = (chrome as unknown as { privacy?: typeof chrome.privacy }).privacy?.network;
    if (!net) return;
    try {
      if (protect) {
        await net.webRTCIPHandlingPolicy.set({ value: 'disable_non_proxied_udp' });
      } else {
        await net.webRTCIPHandlingPolicy.clear({});
      }
    } catch {
      /* not controllable (policy) – nothing we can do */
    }
  },
};

export async function webrtcEnabled(): Promise<boolean> {
  const { webrtcProtection } = await chrome.storage.local.get('webrtcProtection');
  if (webrtcProtection !== true) return false;
  return chrome.permissions.contains({ permissions: ['privacy'] });
}
