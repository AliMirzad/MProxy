// Pure mapping from service-worker state to what the popup shows. Unit-tested.
import type { ApiError, ServerList, ServerSummary } from '../../../shared/protocol/types';
import type { AppState } from './app-state';

export type Tone = 'ok' | 'busy' | 'idle' | 'error';
export type PrimaryAction = 'connect' | 'disconnect' | 'cancel' | 'retry' | 'none';

export interface View {
  label: string;
  tone: Tone;
  detail: string | null;
  action: PrimaryAction;
  /** Short hint shown under an error. */
  hint: string | null;
  /** Server list, import and settings are usable. */
  interactive: boolean;
}

const ERROR_TITLES: Partial<Record<ApiError['code'], string>> = {
  XRAY_FAILED: 'Xray failed',
  XRAY_MISSING: 'Xray is missing',
  XRAY_CONFIG_REJECTED: 'Invalid configuration',
  INVALID_CONFIG: 'Invalid configuration',
  SERVER_UNREACHABLE: 'Server unreachable',
  PORT_UNAVAILABLE: 'Local port unavailable',
  SECURE_STORAGE_UNAVAILABLE: 'Secure storage unavailable',
  SUBSCRIPTION_FAILED: 'Subscription update failed',
};

const ERROR_HINTS: Partial<Record<ApiError['code'], string>> = {
  SERVER_UNREACHABLE: 'Check that the server is online and the configuration is current.',
  XRAY_FAILED: 'Try connecting again. If it keeps failing, reinstall the native runtime.',
  XRAY_MISSING: 'Reinstall the native runtime.',
  XRAY_CONFIG_REJECTED: 'Ask the server operator for an updated link.',
};

export function errorTitle(e: ApiError): string {
  return ERROR_TITLES[e.code] ?? 'Error';
}

export function deriveView(s: AppState): View {
  const r = s.runtime;
  switch (r.kind) {
    case 'starting':
      return { label: 'Starting…', tone: 'busy', detail: null, action: 'none', hint: null, interactive: false };
    case 'missing':
      return {
        label: 'Native runtime missing',
        tone: 'error',
        detail: r.message,
        action: 'retry',
        hint: 'Install the MProxy runtime for this computer, then click Retry.',
        interactive: false,
      };
    case 'forbidden':
      return { label: 'Native runtime not authorized', tone: 'error', detail: r.message, action: 'retry', hint: null, interactive: false };
    case 'incompatible':
      return { label: 'Update required', tone: 'error', detail: r.message, action: 'none', hint: null, interactive: false };
    case 'crashed':
      return {
        label: 'Native runtime stopped',
        tone: 'error',
        detail: r.message,
        action: 'retry',
        hint: r.retryInMs ? `Retrying in ${Math.round(r.retryInMs / 1000)} s…` : null,
        interactive: false,
      };
    case 'ready':
      break;
  }
  const st = s.status;
  if (!st) return { label: 'Starting…', tone: 'busy', detail: null, action: 'none', hint: null, interactive: true };
  if (s.proxyError) {
    return { label: 'Browser proxy blocked', tone: 'error', detail: s.proxyError, action: 'connect', hint: null, interactive: true };
  }
  switch (st.state) {
    case 'connected':
      return { label: 'Connected', tone: 'ok', detail: null, action: 'disconnect', hint: null, interactive: true };
    case 'connecting': {
      const detail = st.phase === 'verifying' ? 'Verifying connection…' : st.phase === 'restarting' ? 'Restarting Xray…' : 'Starting Xray…';
      return { label: 'Connecting', tone: 'busy', detail, action: 'cancel', hint: null, interactive: true };
    }
    case 'disconnecting':
      return { label: 'Disconnecting', tone: 'busy', detail: null, action: 'none', hint: null, interactive: true };
    case 'error': {
      const e = st.error ?? { code: 'INTERNAL', message: 'Unknown error' };
      return { label: errorTitle(e), tone: 'error', detail: e.message, action: 'connect', hint: ERROR_HINTS[e.code] ?? null, interactive: true };
    }
    default:
      return { label: 'Disconnected', tone: 'idle', detail: null, action: 'connect', hint: null, interactive: true };
  }
}

export function protocolLine(s: ServerSummary): string {
  const proto = s.protocol === 'vless' ? 'VLESS' : 'VMess';
  const parts = [proto];
  if (s.security !== 'none') parts.push(s.securityLabel);
  parts.push(s.transportLabel);
  if (s.flow) parts.push('Vision');
  return parts.join(' · ');
}

/** Which server the main selector shows: the active one while connected/connecting, else the selection. */
export function currentServerId(s: AppState, selected: string | null): string | null {
  const st = s.status;
  if (st && (st.state === 'connected' || st.state === 'connecting') && st.serverId) return st.serverId;
  return selected;
}

// ------------------------------------------------------------------ server list filter

/** "all", "manual" (imported by hand: links, JSON, QR) or "sub:<subscription id>". */
export type ServerFilter = string;

export interface FilterOption {
  value: ServerFilter;
  label: string;
}

export function filterOptions(list: ServerList): FilterOption[] {
  const manual = list.servers.filter((s) => !s.subscriptionId).length;
  const opts: FilterOption[] = [{ value: 'all', label: `All servers (${list.servers.length})` }];
  // Offered only when there are hand-added servers; subscriptions are always listed (even with
  // no servers) so they can be chosen and updated.
  if (manual > 0) opts.push({ value: 'manual', label: `Manually added (${manual})` });
  for (const sub of list.subscriptions) {
    const n = list.servers.filter((s) => s.subscriptionId === sub.id).length;
    opts.push({ value: `sub:${sub.id}`, label: `Subscription: ${sub.name} (${n})` });
  }
  return opts;
}

/** Unknown filters (e.g. a deleted subscription) fall back to "all". */
export function normalizeFilter(list: ServerList, f: ServerFilter | null | undefined): ServerFilter {
  if (f === 'manual') return list.servers.some((s) => !s.subscriptionId) ? f : 'all';
  if (f && f.startsWith('sub:') && list.subscriptions.some((s) => `sub:${s.id}` === f)) return f;
  return 'all';
}

export function filterServers(list: ServerList, f: ServerFilter): ServerSummary[] {
  if (f === 'manual') return list.servers.filter((s) => !s.subscriptionId);
  if (f.startsWith('sub:')) {
    const id = f.slice(4);
    return list.servers.filter((s) => s.subscriptionId === id);
  }
  return list.servers;
}
