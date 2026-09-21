// Extension <-> native helper protocol, version 1.
// Mirrors native/src/protocol.rs and native/src/service.rs. See PROTOCOL.md.

export const PROTOCOL_VERSION = 3;
export const HOST_NAME = 'com.privateproxy.host';

export type ErrorCode =
  | 'INVALID_REQUEST'
  | 'INCOMPATIBLE_VERSION'
  | 'NOT_FOUND'
  | 'INVALID_CONFIG'
  | 'XRAY_MISSING'
  | 'XRAY_FAILED'
  | 'XRAY_CONFIG_REJECTED'
  | 'PORT_UNAVAILABLE'
  | 'SERVER_UNREACHABLE'
  | 'SUBSCRIPTION_FAILED'
  | 'STORE_ERROR'
  | 'SECURE_STORAGE_UNAVAILABLE'
  | 'BUSY'
  | 'INTERNAL';

export interface ApiError {
  code: ErrorCode;
  message: string;
}

export interface JetbrainsStatus {
  enabled: boolean;
  mode: 'tunnel' | 'direct' | 'off';
  socksPort: number | null;
  httpPort: number | null;
  issue: string | null;
  /** The IDE endpoint requires the credentials from getIdeCredentials. */
  authRequired: boolean;
}

export type ConnState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';

export interface NativeStatus {
  state: ConnState;
  phase?: 'starting' | 'verifying' | 'restarting';
  serverId?: string;
  /** Browser proxy while connected. `username`/`password` are per-connection credentials that only the
   *  service worker uses (to answer the proxy's 407 challenge); they are stripped before any UI sees the status. */
  proxy?: { scheme: 'http'; host: string; port: number; username?: string; password?: string };
  error?: ApiError;
  since?: number;
  jetbrains: JetbrainsStatus;
  xrayAvailable: boolean;
}

export interface HelloResult {
  nativeVersion: string;
  protocolVersion: number;
  xrayVersion: string | null;
  xrayAvailable: boolean;
  platform: string;
  keyStorage: string;
}

export interface ServerSummary {
  id: string;
  name: string;
  protocol: 'vless' | 'vmess';
  address: string;
  port: number;
  transport: string;
  transportLabel: string;
  security: string;
  securityLabel: string;
  flow: string | null;
  subscriptionId: string | null;
}

export interface SubscriptionSummary {
  id: string;
  name: string;
  host: string;
  lastUpdated: number | null;
  lastError: string | null;
  serverCount: number;
}

export interface ServerList {
  servers: ServerSummary[];
  subscriptions: SubscriptionSummary[];
  selectedServerId: string | null;
}

export interface ImportResult {
  added: number;
  updated: number;
  serverIds: string[];
  errors: { entry: number; message: string }[];
  rejected: number;
  unsupported: number;
  warnings: string[];
}

export interface SubscriptionResult {
  subscriptionId: string;
  added: number;
  updated: number;
  removed: number;
  rejected: number;
  unsupported: number;
}

export interface Settings {
  jetbrainsEnabled: boolean;
  jetbrainsSocksPort: number;
  jetbrainsHttpPort: number;
  passthroughWhenDisconnected: boolean;
  debugLogging: boolean;
  /** Allow subscription URLs on private networks (company-internal servers). Default off. */
  allowPrivateSubscriptionHosts: boolean;
  /** Require a username/password on the IDE endpoint. Default on. */
  ideAuth: boolean;
}

/** Commands the UI may send, with their argument types. */
export interface Commands {
  getStatus: Record<string, never>;
  listServers: Record<string, never>;
  importText: { text: string; source: 'paste' | 'qr' | 'file' };
  addSubscription: { name: string; url: string };
  updateSubscription: { id: string };
  deleteSubscription: { id: string; deleteServers: boolean };
  renameServer: { id: string; name: string };
  deleteServer: { id: string };
  selectServer: { id: string };
  connect: { serverId: string };
  disconnect: Record<string, never>;
  getSettings: Record<string, never>;
  setSettings: Partial<Settings>;
  getDiagnostics: Record<string, never>;
  getIdeCredentials: Record<string, never>;
  regenerateIdeCredentials: Record<string, never>;
  resetAll: { confirm: true };
}

export type CommandName = keyof Commands;

/** Allow-list enforced by the service worker before forwarding UI requests. */
export const UI_COMMANDS: readonly CommandName[] = [
  'getStatus',
  'listServers',
  'importText',
  'addSubscription',
  'updateSubscription',
  'deleteSubscription',
  'renameServer',
  'deleteServer',
  'selectServer',
  'connect',
  'disconnect',
  'getSettings',
  'setSettings',
  'getDiagnostics',
  'getIdeCredentials',
  'regenerateIdeCredentials',
  'resetAll',
] as const;

export type NativeResponse<T = unknown> = { id: number; ok: true; result: T } | { id: number; ok: false; error: ApiError };
export type NativeEvent = { event: 'status'; status: NativeStatus } | { event: 'protocolError'; error: ApiError };

export interface IdeCredentials {
  username: string;
  password: string;
  required: boolean;
  reconnectRequired: boolean;
}
