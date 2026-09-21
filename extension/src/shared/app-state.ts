import type { HelloResult, NativeStatus } from '../../../shared/protocol/types';

/** Availability of the native runtime, as seen by the service worker. */
export type RuntimeState =
  | { kind: 'starting' }
  | { kind: 'ready'; hello: HelloResult }
  | { kind: 'missing'; message: string }
  | { kind: 'forbidden'; message: string }
  | { kind: 'incompatible'; message: string }
  | { kind: 'crashed'; message: string; retryInMs: number | null };

export interface AppState {
  runtime: RuntimeState;
  /** Latest status from the helper (null until the first status arrives). */
  status: NativeStatus | null;
  /** Problem applying the browser proxy (e.g. another extension controls it). */
  proxyError: string | null;
  /** True while the browser is actually routed through the local proxy. */
  browserProxied: boolean;
  extensionVersion: string;
}

export const EXTENSION_PROTOCOL_VERSION = 1;

/** Messages from extension pages (popup) to the service worker. */
export type UiMessage =
  | { type: 'request'; cmd: string; args: Record<string, unknown> }
  | { type: 'retryNative' }
  | { type: 'getState' };

/** Messages pushed from the service worker to connected popups. */
export type SwPush = { type: 'state'; state: AppState };
