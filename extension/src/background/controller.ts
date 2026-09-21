// The service worker's brain. All browser APIs are injected (see chrome-adapters.ts), so the
// logic here is unit-tested with fakes (tests/controller.test.ts).
//
// Invariants:
//  * The browser proxy is set ONLY while the helper reports `connected` with a proxy port.
//  * On any other state, on helper exit, on service-worker start, the proxy is cleared
//    (fail-open to direct: there is intentionally no kill switch in V1).
//  * UI requests are forwarded only if the command is in UI_COMMANDS.
//  * The UI never says "connected" while our proxy setting is not in effect: if another
//    extension or a policy takes over the browser proxy, the tunnel is disconnected and the
//    reason is shown (proxyControlChanged).

import { HOST_NAME, UI_COMMANDS, type ApiError, type CommandName, type HelloResult, type NativeEvent, type NativeResponse, type NativeStatus } from '../../../shared/protocol/types';
import { EXTENSION_PROTOCOL_VERSION, type AppState, type RuntimeState } from '../shared/app-state';

export interface PortLike {
  postMessage(msg: unknown): void;
  disconnect(): void;
  onMessage: { addListener(cb: (msg: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
}

export interface ProxyControl {
  /** Route the browser through 127.0.0.1:port (SOCKS5). Resolves to an error message if we could not take control. */
  set(port: number): Promise<string | null>;
  /** Remove our proxy setting (browser goes direct). */
  clear(): Promise<void>;
  /** Null if our setting is the one in effect, otherwise why not. */
  controlProblem(): Promise<string | null>;
}

export interface WebRtcControl {
  /** Apply (true) or restore (false) the WebRTC leak protection; no-op if not permitted. */
  apply(protect: boolean): Promise<void>;
  /** Null if the leak protection is in effect, otherwise why not (e.g. another extension overrode it). */
  problem(): Promise<string | null>;
}

export interface Deps {
  connectNative(host: string): PortLike;
  /** Error text of the last native disconnect (chrome.runtime.lastError). */
  lastError(): string | undefined;
  proxy: ProxyControl;
  webrtc: WebRtcControl;
  webrtcEnabled(): Promise<boolean>;
  broadcast(state: AppState): void;
  extensionVersion: string;
  setTimer(cb: () => void, ms: number): unknown;
  clearTimer(t: unknown): void;
  requestTimeoutMs?: number;
}

type Pending = { resolve: (r: NativeResponse) => void; timer: unknown };

const RETRY_DELAYS = [1000, 3000, 10000, 30000];

export function classifyDisconnect(err: string | undefined): RuntimeState {
  const e = err ?? '';
  if (/not found/i.test(e)) {
    return { kind: 'missing', message: 'Native runtime is not installed.' };
  }
  if (/forbidden/i.test(e)) {
    return { kind: 'forbidden', message: 'The native runtime is installed for a different extension ID. Reinstall the runtime.' };
  }
  return { kind: 'crashed', message: 'The native runtime stopped unexpectedly.', retryInMs: null };
}

export class Controller {
  state: AppState;
  private port: PortLike | null = null;
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private retryIndex = 0;
  private retryTimer: unknown = null;
  private proxyChain: Promise<void> = Promise.resolve();
  private generation = 0;
  /** Credentials of the browser proxy for the current connection (memory only, never broadcast). */
  private proxyAuth: { port: number; username: string; password: string } | null = null;

  constructor(private deps: Deps) {
    this.state = { runtime: { kind: 'starting' }, status: null, proxyError: null, browserProxied: false, extensionVersion: deps.extensionVersion };
  }

  /** Called on every service-worker start. */
  async start(): Promise<void> {
    // A fresh service worker never owns a live tunnel (the helper dies with the old port),
    // so any proxy setting left from before is stale.
    await this.enqueueProxy(async () => {
      await this.deps.proxy.clear();
      this.state.browserProxied = false;
    });
    this.connect();
  }

  private emit() {
    this.deps.broadcast(structuredClone(this.state));
  }

  private setRuntime(r: RuntimeState) {
    this.state.runtime = r;
    this.emit();
  }

  connect(): void {
    if (this.port) return;
    if (this.retryTimer) {
      this.deps.clearTimer(this.retryTimer);
      this.retryTimer = null;
    }
    const gen = ++this.generation;
    this.setRuntime({ kind: 'starting' });
    let port: PortLike;
    try {
      port = this.deps.connectNative(HOST_NAME);
    } catch (e) {
      this.onDisconnect(gen, String(e));
      return;
    }
    this.port = port;
    port.onMessage.addListener((m) => this.onMessage(m));
    port.onDisconnect.addListener(() => this.onDisconnect(gen, this.deps.lastError()));
    this.send('hello', { protocolVersion: EXTENSION_PROTOCOL_VERSION, extensionVersion: this.deps.extensionVersion }).then((r) => {
      if (gen !== this.generation) return;
      if (r.ok) {
        this.retryIndex = 0;
        this.setRuntime({ kind: 'ready', hello: r.result as HelloResult });
        void this.send('getStatus', {}).then((s) => s.ok && this.onStatus(s.result as NativeStatus));
      } else if (r.error.code === 'INCOMPATIBLE_VERSION') {
        this.setRuntime({ kind: 'incompatible', message: r.error.message });
        this.dropPort();
      }
    });
  }

  /** User asked to retry (e.g. popup opened while the runtime was missing). */
  retry(): void {
    this.retryIndex = 0;
    this.connect();
  }

  private dropPort() {
    const p = this.port;
    this.port = null;
    this.generation++;
    try {
      p?.disconnect();
    } catch {
      /* already gone */
    }
    this.failPending({ code: 'INTERNAL', message: 'Native runtime disconnected' });
  }

  private failPending(error: ApiError) {
    for (const [id, p] of this.pending) {
      this.deps.clearTimer(p.timer);
      p.resolve({ id, ok: false, error });
    }
    this.pending.clear();
  }

  private onDisconnect(gen: number, err: string | undefined) {
    if (gen !== this.generation) return;
    this.proxyAuth = null;
    this.generation++; // late responses from the dead port must not change state
    this.port = null;
    this.failPending({ code: 'INTERNAL', message: 'Native runtime is not available' });
    // Fail safe: the helper (and Xray) are gone, so never leave the browser pointing at a dead proxy.
    void this.enqueueProxy(async () => {
      await this.deps.proxy.clear();
      await this.deps.webrtc.apply(false);
      this.state.browserProxied = false;
    });
    this.state.status = null;
    let r = classifyDisconnect(err);
    if (r.kind === 'crashed') {
      const delay = RETRY_DELAYS[Math.min(this.retryIndex, RETRY_DELAYS.length - 1)];
      this.retryIndex++;
      r = { ...r, retryInMs: delay };
      this.retryTimer = this.deps.setTimer(() => {
        this.retryTimer = null;
        this.connect();
      }, delay);
    }
    this.setRuntime(r);
  }

  private onMessage(raw: unknown) {
    const m = raw as NativeResponse & NativeEvent;
    if (typeof m !== 'object' || m === null) return;
    if ('id' in m && typeof m.id === 'number') {
      const p = this.pending.get(m.id);
      if (p) {
        this.pending.delete(m.id);
        this.deps.clearTimer(p.timer);
        p.resolve(m as NativeResponse);
      }
      return;
    }
    if ('event' in m && m.event === 'status') {
      this.onStatus((m as { status: NativeStatus }).status);
    }
  }

  private send(cmd: string, args: unknown, timeoutMs = this.deps.requestTimeoutMs ?? 60000): Promise<NativeResponse> {
    return new Promise((resolve) => {
      if (!this.port) {
        resolve({ id: 0, ok: false, error: { code: 'INTERNAL', message: 'Native runtime is not available' } });
        return;
      }
      const id = this.nextId++;
      const timer = this.deps.setTimer(() => {
        this.pending.delete(id);
        resolve({ id, ok: false, error: { code: 'INTERNAL', message: 'The native runtime did not respond in time' } });
      }, timeoutMs);
      this.pending.set(id, { resolve, timer });
      try {
        this.port.postMessage({ id, cmd, args });
      } catch (e) {
        this.pending.delete(id);
        this.deps.clearTimer(timer);
        resolve({ id, ok: false, error: { code: 'INTERNAL', message: String(e) } });
      }
    });
  }

  /** Entry point for UI requests. Enforces the command allow-list. */
  async request(cmd: string, args: unknown): Promise<NativeResponse> {
    if (!(UI_COMMANDS as readonly string[]).includes(cmd)) {
      return { id: 0, ok: false, error: { code: 'INVALID_REQUEST', message: 'Unknown command' } };
    }
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      return { id: 0, ok: false, error: { code: 'INVALID_REQUEST', message: 'Invalid arguments' } };
    }
    if (this.state.runtime.kind !== 'ready') {
      return { id: 0, ok: false, error: { code: 'INTERNAL', message: runtimeMessage(this.state.runtime) } };
    }
    const r = await this.send(cmd as CommandName, args);
    if (r.ok && (cmd === 'connect' || cmd === 'disconnect' || cmd === 'getStatus')) {
      this.onStatus(r.result as NativeStatus);
    }
    return r;
  }

  private enqueueProxy(op: () => Promise<void>): Promise<void> {
    this.proxyChain = this.proxyChain.then(op).catch(() => undefined);
    return this.proxyChain;
  }

  /** Mirrors helper state into browser proxy settings. */
  onStatus(status: NativeStatus): void {
    if (status.state === 'connected' && status.proxy?.username && status.proxy.password) {
      this.proxyAuth = { port: status.proxy.port, username: status.proxy.username, password: status.proxy.password };
    } else if (!(status.state === 'connecting' && status.phase === 'restarting')) {
      this.proxyAuth = null;
    }
    // The UI gets the status without the credentials.
    this.state.status = status.proxy ? { ...status, proxy: { scheme: status.proxy.scheme, host: status.proxy.host, port: status.proxy.port } } : status;
    this.emit();
    const connected = status.state === 'connected' && status.proxy;
    const keepDuringRestart = status.state === 'connecting' && status.phase === 'restarting' && this.state.browserProxied;
    void this.enqueueProxy(async () => {
      if (connected && status.proxy) {
        const err = await this.deps.proxy.set(status.proxy.port);
        if (err) {
          this.state.proxyError = err;
          this.state.browserProxied = false;
          await this.deps.proxy.clear();
          this.emit();
          void this.send('disconnect', {});
          return;
        }
        this.state.proxyError = null;
        this.state.browserProxied = true;
        const protect = await this.deps.webrtcEnabled();
        await this.deps.webrtc.apply(protect);
        // Fail closed: WebRTC protection is on (the default) but not in effect, e.g. another
        // extension controls the setting. Browsing would leak the real IP address over WebRTC.
        const rtcProblem = protect ? await this.deps.webrtc.problem() : null;
        if (rtcProblem) {
          this.state.proxyError = `${rtcProblem} The tunnel was disconnected.`;
          this.state.browserProxied = false;
          await this.deps.proxy.clear();
          await this.deps.webrtc.apply(false);
          this.emit();
          void this.send('disconnect', {});
          return;
        }
      } else if (!keepDuringRestart) {
        if (this.state.browserProxied || status.state !== 'connecting') {
          await this.deps.proxy.clear();
          await this.deps.webrtc.apply(false);
        }
        this.state.browserProxied = false;
        if (status.state === 'disconnected') this.state.proxyError = null;
      }
      this.emit();
    });
  }

  /**
   * chrome.proxy.settings changed (by us, another extension, or policy). If the tunnel is up but
   * our setting is no longer the one in effect, browser traffic is not going through the tunnel:
   * disconnect and say why, instead of continuing to show "connected".
   */
  proxyControlChanged(): void {
    void this.enqueueProxy(async () => {
      if (!this.state.browserProxied) return;
      // The proxy setting, and (when enabled) the WebRTC leak protection, must both stay ours.
      const problem =
        (await this.deps.proxy.controlProblem()) ?? ((await this.deps.webrtcEnabled()) ? await this.deps.webrtc.problem() : null);
      if (!problem) return;
      this.state.browserProxied = false;
      this.state.proxyError = `${problem} The tunnel was disconnected.`;
      await this.deps.proxy.clear();
      await this.deps.webrtc.apply(false);
      this.emit();
      void this.send("disconnect", {});
    });
  }

  /**
   * Credentials for a proxy authentication challenge, or null. Only our own tunnel inbound
   * (127.0.0.1 and exactly the current port) is ever answered, and only while our proxy setting is
   * in effect, so the credentials cannot be sent to any other proxy.
   */
  proxyCredentials(challenger: { host: string; port: number }): { username: string; password: string } | null {
    const a = this.proxyAuth;
    if (!a || !this.state.browserProxied) return null;
    if (challenger.host !== '127.0.0.1' || challenger.port !== a.port) return null;
    return { username: a.username, password: a.password };
  }

  /** For tests. */
  idle(): Promise<void> {
    return this.proxyChain;
  }
}

export function runtimeMessage(r: RuntimeState): string {
  switch (r.kind) {
    case 'ready':
      return '';
    case 'starting':
      return 'Starting the native runtime…';
    default:
      return r.message;
  }
}
