// MV3 service worker: owns the native messaging port and the browser proxy setting.
// Only this extension's own pages (the popup) can talk to it: there are no content
// scripts and no `externally_connectable`, and every message's sender is checked.
import { Controller } from './controller';
import { chromeProxy, chromeWebRtc, webrtcEnabled } from './chrome-adapters';
import type { AppState, SwPush, UiMessage } from '../shared/app-state';

const popupPorts = new Set<chrome.runtime.Port>();

const controller = new Controller({
  connectNative: (host) => chrome.runtime.connectNative(host),
  lastError: () => chrome.runtime.lastError?.message,
  proxy: chromeProxy,
  webrtc: chromeWebRtc,
  webrtcEnabled,
  broadcast: (state: AppState) => {
    const msg: SwPush = { type: 'state', state };
    for (const p of popupPorts) {
      try {
        p.postMessage(msg);
      } catch {
        popupPorts.delete(p);
      }
    }
    void chrome.action.setBadgeText({ text: state.browserProxied ? 'ON' : '' });
    void chrome.action.setBadgeBackgroundColor({ color: '#1f9d55' });
  },
  extensionVersion: chrome.runtime.getManifest().version,
  setTimer: (cb, ms) => setTimeout(cb, ms),
  clearTimer: (t) => clearTimeout(t as ReturnType<typeof setTimeout>),
});

function fromOwnPage(sender: chrome.runtime.MessageSender): boolean {
  // Our own pages only (the popup, possibly opened in a tab for debugging). Web pages cannot
  // message us: there is no externally_connectable and no content script.
  return sender.id === chrome.runtime.id && typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(''));
}

// Registering these listeners makes Chromium start the worker at browser startup, which
// clears any stale proxy setting and (re)connects the runtime.
chrome.runtime.onStartup.addListener(() => undefined);
chrome.runtime.onInstalled.addListener(() => undefined);

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'popup' || !port.sender || !fromOwnPage(port.sender)) {
    port.disconnect();
    return;
  }
  popupPorts.add(port);
  port.onDisconnect.addListener(() => popupPorts.delete(port));
  const msg: SwPush = { type: 'state', state: controller.state };
  port.postMessage(msg);
  const k = controller.state.runtime.kind;
  if (k === 'missing' || k === 'forbidden' || k === 'crashed') controller.retry();
});

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  if (!fromOwnPage(sender)) return false;
  const msg = raw as UiMessage;
  switch (msg?.type) {
    case 'request':
      controller.request(String(msg.cmd), msg.args ?? {}).then(sendResponse);
      return true; // async response
    case 'retryNative':
      controller.retry();
      sendResponse({ ok: true });
      return false;
    case 'getState':
      sendResponse(controller.state);
      return false;
    default:
      return false;
  }
});

// Answer the tunnel inbound's 407 challenge with the per-connection credentials. Nothing else is
// answered (other proxies, and every website's own authentication, get the browser default), and a
// request challenged twice is cancelled so wrong credentials can never loop.
const answered = new Set<string>();
chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    let response: chrome.webRequest.BlockingResponse = {};
    const creds = details.isProxy && details.challenger ? controller.proxyCredentials(details.challenger) : null;
    if (creds) {
      if (answered.has(details.requestId)) {
        answered.delete(details.requestId);
        response = { cancel: true };
      } else {
        answered.add(details.requestId);
        if (answered.size > 1000) answered.clear();
        response = { authCredentials: creds };
      }
    }
    callback?.(response);
    return undefined;
  },
  { urls: ['<all_urls>'] },
  ['asyncBlocking'],
);

// Another extension or a policy can take over the browser proxy at any time; never keep showing
// "connected" when our setting is no longer in effect.
chrome.proxy.settings.onChange.addListener(() => controller.proxyControlChanged());

void controller.start();
