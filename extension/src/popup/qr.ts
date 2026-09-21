// Local QR decoding (jsQR). Images never leave the browser.
import jsQR from 'jsqr';

const MAX_SIDE = 1600;

/** Decodes the first QR code in an image blob. Returns null if none is found. */
export async function decodeQrFromBlob(blob: Blob): Promise<string | null> {
  if (!blob.type.startsWith('image/')) throw new Error('Not an image');
  if (blob.size > 20 * 1024 * 1024) throw new Error('Image is too large');
  const bmp = await createImageBitmap(blob);
  try {
    const scale = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = new OffscreenCanvas(w, h);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('Canvas unavailable');
    ctx.drawImage(bmp, 0, 0, w, h);
    const img = ctx.getImageData(0, 0, w, h);
    return decodeQrFromImageData(img.data, w, h);
  } finally {
    bmp.close();
  }
}

export function decodeQrFromImageData(data: Uint8ClampedArray, w: number, h: number): string | null {
  const code = jsQR(data, w, h, { inversionAttempts: 'attemptBoth' });
  return code?.data ? code.data : null;
}

/** Screenshot of the visible tab (needs activeTab, granted by opening the popup). */
export async function captureVisibleTab(): Promise<Blob> {
  const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' });
  const res = await fetch(dataUrl);
  return res.blob();
}

/** Quick local check so we can show a clear error for unrelated QR content. */
export function looksLikeProxyConfig(text: string): boolean {
  const t = text.trim();
  return /^(vless|vmess):\/\//i.test(t) || t.startsWith('{') || (!t.includes('://') && /^[A-Za-z0-9+/=_\-\s]+$/.test(t) && t.length > 16);
}
