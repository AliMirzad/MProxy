import { describe, expect, it } from 'vitest';
import QRCode from 'qrcode';
import { decodeQrFromImageData, looksLikeProxyConfig } from '../src/popup/qr';

/** Renders a QR matrix to RGBA pixels (4px per module, 4-module quiet zone). */
function render(text: string): { data: Uint8ClampedArray; w: number; h: number } {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size;
  const scale = 4;
  const quiet = 4;
  const w = (n + quiet * 2) * scale;
  const data = new Uint8ClampedArray(w * w * 4).fill(255);
  for (let y = 0; y < n; y++)
    for (let x = 0; x < n; x++)
      if (qr.modules.get(y, x))
        for (let dy = 0; dy < scale; dy++)
          for (let dx = 0; dx < scale; dx++) {
            const o = (((y + quiet) * scale + dy) * w + (x + quiet) * scale + dx) * 4;
            data[o] = data[o + 1] = data[o + 2] = 0;
          }
  return { data, w, h: w };
}

describe('QR decoding (local, jsQR)', () => {
  it('round-trips a VLESS REALITY link', () => {
    const link =
      'vless://b831381d-6324-4d53-ad4f-8cda48b30811@de.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=OFAMcMJ-9uns7MO5APwkUr8PfvouYrl-t8s7UIEn9mI&sid=6ba85179e30d4fc2&type=tcp#Germany%20Reality';
    const { data, w, h } = render(link);
    expect(decodeQrFromImageData(data, w, h)).toBe(link);
  });

  it('returns null for an image without a QR code', () => {
    const w = 64;
    expect(decodeQrFromImageData(new Uint8ClampedArray(w * w * 4).fill(255), w, w)).toBeNull();
  });

  it('classifies payloads without acting on them', () => {
    expect(looksLikeProxyConfig('vless://x@y:1')).toBe(true);
    expect(looksLikeProxyConfig('VMESS://abc')).toBe(true);
    expect(looksLikeProxyConfig('https://evil.example.com/login')).toBe(false);
    expect(looksLikeProxyConfig('WIFI:S:x;T:WPA;P:y;;')).toBe(false);
    expect(looksLikeProxyConfig('dmxlc3M6Ly94QHk6MQ==dmxlc3M6Ly94QHk6MQ==')).toBe(true);
  });
});
