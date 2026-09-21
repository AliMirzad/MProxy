// Generates the toolbar icons (simple shield-like rounded square with a keyhole) as PNGs,
// without any image dependencies. Run: node scripts/make-icons.mjs
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'icons');
mkdirSync(out, { recursive: true });

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
};

function png(size) {
  const px = Buffer.alloc(size * (size * 4 + 1));
  const r = size * 0.22; // corner radius
  const bg = [37, 99, 235];
  for (let y = 0; y < size; y++) {
    px[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const cx = x + 0.5, cy = y + 0.5;
      // rounded square coverage (with 1px anti-aliasing)
      const dx = Math.max(r - cx, 0, cx - (size - r));
      const dy = Math.max(r - cy, 0, cy - (size - r));
      const d = Math.hypot(dx, dy) - r;
      let a = Math.min(1, Math.max(0, 0.5 - d));
      let [R, G, B] = bg;
      // keyhole: circle + trapezoid in white
      const kx = size / 2, ky = size * 0.42, kr = size * 0.14;
      const inCircle = Math.hypot(cx - kx, cy - ky) <= kr;
      const t = (cy - ky) / (size * 0.36);
      const inStem = t >= 0 && t <= 1 && Math.abs(cx - kx) <= size * (0.06 + 0.05 * t);
      if (inCircle || inStem) [R, G, B] = [255, 255, 255];
      const o = y * (size * 4 + 1) + 1 + x * 4;
      px[o] = R; px[o + 1] = G; px[o + 2] = B; px[o + 3] = Math.round(a * 255);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(px)), chunk('IEND', Buffer.alloc(0))]);
}

for (const s of [16, 32, 48, 128]) writeFileSync(join(out, `icon-${s}.png`), png(s));
console.log('icons written to', out);
