// Generates the MProxy toolbar icons (gradient rounded square with an "M") as PNGs,
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

// MProxy icon: rounded square with a diagonal indigo -> violet -> cyan gradient and a white "M",
// rendered with 4x4 supersampling for smooth edges.
const lerp = (a, b, t) => a + (b - a) * t;
const stops = [[99, 102, 241], [168, 85, 247], [34, 211, 238]];
function gradient(t) {
  const u = Math.min(1, Math.max(0, t)) * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(u));
  const k = u - i;
  return stops[i].map((c, j) => lerp(c, stops[i + 1][j], k));
}
function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
const M = [[0.27, 0.72], [0.27, 0.30], [0.5, 0.56], [0.73, 0.30], [0.73, 0.72]];

function png(size) {
  const px = Buffer.alloc(size * (size * 4 + 1));
  const r = size * 0.24;
  const stroke = Math.max(1.4, size * 0.105);
  const N = 4;
  for (let y = 0; y < size; y++) {
    px[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      let cover = 0, white = 0;
      for (let sy = 0; sy < N; sy++) {
        for (let sx = 0; sx < N; sx++) {
          const cx = x + (sx + 0.5) / N, cy = y + (sy + 0.5) / N;
          const dx = Math.max(r - cx, 0, cx - (size - r));
          const dy = Math.max(r - cy, 0, cy - (size - r));
          if (Math.hypot(dx, dy) > r) continue;
          cover++;
          let d = Infinity;
          for (let i = 0; i + 1 < M.length; i++) d = Math.min(d, distToSegment(cx, cy, M[i][0] * size, M[i][1] * size, M[i + 1][0] * size, M[i + 1][1] * size));
          if (d <= stroke / 2) white++;
        }
      }
      const [gr, gg, gb] = gradient((x + y) / (2 * size));
      const w = cover ? white / cover : 0;
      const o = y * (size * 4 + 1) + 1 + x * 4;
      px[o] = Math.round(lerp(gr, 255, w));
      px[o + 1] = Math.round(lerp(gg, 255, w));
      px[o + 2] = Math.round(lerp(gb, 255, w));
      px[o + 3] = Math.round((cover / (N * N)) * 255);
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
