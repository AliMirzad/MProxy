#!/usr/bin/env node
// Generates the RSA key that pins the extension ID.
//
// Chromium derives an unpacked extension's ID from the path unless manifest.json has a
// "key" field. Native messaging `allowed_origins` cannot use wildcards, so we need a fixed
// ID. This script writes:
//   extension/manifest.key.json   -> { "key": "<base64 SPKI>" } (public, committed)
//   shared/extension-id.txt       -> the derived extension ID (committed)
//   .keys/extension-private.pem   -> private key (NOT committed; only needed to pack a .crx)
//
// Run once per organisation fork: node scripts/generate-extension-key.mjs [--force]
import { generateKeyPairSync, createHash } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pubOut = join(root, 'extension/manifest.key.json');
if (existsSync(pubOut) && !process.argv.includes('--force')) {
  console.error('extension/manifest.key.json already exists; pass --force to rotate (changes the extension ID!)');
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const der = publicKey.export({ type: 'spki', format: 'der' });
const id = extensionIdFromSpki(der);

mkdirSync(join(root, '.keys'), { recursive: true });
writeFileSync(join(root, '.keys/extension-private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
writeFileSync(pubOut, JSON.stringify({ key: der.toString('base64') }, null, 2) + '\n');
writeFileSync(join(root, 'shared/extension-id.txt'), id + '\n');
console.log(`Extension ID: ${id}`);

export function extensionIdFromSpki(spkiDer) {
  const hex = createHash('sha256').update(spkiDer).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode('a'.charCodeAt(0) + parseInt(c, 16))).join('');
}
