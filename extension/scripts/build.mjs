// Builds the unpacked extension into extension/dist.
//   node scripts/build.mjs            development build (source maps)
//   node scripts/build.mjs --release  minified, no source maps
//   node scripts/build.mjs --watch
import * as esbuild from 'esbuild';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ext = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(ext, 'dist');
const release = process.argv.includes('--release');
const watch = process.argv.includes('--watch');

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'icons'), { recursive: true });

function copyStatic() {
  const manifest = JSON.parse(readFileSync(join(ext, 'manifest/manifest.json'), 'utf8'));
  const keyFile = join(ext, 'manifest.key.json');
  if (!existsSync(keyFile)) throw new Error('extension/manifest.key.json missing: run node scripts/generate-extension-key.mjs');
  // The public key pins the extension ID, which native messaging allowed_origins depends on.
  manifest.key = JSON.parse(readFileSync(keyFile, 'utf8')).key;
  const pkg = JSON.parse(readFileSync(join(ext, 'package.json'), 'utf8'));
  manifest.version = pkg.version;
  writeFileSync(join(dist, 'manifest.json'), JSON.stringify(manifest, null, 2));
  cpSync(join(ext, 'src/popup/popup.html'), join(dist, 'popup.html'));
  cpSync(join(ext, 'src/popup/popup.css'), join(dist, 'popup.css'));
  cpSync(join(ext, 'assets/icons'), join(dist, 'icons'), { recursive: true });
  mkdirSync(join(dist, 'licenses'), { recursive: true });
  cpSync(join(ext, 'node_modules/jsqr/LICENSE'), join(dist, 'licenses/jsQR-LICENSE.txt'));
}

const options = {
  entryPoints: { background: join(ext, 'src/background/service-worker.ts'), popup: join(ext, 'src/popup/popup.ts') },
  outdir: dist,
  bundle: true,
  format: 'esm',
  target: 'chrome110',
  platform: 'browser',
  minify: release,
  sourcemap: release ? false : 'linked',
  legalComments: 'linked',
  logLevel: 'info',
};

copyStatic();
if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log('watching…');
} else {
  await esbuild.build(options);
  console.log(`extension built (${release ? 'release' : 'dev'}) -> ${dist}`);
}
