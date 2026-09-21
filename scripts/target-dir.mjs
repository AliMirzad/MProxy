// Location of the Cargo target directory, shared by all scripts.
//
// Windows limits process image paths to MAX_PATH (260) characters, and Cargo's build scripts
// live several levels deep in the target directory. When the repository itself sits in a long
// path (for example a virtualized AppData folder), `CreateProcess` fails with "path not found".
// In that case the target directory moves to a short per-user path. Set CARGO_TARGET_DIR to
// override.
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export function targetDir() {
  if (process.env.CARGO_TARGET_DIR) return process.env.CARGO_TARGET_DIR;
  const inRepo = join(root, 'native', 'target');
  if (process.platform === 'win32' && inRepo.length > 100) return join(homedir(), '.private-proxy-target');
  return inRepo;
}

/** Candidate paths of a built helper binary for `profile` ("debug" | "release"). */
export function hostCandidates(profile, rustTarget) {
  const exe = process.platform === 'win32' ? 'private-proxy-host.exe' : 'private-proxy-host';
  const t = targetDir();
  return [
    ...(rustTarget ? [join(t, rustTarget, profile, exe)] : []),
    join(t, profile, exe),
    join(t, 'x86_64-pc-windows-gnullvm', profile, exe),
  ];
}
