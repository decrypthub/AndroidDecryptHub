// Resolving paths is pure. Only explicit writes/initialization create directories.
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

export function resolveStoragePaths(env: NodeJS.ProcessEnv = process.env) {
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const testRoot = env.ADH_SKIP_ARTIFACT_LOAD === '1' ? join(tmpdir(), `adh-test-${process.pid}`) : '';
  const dataDir = resolve(env.ADH_DATA_DIR || (testRoot ? join(testRoot, 'adhd-data') : join(repository, 'adhd-data')));
  // Preserve the old default layout; an explicitly isolated data root isolates dumps too.
  const capturesDir = resolve(env.ADH_CAPTURES_DIR || (env.ADH_DATA_DIR ? join(dataDir, 'captures')
    : testRoot ? join(testRoot, 'captures') : join(repository, 'captures')));
  return { dataDir, capturesDir };
}

export const storagePaths = resolveStoragePaths();

export function captureFile(name: string): string {
  mkdirSync(storagePaths.capturesDir, { recursive: true });
  return join(storagePaths.capturesDir, name);
}

export function atomicWriteJson(path: string, value: unknown): void {
  atomicWriteText(path, JSON.stringify(value, null, 2) + '\n');
}

export function atomicWriteText(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temporary, 'wx', 0o600);
    writeFileSync(fd, value);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(temporary, path);
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch { /* renamed or never created */ }
  }
}
