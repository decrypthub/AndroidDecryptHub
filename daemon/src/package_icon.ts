import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { catalogIcon, ensureCatalogIdentity } from './app_catalog.ts';
import { shQuote } from './sandbox_fs.ts';

const execFileP = promisify(execFile);
const cache = new Map<string, { body: Buffer; type: string } | null>();

function adbBase(): string[] {
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return serial ? ['-s', serial] : [];
}

async function adbOut(command: string): Promise<Buffer> {
  const { stdout } = await execFileP('adb', [...adbBase(), 'exec-out', command], {
    timeout: 20000, windowsHide: true, maxBuffer: 4 * 1024 * 1024, encoding: 'buffer',
  });
  return stdout as Buffer;
}

function imageType(body: Buffer): string {
  if (body.length > 8 && body[0] === 0x89 && body[1] === 0x50 && body[2] === 0x4e && body[3] === 0x47) return 'image/png';
  if (body.length > 12 && body.subarray(0, 4).toString() === 'RIFF' && body.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  return '';
}

async function managerIcon(pkg: string): Promise<{ body: Buffer; type: string } | null> {
  const out = String(await adbOut(`content call --uri 'content://com.adh.manager.daemon-bridge' --method appIcon --arg '${pkg.replace(/'/g, `'\\''`)}'`));
  const b64 = /base64=([A-Za-z0-9+/=]+)\}/.exec(out)?.[1] || '';
  if (!b64) return null;
  const body = Buffer.from(b64, 'base64');
  const type = imageType(body);
  return type ? { body, type } : null;
}

async function listApkEntries(apk: string): Promise<{ size: number; path: string }[]> {
  const out = String(await adbOut(`su -c ${shQuote(`unzip -l ${shQuote(apk)}`)}`));
  const entries: { size: number; path: string }[] = [];
  for (const line of out.split(/\r?\n/)) {
    const matched = /^\s*(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+)$/.exec(line);
    if (matched) entries.push({ size: Number(matched[1]), path: matched[2] });
  }
  return entries;
}

function densityRank(path: string): number {
  if (/xxxhdpi/i.test(path)) return 6;
  if (/xxhdpi/i.test(path)) return 5;
  if (/xhdpi/i.test(path)) return 4;
  if (/hdpi/i.test(path)) return 3;
  if (/mdpi/i.test(path)) return 2;
  if (/ldpi/i.test(path)) return 1;
  return 0;
}

/** Adaptive icons are XML; try to locate the matching foreground/layer PNG in the same APK. */
async function resolveAdaptiveLayer(apk: string, xmlPath: string): Promise<string | null> {
  const stem = xmlPath.split('/').pop()?.replace(/\.xml$/i, '') || '';
  if (!stem) return null;
  const names = [stem, `${stem}_foreground`, `${stem}_fg`, `${stem}_background`, `${stem}_bg`];
  const entries = await listApkEntries(apk);
  const candidates = entries
    .filter(e => /^res\/(mipmap|drawable)/i.test(e.path) && /\.png$/i.test(e.path))
    .map(e => ({ ...e, rank: densityRank(e.path), hit: names.some(n => e.path.toLowerCase().includes(n.toLowerCase())) }))
    .filter(e => e.hit);
  candidates.sort((a, b) => b.rank - a.rank || b.size - a.size);
  return candidates[0]?.path || null;
}

/** The launcher bitmap named by aapt, not a foreground or monochrome layer. */
export async function readPackageIcon(pkg: string): Promise<{ body: Buffer; type: string } | null> {
  if (cache.has(pkg)) return cache.get(pkg) || null;
  const manager = await managerIcon(pkg);
  if (manager) { cache.set(pkg, manager); return manager; }
  let known = catalogIcon(pkg);
  if (!known) {
    await ensureCatalogIdentity(pkg);
    known = catalogIcon(pkg);
  }
  if (!known || !known.path || !known.apk) {
    cache.set(pkg, null);
    return null;
  }
  let path = known.path;
  if (/\.xml$/i.test(path)) {
    const layer = await resolveAdaptiveLayer(known.apk, path);
    if (!layer) { cache.set(pkg, null); return null; }
    path = layer;
  }
  const body = await adbOut(`su -c ${shQuote(`unzip -p ${shQuote(known.apk)} ${shQuote(path)}`)}`);
  const type = imageType(body);
  if (!type) {
    cache.set(pkg, null);
    return null;
  }
  const result = { body, type };
  cache.set(pkg, result);
  return result;
}
