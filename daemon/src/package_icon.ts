import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { catalogIcon, ensureCatalogIdentity } from './app_catalog.ts';
import { apkAaptDumps } from './scope_list.ts';
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

/** The device daemon icon can fall back to a shared system default; only trust a real APK bitmap. */
async function apkIcon(pkg: string): Promise<{ body: Buffer; type: string } | null> {
  let known = catalogIcon(pkg);
  if (!known) {
    await ensureCatalogIdentity(pkg);
    known = catalogIcon(pkg);
  }
  if (!known || !known.path || !known.apk) return null;
  let path = known.path;
  if (/\.xml$/i.test(path)) {
    const layer = (await resolveApkIcon(known.apk)) || (await resolveAdaptiveLayer(known.apk, path));
    if (!layer) return null;
    path = layer;
  }
  const body = await adbOut(`su -c ${shQuote(`unzip -p ${shQuote(known.apk)} ${shQuote(path)}`)}`);
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

const DPI = ['xxxhdpi', 'xxhdpi', 'xhdpi', 'hdpi', 'mdpi', 'ldpi'];

function configRank(config: string): number {
  const i = DPI.findIndex(d => config.toLowerCase().includes(d));
  return i < 0 ? 0 : DPI.length - i;
}

interface ResEntry { rank: number; type: number; d: number }

/** `aapt dump resources` → resource id → per-config entries (density rank, value type, data index). */
function parseResourceTable(dump: string): Map<string, ResEntry[]> {
  const table = new Map<string, ResEntry[]>();
  let config = '';
  for (const line of dump.split(/\r?\n/)) {
    const cfg = /\bconfig ([^:]+):/.exec(line);
    if (cfg) config = cfg[1];
    const m = /resource (0x[0-9a-f]+)\s+\S+?:\S+?: t=0x([0-9a-f]+) d=0x([0-9a-f]+)/i.exec(line);
    if (!m) continue;
    const id = m[1].toLowerCase();
    const list = table.get(id) ?? [];
    list.push({ rank: configRank(config), type: parseInt(m[2], 16), d: parseInt(m[3], 16) });
    table.set(id, list);
  }
  return table;
}

/** `aapt dump strings` → string-pool index → value. Resource `d=` values index this pool. */
function parseStringPool(dump: string): Map<number, string> {
  const pool = new Map<number, string>();
  for (const m of dump.matchAll(/^String #(\d+): (.*)$/gm)) pool.set(Number(m[1]), m[2].trim());
  return pool;
}

/** Drawable references inside an XML resource (adaptive-icon layers etc.), foreground first. */
function xmlDrawableIds(tree: string): string[] {
  const byElement = new Map<string, string>();
  let element = '';
  for (const line of tree.split(/\r?\n/)) {
    const el = /E: (\S+)/.exec(line);
    if (el) element = el[1];
    const attr = /android:drawable\(0x[0-9a-f]+\)=@0x([0-9a-f]+)/i.exec(line);
    if (attr && !byElement.has(element)) byElement.set(element, `0x${attr[1].toLowerCase()}`);
  }
  const ordered = ['foreground', 'background', 'monochrome']
    .flatMap(k => (byElement.has(k) ? [byElement.get(k)!] : []));
  return [...new Set([...ordered, ...byElement.values()])];
}

/** Resolve a resource id to a raster file inside the APK, following aliases and XML layer refs. */
async function resolveResIcon(
  apk: string,
  table: Map<string, ResEntry[]>,
  pool: Map<number, string>,
  id: string,
  depth: number,
): Promise<string | null> {
  const entries = table.get(id) ?? [];
  const paths = entries
    .filter(e => e.type === 0x03)
    .map(e => ({ rank: e.rank, path: pool.get(e.d) ?? '' }))
    .filter(e => /\.(png|webp|xml)$/i.test(e.path))
    .sort((a, b) => b.rank - a.rank);
  const raster = paths.find(e => /\.(png|webp)$/i.test(e.path));
  if (raster) return raster.path;
  if (depth <= 0) return null;
  const xml = paths.find(e => /\.xml$/i.test(e.path));
  if (xml) {
    const [tree] = await apkAaptDumps(apk, [xml.path], [['xmltree', xml.path]]);
    for (const inner of xmlDrawableIds(tree)) {
      const hit = await resolveResIcon(apk, table, pool, inner, depth - 1);
      if (hit) return hit;
    }
  }
  const ref = entries.find(e => e.type === 0x01);
  if (ref) return resolveResIcon(apk, table, pool, `0x${ref.d.toString(16).padStart(8, '0')}`, depth - 1);
  return null;
}

/** Manifest icon/roundIcon → resource table → highest-density PNG/WebP, adaptive layers included. */
async function resolveApkIcon(apk: string): Promise<string | null> {
  const [manifestTree, resources, strings] = await apkAaptDumps(apk, [], [
    ['xmltree', 'AndroidManifest.xml'],
    ['resources'],
    ['strings'],
  ]);
  if (!manifestTree || !resources || !strings) return null;
  const table = parseResourceTable(resources);
  const pool = parseStringPool(strings);
  const ids: string[] = [];
  for (const attr of ['icon', 'roundIcon']) {
    const m = new RegExp(`android:${attr}\\(0x[0-9a-f]+\\)=@0x([0-9a-f]+)`, 'i').exec(manifestTree);
    if (m && !ids.includes(`0x${m[1].toLowerCase()}`)) ids.push(`0x${m[1].toLowerCase()}`);
  }
  for (const id of ids) {
    const path = await resolveResIcon(apk, table, pool, id, 2);
    if (path) return path;
  }
  return null;
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
  const result = await apkIcon(pkg);
  cache.set(pkg, result);
  return result;
}
