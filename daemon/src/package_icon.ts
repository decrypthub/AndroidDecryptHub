import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { catalogIcon, ensureCatalogIdentity } from './app_catalog.ts';
import { apkAaptDumps } from './scope_list.ts';
import { shQuote } from './sandbox_fs.ts';
import { deviceIcon, deviceSerial } from './device_bridge.ts';

const execFileP = promisify(execFile);
const cache = new Map<string, { at: number; v: { body: Buffer; type: string } | null }>();
const inflight = new Map<string, Promise<{ body: Buffer; type: string } | null>>();
const NEG_TTL = 30_000;

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
  if (!known) return null;
  if (!known.apk) {
    const out = await adbOut(`pm path ${pkg}`).catch(() => Buffer.alloc(0));
    const match = /^package:(.+\.apk)\s*$/m.exec(out.toString('utf8'));
    if (!match) return null;
    known = { ...known, apk: match[1].trim() };
  }
  let path = known.path;
  if (!/\.(png|webp)$/i.test(path)) {
    const resolved = await resolveApkIcon(known.apk);
    if (resolved?.raster) {
      path = resolved.path;
    } else if (resolved) {
      const svg = await vectorIconSvg(known.apk, resolved.path);
      if (svg) return { body: Buffer.from(svg, 'utf8'), type: 'image/svg+xml' };
      const layer = await resolveAdaptiveLayer(known.apk, path || resolved.path);
      if (!layer) return null;
      path = layer;
    } else {
      const layer = path ? await resolveAdaptiveLayer(known.apk, path) : null;
      if (!layer) return null;
      path = layer;
    }
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

interface ResIndex { manifestTree: string; table: Map<string, ResEntry[]>; pool: Map<number, string> }
const resIndexCache = new Map<string, Promise<ResIndex | null>>();

/** Manifest xmltree + resource table + string pool for one APK, fetched once per path. */
function getResIndex(apk: string): Promise<ResIndex | null> {
  let job = resIndexCache.get(apk);
  if (!job) {
    job = (async () => {
      const [manifestTree, resources, strings] = await apkAaptDumps(apk, [], [
        ['xmltree', 'AndroidManifest.xml'], ['resources'], ['strings'],
      ]);
      if (!resources || !strings) return null;
      return { manifestTree, table: parseResourceTable(resources), pool: parseStringPool(strings) };
    })();
    resIndexCache.set(apk, job);
  }
  return job;
}

/** File paths a resource id can take, best density first. */
function resFilePaths(idx: ResIndex, id: string): { path: string; rank: number }[] {
  return (idx.table.get(id) ?? [])
    .filter(e => e.type === 0x03)
    .map(e => ({ rank: e.rank, path: idx.pool.get(e.d) ?? '' }))
    .filter(e => /\.(png|webp|xml)$/i.test(e.path))
    .sort((a, b) => b.rank - a.rank);
}

/** Manifest icon/roundIcon → resource table → best file path (raster preferred, then XML). */
async function resolveApkIcon(apk: string): Promise<{ path: string; raster: boolean } | null> {
  const idx = await getResIndex(apk);
  if (!idx) return null;
  const ids: string[] = [];
  for (const attr of ['icon', 'roundIcon']) {
    const m = new RegExp(`android:${attr}\\(0x[0-9a-f]+\\)=@0x([0-9a-f]+)`, 'i').exec(idx.manifestTree);
    if (m) {
      const id = `0x${m[1].toLowerCase()}`;
      if (!ids.includes(id)) ids.push(id);
    }
  }
  let xmlPath = '';
  for (let i = 0; i < ids.length; i++) {
    const entries = idx.table.get(ids[i]) ?? [];
    const paths = resFilePaths(idx, ids[i]);
    const raster = paths.find(p => /\.(png|webp)$/i.test(p.path));
    if (raster) return { path: raster.path, raster: true };
    if (!xmlPath) {
      const xml = paths.find(p => /\.xml$/i.test(p.path));
      if (xml) xmlPath = xml.path;
    }
    const ref = entries.find(e => e.type === 0x01);
    if (ref) {
      const target = `0x${ref.d.toString(16).padStart(8, '0')}`;
      if (!ids.includes(target)) ids.push(target);
    }
  }
  return xmlPath ? { path: xmlPath, raster: false } : null;
}

// --- Android vector / adaptive icons → SVG ---------------------------------

interface XmlNode { name: string; attrs: Map<string, AttrVal>; children: XmlNode[] }
interface AttrVal { t: 'str' | 'ref' | 'num' | 'raw'; s?: string; i?: number; numType?: number }

/** aapt `dump xmltree` line output → element tree. */
function parseXmlTree(text: string): XmlNode | null {
  let root: XmlNode | null = null;
  const stack: { node: XmlNode; indent: number }[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^(\s*)([ENA]): (.+)$/.exec(line);
    if (!m) continue;
    const indent = m[1].length, kind = m[2], rest = m[3];
    if (kind === 'E') {
      const node: XmlNode = { name: rest.split(' ')[0], attrs: new Map(), children: [] };
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      if (stack.length) stack[stack.length - 1].node.children.push(node);
      else root = node;
      stack.push({ node, indent });
    } else if (kind === 'A' && stack.length) {
      const am = /^([^\s(]+)\(0x[0-9a-f]+\)=(.*)$/.exec(rest);
      if (am) stack[stack.length - 1].node.attrs.set(am[1].replace(/^(android|aapt):/, ''), attrVal(am[2]));
    }
  }
  return root;
}

function attrVal(raw: string): AttrVal {
  const s = raw.trim();
  const q = /^"((?:[^"\\]|\\.)*)"/.exec(s);
  if (q) return { t: 'str', s: q[1] };
  const r = /^@0x([0-9a-f]+)/i.exec(s);
  if (r) return { t: 'ref', i: parseInt(r[1], 16) };
  const m = /^\(type 0x([0-9a-f]+)\)\s*(-?0x[0-9a-f]+|-?[\d.eE+-]+)/i.exec(s);
  if (m) {
    const v = m[2];
    const i = v.toLowerCase().startsWith('-0x')
      ? -parseInt(v.slice(1), 16)
      : v.toLowerCase().startsWith('0x') ? parseInt(v, 16) >>> 0 : Number(v);
    return { t: 'num', numType: parseInt(m[1], 16), i };
  }
  return { t: 'raw', s };
}

function numOf(v: AttrVal | undefined): number {
  if (!v || v.t !== 'num' || v.i == null) return NaN;
  if (v.numType === 0x04) {
    const buf = new DataView(new ArrayBuffer(4));
    buf.setUint32(0, v.i >>> 0);
    return buf.getFloat32(0);
  }
  if (v.numType === 0x12) return v.i ? 1 : 0;
  if (v.numType === 0x05) {
    const i32 = v.i | 0;
    return ((i32 & 0xffffff00) >> 8) * [1 / (1 << 23), 1 / (1 << 15), 1 / 128, 1][(i32 >>> 4) & 3];
  }
  return v.i;
}

function strOf(v: AttrVal | undefined): string {
  return v?.t === 'str' ? (v.s ?? '') : '';
}

function escXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

interface SvgCtx { idx: ResIndex; apk: string; defs: string[]; clipSeq: number; depth: number }

/** Resource id or literal color attr → ARGB. Follows aliases and color-selector XML once. */
async function argbOf(v: AttrVal | undefined, ctx: SvgCtx, depth: number): Promise<number | undefined> {
  if (!v) return undefined;
  if (v.t === 'num' && v.i != null) {
    if (v.numType === 0x1c || v.numType === 0x1d) return v.i >>> 0;
    if (v.numType === 0x10 || v.numType === 0x05 || v.numType === 0x04) return v.i >>> 0;
    return v.i >>> 0;
  }
  if (v.t !== 'ref' || v.i == null || depth <= 0) return undefined;
  const id = `0x${v.i.toString(16).padStart(8, '0')}`;
  const entries = ctx.idx.table.get(id) ?? [];
  const lit = entries.find(e => e.type === 0x1c || e.type === 0x1d);
  if (lit) return lit.d >>> 0;
  const ref = entries.find(e => e.type === 0x01);
  if (ref) return argbOf({ t: 'ref', i: ref.d }, ctx, depth - 1);
  const file = resFilePaths(ctx.idx, id).find(p => /\.xml$/i.test(p.path));
  if (file) {
    const [tree] = await apkAaptDumps(ctx.apk, [file.path], [['xmltree', file.path]]);
    const root = parseXmlTree(tree);
    const item = root && findXml(root, 'item');
    const color = item?.attrs.get('color');
    if (color) return argbOf(color, ctx, depth - 1);
  }
  return undefined;
}

function findXml(node: XmlNode, name: string): XmlNode | null {
  if (node.name === name) return node;
  for (const c of node.children) {
    const hit = findXml(c, name);
    if (hit) return hit;
  }
  return null;
}

async function cssColor(v: AttrVal | undefined, ctx: SvgCtx): Promise<string> {
  const argb = await argbOf(v, ctx, 3);
  if (argb == null) return '';
  const a = (argb >>> 24) & 0xff, r = (argb >>> 16) & 0xff, g = (argb >>> 8) & 0xff, b = argb & 0xff;
  return a === 255 ? `rgb(${r},${g},${b})` : `rgba(${r},${g},${b},${(a / 255).toFixed(3)})`;
}

const LINECAP = ['butt', 'round', 'square'];
const LINEJOIN = ['miter', 'round', 'bevel'];

async function vectorChildSvg(n: XmlNode, ctx: SvgCtx): Promise<string> {
  if (n.name === 'group') {
    const tx = numOf(n.attrs.get('translateX')) || 0, ty = numOf(n.attrs.get('translateY')) || 0;
    const rot = numOf(n.attrs.get('rotation')) || 0;
    const px = numOf(n.attrs.get('pivotX')) || 0, py = numOf(n.attrs.get('pivotY')) || 0;
    const sx = numOf(n.attrs.get('scaleX')) || 1, sy = numOf(n.attrs.get('scaleY')) || 1;
    const parts = [`translate(${tx} ${ty})`, `rotate(${rot} ${px} ${py})`, `scale(${sx} ${sy})`]
      .filter((p, i) => (i === 0 ? tx || ty : i === 1 ? rot : sx !== 1 || sy !== 1));
    const clipNodes = n.children.filter(c => c.name === 'clip-path');
    let clipAttr = '';
    if (clipNodes.length) {
      const id = `c${++ctx.clipSeq}`;
      ctx.defs.push(`<clipPath id="${id}">${clipNodes.map(c => `<path d="${escXml(strOf(c.attrs.get('pathData')))}"/>`).join('')}</clipPath>`);
      clipAttr = ` clip-path="url(#${id})"`;
    }
    const inner = (await Promise.all(n.children.filter(c => c.name !== 'clip-path').map(c => vectorChildSvg(c, ctx)))).join('');
    return `<g${parts.length ? ` transform="${parts.join(' ')}"` : ''}${clipAttr}>${inner}</g>`;
  }
  if (n.name === 'clip-path') return '';
  if (n.name !== 'path') return '';
  const d = strOf(n.attrs.get('pathData'));
  if (!d) return '';
  const fill = await cssColor(n.attrs.get('fillColor'), ctx);
  const stroke = await cssColor(n.attrs.get('strokeColor'), ctx);
  let out = `<path d="${escXml(d)}"${fill ? ` fill="${fill}"` : ' fill="none"'}`;
  if (stroke) {
    out += ` stroke="${stroke}"`;
    const w = numOf(n.attrs.get('strokeWidth'));
    if (w > 0) out += ` stroke-width="${w}"`;
    const cap = numOf(n.attrs.get('strokeLineCap'));
    if (cap >= 0) out += ` stroke-linecap="${LINECAP[cap] ?? 'butt'}"`;
    const join = numOf(n.attrs.get('strokeLineJoin'));
    if (join >= 0) out += ` stroke-linejoin="${LINEJOIN[join] ?? 'miter'}"`;
    const miter = numOf(n.attrs.get('strokeMiterLimit'));
    if (miter > 0) out += ` stroke-miterlimit="${miter}"`;
    const sa = numOf(n.attrs.get('strokeAlpha'));
    if (sa >= 0 && sa < 1) out += ` stroke-opacity="${sa}"`;
  }
  const fa = numOf(n.attrs.get('fillAlpha'));
  if (fa >= 0 && fa < 1) out += ` fill-opacity="${fa}"`;
  const ft = numOf(n.attrs.get('fillType'));
  if (ft === 1) out += ' fill-rule="evenodd"';
  return `${out}/>`;
}

interface SvgShape { w: number; h: number; body: string }

/** One drawable node → SVG body. Vector groups/paths, adaptive layers, bitmap wrappers. */
async function drawableSvg(n: XmlNode, ctx: SvgCtx, depth: number): Promise<SvgShape | null> {
  if (depth > 3) return null;
  if (n.name === 'vector') {
    const w = numOf(n.attrs.get('viewportWidth')) || 24, h = numOf(n.attrs.get('viewportHeight')) || 24;
    const clips = n.children.filter(c => c.name === 'clip-path');
    let clipAttr = '';
    if (clips.length) {
      const id = `c${++ctx.clipSeq}`;
      ctx.defs.push(`<clipPath id="${id}">${clips.map(c => `<path d="${escXml(strOf(c.attrs.get('pathData')))}"/>`).join('')}</clipPath>`);
      clipAttr = ` clip-path="url(#${id})"`;
    }
    const body = (await Promise.all(n.children.filter(c => c.name !== 'clip-path').map(c => vectorChildSvg(c, ctx)))).join('');
    return { w, h, body: `<g${clipAttr}>${body}</g>` };
  }
  if (n.name === 'adaptive-icon' || n.name === 'layer-list') {
    const layers: string[] = [];
    for (const child of n.children) {
      const layer = await layerElementSvg(child, ctx, depth + 1);
      if (layer) layers.push(layer);
    }
    if (!layers.length) return null;
    return { w: 108, h: 108, body: layers.join('') };
  }
  if (n.name === 'bitmap' || n.name === 'inset' || n.name === 'scale' || n.name === 'rotate') {
    const ref = n.attrs.get('src') ?? n.attrs.get('drawable');
    if (!ref || ref.t !== 'ref' || ref.i == null) return null;
    const layer = await layerSvg(ref.i, ctx, depth + 1);
    if (!layer) return null;
    return { w: 108, h: 108, body: layer };
  }
  return null;
}

/** One layer slot: `android:drawable` ref, `<color>` solid, `<inset>`/inline drawable child. */
async function layerElementSvg(el: XmlNode, ctx: SvgCtx, depth: number): Promise<string> {
  if (depth > 4) return '';
  const ref = el.attrs.get('drawable') ?? el.attrs.get('src');
  if (ref?.t === 'ref' && ref.i != null) {
    const s = await layerSvg(ref.i, ctx, depth + 1);
    if (s) return s;
  }
  for (const sub of el.children) {
    if (sub.name === 'color') {
      const argb = await argbOf(sub.attrs.get('color'), ctx, 3);
      if (argb != null) {
        const a = (argb >>> 24) & 0xff;
        const fill = `rgb(${(argb >>> 16) & 0xff},${(argb >>> 8) & 0xff},${argb & 0xff})`;
        return `<rect x="0" y="0" width="108" height="108" fill="${fill}"${a < 255 ? ` fill-opacity="${(a / 255).toFixed(3)}"` : ''}/>`;
      }
      continue;
    }
    const shape = await drawableSvg(sub, ctx, depth + 1);
    if (shape) return `<svg x="0" y="0" width="108" height="108" viewBox="0 0 ${shape.w} ${shape.h}">${shape.body}</svg>`;
    const inner = await layerElementSvg(sub, ctx, depth + 1);
    if (inner) return inner;
  }
  return '';
}

/** Resource id → `<image>` data URI, solid `<rect>`, or nested `<svg>` for one icon layer. */
async function layerSvg(resId: number, ctx: SvgCtx, depth: number): Promise<string> {
  const id = `0x${resId.toString(16).padStart(8, '0')}`;
  const entries = ctx.idx.table.get(id) ?? [];
  const lit = entries.find(e => e.type === 0x1c || e.type === 0x1d);
  if (lit) {
    const argb = lit.d >>> 0, a = (argb >>> 24) & 0xff;
    const fill = `rgb(${(argb >>> 16) & 0xff},${(argb >>> 8) & 0xff},${argb & 0xff})`;
    return `<rect x="0" y="0" width="108" height="108" fill="${fill}"${a < 255 ? ` fill-opacity="${(a / 255).toFixed(3)}"` : ''}/>`;
  }
  const file = resFilePaths(ctx.idx, id)[0];
  if (!file) {
    const ref = entries.find(e => e.type === 0x01);
    return ref ? layerSvg(ref.d, ctx, depth) : '';
  }
  if (/\.(png|webp)$/i.test(file.path)) {
    const body = await adbOut(`su -c ${shQuote(`unzip -p ${shQuote(ctx.apk)} ${shQuote(file.path)}`)}`);
    const type = imageType(body);
    if (!type) return '';
    return `<image x="0" y="0" width="108" height="108" preserveAspectRatio="xMidYMid slice" href="data:${type};base64,${body.toString('base64')}"/>`;
  }
  if (/\.xml$/i.test(file.path) && depth <= 3) {
    const [tree] = await apkAaptDumps(ctx.apk, [file.path], [['xmltree', file.path]]);
    const root = parseXmlTree(tree);
    if (!root) return '';
    const inner = await drawableSvg(root, ctx, depth + 1);
    if (!inner) return '';
    return `<svg x="0" y="0" width="108" height="108" viewBox="0 0 ${inner.w} ${inner.h}">${inner.body}</svg>`;
  }
  return '';
}

/** An XML icon resource → a standalone SVG document, or null when it is not renderable. */
async function vectorIconSvg(apk: string, xmlPath: string): Promise<string | null> {
  const idx = await getResIndex(apk);
  if (!idx) return null;
  const [tree] = await apkAaptDumps(apk, [xmlPath], [['xmltree', xmlPath]]);
  const root = parseXmlTree(tree);
  if (!root) return null;
  const ctx: SvgCtx = { idx, apk, defs: [], clipSeq: 0, depth: 0 };
  const shape = await drawableSvg(root, ctx, 1);
  if (!shape || !shape.body) return null;
  const defs = ctx.defs.length ? `<defs>${ctx.defs.join('')}</defs>` : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${shape.w} ${shape.h}">${defs}${shape.body}</svg>`;
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

/** Device-rendered PNG via adh.device/1; falls back to host APK parsing when the
 *  persistent channel is down. 'none' from the device is authoritative — the
 *  package genuinely has no renderable icon (no fake robot fallback). */
async function resolveIcon(pkg: string): Promise<{ body: Buffer; type: string } | null> {
  const serial = deviceSerial();
  if (serial) {
    try {
      const icon = await deviceIcon(serial, pkg);
      if (icon === 'none') return null;
      if (icon) return { body: icon, type: imageType(icon) };
    } catch { /* channel error: fall back to host parsing */ }
  }
  return apkIcon(pkg);
}

/** The launcher bitmap named by aapt, not a foreground or monochrome layer. */
export async function readPackageIcon(pkg: string): Promise<{ body: Buffer; type: string } | null> {
  const hit = cache.get(pkg);
  if (hit && (hit.v || Date.now() - hit.at < NEG_TTL)) return hit.v;
  let job = inflight.get(pkg);
  if (!job) {
    job = resolveIcon(pkg).then(result => {
      cache.set(pkg, { at: Date.now(), v: result });
      return result;
    }).finally(() => inflight.delete(pkg));
    inflight.set(pkg, job);
  }
  return job;
}
