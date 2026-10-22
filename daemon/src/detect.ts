// Detection summary for the system-capture family (module V).
//
// The agent records ptrace / access / faccessat / property reads as text lines. This file
// turns those lines, plus detection-shaped file opens and a few Java hook hits, into the
// checklist the panel asks: debug, root, signature, emulator, integrity. It does not install
// anything by itself. Java hooks are a separate, caller-named plan.

import { appOwnedSoModules } from './so_select.ts';
import { modulesFromMaps, sendCmd as serviceSendCmd } from './service.ts';
import { capturePackage, captures as stateCaptures, sessions as stateSessions } from './state.ts';

export type DetectKind = 'debug' | 'root' | 'signature' | 'emulator' | 'integrity' | 'prop' | 'other';

export const DETECT_SYMBOLS = [
  'ptrace', 'access', 'faccessat', '__system_property_get', '__system_property_read_callback',
] as const;

const KIND_LABEL: { id: DetectKind; label: string; core: boolean }[] = [
  { id: 'debug', label: '反调试', core: true },
  { id: 'root', label: 'root / 框架', core: true },
  { id: 'signature', label: '签名', core: true },
  { id: 'emulator', label: '模拟器', core: true },
  { id: 'integrity', label: '完整性', core: true },
  { id: 'prop', label: '系统属性', core: false },
  { id: 'other', label: '其它路径', core: false },
];

export interface DetectRecord {
  id?: number;
  func: string;
  hex?: string;
  text?: string;
  tid?: number;
  ts?: number;
}

export interface DetectHit {
  kind: DetectKind;
  func: string;
  detail: string;
  ret?: string;
  lr?: string;
  id?: number;
  tid?: number;
  ts?: number;
}

export interface DetectSummary {
  armed: boolean | null;
  reason: string;
  caveat: string;
  unchecked: string[];
  kinds: { kind: DetectKind; label: string; count: number; examples: string[] }[];
  hits: DetectHit[];
}

const CAVEAT = '有些检测方式目前还看不到（例如应用直接读手机型号）。';

export function textOf(rec: { hex?: string; text?: string }): string {
  if (typeof rec.text === 'string') return rec.text;
  const hex = rec.hex ?? '';
  let s = '';
  for (let i = 0; i + 1 < hex.length; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16);
    if (!Number.isFinite(b)) break;
    s += String.fromCharCode(b);
  }
  return s;
}

function fieldsOf(text: string): Map<string, string> {
  const map = new Map<string, string>();
  if (text.includes('\t')) {
    for (const part of text.split('\t')) {
      const i = part.indexOf('=');
      if (i > 0) map.set(part.slice(0, i), part.slice(i + 1));
    }
    return map;
  }
  const req = text.match(/request=(\d+)/);
  if (req) map.set('request', req[1]);
  if (text.includes('PTRACE_TRACEME')) map.set('note', 'PTRACE_TRACEME');
  return map;
}

/** A path is a detection probe only when a path segment or a known filename says so. */
export function pathKind(path: string): DetectKind | null {
  const l = path.replace(/\\/g, '/').toLowerCase();
  if (/\/proc\/(self|\d+)\/status\b/.test(l) || l.includes('tracerpid')) return 'debug';
  if (/\/proc\/(self|\d+)\/(maps|smaps|map_files)\b/.test(l)) return 'integrity';
  if (l.includes('/proc/self/mounts') || l.includes('/proc/mounts') || l.includes('magisk')) return 'root';
  if (/(^|\/)su$/.test(l) || l.includes('/su/') || l.includes('supersu') || l.includes('superuser') || l.includes('daemonsu')) return 'root';
  if (l.includes('frida') || l.includes('xposed') || l.includes('substrate') || l.includes('libriru') || l.includes('zygisk')) return 'root';
  if (/goldfish|ranchu|genymotion|bluestacks|microvirt|qemu|vbox|nox/.test(l)) return 'emulator';
  return null;
}

function propKind(name: string, value: string): DetectKind {
  const n = name.trim();
  const v = value.toLowerCase();
  if (n === 'ro.kernel.qemu' || n === 'ro.hardware' || n.startsWith('ro.product.') || n === 'ro.build.fingerprint' || n === 'ro.boot.hardware') return 'emulator';
  if (n === 'ro.build.tags' || n === 'service.adb.root') return 'root';
  if (n === 'ro.debuggable' || n === 'ro.secure' || n === 'init.svc.adbd') return 'debug';
  if (n.startsWith('ro.boot.verifiedboot') || n.startsWith('ro.boot.vbmeta') || n === 'ro.boot.flash.locked') return 'integrity';
  if (/goldfish|ranchu|sdk_gphone|genymotion/.test(v)) return 'emulator';
  if (v.includes('test-keys')) return 'root';
  return 'prop';
}

function javaHit(text: string): { kind: DetectKind; detail: string } | null {
  if (!text.startsWith('{')) return null;
  let target = '';
  let arg = '';
  try {
    const o = JSON.parse(text) as { target?: unknown; arg?: unknown };
    target = String(o.target ?? '');
    arg = String(o.arg ?? '');
  } catch { return null; }
  if (/android\.os\.Debug\.(isDebuggerConnected|waitingForDebugger)\(/.test(target)) return { kind: 'debug', detail: target };
  if (/java\.lang\.Runtime\.exec\(/.test(target)) return { kind: 'root', detail: arg || target };
  if (/getPackageInfo\(/.test(target) || /checkSignatures\(/.test(target)) return { kind: 'signature', detail: target };
  if (/File\.exists\(/.test(target)) {
    const kind = pathKind(arg);
    return kind ? { kind, detail: arg } : null;
  }
  return null;
}

function oneHit(rec: DetectRecord, text: string): DetectHit | null {
  const func = rec.func || '';
  const f = fieldsOf(text);
  const base = { func, id: rec.id, tid: rec.tid, ts: rec.ts, lr: f.get('lr'), ret: f.get('ret') };
  if (func === 'ptrace') {
    const note = f.get('note') || (text.includes('PTRACE_TRACEME') ? 'PTRACE_TRACEME' : '');
    const req = f.get('request');
    const detail = note ? `ptrace ${note}${base.ret != null ? ' ret=' + base.ret : ''}` : `ptrace request=${req ?? '?'}${base.ret != null ? ' ret=' + base.ret : ''}`;
    return { ...base, kind: 'debug', detail };
  }
  if (func === 'JAVA_HOOK') {
    const hit = javaHit(text);
    return hit ? { ...base, kind: hit.kind, detail: hit.detail } : null;
  }
  if (func === 'sysprop' || func === 'propread' || func === '__system_property_get' || func === 'getprop') {
    const name = f.get('name') || (!text.includes('\t') && !text.includes('=') ? text : '');
    if (!name) return null;
    const value = f.get('value') ?? '';
    return { ...base, kind: propKind(name, value), detail: value ? `${name}=${value}` : name };
  }
  if (func === 'access' || func === 'faccessat' || func === 'open' || func === 'openat') {
    const path = f.get('path') || (!text.includes('=') ? text : '');
    if (!path) return null;
    const kind = pathKind(path);
    if (!kind && (func === 'open' || func === 'openat')) return null;
    const ret = base.ret != null ? ` ret=${base.ret}` : '';
    return { ...base, kind: kind ?? 'other', detail: path + ret };
  }
  return null;
}

export function summarizeDetection(records: readonly DetectRecord[], armed: boolean | null): DetectSummary {
  const counts = new Map<DetectKind, number>();
  const examples = new Map<DetectKind, string[]>();
  const hits: DetectHit[] = [];
  for (const rec of records) {
    const text = textOf(rec);
    const hit = oneHit(rec, text);
    if (!hit) continue;
    counts.set(hit.kind, (counts.get(hit.kind) ?? 0) + 1);
    const ex = examples.get(hit.kind) ?? [];
    if (ex.length < 3 && !ex.includes(hit.detail)) ex.push(hit.detail);
    examples.set(hit.kind, ex);
    hits.push(hit);
  }
  const kinds = KIND_LABEL.filter((k) => k.core || (counts.get(k.id) ?? 0) > 0).map((k) => ({
    kind: k.id,
    label: k.label,
    count: counts.get(k.id) ?? 0,
    examples: examples.get(k.id) ?? [],
  }));
  const unchecked = KIND_LABEL.filter((k) => k.core && (counts.get(k.id) ?? 0) === 0).map((k) => k.label);
  const total = hits.length;
  // Short labels (the Web summary line, 2026-10-20). `armed === null` means "no capture_start
  // reply seen yet" and used to fall through to an empty string, which made "we do not know"
  // indistinguishable from "nothing to say" for every consumer of this payload.
  let reason = '状态未知';
  if (armed === false) reason = '未开';
  else if (armed === true && total === 0) reason = '已开 · 暂无';
  else if (armed === true) reason = '已开';
  // The caveat stays on the payload even though the Web summary line no longer renders it: an MCP
  // consumer reading `detect_summary` still has to know what this view cannot see.
  return { armed, reason, caveat: CAVEAT, unchecked, kinds, hits: hits.slice(-40) };
}

/** True when a capture_start reply shows at least one system hook installed. null = no reply yet. */
export function sysHooksArmed(hooks: any): boolean | null {
  if (!hooks || typeof hooks !== 'object') return null;
  if (hooks.op === 'capture_stop') return false;
  const sys = hooks.sys;
  if (!sys || typeof sys !== 'object') return null;
  const keys = ['ptrace', 'access', 'faccessat', 'prop', 'propread'];
  if (!keys.some((k) => k in sys)) return null;
  return keys.some((k) => Number(sys[k]) > 0);
}

export function detectionReport(filter: { package?: string; session?: string } = {}): DetectSummary {
  const pkg = (filter.package ?? '').trim();
  const session = (filter.session ?? '').trim();
  const records = stateCaptures.filter((c) => {
    if (session && c.sessionId !== session) return false;
    if (pkg && capturePackage(c) !== pkg) return false;
    return true;
  });
  let armed: boolean | null = null;
  for (const s of stateSessions.values()) {
    if (session && s.sessionId !== session) continue;
    if (pkg && s.package !== pkg) continue;
    const one = sysHooksArmed(s.captureHooks);
    if (one === true) { armed = true; break; }
    if (one === false) armed = false;
  }
  return summarizeDetection(records, armed);
}

export interface DetectModuleInput {
  name: string;
  path: string;
  symbols: readonly string[];
  /** Packed relocation table: an empty symbol list is "could not read", not "imports nothing". */
  packed?: boolean;
}

export interface DetectModulePlan {
  ok: boolean;
  error?: string;
  sysModule: string;
  modules: { name: string; path: string; symbols: string[] }[];
  skippedPacked: string[];
  truncated: boolean;
}

const MODULE_CAP = 8;

export function selectDetectModules(modules: readonly DetectModuleInput[], packageName: string): DetectModulePlan {
  const pkg = packageName.trim();
  if (!pkg || pkg === '?') return { ok: false, error: 'need package', sysModule: '', modules: [], skippedPacked: [], truncated: false };
  const owned = new Set(appOwnedSoModules(modules, pkg).map((m) => m.path));
  const skippedPacked: string[] = [];
  const picked: { name: string; path: string; symbols: string[] }[] = [];
  for (const mod of modules) {
    if (!owned.has(mod.path)) continue;
    const symbols = DETECT_SYMBOLS.filter((s) => mod.symbols.includes(s));
    if (symbols.length === 0) {
      if (mod.packed) skippedPacked.push(mod.name);
      continue;
    }
    picked.push({ name: mod.name, path: mod.path, symbols: [...symbols] });
  }
  picked.sort((a, b) => a.name.localeCompare(b.name));
  const truncated = picked.length > MODULE_CAP;
  const kept = picked.slice(0, MODULE_CAP);
  return {
    ok: true,
    sysModule: kept.map((m) => m.name).join(','),
    modules: kept,
    skippedPacked,
    truncated,
  };
}

export type DetectSend = (session: string, op: string, args?: Record<string, unknown>, timeoutMs?: number) => Promise<any>;

export async function planDetectModules(session: string, packageName: string, send: DetectSend = serviceSendCmd): Promise<DetectModulePlan & { scanned: number; unreadable: { name: string; error: string }[] }> {
  const pkg = packageName.trim();
  if (!pkg || pkg === '?') return { ok: false, error: 'need package', sysModule: '', modules: [], skippedPacked: [], truncated: false, scanned: 0, unreadable: [] };
  const maps = await send(session, 'maps', {}, 30_000);
  const owned = appOwnedSoModules(modulesFromMaps(maps?.regions ?? []), pkg);
  owned.sort((a, b) => a.name.localeCompare(b.name));
  const scan = owned.slice(0, 16);
  const unreadable: { name: string; error: string }[] = [];
  const inputs: DetectModuleInput[] = [];
  for (const mod of scan) {
    try {
      const reply = await send(session, 'got_enum', { module: mod.name, filter: '' }, 20_000);
      const result = reply?.result ?? {};
      const entries = Array.isArray(result.entries) ? result.entries : [];
      if (reply?.ok === false) {
        unreadable.push({ name: mod.name, error: String(reply?.error ?? 'got_enum failed') });
        continue;
      }
      inputs.push({
        name: mod.name,
        path: mod.path,
        packed: result.packed === true,
        symbols: entries.map((e: { symbol?: string }) => String(e?.symbol ?? '')).filter(Boolean),
      });
    } catch (e) {
      unreadable.push({ name: mod.name, error: (e as Error).message });
    }
  }
  const plan = selectDetectModules(inputs, pkg);
  return { ...plan, truncated: plan.truncated || owned.length > scan.length, scanned: scan.length, unreadable };
}

export type DetectJavaFamily = 'debug' | 'root' | 'signature' | 'file';

export interface DetectJavaHook {
  family: DetectJavaFamily;
  className: string;
  method: string;
  params: string;
  hot?: boolean;
}

export const DETECT_JAVA: readonly DetectJavaHook[] = [
  { family: 'debug', className: 'android.os.Debug', method: 'isDebuggerConnected', params: '' },
  { family: 'debug', className: 'android.os.Debug', method: 'waitingForDebugger', params: '' },
  { family: 'root', className: 'java.lang.Runtime', method: 'exec', params: 'java.lang.String' },
  { family: 'signature', className: 'android.app.ApplicationPackageManager', method: 'getPackageInfo', params: 'java.lang.String,int' },
  { family: 'signature', className: 'android.app.ApplicationPackageManager', method: 'getPackageInfo', params: 'java.lang.String,android.content.pm.PackageManager$PackageInfoFlags' },
  { family: 'file', className: 'java.io.File', method: 'exists', params: '', hot: true },
];

const JAVA_FAMILIES = new Set<string>(['debug', 'root', 'signature', 'file']);

export function detectJavaPlan(families: readonly string[]): { ok: boolean; error?: string; hooks: DetectJavaHook[] } {
  const wanted = [...new Set(families.map((f) => String(f).trim()).filter(Boolean))];
  if (wanted.length === 0) return { ok: false, error: 'name at least one family: debug, root, signature, file', hooks: [] };
  const unknown = wanted.filter((f) => !JAVA_FAMILIES.has(f));
  if (unknown.length) return { ok: false, error: `unknown family: ${unknown.join(',')}`, hooks: [] };
  return { ok: true, hooks: DETECT_JAVA.filter((h) => wanted.includes(h.family)) };
}

export async function armDetectJava(session: string, families: readonly string[], confirm: boolean, send: DetectSend = serviceSendCmd): Promise<any> {
  const plan = detectJavaPlan(families);
  if (!confirm) return { ok: false, error: 'detect_java requires confirm:true', plan };
  if (!plan.ok) return { ok: false, error: plan.error, hooks: [] };
  const hookIds: number[] = [];
  const failed: { className: string; method: string; params: string; error: string }[] = [];
  for (const hook of plan.hooks) {
    try {
      const reply = await send(session, 'java_hook', {
        action: 'hook', className: hook.className, method: hook.method, params: hook.params,
        stack: 'true', skipOriginal: 'false', returnValue: '', argIndex: -1, argValue: '', hookId: 0, limit: 0,
      }, 30_000);
      const id = Number(reply?.hookId ?? reply?.id ?? 0);
      if (reply?.ok === false || !id) failed.push({ ...hook, error: String(reply?.error ?? 'java_hook did not return a hookId') });
      else hookIds.push(id);
    } catch (e) {
      failed.push({ className: hook.className, method: hook.method, params: hook.params, error: (e as Error).message });
    }
  }
  return {
    ok: failed.length === 0 && hookIds.length === plan.hooks.length,
    partial: failed.length > 0 && hookIds.length > 0,
    installed: hookIds.length,
    attempted: plan.hooks.length,
    hookIds,
    failed,
    hooks: plan.hooks,
    caveat: plan.hooks.some((h) => h.hot) ? 'File.exists runs on a hot path; unhook it when the check is done.' : CAVEAT,
  };
}
