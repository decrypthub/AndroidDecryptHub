// Detection summary for the system-capture family (module V).
//
// The agent records ptrace / access / faccessat / property reads as text lines. This file
// turns those lines, plus detection-shaped file opens and Java hook hits, into two answers:
//   1. 设备指纹 — what this app collects to fingerprint the device (identifier / deviceinfo),
//      the panel's 系统 tab primary question since 2026-11-27;
//   2. 反分析 — the debug / root / signature / emulator / integrity checklist (module V's
//      original framing, kept in the payload but no longer the panel's headline).
// It does not install anything by itself. Java hooks are a separate, caller-named plan.

import { appOwnedSoModules } from './so_select.ts';
import { modulesFromMaps, sendCmd as serviceSendCmd } from './service.ts';
import { capturePackage, captures as stateCaptures, sessions as stateSessions } from './state.ts';

export type DetectKind = 'identifier' | 'deviceinfo' | 'debug' | 'root' | 'signature' | 'emulator' | 'integrity' | 'prop' | 'other';

export const DETECT_SYMBOLS = [
  'ptrace', 'access', 'faccessat', '__system_property_get', '__system_property_read_callback',
] as const;

const KIND_LABEL: { id: DetectKind; label: string; core: boolean }[] = [
  { id: 'identifier', label: '设备标识', core: false },
  { id: 'deviceinfo', label: '设备信息', core: false },
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
  /** Stable fingerprint signal identity when this hit is fingerprint evidence:
   *  key    — dedupe key, e.g. "android_id", "imei", "prop:ro.product.model", "path:/proc/cpuinfo"
   *  label  — 白话信号名, e.g. "android_id", "IMEI", "ro.product.model"
   *  value  — the value actually collected, when observed (last non-empty wins in the summary) */
  fp?: { key: string; label: string; value?: string };
}

export interface FingerprintItem {
  key: string;
  label: string;
  kind: 'identifier' | 'deviceinfo';
  value?: string;
  reads: number;
  firstTs?: number;
  lastTs?: number;
  /** Which capture lanes saw it (sysprop / access / openat / JAVA_HOOK …). */
  sources: string[];
}

export interface DetectSummary {
  armed: boolean | null;
  reason: string;
  caveat: string;
  unchecked: string[];
  kinds: { kind: DetectKind; label: string; count: number; examples: string[] }[];
  hits: DetectHit[];
  fingerprint: { items: FingerprintItem[]; identifiers: number; info: number };
}

const CAVEAT = '有些采集方式目前还看不到（例如应用直接引用 Build.MODEL 等编译期内联常量，运行时不产生调用）。';

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

/** A path is a detection probe or a fingerprint read only when a path segment or a known
 *  filename says so. Fingerprint classification takes precedence for the identity/hardware
 *  files: an app reading /proc/cpuinfo or the NIC address is overwhelmingly collecting device
 *  fingerprint, even though the same files occasionally serve emulator checks. */
export function pathKind(path: string): DetectKind | null {
  const l = path.replace(/\\/g, '/').toLowerCase();
  // Fingerprint: stable identifiers first.
  if (/\/sys\/class\/net\/[^/]+\/address$/.test(l)) return 'identifier';   // interface MAC
  // Fingerprint: hardware/system inventory.
  if (/^\/proc\/(cpuinfo|meminfo|version|stat|uptime|partitions|diskstats|loadavg|devices)\b/.test(l)) return 'deviceinfo';
  if (l.startsWith('/sys/devices/system/cpu/')) return 'deviceinfo';
  if (/^\/proc\/net\/[^/]+$/.test(l)) return 'deviceinfo';
  if (l.startsWith('/sys/class/power_supply/')) return 'deviceinfo';
  if (/\/proc\/(self|\d+)\/status\b/.test(l) || l.includes('tracerpid')) return 'debug';
  if (/\/proc\/(self|\d+)\/(maps|smaps|map_files)\b/.test(l)) return 'integrity';
  if (l.includes('/proc/self/mounts') || l.includes('/proc/mounts') || l.includes('magisk')) return 'root';
  if (/(^|\/)su$/.test(l) || l.includes('/su/') || l.includes('supersu') || l.includes('superuser') || l.includes('daemonsu')) return 'root';
  if (l.includes('frida') || l.includes('xposed') || l.includes('substrate') || l.includes('libriru') || l.includes('zygisk')) return 'root';
  if (/goldfish|ranchu|genymotion|bluestacks|microvirt|qemu|vbox|nox/.test(l)) return 'emulator';
  return null;
}

/** Property classification. Order is the semantics:
 *  1. emulator only on STRONG signals (qemu-named keys, emulator-valued builds) — reading
 *     ro.product.model is overwhelmingly fingerprint collection, not an emulator check;
 *  2. fingerprint: stable identifiers, then hardware/system inventory;
 *  3. anti-analysis environment checks (root/debug/integrity). */
function propKind(name: string, value: string): DetectKind {
  const n = name.trim();
  const v = value.toLowerCase();
  if (n === 'ro.kernel.qemu' || n.startsWith('ro.kernel.qemu.')) return 'emulator';
  if (/goldfish|ranchu|sdk_gphone|genymotion|bluestacks|microvirt|nox|vbox/.test(v)) return 'emulator';
  if (n === 'ro.serialno' || n === 'ro.boot.serialno' || n === 'ro.ril.oem.serialno' || n === 'sys.serialno') return 'identifier';
  if (n.startsWith('ro.product.') || n === 'ro.hardware' || n === 'ro.boot.hardware' ||
      n === 'ro.build.fingerprint' || n === 'ro.build.display.id' || n.startsWith('ro.build.version.') ||
      n === 'ro.build.date' || n === 'net.hostname' || n === 'persist.sys.timezone' ||
      n.startsWith('persist.sys.locale') || n.startsWith('gsm.operator') || n.startsWith('gsm.sim.operator')) return 'deviceinfo';
  if (n === 'ro.build.tags' || n === 'service.adb.root') return 'root';
  if (n === 'ro.debuggable' || n === 'ro.secure' || n === 'init.svc.adbd') return 'debug';
  if (n.startsWith('ro.boot.verifiedboot') || n.startsWith('ro.boot.vbmeta') || n === 'ro.boot.flash.locked') return 'integrity';
  if (v.includes('test-keys')) return 'root';
  return 'prop';
}

type JavaHit = { kind: DetectKind; detail: string; fp?: { key: string; label: string; value?: string } };

/** Bounded value for a fingerprint detail line: the collected value matters, a 4 KB
 *  installed-package dump does not. Errors count as evidence too — a SecurityException
 *  still proves the app TRIED to read the identifier. */
function fpValue(ret: string, error: string): { text: string; value?: string } {
  const r = ret.trim();
  const e = error.trim();
  if (r && r !== 'null') return { text: r.length > 96 ? r.slice(0, 96) + '…' : r, value: r.length > 256 ? r.slice(0, 256) : r };
  if (e) return { text: e.length > 96 ? e.slice(0, 96) + '…' : e };
  return { text: 'null' };
}

/** The settings key out of a getString joined-argument line ("0=…ContentResolver@x, 1=android_id"). */
function settingsKeyOf(arg: string): string {
  const m = /(?:^|,\s*)1=([A-Za-z0-9_.]+)/.exec(arg);
  if (m) return m[1];
  // Single bare value happens only if the hook renders one argument — accept it as the key directly.
  const bare = /^[A-Za-z0-9_.]+$/.test(arg.trim()) ? arg.trim() : '';
  return bare;
}

function javaHit(text: string): JavaHit | null {
  if (!text.startsWith('{')) return null;
  let target = '';
  let arg = '';
  let ret = '';
  let error = '';
  try {
    const o = JSON.parse(text) as { target?: unknown; arg?: unknown; ret?: unknown; error?: unknown };
    target = String(o.target ?? '');
    arg = String(o.arg ?? '');
    ret = String(o.ret ?? '');
    error = String(o.error ?? '');
  } catch { return null; }

  // ---- 设备指纹：稳定标识符 ----
  const telephony = /android\.telephony\.TelephonyManager\.(getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number)\(([^)]*)\)/.exec(target);
  if (telephony) {
    const names: Record<string, [string, string]> = {
      getDeviceId: ['deviceid', 'deviceId'], getImei: ['imei', 'IMEI'], getMeid: ['meid', 'MEID'],
      getSubscriberId: ['imsi', 'IMSI'], getSimSerialNumber: ['simserial', 'SIM 序列号'], getLine1Number: ['phonenumber', '本机号码'],
    };
    const [key, label] = names[telephony[1]] ?? [telephony[1].toLowerCase(), telephony[1]];
    const v = fpValue(ret, error);
    return { kind: 'identifier', detail: `${label} = ${v.text}`, fp: { key, label, value: v.value } };
  }
  if (/android\.provider\.Settings\$(Secure|System|Global)\.getString\(/.test(target)) {
    const key = settingsKeyOf(arg);
    if (key !== 'android_id') return null;   // 其它设置项不是指纹证据，留在普通事件流
    const v = fpValue(ret, error);
    return { kind: 'identifier', detail: `android_id = ${v.text}`, fp: { key: 'android_id', label: 'android_id', value: v.value } };
  }
  if (/android\.net\.wifi\.WifiInfo\.getMacAddress\(/.test(target) || /java\.net\.NetworkInterface\.getHardwareAddress\(/.test(target)) {
    const v = fpValue(ret, error);
    return { kind: 'identifier', detail: `MAC = ${v.text}`, fp: { key: 'mac', label: 'MAC 地址', value: v.value } };
  }
  if (/ads\.identifier\.AdvertisingIdClient/.test(target) || /miitmdid|com\.bun\.|oaid/i.test(target)) {
    const v = fpValue(ret, error);
    return { kind: 'identifier', detail: `广告 ID = ${v.text}`, fp: { key: 'adid', label: '广告 ID', value: v.value } };
  }

  // ---- 设备指纹：硬件/环境清单 ----
  if (/getInstalledPackages\(|getInstalledApplications\(/.test(target)) {
    return { kind: 'deviceinfo', detail: '读取已安装应用列表', fp: { key: 'installedapps', label: '已安装应用列表' } };
  }
  if (/android\.hardware\.SensorManager\.getSensorList\(/.test(target)) {
    return { kind: 'deviceinfo', detail: '枚举传感器列表', fp: { key: 'sensors', label: '传感器列表' } };
  }

  // ---- 反分析 ----
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
    return hit ? { ...base, kind: hit.kind, detail: hit.detail, ...(hit.fp ? { fp: hit.fp } : {}) } : null;
  }
  if (func === 'sysprop' || func === 'propread' || func === '__system_property_get' || func === 'getprop') {
    const name = f.get('name') || (!text.includes('\t') && !text.includes('=') ? text : '');
    if (!name) return null;
    const value = f.get('value') ?? '';
    const kind = propKind(name, value);
    const fp = kind === 'identifier' || kind === 'deviceinfo'
      ? { key: `prop:${name}`, label: name, ...(value ? { value } : {}) }
      : undefined;
    return { ...base, kind, detail: value ? `${name}=${value}` : name, ...(fp ? { fp } : {}) };
  }
  if (func === 'access' || func === 'faccessat' || func === 'open' || func === 'openat') {
    const path = f.get('path') || (!text.includes('=') ? text : '');
    if (!path) return null;
    const kind = pathKind(path);
    if (!kind && (func === 'open' || func === 'openat')) return null;
    const ret = base.ret != null ? ` ret=${base.ret}` : '';
    const fp = kind === 'identifier' || kind === 'deviceinfo'
      ? { key: `path:${path}`, label: path }
      : undefined;
    return { ...base, kind: kind ?? 'other', detail: path + ret, ...(fp ? { fp } : {}) };
  }
  return null;
}

/** Aggregate hits into deduped fingerprint items: one row per signal, last non-empty value
 *  wins, read counts and first/last timestamps kept so the panel can answer "采了什么、
 *  采到没有、采了几次" without scrolling the raw timeline. */
function collectFingerprint(hits: readonly DetectHit[]): DetectSummary['fingerprint'] {
  const items = new Map<string, FingerprintItem>();
  for (const h of hits) {
    if (!h.fp || (h.kind !== 'identifier' && h.kind !== 'deviceinfo')) continue;
    const kind = h.kind as 'identifier' | 'deviceinfo';
    const cur = items.get(h.fp.key);
    if (!cur) {
      items.set(h.fp.key, {
        key: h.fp.key, label: h.fp.label, kind,
        ...(h.fp.value ? { value: h.fp.value } : {}),
        reads: 1, firstTs: h.ts, lastTs: h.ts, sources: h.func ? [h.func] : [],
      });
    } else {
      cur.reads++;
      if (h.ts != null) {
        if (cur.firstTs == null || h.ts < cur.firstTs) cur.firstTs = h.ts;
        if (cur.lastTs == null || h.ts > cur.lastTs) cur.lastTs = h.ts;
      }
      if (h.fp.value) cur.value = h.fp.value;
      if (h.func && !cur.sources.includes(h.func)) cur.sources.push(h.func);
    }
  }
  const list = [...items.values()].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'identifier' ? -1 : 1;
    return b.reads - a.reads;
  });
  return {
    items: list.slice(0, 80),
    identifiers: list.filter((i) => i.kind === 'identifier').length,
    info: list.filter((i) => i.kind === 'deviceinfo').length,
  };
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
  return { armed, reason, caveat: CAVEAT, unchecked, kinds, hits: hits.slice(-40), fingerprint: collectFingerprint(hits) };
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

export type DetectJavaFamily = 'debug' | 'root' | 'signature' | 'file' | 'fingerprint';

export interface DetectJavaHook {
  family: DetectJavaFamily;
  className: string;
  method: string;
  params: string;
  hot?: boolean;
  /** Optional hooks are expected to be absent on some targets/API levels (vendor SDKs,
   *  GMS-only classes). Their failure is reported but does not flip the arm verdict. */
  optional?: boolean;
}

const TM = 'android.telephony.TelephonyManager';
const PKG_FLAGS = 'android.content.pm.PackageManager$PackageInfoFlags';

export const DETECT_JAVA: readonly DetectJavaHook[] = [
  { family: 'debug', className: 'android.os.Debug', method: 'isDebuggerConnected', params: '' },
  { family: 'debug', className: 'android.os.Debug', method: 'waitingForDebugger', params: '' },
  { family: 'root', className: 'java.lang.Runtime', method: 'exec', params: 'java.lang.String' },
  { family: 'signature', className: 'android.app.ApplicationPackageManager', method: 'getPackageInfo', params: 'java.lang.String,int' },
  { family: 'signature', className: 'android.app.ApplicationPackageManager', method: 'getPackageInfo', params: `java.lang.String,${PKG_FLAGS}` },
  { family: 'file', className: 'java.io.File', method: 'exists', params: '', hot: true },
  // ---- fingerprint: stable identifiers. Overloads are listed one by one because java_hook
  // matches exact signatures; methods missing on the target's API level land in failed[]. ----
  { family: 'fingerprint', className: 'android.provider.Settings$Secure', method: 'getString', params: 'android.content.ContentResolver,java.lang.String' },
  { family: 'fingerprint', className: 'android.provider.Settings$System', method: 'getString', params: 'android.content.ContentResolver,java.lang.String' },
  { family: 'fingerprint', className: 'android.provider.Settings$Global', method: 'getString', params: 'android.content.ContentResolver,java.lang.String' },
  { family: 'fingerprint', className: TM, method: 'getDeviceId', params: '' },
  { family: 'fingerprint', className: TM, method: 'getDeviceId', params: 'int' },
  { family: 'fingerprint', className: TM, method: 'getImei', params: '' },
  { family: 'fingerprint', className: TM, method: 'getImei', params: 'int' },
  { family: 'fingerprint', className: TM, method: 'getMeid', params: '' },
  { family: 'fingerprint', className: TM, method: 'getMeid', params: 'int' },
  { family: 'fingerprint', className: TM, method: 'getSubscriberId', params: '' },
  { family: 'fingerprint', className: TM, method: 'getSimSerialNumber', params: '' },
  { family: 'fingerprint', className: TM, method: 'getLine1Number', params: '' },
  { family: 'fingerprint', className: 'android.net.wifi.WifiInfo', method: 'getMacAddress', params: '' },
  { family: 'fingerprint', className: 'java.net.NetworkInterface', method: 'getHardwareAddress', params: '' },
  // ---- fingerprint: hardware/environment inventory ----
  { family: 'fingerprint', className: 'android.app.ApplicationPackageManager', method: 'getInstalledPackages', params: 'int' },
  { family: 'fingerprint', className: 'android.app.ApplicationPackageManager', method: 'getInstalledPackages', params: PKG_FLAGS },
  { family: 'fingerprint', className: 'android.app.ApplicationPackageManager', method: 'getInstalledApplications', params: 'int' },
  { family: 'fingerprint', className: 'android.app.ApplicationPackageManager', method: 'getInstalledApplications', params: PKG_FLAGS },
  { family: 'fingerprint', className: 'android.hardware.SensorManager', method: 'getSensorList', params: 'int' },
  // GMS / vendor advertising-id classes are absent on most CN ROMs — optional on purpose.
  { family: 'fingerprint', className: 'com.google.android.gms.ads.identifier.AdvertisingIdClient$Info', method: 'getId', params: '', optional: true },
];

const JAVA_FAMILIES = new Set<string>(['debug', 'root', 'signature', 'file', 'fingerprint']);

export function detectJavaPlan(families: readonly string[]): { ok: boolean; error?: string; hooks: DetectJavaHook[] } {
  const wanted = [...new Set(families.map((f) => String(f).trim()).filter(Boolean))];
  if (wanted.length === 0) return { ok: false, error: 'name at least one family: debug, root, signature, file, fingerprint', hooks: [] };
  const unknown = wanted.filter((f) => !JAVA_FAMILIES.has(f));
  if (unknown.length) return { ok: false, error: `unknown family: ${unknown.join(',')}`, hooks: [] };
  return { ok: true, hooks: DETECT_JAVA.filter((h) => wanted.includes(h.family)) };
}

export async function armDetectJava(session: string, families: readonly string[], confirm: boolean, send: DetectSend = serviceSendCmd): Promise<any> {
  const plan = detectJavaPlan(families);
  if (!confirm) return { ok: false, error: 'detect_java requires confirm:true', plan };
  if (!plan.ok) return { ok: false, error: plan.error, hooks: [] };
  const hookIds: number[] = [];
  const failed: { className: string; method: string; params: string; error: string; optional?: boolean }[] = [];
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
      failed.push({ className: hook.className, method: hook.method, params: hook.params, error: (e as Error).message, ...(hook.optional ? { optional: true } : {}) });
    }
  }
  // Optional hooks (GMS advertising id, vendor SDK classes) are expected to be absent on some
  // targets: their failure is reported for transparency but does not flip the verdict. A
  // required hook that failed still means the plan is not fully live.
  const requiredTotal = plan.hooks.filter((h) => !h.optional).length;
  const requiredFailed = failed.filter((f) => !f.optional).length;
  const requiredInstalled = requiredTotal - requiredFailed;
  return {
    ok: requiredFailed === 0 && requiredInstalled === requiredTotal && hookIds.length > 0,
    partial: failed.length > 0 && hookIds.length > 0,
    installed: hookIds.length,
    attempted: plan.hooks.length,
    hookIds,
    failed,
    hooks: plan.hooks,
    caveat: plan.hooks.some((h) => h.hot) ? 'File.exists runs on a hot path; unhook it when the check is done.' : CAVEAT,
  };
}
