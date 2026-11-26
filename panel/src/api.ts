// 端点封装 + 统一耗时统计。面板所有请求走 api()，自动进 perfStat。

export interface Cap {
  id: number; ts: number; category: string;
  algo?: string; op?: string; func?: string; hook?: string; path?: string;
  preview?: string; inl?: number; outl?: number; out?: number;
  package?: string; sessionId?: string;
  keyHex?: string; ivHex?: string; outHex?: string;
  [k: string]: unknown;
}
export interface Session {
  sessionId: string; package: string; pid: number; online: boolean;
  process?: string; mapsCount?: number; hello?: number; close?: number;
  [k: string]: unknown;
}
export interface FsEntry {
  name: string; path: string; type: 'd' | 'f' | 'l' | string;
  size?: number; mtime?: number; mode?: number;
}
export interface AppInfo { package: string; label?: string; system?: boolean; [k: string]: unknown }

export interface PerfSample { last: number; total: number; peak: number; n: number }
const perf = new Map<string, PerfSample>();
export function perfStats() { return perf; }
export function perfMs(label: string) { return perf.get(label)?.last ?? 0; }
export function perfReport() {
  return [...perf.entries()]
    .sort((a, b) => b[1].total - a[1].total)
    .map(([k, s]) => `${k}  last=${Math.round(s.last)}ms avg=${Math.round(s.total / s.n)}ms peak=${Math.round(s.peak)}ms n=${s.n}`);
}
if (typeof window !== 'undefined') (window as unknown as { perfReport: typeof perfReport }).perfReport = perfReport;

function notePerf(label: string, ms: number) {
  const s = perf.get(label) ?? { last: 0, total: 0, peak: 0, n: 0 };
  s.last = ms; s.total += ms; s.peak = Math.max(s.peak, ms); s.n++;
  perf.set(label, s);
}

let lastPerf = { label: '', ms: 0, at: 0 };
export function perfLast() { return lastPerf; }

export async function api<T = unknown>(path: string, init?: RequestInit, timeoutMs = 8000): Promise<T> {
  const label = `${init?.method ?? 'GET'} ${path.split('?')[0]}`;
  const t0 = performance.now();
  try {
    const res = await fetch(path, { ...init, signal: AbortSignal.timeout(timeoutMs), cache: 'no-store' });
    const ms = performance.now() - t0;
    notePerf(label, ms); lastPerf = { label, ms, at: Date.now() };
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  } catch (e) {
    notePerf(label, performance.now() - t0);
    throw e;
  }
}
const post = <T = unknown>(path: string, body: unknown, timeoutMs?: number) =>
  api<T>(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, timeoutMs);

// ---- 端点 ----
export const getDevices = () => api<{ ok: boolean; devices: unknown[]; transports: unknown[]; localUsb?: Record<string, unknown> }>('/api/devices?action=list');
export interface DeviceInfo {
  model: string; android: string; sdk: number; abi: string;
  ramBytes: number; storageFreeBytes: number; storageTotalBytes: number;
  screen: string; battery: number | null;
}
export const getDeviceInfo = (serial: string) =>
  api<{ ok: boolean; info?: DeviceInfo; error?: string }>(`/api/devices?action=info&serial=${encodeURIComponent(serial)}`);export const getHealth = () => api<{ ok: boolean; version?: string }>('/health');
export const getApps = () => api<{ ok: boolean; apps: AppInfo[]; error?: string; capture?: { enabled: boolean }; captureByPackage?: Record<string, unknown>; localObservation?: Record<string, unknown> }>('/api/apps');
export const getScope = () => api<{ ok: boolean; packages: string[] }>('/api/scope');
export const scopeAdd = (pkg: string) => post('/api/scope', { add: [pkg] });
export const scopeRemove = (pkg: string) => post('/api/scope', { remove: [pkg] });
export const appControl = (pkg: string, action: string) => post('/api/apps/control', { package: pkg, action });
// 设备写操作走专用封装：服务器把失败原因（DEVICE_NOT_READY、缺少 bootstrap、手机不在线）
// 放在错误响应体的 error 字段，通用 api() 只抛 HTTP 状态会丢掉真实原因，toast 必须拿到它。
async function postDevice<T = unknown>(body: unknown, timeoutMs = 20000): Promise<T> {
  const t0 = performance.now();
  let res: Response;
  try {
    res = await fetch('/api/devices', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store',
    });
  } catch (e) {
    notePerf('POST /api/devices', performance.now() - t0);
    throw e;
  }
  notePerf('POST /api/devices', performance.now() - t0);
  const data = await res.json().catch(() => null) as ({ ok?: boolean; error?: string } & T) | null;
  if (!res.ok || data?.ok === false) throw new Error(data?.error || `${res.status} ${res.statusText}`);
  return data as T;
}
export const observePackage = (serial: string, pkg: string) =>
  postDevice({ action: 'observe', serial, package: pkg });
export const connectDevice = (serial: string) =>
  postDevice<{ ok: boolean; serial: string; deviceId?: string }>({ action: 'connect', serial });
export const disconnectDevice = (serial: string) =>
  postDevice<{ ok: boolean; serial: string; dropped?: boolean }>({ action: 'disconnect', serial });

export interface ReconnectReply {
  ok: boolean; serial: string; link: 'usb' | 'adb-tcp' | null; reverse: 'present' | 'added' | 'skipped';
  rpc: boolean; deviceId?: string;
  agent?: { online: boolean; pid: number; sessionId: string; waitedMs: number };
  warnings: string[]; code?: string; error?: string; elapsedMs: number;
}
// 重连失败也带着分层的诊断（哪一层没通、为什么），所以这里不按 HTTP 状态抛错，
// 让调用方能显示完整原因；真正的网络错误仍然抛。
async function deviceActionRaw(body: unknown, timeoutMs = 25000): Promise<ReconnectReply> {
  const res = await fetch('/api/devices', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store',
  });
  const data = await res.json().catch(() => null) as ReconnectReply | null;
  if (!data || typeof data !== 'object') throw new Error(`${res.status} ${res.statusText}`);
  return { ...data, ok: data.ok === true && res.ok };
}
export const reconnectDevice = (serial: string) => deviceActionRaw({ action: 'reconnect', serial });
export const adbConnectDevice = (address: string) => deviceActionRaw({ action: 'adb-connect', address });

export interface CapturesQuery {
  package: string;
  since?: number;
  beforeId?: number | null;
  fromTs?: number | null;
  toTs?: number | null;
  category?: string;
  q?: string;
  limit?: number;
}
export interface CapturesReply {
  ok?: boolean;
  captures?: Cap[];
  items?: Cap[];
  dropped?: number;
  complete?: boolean;
  latest?: number;
  latestId?: number | null;
  oldestId?: number | null;
  nextBeforeId?: number | null;
  hasMore?: boolean;
  returned?: number;
  total?: number;
  /** 当前筛选在保留窗口内命中的总条数（分页游标不影响它），用于「共 N 条」 */
  matched?: number;
}

export const getCaptures = (q: CapturesQuery | string, since = 0, limit = 1000) => {
  const opts: CapturesQuery = typeof q === 'string' ? { package: q, since, limit } : q;
  const p = new URLSearchParams();
  if (opts.package) p.set('package', opts.package);
  if (opts.since) p.set('since', String(opts.since));
  if (opts.beforeId != null) p.set('beforeId', String(opts.beforeId));
  if (opts.fromTs != null) p.set('fromTs', String(opts.fromTs));
  if (opts.toTs != null) p.set('toTs', String(opts.toTs));
  if (opts.category) p.set('category', opts.category);
  if (opts.q) p.set('q', opts.q);
  p.set('limit', String(opts.limit ?? 200));
  return api<CapturesReply>(`/api/captures?${p.toString()}`);
};
export const getCaptureDetail = (id: number, pkg?: string) =>
  api<Record<string, unknown>>(`/api/captures/${id}${pkg ? `?package=${encodeURIComponent(pkg)}` : ''}`);
export const deleteCapture = (id: number, pkg?: string) =>
  post<{ ok?: boolean; error?: string }>(`/api/captures/${id}${pkg ? `?package=${encodeURIComponent(pkg)}` : ''}`, { action: 'delete' });
export const getExchanges = (pkg: string, range?: { fromTs?: number | null; toTs?: number | null }) => {
  const p = new URLSearchParams({ package: pkg });
  if (range?.fromTs != null) p.set('fromTs', String(range.fromTs));
  if (range?.toTs != null) p.set('toTs', String(range.toTs));
  return api<{ ok?: boolean; exchanges?: unknown[]; items?: unknown[]; http2Idle?: number; consumedIds?: number[] }>(`/api/http/exchanges?${p.toString()}`);
};
export const getDetectSummary = (pkg: string) =>
  api<Record<string, unknown>>(`/api/detect/summary?package=${encodeURIComponent(pkg)}`);
export const getDumpEvents = (pkg: string) =>
  api<{ ok?: boolean; events?: Array<Record<string, unknown>>; items?: Array<Record<string, unknown>> }>(
    `/api/events?type=dump.new&limit=80&package=${encodeURIComponent(pkg)}`);

export const fsList = (pkg: string, path: string) =>
  api<{ ok: boolean; entries: FsEntry[]; limited?: boolean; error?: string }>(
    `/api/fs/list?package=${encodeURIComponent(pkg)}&path=${encodeURIComponent(path)}`);
export const fsRead = (pkg: string, path: string) =>
  post<{ ok: boolean; text?: string; b64?: string; base64?: string; size?: number; fsize?: number; truncated?: boolean; binary?: boolean; error?: string }>(
    '/api/fs/read', { package: pkg, path });

export const getFamilies = (pkg: string) =>
  api<{ ok: boolean; package?: string; capture?: { enabled?: boolean; families?: Record<string, boolean> } }>(
    `/api/capture/families?package=${encodeURIComponent(pkg)}`);
export const setFamily = (pkg: string, family: string, enabled: boolean) =>
  post('/api/capture/families', { package: pkg, family, enabled });

export const unpackRun = (pkg: string) =>
  post<{ ok: boolean; error?: string; included?: unknown[]; runId?: string }>('/api/unpack/run', { package: pkg }, 150_000);
export const unpackInventory = (session: string) =>
  api<{ ok: boolean; loaded?: Array<{ name?: string; size?: number; savedSize?: number; sha256?: string; path?: string; base?: string }>; packaged?: Array<{ name?: string; path?: string; size?: number; sha256?: string }>; error?: string }>(
    `/api/unpack/inventory?session=${encodeURIComponent(session)}`);
export const unpackHistory = (pkg: string) =>
  api<{ ok?: boolean; runs?: Array<Record<string, unknown>>; records?: Array<Record<string, unknown>>; items?: Array<Record<string, unknown>> }>(
    `/api/unpack/history?package=${encodeURIComponent(pkg)}`);
export const unpackPullSo = (pkg: string, path: string) =>
  post('/api/unpack/pull-so', { package: pkg, path });
export const unpackDumpSoOne = (session: string, base: string, name: string) =>
  post('/api/unpack/dump-so-one', { session, base, name });
export const dumpDownloadUrl = (sha: string, name?: string) =>
  `/api/dumps/download?sha=${encodeURIComponent(sha)}${name ? `&name=${encodeURIComponent(name)}` : ''}`;
export const moduleWatch = (session: string, action: 'start' | 'stop' | 'status' | 'list', limit = 100) =>
  post<{ ok?: boolean; watching?: boolean; installed?: boolean; error?: string; count?: number; modules?: ModuleLoadRec[] }>(
    '/api/module/watch', { session, action, limit });
export interface ModuleLoadRec {
  path?: string; handle?: string; base?: string; size?: number; mapped?: boolean;
  at?: number; captureId?: number; unparsed?: string;
}
export const appIconUrl = (pkg: string, serial?: string, version?: unknown) =>
  `/api/apps/icon?package=${encodeURIComponent(pkg)}${serial ? `&serial=${encodeURIComponent(serial)}` : ''}${version ? `&v=${encodeURIComponent(String(version))}` : ''}`;
export const getConfig = () => api<{ settings?: { capture?: { retain?: number; maxAgeDays?: number }; ui?: { displayCap?: number } } }>('/api/config');
