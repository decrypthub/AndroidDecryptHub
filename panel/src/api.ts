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
  size?: number; mtime?: number; mode?: string;
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
const post = <T = unknown>(path: string, body: unknown) =>
  api<T>(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

// ---- 端点 ----
export const getDevices = () => api<{ ok: boolean; devices: unknown[]; transports: unknown[]; localUsb?: Record<string, unknown> }>('/api/devices?action=list');
export const getApps = () => api<{ ok: boolean; apps: AppInfo[]; error?: string; capture?: { enabled: boolean }; captureByPackage?: Record<string, unknown>; localObservation?: Record<string, unknown> }>('/api/apps');
export const getScope = () => api<{ ok: boolean; packages: string[] }>('/api/scope');
export const scopeAdd = (pkg: string) => post('/api/scope', { add: [pkg] });
export const scopeRemove = (pkg: string) => post('/api/scope', { remove: [pkg] });
export const appControl = (pkg: string, action: string) => post('/api/apps/control', { package: pkg, action });
export const observePackage = (serial: string, pkg: string) =>
  post('/api/devices', { action: 'observe', serial, package: pkg });
export const disconnectDevice = (serial: string) => post('/api/devices', { action: 'disconnect', serial });

export const getCaptures = (pkg: string, since = 0, limit = 5000) =>
  api<{ ok: boolean; items: Cap[]; dropped?: number; complete?: boolean; latest?: number }>(
    `/api/captures?package=${encodeURIComponent(pkg)}&since=${since}&limit=${limit}`);
export const getCaptureDetail = (id: number) => api<Record<string, unknown>>(`/api/captures/${id}`);
export const getExchanges = (pkg: string) =>
  api<{ ok: boolean; items: unknown[] }>(`/api/http/exchanges?package=${encodeURIComponent(pkg)}`);
export const getDetectSummary = (pkg: string) =>
  api<Record<string, unknown>>(`/api/detect/summary?package=${encodeURIComponent(pkg)}`);
export const getDumpEvents = (pkg: string) =>
  api<{ ok: boolean; items: unknown[] }>(`/api/events?type=dump.new&limit=80&package=${encodeURIComponent(pkg)}`);

export const fsList = (pkg: string, path: string) =>
  api<{ ok: boolean; entries: FsEntry[]; limited?: boolean; error?: string }>(
    `/api/fs/list?package=${encodeURIComponent(pkg)}&path=${encodeURIComponent(path)}`);
export const fsRead = (pkg: string, path: string) =>
  post<{ ok: boolean; text?: string; base64?: string; size?: number; truncated?: boolean; binary?: boolean; error?: string }>(
    '/api/fs/read', { package: pkg, path });

export const getFamilies = (pkg: string) =>
  api<{ ok: boolean; package?: string; capture?: { enabled?: boolean; families?: Record<string, boolean> } }>(
    `/api/capture/families?package=${encodeURIComponent(pkg)}`);
export const setFamily = (pkg: string, family: string, enabled: boolean) =>
  post('/api/capture/families', { package: pkg, family, enabled });

export const unpackRun = (pkg: string) => post<{ ok: boolean; error?: string }>('/api/unpack/run', { package: pkg });
export const unpackInventory = (session: string) =>
  api<{ ok: boolean; loaded?: Array<{ name?: string; size?: number; savedSize?: number; sha256?: string; path?: string }>; packaged?: Array<{ name?: string; path?: string; size?: number; sha256?: string }>; error?: string }>(
    `/api/unpack/inventory?session=${encodeURIComponent(session)}`);
export const unpackHistory = (pkg: string) =>
  api<{ ok: boolean; items?: Array<Record<string, unknown>> }>(`/api/unpack/history?package=${encodeURIComponent(pkg)}`);
export const unpackPullSo = (pkg: string, path: string) =>
  post('/api/unpack/pull-so', { package: pkg, path });
export const unpackDumpSoOne = (pkg: string, name: string) =>
  post('/api/unpack/dump-so-one', { package: pkg, name });
export const dumpDownloadUrl = (sha: string) => `/api/dumps/download?sha=${encodeURIComponent(sha)}`;
export const appIconUrl = (pkg: string) => `/api/apps/icon?package=${encodeURIComponent(pkg)}`;
export const getConfig = () => api<Record<string, unknown>>('/api/config');
