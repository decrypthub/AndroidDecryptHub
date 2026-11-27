export interface DeviceBinding {serial:string;transportId:string;leaseId:string;process:{pid:number;uid:number;starttimeTicks:string;name:string}}
let scopeProvider:()=>{serial?:string;package?:string}=()=>({});
export function setApiScopeProvider(provider:typeof scopeProvider){scopeProvider=provider;}
export function scopeHeaders(path:string,headers?:HeadersInit,explicit?:{serial?:string;package?:string}):Headers{
  const h=new Headers(headers);
  // Global inventory must remain reachable when the selected phone has gone away.
  if(path==='/health'||path.startsWith('/api/devices?action='))return h;
  const scope=explicit??scopeProvider();
  if(scope.serial&&!h.has('x-adh-device-serial'))h.set('x-adh-device-serial',scope.serial);
  if(scope.package&&!h.has('x-adh-package'))h.set('x-adh-package',scope.package);
  return h;
}
// 端点封装 + 统一耗时统计。面板所有请求走 api()，自动进 perfStat。

export interface Cap {
  id: number; ts: number; category: string;displayId?:number;captureGeneration?:string;
  algo?: string; op?: string; func?: string; hook?: string; path?: string;
  preview?: string; inl?: number; outl?: number; out?: number;
  package?: string; sessionId?: string; deviceBinding?:DeviceBinding;
  keyHex?: string; ivHex?: string; outHex?: string;
  javaTarget?:string; javaTargetTruncated?:boolean; javaHookId?:number; captureMethodId?:string;
  inputBytesPresent?:boolean; inputScope?:string; recordSchema?:string; keyl?:number; ivl?:number;
  [k: string]: unknown;
}
export interface Session {
  sessionId: string; package: string; pid: number; online: boolean;
  deviceBinding?:DeviceBinding;
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

export async function api<T = unknown>(path: string, init?: RequestInit, timeoutMs = 8000, explicitScope?:{serial?:string;package?:string}): Promise<T> {
  const label = `${init?.method ?? 'GET'} ${path.split('?')[0]}`;
  const t0 = performance.now();
  try {
    const res = await fetch(path, { ...init, headers:scopeHeaders(path,init?.headers,explicitScope), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store' });
    if (!res.ok) {
      const data = await res.json().catch(() => null) as { error?: unknown } | null;
      const reason = typeof data?.error === 'string' ? data.error : '';
      throw new Error(reason || `${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  } finally {
    // HTTP 错误也只记一次；耗时覆盖响应体读取，失败时保留最近请求信息。
    const ms = performance.now() - t0;
    notePerf(label, ms); lastPerf = { label, ms, at: Date.now() };
  }
}
const post = <T = unknown>(path: string, body: unknown, timeoutMs?: number) =>
  api<T>(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, timeoutMs);
// POST where a non-2xx reply still carries the useful answer (the daemon puts the reason in
// `error`). api() throws on the status and loses it, which turns "unreadable at 0x…" into "502".
async function postDetail<T extends { error?: string }>(path: string, body: unknown, timeoutMs = 20000,extraHeaders?:HeadersInit): Promise<T> {
  const requestHeaders=new Headers(extraHeaders);requestHeaders.set('content-type','application/json');
  const t0 = performance.now();
  let res: Response;
  try {
    res = await fetch(path, {
      method: 'POST', headers: scopeHeaders(path,requestHeaders),
      body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store',
    });
  } catch (e) {
    notePerf(`POST ${path}`, performance.now() - t0);
    throw e;
  }
  notePerf(`POST ${path}`, performance.now() - t0);
  const data = await res.json().catch(() => null) as T | null;
  if (!data || typeof data !== 'object') throw new Error(`${res.status} ${res.statusText}`);
  return data;
}

// GET 版 postDetail：daemon 把原因放在 error 字段里（400/502/504 都带），
// api() 只抛状态码会把「agent 已断开」说成「502 Bad Gateway」。
async function getDetail<T extends { error?: string }>(path: string, timeoutMs = 12000): Promise<T> {
  const label = `GET ${path.split('?')[0]}`;
  const t0 = performance.now();
  let res: Response;
  try {
    res = await fetch(path, { headers:scopeHeaders(path), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store' });
  } catch (e) {
    notePerf(label, performance.now() - t0);
    throw e;
  }
  notePerf(label, performance.now() - t0);
  const data = await res.json().catch(() => null) as T | null;
  if (!data || typeof data !== 'object') throw new Error(`${res.status} ${res.statusText}`);
  return data;
}

// ---- 端点 ----
export const getDevices = () => api<{ ok: boolean; devices: unknown[]; transports: unknown[]; localUsb?: Record<string, unknown> }>('/api/devices?action=list');
export interface DeviceInfo {
  model: string; android: string; sdk: number; abi: string;
  ramBytes: number; storageFreeBytes: number; storageTotalBytes: number;
  screen: string; battery: number | null;
}
export const getDeviceInfo = (serial: string) =>
  api<{ ok: boolean; info?: DeviceInfo; error?: string }>(`/api/devices?action=info&serial=${encodeURIComponent(serial)}`);export const getHealth = () => api<{ ok: boolean; version?: string; panelProtocol?:number }>('/health');
export const getApps = () => api<{ ok: boolean; apps: AppInfo[]; error?: string; capture?: { enabled: boolean }; captureByPackage?: Record<string, unknown>; localObservation?: Record<string, unknown> }>('/api/apps');
export const getScope = () => api<{ ok: boolean; packages: string[];error?:string }>('/api/scope');
const scopeChange=(pkg:string,add:boolean,serial?:string)=>api('/api/scope',{method:'POST',headers:scopeHeaders('/api/scope',{'content-type':'application/json','x-adh-package':pkg},serial?{serial,package:pkg}:undefined),body:JSON.stringify(add?{add:[pkg]}:{remove:[pkg]})});
export const scopeAdd = (pkg: string,serial?:string) => scopeChange(pkg,true,serial);
export const scopeRemove = (pkg: string,serial?:string) => scopeChange(pkg,false,serial);
export const appControl = (pkg: string, action: string) => post('/api/apps/control', { package: pkg, action });
// 设备写操作走专用封装：服务器把失败原因（DEVICE_NOT_READY、缺少 bootstrap、手机不在线）
// 放在错误响应体的 error 字段，通用 api() 只抛 HTTP 状态会丢掉真实原因，toast 必须拿到它。
async function postDevice<T = unknown>(body: unknown, timeoutMs = 20000): Promise<T> {
  const t0 = performance.now();
  let res: Response;
  try {
    res = await fetch('/api/devices', {
      method: 'POST', headers: scopeHeaders('/api/devices',{'content-type':'application/json'},body as {serial?:string;package?:string}),
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
    method: 'POST', headers: scopeHeaders('/api/devices',{'content-type':'application/json'},body as {serial?:string;package?:string}),
    body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), cache: 'no-store',
  });
  const data = await res.json().catch(() => null) as ReconnectReply | null;
  if (!data || typeof data !== 'object') throw new Error(`${res.status} ${res.statusText}`);
  return { ...data, ok: data.ok === true && res.ok };
}
export const reconnectDevice = (serial: string) => deviceActionRaw({ action: 'reconnect', serial });
export const adbConnectDevice = (address: string) => deviceActionRaw({ action: 'adb-connect', address });

export interface CapturesQuery {
  history?:boolean;
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
  historyVersion?:number;generation?:string;scope?:{serial:string;package:string};archiveError?:string;
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
  if(opts.history)p.set('history','1');if(opts.maxId!=null)p.set('maxId',String(opts.maxId));
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
export const getCaptureDetail = (id: number, pkg?: string, serial?:string) =>
  api<Record<string, unknown>>(`/api/captures/${id}${pkg ? `?package=${encodeURIComponent(pkg)}` : ''}`,serial?{headers:scopeHeaders('/api/captures',undefined,{serial,package:pkg})}:undefined);
export const deleteCapture = (id: number, pkg?: string) =>
  post<{ ok?: boolean; error?: string }>(`/api/captures/${id}${pkg ? `?package=${encodeURIComponent(pkg)}` : ''}`, { action: 'delete' });
export const getExchanges = (pkg: string, range?: { history?:boolean;maxId?:number|null;beforeId?:number|null;limit?:number;fromTs?: number | null; toTs?: number | null }) => {
  const p = new URLSearchParams({ package: pkg });
  if(range?.history)p.set('history','1');
  for(const key of ['maxId','beforeId','limit'] as const)if(range?.[key]!=null)p.set(key,String(range[key]));
  if (range?.fromTs != null) p.set('fromTs', String(range.fromTs));
  if (range?.toTs != null) p.set('toTs', String(range.toTs));
  return api<{historyVersion?:number;generation?:string;nextBeforeId?:number|null;hasMore?:boolean;matched?:number;archiveError?:string; ok?: boolean; scope?:{serial:string|null;package:string|null};panelProtocol?:number;exchanges?: unknown[]; items?: unknown[]; http2Idle?: number; consumedIds?: number[] }>(`/api/http/exchanges?${p.toString()}`);
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

// ---- 内存映射：一次取全部区域 + 统计，筛选/排序/分页在面板本地做 ----
export interface MapsRegion { start: string; end: string; size: number; perms: string; offset: string; path: string }
export interface MapsStats {
  total: number; readable: number; writable: number; executable: number; writableExecutable: number;
  anonymous: number; anonymousExecutable: number; fileBacked: number;
  mappedBytes: number; executableBytes: number; anonymousExecutableBytes: number;
}
export interface MapsView {
  ok: boolean; total: number; regions: MapsRegion[]; stats: MapsStats;
  count?: number; truncated?: boolean; error?: string;
}
export const memoryMaps = (session: string) =>
  getDetail<MapsView>(`/api/memory/maps?session=${encodeURIComponent(session)}`, 20000);

export interface MemoryReadReply {
  ok: boolean; addr?: string; size?: number; requested?: number;
  short?: boolean; via?: string; b64?: string; error?: string;
}
export const memoryRead = (session: string, addr: string, size: number) =>
  postDetail<MemoryReadReply>('/api/memory/read', { session, addr, size }, 25000);

export interface MemoryDumpReply {
  ok?: boolean; sha256?: string; size?: number; requestedSize?: number; complete?: boolean;
  kind?: string; tag?: string; addr?: string; capturedAt?: number; dedup?: boolean;
  /** false = 内容与已有产物相同，没有新增「脱壳记录」行 */
  recorded?: boolean; error?: string;
}
export const memoryDump = (session: string, addr: string, size: number) => {
  // 转储按 1MB 分块读，超时要跟着大小走：默认 8s 会让 64MB 的转储先在客户端失败，
  // 而服务端其实还在正常读。tag=panel 让记录列表能把「面板转储」和模型的 memory_dump 分开。
  const budget = Math.min(600_000, 30_000 + Math.ceil(size / (1024 * 1024)) * 4_000);
  return postDetail<MemoryDumpReply>('/api/memory/dump', { session, addr, size, tag: 'panel' }, budget);
};
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

export interface CaptureControlsView {ok:boolean;serial:string;package:string;session:string|null;revision:number;config:any;history:any[];lastApplied:any;pending:boolean;foreignOwner:boolean;runtime:any;catalogs:any;control:{revision:number;epoch:number;hostEpoch:number;resource:string};saveControl?:{revision:number;epoch:number;hostEpoch:number;resource:string};lastIntent?:any}
export const getCaptureControls=(serial:string,pkg:string,session?:string)=>api<CaptureControlsView>('/api/capture/controls?'+new URLSearchParams({serial,package:pkg,...(session?{session}:{})}),{headers:{'x-adh-device-serial':serial,'x-adh-package':pkg}});
export async function writeCaptureControls(view:CaptureControlsView,action:'discover'|'save'|'apply',config?:unknown,confirmRisk=false){
 const control=action==='save'?(view.saveControl??view.control):view.control;
 const body={action,serial:view.serial,package:view.package,...(view.session?{session:view.session}:{}),expectedRevision:view.revision,runtimeToken:view.runtime?.token,config,confirmRisk,
 _operation:{expectedRevision:control.revision,controlEpoch:control.epoch,hostEpoch:control.hostEpoch,idempotencyKey:operationId(),timeoutMs:45000}};
 // Use the frozen view's target even if the user changes tabs before the request begins.
 return postDetail<any>('/api/capture/controls',body,50000,{'x-adh-device-serial':view.serial,'x-adh-package':view.package});
}

// randomUUID is secure-context-only in browsers; LAN HTTP still supports getRandomValues.
export function operationId():string {
 if(typeof globalThis.crypto?.randomUUID==='function')return crypto.randomUUID();
 if(typeof globalThis.crypto?.getRandomValues!=='function')throw new Error('浏览器缺少安全随机数，未提交操作');
 const b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
 const h=Array.from(b,n=>n.toString(16).padStart(2,'0')).join('');return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
}
export interface HostSettingsControl {resource:string;revision:number;epoch:number;hostEpoch:number}
export interface HostSettingsView {settings:Record<string,unknown>;control:HostSettingsControl}
let hostSettingsClient='';
async function hostSettingsRequest(path:string,init?:RequestInit) {
 if(!hostSettingsClient)hostSettingsClient=operationId();
 const headers=new Headers(init?.headers);headers.set('x-adh-client-id',hostSettingsClient);
 let response:Response,body:any;
 try{response=await fetch(path,{...init,headers,cache:'no-store',signal:AbortSignal.timeout(12000)});body=await response.json();}
 catch{throw Object.assign(new Error(init?.method==='POST'?'结果未确认；请刷新核查，不要直接重发导入。':'读取电脑端设置失败'),{uncertain:init?.method==='POST',code:'TRANSPORT_UNCONFIRMED'});}
 if(!response.ok||body?.ok===false)throw Object.assign(new Error(body?.error||'电脑端拒绝操作'),{code:body?.code??'REQUEST_FAILED',uncertain:body?.state==='unknown'});
 let control:any;try{control=JSON.parse(response.headers.get('x-adh-control')||'null');}catch{}
 return{body,control};
}
export async function getHostSettingsSnapshot():Promise<HostSettingsView>{
 const {body,control}=await hostSettingsRequest('/api/config');
 if(!control||control.resource!=='host'||!['revision','epoch','hostEpoch'].every(k=>Number.isSafeInteger(control[k])&&control[k]>=0))throw new Error('Host 未提供有效状态版本，不能安全导入');
 return{settings:body.settings,control:Object.freeze({...control})};
}
export async function exportHostSettings(){return(await hostSettingsRequest('/api/settings/export')).body;}
export async function importHostSettings(view:HostSettingsView,patch:Record<string,unknown>){
 const c=view.control;if(c.resource!=='host')throw new Error('设置目标不是电脑端，未导入');
 const operation={expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch,idempotencyKey:operationId()};
 // Use the version observed when the file was selected; never prepare/rebase/retry behind the user.
 return(await hostSettingsRequest('/api/settings/import',{method:'POST',headers:{'content-type':'application/json','x-adh-operation':JSON.stringify(operation)},body:JSON.stringify(patch)})).body;
}

export interface CapturePackage {package:string;lines:number;bytes:number;oldestTs:number;newestTs:number}
export const getCapturePackages=(serial:string)=>api<{packages:CapturePackage[]}>('/api/captures/packages',undefined,8000,{serial});

export const clearCaptureBoard=(pkg:string,kind:'crypto'|'system'|'net')=>post<{ok:boolean;generation:string;removed:number;kind:string}>('/api/captures/clear?package='+encodeURIComponent(pkg),{action:'clear-board',kind});
