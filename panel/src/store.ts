// 全局响应式状态。防丢语义（历史三修，勿回退）：
//  1. 记录归属按包名 stamp，不绑会话存活——会话剪枝后旧记录仍在。
//  2. capItems 只在「设备+包身份」真变时清空——应用启停、轮询失败不触发。
//  3. 读失败 ≠ 设备没了——catch 保旧数据标 failed，等下次成功轮判定生死。
import { reactive, computed, watch } from 'vue';
import * as A from './api';
import { recordVisible } from './observations';

export interface DeviceAgent { online: boolean; pid: number; sessionId: string; lastSeen?: number; version?: string }

export interface DeviceView {
  key: string; serial: string; model: string; state: string;
  link: string; observed?: string; online: boolean | null; failed?: boolean;
  appSession?: string | null;
  // adh.device/1 RPC 通道在线（或有建立中的连接），只有真实 transport 行才带这个字段
  rpc?: boolean;
  // 网络串号（host:port，无线调试）；USB 序列号没有这个标志
  net?: boolean;
  // 只有观察设备有 agent 会话，其它设备如实为空
  agent?: DeviceAgent | null;
  // 面板本地清单：显示名 / 是否记住 / 是否默认 / 上次见到的时间
  name?: string;
  remembered?: boolean;
  seenAt?: number;
}

/** 面板本地设备清单（localStorage）：只存显示名/默认/记住时间，权威状态一律来自 daemon。 */
export interface DevicePref { name?: string; default?: boolean; rememberedAt?: number; lastSeenAt?: number }

// 本地设备清单的存储键必须早于 store 初始化：loadDevicePrefs 在 reactive(store) 里同步调用，
// 键放在后面会落进 TDZ，被 catch 吞成空对象（命名/默认在刷新后丢失）。
const DEVICE_PREFS_KEY = 'adh.devices.v1';

export const CAP_BUFFER_LIMIT = 4500;
const BUCKET_LIMIT = 1500;

function bucketOf(cat: string): 'crypto' | 'net' | 'system' {
  if (cat === 'crypto') return 'crypto';
  if (cat === 'net') return 'net';
  return 'system';
}

export const store = reactive({
  // 连接
  wsState: 'off' as 'off' | 'live' | 'fail',
  // 列表初始加载中（列表只切加载光标、不铺骨架；分页加载走各自面板的 pageLoading）
  capLoading: false,
  // 设备
  devices: [] as DeviceView[],
  devicePrefs: loadDevicePrefs() as Record<string, DevicePref>,
  localUsb: null as Record<string, unknown> | null,
  devicesFailed: false,
  devicesUpdated: 0,
  // 应用
  apps: [] as A.AppInfo[],
  appsError: '',
  appsFailed: false,
  captureEnabled: false,
  scope: new Set<string>(),
  // 会话
  sessions: new Map<string, A.Session>(),
  sessionPkg: new Map<string, string>(),
  // 选择（设备+包身份；应用启停不动它）
  chosenPkg: '',
  selectedDeviceKey: '',
  // 记录
  capItems: [] as A.Cap[],
  capDropped: 0,
  capComplete: true,
  capLatest: 0,
  capHasOlder: { crypto: false, system: false, net: false },
  // 服务端「保留窗口内命中多少条」——页脚显示共 N 条，而不是把当前页当全部
  capTotal: { crypto: 0, system: 0, net: 0 },
  // 视图
  view: 'cc' as 'cc' | 'sy' | 'nt' | 'files' | 'dump' | 'settings',
  appDialogOpen: false,
  hookSource: null as null | {serial:string;package:string;methodId?:string;recordId?:number;session?:string;feature?:string;returnView:'cc'|'sy'|'nt'},
});

// Target selection belongs to this tab. Historical captures carry their own immutable proof.
export function selectedSerial():string{return store.devices.find(d=>d.key===store.selectedDeviceKey)?.serial??'';}
export function targetKey():string{return selectedSerial()+'\n'+store.chosenPkg;}
A.setApiScopeProvider(()=>({serial:selectedSerial()||undefined,package:store.chosenPkg||undefined}));
export function belongsToApp(c:A.Cap):boolean{
  const serial=selectedSerial();
  return !!serial&&!!store.chosenPkg&&c.deviceBinding?.serial===serial&&c.package===store.chosenPkg;
}
function stampSession(s: A.Session) {
  if (s.sessionId && s.package) store.sessionPkg.set(s.sessionId, s.package);
}

// ---- 记录（按板块独立限额淘汰，防止高频加解密把网络/系统记录挤空）----
export function capPush(c: A.Cap) {
  if(!belongsToApp(c))return;
  if (c.sessionId && c.package) store.sessionPkg.set(c.sessionId, c.package);
  store.capItems.push(c);
  const b = bucketOf(c.category);
  let cnt = 0;
  for (let i = store.capItems.length - 1; i >= 0; i--) {
    if (bucketOf(store.capItems[i].category) !== b) continue;
    cnt++;
    if (cnt > BUCKET_LIMIT) {
      store.capItems.splice(i, 1);
      store.capHasOlder[b] = true;
    }
  }
}
/** 清空显示：只从内存列表移除匹配记录，不动 daemon/disk。 */
export function capRemoveWhere(fn: (c: A.Cap) => boolean): number {
  const before = store.capItems.length;
  for (let i = store.capItems.length - 1; i >= 0; i--) if (fn(store.capItems[i])) store.capItems.splice(i, 1);
  return before - store.capItems.length;
}

// ---- toast ----
export const toasts = reactive<{ id: number; text: string }[]>([]);
let toastSeq = 0;
export function toast(text: string) {
  const id = ++toastSeq;
  toasts.push({ id, text });
  setTimeout(() => { const i = toasts.findIndex(t => t.id === id); if (i >= 0) toasts.splice(i, 1); }, 2600);
}
export async function capLoad() {
  const pkg = store.chosenPkg,key=targetKey();
  if (!pkg) { store.capItems = []; return; }
  store.capLoading = true;
  try {
    const [rc, rs, rn] = await Promise.all([
      A.getCaptures({ package: pkg, category: 'crypto', limit: 600 }),
      A.getCaptures({ package: pkg, category: 'system,file', limit: 600 }),
      A.getCaptures({ package: pkg, category: 'net', limit: 400 }),
    ]);
    if (targetKey() !== key) return;
    const byId = new Map<number, A.Cap>();
    for (const r of [rc, rs, rn]) {
      for (const c of (r.captures ?? r.items ?? [])) {
        if(belongsToApp(c))byId.set(c.id, c);
        if (c.sessionId && c.package) store.sessionPkg.set(c.sessionId, c.package);
      }
    }
    // 合并这期间通过 WebSocket 新推上来的记录，避免初始请求往返期间丢尾部
    for (const c of store.capItems) {
      if (belongsToApp(c)) byId.set(c.id, c);
    }
    const merged = [...byId.values()].sort((a, b) => a.id - b.id);
    store.capItems = merged;
    store.capHasOlder.crypto = !!rc.hasMore;
    store.capHasOlder.system = !!rs.hasMore;
    store.capHasOlder.net = !!rn.hasMore;
    // 共 N 条 = 服务端按同一筛选算出的命中数（分页游标不影响），拿不到时退回本页长度
    const pageCount = (r: A.CapturesReply) => (r.captures ?? r.items ?? []).length;
    store.capTotal.crypto = rc.matched ?? rc.total ?? pageCount(rc);
    store.capTotal.system = rs.matched ?? rs.total ?? pageCount(rs);
    store.capTotal.net = rn.matched ?? rn.total ?? pageCount(rn);
    store.capDropped = rc.dropped ?? rs.dropped ?? 0;
    store.capComplete = rc.complete !== false;
    store.capLatest = merged.at(-1)?.id ?? 0;
  } catch {
    // 网络瞬断保旧数据，绝不把已有列表洗成空数组
  } finally {
    if (targetKey() === key) store.capLoading = false;
  }
}

// 只按包名切作用域：临时传输层 key 波动不清空当前应用已加载的数据。
let lastLoadedPkg = '';
export async function syncCapScope() {
  const key=targetKey();if(key===lastLoadedPkg)return;
  lastLoadedPkg=key;
  store.capItems=[];store.capLatest=0;store.capDropped=0;store.capComplete=true;
  store.capTotal={crypto:0,system:0,net:0};store.capHasOlder={crypto:false,system:false,net:false};
  if(!selectedSerial()||!store.chosenPkg){store.capLoading=false;return;}
  await capLoad();
}

// ---- 设备清单（localStorage，仅当前浏览器）：命名、默认设备、记住但暂时没插的设备 ----
export function loadDevicePrefs(): Record<string, DevicePref> {
  try {
    const raw = JSON.parse(localStorage.getItem(DEVICE_PREFS_KEY) ?? '{}') as unknown;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
    const out: Record<string, DevicePref> = {};
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (!key || typeof value !== 'object' || value === null) continue;
      const row = value as Record<string, unknown>;
      out[key] = {
        ...(typeof row.name === 'string' && row.name.trim() ? { name: row.name.trim().slice(0, 40) } : {}),
        ...(row.default === true ? { default: true } : {}),
        ...(typeof row.rememberedAt === 'number' && Number.isFinite(row.rememberedAt) ? { rememberedAt: row.rememberedAt } : {}),
        ...(typeof row.lastSeenAt === 'number' && Number.isFinite(row.lastSeenAt) ? { lastSeenAt: row.lastSeenAt } : {}),
      };
    }
    return out;
  } catch { return {}; }
}
// 多标签同时开会各持一份内存快照；整份覆盖写回会把另一个标签新加的设备冲掉
// （实测：A 页添加设备后，B 页下一次轮询把 localStorage 写回旧清单）。
// 所以写盘前先读磁盘合并；忘记设备则显式从磁盘删除。
function persistDevicePrefs(mode: 'merge' | 'remove' = 'merge', removedKey?: string) {
  try {
    const disk = loadDevicePrefs();
    let next: Record<string, DevicePref>;
    if (mode === 'remove' && removedKey) {
      delete disk[removedKey];
      next = { ...disk };
      for (const [key, pref] of Object.entries(store.devicePrefs)) if (key !== removedKey) next[key] = pref;
    } else {
      next = { ...disk, ...store.devicePrefs };
    }
    store.devicePrefs = next;
    localStorage.setItem(DEVICE_PREFS_KEY, JSON.stringify(next));
  } catch { /* 仅本会话 */ }
}
export function devicePref(key: string): DevicePref { return store.devicePrefs[key] ?? {}; }
/** 显示名：用户命名优先，其次型号，最后串号。 */
export function deviceLabel(d: DeviceView): string {
  const label=d.name||d.model||d.serial;
  const duplicates=store.devices.filter(other=>(other.name||other.model||other.serial)===label&&other.serial!==d.serial);
  if(!duplicates.length)return label;
  const tail=d.serial.slice(-4),suffix=duplicates.some(other=>other.serial.slice(-4)===tail)?d.serial:tail;
  return `${label} · ${suffix}`;
}
export function rememberDevice(key: string, name?: string) {
  const current = devicePref(key);
  const clean = (name ?? '').trim().slice(0, 40);
  store.devicePrefs[key] = { ...current, ...(clean ? { name: clean } : {}), rememberedAt: current.rememberedAt ?? Date.now() };
  persistDevicePrefs();
  void refreshDevices();
}
export function renameDevice(key: string, name: string) {
  const current = devicePref(key);
  const clean = name.trim().slice(0, 40);
  store.devicePrefs[key] = { ...current, name: clean, rememberedAt: current.rememberedAt ?? Date.now() };
  persistDevicePrefs();
  void refreshDevices();
}
export function forgetDevice(key: string) {
  delete store.devicePrefs[key];
  persistDevicePrefs('remove', key);
  void refreshDevices();
}

// ---- 设备轮询：失败保旧值 ----
export async function refreshDevices() {
  try {
    const r = await A.getDevices();
    const transports = (r.transports ?? []) as Array<Record<string, unknown>>;
    const usb = r.localUsb ?? null;
    const live: DeviceView[] = transports.map(t => ({
      key: String(t.serial ?? ''),
      serial: String(t.serial ?? ''),
      model: String(t.model ?? t.serial ?? ''),
      state: String(t.state ?? ''),
      link: String(t.link ?? ''),
      observed: t.observed === true ? (usb?.observedPackage as string | undefined) : (typeof t.observed === 'string' ? t.observed : undefined),
      online: t.online as boolean | null,
      rpc: t.rpc === true,
      net: t.net === true || String(t.serial ?? '').includes(':'),
      agent: t.agent && typeof t.agent === 'object' ? (t.agent as DeviceAgent) : null,
    }));
    store.localUsb = usb;
    // 本地观察模式：transports 为空时 localUsb 自己当设备行
    if (usb && !live.length) {
      live.push({
        key: String(usb.transport ?? 'usb'), serial: String(usb.transport ?? 'usb'),
        model: String(usb.model ?? '本地设备'), state: String(usb.linkState ?? ''),
        link: String(usb.transport ?? 'usb'),
        observed: usb.observedPackage as string | undefined,
        online: usb.online as boolean | null,
        appSession: usb.appSession as string | null,
      });
    }
    // 合并本地清单：命名/默认/上次在线，以及「记住但现在没插」的设备
    const now = Date.now();
    let prefsDirty = false;
    for (const device of live) {
      const pref = store.devicePrefs[device.key];
      if (!pref) continue;
      device.name = pref.name;
      device.remembered = true;
      device.seenAt = pref.lastSeenAt;
      // 见到即刷新，但每分钟最多写一次，避免每次轮询都写 localStorage
      if (!pref.lastSeenAt || now - pref.lastSeenAt > 60_000) {
        store.devicePrefs[device.key] = { ...pref, lastSeenAt: now };
        prefsDirty = true;
      }
    }
    for (const [key, pref] of Object.entries(store.devicePrefs)) {
      if (!pref.rememberedAt || live.some(d => d.key === key)) continue;
      live.push({ key, serial: key, model: '', state: 'disconnected', link: '', online: false, rpc: false,
        net: key.includes(':'), name: pref.name, remembered: true, seenAt: pref.lastSeenAt });
    }
    store.devices = live;
    if (prefsDirty) persistDevicePrefs();
    store.devicesFailed = false;
    store.devicesUpdated = now;
    if (!store.selectedDeviceKey || !store.devices.some(d => d.key === store.selectedDeviceKey)) {
      // 默认选中本机观察的那台；没有就取第一台（不再维护单独的「默认设备」偏好）
      const pick = store.devices.find(d => d.observed) ?? store.devices[0];
      if (pick) selectDevice(pick.key);
    }
  } catch {
    store.devicesFailed = true; // 保旧列表，只标失败
  }
}

const chosenByDevice=new Map<string,string>();
export function selectDevice(key: string) {
  if (store.selectedDeviceKey === key) return;
  if(store.selectedDeviceKey)chosenByDevice.set(store.selectedDeviceKey,store.chosenPkg);
  store.selectedDeviceKey = key;
  const dev = store.devices.find(d => d.key === key);
  store.chosenPkg=chosenByDevice.get(key)??dev?.observed??'';
  store.apps=[];store.appsError='';store.scope=new Set();
  void refreshApps();void refreshScope();
  void syncCapScope();
}

export function choosePackage(pkg: string) {
  if (store.chosenPkg === pkg) return;
  store.chosenPkg = pkg;
  void syncCapScope();
}

// ---- 应用列表：失败保旧值（scope 涉及手机 su 读盘，只在打开应用弹窗或设置页时拉取）----
export async function refreshScope() {
  const key=targetKey();if(!selectedSerial())return;
  try {
    const s = await A.getScope();
    if (targetKey()!==key)return;
    if (s.ok) store.scope = new Set(s.packages);
  } catch { /* scope 读取失败不遮罩主流程 */ }
}

export async function refreshApps() {
  const key=targetKey();if(!selectedSerial())return;
  try {
    const r = await A.getApps();
    if(targetKey()!==key)return;
    store.apps = r.apps ?? [];
    store.appsError = r.error ?? '';
    store.captureEnabled = r.capture?.enabled !== false;
    store.appsFailed = false;
  } catch {
    if(targetKey()===key)store.appsFailed = true;
  }
}

watch(() => store.appDialogOpen, open => { if (open) void refreshScope(); });
watch(() => store.view, v => { if (v === 'settings') void refreshScope(); });

// ---- WebSocket ----
let ws: WebSocket | null = null;
let wsRetry = 0;
export function connectWs() {
  const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
  try { ws?.close(); } catch { /* noop */ }
  ws = new WebSocket(url);
  ws.onopen = () => { store.wsState = 'live'; wsRetry = 0; void refreshApps(); };
  ws.onclose = () => {
    store.wsState = 'off';
    setTimeout(connectWs, Math.min(1500 * ++wsRetry, 8000));
  };
  ws.onerror = () => { store.wsState = 'fail'; };
  ws.onmessage = ev => {
    let m: { type?: string; event?: string; data?: unknown };
    try { m = JSON.parse(String(ev.data)); } catch { return; }
    const d = m.data as Record<string, unknown> | undefined;
    switch (m.event ?? m.type) {
      case 'snapshot':
        store.sessions.clear();
        for (const s of (m.data as A.Session[]) ?? []) { store.sessions.set(s.sessionId, s); stampSession(s); }
        break;
      case 'agent.hello':
        if (d) { const s = d as unknown as A.Session; store.sessions.set(s.sessionId, s); stampSession(s); }
        break;
      case 'agent.maps':
        if (d?.sessionId) {
          const s = store.sessions.get(String(d.sessionId));
          if (s) s.mapsCount = d.mapsCount as number;
        }
        break;
      case 'agent.close':
        if (d?.sessionId) {
          const s = store.sessions.get(String(d.sessionId));
          if (s) s.online = false;
        }
        break;
      case 'capture.new':
        if (d) capPush(d as unknown as A.Cap);
        break;
      case 'data.cleared':
        if(d?.serial&&d.serial!==selectedSerial())break;
        if(d?.package&&d.package!==store.chosenPkg)break;
        if(d?.what&&d.what!=='captures')break;
        store.capItems = [];
        store.capDropped = 0;
        break;
      case 'devices.changed':
        void refreshDevices();
        break;
      case 'dump.new':
        window.dispatchEvent(new CustomEvent('adh:dump-new', { detail: d }));
        break;
      case 'unpack.done':
      case 'unpack.dex':
        window.dispatchEvent(new CustomEvent('adh:unpack-done', { detail: d }));
        break;
    }
  };
}

// ---- 轮询（设备变更已有 WS track-devices 实时推送，后台隐藏标签页停轮询，不打扰 USB）----
export function startPolling() {
  void refreshDevices();
  void refreshApps();
  void refreshScope();
  void capLoad();
  setInterval(() => {
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
    void refreshDevices();
  }, 12000);
  setInterval(() => {
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
    void refreshApps();
  }, 15000);
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        void refreshDevices();
        void refreshApps();
      }
    });
  }
}

export const appSessions = computed(() =>
  [...store.sessions.values()].filter(s => s.package === store.chosenPkg&&s.deviceBinding?.serial===selectedSerial()));
export const liveSession = computed(()=>{
  const online=appSessions.value.filter(s=>s.online),main=online.filter(s=>s.process===s.package);
  const rows=main.length?main:online;
  // No arbitrary process when multiple generations/subprocesses remain.
  const generations=new Set(rows.map(s=>s.pid+':'+(s.deviceBinding?.process.starttimeTicks??'')));
  return generations.size===1?rows.sort((a,b)=>Number(b.connectedAt??0)-Number(a.connectedAt??0))[0]??null:null;
});

// ---- 面板显示偏好（localStorage，仅当前浏览器）----
export interface PanelDisplay { limit: number | null; time: 'time' | 'date'; density: 'standard' | 'compact'; rail: boolean }
const PANEL_DISPLAY_KEY = 'adh.panel.display';
export const DISPLAY_CAPS = [100, 200, 300, 500, 800];
function normalizePanelDisplay(v?: Partial<PanelDisplay> | null): PanelDisplay {
  return {
    limit: v?.limit != null && DISPLAY_CAPS.includes(v.limit) ? v.limit : null,
    time: v?.time === 'date' ? 'date' : 'time',
    density: v?.density === 'compact' ? 'compact' : 'standard',
    rail: v?.rail === true,
  };
}
function readPanelDisplay(): PanelDisplay {
  try { return normalizePanelDisplay(JSON.parse(localStorage.getItem(PANEL_DISPLAY_KEY) ?? '')); }
  catch { return normalizePanelDisplay(); }
}
export const panelDisplay = reactive<PanelDisplay>(readPanelDisplay());
export const hostDisplayCap = reactive({ value: 300 });
export const capDisplayCap = computed(() => panelDisplay.limit ?? hostDisplayCap.value);
export function savePanelDisplay(v?: Partial<PanelDisplay>) {
  Object.assign(panelDisplay, normalizePanelDisplay(v));
  try { localStorage.setItem(PANEL_DISPLAY_KEY, JSON.stringify(panelDisplay)); return true; }
  catch { return false; }
}

// ---- 记录显示：按包隐藏的 category/hook/算法 键（localStorage）----
const hiddenKeyFor = (pkg: string) => `adh.panel.hidden-hooks.v1:${pkg}`;
export const hiddenHooks = reactive(new Set<string>());
let hiddenPkg = '';
function loadHidden() {
  const pkg = store.chosenPkg;
  if (pkg === hiddenPkg) return;
  hiddenPkg = pkg;
  hiddenHooks.clear();
  if (!pkg) return;
  try {
    const saved = JSON.parse(localStorage.getItem(hiddenKeyFor(pkg)) ?? '[]') as unknown;
    if (Array.isArray(saved)) for (const k of saved) if (typeof k === 'string' && k.length < 160) hiddenHooks.add(k);
  } catch { /* 损坏当空集 */ }
}
watch(() => store.chosenPkg, loadHidden, { immediate: true });
export function setHidden(key: string, show: boolean) {
  if (show) hiddenHooks.delete(key); else hiddenHooks.add(key);
  saveHidden();
}
export function resetHidden() {
  hiddenHooks.clear();
  saveHidden();
}
function saveHidden(): boolean {
  if (!store.chosenPkg) return false;
  try {
    if (hiddenHooks.size) localStorage.setItem(hiddenKeyFor(store.chosenPkg), JSON.stringify([...hiddenHooks]));
    else localStorage.removeItem(hiddenKeyFor(store.chosenPkg));
    return true;
  } catch { return false; }
}
export const capVisible = (c: A.Cap) => recordVisible(c, hiddenHooks);
