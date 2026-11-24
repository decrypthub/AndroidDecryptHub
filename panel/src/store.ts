// 全局响应式状态。防丢语义（历史三修，勿回退）：
//  1. 记录归属按包名 stamp，不绑会话存活——会话剪枝后旧记录仍在。
//  2. capItems 只在「设备+包身份」真变时清空——应用启停、轮询失败不触发。
//  3. 读失败 ≠ 设备没了——catch 保旧数据标 failed，等下次成功轮判定生死。
import { reactive, computed } from 'vue';
import * as A from './api';

export interface DeviceView {
  key: string; serial: string; model: string; state: string;
  link: string; observed?: string; online: boolean | null; failed?: boolean;
  appSession?: string | null;
}

export const CAP_BUFFER_LIMIT = 5000;

export const store = reactive({
  // 连接
  wsState: 'off' as 'off' | 'live' | 'fail',
  // 设备
  devices: [] as DeviceView[],
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
  // 视图
  view: 'cc' as 'cc' | 'sy' | 'nt' | 'files' | 'dump' | 'settings',
  appDialogOpen: false,
});

// ---- 包名归属（stamp 制，不看会话死活）----
export function belongsToApp(c: A.Cap): boolean {
  if (!store.chosenPkg) return false;
  const stamped = c.package || (c.sessionId ? store.sessionPkg.get(c.sessionId) : undefined);
  if (stamped) return stamped === store.chosenPkg;
  return !c.sessionId; // 无会话信息的服务端记录按当前包算
}
function stampSession(s: A.Session) {
  if (s.sessionId && s.package) store.sessionPkg.set(s.sessionId, s.package);
}

// ---- 记录 ----
export function capPush(c: A.Cap) {
  if (c.sessionId && c.package) store.sessionPkg.set(c.sessionId, c.package);
  store.capItems.push(c);
  if (store.capItems.length > CAP_BUFFER_LIMIT) store.capItems.splice(0, store.capItems.length - CAP_BUFFER_LIMIT);
}
export async function capLoad() {
  if (!store.chosenPkg) { store.capItems = []; return; }
  const r = await A.getCaptures(store.chosenPkg, 0, CAP_BUFFER_LIMIT);
  store.capItems = (r.items ?? []).slice(-CAP_BUFFER_LIMIT);
  for (const c of store.capItems) if (c.sessionId && c.package) store.sessionPkg.set(c.sessionId, c.package);
  store.capDropped = r.dropped ?? 0;
  store.capComplete = r.complete !== false;
  store.capLatest = r.latest ?? (store.capItems.at(-1)?.id ?? 0);
}

// 设备+包身份。应用 pid/session 变化不进来——重启不清列表。
export function capScopeKey(): string {
  return `${store.selectedDeviceKey}|${store.chosenPkg}`;
}
let lastCapScope = '';
export function scopeChanged(): boolean {
  const k = capScopeKey();
  if (k === lastCapScope) return false;
  lastCapScope = k;
  return true;
}
export async function syncCapScope() {
  if (scopeChanged()) await capLoad();
}

// ---- 设备轮询：失败保旧值 ----
export async function refreshDevices() {
  try {
    const r = await A.getDevices();
    const transports = (r.transports ?? []) as Array<Record<string, unknown>>;
    const usb = r.localUsb ?? null;
    store.devices = transports.map(t => ({
      key: String(t.serial ?? ''),
      serial: String(t.serial ?? ''),
      model: String(t.model ?? t.serial ?? ''),
      state: String(t.state ?? ''),
      link: String(t.link ?? ''),
      observed: t.observed as string | undefined,
      online: t.online as boolean | null,
    }));
    store.localUsb = usb;
    // 本地观察模式：transports 为空时 localUsb 自己当设备行
    if (usb && !store.devices.length) {
      store.devices = [{
        key: String(usb.transport ?? 'usb'), serial: String(usb.transport ?? 'usb'),
        model: String(usb.model ?? '本地设备'), state: String(usb.linkState ?? ''),
        link: String(usb.transport ?? 'usb'),
        observed: usb.observedPackage as string | undefined,
        online: usb.online as boolean | null,
        appSession: usb.appSession as string | null,
      }];
    }
    store.devicesFailed = false;
    store.devicesUpdated = Date.now();
    if (!store.selectedDeviceKey && store.devices.length) selectDevice(store.devices[0].key);
  } catch {
    store.devicesFailed = true; // 保旧列表，只标失败
  }
}

export function selectDevice(key: string) {
  if (store.selectedDeviceKey === key) return;
  store.selectedDeviceKey = key;
  const dev = store.devices.find(d => d.key === key);
  const observed = dev?.observed ?? (store.localUsb?.observedPackage as string | undefined);
  if (observed) store.chosenPkg = observed;
  void syncCapScope();
}

export function choosePackage(pkg: string) {
  if (store.chosenPkg === pkg) return;
  store.chosenPkg = pkg;
  void syncCapScope();
}

// ---- 应用列表：失败保旧值 ----
export async function refreshApps() {
  try {
    const r = await A.getApps();
    store.apps = r.apps ?? [];
    store.appsError = r.error ?? '';
    store.captureEnabled = r.capture?.enabled !== false;
    store.appsFailed = false;
  } catch {
    store.appsFailed = true;
  }
  try {
    const s = await A.getScope();
    if (s.ok) store.scope = new Set(s.packages);
  } catch { /* scope 读取失败不遮罩主流程 */ }
}

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
    let m: { type?: string; data?: unknown };
    try { m = JSON.parse(String(ev.data)); } catch { return; }
    const d = m.data as Record<string, unknown> | undefined;
    switch (m.type) {
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
      case 'dump.new':
        window.dispatchEvent(new CustomEvent('adh:dump-new', { detail: d }));
        break;
    }
  };
}

// ---- 轮询 ----
export function startPolling() {
  void refreshDevices();
  void refreshApps();
  void capLoad();
  setInterval(() => { void refreshDevices(); }, 4000);
  setInterval(() => { void refreshApps(); }, 8000);
}

export const appSessions = computed(() =>
  [...store.sessions.values()].filter(s => s.package === store.chosenPkg));
export const liveSession = computed(() => appSessions.value.find(s => s.online) ?? null);
