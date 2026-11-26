// 面板「设备管理」的重连动作：把三层放在一个结果里 —— ADB 传输、设备域 RPC、agent 通道。
// 三层失败原因完全不同（手机没插 / 手机侧 device daemon 没起 / 目标 App 没重开），
// 面板必须能分别说清楚，不能把「设备域连不上」显示成「设备离线」。
import { AGENT_PORT } from './config.ts';
import { adbExec } from './adb_wire.ts';
import { connectDevice,deviceSerial } from './device_bridge.ts';
import {usbAgentRoutes} from './usb_agent_routes.ts';
import { agentSockets, sessions } from './state.ts';
import { currentLocalObserver } from './local_observer.ts';
import { parseAdbDevices } from './transport/adb_device.ts';

/** adb 网络设备串号固定是 host:port（无线调试 / TCP 转发），与 USB 序列号区分开。 */
export const NET_TARGET_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*:\d{1,5}$/;

export function isNetTarget(value: string): boolean {
  if (!NET_TARGET_RE.test(value)) return false;
  const port = Number(value.slice(value.lastIndexOf(':') + 1));
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export interface AgentView { online: boolean; pid: number; sessionId: string; connectedAt: number }

export interface ReconnectDeps {
  adb: (args: string[], opts?: { timeout?: number }) => Promise<{ stdout: string; stderr: string }>;
  connectDomain: (serial: string) => Promise<{ deviceId?: string }>;
  addReverse: (serial: string, port: number) => Promise<void>;
  dropAgentSockets: (pkg: string) => number;
  agentView: (pkg: string) => AgentView | null;
  observed: () => { serial: string; pkg: string } | null;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

export interface ReconnectResult {
  ok: boolean;
  /** 请求的目标串号（USB 序列号或 host:port）。 */
  serial: string;
  /** 这台设备在 ADB 里的链路类型；未发现时为 null。 */
  link: 'usb' | 'adb-tcp' | null;
  /** agent 拨号用的 reverse 隧道：present = 本来就有，added = 本次补上。 */
  reverse: 'present' | 'added' | 'skipped';
  /** adh.device/1 控制通道是否在线。 */
  rpc: boolean;
  deviceId?: string;
  agent?: AgentView & { waitedMs: number };
  /** 在线但某一层失败时的如实说明，不改变 ok（agent 通道才是本机观察入口的主通道）。 */
  warnings: string[];
  code?: string;
  error?: string;
  elapsedMs: number;
}

function observedTarget(): { serial: string; pkg: string } | null {
  const observer = currentLocalObserver();
  if (!observer || !observer.usbSerial || !observer.package) return null;
  return { serial: observer.usbSerial, pkg: observer.package };
}

function liveAgents(pkg: string): AgentView[] {
  const out: AgentView[] = [];
  for (const socket of agentSockets.keys()) {
    const session = sessions.get(socket);
    if (!session || session.package !== pkg||session.deviceBinding?.serial!==deviceSerial()) continue;
    out.push({ online: session.online === true, pid: session.pid, sessionId: session.sessionId, connectedAt: session.connectedAt });
  }
  return out;
}

export function defaultReconnectDeps(): ReconnectDeps {
  return {
    adb: (args, opts) => adbExec(args, { timeout: opts?.timeout ?? 8000, maxBuffer: 1024 * 1024 }),
    connectDomain: async (serial) => {
      const connection = await connectDevice(serial);
      return { deviceId: connection.peer.deviceId };
    },
    addReverse: async (serial, port) => {
      await adbExec(['-s', serial, 'reverse', `tcp:${port}`, `tcp:${port}`], { timeout: 8000 });
    },
    dropAgentSockets: (pkg) => {
      let dropped = 0;
      for (const [sessionId, socket] of [...agentSockets]) {
        const session = sessions.get(sessionId);
        if (!session || session.package !== pkg||session.deviceBinding?.serial!==deviceSerial()) continue;
        dropped++;
        socket.destroy();
      }
      return dropped;
    },
    agentView: (pkg) => {
      const rows = liveAgents(pkg);
      const best = rows.find((row) => row.online) ?? rows[0];
      return best ?? null;
    },
    observed: observedTarget,
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
}

async function waitForAgent(pkg: string, deps: ReconnectDeps, since: number, timeoutMs: number): Promise<(AgentView & { waitedMs: number }) | null> {
  const deadline = deps.now() + timeoutMs;
  for (;;) {
    const row = deps.agentView(pkg);
    // A session that predates this reconnect is the one we just killed; wait for a fresh dial-in.
    if (row && row.online && row.connectedAt >= since - 1000) return { ...row, waitedMs: deps.now() - since };
    if (deps.now() >= deadline) return row ? { ...row, waitedMs: deps.now() - since } : null;
    await deps.sleep(200);
  }
}

async function ensureReverse(serial: string, deps: ReconnectDeps): Promise<'present' | 'added'> {
  const routes=usbAgentRoutes();if(routes){const had=!!routes.get(serial);await routes.ensure(serial);return had?'present':'added';}
  const port = 'tcp:' + AGENT_PORT;
  const list = (await deps.adb(['-s', serial, 'reverse', '--list'], { timeout: 8000 })).stdout;
  const have = list.split(/\r?\n/)
    .some((line) => line.trim().split(/\s+/).slice(-2).join(' ') === port + ' ' + port);
  if (have) return 'present';
  await deps.addReverse(serial, AGENT_PORT);
  return 'added';
}

/**
 * 重连一台设备。
 * - USB / host:port：先确认 ADB 层（网络串号会自动 adb connect），再补 reverse，再连设备域；
 *   若这台就是本机观察设备，则强制 agent 重拨并等它回来 —— 这是面板「重连」最常要的效果。
 * - 观察设备以 agent 通道判定成功；其余设备以设备域 RPC 判定成功。别的层失败写进 warnings。
 */
export async function reconnectDevice(serialRaw: string, deps: ReconnectDeps = defaultReconnectDeps()): Promise<ReconnectResult> {
  const started = deps.now();
  const serial = String(serialRaw ?? '').trim();
  const result: ReconnectResult = {
    ok: false, serial, link: null, reverse: 'skipped', rpc: false, warnings: [], elapsedMs: 0,
  };
  if (!serial) {
    return { ...result, code: 'SERIAL_REQUIRED', error: '需要一个设备串号或网络地址' };
  }

  const observed = deps.observed();
  const isObserved = !!observed && observed.serial === serial;

  let rows;
  try {
    rows = parseAdbDevices((await deps.adb(['devices', '-l'], { timeout: 5000 })).stdout);
  } catch (error) {
    return { ...result, code: 'ADB_UNAVAILABLE', error: `读不到 ADB 设备列表：${(error as Error).message}`, elapsedMs: deps.now() - started };
  }

  // 网络串号：不在花名册里就先 adb connect，把它拉回来。
  if (!rows.some((row) => row.serial === serial) && isNetTarget(serial)) {
    try {
      const reply = await deps.adb(['connect', serial], { timeout: 10000 });
      const text = String(reply.stdout ?? '').trim();
      if (!/^(connected to|already connected to)/i.test(text)) {
        return { ...result, code: 'ADB_CONNECT_FAILED', error: text || 'adb connect 没有返回结果', elapsedMs: deps.now() - started };
      }
      rows = parseAdbDevices((await deps.adb(['devices', '-l'], { timeout: 5000 })).stdout);
    } catch (error) {
      const reason = (error as Error).message || '连接失败';
      const readable = /超时|timeout/i.test(reason)
        ? `等不到 ${serial}：确认手机已开无线调试、和电脑在同一网络、地址和端口没写错`
        : reason;
      return { ...result, code: 'ADB_CONNECT_FAILED', error: readable, elapsedMs: deps.now() - started };
    }
  }

  const row = rows.find((candidate) => candidate.serial === serial);
  if (!row) {
    return {
      ...result, code: 'DEVICE_ABSENT',
      error: isNetTarget(serial) ? `连不上 ${serial}（网络调试没开或地址不对）` : `这台手机现在不在 USB 上（${serial}）`,
      elapsedMs: deps.now() - started,
    };
  }
  result.link = row.link === 'usb' || row.link === 'adb-tcp' ? row.link : null;
  if (row.state !== 'device') {
    const stateText: Record<string, string> = { unauthorized: '未授权（手机上要允许 USB 调试）', offline: '离线', connecting: '正在连接' };
    return {
      ...result, code: 'DEVICE_NOT_READY', state: row.state,
      error: stateText[row.state] ?? `ADB 状态是 ${row.state}`,
      elapsedMs: deps.now() - started,
    } as ReconnectResult;
  }

  try {
    result.reverse = await ensureReverse(serial, deps);
  } catch (error) {
    result.reverse = 'skipped';
    result.warnings.push(`reverse 隧道没补上：${(error as Error).message}`);
  }

  let domainOk = false;
  try {
    const connection = await deps.connectDomain(serial);
    domainOk = true;
    result.rpc = true;
    if (connection?.deviceId) result.deviceId = connection.deviceId;
  } catch (error) {
    const message = (error as Error).message || '设备域连接失败';
    if (isObserved) result.warnings.push(`设备域通道未连通（不影响 agent 采集）：${message}`);
    else result.warnings.push(`设备域通道未连通：${message}`);
  }

  if (isObserved) {
    const since = deps.now();
    const dropped = deps.dropAgentSockets(observed!.pkg);
    const agent = await waitForAgent(observed!.pkg, deps, since, 6000);
    if (agent) result.agent = agent;
    result.ok = !!agent && agent.online;
    if (!result.ok) {
      result.code = 'AGENT_OFFLINE';
      result.error = dropped
        ? '已断开旧连接，但目标 App 的 agent 没有在 6 秒内重连；确认 App 还在前台运行'
        : '目标 App 的 agent 不在线；确认 App 还在前台运行';
    }
  } else {
    result.ok = domainOk;
    if (!domainOk) {
      result.code = 'DOMAIN_UNAVAILABLE';
      result.error = '设备域通道没连上：手机侧的 device daemon 可能没在运行（模块未启用或已停）';
    }
  }
  result.elapsedMs = deps.now() - started;
  return result;
}

/** 无线调试添加：adb connect 后立刻回读花名册，返回这台设备当前的真实状态。 */
export async function connectNetDevice(addressRaw: string, deps: ReconnectDeps = defaultReconnectDeps()): Promise<ReconnectResult> {
  const address = String(addressRaw ?? '').trim();
  if (!isNetTarget(address)) {
    const started = deps.now();
    return {
      ok: false, serial: address, link: null, reverse: 'skipped', rpc: false, warnings: [],
      code: 'INVALID_ADDRESS', error: '网络地址要写成 IP:端口（例如 192.168.1.50:5555）', elapsedMs: deps.now() - started,
    };
  }
  return reconnectDevice(address, deps);
}
