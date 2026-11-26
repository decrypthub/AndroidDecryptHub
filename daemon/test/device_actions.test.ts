// 设备管理「重连」的三层判定：ADB 链路 / reverse 隧道 / 设备域通道 / agent 重拨。
// 这些用例只用注入依赖，不连真机也不碰 5037。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectNetDevice, isNetTarget, reconnectDevice, type AgentView, type ReconnectDeps } from '../src/device_actions.ts';
import { AGENT_PORT } from '../src/config.ts';

const AGENT_TUNNEL = `UsbFfs tcp:${AGENT_PORT} tcp:${AGENT_PORT}\n`;

interface FakeAdbState { rows: string; reverse: string; connectReply?: string; connectThrows?: string; seen: string[] }

function fakeAdb(state: FakeAdbState): ReconnectDeps['adb'] {
  return async (args: string[]) => {
    const key = args.join(' ');
    state.seen.push(key);
    if (key === 'devices -l') return { stdout: 'List of devices attached\n' + state.rows, stderr: '' };
    if (args[0] === 'connect') {
      if (state.connectThrows) throw new Error(state.connectThrows);
      state.rows += `${args[1]}\tdevice product:PGP110 model:PGP110 transport_id:9\n`;
      return { stdout: (state.connectReply ?? `connected to ${args[1]}\n`), stderr: '' };
    }
    if (key.endsWith('reverse --list')) return { stdout: state.reverse, stderr: '' };
    throw new Error('unexpected adb call: ' + key);
  };
}

interface HarnessOptions {
  rows?: string;
  reverse?: string;
  observed?: { serial: string; pkg: string } | null;
  domain?: 'ok' | 'fail';
  agentScript?: AgentView[];
  connectReply?: string;
  connectThrows?: string;
}

function harness(opts: HarnessOptions = {}) {
  const state: FakeAdbState = {
    rows: opts.rows ?? 'aa165071               device product:PGP110 model:PGP110 transport_id:1\n',
    reverse: opts.reverse ?? AGENT_TUNNEL,
    connectReply: opts.connectReply,
    connectThrows: opts.connectThrows,
    seen: [],
  };
  let clock = 1_000_000;
  const script = [...(opts.agentScript ?? [])];
  const calls = { addReverse: 0, dropAgent: 0, connectDomain: 0 };
  const deps: ReconnectDeps = {
    adb: fakeAdb(state),
    connectDomain: async (serial) => {
      calls.connectDomain++;
      if (opts.domain === 'fail') throw new Error('DEVICE_NOT_READY: adb transport is offline');
      return { deviceId: '11111111-2222-3333-4444-555555555555', serial };
    },
    addReverse: async () => { calls.addReverse++; },
    dropAgentSockets: () => { calls.dropAgent++; return 1; },
    agentView: () => {
      const next = script.shift();
      return next ?? null;
    },
    observed: () => opts.observed ?? null,
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
  };
  return { deps, state, calls, clockNow: () => clock };
}

test('网络串号只认 host:port', () => {
  assert.equal(isNetTarget('192.168.1.50:5555'), true);
  assert.equal(isNetTarget('my-phone.local:5555'), true);
  assert.equal(isNetTarget('aa165071'), false);
  assert.equal(isNetTarget('192.168.1.50'), false);
  assert.equal(isNetTarget('192.168.1.50:0'), false);
  assert.equal(isNetTarget('192.168.1.50:70000'), false);
});

test('设备不在花名册：USB 报 DEVICE_ABSENT，网络串号先 adb connect', async () => {
  const usb = harness({ rows: 'a22fecdd               device product:PGP110 model:PGP110 transport_id:1\n' });
  const absent = await reconnectDevice('aa165071', usb.deps);
  assert.equal(absent.ok, false);
  assert.equal(absent.code, 'DEVICE_ABSENT');
  assert.match(absent.error ?? '', /不在 USB 上/);

  const net = harness({
    rows: '',
    connectReply: 'connected to 192.168.1.50:5555\n',
    observed: { serial: 'aa165071', pkg: 'com.adh.sandbox' },
  });
  const connected = await reconnectDevice('192.168.1.50:5555', net.deps);
  assert.equal(connected.ok, true, connected.error);
  assert.equal(connected.link, 'adb-tcp');
  assert.equal(connected.rpc, true);
  assert.deepEqual(net.state.seen.filter((c) => c.startsWith('connect ')), ['connect 192.168.1.50:5555']);
});

test('adb connect 被拒时如实回传服务器那句原因', async () => {
  const h = harness({ rows: '', connectReply: "failed to connect to '192.168.1.50:5555': Connection refused\n" });
  const result = await reconnectDevice('192.168.1.50:5555', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'ADB_CONNECT_FAILED');
  assert.match(result.error ?? '', /Connection refused/);
});

test('adb connect 抛错也走 ADB_CONNECT_FAILED，不谎报已连接', async () => {
  const h = harness({ rows: '', connectThrows: 'adb server 断开了连接' });
  const result = await reconnectDevice('192.168.1.50:5555', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'ADB_CONNECT_FAILED');
  assert.match(result.error ?? '', /断开了连接/);
});

test('ADB 状态不是 device：报 DEVICE_NOT_READY 并带可读原因', async () => {
  const h = harness({ rows: 'aa165071               unauthorized transport_id:1\n' });
  const result = await reconnectDevice('aa165071', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'DEVICE_NOT_READY');
  assert.match(result.error ?? '', /未授权/);
  assert.equal(result.link, null);
});

test('观察设备：reverse 缺失要补，agent 掉线要强制重拨并等它回来', async () => {
  const h = harness({
    reverse: '',
    observed: { serial: 'aa165071', pkg: 'com.adh.sandbox' },
    domain: 'ok',
    agentScript: [
      { online: false, pid: 100, sessionId: 's_old', connectedAt: 999_000 },
      null,
      { online: true, pid: 200, sessionId: 's_new', connectedAt: 1_000_400 },
    ],
  });
  const result = await reconnectDevice('aa165071', h.deps);
  assert.equal(result.reverse, 'added');
  assert.equal(h.calls.addReverse, 1);
  assert.equal(h.calls.dropAgent, 1);
  assert.equal(result.ok, true, result.error);
  assert.equal(result.agent?.sessionId, 's_new');
  assert.equal(result.agent?.online, true);
  assert.ok((result.agent?.waitedMs ?? 0) >= 200, `waitedMs=${result.agent?.waitedMs}`);
});

test('观察设备：agent 六秒没回来就报 AGENT_OFFLINE，不把设备域成功当成功', async () => {
  const h = harness({
    observed: { serial: 'aa165071', pkg: 'com.adh.sandbox' },
    domain: 'ok',
    agentScript: [],
  });
  const result = await reconnectDevice('aa165071', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'AGENT_OFFLINE');
  assert.equal(result.rpc, true, '设备域成功仍然是事实，要如实带出来');
  assert.match(result.error ?? '', /agent 不在线|没有在 6 秒内重连/);
});

test('非观察设备：设备域通道失败即失败，并把手机侧原因写清楚', async () => {
  const h = harness({ domain: 'fail', observed: null });
  const result = await reconnectDevice('aa165071', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'DOMAIN_UNAVAILABLE');
  assert.match(result.error ?? '', /device daemon/);
  assert.equal(result.rpc, false);
});

test('非观察设备：设备域连上即成功，reverse 已有就不重复加', async () => {
  const h = harness({ observed: null, domain: 'ok' });
  const result = await reconnectDevice('aa165071', h.deps);
  assert.equal(result.ok, true, result.error);
  assert.equal(result.rpc, true);
  assert.equal(result.reverse, 'present');
  assert.equal(h.calls.addReverse, 0);
});

test('非法网络地址在发请求前就被拒绝', async () => {
  const h = harness({ rows: '' });
  const result = await connectNetDevice('192.168.1.50', h.deps);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'INVALID_ADDRESS');
  assert.deepEqual(h.state.seen, [], '校验失败不应该产生任何 adb 请求');
});
