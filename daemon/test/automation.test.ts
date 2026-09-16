import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { AutomationHub } from '../src/automation.ts';
import { mergeSettings, settings } from '../src/state.ts';
import { agentWaitSightings, findAgentWaitMatch, hasAgentWaitFilters } from '../src/agent_events.ts';
import { implicitSelectorFor, selectorFrom } from '../src/phone_selectors.ts';

function connect(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => resolve(socket));
    socket.once('error', reject);
  });
}

function writeLine(socket: net.Socket, value: unknown) {
  socket.write(JSON.stringify(value) + '\n');
}

function nextJson(socket: net.Socket): Promise<any> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      socket.off('data', onData);
      socket.off('error', onError);
      resolve(JSON.parse(buffer.slice(0, newline)));
    };
    const onError = (error: Error) => {
      socket.off('data', onData);
      reject(error);
    };
    socket.on('data', onData);
    socket.once('error', onError);
  });
}

test('automation hub registers a device and round-trips a command', async () => {
  const hub = new AutomationHub();
  const port = await hub.listen(0);
  const socket = await connect(port);
  writeLine(socket, {
    t: 'hello',
    deviceId: 'test-device',
    model: 'Unit Test Phone',
    sdk: 35,
    caps: { tree: true, screenshot: true, gestures: true, setText: true, maxNodes: 300 },
  });
  const helloAck = await nextJson(socket);
  assert.equal(helloAck.t, 'helloAck');
  assert.equal(helloAck.deviceId, 'test-device');
  assert.equal(hub.status().connected, true);
  assert.equal(hub.status().devices[0].model, 'Unit Test Phone');

  const commandPromise = hub.cmd('observe', { mode: 'auto' }, 2_000);
  const command = await nextJson(socket);
  assert.equal(command.t, 'cmd');
  assert.equal(command.op, 'observe');
  assert.deepEqual(command.args, { mode: 'auto' });
  writeLine(socket, { t: 'result', id: command.id, ok: true, result: { mode: 'tree', nodes: [] } });
  const result = await commandPromise;
  assert.equal(result.mode, 'tree');

  socket.destroy();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(hub.status().connected, false);
  await hub.close();
});

test('automation hub fails loudly when no device is connected', async () => {
  const hub = new AutomationHub();
  await hub.listen(0);
  await assert.rejects(() => hub.cmd('observe', {}, 100), /no automation device connected/);
  await hub.close();
});

test('automation settings merge is opt-in and bounded', () => {
  const before = JSON.stringify(settings.automation);
  const applied = mergeSettings({
    automation: {
      enabled: true,
      screenshot: false,
      packages: [' com.example.one ', 'com.example.one', 'com.example.two'],
      maxNodes: 5000,
      screenshotMaxDimension: 100,
    },
  });
  assert.ok(applied.includes('automation'));
  assert.equal(settings.automation.enabled, true);
  assert.equal(settings.automation.screenshot, false);
  assert.deepEqual(settings.automation.packages, ['com.example.one', 'com.example.two']);
  assert.equal(settings.automation.maxNodes, 2000);
  assert.equal(settings.automation.screenshotMaxDimension, 480);
  Object.assign(settings.automation, JSON.parse(before));
});


function waitEvent(seq: number, ts: number, type: string, data: any = {}) {
  return { seq, ts, type, data };
}

function waitCapture(id: number, ts: number, category: string, extra: any = {}) {
  return {
    id, ts, category, sessionId: 's_test', source: 'native', func: 'SSL_write', algo: 'tls', op: 'write',
    preview: 'GET /l', inl: 128, tid: 42, tsNs: 1, hex: 'ab'.repeat(400), ...extra,
  };
}

const T0 = 1_000_000;

test('agent wait filters are opt-in', () => {
  assert.equal(hasAgentWaitFilters({ textContains: 'Login' }), false);
  assert.equal(hasAgentWaitFilters({}), false);
  assert.equal(hasAgentWaitFilters({ captureCategory: 'crypto' }), true);
  assert.equal(hasAgentWaitFilters({ agentEvent: 'hook.hit' }), true);
});

test('agent wait matches a capture by category only after the wait started', () => {
  const old = waitCapture(1, T0 - 5_000, 'crypto');
  const fresh = waitCapture(2, T0 + 120, 'crypto', { algo: 'AES', preview: 'hello-world' });
  const hit = findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [old, fresh]);
  assert.equal(hit?.kind, 'capture');
  assert.equal(hit?.item.id, 2);
  assert.equal(hit?.item.preview, 'hello-world');
  assert.equal(hit?.item.hexLen, 800);
  assert.equal(hit?.item.hex, undefined);                          // oversized hex stays out of the payload
  assert.equal(findAgentWaitMatch({ captureCategory: 'net' }, { since: T0 }, [], [old, fresh]), null);
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 + 200 }, [], [old, fresh]), null);
});

test('agent wait ANDs same-kind filters and races event against capture', () => {
  const events = [waitEvent(7, T0 + 400, 'agent.maps', { count: 12 }), waitEvent(8, T0 + 900, 'hook.hit', { symbol: 'SSL_read' })];
  const captures = [waitCapture(3, T0 + 500, 'net', { func: 'SSL_write', preview: 'ADH_NET_MARKER_v1' })];
  assert.equal(findAgentWaitMatch({ captureCategory: 'net', captureContains: 'ADH_NET_MARKER_v1' }, { since: T0 }, events, captures)?.item.id, 3);
  assert.equal(findAgentWaitMatch({ captureCategory: 'net', captureContains: 'nope' }, { since: T0 }, events, captures), null);
  const newest = findAgentWaitMatch({ agentEventContains: 'hook.hit', captureCategory: 'net' }, { since: T0 }, events, captures);
  assert.equal(newest?.kind, 'event');
  assert.equal(newest?.item.type, 'hook.hit');
});

test('agent wait takes the newest exact event and compacts oversized data', () => {
  const big = { blob: 'x'.repeat(5_000) };
  const events = [waitEvent(1, T0 + 10, 'hook.hit', { symbol: 'first' }), waitEvent(2, T0 + 20, 'hook.hit', big)];
  const hit = findAgentWaitMatch({ agentEvent: 'hook.hit' }, { since: T0 }, events, []);
  assert.equal(hit?.item.seq, 2);
  assert.equal(hit?.item.data.truncated, true);
  assert.equal(hit?.item.data.bytes > 4_000, true);
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.miss' }, { since: T0 }, events, []), null);
});

test('agent wait cursor mode ignores the timestamp and only accepts newer records', () => {
  const older = waitCapture(41, T0 - 60_000, 'crypto', { preview: 'ADH手动_AES_#7_x' });
  const newer = waitCapture(42, T0 - 59_000, 'crypto', { preview: 'ADH手动_AES_#8_x' });
  const cursor = { afterCaptureId: 41 };
  const hit = findAgentWaitMatch({ captureCategory: 'crypto', captureContains: 'ADH手动_AES_#' }, cursor, [], [older, newer]);
  assert.equal(hit?.item.id, 42);
  const same = findAgentWaitMatch({ captureCategory: 'crypto' }, { afterCaptureId: 42 }, [], [older, newer]);
  assert.equal(same, null);
  const events = [waitEvent(9, T0 - 60_000, 'hook.hit', {}), waitEvent(10, T0 - 59_000, 'hook.hit', {})];
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.hit' }, { afterEventSeq: 9 }, events, [])?.item.seq, 10);
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.hit' }, { afterEventSeq: 10 }, events, []), null);
});

test('agent wait lookback still honours the timestamp window without a cursor', () => {
  const capture = waitCapture(50, T0 - 1_500, 'crypto');
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 - 5_000 }, [], [capture])?.item.id, 50);
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [capture]), null);
});

test('capture filters and payloads decode UTF-8 text out of the hex bytes', () => {
  const marker = 'ADH手动_AES_#7_订单金额=99.00元';
  const capture = waitCapture(60, T0 + 5, 'crypto', { hex: Buffer.from(marker, 'utf8').toString('hex'), preview: 'ADH......_AES_#7_............=99.00...' });
  const hit = findAgentWaitMatch({ captureCategory: 'crypto', captureContains: 'ADH手动_AES_#' }, { since: T0 }, [], [capture]);
  assert.equal(hit?.item.text, marker);
  const binary = waitCapture(61, T0 + 6, 'crypto', { hex: '00010203ff' });
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [binary])?.item.text, undefined);
});

test('a timed-out agent wait reports what actually arrived in the window', () => {
  const captures = [waitCapture(70, T0 + 100, 'net', { preview: 'GET /x' }), waitCapture(71, T0 + 200, 'crypto', { algo: 'MD5' })];
  const events = [waitEvent(10, T0 - 5_000, 'agent.hello', {}), waitEvent(11, T0 + 50, 'agent.maps', { count: 3 })];   // append order: oldest first
  const sightings = agentWaitSightings({ since: T0 }, events, captures, 2);
  assert.equal(sightings.totals.captures, 2);
  assert.equal(sightings.totals.events, 1);
  assert.deepEqual(sightings.captures.map((item: any) => item.id), [71, 70]);
  assert.equal(sightings.events[0].type, 'agent.maps');

  const cursorView = agentWaitSightings({ afterCaptureId: 70 }, [], captures, 2);
  assert.equal(cursorView.totals.captures, 1);
  assert.equal(cursorView.captures[0].id, 71);
});

test('agent wait sightings keep everything counted but bounded in size', () => {
  const captures = [waitCapture(80, T0 + 1, 'crypto'), waitCapture(81, T0 + 2, 'crypto'), waitCapture(82, T0 + 3, 'crypto')];
  const sightings = agentWaitSightings({ since: T0 }, [], captures, 2);
  assert.equal(sightings.captures.length, 2);
  assert.equal(sightings.totals.captures, 3);
});

test('set_text payload is never read as a selector', () => {
  // The field is targeted by id; `text` is what we are about to type, not a filter.
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed', resourceId: 'com.x:id/box' }), { resourceId: 'com.x:id/box' });
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed', editable: true }), { editable: true });
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed' }), {});
  // An explicit selector still wins, including targeting a field by its, current text.
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'new', selector: { text: 'old' } }), { text: 'old' });
});

test('other actions keep text as a selector and false stays a real filter', () => {
  assert.deepEqual(implicitSelectorFor('tap', { text: '搜索' }), { text: '搜索' });
  assert.deepEqual(implicitSelectorFor(undefined, { contentDescription: '搜索' }), { contentDescription: '搜索' });
  assert.deepEqual(selectorFrom({ text: 'a', clickable: false }), { text: 'a', clickable: false });
  assert.deepEqual(selectorFrom({ text: null, clickable: undefined }), {});
});
