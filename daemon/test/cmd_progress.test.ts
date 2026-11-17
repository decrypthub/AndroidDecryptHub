// Live progress channel: a long command must report while it is in flight, and must stop reporting
// the moment it settles. These assertions are about the CONTRACT the WebSocket client relies on:
//   cmd.start    once, before anything can complete
//   cmd.progress zero or more, carrying real elapsed time (never a fabricated percentage)
//   cmd.done     exactly once, on success, on timeout, and on disconnect
// The failure this guards against is silence: before the change, a 6 s trace and a dead agent were
// indistinguishable to the caller because neither produced any event.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

process.env.ADH_SKIP_ARTIFACT_LOAD = '1';
process.env.ADH_DATA_DIR = process.env.ADH_DATA_DIR || 'adhd-data/test-progress';

const state = await import('../src/state.ts');
const { sendCmd } = await import('../src/service.ts');

// Capture the live channel by attaching a fake client to the real wss. ESM exports are read-only, so
// the module object cannot be patched - but `wss.clients` is a mutable Set on a real WebSocketServer.
function captureLive() {
  state.wss.clients.clear();   // never inherit a previous test's fake client
  const seen = [];
  const fake = { readyState: 1, send: (m) => seen.push(JSON.parse(m)) };
  state.wss.clients.add(fake as any);
  return { seen, drop: () => state.wss.clients.delete(fake as any) };
}

// A fake agent socket: it records what the daemon wrote and lets the test answer on demand.
// The daemon writes 5-byte-header frames (u32be length + u8 type), not bare JSON.
function fakeAgent() {
  const writes = [];
  const sock = { destroyed: false, write: (b) => { writes.push(Buffer.isBuffer(b) ? b : Buffer.from(String(b))); } };
  return { sock, writes };
}
function decodeFrame(buf) {
  const len = buf.readUInt32BE(0);
  return JSON.parse(buf.subarray(5, 5 + len).toString('utf8'));
}

test('an in-flight command reports start, progress and done on the live channel', async () => {
  const { seen, drop } = captureLive();
  const { sock, writes } = fakeAgent();
  state.agentSockets.set('s_test', sock as any);

  const p = sendCmd('s_test', 'qbdi_trace', { budget: 1000 }, 4000);
  // cmd.start is emitted synchronously, before the agent has answered anything
  assert.equal(seen.filter(e => e.event === 'cmd.start').length, 1);
  assert.equal(seen[0].event, 'cmd.start');
  assert.equal(seen[0].data.op, 'qbdi_trace');

  // answer it as the agent would
  const id = decodeFrame(writes[0]).id;
  const entry = state.pending.get(id);
  assert.ok(entry, 'the command must be pending');
  entry.resolve({ ok: true, seen: 42 });
  const out = await p;
  assert.equal(out.seen, 42);

  const done = seen.filter(e => e.event === 'cmd.done');
  assert.equal(done.length, 1);
  assert.equal(done[0].data.ok, true);
  assert.equal(typeof done[0].data.elapsedMs, 'number');
  // nothing may keep reporting after the command settled
  assert.equal(state.inflight.has(id), false);
  state.agentSockets.delete('s_test'); drop();
});

test('a timeout reports done with ok:false instead of only throwing', async () => {
  const { seen, drop } = captureLive();
  const { sock } = fakeAgent();
  state.agentSockets.set('s_timeout', sock as any);

  await assert.rejects(() => sendCmd('s_timeout', 'root_watch', {}, 120), /command timeout/);
  const done = seen.filter(e => e.event === 'cmd.done');
  assert.equal(done.length, 1);
  assert.equal(done[0].data.ok, false);
  assert.equal(done[0].data.op, 'root_watch');
  assert.equal(done[0].data.state, 'unknown');
  assert.equal(done[0].data.targetStopped, false);
  assert.equal([...state.inflight.values()].filter(t => t.sessionId === 's_timeout').length, 0);
  state.agentSockets.delete('s_timeout'); drop();
});

test('a disconnect fails the command and closes its progress entry', () => {
  const { seen, drop } = captureLive();
  const { sock } = fakeAgent();
  state.agentSockets.set('s_dead', sock as any);

  const p = sendCmd('s_dead', 'native_call', {}, 30000);
  p.catch(() => { });                                   // the rejection is asserted through failPendingFor
  const n = state.failPendingFor('s_dead', 'agent not connected');
  assert.equal(n, 1);

  const done = seen.filter(e => e.event === 'cmd.done');
  assert.equal(done.length, 1);
  assert.equal(done[0].data.ok, false);
  assert.equal(done[0].data.reason, 'agent not connected');
  // the tracker must not survive the disconnect, or the heartbeat would keep firing for a dead socket
  assert.equal([...state.inflight.values()].filter(t => t.sessionId === 's_dead').length, 0);
  state.agentSockets.delete('s_dead'); drop();
});

test('progress is never persisted to the event log', () => {
  // broadcastLive must not touch recordEvent: a trace reporting every second would otherwise append
  // thousands of lines and turn a diagnostic into disk pressure.
  const before = state.events.length;
  state.broadcastLive('cmd.progress', { cmdId: 'x', elapsedMs: 1 });
  assert.equal(state.events.length, before);
});
