import test from 'node:test';
import assert from 'node:assert/strict';
import { assessAnalysis, type AssessmentDeps } from '../src/analysis_assist.ts';
import { MCP_MAP } from '../src/mcp.ts';
import { sessions, captures } from '../src/state.ts';

const session = { sessionId: 's_assess', package: 'synthetic.example', process: 'synthetic.example', pid: 777, online: true, starttimeTicks: '12345', caps: { ops: ['native_hook'] } };
function setup(hooks: any[] = []) {
  let calls = 0;
  const deps: AssessmentDeps = {
    sessions: new Map([[session.sessionId, { ...session }]]), captures: [], stats: new Map(), storeLoss: () => null, now: () => 100000,
    readHookStatus: async () => { calls++; return { ok: true, status: { hooks, slots: { free: 8, retired: 0 } } }; },
  };
  return { deps, calls: () => calls };
}
const assess = (deps: AssessmentDeps, extra: any = {}) => assessAnalysis({ topic: 'stuck', session: session.sessionId, ...extra }, deps);

test('missing, unknown and offline sessions never issue target commands or select another process silently', async () => {
  const s = setup();
  for (const sid of [undefined, 'old-session']) {
    const r = await assess(s.deps, { session: sid }); assert.equal(r.stage, 'choose-session'); assert.equal(r.next?.tool, 'process_list');
  }
  (s.deps.sessions.get(session.sessionId) as any).online = false;
  assert.equal((await assess(s.deps)).stage, 'session-offline'); assert.equal(s.calls(), 0);
});

test('transport failures and rejected status replies lead to different diagnoses', async () => {
  const s = setup(); s.deps.readHookStatus = async () => { throw new Error('timed out'); };
  const timeout = await assess(s.deps); assert.equal(timeout.stage, 'agent-status-unavailable');
  assert.equal(timeout.next?.tool, 'runtime_diagnostics'); assert.match(timeout.doNotConclude.join(' '), /anti-debugging/);
  s.deps.readHookStatus = async () => ({ ok: false, error: 'unsupported operation' });
  const rejected = await assess(s.deps); assert.equal(rejected.stage, 'hook-status-rejected'); assert.equal(rejected.next?.tool, 'capabilities');
});

test('zero hits, filtered calls and suppressed observations remain distinct even with older retained data', async () => {
  for (const [fields, stage] of [
    [{ hits: 0 }, 'await-known-trigger'],
    [{ hits: 8, filtered: 8, selected: 0, emitted: 0 }, 'all-hits-filtered'],
    [{ hits: 8, selected: 8, emitted: 0, throttled: 8 }, 'observation-suppressed'],
  ] as const) {
    const s = setup([{ id: 7, ...fields }]); s.deps.captures = [{ id: 1, sessionId: session.sessionId, hookId: 7, func: 'NATIVE_HOOK' }];
    const r = await assess(s.deps, { hookId: 7 }); assert.equal(r.stage, stage); assert.equal(s.calls(), 1);
    assert.equal(r.executedMutations, false); assert.equal(r.next?.tool, 'native_look');
  }
});

test('submitted events without retained records are not presented as no traffic or guaranteed loss', async () => {
  const s = setup([{ id: 7, hits: 8, selected: 8, emitted: 8 }]);
  const r = await assess(s.deps); assert.equal(r.stage, 'submitted-without-retained-record');
  assert.match(r.summary, /Pending drain/); assert.equal(r.next?.effect, 'drain-existing-captures');
  assert.equal((r.facts.captureHealth as any).complete, null);
});

test('in-flight callbacks and unexplained pending submissions are not guessed to be throttled', async () => {
  const busy = setup([{ id: 7, hits: 1, selected: 1, emitted: 0, inFlight: 1 }]);
  assert.equal((await assess(busy.deps)).stage, 'callbacks-in-flight');
  const unsettled = setup([{ id: 7, hits: 1, selected: 1, emitted: 0, inFlight: 0 }]);
  assert.equal((await assess(unsettled.deps)).stage, 'submission-not-established');
});

test('assessment never chooses another hook or leaks byte fields into its context checkpoint', async () => {
  const s = setup(); (s.deps.sessions.get(session.sessionId) as any).caps = { ops: [] };
  s.deps.captures = [
    { id: 91, sessionId: 'another-session', func: 'FOREIGN', hex: 'FOREIGN_SECRET' },
    { id: 92, sessionId: session.sessionId, hookId: 8, func: 'NATIVE_HOOK', hex: 'PRIVATE_INPUT', keyHex: 'PRIVATE_KEY', outHex: 'PRIVATE_OUTPUT' },
  ];
  const r = await assess(s.deps, { topic: 'writer', hookId: 7 });
  assert.equal(r.stage, 'writer-needs-buffer-and-thread'); assert.equal(r.next?.tool, 'analysis_guide');
  assert.doesNotMatch(JSON.stringify(r), /FOREIGN_SECRET|PRIVATE_INPUT|PRIVATE_KEY|PRIVATE_OUTPUT|FOREIGN/);
  const multiple = setup([{ id: 7 }, { id: 8 }]); assert.equal((await assess(multiple.deps)).stage, 'choose-hook');
});

test('known loss, baseline-relative counters and stale health are kept explicit', async () => {
  const s = setup(); const stats = new Map(); s.deps.stats = stats;
  stats.set(session.sessionId, { dropped: 5, jdropped: 2, complete: true, ts: 100000, base: { dropped: 4, jdropped: 1 } });
  const loss = await assess(s.deps, { topic: 'start' }); assert.equal((loss.facts.captureHealth as any).dropped, 2);
  assert.equal((loss.facts.captureHealth as any).complete, false);
  stats.set(session.sessionId, { dropped: 0, jdropped: 0, complete: true, ts: 1 });
  assert.equal(((await assess(s.deps, { topic: 'start' })).facts.captureHealth as any).complete, null);
});

test('writer candidates propose a visible root preparation but never arm or upload automatically', async () => {
  const s = setup(); const r = await assess(s.deps, { topic: 'writer', buffer: '0x1000', tid: 19 });
  assert.equal(r.stage, 'watch-inputs-supplied'); assert.equal(r.next?.tool, 'root_watch');
  assert.equal(r.next?.arguments.action, 'prepare'); assert.equal(r.next?.effect, 'prepare-root-helper'); assert.equal(s.calls(), 0);
  assert.match(r.doNotConclude.join(' '), /automatically the correct writer/);
  await assert.rejects(() => assess(s.deps, { tid: 0 }), /positive integer/);
  await assert.rejects(() => assess(s.deps, { buffer: '0' }), /hex address/);
});

test('trace capability and a permanently exhausted slot budget do not silently fall back or restart', async () => {
  const s = setup(); const old = await assess(s.deps, { topic: 'trace' }); assert.equal(old.stage, 'trace-capability-unverified');
  assert.equal(s.calls(), 0);
  s.deps.readHookStatus = async () => ({ ok: true, status: { hooks: [], slots: { free: 0, retired: 16 } } });
  const exhausted = await assess(s.deps); assert.equal(exhausted.stage, 'hook-budget-exhausted');
  assert.equal(exhausted.next?.tool, 'analysis_guide'); assert.equal(exhausted.executedMutations, false);
});

test('the proposed same-record crypto check runs through the real MCP adapter with unknown collection health intact', async () => {
  const s = setup(); s.deps.captures = [{ id: 900000021, sessionId: session.sessionId, func: 'MD5', hex: '616263', outHex: '900150983cd24fb0d6963f7d28e17f72' }];
  const r = await assess(s.deps, { topic: 'crypto' }); assert.equal(r.stage, 'verify-observed-boundary');
  assert.equal(r.next?.tool, 'crypto_evidence');
  captures.push({ ...s.deps.captures[0], source: 'native', inl: 3, tid: 5, ts: 1 } as any);
  try {
    const checked = await MCP_MAP.get('crypto_evidence')!.handler(r.next!.arguments);
    assert.equal(checked.counts.unavailable, 1, 'missing original output length must remain unknown');
    assert.match(r.next!.expect, /independently established/);
    assert.equal(checked.rows[0].role, 'unspecified');
    assert.equal(checked.captureCollectionComplete, null); assert.equal(checked.complete, false);
    // For this public MD5 vector ONLY, the independent expected digest length is known to be 16.
    const withProof: any = structuredClone(r.next!.arguments); withProof.observations[0].output.expectedBytes = 16;
    const verified = await MCP_MAP.get('crypto_evidence')!.handler(withProof);
    assert.equal(verified.counts.matched, 1); assert.equal(verified.captureCollectionComplete, null);
    const noSession = await MCP_MAP.get('analysis_guide')!.handler({ action: 'assess' });
    assert.equal(noSession.stage, 'choose-session'); assert.equal(noSession.executedMutations, false);
  } finally { captures.splice(captures.findIndex(c => c.id === 900000021), 1); sessions.delete(session.sessionId); }
});
