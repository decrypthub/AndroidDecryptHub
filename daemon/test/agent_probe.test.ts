import test from 'node:test';
import assert from 'node:assert/strict';
import {
  agentPing, engineVerdict, frameEchoVerdict, hookEngineSelftest, protocolSelfTest, FRAME_ECHO_TAIL,
} from '../src/agent_probe.ts';

const clock = (values: number[]) => { let i = 0; return () => values[Math.min(i++, values.length - 1)]; };

test('agent ping reports the round trip and refuses a reply that is not ok', async () => {
  const sent: any[] = [];
  const ok = await agentPing('s1', {
    send: async (session, op, args, timeout) => { sent.push({ session, op, args, timeout }); return { ok: true, op: 'ping' }; },
    now: clock([100, 112.5]),
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.latencyMs, 12.5);
  assert.equal(sent[0].op, 'ping');
  assert.equal(sent[0].session, 's1');
  assert.ok(sent[0].timeout <= 5_000, 'liveness must fail fast, not sit on the default timeout');

  await assert.rejects(() => agentPing('s1', { send: async () => ({ ok: false, error: 'agent not connected' }), now: clock([0, 1]) }), /agent ping failed: agent not connected/);
});

test('engine verdict separates "not installed", "never fired" and "left RELRO weakened"', () => {
  const broken = engineVerdict({ replaced: 0, hitsBefore: 0, hitsAfter: 0, fired: false, protRestored: false });
  assert.equal(broken.ok, false);
  assert.match(broken.verdict, /not replaced/);

  const silent = engineVerdict({ replaced: 1, hitsBefore: 3, hitsAfter: 3, fired: false, protRestored: true });
  assert.equal(silent.ok, false);
  assert.match(silent.verdict, /never fired/);

  const leaky = engineVerdict({ replaced: 1, hitsBefore: 3, hitsAfter: 4, fired: true, protRestored: false, origPerms: 'r--', slotPerms: 'rw-' });
  assert.equal(leaky.ok, false);
  assert.match(leaky.verdict, /RELRO/);
  assert.match(leaky.verdict, /detectable/);

  const good = engineVerdict({ replaced: 1, hitsBefore: 3, hitsAfter: 4, fired: true, protRestored: true, origPerms: 'r--', slotPerms: 'r--' });
  assert.equal(good.ok, true);
  assert.match(good.verdict, /GOT engine OK/);
});

test('frame echo verdict fails loud on a lost tail and on a truncated frame', () => {
  const expected = { tail: FRAME_ECHO_TAIL, padLen: 8192 };
  const good = frameEchoVerdict({ recvBytes: 9000, tail: FRAME_ECHO_TAIL, padLen: 8192 }, expected);
  assert.deepEqual(good, { ok: true, tailOk: true, notTruncated: true, problems: [] });

  const lostTail = frameEchoVerdict({ recvBytes: 9000, tail: '', padLen: 8192 }, expected);
  assert.equal(lostTail.ok, false);
  assert.match(lostTail.problems.join(' '), /tail mismatch/);

  const short = frameEchoVerdict({ recvBytes: 8192, tail: FRAME_ECHO_TAIL, padLen: 8192 }, expected);
  assert.equal(short.ok, false);
  assert.match(short.problems.join(' '), /truncated/);
});

test('protocol selftest sends a frame whose tail sits past the old 8192-byte cap', async () => {
  const sent: any[] = [];
  const r = await protocolSelfTest('s1', 16, {
    send: async (session, op, args) => {
      sent.push({ op, args });
      return { ok: true, recvBytes: String(args.pad).length + 200, tail: args.tail, padLen: args.padLen };
    },
    now: () => 0,
  });
  assert.equal(r.ok, true);
  assert.equal(r.sentPadLen, 16 * 1024);
  assert.equal(sent[0].args.tail, FRAME_ECHO_TAIL);
  assert.equal(String(sent[0].args.pad).length, 16 * 1024);

  const broken = await protocolSelfTest('s1', 8, { send: async () => ({ ok: true, recvBytes: 8192, tail: '', padLen: 8192 }), now: () => 0 });
  assert.equal(broken.ok, false);
  assert.match(broken.verdict, /channel BROKEN/);
});

test('the engine selftest keeps the agent fields top level and reports ok as the verdict', async () => {
  const good = await hookEngineSelftest('s1', {
    send: async () => ({ ok: true, op: 'gothook_selftest', replaced: 1, hitsBefore: 3, hitsAfter: 4, fired: true, protRestored: true, origPerms: 'r--', slotPerms: 'r--' }),
    now: () => 0,
  });
  assert.equal(good.ok, true);            // verdict, not merely "the command ran"
  assert.equal(good.commandOk, true);
  assert.equal(good.replaced, 1);         // the fields the v04/v26 scripts and the REST route read
  assert.equal(good.fired, true);
  assert.equal(good.protRestored, true);

  const leaky = await hookEngineSelftest('s1', {
    send: async () => ({ ok: true, replaced: 1, hitsBefore: 0, hitsAfter: 2, fired: true, protRestored: false, origPerms: 'r--', slotPerms: 'rw-' }),
    now: () => 0,
  });
  assert.equal(leaky.ok, false);          // a weakened-RELRO build must not be reported as healthy
  assert.equal(leaky.commandOk, true);
  assert.match(leaky.verdict, /detectable/);
});

test('a FAILED selftest command is not reported as a broken engine', async () => {
  const r = await hookEngineSelftest('s1', {
    send: async () => ({ ok: false, error: 'got engine unavailable in this build' }),
    now: () => 0,
  });
  assert.equal(r.ok, false);
  assert.equal(r.commandOk, false);
  assert.match(r.verdict, /command itself failed/);
  assert.doesNotMatch(r.verdict, /cannot install/);   // the engine was never asked
});

test('a frame that comes back without the echoed padLen counts as truncated', () => {
  const expected = { tail: FRAME_ECHO_TAIL, padLen: 16384 };
  const noEcho = frameEchoVerdict({ recvBytes: 17000, tail: FRAME_ECHO_TAIL }, expected);
  assert.equal(noEcho.ok, false);
  assert.equal(noEcho.tailOk, true);
  assert.equal(noEcho.notTruncated, false);
  assert.match(noEcho.problems.join(' '), /echoed padLen/);
  const wrongEcho = frameEchoVerdict({ recvBytes: 17000, tail: FRAME_ECHO_TAIL, padLen: 8192 }, expected);
  assert.equal(wrongEcho.ok, false);
});

test('protocol selftest clamps the frame size instead of sending whatever was asked', async () => {
  const sent: any[] = [];
  const fake = async (_s: string, _o: string, args: Record<string, unknown>) => {
    sent.push(args);
    return { ok: true, recvBytes: String(args.pad).length + 120, tail: args.tail, padLen: args.padLen };
  };
  const small = await protocolSelfTest('s1', 0, { send: fake, now: () => 0 });
  assert.equal(small.kb, 1);
  assert.equal(small.sentPadLen, 1024);
  const huge = await protocolSelfTest('s1', 5000, { send: fake, now: () => 0 });
  assert.equal(huge.kb, 4096);
  assert.equal(huge.sentPadLen, 4096 * 1024);
  assert.equal(sent.length, 2);
});
