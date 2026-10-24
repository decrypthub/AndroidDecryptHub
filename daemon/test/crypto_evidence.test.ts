import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeCryptoEvidence, CRYPTO_EVIDENCE_LIMITS, saveCryptoEvidence, readCryptoEvidence,
  listCryptoEvidence, dropCryptoEvidence, selectCaptureBytes } from '../src/crypto_evidence.ts';
import type { CryptoObservation, EvidenceBytes, EvidenceCapture } from '../src/crypto_evidence.ts';
import { buildCryptoChallenge } from './fixtures/crypto_challenge.ts';

const raw = (hex: string, callId = 'call1'): EvidenceBytes => ({ hex, complete: true, source: { kind: 'oracle', session: 'test', callId } });
const text = (utf8: string, callId = 'call1'): EvidenceBytes => ({ utf8, complete: true, source: { kind: 'oracle', session: 'test', callId } });
const digest = (value: string, algorithm = 'md5') => createHash(algorithm).update(value).digest('hex');
const sample = (id = 'a'): CryptoObservation => ({ id, input: text('abc'), output: raw(digest('abc')), algorithms: ['md5'], role: 'intermediate' });

test('published digest and HMAC vectors verify exact bytes; matching MD5 stays intermediate', () => {
  const r = analyzeCryptoEvidence({ observations: [
    { id: 'empty-md5', input: text(''), output: raw('d41d8cd98f00b204e9800998ecf8427e'), algorithms: ['md5'], role: 'intermediate' },
    { id: 'rfc4231', input: text('Hi There'), key: raw('0b'.repeat(20)), output: raw('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'), algorithms: ['hmac-sha256'] },
  ] });
  assert.equal(r.counts.matched, 2); assert.equal(r.rows[0].role, 'intermediate');
  assert.match(r.caveat, /intermediate primitive is not a verified final/);
  assert.equal(r.rows[1].key!.source!.kind, 'oracle');
  assert.equal('hex' in r.rows[1].key!, false);
});

test('digest raw bytes, hexdigest text, and final-field claims are separate checks', () => {
  const md5 = digest('abc');
  const r = analyzeCryptoEvidence({ observations: [
    sample('primitive'), { id: 'wrong-final', role: 'final', algorithms: ['md5'], input: text('abc'), output: text(md5) },
    { id: 'encoding', role: 'final', algorithms: ['hex-lower'], input: raw(md5), output: text(md5) },
  ] });
  assert.equal(r.rows[0].checks[0].status, 'matched');
  assert.equal(r.rows[1].checks[0].status, 'mismatched');
  assert.equal(r.rows[2].checks[0].status, 'matched');
  assert.deepEqual(r.contentLinks.map(l => [l.from, l.to]), [['primitive', 'encoding']]);
});

test('missing output, truncated input and unknown completeness never count as algorithm mismatches', () => {
  const missing = sample('missing'); delete missing.output;
  const short = sample('short'); (short.input as EvidenceBytes).expectedBytes = 10;
  const unknown = sample('unknown'); delete unknown.output!.complete;
  const r = analyzeCryptoEvidence({ observations: [missing, short, unknown], loss: { complete: false, dropped: 3, storeLoss: 'evicted window' } });
  assert.equal(r.counts.tested, 0); assert.equal(r.counts.mismatched, 0); assert.equal(r.counts.unavailable, 3);
  assert.equal(r.complete, false); assert.equal(r.loss.dropped, 3);
  assert.match(r.rows[1].checks[0].reason!, /length 3 differs from expected 10/);
  assert.match(r.rows[2].checks[0].reason!, /completeness was not established/);
});

test('verified supplied pairs and capture-collection coverage are separate completeness signals', () => {
  const unknown = analyzeCryptoEvidence({ observations: [sample()] });
  assert.equal(unknown.analysisComplete, true); assert.equal(unknown.captureCollectionComplete, null); assert.equal(unknown.complete, false);
  const reportedComplete = analyzeCryptoEvidence({ observations: [sample()], loss: { complete: true, dropped: 0 } });
  assert.equal(reportedComplete.complete, true);
  const dropped = analyzeCryptoEvidence({ observations: [sample()], loss: { complete: true, dropped: 1 } });
  assert.equal(dropped.analysisComplete, true); assert.equal(dropped.captureCollectionComplete, false); assert.equal(dropped.complete, false);
});

test('same thread alone is insufficient; seq is scoped by hook, session and TID', () => {
  const make = (id: string, patch: object) => {
    const o = sample(id); const src = { kind: 'hook-window' as const, session: 'test', tid: 7, hookId: 1, seq: 9 };
    (o.input as EvidenceBytes).source = src; o.output!.source = { ...src, ...patch }; return o;
  };
  const threadOnly = sample('thread-only');
  (threadOnly.input as EvidenceBytes).source = { kind: 'capture', session: 'test', tid: 7 };
  threadOnly.output!.source = { kind: 'capture', session: 'test', tid: 7 };
  const r = analyzeCryptoEvidence({ observations: [make('ok', {}), make('wrong-hook', { hookId: 2 }), make('wrong-tid', { tid: 8 }),
    make('wrong-session', { session: 'other' }), make('wrong-seq', { seq: 10 }), threadOnly] });
  assert.equal(r.counts.matched, 1); assert.equal(r.counts.unavailable, 5);
  for (const row of r.rows.slice(1)) assert.equal(row.pairing.paired, false, row.id);
});

test('shared outer call IDs support explicitly attributed async boundaries; conflicting sessions still fail', () => {
  const o = sample(); (o.input as EvidenceBytes).source.tid = 7; o.output!.source.tid = 8;
  assert.equal(analyzeCryptoEvidence({ observations: [o] }).counts.matched, 1);
  o.output!.source.session = 'another-session';
  assert.equal(analyzeCryptoEvidence({ observations: [o] }).counts.unavailable, 1);
});

test('analyst pairing is explicit and cannot override contradictory recorded thread identities', () => {
  const o = sample(); (o.input as EvidenceBytes).source = { kind: 'manual' }; o.output!.source = { kind: 'manual' };
  assert.equal(analyzeCryptoEvidence({ observations: [o] }).counts.unavailable, 1);
  o.pairing = { basis: 'analyst', note: 'same controlled invocation; external recorder supplied these two buffers' };
  assert.equal(analyzeCryptoEvidence({ observations: [o] }).counts.matched, 1);
  (o.input as EvidenceBytes).source.tid = 1; o.output!.source.tid = 2;
  assert.equal(analyzeCryptoEvidence({ observations: [o] }).counts.unavailable, 1);
});

test('parameter fingerprints separate rotating actual keys even if the caller repeats one label', () => {
  const make = (id: string, key: string): CryptoObservation => ({ id, parameterLabel: 'fixed-label', algorithms: ['hmac-sha256'],
    input: text('message'), key: text(key, 'initialization'), output: raw(createHmac('sha256', key).update('message').digest('hex')) });
  const r = analyzeCryptoEvidence({ observations: [make('one', 'k1'), make('two', 'k2'), make('three', 'k1')] });
  assert.equal(r.counts.matched, 3); assert.equal(r.parameterGroups.length, 2);
  assert.deepEqual(r.parameterGroups.map(p => p.observations.length).sort(), [1, 2]);
  assert.equal(r.parameterGroups[0].keySources[0].callId, 'initialization');
});

test('content links require whole exact bytes, never a shared thread or substring, and do not claim causality', () => {
  const r = analyzeCryptoEvidence({ observations: [
    { id: 'binary', input: raw('00ff'), output: raw('00ff'), algorithms: ['identity'] },
    { id: 'equal-other-call', input: raw('00ff', 'elsewhere'), output: raw('00ff', 'elsewhere'), algorithms: ['identity'] },
    { id: 'substring', input: raw('ff'), output: raw('ff'), algorithms: ['identity'] },
    { id: 'empty', input: raw(''), output: raw(''), algorithms: ['identity'] },
  ] });
  assert.equal(r.contentLinks.length, 2); assert.equal(r.contentLinks.every(l => l.sharedCallId === false), true);
  assert.equal(r.contentLinks.some(l => l.to === 'substring' || l.to === 'empty'), false);
  assert.match(r.caveat, /not execution order, causal flow/);
});

test('a chunked content match cannot attribute the whole input to only its first chunk callId', () => {
  const r = analyzeCryptoEvidence({ observations: [
    { id: 'producer', input: raw('0102'), output: raw('0102'), algorithms: ['identity'] },
    { id: 'mixed', input: [raw('01'), raw('02', 'different-call')], output: raw('0102'), algorithms: ['identity'] },
  ] });
  assert.equal(r.rows[1].pairing.paired, false);
  const link = r.contentLinks.find(l => l.from === 'producer' && l.to === 'mixed')!;
  assert.ok(link); assert.equal(link.sharedCallId, false);
});

test('invalid encodings and short masks are unavailable rather than silently decoded or repeated', () => {
  const bad = sample('bad-hex'); bad.output!.hex = '01zz';
  const b64 = sample('bad-b64'); b64.output = { b64: 'YR==', complete: true, source: { kind: 'manual' } };
  const mask: CryptoObservation = { id: 'mask', input: raw('010203'), output: raw('000000'), params: { xor: raw('ff') }, algorithms: ['xor'] };
  const r = analyzeCryptoEvidence({ observations: [bad, b64, mask] });
  assert.equal(r.counts.unavailable, 3); assert.equal(r.counts.mismatched, 0);
  assert.match(r.rows[2].checks[0].reason!, /exactly the input length/);
});

test('capture selectors preserve source identities and phase; ambiguous/missing windows fail explicitly', () => {
  const event = (seq: number, phase: string, mem: any[]) => Buffer.from(JSON.stringify({ hookId: 9, seq, phase, mem })).toString('hex');
  const records: EvidenceCapture[] = [
    { id: 1, sessionId: 's', tid: 20, hookId: 9, seq: 5, func: 'NATIVE_HOOK_MEM', hex: event(5, 'before', [{ reg: 'x0', offset: 0, requested: 3, got: 3, hex: '616263' }]) },
    { id: 2, sessionId: 's', tid: 20, hookId: 9, seq: 5, func: 'NATIVE_HOOK_MEM', hex: event(5, 'after', [{ reg: 'x1', requested: 16, got: 16, hex: digest('abc') }]) },
  ];
  const input = selectCaptureBytes(records, { captureId: 1, field: 'mem', reg: 'x0' });
  const output = selectCaptureBytes(records, { captureId: 2, field: 'mem', windowIndex: 0 });
  assert.equal(output.source.phase, 'after'); assert.equal(output.source.seq, 5);
  assert.equal(analyzeCryptoEvidence({ observations: [{ id: 'capture-md5', input, output, algorithms: ['md5'] }] }).counts.matched, 1);
  assert.throws(() => selectCaptureBytes([...records, records[0]], { captureId: 1 }), /ambiguous/);
  assert.throws(() => selectCaptureBytes(records, { captureId: 7 }), /missing/);
  assert.throws(() => selectCaptureBytes(records, { captureId: 1, field: 'mem', reg: 'x8' }), /missing/);
  const inconsistent = { ...records[0], seq: 99 };
  assert.throws(() => selectCaptureBytes([inconsistent], { captureId: 1, field: 'mem', reg: 'x0' }), /disagrees/);
  assert.throws(() => selectCaptureBytes(records, { captureId: 1, field: 'mem', reg: 'x0', expectedBytes: 2 }), /disagrees with recorded/);
  const wrongGot = { ...records[0], hex: event(5, 'before', [{ reg: 'x0', requested: 3, got: 2, hex: '616263' }]) };
  const badInput = selectCaptureBytes([wrongGot], { captureId: 1, field: 'mem', reg: 'x0' });
  assert.equal(analyzeCryptoEvidence({ observations: [{ id: 'bad-got', input: badInput, output, algorithms: ['md5'] }] }).counts.unavailable, 1);
});

test('old capture fields with no original key/output length remain unknown until explicitly supplied', () => {
  const records = [{ id: 1, sessionId: 'test', tid: 9, func: 'digest', hex: '616263', inl: 4, outHex: digest('abc') }];
  const input = selectCaptureBytes(records, { captureId: 1 });
  const output = selectCaptureBytes(records, { captureId: 1, field: 'output' });
  assert.equal(analyzeCryptoEvidence({ observations: [{ id: 'short', input, output, algorithms: ['md5'] }] }).counts.unavailable, 1);
  assert.throws(() => selectCaptureBytes(records, { captureId: 1, expectedBytes: 3 }), /disagrees with captured original length/);
  const exactRecords = [{ ...records[0], inl: 3 }];
  const exactInput = selectCaptureBytes(exactRecords, { captureId: 1 });
  const exactOutput = selectCaptureBytes(records, { captureId: 1, field: 'output', expectedBytes: 16 });
  assert.equal(analyzeCryptoEvidence({ observations: [{ id: 'exact', input: exactInput, output: exactOutput, algorithms: ['md5'] }] }).counts.matched, 1);
});

test('disk-backed reports page without leaking raw bytes/keys by default and reload without process state', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adh-crypto-evidence-'));
  try {
    const secret = 'SYNTHETIC-KEY-ONLY-FOR-THIS-TEST-7331';
    const observations = Array.from({ length: 19 }, (_, i): CryptoObservation => ({ id: `pair-${i}`, algorithms: ['hmac-sha256'],
      input: text(`input-${i}`), key: text(secret), output: raw(createHmac('sha256', secret).update(`input-${i}`).digest('hex')) }));
    const saved = saveCryptoEvidence(dir, { observations }, 'synthetic');
    assert.equal(saved.counts.matched, 19); assert.equal(readFileSync(saved.file, 'utf8').includes(secret), true);
    assert.equal(JSON.stringify(saved).includes(secret), false);
    const first = readCryptoEvidence(dir, saved.id, { limit: 16 });
    assert.equal(first.rows.length, 16); assert.equal(first.nextOffset, 16); assert.equal(JSON.stringify(first).includes(secret), false);
    const last = readCryptoEvidence(dir, saved.id, { offset: first.nextOffset!, includePayload: true });
    assert.equal(last.rows.length, 3); assert.equal(last.nextOffset, null); assert.equal(last.observations![0].key!.utf8, secret);
    assert.equal(listCryptoEvidence(dir).records[0].id, saved.id);
    assert.throws(() => readCryptoEvidence(dir, '../outside'), /invalid/);
    assert.throws(() => readCryptoEvidence(dir, saved.id, { limit: 17 }), /limit/);
    dropCryptoEvidence(dir, saved.id); assert.equal(listCryptoEvidence(dir).total, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('bounds reject duplicate IDs, unsupported candidates, excessive fields and observations', () => {
  assert.throws(() => analyzeCryptoEvidence({ observations: [sample(), sample()] }), /unique id/);
  assert.throws(() => analyzeCryptoEvidence({ observations: [sample()], candidates: ['guessed' as any] }), /supported/);
  const huge = sample(); huge.input = raw('aa'.repeat(CRYPTO_EVIDENCE_LIMITS.fieldBytes + 1));
  assert.throws(() => analyzeCryptoEvidence({ observations: [huge] }), /field exceeds/);
  assert.throws(() => analyzeCryptoEvidence({ observations: Array.from({ length: 129 }, (_, i) => sample(String(i))) }), /1..128/);
});

test('seeded variable-composition challenge validates every stage and rejects confounded evidence', () => {
  for (const seed of ['31'.repeat(32), 'a7'.repeat(32)]) {
    const challenge = buildCryptoChallenge(seed, 8), r = analyzeCryptoEvidence(challenge.input);
    const rows = new Map(r.rows.map(row => [row.id, row]));
    for (const id of challenge.expected.validIds) assert.equal(rows.get(id)!.checks[0].status, 'matched', id);
    for (const id of challenge.expected.mismatchedIds) assert.equal(rows.get(id)!.checks[0].status, 'mismatched', id);
    for (const id of challenge.expected.unavailableIds) assert.equal(rows.get(id)!.checks[0].status, 'unavailable', id);
    assert.equal(r.counts.matched, challenge.expected.validIds.length);
    assert.equal(r.counts.mismatched, 2); assert.equal(r.counts.unavailable, 6);
    assert.equal(r.contentLinks.some(link => link.from === 'r0:s0:sha256' && link.to === 'r0:s1:add-xor'), true);
    assert.equal(r.contentLinks.some(link => link.from === 'r0:s2:hmac-sha1' && link.to === 'r0:s3:xor'), true);
  }
});
