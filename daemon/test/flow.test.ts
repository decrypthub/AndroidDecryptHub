import test from 'node:test';
import assert from 'node:assert/strict';
import { correlateFlow, asciiOf, WINDOW_NS, FLOW_CAVEAT } from '../src/flow.ts';

const hex = (text: string) => Buffer.from(text, 'utf8').toString('hex');
const rec = (func: string, tid: number, tsNs: number, text = '') => ({ func, tid, tsNs, hex: hex(text) });

test('a crypto record and a net record on the same thread inside the window pair up', () => {
  const r = correlateFlow([
    rec('EVP_CipherUpdate', 7, 1_000_000_000, 'ADH_CORRELATE_v1'),
    rec('SSL_write', 7, 1_000_050_000, 'POST /x'),
  ]);
  assert.equal(r.correlations.length, 1);
  assert.deepEqual(r.considered, { crypto: 1, net: 1 });
  assert.equal(r.correlations[0].tid, 7);
  assert.equal(r.correlations[0].cryptoFunc, 'EVP_CipherUpdate');
  assert.equal(r.correlations[0].netFunc, 'SSL_write');
  assert.equal(r.correlations[0].plaintext, 'ADH_CORRELATE_v1');
  assert.equal(r.correlations[0].request, 'POST /x');
  assert.ok(r.correlations[0].deltaMs > 0 && r.correlations[0].deltaMs < 1);
  assert.equal(r.reason, undefined);
});

test('cross-thread records never pair, however close in time', () => {
  // This is the mis-attribution case: two threads doing unrelated crypto stay unrelated.
  const r = correlateFlow([
    rec('EVP_CipherUpdate', 7, 1_000_000_000, 'thread A plaintext'),
    rec('SSL_write', 8, 1_000_000_001, 'thread B request'),
  ]);
  assert.equal(r.correlations.length, 0);
  assert.deepEqual(r.considered, { crypto: 1, net: 1 });
  assert.match(String(r.reason), /shared a thread/);
});

test('the window boundary is inclusive on both sides of the pair', () => {
  const at = correlateFlow([
    rec('EVP_CipherUpdate', 1, 1_000_000_000, 'p'),
    rec('SSL_write', 1, 1_000_000_000 + WINDOW_NS, 'r'),
  ]);
  assert.equal(at.correlations.length, 1);
  const past = correlateFlow([
    rec('EVP_CipherUpdate', 1, 1_000_000_000, 'p'),
    rec('SSL_write', 1, 1_000_000_001 + WINDOW_NS, 'r'),
  ]);
  assert.equal(past.correlations.length, 0, 'one nanosecond past the window must not pair');
});

test('deltaMs is reported in milliseconds', () => {
  const r = correlateFlow([
    rec('EVP_CipherUpdate', 3, 0, 'p'),
    rec('SSL_write', 3, 50_000_000, 'r'),
  ]);
  assert.equal(r.correlations[0].deltaMs, 50);
});

test('only EVP_*/HMAC_Update join against SSL_*', () => {
  const mixed = [
    rec('EVP_DigestUpdate', 1, 100, 'digest'),   // crypto family (EVP_ prefix)
    rec('HMAC_Update', 1, 100, 'hmac'),          // crypto family (explicit)
    rec('openat', 1, 100, '/data/x'),            // file: never a crypto side
    rec('read', 1, 100, 'bytes'),                // file: never a net side
    rec('SSL_read', 1, 100, 'resp'),             // net family
  ];
  const r = correlateFlow(mixed);
  assert.deepEqual(r.considered, { crypto: 2, net: 1 });
  const funcs = new Set(r.correlations.map((c) => c.cryptoFunc));
  assert.deepEqual([...funcs].sort(), ['EVP_DigestUpdate', 'HMAC_Update']);
  for (const c of r.correlations) assert.ok(c.netFunc.startsWith('SSL_'));
});

test('a one-sided store returns an empty result WITH a reason, never a bare empty array', () => {
  const onlyCrypto = correlateFlow([rec('EVP_CipherUpdate', 1, 5, 'p')]);
  assert.equal(onlyCrypto.correlations.length, 0);
  assert.match(String(onlyCrypto.reason), /no net record/);
  const onlyNet = correlateFlow([rec('SSL_write', 1, 5, 'r')]);
  assert.match(String(onlyNet.reason), /no crypto record/);
  const neither = correlateFlow([]);
  assert.match(String(neither.reason), /no captures in window/);
});

test('every reply states the caveat that this is not a content-hash match', () => {
  const r = correlateFlow([rec('EVP_CipherUpdate', 1, 1, 'p'), rec('SSL_write', 1, 1, 'r')]);
  assert.equal(r.caveat, FLOW_CAVEAT);
  assert.match(r.caveat, /WS-I/);
  assert.match(r.caveat, /not/i);
});

test('asciiOf renders printables, dots the rest, and never throws on malformed hex', () => {
  assert.equal(asciiOf(hex('ADH_v1')), 'ADH_v1');
  assert.equal(asciiOf('000a41'), '..A');
  assert.equal(asciiOf(''), '');
  assert.equal(asciiOf('4'), '');          // odd length: no half byte invented
  assert.equal(asciiOf('zz'), '');         // NaN byte: stop, do not emit garbage
});

test('the store category decides the side (Java-layer crypto names its records by operation)', () => {
  // Measured 2026-10-01: the store held 65 crypto records and only the 4 native EVP_* ones would
  // have matched a prefix test - the Java-layer rich capture calls its records encrypt/digest/hmac.
  const r = correlateFlow([
    { func: 'encrypt', tid: 5, tsNs: 1_000, hex: hex('ADH_X'), category: 'crypto' },
    { func: 'SSL_write', tid: 5, tsNs: 2_000, hex: hex('req'), category: 'net' },
    { func: 'read', tid: 5, tsNs: 3_000, hex: hex('bytes'), category: 'file' },
    { func: 'ptrace', tid: 5, tsNs: 4_000, hex: hex('trace'), category: 'system' },
  ]);
  assert.deepEqual(r.considered, { crypto: 1, net: 1 });
  assert.equal(r.correlations.length, 1);
  assert.equal(r.correlations[0].cryptoFunc, 'encrypt');
  assert.equal(r.correlations[0].plaintext, 'ADH_X');
});

test('a record whose payload cannot be rendered is counted as skipped', () => {
  const r = correlateFlow([
    { func: 'EVP_CipherUpdate', tid: 1, tsNs: 1, hex: 'not-hex' },
    rec('SSL_write', 1, 1, 'r'),
  ]);
  assert.equal(r.skipped, 1);
  assert.equal(r.correlations[0].plaintext, '');
});
