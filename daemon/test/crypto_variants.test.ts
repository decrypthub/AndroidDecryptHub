import test from 'node:test';
import assert from 'node:assert/strict';

import { scanCryptoVariants } from '../src/crypto_variants.ts';

// Every byte pattern below is the REAL one from the reference sample repo
// (CYRUS-STUDIO/CyReverse, app/src/main/cpp — read 2026-09-29), not an invented vector:
//   md5_change_constant.cpp, sha1_change_constant.cpp, custom_base64_alphabet.cpp,
//   dynamic_base64_alphabet.cpp, custom_crc32_table.cpp, modified_crc32.cpp.
// The point of the module is that a variant is identified from the parts the mutation did NOT touch,
// so the vectors have to be the mutations people actually ship.

const le32 = (...vals: number[]) =>
  Buffer.from(vals.flatMap((v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]));

const MD5_K = le32(0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee);
const MD5_IV_STD = le32(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
/** md5_change_constant.cpp: only the top byte of each IV word was rewritten. */
const MD5_IV_VARIANT = le32(0xaa452301, 0xbbcdab89, 0xccbadcfe, 0xdd325476);
const SHA1_IV_STD = le32(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0);
const SHA1_RC_STD = le32(0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6);
/** sha1_change_constant.cpp: the round constants were rewritten, the IV was not. */
const SHA1_RC_VARIANT = le32(0xaa827999, 0xbb827999, 0xccd9eba1, 0xdd1bbcdc, 0xee62c1d6);
/** custom_base64_alphabet.cpp — case-swapped, URL-safe tail. */
const B64_CUSTOM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Image = deadbeef padding + the given chunks, so offsets are never 0 by accident. */
const image = (...chunks: (Buffer | string)[]) =>
  Buffer.concat([Buffer.from('deadbeef', 'hex'), ...chunks.map((c) => (typeof c === 'string' ? Buffer.from(c + '\0', 'latin1') : c))]);

const family = (report: ReturnType<typeof scanCryptoVariants>, name: string) =>
  report.families.find((f) => f.family === name);

test('standard MD5 is identified as standard (K table + init both present)', () => {
  const r = scanCryptoVariants(image(MD5_K, MD5_IV_STD));
  const md5 = family(r, 'MD5');
  assert.equal(md5?.verdict, 'standard');
  assert.deepEqual(md5?.missing, []);
  assert.match(String(md5?.anchor.what), /round-constant table/);
});

test('md5_change_constant is caught as a VARIANT: the K table anchors it, the absent init proves it', () => {
  const r = scanCryptoVariants(image(MD5_K, MD5_IV_VARIANT));
  const md5 = family(r, 'MD5');
  assert.equal(md5?.verdict, 'variant');
  assert.deepEqual(md5?.missing, ['MD5 init A..D']);
  // The rewritten IV is reported as a perturbed copy of the standard one, with the count — that is
  // the difference between "MD5, IV modified" and "unknown algorithm".
  assert.match(String(md5?.detail), /12\/16 bytes/);
  assert.match(String(md5?.detail), /rewritten in place/);
});

test('sha1_change_constant is caught from the OTHER end: the IV anchors it, the rewritten round constants prove it', () => {
  const r = scanCryptoVariants(image(SHA1_IV_STD, SHA1_RC_VARIANT));
  const sha1 = family(r, 'SHA1');
  assert.equal(sha1?.verdict, 'variant');
  assert.deepEqual(sha1?.missing, ['SHA1 round constants 0x5a827999/0x6ed9eba1/0x8f1bbcdc/0xca62c1d6']);
  assert.equal(sha1?.anchor.offset, '0x4', 'anchored on the IV, which this mutation left alone');
  // 12/16, and the arithmetic is worth showing because it is the mutation's fingerprint: each
  // rewritten constant keeps the low three bytes (XX7999 / XXd9eba1 / XX1bbcdc / XX62c1d6) and
  // changes only the top one — and his second constant (0xbb827999) reuses the 827999 tail, so the
  // best-aligning window starts at HIS second constant (0x1c = 4 pad + 20 IV + 4). Measured, not
  // assumed: the first version of this test asserted 16/16 and was wrong.
  assert.match(String(sha1?.detail), /at 0x1c matches the standard round constants in 12\/16 bytes/);
  // MD5 must NOT be claimed off the shared 16-byte prefix — that would be a false positive.
  assert.equal(family(r, 'MD5'), undefined);
});

test('standard SHA1 stays standard, and the shared MD5/SHA1 init prefix is not used to guess', () => {
  const std = scanCryptoVariants(image(SHA1_IV_STD, SHA1_RC_STD));
  assert.equal(family(std, 'SHA1')?.verdict, 'standard');
  assert.equal(family(std, 'MD5'), undefined);

  // Init prefix alone (no structure table, no 20-byte SHA1 init): explicitly left unclassified.
  const ambiguous = scanCryptoVariants(image(MD5_IV_STD));
  assert.deepEqual(ambiguous.families, []);
  assert.ok(ambiguous.limits.some((l) => /shared by both algorithms/.test(l)));
});

test('a custom base64 alphabet is found by SHAPE, and the substitution count says how far it drifted', () => {
  const r = scanCryptoVariants(image(B64_CUSTOM));
  assert.equal(r.alphabets.length, 1);
  assert.equal(r.alphabets[0].kind, 'variant');
  assert.equal(r.alphabets[0].sample, B64_CUSTOM);
  assert.equal(r.alphabets[0].substitutions, 54, '26 case swaps + 26 case swaps + the two tail chars');
});

test('the standard and URL-safe alphabets are recognised as themselves, not as drift', () => {
  const std = scanCryptoVariants(image(B64_STD));
  assert.equal(std.alphabets[0]?.kind, 'standard');
  assert.equal(std.alphabets[0]?.substitutions, 0);
  const url = scanCryptoVariants(image(B64_URL));
  assert.equal(url.alphabets[0]?.kind, 'url');
});

test('dynamic_base64_alphabet: the standard table is seen, the per-invocation one cannot be, and the report says so', () => {
  // dynamic_base64_alphabet.cpp ships the STANDARD alphabet and computes the real one at runtime as
  // `out[i ^ (len % 64)] = std[i]`. Statically there is nothing else to find — the honest output is
  // "standard alphabet present" plus a stated limit, not a silent miss.
  const r = scanCryptoVariants(image(B64_STD));
  assert.equal(r.alphabets[0].kind, 'standard');
  assert.ok(r.limits.some((l) => /builds at runtime/.test(l)));
});

test('CRC polynomials are reported as the standard families they are', () => {
  const c = scanCryptoVariants(image(le32(0xedb88320)));
  assert.equal(family(c, 'CRC32')?.verdict, 'standard');
  assert.match(String(family(c, 'CRC32')?.anchor.what), /CRC-32 polynomial/);
  // modified_crc32.cpp uses 0x82f63b78, which is not a mutation at all — it is CRC-32C.
  const c32 = scanCryptoVariants(image(le32(0x82f63b78)));
  assert.match(String(family(c32, 'CRC32')?.anchor.what), /CRC-32C/);
});

test('one recycled constant proves nothing: the CRC-sample literal 0xd76aa478 is NOT claimed as MD5', () => {
  // custom_crc32_table.cpp builds its table at runtime from the polynomial 0xd76aa478 — the MD5 K[0]
  // constant reused as something else entirely. A single-constant matcher would call this "MD5".
  const r = scanCryptoVariants(image(le32(0xd76aa478)));
  assert.deepEqual(r.families, []);
});

test('a SHA1 init must not be read as the MD5 init (16-byte strict prefix)', () => {
  // Found by the compiled fixture, not by reasoning: an image with an MD5 K table and a SHA1
  // implementation answers "yes" to a naive MD5-init search, because MD5's 16-byte init is the first
  // 16 bytes of SHA1's 20-byte init. Every synthetic buffer here happened to hold one init at a time;
  // a real .so usually holds both. Left unfixed, the variant fixture was reported as standard MD5.
  const r = scanCryptoVariants(image(MD5_K, SHA1_IV_STD));
  assert.equal(family(r, 'MD5')?.verdict, 'variant', 'no standalone MD5 init here');
  assert.deepEqual(family(r, 'MD5')?.missing, ['MD5 init A..D']);
  assert.equal(family(r, 'SHA1')?.verdict, 'variant', 'the standard round constants are absent');
});

test('a plain text blob yields no alphabet and no family (false-positive guard)', () => {
  const sentence = 'The quick brown fox jumps over the lazy dog, and then it does it again and again.';
  const r = scanCryptoVariants(Buffer.from(sentence, 'latin1'));
  assert.deepEqual(r.alphabets, []);
  assert.deepEqual(r.families, []);
});

test('a 64-byte run outside the base64 vocabulary is not an alphabet', () => {
  const high = Buffer.from(Array.from({ length: 64 }, (_, i) => 0x80 + i));
  const r = scanCryptoVariants(high);
  assert.deepEqual(r.alphabets, []);
});

test('every report states where a static scan is blind', () => {
  const r = scanCryptoVariants(Buffer.alloc(0));
  assert.equal(r.limits.length, 3);
  assert.ok(r.limits.some((l) => /static scan only/.test(l)));
  assert.ok(r.limits.some((l) => /single 32-bit constant/.test(l)));
  assert.ok(r.limits.some((l) => /rewrites the ANCHOR/.test(l)));
});
