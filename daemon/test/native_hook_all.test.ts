import test from 'node:test';
import assert from 'node:assert/strict';
import { effectiveBatchLimit, selectExportSymbols } from '../src/native_hook_all.ts';

const sym = (name, addr, size, kind = 'func') => ({ name, addr, size, kind });

const TABLE = [
  sym('EVP_EncryptInit_ex', 0x1000n, 40),
  sym('EVP_EncryptUpdate', 0x1100n, 60),
  sym('EVP_DecryptUpdate', 0x1200n, 55),
  sym('EVP_CIPHER_CTX_new', 0x1300n, 20),
  sym('SSL_write', 0x2000n, 30),
  sym('crypto_lock', 0x2100n, 10),
  sym('crypto_table', 0x3000n, 8, 'object'),      // data, must never be hooked
  sym('', 0x3100n, 4),                            // unnamed, ignored
];

test('a prefix selects only exported functions with that prefix', () => {
  const { selected, matched } = selectExportSymbols(TABLE, { prefix: 'EVP_', limit: 8 });
  assert.equal(matched, 4);
  assert.deepEqual(selected.map((s) => s.name), [
    'EVP_EncryptInit_ex', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate', 'EVP_CIPHER_CTX_new',
  ]);
  assert.ok(selected.every((s) => !s.name.includes('crypto')));
});

test('matched counts every match while selected is limited, and the subset is deterministic', () => {
  const a = selectExportSymbols(TABLE, { prefix: 'EVP_', limit: 2 });
  const b = selectExportSymbols([...TABLE].reverse(), { prefix: 'EVP_', limit: 2 });
  assert.equal(a.matched, 4);
  assert.equal(a.selected.length, 2);
  assert.deepEqual(a.selected.map((s) => s.name), b.selected.map((s) => s.name));
  assert.deepEqual(a.selected.map((s) => s.name), ['EVP_EncryptInit_ex', 'EVP_EncryptUpdate']);
});

test('the limit is clamped to the native slot ceiling', () => {
  const many = [];
  for (let i = 0; i < 40; i++) many.push(sym(`fn_${i}`, BigInt(0x1000 + i * 0x10), 16));
  const { selected, matched } = selectExportSymbols(many, { prefix: 'fn_', limit: 100 });
  assert.equal(matched, 40);
  assert.equal(selected.length, 16);
});

test('exclude removes noisy symbols (init/fini style) from the selection', () => {
  const t = [sym('EVP_a', 0x10n, 4), sym('EVP_deregister', 0x20n, 4), sym('EVP_b', 0x30n, 4)];
  const { selected, matched } = selectExportSymbols(t, { prefix: 'EVP_', exclude: ['deregister'], limit: 8 });
  assert.deepEqual(selected.map((s) => s.name), ['EVP_a', 'EVP_b']);
  assert.equal(matched, 2);
});

test('contains and exact are alternatives to the prefix filter', () => {
  const contains = selectExportSymbols(TABLE, { contains: 'Decrypt', limit: 8 });
  assert.deepEqual(contains.selected.map((s) => s.name), ['EVP_DecryptUpdate']);
  const exact = selectExportSymbols(TABLE, { exact: 'SSL_write', limit: 8 });
  assert.deepEqual(exact.selected.map((s) => s.name), ['SSL_write']);
  const noneExact = selectExportSymbols(TABLE, { exact: 'SSL_read', limit: 8 });
  assert.equal(noneExact.matched, 0);
});

test('no filter means every exported function, never data symbols', () => {
  const { selected, matched } = selectExportSymbols(TABLE, { limit: 16 });
  assert.equal(matched, 6);                       // 6 funcs; the object and the unnamed one are out
  assert.ok(selected.every((s) => s.name && s.size >= 0));
  assert.ok(!selected.some((s) => s.name === 'crypto_table'));
});

test('addresses stay module-relative and carry their offset', () => {
  const { selected } = selectExportSymbols([sym('EVP_x', 0x2a00n, 12)], { prefix: 'EVP_', limit: 1 });
  assert.equal(selected[0].address, '0x2a00');
  assert.equal(selected[0].offset, '0x2a00');
  assert.equal(selected[0].size, 12);
});
test('the batch limit comes from the agent slot budget, not from a guess', () => {
  // older payload: no budget reported -> assume the request, but say so
  const noBudget = effectiveBatchLimit(8, null);
  assert.deepEqual({ limit: noBudget.limit, blocked: noBudget.blocked }, { limit: 8, blocked: false });
  assert.match(noBudget.reason, /did not report a slot budget/);

  // only 4 slots left: truncate to 4 and explain
  const tight = effectiveBatchLimit(16, 4);
  assert.equal(tight.limit, 4);
  assert.match(tight.reason, /only 4 of the requested 16/);

  // nothing left: refuse instead of failing symbol by symbol
  const none = effectiveBatchLimit(8, 0);
  assert.equal(none.blocked, true);
  assert.equal(none.limit, 0);
  assert.match(none.reason, /unhook something first/);

  // plenty free: keep the request; an absurd request still clamps to the agent ceiling
  assert.equal(effectiveBatchLimit(8, 64).limit, 8);
  assert.equal(effectiveBatchLimit(1000, 64).limit, 16);
});

test('a corrupt or oddly-typed slot budget is handled explicitly', () => {
  // JSON numbers arrive as strings when a producer stringifies them: still usable
  assert.equal(effectiveBatchLimit(8, Number('4')).limit, 4);
  // negative = corrupt report, not "0 free": say what was received instead of putting words in the agent mouth
  const negative = effectiveBatchLimit(8, -3);
  assert.equal(negative.blocked, true);
  assert.match(negative.reason, /corrupt slot budget \(free=-3\)/);
  // NaN falls back to the request with a note (older payloads and broken producers look the same)
  const nan = effectiveBatchLimit(8, Number.NaN);
  assert.equal(nan.limit, 8);
  assert.match(nan.reason, /did not report a slot budget/);
});
