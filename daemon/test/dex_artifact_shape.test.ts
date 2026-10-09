import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyDexArtifact, DEX_CARRIER_BYTES_PER_CLASS } from '../src/dex.ts';

// Synthetic examples keep the carrier-to-code density contrast deterministic.
const SPARSE_CARRIER = { size: 120_000_000, classes: 20, methods: 200 };
const DENSE_DEX = { size: 14_000_000, classes: 9_000, methods: 65_000 };

test('a sparse carrier dex is flagged and a dense dex is not', () => {
  const carrier = classifyDexArtifact(SPARSE_CARRIER.size, SPARSE_CARRIER.classes, SPARSE_CARRIER.methods);
  assert.equal(carrier.carrier, true);
  assert.equal(carrier.bytesPerClass, Math.round(120_000_000 / 20));
  assert.match(carrier.reason, /carrier, not code/);

  const real = classifyDexArtifact(DENSE_DEX.size, DENSE_DEX.classes, DENSE_DEX.methods);
  assert.equal(real.carrier, false);
  assert.equal(real.bytesPerClass, Math.round(14_000_000 / 9_000));
  assert.equal(real.classes, 9_000);
});

test('a dex that declares no classes is a carrier, not a small real dex', () => {
  const r = classifyDexArtifact(4096, 0, 0);
  assert.equal(r.carrier, true);
  assert.equal(r.bytesPerClass, 0);        // reported as 0, never as a divide-by-zero or Infinity
  assert.match(r.reason, /no classes/);
});

test('the threshold is per class and exclusive, so a large file with many classes stays real', () => {
  // Exactly at the limit is NOT a carrier (the rule is ">", so a big-but-dense dex survives).
  const at = classifyDexArtifact(DEX_CARRIER_BYTES_PER_CLASS * 100, 100, 100);
  assert.equal(at.bytesPerClass, DEX_CARRIER_BYTES_PER_CLASS);
  assert.equal(at.carrier, false);
  const over = classifyDexArtifact(DEX_CARRIER_BYTES_PER_CLASS * 100 + 100, 100, 100);
  assert.equal(over.carrier, true);
});

test('size alone does not decide it: a 100 MB dex with 60k classes is real code', () => {
  const big = classifyDexArtifact(100 * 1024 * 1024, 60_000, 70_000);
  assert.equal(big.carrier, false);
  assert.ok(big.bytesPerClass < DEX_CARRIER_BYTES_PER_CLASS);
});
