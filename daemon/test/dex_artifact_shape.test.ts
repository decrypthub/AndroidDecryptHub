import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyDexArtifact, DEX_CARRIER_BYTES_PER_CLASS } from '../src/dex.ts';

// The numbers below are the real ones from the Chaoxing/SecNeo unpack (docs/CASE_STUDIES.md case 1):
// ART named a 120,451,440-byte buffer "classes.dex" and it parsed fine, but it held 17 wrapper
// classes - the packer's carrier. The 13 real dexes sat beside it in the same malloc region at
// roughly 1.5 KB per class. Without this classification both look like "a dex".
const CHAOXING_CARRIER = { size: 120_451_440, classes: 17, methods: 216 };
const CHAOXING_REAL = { size: 13_705_120, classes: 9093, methods: 64_912 };

test('the SecNeo carrier dex is flagged and a real one from the same target is not', () => {
  const carrier = classifyDexArtifact(CHAOXING_CARRIER.size, CHAOXING_CARRIER.classes, CHAOXING_CARRIER.methods);
  assert.equal(carrier.carrier, true);
  assert.equal(carrier.bytesPerClass, Math.round(120_451_440 / 17));   // ~7.1 MB per class
  assert.match(carrier.reason, /carrier, not code/);

  const real = classifyDexArtifact(CHAOXING_REAL.size, CHAOXING_REAL.classes, CHAOXING_REAL.methods);
  assert.equal(real.carrier, false);
  assert.equal(real.bytesPerClass, Math.round(13_705_120 / 9093));     // ~1.5 KB per class
  assert.equal(real.classes, 9093);
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
