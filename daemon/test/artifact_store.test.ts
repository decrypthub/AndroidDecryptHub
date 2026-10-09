import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactKindOf, planArtifactEviction } from '../src/artifacts.ts';

const MB = 1024 * 1024;
const DAY = 86_400_000;
const at = (n: number) => n * DAY;
// NB: mtime 0 means "unknown" in the policy (a real file never has mtime 0), so tests must not use
// it to mean "the epoch" — that is what UNKNOWN_MTIME pins below.

test('artifactKindOf maps the three naming schemes this daemon writes, and rejects anything else', () => {
  assert.equal(artifactKindOf('8832caf91837712c.dex.bin'), 'dex');
  assert.equal(artifactKindOf('0d29d08b1a755c37.region.bin'), 'region');
  assert.equal(artifactKindOf('8832caf91837712c.bin'), 'region');   // no middle segment
  assert.equal(artifactKindOf('0cb604faf9fa4767.so'), 'so');
  assert.equal(artifactKindOf('0fdc8883db4a64e4.dex'), 'dex');
  // not artifacts we wrote: readme.txt, a subdirectory, a short/long prefix, an uppercase hex run
  assert.equal(artifactKindOf('readme.txt'), null);
  assert.equal(artifactKindOf('ecapture'), null);
  assert.equal(artifactKindOf('8832caf9183771.dex.bin'), null);
  assert.equal(artifactKindOf('8832CAF91837712C.dex.bin'), null);
  assert.equal(artifactKindOf('8832caf91837712c.dex.bin.tmp'), null);
});

test('eviction: nothing to do under both limits', () => {
  const entries = [
    { sha256: 'a', path: '/a', size: 10 * MB, mtime: at(100) },
    { sha256: 'b', path: '/b', size: 10 * MB, mtime: at(101) },
  ];
  const r = planArtifactEviction(entries, { maxBytes: 100 * MB, maxAgeDays: 14 }, at(102));
  assert.deepEqual(r.evict, []);
  assert.equal(r.overAge, 0);
  assert.equal(r.overSize, 0);
  assert.equal(r.remainingBytes, 20 * MB);
});

test('eviction: over-age entries go regardless of the byte budget, and are counted separately', () => {
  const entries = [
    { sha256: 'old', path: '/old', size: 1 * MB, mtime: at(1) },
    { sha256: 'fresh', path: '/fresh', size: 1 * MB, mtime: at(30) },
  ];
  const r = planArtifactEviction(entries, { maxBytes: 1000 * MB, maxAgeDays: 14 }, at(30));
  assert.deepEqual(r.evict.map((e) => e.sha256), ['old']);
  assert.equal(r.overAge, 1);
  assert.equal(r.overSize, 0);
  assert.equal(r.remainingBytes, 1 * MB);
});

test('eviction: maxAgeDays = 0 turns the age rule off, the size budget still applies', () => {
  const entries = [{ sha256: 'ancient', path: '/ancient', size: 1 * MB, mtime: at(1) }];
  const off = planArtifactEviction(entries, { maxBytes: 100 * MB, maxAgeDays: 0 }, at(10_000));
  assert.deepEqual(off.evict, []);
  assert.equal(off.remainingBytes, 1 * MB);
  const on = planArtifactEviction(entries, { maxBytes: 100 * MB, maxAgeDays: 14 }, at(10_000));
  assert.deepEqual(on.evict.map((e) => e.sha256), ['ancient']);
});

test('eviction: oldest-first until the budget is met, and no further', () => {
  const entries = [
    { sha256: 'newest', path: '/n', size: 4 * MB, mtime: at(300) },
    { sha256: 'oldest', path: '/o', size: 4 * MB, mtime: at(100) },
    { sha256: 'middle', path: '/m', size: 4 * MB, mtime: at(200) },
  ];
  // 12 MB held, budget 8 MB: only the oldest has to go.
  const r = planArtifactEviction(entries, { maxBytes: 8 * MB, maxAgeDays: 0 }, at(400));
  assert.deepEqual(r.evict.map((e) => e.sha256), ['oldest']);
  assert.equal(r.overSize, 1);
  assert.equal(r.remainingBytes, 8 * MB);
});

test('eviction: the artifact just written is never evicted by the size rule', () => {
  // The protected entry is the OLDEST here, so it is the first candidate — it must still survive.
  const entries = [
    { sha256: 'just-written', path: '/w', size: 9 * MB, mtime: at(100) },
    { sha256: 'other', path: '/x', size: 9 * MB, mtime: at(200) },
  ];
  const r = planArtifactEviction(entries, { maxBytes: 10 * MB, maxAgeDays: 0 }, at(300), 'just-written');
  assert.deepEqual(r.evict.map((e) => e.sha256), ['other']);
  assert.equal(r.remainingBytes, 9 * MB);
});

test('eviction: a budget below a single artifact still reports what it actually freed', () => {
  // Only one artifact and it exceeds the budget: it is the protected one, so nothing can be freed.
  const entries = [{ sha256: 'only', path: '/only', size: 500 * MB, mtime: at(1) }];
  const r = planArtifactEviction(entries, { maxBytes: 256 * MB, maxAgeDays: 0 }, at(2), 'only');
  assert.deepEqual(r.evict, []);
  assert.equal(r.remainingBytes, 500 * MB);   // honest: the store is still over budget
});

test('eviction: an artifact whose mtime cannot be read is kept, not guessed to be ancient', () => {
  // state.ts fills mtime from statSync with a capturedAt fallback; a 0 means neither was available.
  // Deleting on "I could not tell how old this is" would destroy the newest artifact on a stat
  // failure, so the age rule skips it (the size rule can still reclaim it).
  const entries = [{ sha256: 'unknown', path: '/u', size: 50 * MB, mtime: 0 }];
  const aged = planArtifactEviction(entries, { maxBytes: 1000 * MB, maxAgeDays: 1 }, at(10_000));
  assert.deepEqual(aged.evict, []);
  const sized = planArtifactEviction(entries, { maxBytes: 10 * MB, maxAgeDays: 0 }, at(10_000));
  assert.deepEqual(sized.evict.map((e) => e.sha256), ['unknown']);
});
