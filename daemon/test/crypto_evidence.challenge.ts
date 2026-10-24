// Host acceptance: random parameters, four compositions, shuffled captures and deliberate defects.
import assert from 'node:assert/strict';
import { analyzeCryptoEvidence } from '../src/crypto_evidence.ts';
import { buildCryptoChallenge } from './fixtures/crypto_challenge.ts';

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--seed')) throw new Error('usage: node test/crypto_evidence.challenge.ts [--seed <64hex>]');
const challenge = buildCryptoChallenge(args[1]);
const report = analyzeCryptoEvidence(challenge.input);
const rows = new Map(report.rows.map(row => [row.id, row]));
for (const id of challenge.expected.validIds) assert.equal(rows.get(id)!.checks[0].status, 'matched', id);
for (const id of challenge.expected.mismatchedIds) assert.equal(rows.get(id)!.checks[0].status, 'mismatched', id);
for (const id of challenge.expected.unavailableIds) assert.equal(rows.get(id)!.checks[0].status, 'unavailable', id);
assert.equal(report.counts.matched, challenge.expected.validIds.length);
assert.equal(report.counts.mismatched, challenge.expected.mismatchedIds.length);
assert.equal(report.counts.unavailable, challenge.expected.unavailableIds.length);
assert.equal(report.contentLinks.some(link => link.from === 'r0:s0:sha256' && link.to === 'r0:s1:add-xor'), true);
assert.equal(report.contentLinks.some(link => link.from === 'r0:s2:hmac-sha1' && link.to === 'r0:s3:xor'), true);
const hmacGroups = report.parameterGroups.filter(group => group.algorithm.startsWith('hmac-'));
assert.ok(hmacGroups.length >= challenge.expected.parameterProfiles);
console.log(JSON.stringify({ ok: true, seed: challenge.seed, counts: report.counts, dimensions: {
  recipes: challenge.expected.recipes, parameterProfiles: challenge.expected.parameterProfiles,
  chunkedBinaryInputs: challenge.expected.binaryChunkedInputs, shuffled: true,
  rejected: challenge.expected.unavailableIds, mismatched: challenge.expected.mismatchedIds,
}, caveat: 'Host evidence-verification challenge, not a blind deobfuscation or native hostile-runtime benchmark.' }));
