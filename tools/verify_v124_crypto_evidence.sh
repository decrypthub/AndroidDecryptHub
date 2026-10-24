#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_unit_pass "explicit crypto evidence and attribution" crypto_evidence.test.ts 16 || exit 1
cd "$ROOT"
set +e
OUT="$(node --input-type=module - <<'EOF'
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeCryptoEvidence, saveCryptoEvidence, readCryptoEvidence } from './daemon/src/crypto_evidence.ts';
import { buildCryptoChallenge } from './daemon/test/fixtures/crypto_challenge.ts';
const dir = mkdtempSync(join(tmpdir(), 'adh-v124-'));
try {
  const seed = randomBytes(32).toString('hex');
  const { input, expected } = buildCryptoChallenge(seed);
  const report = analyzeCryptoEvidence(input), rows = new Map(report.rows.map(row => [row.id, row]));
  for (const id of expected.validIds) assert.equal(rows.get(id).checks[0].status, 'matched', id);
  for (const id of expected.mismatchedIds) assert.equal(rows.get(id).checks[0].status, 'mismatched', id);
  for (const id of expected.unavailableIds) assert.equal(rows.get(id).checks[0].status, 'unavailable', id);
  assert.equal(report.counts.matched, expected.validIds.length);
  assert.equal(report.counts.mismatched, expected.mismatchedIds.length);
  assert.equal(report.counts.unavailable, expected.unavailableIds.length);
  assert.ok(report.contentLinks.some(link => link.from === 'r0:s0:sha256' && link.to === 'r0:s1:add-xor'));
  assert.ok(report.contentLinks.some(link => link.from === 'r0:s2:hmac-sha1' && link.to === 'r0:s3:xor'));
  const saved = saveCryptoEvidence(dir, input, 'random synthetic challenge');
  let offset = 0, read = 0;
  do {
    const page = readCryptoEvidence(dir, saved.id, { offset, limit: 8 });
    assert.ok(page.rows.length <= 8); assert.equal('observations' in page, false);
    read += page.rows.length; offset = page.nextOffset;
  } while (offset !== null);
  assert.equal(read, input.observations.length);
  console.log(JSON.stringify({ seed, counts: report.counts, recipes: expected.recipes,
    parameterProfiles: expected.parameterProfiles, chunkedBinaryInputs: expected.binaryChunkedInputs,
    scope: 'Host paired-evidence verification; no claim of blind native deobfuscation' }));
  console.log('RESULT:PASS');
} catch (e) { console.error(e); console.log('RESULT:FAIL'); process.exitCode = 1; }
finally { rmSync(dir, { recursive: true, force: true }); }
EOF
)"
RC=$?
set -e
echo "$OUT"
if [ "$RC" != 0 ]; then exit "$RC"; fi
verify_gate 'crypto evidence random-parameter composition challenge' 0
