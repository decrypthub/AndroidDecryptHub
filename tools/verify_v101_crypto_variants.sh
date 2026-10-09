#!/usr/bin/env bash
# v10.1 mutated-algorithm identification (HOST-ONLY).
#
# The gap this closes, measured rather than argued: ADH identified crypto two ways — by the library
# function a capture came from, and by a fixed table of STANDARD constants (`native_crypto_const`).
# An app that implements the algorithm itself and perturbs it defeats both at once: no library call
# to name, and no standard constant to match. Worse, on a real mutated binary the constant scan does
# not merely go quiet, it MISREPORTS — this script asserts that too (see step 4).
#
# Fixtures are compiled, not synthesised: fixtures/crypto-variants/{std,variant}.c are built into two
# real arm64 .so files, one textbook (the negative control) and one carrying the mutations that the
# reference sample repo actually ships (MD5 init rewritten, SHA1 round constants rewritten, base64
# alphabet permuted). Asserting against a Buffer the test assembled itself would only prove the test
# can spell the constants.
#
# Exit 0 = PASS. SKIPs (no clang, no daemon) exit 0 without the sentinel.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# --- 1. the detector's own unit tests (pure, no daemon, no compiler) --------------------------
if ! verify_unit_pass "crypto-variant detector" crypto_variants.test.ts 13; then
  echo "RESULT:FAIL (crypto-variant unit tests did not all pass)"
  exit 1
fi

# --- 2. build the fixtures -------------------------------------------------------------------
# $CLANG comes from tools/lib/env.sh: an NDK that has THIS host's toolchain, falling back to another
# installed NDK when the pinned Win-path one is absent. Hardcoding the Windows path here made this
# script SKIP ("no clang") on a Linux host that could build the fixtures perfectly well.
if [ ! -x "$CLANG" ]; then
  echo "SKIP (no clang resolved — CLANG='${CLANG:-<empty>}'; set ANDROID_NDK_HOME or install an NDK)"
  exit 0
fi
if ! bash "$ROOT/tools/build_crypto_variants.sh"; then
  echo "RESULT:FAIL (fixture build failed)"
  exit 1
fi

if ! curl -s -o /dev/null "http://127.0.0.1:$HTTP/health"; then
  echo "SKIP (no daemon on :$HTTP)"
  exit 0
fi

# --- 3+4. scan both fixtures through the daemon's own REST surface ---------------------------
OUT="$(node - "$ROOT" "$HTTP" <<'EOF'
const [root, http] = process.argv.slice(2);
import { readFileSync } from 'node:fs';
const base = `http://127.0.0.1:${http}`;
const post = async (p, b) => (await (await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })).json());
const problems = [];
const checks = [];
const chk = (label, cond, detail) => { if (cond) checks.push(label); else problems.push(`${label}${detail ? ` — ${detail}` : ''}`); };

const scan = async (name) => {
  const b64 = readFileSync(`${root}/fixtures/crypto-variants/build/libadhcrypto_${name}.so`).toString('base64');
  return { variants: await post('/api/native/crypto_variants', { b64 }), consts: await post('/api/native/crypto_const', { b64 }) };
};
const fam = (r, f) => r.families.find((x) => x.family === f);

const std = await scan('std');
const varnt = await scan('variant');

// --- negative control: a textbook implementation must produce NO variant verdict ---------------
chk('negative control (textbook constants): every family reports standard, zero variant verdicts',
  std.variants.families.length >= 3 && std.variants.families.every((f) => f.verdict === 'standard') &&
  std.variants.alphabets.length === 1 && std.variants.alphabets[0].kind === 'standard' && std.variants.alphabets[0].substitutions === 0,
  JSON.stringify(std.variants.families.map((f) => `${f.family}:${f.verdict}`)));

// --- the mutated MD5: anchored by the K table the mutation left intact ------------------------
const md5 = fam(varnt.variants, 'MD5');
chk('mutated MD5 is a VARIANT, anchored on the round-constant table the mutation did not touch',
  md5?.verdict === 'variant' && md5.missing.length === 1 && /init/.test(md5.missing[0]), JSON.stringify(md5));
chk('the rewritten init is reported as a perturbed copy, with how much of it survived',
  /12\/16 bytes/.test(String(md5?.detail)), String(md5?.detail));

// --- the mutated SHA1: anchored from the opposite end ----------------------------------------
const sha1 = fam(varnt.variants, 'SHA1');
chk('mutated SHA1 is a VARIANT, anchored on the IV the mutation did not touch',
  sha1?.verdict === 'variant' && /round constants/.test(String(sha1?.missing?.[0])), JSON.stringify(sha1));

// --- the permuted base64 alphabet: found by shape, with the drift counted ---------------------
const custom = varnt.variants.alphabets.find((a) => a.kind === 'variant');
chk('the permuted base64 alphabet is found by shape and its drift is counted',
  custom?.substitutions === 54 && custom.sample.startsWith('abcdefghijklmnopqrstuvwxyz'), JSON.stringify(custom));

// --- a different standard is not a mutation --------------------------------------------------
chk('CRC-32C is reported as the standard family it is, not as a mutation',
  /CRC-32C/.test(String(fam(varnt.variants, 'CRC32')?.anchor.what)), JSON.stringify(fam(varnt.variants, 'CRC32')?.anchor));

// --- the limit statement: a static scan must say where it is blind ---------------------------
chk('the report states its own blind spots (runtime-built tables, anchor-rewriting mutations)',
  varnt.variants.limits.length === 3 && varnt.variants.limits.some((l) => /builds at runtime/.test(l)),
  JSON.stringify(varnt.variants.limits.length));

// --- 4. THE GAP, asserted: the standard-constant scan cannot tell the two apart, and one of its
//        names on the mutated binary is a false positive (it calls MD5 standard while MD5's init is
//        gone — the pattern it matched is the first 8 bytes of the SHA1 init).
const sameNames = JSON.stringify(std.consts.algorithms) === JSON.stringify(varnt.consts.algorithms);
chk('the standard-constant scan returns the SAME algorithm names for both binaries (it is blind to the mutation)',
  sameNames, `std=${JSON.stringify(std.consts.algorithms)} variant=${JSON.stringify(varnt.consts.algorithms)}`);
chk('and it claims MD5-init on the mutated binary even though the MD5 init is gone (a false positive)',
  varnt.consts.algorithms.includes('MD5-init') && md5?.verdict === 'variant',
  `const-scan=${JSON.stringify(varnt.consts.algorithms)} vs variant scan=${md5?.verdict}`);

// --- the MCP surface can reach it, and the old tool points at the new one ---------------------
const tools = (await (await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) })).json()).result.tools;
const vt = tools.find((t) => t.name === 'crypto_variant_scan');
const ct = tools.find((t) => t.name === 'native_crypto_const');
chk('the MCP surface exposes crypto_variant_scan', !!vt, `tools=${tools.length}`);
chk('native_crypto_const points at crypto_variant_scan so a caller finds the second layer',
  /crypto_variant_scan/.test(String(ct?.description)), String(ct?.description).slice(0, 80));

console.log(`checks=${checks.length} problems=${problems.length}`);
console.log(`  ${checks.join('\n  ')}`);
if (problems.length) { console.log('problems:'); for (const p of problems.slice(0, 20)) console.log('  ✗ ' + p); }
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v10.1 mutated-algorithm identification (structure-anchored, mutation named, standard-constant scan proven blind)" 0
