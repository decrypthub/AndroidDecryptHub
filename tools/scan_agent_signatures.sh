#!/usr/bin/env bash
# Signature scan for the shipped agent artifact (host-side, no device needed).
#
# Why this exists: the agent runs INSIDE the target process, so every string in its .rodata is a
# string the target can read back out of its own memory. A detector that greps its own mappings for
# a known tool name (frida / xposed / dobby / lsplant / <vendor>) does not need root, a hook, or a
# syscall - it only needs the strings to be there. This scan is the measurable half of "去特征":
# it turns "does the binary still carry identifying strings" into a pass/fail signal.
#
# Two classes of token:
#   - MUST_BE_ABSENT: our own identity strings. They have no external contract (nothing in the repo
#     parses logcat, and no host code matches these texts), so they must not appear at all.
#   - BUDGETED: strings we cannot remove yet without a coordinated change (exported symbol names the
#     Zygisk/Xposed loaders resolve, the Java bridge class inside the generated dex, vendored
#     third-party code). Each one carries the current count as a ceiling: the number may only go
#     down. Stage 2 fixes are named next to them.
#
# Usage: bash tools/scan_agent_signatures.sh [path/to/libadh_agent.so]
#   exit 0 = RESULT:PASS (or RESULT:SKIP when the artifact has not been built)
#   exit 1 = RESULT:FAIL (a MUST_BE_ABSENT token is present, or a budget was exceeded)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SO="${1:-agent/build/libadh_agent.so}"
case "$SO" in /*|[A-Za-z]:*) ;; *) SO="$ROOT/$SO" ;; esac
if [ ! -f "$SO" ]; then
  echo "RESULT:SKIP agent artifact not built ($SO)"
  echo "⏭ signature scan SKIP (run: bash tools/build_agent.sh)"
  exit 0
fi

OUT="$(node - "$SO" <<'EOF'
const fs = require('node:fs');
const so = process.argv[2];
const data = fs.readFileSync(so);
const strings = (data.toString('latin1').match(/[\x20-\x7e]{4,}/g) ?? []);
const uniq = [...new Set(strings)];

// --- stage 1: our own strings, no external contract, must be gone -----------------------------
const MUST_BE_ABSENT = [
  // our own log tags (v4.50: renamed to neutral rt.* - nothing outside the agent read logcat)
  'ADH_AGENT', 'ADH_RT', 'ADH_NATIVE_HOOK', 'ADH_INLINE', 'ADH_SITE', 'ADH_SLOT', 'ADH_JAVA_ENUM',
  // our own log/error text that named the tool
  'Host ADH Daemon', 'ADH wrapper',
  // our own messages that named the vendored frameworks
  'lsplant::', 'DobbyDestroy', 'stale Dobby state', 'fetch_dobby.sh', 'fetch_lsplant.sh',
  // the vendored ART backend, renamed by tools/patch_vendor_signatures.sh at fetch time: its suspend
  // reason, its log tag and (most importantly) the source name of the dex it generates at runtime
  'LSPlant', 'lsplant',
  // sandbox fixture names: the agent must never know them (they were defaults in qbdi_trace)
  'libadhdetect.so', 'adh_trace_target',
  // our own library name: it used to sit in .rodata (self-name fallback) and in DT_SONAME
  'libadh_agent.so',
];

// --- stage 2: known leaks we cannot remove yet, each with its ceiling ------------------------
// Stage 2 (each needs a coordinated change, named here so the budget can be driven to 0):
//   exports        -> rename adh_agent_* and update both loaders + the verify scripts that assert them
//   Java bridge    -> regenerate the embedded dex with a neutral package/class (+ the code-cache name)
//   reporter.class -> rename the property together with the sandbox app that sets it
//   Dobby/LSPlant  -> patch the vendored sources at fetch time (their PREBUILT static lib carries the
//                     names: rebuilding from patched source is the only way to drop them)
//   libQBDI.so     -> stage the tracer under a neutral file name (fetch + dlopen + docs)
//   libzygisk.so   -> the injection-backend probe reads the real module name
const BUDGETED = [
  { token: 'adh_agent_start', budget: 1, why: 'export name resolved by the Zygisk/Xposed loaders (stage 2: rename it and drop this to 0)' },
  { token: 'adh_agent_set_package', budget: 1, why: 'same loader contract (stage 2: rename it and drop this to 0)' },
  { token: 'com.adh.agent', budget: 1, why: 'Java bridge class inside the embedded dex (stage 2: rename it and drop this to 0)' },
  { token: 'AdhJavaHookBridge', budget: 10, why: 'the class name in the dex type descriptor + 9 bridge diagnostics; stage 2 renames them together' },
  { token: 'adh_bridge.dex', budget: 1, why: 'code-cache dex file name for the same bridge (stage 2: rename it and drop this to 0)' },
  { token: 'adh.reporter.class', budget: 1, why: 'property the sandbox sets to name its reporter class; stage 2 needs a DUAL READ (new name first, old as fallback) or existing targets silently lose the rich reporter' },
  { token: 'Dobby', budget: 2, why: 'prebuilt Dobby AAR (static lib only, no source): either binary-patch the archive or rebuild Dobby from patched source' },
  { token: 'DobbyHook', budget: 1, why: 'same prebuilt AAR' },
  { token: 'libQBDI.so', budget: 2, why: 'the real dlopen name of the tracer library' },
  { token: 'libzygisk.so', budget: 1, why: 'injection-backend probe reads the real module name' },
];

// Substring matching on purpose: for identity tokens that is the stricter reading (a token hidden inside
// a longer string still counts). The tradeoff is noise - a vendored path containing a short token would
// show up as a leak - so the tokens in the tables are kept specific.
const count = (t) => uniq.filter((s) => s.includes(t)).length;
const samples = (t, n = 4) => uniq.filter((s) => s.includes(t)).slice(0, n);

let bad = 0;
console.log(`artifact: ${so} (${data.length} bytes, ${strings.length} strings, ${uniq.length} unique)`);
console.log('\n-- stage 1: must be absent --');
for (const t of MUST_BE_ABSENT) {
  const n = count(t);
  if (n === 0) { console.log(`   ok    ${t}`); continue; }
  bad++;
  console.log(`   LEAK  ${t} x${n}`);
  for (const s of samples(t)) console.log(`           ${s.slice(0, 100)}`);
}
console.log('\n-- stage 2: budgeted (may only decrease) --');
for (const { token, budget, why } of BUDGETED) {
  const n = count(token);
  const verdict = n > budget ? 'OVER ' : 'ok   ';
  if (n > budget) bad++;
  console.log(`   ${verdict} ${token} x${n} (budget ${budget}) - ${why}`);
  if (n > budget) for (const s of samples(token)) console.log(`           ${s.slice(0, 100)}`);
}
console.log(`\nRESULT:${bad === 0 ? 'PASS' : 'FAIL'}`);
EOF
)"
echo "$OUT"
grep -q 'RESULT:PASS' <<<"$OUT"
