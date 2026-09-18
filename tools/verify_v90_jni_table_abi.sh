#!/usr/bin/env bash
# v4.54 JNIEnv table ABI check (HOST-ONLY: needs the NDK headers, no device).
#
# jni_env_hooks.c patches JNIEnv function-table entries BY INDEX. A wrong index would intercept a
# NEIGHBOURING JNI function, so the agent carries two guards: env_hook_slot() takes the address of the
# real struct field (the compiler computes the offset from jni.h) and env_hook_spec_index() returns
# the index the author believes in - the install refuses to patch when they disagree.
#
# This script checks that belief against the SDK's own jni.h: it reads the field order inside
# struct JNINativeInterface, maps every ENV_SLOT_* to the JNI function it claims, and fails on any
# mismatch. That validates the whole table without a device, and it is what makes ADDING slots
# mechanical: the new index is machine-checked before it ever runs in a target.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
# env.sh carries the NDK path this check reads jni.h from.
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

JNI_H="$NDK/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include/jni.h"
AGENT_C="$ROOT/agent/src/runtime/jni_env_hooks.c"
if [ ! -f "$JNI_H" ]; then
  echo "RESULT:SKIP jni.h not found ($JNI_H)"
  echo "⏭ JNIEnv table ABI SKIP"
  exit 0
fi
if [ ! -f "$AGENT_C" ]; then
  echo "RESULT:SKIP agent source not found ($AGENT_C)"
  echo "⏭ JNIEnv table ABI SKIP"
  exit 0
fi

OUT="$(node - "$JNI_H" "$AGENT_C" <<'EOF'
const fs = require('fs');
const [jniH, agentPath] = process.argv.slice(2);
const problems = [];
const notes = [];

// ---- 1. the ABI: field order inside struct JNINativeInterface ----
const h = fs.readFileSync(jniH, 'utf8');
const start = h.indexOf('struct JNINativeInterface {');
const end = start < 0 ? -1 : h.indexOf('\n};', start);
if (start < 0 || end < 0) {
  console.log('FAIL could not locate struct JNINativeInterface in jni.h');
  console.log('RESULT:FAIL');
  process.exit(0);
}
const body = h.slice(start, end);
const reserved = [...body.matchAll(/void\s*\*\s*(reserved\d+)\s*;/g)].map((m) => m[1]);
const fns = [...body.matchAll(/\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(/g)].map((m) => m[1]);
const abi = new Map();
reserved.forEach((r, i) => abi.set(r, i));
fns.forEach((f, i) => abi.set(f, reserved.length + i));
notes.push(`jni.h: ${reserved.length} reserved + ${fns.length} functions = ${abi.size} slots`);

// ---- 2. what the agent claims: slot name -> spec index ----
const src = fs.readFileSync(agentPath, 'utf8');
const claimed = new Map();
for (const m of src.matchAll(/case ENV_SLOT_([A-Za-z0-9_]+):\s*return (\d+);/g)) claimed.set(m[1], Number(m[2]));

// family macros: X(Name, ret, target, kind, ENV_SLOT_Name, SPEC) defines Name/NameV/NameA
const families = [];
const addFamily = (name, spec) => {
  families.push({ name, spec });
  claimed.set(name, spec);
  claimed.set(name + 'V', spec + 1);
  claimed.set(name + 'A', spec + 2);
};
// value families: X(Name, ret, target, kind, ENV_SLOT_Name, SPEC)
for (const m of src.matchAll(/X\(\s*([A-Za-z0-9_]+)\s*,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*ENV_SLOT_[A-Za-z0-9_]+\s*,\s*(\d+)\s*\)/g)) addFamily(m[1], Number(m[2]));
// void families: X(Name, target, kind, ENV_SLOT_Name, SPEC)
for (const m of src.matchAll(/X\(\s*([A-Za-z0-9_]+)\s*,\s*[^,]+,\s*[^,]+,\s*ENV_SLOT_[A-Za-z0-9_]+\s*,\s*(\d+)\s*\)/g)) {
  if (!claimed.has(m[1])) addFamily(m[1], Number(m[2]));
}
// fixed slots declared for installation: X("GetStringUTFChars") ...
const fixed = [...src.matchAll(/X\("([A-Za-z0-9_]+)"\)/g)].map((m) => m[1]);
notes.push(`agent: ${fixed.length} fixed slots + ${families.length} call families (= ${fixed.length + families.length * 3} table entries), ${claimed.size} spec indices`);

// ---- 3. every claimed index must equal the ABI index ----
for (const [name, spec] of claimed) {
  const abiIdx = abi.get(name);
  if (abiIdx === undefined) { problems.push(`spec index for '${name}' has no counterpiece in jni.h`); continue; }
  if (abiIdx !== spec) problems.push(`'${name}': agent says ${spec}, jni.h says ${abiIdx}`);
}
// ---- 4. every slot we install must HAVE a spec index (a missing one makes the install refuse) ----
for (const name of fixed) {
  if (!claimed.has(name)) problems.push(`fixed slot '${name}' has no spec index (the install would refuse it)`);
}
for (const f of families) {
  for (const suffix of ['', 'V', 'A']) {
    if (!claimed.has(f.name + suffix)) problems.push(`call family '${f.name}${suffix}' has no spec index`);
  }
}
notes.push(`checked ${claimed.size} indices against the ABI`);

// ---- coverage report: turn "JNIEnv fully hookable" into a number ----
const abiFns = [...abi.keys()].filter((n) => !/^reserved\d+$/.test(n));
const covered = abiFns.filter((n) => claimed.has(n));
const uncovered = abiFns.filter((n) => !claimed.has(n));
notes.push(`coverage: ${covered.length}/${abiFns.length} function-table entries hooked (${Math.round((covered.length / abiFns.length) * 100)}%)`);
notes.push(`uncovered (${uncovered.length}): ${uncovered.slice(0, 16).join(', ')}${uncovered.length > 16 ? ', ...' : ''}`);
if (covered.length < 133) problems.push(`JNIEnv coverage dropped to ${covered.length}/${abiFns.length} (expected >= 133; the floor only ratchets up)`);

// ---- 5. pin the indices the NEXT step (field accessors) will use, so those numbers come from the
// ABI header instead of being hand-copied into the implementation or the docs ----
const FIELD_TYPES = ['Object', 'Boolean', 'Byte', 'Char', 'Short', 'Int', 'Long', 'Float', 'Double'];
const planned = [];
for (let i = 0; i < FIELD_TYPES.length; i++) {
  planned.push([`Get${FIELD_TYPES[i]}Field`, 95 + i]);
  planned.push([`Set${FIELD_TYPES[i]}Field`, 104 + i]);
  planned.push([`GetStatic${FIELD_TYPES[i]}Field`, 145 + i]);
  planned.push([`SetStatic${FIELD_TYPES[i]}Field`, 154 + i]);
}
for (const [name, spec] of planned) {
  const abiIdx = abi.get(name);
  if (abiIdx === undefined) problems.push(`planned field accessor '${name}' is not in jni.h`);
  else if (abiIdx !== spec) problems.push(`planned field accessor '${name}': expected ${spec}, jni.h says ${abiIdx}`);
}
notes.push(`planned field accessors: ${planned.length} indices verified (instance Get 95-103 / Set 104-112, static Get 145-153 / Set 154-162)`);

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.54 JNIEnv table indices match the SDK jni.h ABI" 0
