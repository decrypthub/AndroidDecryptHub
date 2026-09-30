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
# env.sh resolves JNI_H (and CLANG) from an NDK that has THIS host's toolchain, falling back to
# other installed NDKs when the pinned Win-path one is absent. Do not hardcode the path here — doing
# so made this check SKIP silently on a Linux host that had a usable NDK.
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

AGENT_C="$ROOT/agent/src/runtime/jni_env_hooks.c"
if [ ! -f "$JNI_H" ]; then
  echo "RESULT:SKIP jni.h not found (JNI_H='${JNI_H:-<unresolved>}' — set ANDROID_NDK_HOME)"
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
// Fixed slots: they live in their own list macro (ADH_FIXED_SLOT_LIST, unquoted names) that now
// drives the enum values AND the installable-name table, so parsing that list is also checking
// that the agent has one source of truth for them.
const fixedDef = src.match(/#define ADH_FIXED_SLOT_LIST\(X\)([\s\S]*?)\n#define /);
const fixed = fixedDef ? [...fixedDef[1].matchAll(/\bX\(([A-Za-z0-9_]+)\)/g)].map((m) => m[1]) : [];
if (fixed.length !== 99) problems.push(`expected 99 fixed slots in ADH_FIXED_SLOT_LIST, found ${fixed.length}`);
// field accessors live in their own list macro (ADH_FIELD_SLOT_LIST, v4.55) and are installed by
// name as well, so they belong in the "what can we install" inventory - and in the spec-index check.
const fieldDef = src.match(/#define ADH_FIELD_SLOT_LIST\(X\)([\s\S]*?)\n#define /);
const fieldSlots = fieldDef ? [...fieldDef[1].matchAll(/\bX\(([A-Za-z0-9_]+)\)/g)].map((m) => m[1]) : [];
if (fieldSlots.length !== 36) problems.push(`expected 36 field accessors in ADH_FIELD_SLOT_LIST, found ${fieldSlots.length} (update this gate deliberately when the list changes)`);
notes.push(`agent: ${fixed.length} fixed slots + ${fieldSlots.length} field accessors + ${families.length} call families (= ${fixed.length + fieldSlots.length + families.length * 3} table entries), ${claimed.size} spec indices`);

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
for (const name of fieldSlots) {
  if (!claimed.has(name)) problems.push(`field accessor '${name}' has no spec index (the install would refuse it)`);
}
for (const f of families) {
  for (const suffix of ['', 'V', 'A']) {
    if (!claimed.has(f.name + suffix)) problems.push(`call family '${f.name}${suffix}' has no spec index`);
  }
}
notes.push(`checked ${claimed.size} indices against the ABI`);

// ---- 5. installability and event wiring -------------------------------------
// A name that resolves and then hits no case is refused at runtime (fail-loud, but only once a
// device is attached); a wrapper that never emits looks installed and silently collects nothing.
// Both are cheap to catch here. The dispatch cases are generated from the same lists that build the
// enum and the table, so the check is about the macro bodies pairing a name with ITS OWN field and
// wrapper - a hand-written pair with identical signatures (two ID lookups, two field entries) used
// to be invisible to the signature asserts, the layout check and the offset check alike.
const macroBodies = new Map();
{
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^#define\s+([A-Za-z0-9_]+)\s*(\([^)]*\))?\s*(.*)$/);
    if (!m) continue;
    let body = m[3];
    while (lines[i].trimEnd().endsWith('\\') && i + 1 < lines.length) { i++; body += '\n' + lines[i]; }
    macroBodies.set(m[1], body);
  }
}
const missingExpansions = [
  'ADH_FIXED_SLOT_LIST(ADH_FIXED_SLOT_CASE)', 'ADH_FIXED_SLOT_LIST(ADH_FIXED_WRAPPER_CASE)',
  'ADH_FIELD_SLOT_LIST(ADH_FIELD_SLOT_CASE)', 'ADH_FIELD_SLOT_LIST(ADH_FIELD_WRAPPER_CASE)',
  'ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)', 'ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)',
  'ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)', 'ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)',
  'ADH_CALL_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)', 'ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)',
  'ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)', 'ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)',
].filter((e) => !src.includes(e));
if (missingExpansions.length) problems.push(`missing dispatch expansion(s): ${missingExpansions.join(', ')}`);
// A case macro must select the SAME member it dispatches to; that pairing is what a hand-written
// switch can get wrong while every other check stays green.
const pairing = [
  ['ADH_FIXED_SLOT_CASE', /&table->name\b/, 'selects &table->name'],
  ['ADH_FIXED_WRAPPER_CASE', /&name##_wrapper/, 'installs &name##_wrapper'],
  ['ADH_FIELD_SLOT_CASE', /&table->name\b/, 'selects &table->name'],
  ['ADH_FIELD_WRAPPER_CASE', /&name##_wrapper/, 'installs &name##_wrapper'],
  // Anchored on the semicolon: /&table->name\b/ also matches "&table->name##V" (# is a non-word
  // char, so \b still holds), which let the family BASE case be deleted with the gate still green.
  ['ADH_CALL_SLOT_CASES', /&table->name;/, 'selects &table->name'],
  ['ADH_CALL_SLOT_CASES', /&table->name##V;/, 'selects &table->nameV'],
  ['ADH_CALL_SLOT_CASES', /&table->name##A;/, 'selects &table->nameA'],
  ['ADH_CALL_WRAPPER_CASES', /&name##_wrapper;/, 'installs &name_wrapper'],
  ['ADH_CALL_WRAPPER_CASES', /&name##V_wrapper/, 'installs &nameV_wrapper'],
  ['ADH_CALL_WRAPPER_CASES', /&name##A_wrapper;/, 'installs &nameA_wrapper'],
];
for (const [macro, pattern, what] of pairing) {
  const body = macroBodies.get(macro) ?? '';
  if (!pattern.test(body)) problems.push(`${macro} must ${what} (the case and the entry it returns have to stay paired)`);
}
// Every wrapper-generating macro must contain an emit call, and so must every hand-written wrapper.
const silentMacros = [...macroBodies.entries()]
  .filter(([name, body]) => name.startsWith('ADH_DEFINE_') && /_wrapper\(/.test(body) && !/env_note\(|call_emit\(/.test(body))
  .map(([name]) => name);
if (silentMacros.length) problems.push(`wrapper macros with no event call: ${silentMacros.join(', ')}`);
const silentWrappers = [];
for (const m of src.matchAll(/static [^\n]*?([A-Za-z0-9_]+)_wrapper\([^)]*\)\s*\{([\s\S]*?)\n\}/g)) {
  if (m[1] === 'env_hook') continue;   // the dispatch helper itself, matched by the same shape
  if (!/env_note\(|call_emit\(/.test(m[2])) silentWrappers.push(m[1]);
}
if (silentWrappers.length) problems.push(`hand-written wrappers with no event call: ${silentWrappers.join(', ')}`);
// A wrapper body must talk about ITS OWN slot. A hand-written wrapper that calls slot_original() or
// env_note() with a foreign ENV_SLOT_* emits into (and restores) the wrong slot while looking
// perfectly healthy - no other gate and no signature assert can see it, only a device run.
const foreignSlots = [];
for (const m of src.matchAll(/static [^\n]*?([A-Za-z0-9_]+)_wrapper\([^)]*\)\s*\{([\s\S]*?)\n\}/g)) {
  if (m[1] === 'env_hook') continue;
  const foreign = [...new Set([...m[2].matchAll(/ENV_SLOT_([A-Za-z0-9_]+)/g)].map((x) => x[1]))].filter((s) => s !== m[1]);
  if (foreign.length) foreignSlots.push(`${m[1]} uses ${foreign.join(',')}`);
}
if (foreignSlots.length) problems.push(`hand-written wrappers referencing another slot: ${foreignSlots.join('; ')}`);
// Macro-generated wrappers take the slot as a parameter (ENV_SLOT_##NAME); a literal ENV_SLOT_ name
// inside such a macro means the generic wrapper is hard-wired to one entry.
const hardwired = [...macroBodies.entries()]
  .filter(([, body]) => /_wrapper\(/.test(body) && /ENV_SLOT_[A-Za-z0-9_]+/.test(body))
  .map(([name]) => name);
if (hardwired.length) problems.push(`wrapper macros naming a slot literally: ${hardwired.join(', ')}`);
notes.push(`wiring: ${fixed.length} fixed slots dispatched from the list, ${fieldSlots.length} field accessors and ${families.length} families kept paired, ${silentWrappers.length + silentMacros.length} silent wrappers`);

// ---- coverage report: turn "JNIEnv fully hookable" into a number ----
const abiFns = [...abi.keys()].filter((n) => !/^reserved\d+$/.test(n));
const covered = abiFns.filter((n) => claimed.has(n));
const uncovered = abiFns.filter((n) => !claimed.has(n));
notes.push(`coverage: ${covered.length}/${abiFns.length} function-table entries hooked (${Math.round((covered.length / abiFns.length) * 100)}%)`);
notes.push(`uncovered (${uncovered.length}): ${uncovered.slice(0, 16).join(', ')}${uncovered.length > 16 ? ', ...' : ''}`);
// The one entry no table slot can claim: jni_hooks.c inline-hooks the RegisterNatives entry
// itself and reports JNI_HOOK events, so it is covered by a different mechanism on purpose.
const COVERED_ELSEWHERE = new Set(['RegisterNatives']);
const unclassified = uncovered.filter((n) => !COVERED_ELSEWHERE.has(n));
if (unclassified.length) problems.push(`unclassified JNIEnv entries (neither hooked nor covered elsewhere): ${unclassified.join(', ')}`);
if (covered.length < 228) problems.push(`JNIEnv coverage dropped to ${covered.length}/${abiFns.length} (expected >= 228; the floor only ratchets up)`);

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
