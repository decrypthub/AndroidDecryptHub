#!/usr/bin/env bash
# v4.53 object_set (device): patch a field of a LIVE object, like Frida field assignment.
#
# We could already read a live object (object_inspect) and call its methods (object_invoke); the
# missing half was writing - flipping isRooted/debugChecked/a key blob on an instance is a normal
# analysis move. This drives the write through the same static-holder convention and proves three
# things: the reply carries before/after, the new value is visible to a FOLLOW-UP read in the target,
# and a field that cannot be written (Kotlin val -> final) comes back ok:false instead of pretending.
#
# Missing preconditions (no device / no agent / old APK without the mutable fixture) print SKIP and
# exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v89_object_set (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const skip = (msg) => { console.log('SKIP  verify_v89_object_set (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
const fail = (msg, extra) => { if (extra !== undefined) console.log(JSON.stringify(extra)); console.log('FAIL ' + msg); console.log('RESULT:FAIL'); process.exit(0); };
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let parsed = null; try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : []).filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) skip('no online sandbox agent');
const session = agent.sessionId;
const CLASS = 'com.adh.sandbox.HeapProbe';
let inheritedOk = true;   // stays true when the sandbox APK predates the inherited fixture
const HOLDER = 'sConfig';
const set = (targetField, value) => post('/api/object/set', { session, className: CLASS, field: HOLDER, targetField, value });
// The inherited-field fixture is a SECOND holder object: writing "inherited" through sConfig can
// only fail (that field is not on Config), which is what the first device run showed.
const setOn = (holder, targetField, value) => post('/api/object/set', { session, className: CLASS, field: holder, targetField, value });

// (0) positive control: the read path must work, so a failing write cannot be excused by a missing
// fixture. A payload without object_set answers with an unknown-op error -> SKIP.
const probe = await post('/api/object/inspect', { session, className: CLASS, field: HOLDER });
if (probe.body?.ok !== true) skip('object_inspect fixture unavailable: ' + String(probe.body?.error ?? probe.status));
const firstSet = await set('flag', 'true');
const setErr = String(firstSet.body?.error ?? '');
if (/unknown op|unsupported/i.test(setErr)) skip('agent predates object_set: ' + setErr);
const fixtureMissing = /target field not found|unsupported field type/i.test(setErr);
if (fixtureMissing) skip('sandbox APK has no mutable fixture fields: ' + setErr);

// (1) boolean write with before/after
console.log(`flag: ok=${firstSet.body?.ok} type=${firstSet.body?.type} before=${firstSet.body?.before} after=${firstSet.body?.after}`);
if (firstSet.body?.ok !== true) fail('boolean write failed: ' + setErr, firstSet.body);
const flagBefore = firstSet.body.before === 'false';
const flagAfter = firstSet.body.after === 'true';

// (2) the write must be visible to a NEW read inside the target
const afterRead = await post('/api/object/inspect', { session, className: CLASS, field: HOLDER });
const fields = Object.fromEntries((afterRead.body?.fields ?? []).map((f) => [f.name, f.value]));
console.log(`read back: flag=${fields.flag} counter=${fields.counter} label=${fields.label}`);

// (3) int + String writes
const counter = await set('counter', '99');
const label = await set('label', 'patched');
console.log(`counter: ok=${counter.body?.ok} ${counter.body?.before} -> ${counter.body?.after}`);
console.log(`label: ok=${label.body?.ok} ${label.body?.before} -> ${label.body?.after}`);

// (3b) an INHERITED field: declared on the superclass, so getDeclaredField alone would say
// "not found". The write must succeed AND the follow-up read (which now walks the chain too) must
// show the new value together with its declaring class.
const inheritedProbe = await post('/api/object/inspect', { session, className: CLASS, field: 'sInherited' });
if (inheritedProbe.body?.ok !== true) {
  console.log('inherited fixture unavailable (older APK) - that part is skipped');
} else {
  const inheritedSet = await setOn('sInherited', 'inherited', '9');
  const inheritedRead = await post('/api/object/inspect', { session, className: CLASS, field: 'sInherited' });
  const inhFields = Object.fromEntries((inheritedRead.body?.fields ?? []).map((f) => [f.name, f.value]));
  const inhDeclaring = (inheritedRead.body?.fields ?? []).find((f) => f.name === 'inherited')?.class ?? '';
  console.log(`inherited: ok=${inheritedSet.body?.ok} ${inheritedSet.body?.before} -> ${inheritedSet.body?.after} readBack=${inhFields.inherited} declaredOn=${inhDeclaring}`);
  inheritedOk = inheritedSet.body?.ok === true && inheritedSet.body.before === '5' && inheritedSet.body.after === '9'
    && inhFields.inherited === '9' && /InheritBase/.test(inhDeclaring);
  const restoreInherited = await setOn('sInherited', 'inherited', '5');
  if (restoreInherited.body?.ok !== true) inheritedOk = false;
}

// (4) a final field (Kotlin val) must fail loud, not pretend
const finalField = await set('note', 'nope');
console.log(`final field: ok=${finalField.body?.ok} error=${JSON.stringify(String(finalField.body?.error ?? '').slice(0, 60))}`);
// The reason must name the real cause: "set failed" alone would also match a rejected VALUE, which
// is a different bug class (and a fixture that silently became writable would pass unnoticed).
const finalRefused = finalField.body?.ok === false && /final|read-only/i.test(String(finalField.body?.error ?? ''));

// (4b) strict parsing: a typo must not be written as 0, and an out-of-range int must not wrap.
const typo = await set('counter', 'abc');
const overflow = await set('counter', '99999999999');
console.log(`typo: ok=${typo.body?.ok} error=${JSON.stringify(String(typo.body?.error ?? '').slice(0, 50))}`);
console.log(`overflow: ok=${overflow.body?.ok} error=${JSON.stringify(String(overflow.body?.error ?? '').slice(0, 50))}`);
const strictParse = typo.body?.ok === false && /expects an integer/i.test(String(typo.body?.error ?? ''))
  && overflow.body?.ok === false && /expects an integer in int range/i.test(String(overflow.body?.error ?? ''));

// (5) restore the fixture and prove the restore landed
const restores = [await set('flag', 'false'), await set('counter', '7'), await set('label', 'before')];
const restoredOk = restores.every((r) => r.body?.ok === true);
const restored = await post('/api/object/inspect', { session, className: CLASS, field: HOLDER });
const back = Object.fromEntries((restored.body?.fields ?? []).map((f) => [f.name, f.value]));
const { spawnSync } = await import('node:child_process');
const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
const alive = String(spawnSync('adb', ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();

const pass = flagBefore && flagAfter
  && fields.flag === 'true'
  && counter.body?.ok === true && counter.body.before === '7' && counter.body.after === '99'
  && label.body?.ok === true && label.body.before === 'before' && label.body.after === 'patched'
  && finalRefused
  && strictParse
  && restoredOk
  && inheritedOk
  && back.flag === 'false' && back.counter === '7' && back.label === 'before'
  && alive.length > 0;
if (!finalRefused) console.log('the final-field write did not fail loud with a final/read-only reason');
if (!strictParse) console.log('a typo or an out-of-range int was not refused (silent cast)');
if (!restoredOk) console.log('the fixture restore did not report ok');
if (!inheritedOk) console.log('the inherited-field write/read-back failed (superclass walk)');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.53 object_set (live-object field write: before/after, read-back, final-field refusal)" 0 && exit 0 || exit 1
