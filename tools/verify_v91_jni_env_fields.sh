#!/usr/bin/env bash
# v4.55 JNIEnv FIELD accessor slots (device).
#
# We could already hook the ID lookups (GetFieldID) and the Call* family; the actual field READS and
# WRITES that native code performs through the env table were a blind spot (object_set only covers
# the reflection path). This checks the new Get/Set<Type>Field slots end to end: hook four of them,
# let the sandbox native probe drive them (GetStaticObjectField -> Get/SetIntField, Get/SetBooleanField,
# Get/SetObjectField, Get/SetStaticIntField), and require JNI_ENV events with the field id + value.
# The RELRO checks from v58 apply too: the table page must come back read-only after the swap.
#
# Sections (3f)-(3h) extend the same chain: the string-copy / direct-buffer entries (v4.63/v4.65), the
# array-region family (v4.70), the array-elements family (v4.72), the status filter/counters (v4.80) and the
# creation / object-array / CallNonvirtual / reflection / string families (v4.83) -
# the native fixtures drive them
# with fixed contents, so every entry must emit its own event (start/len/first=[..], plus isCopy and
# the release mode for the element family, where a JNI_ABORT round also has to be seen discarding).
#
# Missing preconditions (no device / no agent / old payload without the field slots / old APK without
# the fixture) print SKIP and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v91_jni_env_fields (no device)"
  exit 0
fi
# This long probe installs many JNI table hooks across several fixture calls. Start from a clean
# sandbox process so a previous verifier's still-live table patch cannot affect the family result.
verify_restart_sandbox || { echo "FAIL  could not restart sandbox before JNI family probe"; exit 1; }

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Every install is recorded here so the terminal paths (fail/skip) always restore the table: a
// check that fails while leaving slots patched would poison every later run in the same process.
const installedSlots = [];
const uninstallAll = async () => {
  const list = installedSlots.splice(0, installedSlots.length);
  for (const f of list) {
    try { await post('/api/jni/env_hook', { session, action: 'uninstall', function: f }); } catch { /* best effort */ }
  }
};
const skip = async (msg) => { await uninstallAll(); console.log('SKIP  verify_v91_jni_env_fields (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
const fail = async (msg, extra) => { if (extra !== undefined) console.log(JSON.stringify(extra).slice(0, 600)); console.log('FAIL ' + msg); await uninstallAll(); console.log('RESULT:FAIL'); process.exit(0); };
const installSlot = async (f) => {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  if (r.body?.ok !== true) { await fail(`install of ${f} failed: ` + String(r.body?.error ?? r.status), r.body); return false; }
  installedSlots.push(f);
  return true;
};
const uninstallSlot = async (f) => {
  const r = await post('/api/jni/env_hook', { session, action: 'uninstall', function: f });
  const ok = r.body?.ok === true;
  if (ok) { const i = installedSlots.indexOf(f); if (i >= 0) installedSlots.splice(i, 1); }
  return ok;
};
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let parsed = null; try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : []).filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) await skip('no online sandbox agent');
const session = agent.sessionId;
// GetFieldID is hooked as well so the field DIGEST can join an access back to its name.
const FUNCS = ['GetFieldID', 'GetStaticObjectField', 'GetIntField', 'SetIntField', 'GetStaticIntField', 'SetStaticIntField'];

// (0) capability: a status call must know the slot names at all.
const status0 = await post('/api/jni/env_hook', { session, action: 'status' });
if (status0.status === 404) await skip('daemon predates the JNIEnv surface');
const known = new Set((status0.body?.hooks ?? []).map((h) => h.function));
if (FUNCS.some((f) => !known.has(f))) await skip('agent predates the field accessor slots (redeploy the agent)');

// (1) hook them
const hooked = [];
for (const f of FUNCS) { await installSlot(f); hooked.push(f); }
const status1 = await post('/api/jni/env_hook', { session, action: 'status' });
const slots = (status1.body?.hooks ?? []).filter((h) => hooked.includes(h.function));
const installedOk = slots.length === FUNCS.length && slots.every((h) => h.installed === true);
const patchedOk = slots.every((h) => h.slotValue && h.original && h.slotValue !== h.original);
const relroOk = typeof status1.body?.tablePerms === 'string' && status1.body.tablePerms.startsWith('r') && status1.body.tablePerms[1] !== 'w'
  && slots.every((h) => typeof h.perms !== 'string' || (h.perms.startsWith('r') && h.perms[1] !== 'w'));
console.log(`hooks: ${slots.map((h) => h.function).join(',')} installed=${installedOk} patched=${patchedOk} relro=${relroOk} tablePerms=${status1.body?.tablePerms}`);

// (1b) baseline cursor so the event assertions below cannot be satisfied by events from an
// EARLIER run (the capture store keeps history).
const preList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preList || !Array.isArray(preList.captures)) await fail('could not read the capture baseline (the cursor would silently become 0 and history could satisfy the event assertions)');
const cursor = Math.max(0, ...(preList.captures ?? []).map((c) => Number(c.id ?? 0)));
console.log(`event baseline cursor=${cursor}`);

// (2) trigger the native probe (it goes through the hooked entries)
const fieldSinceMs = Date.now();
const call = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniFieldProbe', params: '', args: [] });
const calls = Number(call.body?.result?.result ?? -1);
if (calls === 0) {
  console.log('fixture unavailable (HeapProbe.sConfig not initialized) - is the sandbox activity open?');
  for (const f of hooked) await uninstallSlot(f);
  await skip('sandbox fixture not initialized');
}
if (calls < 0) await fail('java_call of the field probe failed: ' + String(call.body?.error ?? call.status), call.body);
const fieldUnhooked = [];
for (const f of hooked) fieldUnhooked.push(await uninstallSlot(f));
await sleep(1500);   // let the capture loop drain

// (3) the events must name the hooked accessors and carry the field id
const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json().catch(() => ({}));
const seen = new Map();
for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV' && Number(x.id ?? 0) > cursor)) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  let ev = null;
  try { ev = JSON.parse(String(d?.text ?? '')); } catch { ev = null; }
  if (!ev?.function || !hooked.includes(ev.function)) continue;
  const list2 = seen.get(ev.function) ?? [];
  list2.push(ev.value);
  seen.set(ev.function, list2);
}
for (const f of hooked) console.log(`  event ${f}: ${(seen.get(f) ?? []).length} (${(seen.get(f) ?? [])[0] ?? '-'})`);
const missing = hooked.filter((f) => (seen.get(f) ?? []).length === 0);
const valueOk = [...seen.values()].some((vals) => vals.some((v) => /field=0x/.test(String(v))));

// (3b) the digest must resolve at least one access to a NAME through the id the lookup handed out
const digest = await post('/api/jni/field_digest', { session, maxGroups: 20, sinceMs: fieldSinceMs });
const resolvedGroups = (digest.body?.groups ?? []).filter((g) => g.resolved === true);
console.log(`digest: groups=${(digest.body?.groups ?? []).length} resolved=${resolvedGroups.length} unresolvedAccesses=${digest.body?.unresolvedAccesses}`);
if (resolvedGroups[0]) console.log(`  ${resolvedGroups[0].accessor} ${resolvedGroups[0].field} x${resolvedGroups[0].count} last=${resolvedGroups[0].lastValue}`);
const digestOk = digest.body?.drain?.ok === true && resolvedGroups.length >= 1 && /#/.test(String(resolvedGroups[0]?.field ?? ''));

// (3c) pattern selection: "*Field" must select the whole field family (36 slots) in ONE call.
const byPattern = await post('/api/jni/env_hook', { session, action: 'install', function: '*Field' });
const status3 = await post('/api/jni/env_hook', { session, action: 'status' });
const fieldSlots = (status3.body?.hooks ?? []).filter((h) => h.installed === true && /Field$/.test(String(h.function ?? '')));
const patternOk = byPattern.body?.ok === true && fieldSlots.length >= 36;
console.log(`pattern "*Field": ok=${byPattern.body?.ok} installedFieldSlots=${fieldSlots.length} (expect >= 36)`);
const unhookPattern = await post('/api/jni/env_hook', { session, action: 'uninstall', function: '*Field' });
const patternUnhookOk = unhookPattern.body?.ok === true;
if (!patternUnhookOk) console.log('pattern unhook did not report ok');

// (3d) write override (v4.58): with setValue the hook REWRITES what native code stores. The probe
// reads HeapProbe.sConfig.counter and writes it back, so with SetIntField overridden to 42 a
// follow-up read must see 42 instead of the original 7.
// Pin the value the fixture holds BEFORE the override, otherwise "counter == 42 afterwards" could
// be satisfied by a fixture that was already 42.
const beforeOv = await post('/api/object/inspect', { session, className: 'com.adh.sandbox.HeapProbe', field: 'sConfig' });
const counterBefore = Object.fromEntries((beforeOv.body?.fields ?? []).map((f) => [f.name, f.value])).counter;
if (counterBefore !== '7') await fail(`the fixture should hold counter=7 before the override, saw ${counterBefore}`, beforeOv.body);
const ovHook = await post('/api/jni/env_hook', { session, action: 'install', function: 'SetIntField', setValue: '42' });
if (ovHook.body?.ok !== true) await fail('SetIntField override install failed: ' + String(ovHook.body?.error ?? ovHook.status), ovHook.body);
const ovSinceMs = Date.now();
const ovCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniFieldProbe', params: '', args: [] });
const ovRead = await post('/api/object/inspect', { session, className: 'com.adh.sandbox.HeapProbe', field: 'sConfig' });
const counterNow = Object.fromEntries((ovRead.body?.fields ?? []).map((f) => [f.name, f.value])).counter;
console.log(`override: calls=${ovCall.body?.result?.result} counter=${counterNow} (expect 42)`);
// restore FIRST (the assertion below is a plain conjunction, and the earlier version referenced
// ovRestoreOk before its declaration - a TDZ crash that only a device run would have shown)
const ovUnhook = await post('/api/jni/env_hook', { session, action: 'uninstall', function: 'SetIntField' });
const restoreCounter = await post('/api/object/set', { session, className: 'com.adh.sandbox.HeapProbe', field: 'sConfig', targetField: 'counter', value: '7' });
const ovRestoreOk = ovUnhook.body?.ok === true && restoreCounter.body?.ok === true;
if (!ovRestoreOk) console.log('the override unhook / fixture restore did not report ok');
const overrideOk = ovCall.body?.ok === true && counterNow === '42' && ovRestoreOk;

// (3e) the digest must attribute the rewrite: v4.61 exists precisely so "the target asked for 7 and
// the hook stored 42" shows up as a rewritten sample instead of an ordinary write.
await sleep(1500);   // let the capture loop drain the events the probe just produced
const ovDigest = await post('/api/jni/field_digest', { session, maxGroups: 20, sinceMs: ovSinceMs });
const rewrittenGroups = (ovDigest.body?.groups ?? []).filter((g) => Number(g.rewritten ?? 0) >= 1);
console.log(`digest after override: rewrittenSamples=${ovDigest.body?.rewrittenSamples} rewrittenGroups=${rewrittenGroups.length} lastRequested=${rewrittenGroups[0]?.lastRequested}`);
const rewriteDigestOk = Number(ovDigest.body?.rewrittenSamples ?? 0) >= 1
  && rewrittenGroups.some((g) => g.lastRequested === '7');

// (3f) v4.63: the string-copy and direct-buffer entries. The probe lifts a Java string into native
// buffers and hands a native payload to Java as a direct ByteBuffer, so each hooked entry must
// produce an event whose detail carries what the wrapper promised (text preview, address, capacity).
const STR_FUNCS = ['GetStringRegion', 'GetStringUTFRegion', 'GetStringChars', 'ReleaseStringChars', 'NewDirectByteBuffer', 'GetDirectBufferAddress', 'GetDirectBufferCapacity'];
for (const f of STR_FUNCS) await installSlot(f);
const preStr = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preStr || !Array.isArray(preStr.captures)) await fail('could not read the capture baseline for the string section');
const strCursor = Math.max(0, ...(preStr.captures ?? []).map((c) => Number(c.id ?? 0)));
const strCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniStringProbe', params: '', args: [] });
const strCalls = Number(strCall.body?.result?.result ?? -1);
if (strCalls < 0) await fail('java_call of jniStringProbe failed: ' + String(strCall.body?.error ?? strCall.status), strCall.body);
const strUnhooked = [];
for (const f of STR_FUNCS) strUnhooked.push(await uninstallSlot(f));
await sleep(1500);
const strList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json().catch(() => ({}));
const strSeen = new Map();
for (const c of (strList.captures ?? []).filter((x) => x.func === 'JNI_ENV' && Number(x.id ?? 0) > strCursor)) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  let ev = null;
  try { ev = JSON.parse(String(d?.text ?? '')); } catch { ev = null; }
  if (!ev?.function || !STR_FUNCS.includes(ev.function)) continue;
  if (!strSeen.has(ev.function)) strSeen.set(ev.function, ev.value);
}
for (const f of STR_FUNCS) console.log(`  event ${f}: ${strSeen.get(f) ?? '(missing)'}`);
const strMissing = STR_FUNCS.filter((f) => !strSeen.has(f));
// Each string reader is a SEPARATE wrapper, so each one has to prove itself with the text IT
// actually copied - an OR/at-least-two rule would let one working entry carry the section while
// another is broken. The probe copies the region [4,16) of "ADH-STRING-PROBE-0123456789" (i.e.
// "STRING-PROBE") through both region readers, and pins the WHOLE string through GetStringChars;
// asserting "ADH-STR" everywhere would demand that a region reader preview text it never copied.
const previewOf = (f, want) => new RegExp(`text="[^"]*${want}`).test(String(strSeen.get(f) ?? ''));
const utf16Ok = previewOf('GetStringRegion', 'STRING-PROBE');
const utf8Ok = previewOf('GetStringUTFRegion', 'STRING-PROBE');
const pinOk = previewOf('GetStringChars', 'ADH-STRING-PROBE');
const releaseOk = /chars=0x/.test(String(strSeen.get('ReleaseStringChars') ?? ''));
const textOk = utf16Ok && utf8Ok && pinOk && releaseOk;
console.log(`  string previews: utf16=${utf16Ok} utf8=${utf8Ok} pin=${pinOk} release=${releaseOk}`);
const bufferOk = /address=0x/.test(String(strSeen.get('GetDirectBufferAddress') ?? ''))
  && /capacity=64/.test(String(strSeen.get('NewDirectByteBuffer') ?? ''))
  && /capacity=64/.test(String(strSeen.get('GetDirectBufferCapacity') ?? ''));
const stringProbeOk = strCall.body?.ok === true && strCalls >= STR_FUNCS.length && strMissing.length === 0 && textOk && bufferOk && strUnhooked.every(Boolean);
if (strMissing.length) console.log('no event for: ' + strMissing.join(', '));
if (!textOk) console.log('at least one string reader did not carry the copied text preview');
if (!bufferOk) console.log('the direct-buffer events did not carry address/capacity');

// (3g) v4.70: the array-region family. The fixture walks all seven primitive types with fixed
// contents, so every one of the fourteen entries must produce its OWN event with start/len and the
// first elements it moved - a shared "at least one worked" rule would let a broken wrapper ride along.
const REGION_FUNCS = ['GetBooleanArrayRegion', 'SetBooleanArrayRegion', 'GetCharArrayRegion', 'SetCharArrayRegion',
  'GetShortArrayRegion', 'SetShortArrayRegion', 'GetIntArrayRegion', 'SetIntArrayRegion',
  'GetLongArrayRegion', 'SetLongArrayRegion', 'GetFloatArrayRegion', 'SetFloatArrayRegion',
  'GetDoubleArrayRegion', 'SetDoubleArrayRegion'];
// Capability precondition, like the field section: a payload from before v4.70 cannot be judged by
// this section, so it SKIPs instead of turning "old agent" into a FAIL.
if (REGION_FUNCS.some((f) => !known.has(f))) await skip('agent predates the array-region slots (redeploy the agent)');
for (const f of REGION_FUNCS) await installSlot(f);
const preRegion = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preRegion || !Array.isArray(preRegion.captures)) await fail('could not read the capture baseline for the array-region section');
const regionCursor = Math.max(0, ...(preRegion.captures ?? []).map((c) => Number(c.id ?? 0)));
const regionCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniArrayRegionProbe', params: '', args: [] });
const regionCode = Number(regionCall.body?.result?.result ?? -1);
// A missing fixture is an old APK, not a broken hook: the script header promises SKIP for that.
if (regionCall.body?.ok !== true) await skip('jniArrayRegionProbe unavailable (old APK without the v4.70 fixture?)');
if (regionCode !== 0xAD707F) await fail(`jniArrayRegionProbe returned ${regionCode}, expected 0xAD707F (all seven families round-tripped through the hooked entries)`);
const regionUnhooked = [];
for (const f of REGION_FUNCS) regionUnhooked.push(await uninstallSlot(f));
await sleep(1500);
const regionList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=600`)).json().catch(() => ({}));
const regionSeen = new Map();
for (const c of (regionList.captures ?? []).filter((x) => x.func === 'JNI_ENV' && Number(x.id ?? 0) > regionCursor)) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  let ev = null;
  try { ev = JSON.parse(String(d?.text ?? '')); } catch { ev = null; }
  if (!ev?.function || !REGION_FUNCS.includes(ev.function)) continue;
  if (!regionSeen.has(ev.function)) regionSeen.set(ev.function, ev.value);
}
for (const f of REGION_FUNCS) console.log(`  event ${f}: ${regionSeen.get(f) ?? '(missing)'}`);
const regionMissing = REGION_FUNCS.filter((f) => !regionSeen.has(f));
// The fixture writes the same fixed content in both directions, so the preview of a Get and the
// preview of the matching Set must both show it.
const regionExpect = {
  Boolean: '1,0,1,0',
  Char: '65,68,72,33',
  Short: '1000,2000,3000,4000',
  Int: '100000,200000,300000,400000',
  Long: '10000000000,20000000000,30000000000,40000000000',
  Float: '1.5,2.5,3.5,4.5',
  Double: '1.25,2.25,3.25,4.25',
};
const regionBad = [];
for (const [type, preview] of Object.entries(regionExpect)) {
  for (const dir of ['Get', 'Set']) {
    const f = `${dir}${type}ArrayRegion`;
    const v = String(regionSeen.get(f) ?? '');
    if (!(v.includes('start=0') && v.includes('len=4') && v.includes(`first=[${preview}]`))) regionBad.push(f);
  }
}
// A flooded ring would turn "missing event" into a mystery; the health block says whether the
// daemon dropped anything during this window instead of letting the operator guess.
const regionHealth = regionList.health ?? {};
console.log(`  array-region events: ${REGION_FUNCS.length - regionMissing.length}/${REGION_FUNCS.length} present, ${regionBad.length} with a wrong start/len/preview (capture health: dropped=${regionHealth.dropped ?? '?'} backlog=${regionHealth.backlog ?? '?'} complete=${regionHealth.complete ?? '?'})`);
const arrayProbeOk = regionMissing.length === 0 && regionBad.length === 0 && regionUnhooked.every(Boolean);
if (regionMissing.length) console.log('no event for: ' + regionMissing.join(', '));
if (regionBad.length) console.log('start/len/preview mismatch for: ' + regionBad.join(', '));

// (3h) v4.72: the array-elements family. The fixture seeds each primitive type, pins it with
// Get<Type>ArrayElements, mutates the pinned buffer, releases with mode 0 (copy back) and reads the
// array back; one extra int[] round releases with JNI_ABORT, where the mutation must NOT land. Every
// one of the fourteen entries needs its own event, and the release preview must show the values that
// were written back - or, for the abort round, the ones that were thrown away.
const ELEM_TYPES = ['Boolean', 'Char', 'Short', 'Int', 'Long', 'Float', 'Double'];
const ELEM_FUNCS = ELEM_TYPES.flatMap((t) => [`Get${t}ArrayElements`, `Release${t}ArrayElements`]);
if (ELEM_FUNCS.some((f) => !known.has(f))) await skip('agent predates the array-elements slots (redeploy the agent)');
for (const f of ELEM_FUNCS) await installSlot(f);
const preElem = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preElem || !Array.isArray(preElem.captures)) await fail('could not read the capture baseline for the array-elements section');
const elemCursor = Math.max(0, ...(preElem.captures ?? []).map((c) => Number(c.id ?? 0)));
const elemCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniArrayElementsProbe', params: '', args: [] });
if (elemCall.body?.ok !== true) await skip('jniArrayElementsProbe unavailable (old APK without the v4.72 fixture?)');
const elemCode = Number(elemCall.body?.result?.result ?? -1);
if (elemCode !== 0xAD80FF) await fail(`jniArrayElementsProbe returned ${elemCode}, expected 0xAD80FF (seven types copied back and the abort round discarded)`);
const elemUnhooked = [];
for (const f of ELEM_FUNCS) elemUnhooked.push(await uninstallSlot(f));
await sleep(1500);
const elemList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=600`)).json().catch(() => ({}));
const elemEvents = new Map();
for (const c of (elemList.captures ?? []).filter((x) => x.func === 'JNI_ENV' && Number(x.id ?? 0) > elemCursor)) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  let ev = null;
  try { ev = JSON.parse(String(d?.text ?? '')); } catch { ev = null; }
  if (!ev?.function || !ELEM_FUNCS.includes(ev.function)) continue;
  if (!elemEvents.has(ev.function)) elemEvents.set(ev.function, []);
  elemEvents.get(ev.function).push(String(ev.value ?? ''));
}
const elemValues = (f) => elemEvents.get(f) ?? [];
for (const f of ELEM_FUNCS) console.log(`  event ${f}: ${elemValues(f)[0] ?? '(missing)'}`);
const elemMissing = ELEM_FUNCS.filter((f) => elemValues(f).length === 0);
// Structural shape per entry: a real buffer pointer, the array length, and the flag that matters for
// that direction (isCopy on Get, the release mode on Release).
const elemShapeBad = ELEM_FUNCS.filter((f) => {
  const ok = elemValues(f).some((v) => /len=4/.test(v) && /elements=0x[1-9a-fA-F]/.test(v) && /first=\[/.test(v)
    && (f.startsWith('Get') ? /isCopy=[01]/.test(v) : /mode=[012]\(/.test(v)));
  return !ok;
});
// What the pinned buffer was told to become has to show up in the release preview.
const elemExpect = {
  Boolean: { get: '1,0,1,0', rel: '0,0,1,0' },
  Char: { get: '65,68,72,33', rel: '90,68,72,33' },
  Short: { get: '1000,2000,3000,4000', rel: '1111,2000,3000,4000' },
  Int: { get: '100000,200000,300000,400000', rel: '111111,200000,300000,400000' },
  Long: { get: '10000000000,20000000000,30000000000,40000000000', rel: '11111111111,20000000000,30000000000,40000000000' },
  Float: { get: '1.5,2.5,3.5,4.5', rel: '9.5,2.5,3.5,4.5' },
  Double: { get: '1.25,2.25,3.25,4.25', rel: '9.75,2.25,3.25,4.25' },
};
const elemBad = [];
for (const [type, exp] of Object.entries(elemExpect)) {
  if (!elemValues(`Get${type}ArrayElements`).some((v) => v.includes(`first=[${exp.get}]`))) elemBad.push(`Get${type}ArrayElements`);
  if (!elemValues(`Release${type}ArrayElements`).some((v) => v.includes('mode=0(copyback)') && v.includes(`first=[${exp.rel}]`))) elemBad.push(`Release${type}ArrayElements`);
}
// The abort round is the one that proves the hook kept JNI_ABORT semantics: the target read back the
// OLD values (the fixture's return code) and the event still shows the discarded mutation.
const elemAbortOk = elemValues('ReleaseIntArrayElements').some((v) => v.includes('mode=2(abort)') && v.includes('first=[100000,999999,300000,400000]'));
const elemHealth = elemList.health ?? {};
console.log(`  array-elements: ${ELEM_FUNCS.length - elemMissing.length}/${ELEM_FUNCS.length} present, ${elemShapeBad.length} without shape, ${elemBad.length} with a wrong preview, abort=${elemAbortOk} (capture health: dropped=${elemHealth.dropped ?? '?'} backlog=${elemHealth.backlog ?? '?'})`);
const elementsProbeOk = elemMissing.length === 0 && elemShapeBad.length === 0 && elemBad.length === 0 && elemAbortOk && elemUnhooked.every(Boolean);
if (elemMissing.length) console.log('no event for: ' + elemMissing.join(', '));
if (elemShapeBad.length) console.log('no event with len/elements/isCopy-or-mode for: ' + elemShapeBad.join(', '));
if (elemBad.length) console.log('release preview mismatch for: ' + elemBad.join(', '));
if (!elemAbortOk) console.log('the JNI_ABORT round did not show the discarded mutation');

// (3i) v4.80: the status reply has to be honest about what it shows. `function` doubles as a
// filter for action:status (same pattern language as install, plus the keyword "installed"), and
// the reply must state total/matched/emitted/truncated - a clipped list that looks complete would
// let a verifier read "not installed" out of a missing entry.
await installSlot('GetJavaVM');   // the 'installed' filter below needs at least one hooked slot
const stAll = await post('/api/jni/env_hook', { session, action: 'status', function: '' });
const stAllTotal = Number(stAll.body?.total ?? 0), stAllMatched = Number(stAll.body?.matched ?? 0), stAllEmitted = Number(stAll.body?.emitted ?? 0);
// The reply must also vouch for the table layout (v4.86): a drifted enum/name mapping makes the
// agent refuse install/uninstall, and status is where that shows up first.
const stAllOk = stAll.body?.ok === true && stAllTotal >= 228 && stAllMatched === stAllTotal && stAll.body?.layout === 'ok'
  && (stAll.body?.truncated === false ? stAllEmitted === stAllMatched : stAllEmitted < stAllMatched);
const stRegion = await post('/api/jni/env_hook', { session, action: 'status', function: '*ArrayRegion' });
const stRegionHooks = stRegion.body?.hooks ?? [];
const stRegionOk = stRegionHooks.length === 16 && Number(stRegion.body?.matched ?? 0) === 16
  && stRegionHooks.every((h) => typeof h.function === 'string' && h.function.endsWith('ArrayRegion'))
  && stRegionHooks.every((h) => h.installed === false);
const stInst = await post('/api/jni/env_hook', { session, action: 'status', function: 'installed' });
const stInstHooks = stInst.body?.hooks ?? [];
const stInstOk = stInstHooks.length >= 1 && stInstHooks.every((h) => h.installed === true)
  && stInstHooks.some((h) => h.function === 'GetJavaVM')
  && Number(stInst.body?.matched ?? -1) === stInstHooks.length
  && stInst.body?.truncated === false;
console.log(`  status: total=${stAllTotal} matched=${stAllMatched} emitted=${stAllEmitted} truncated=${stAll.body?.truncated} layout=${stAll.body?.layout}; *ArrayRegion=${stRegionHooks.length}; installed=${stInstHooks.length}`);
const statusFilterOk = stAllOk && stRegionOk && stInstOk;
if (!stAllOk) console.log('the unfiltered status did not report a consistent total/matched/emitted/truncated');
if (!stRegionOk) console.log('the "*ArrayRegion" status filter did not return exactly the 16 region entries');
if (!stInstOk) console.log('the "installed" status filter did not return only the hooked slots');
const statusSlotOffOk = await uninstallSlot('GetJavaVM');

// (3j) v4.83: the families added after the array work. The fixture walks array creation, object
// arrays, AllocObject, all three CallNonvirtual forms, the reflection bridge, the string
// length/critical entries and ExceptionCheck, asserting a value for each section - so a hook that
// changes target behaviour fails here instead of looking fine. FatalError and UnregisterNatives
// cannot be triggered on a live process; for those two the section only proves that they install,
// report and uninstall like any other slot.
const FAMILY_FUNCS = ['NewBooleanArray', 'NewByteArray', 'NewCharArray', 'NewShortArray', 'NewIntArray',
  'NewLongArray', 'NewFloatArray', 'NewDoubleArray', 'NewObjectArray', 'GetArrayLength',
  'GetObjectArrayElement', 'SetObjectArrayElement', 'AllocObject',
  'CallNonvirtualObjectMethod', 'CallNonvirtualObjectMethodV', 'CallNonvirtualObjectMethodA',
  'FromReflectedMethod', 'FromReflectedField', 'ToReflectedMethod', 'ToReflectedField',
  'NewString', 'GetStringLength', 'GetStringUTFLength', 'GetStringCritical', 'ReleaseStringCritical',
  'ReleaseStringUTFChars', 'ExceptionCheck', 'FatalError', 'UnregisterNatives'];
const FAMILY_NO_TRIGGER = ['FatalError', 'UnregisterNatives'];
if (FAMILY_FUNCS.some((f) => !known.has(f))) await skip('agent predates the v4.83 families (redeploy the agent)');
for (const f of FAMILY_FUNCS) await installSlot(f);
const preFam = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preFam || !Array.isArray(preFam.captures)) await fail('could not read the capture baseline for the family section');
const famCursor = Math.max(0, ...(preFam.captures ?? []).map((c) => Number(c.id ?? 0)));
const famCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniFamilyProbe', params: '', args: [] });
if (famCall.body?.ok !== true) await skip('jniFamilyProbe unavailable (old APK without the v4.83 fixture?)');
const famCode = Number(famCall.body?.result?.result ?? -1);
if (famCode !== 0xAD91FF) await fail(`jniFamilyProbe returned ${famCode}, expected 0xAD91FF (array creation, object arrays, AllocObject, nonvirtual dispatch, reflection bridge, strings, clean ExceptionCheck)`);
// This family is unusually hot: Java/ART itself calls several of these slots while the MCP reply and
// capture details are being serialized. Stop the hooks as soon as the fixture returns so background
// runtime traffic cannot evict the probe's events before the host reads the ring.
const famUnhooked = [];
for (const f of FAMILY_FUNCS) famUnhooked.push(await uninstallSlot(f));
await sleep(1500);
const famList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=600`)).json().catch(() => ({}));
const famEvents = new Map();
for (const c of (famList.captures ?? []).filter((x) => x.func === 'JNI_ENV' && Number(x.id ?? 0) > famCursor)) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  let ev = null;
  try { ev = JSON.parse(String(d?.text ?? '')); } catch { ev = null; }
  if (!ev?.function || !FAMILY_FUNCS.includes(ev.function)) continue;
  if (!famEvents.has(ev.function)) famEvents.set(ev.function, []);
  famEvents.get(ev.function).push(String(ev.value ?? ''));
}
const famValues = (f) => famEvents.get(f) ?? [];
for (const f of FAMILY_FUNCS) console.log(`  event ${f}: ${famValues(f)[0] ?? (FAMILY_NO_TRIGGER.includes(f) ? '(not triggered by design)' : '(missing)')}`);
const famMissing = FAMILY_FUNCS.filter((f) => !FAMILY_NO_TRIGGER.includes(f) && famValues(f).length === 0);
// Spot checks on the values the wrappers promise; the fixture already proved the target's view.
const famChecks = {
  GetArrayLength: /len=4/,
  NewObjectArray: /len=3 elem=java\.lang\.String/,
  GetObjectArrayElement: /index=0 -> 0x0 \(null element\)/,
  SetObjectArrayElement: /index=1 value=0x/,
  AllocObject: /class=com\.adh\.sandbox\.JniCallTarget -> 0x/,
  CallNonvirtualObjectMethod: /via=com\.adh\.sandbox\.JniNonvirtualBase/,
  FromReflectedMethod: /-> mid=0x/,
  ToReflectedMethod: /static=0 -> 0x/,
  FromReflectedField: /-> fid=0x/,
  ToReflectedField: /static=0 -> 0x/,
  NewString: /len=5 text="ADH42"/,
  GetStringLength: /len=5/,
  GetStringCritical: /text="ADH42"/,
  ReleaseStringCritical: /chars=0x/,
  ReleaseStringUTFChars: /chars=0x/,
  ExceptionCheck: /pending=false/,
};
const famBad = [];
for (const [f, re] of Object.entries(famChecks)) {
  if (!famValues(f).some((v) => re.test(v))) famBad.push(f);
}
const famHealth = famList.health ?? {};
console.log(`  families: ${FAMILY_FUNCS.length - famMissing.length}/${FAMILY_FUNCS.length} present, ${famBad.length} with a wrong value (capture health: dropped=${famHealth.dropped ?? '?'} backlog=${famHealth.backlog ?? '?'})`);
if (famMissing.length) console.log('no event for: ' + famMissing.join(', '));
if (famBad.length) console.log('value mismatch for: ' + famBad.join(', '));
const familyProbeOk = famMissing.length === 0 && famBad.length === 0 && famUnhooked.every(Boolean);

// (4) unhook, table restored, process alive.
// Earlier sections already unhooked some of these on purpose (`*Field` in (3c), SetIntField in (3d)),
// and the agent answers an unhook of an inactive slot with ok:false ("... is not hooked") - that is
// the fail-loud contract, not a failure. Ask which slots are still live and only unhook those; the
// end state is what matters and `restored` below re-reads it from the status.
const preFinal = await post('/api/jni/env_hook', { session, action: 'status', function: 'installed' });
const stillInstalled = new Set((preFinal.body?.hooks ?? []).map((h) => h.function));
const alreadyOff = hooked.filter((f) => !stillInstalled.has(f));
if (alreadyOff.length) console.log(`  already unhooked by an earlier section: ${alreadyOff.join(', ')}`);
const unhooked = [];
for (const f of hooked) {
  if (!stillInstalled.has(f)) { unhooked.push(true); continue; }
  unhooked.push(await uninstallSlot(f));
}
const status2 = await post('/api/jni/env_hook', { session, action: 'status' });
const restored = (status2.body?.hooks ?? []).filter((h) => hooked.includes(h.function))
  .every((h) => h.installed !== true && (!h.original || h.original === '0x0' || h.slotValue === h.original));
const { spawnSync } = await import('node:child_process');
const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
const alive = String(spawnSync('adb', ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();

if (missing.length) console.log('no event for: ' + missing.join(', '));
if (!digestOk) console.log('the field digest did not resolve any access to a name');
if (!patternOk) console.log('the "*Field" pattern did not select the field family (suffix matching)');
if (!overrideOk) console.log('the SetIntField override did not change what the target stored, or the restore failed');
if (!rewriteDigestOk) console.log('the field digest did not report the rewritten write (rewrittenSamples/lastRequested)');
const pass = installedOk && patchedOk && relroOk && calls >= 2 && missing.length === 0 && valueOk && digestOk && patternOk && patternUnhookOk && overrideOk && rewriteDigestOk && stringProbeOk && arrayProbeOk && elementsProbeOk && statusFilterOk && statusSlotOffOk && familyProbeOk
  && unhooked.every(Boolean) && restored && alive.length > 0;
// A bare FAIL with every section printing green is unactionable; name the flags that failed.
if (!pass) {
  const flags = { installedOk, patchedOk, relroOk, 'calls>=2': calls >= 2, 'noMissing': missing.length === 0, valueOk, digestOk, patternOk, patternUnhookOk, overrideOk, rewriteDigestOk, stringProbeOk, arrayProbeOk, elementsProbeOk, statusFilterOk, statusSlotOffOk, familyProbeOk, unhooked: unhooked.every(Boolean), restored, alive: alive.length > 0 };
  console.log('failed checks: ' + Object.entries(flags).filter(([, v]) => !v).map(([k]) => k).join(', '));
}
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.55 JNIEnv field accessor slots (hook, events with field+value, RELRO restored)" 0 && exit 0 || exit 1
