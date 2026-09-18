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
# Missing preconditions (no device / no agent / old payload without the field slots / old APK without
# the fixture) print SKIP and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v91_jni_env_fields (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v91_jni_env_fields (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
const fail = (msg, extra) => { if (extra !== undefined) console.log(JSON.stringify(extra).slice(0, 600)); console.log('FAIL ' + msg); console.log('RESULT:FAIL'); process.exit(0); };
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
// GetFieldID is hooked as well so the field DIGEST can join an access back to its name.
const FUNCS = ['GetFieldID', 'GetStaticObjectField', 'GetIntField', 'SetIntField', 'GetStaticIntField', 'SetStaticIntField'];

// (0) capability: a status call must know the slot names at all.
const status0 = await post('/api/jni/env_hook', { session, action: 'status' });
if (status0.status === 404) skip('daemon predates the JNIEnv surface');
const known = new Set((status0.body?.hooks ?? []).map((h) => h.function));
if (FUNCS.some((f) => !known.has(f))) skip('agent predates the field accessor slots (redeploy the agent)');

// (1) hook them
const hooked = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  if (r.body?.ok !== true) fail(`hook of ${f} failed: ${String(r.body?.error ?? r.status)}`, r.body);
  hooked.push(f);
}
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
if (!preList || !Array.isArray(preList.captures)) fail('could not read the capture baseline (the cursor would silently become 0 and history could satisfy the event assertions)');
const cursor = Math.max(0, ...(preList.captures ?? []).map((c) => Number(c.id ?? 0)));
console.log(`event baseline cursor=${cursor}`);

// (2) trigger the native probe (it goes through the hooked entries)
const call = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniFieldProbe', params: '', args: [] });
const calls = Number(call.body?.result?.result ?? -1);
if (calls === 0) {
  console.log('fixture unavailable (HeapProbe.sConfig not initialized) - is the sandbox activity open?');
  for (const f of hooked) await post('/api/jni/env_hook', { session, action: 'uninstall', function: f }).catch(() => null);
  skip('sandbox fixture not initialized');
}
if (calls < 0) fail('java_call of the field probe failed: ' + String(call.body?.error ?? call.status), call.body);
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
const digest = await post('/api/jni/field_digest', { session, maxGroups: 20 });
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
if (counterBefore !== '7') fail(`the fixture should hold counter=7 before the override, saw ${counterBefore}`, beforeOv.body);
const ovHook = await post('/api/jni/env_hook', { session, action: 'install', function: 'SetIntField', setValue: '42' });
if (ovHook.body?.ok !== true) fail('SetIntField override install failed: ' + String(ovHook.body?.error ?? ovHook.status), ovHook.body);
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
const ovDigest = await post('/api/jni/field_digest', { session, maxGroups: 20 });
const rewrittenGroups = (ovDigest.body?.groups ?? []).filter((g) => Number(g.rewritten ?? 0) >= 1);
console.log(`digest after override: rewrittenSamples=${ovDigest.body?.rewrittenSamples} rewrittenGroups=${rewrittenGroups.length} lastRequested=${rewrittenGroups[0]?.lastRequested}`);
const rewriteDigestOk = Number(ovDigest.body?.rewrittenSamples ?? 0) >= 1
  && rewrittenGroups.some((g) => g.lastRequested === '7');

// (3f) v4.63: the string-copy and direct-buffer entries. The probe lifts a Java string into native
// buffers and hands a native payload to Java as a direct ByteBuffer, so each hooked entry must
// produce an event whose detail carries what the wrapper promised (text preview, address, capacity).
const STR_FUNCS = ['GetStringRegion', 'GetStringUTFRegion', 'GetStringChars', 'ReleaseStringChars', 'NewDirectByteBuffer', 'GetDirectBufferAddress', 'GetDirectBufferCapacity'];
const strInstalled = [];
for (const f of STR_FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  if (r.body?.ok !== true) fail(`install of ${f} failed: ` + String(r.body?.error ?? r.status), r.body);
  strInstalled.push(f);
}
const preStr = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => null);
if (!preStr || !Array.isArray(preStr.captures)) fail('could not read the capture baseline for the string section');
const strCursor = Math.max(0, ...(preStr.captures ?? []).map((c) => Number(c.id ?? 0)));
const strCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniStringProbe', params: '', args: [] });
const strCalls = Number(strCall.body?.result?.result ?? -1);
if (strCalls < 0) fail('java_call of jniStringProbe failed: ' + String(strCall.body?.error ?? strCall.status), strCall.body);
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
// At least two of the three string readers must show the copied text: one of the region copies and
// the pinned pointer, so a single working entry cannot carry the whole section.
const textHit = ['GetStringUTFRegion', 'GetStringRegion', 'GetStringChars']
  .filter((f) => /text="[^"]*ADH-STR/.test(String(strSeen.get(f) ?? '')));
const releaseOk = /chars=0x/.test(String(strSeen.get('ReleaseStringChars') ?? ''));
const textOk = textHit.length >= 2 && releaseOk;
const bufferOk = /address=0x/.test(String(strSeen.get('GetDirectBufferAddress') ?? ''))
  && /capacity=64/.test(String(strSeen.get('NewDirectByteBuffer') ?? ''))
  && /capacity=64/.test(String(strSeen.get('GetDirectBufferCapacity') ?? ''));
const strUnhooked = [];
for (const f of STR_FUNCS) strUnhooked.push((await post('/api/jni/env_hook', { session, action: 'uninstall', function: f })).body?.ok === true);
const stringProbeOk = strCall.body?.ok === true && strCalls >= 7 && strMissing.length === 0 && textOk && bufferOk && strUnhooked.every(Boolean);
if (strMissing.length) console.log('no event for: ' + strMissing.join(', '));
if (!textOk) console.log(`the string readers did not carry the copied text (hits=${textHit.join(',') || 'none'}, release=${releaseOk})`);
if (!bufferOk) console.log('the direct-buffer events did not carry address/capacity');

// (4) unhook, table restored, process alive
const unhooked = [];
for (const f of hooked) unhooked.push((await post('/api/jni/env_hook', { session, action: 'uninstall', function: f })).body?.ok === true);
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
const pass = installedOk && patchedOk && relroOk && calls >= 2 && missing.length === 0 && valueOk && digestOk && patternOk && patternUnhookOk && overrideOk && rewriteDigestOk && stringProbeOk
  && unhooked.every(Boolean) && restored && alive.length > 0;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.55 JNIEnv field accessor slots (hook, events with field+value, RELRO restored)" 0 && exit 0 || exit 1
