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
  const r = await post('/api/jni/env_hook', { session, action: 'hook', function: f });
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

// (2) trigger the native probe (it goes through the hooked entries)
const call = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniFieldProbe', params: '', args: [] });
const calls = Number(call.body?.result?.result ?? -1);
if (calls === 0) {
  console.log('fixture unavailable (HeapProbe.sConfig not initialized) - is the sandbox activity open?');
  for (const f of hooked) await post('/api/jni/env_hook', { session, action: 'unhook', function: f }).catch(() => null);
  skip('sandbox fixture not initialized');
}
if (calls < 0) fail('java_call of the field probe failed: ' + String(call.body?.error ?? call.status), call.body);
await sleep(1500);   // let the capture loop drain

// (3) the events must name the hooked accessors and carry the field id
const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json().catch(() => ({}));
const seen = new Map();
for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV')) {
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
const byPattern = await post('/api/jni/env_hook', { session, action: 'hook', function: '*Field' });
const status3 = await post('/api/jni/env_hook', { session, action: 'status' });
const fieldSlots = (status3.body?.hooks ?? []).filter((h) => h.installed === true && /Field$/.test(String(h.function ?? '')));
const patternOk = byPattern.body?.ok === true && fieldSlots.length >= 36;
console.log(`pattern "*Field": ok=${byPattern.body?.ok} installedFieldSlots=${fieldSlots.length} (expect >= 36)`);
const unhookPattern = await post('/api/jni/env_hook', { session, action: 'unhook', function: '*Field' });
if (unhookPattern.body?.ok !== true) console.log('pattern unhook did not report ok');

// (4) unhook, table restored, process alive
const unhooked = [];
for (const f of hooked) unhooked.push((await post('/api/jni/env_hook', { session, action: 'unhook', function: f })).body?.ok === true);
const status2 = await post('/api/jni/env_hook', { session, action: 'status' });
const restored = (status2.body?.hooks ?? []).filter((h) => hooked.includes(h.function))
  .every((h) => h.installed !== true && (!h.original || h.original === '0x0' || h.slotValue === h.original));
const { spawnSync } = await import('node:child_process');
const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
const alive = String(spawnSync('adb', ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();

if (missing.length) console.log('no event for: ' + missing.join(', '));
if (!digestOk) console.log('the field digest did not resolve any access to a name');
if (!patternOk) console.log('the "*Field" pattern did not select the field family (suffix matching)');
const pass = installedOk && patchedOk && relroOk && calls >= 2 && missing.length === 0 && valueOk && digestOk && patternOk
  && unhooked.every(Boolean) && restored && alive.length > 0;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.55 JNIEnv field accessor slots (hook, events with field+value, RELRO restored)" 0 && exit 0 || exit 1
