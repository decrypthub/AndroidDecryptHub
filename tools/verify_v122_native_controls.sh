#!/usr/bin/env bash
# Bounded native observation: filtering, sampling, strict quota, memory companions and replacement
# invariance. Uses an already-running sandbox only; never installs, restarts, or touches other apps.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

OUT="$(node - "$HTTP" "$SERIAL" <<'EOF'
const [http, serial] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const root = spawnSync('adb', ['-s', serial, 'shell', 'su', '-c', 'id'], { encoding: 'utf8' });
if (!String(root.stdout).includes('uid=0')) { console.log('RESULT:SKIP no rooted test device'); process.exit(0); }
let session;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((a) => a.online && a.package === 'com.adh.sandbox' && (a.serial == null || a.serial === serial))
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) { console.log('RESULT:SKIP no online sandbox; start it separately'); process.exit(0); }
session = agent.sessionId;
let armed = 0;
const active = new Set();
async function mcp(name, args) {
  const response = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session, ...args } } }) });
  const reply = await response.json();
  if (reply.error) throw new Error(JSON.stringify(reply.error));
  const text = reply.result?.content?.[0]?.text;
  let value; try { value = JSON.parse(text); } catch { throw new Error(String(text ?? JSON.stringify(reply))); }
  if (reply.result?.isError || value?.ok === false) throw new Error(JSON.stringify(value));
  return value;
}
function chk(ok, why) { if (!ok) throw new Error(why); }
async function java(method, className = 'com.adh.sandbox.Detection') {
  const r = await mcp('java_call', { className, method, params: '', args: [] });
  return Number(r.result?.result);
}
async function status() {
  return (await mcp('native_hook', { action: 'status' })).status.hooks.find((h) => h.id === armed);
}
async function install(options) {
  const r = await mcp('native_hook', { action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target', ...options });
  armed = r.hookId; active.add(armed);
  chk(armed > 0, 'install returned no hook id');
  return r.status.hooks.find((h) => h.id === armed);
}
async function stop(hard = false) {
  await mcp('native_hook', { action: 'unhook', hookId: armed, hard }); active.delete(armed); armed = 0;
}
function totals(h) {
  chk(h.hits === h.filtered + h.selected, `hit accounting mismatch: ${JSON.stringify(h)}`);
  chk(h.selected === h.sampledOut + h.throttled + h.limited + h.emitted, `selection accounting mismatch: ${JSON.stringify(h)}`);
  chk(h.emittedMeaning === 'submitted-to-capture-ring', 'emission must not claim transport completeness');
}
try {
  chk(await java('siteProbe') === 84, 'unexpected sandbox baseline');
  const tid = await java('myTid', 'android.os.Process');
  chk(tid > 0, 'could not resolve persistent command-thread tid');

  // Empty scope is the real wire default; it must behave as target-module scope.
  let r = await mcp('native_hook', { action: 'hook', mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', scope: '', sites: 4, maxEvents: 1 });
  armed = r.hookId; active.add(armed);
  chk(r.status.hooks.find((h) => h.id === armed)?.slotsPatched > 0, 'default sites scope installed no sites');
  chk(await java('siteProbe') === 84, 'sites changed the original return value');
  chk((await status()).hits >= 1, 'default-scope sites never fired');
  await stop(true);

  let h = await install({ maxEvents: 2, sampleEvery: 3, memAfter: 'x0:8' });
  if (h.maxEvents === undefined) {
    await stop(); console.log('RESULT:SKIP deployed agent does not have native event controls'); process.exit(0);
  }
  for (let i = 0; i < 8; i++) chk(await java('siteProbe') === 84, 'observation controls changed original execution');
  h = await status(); totals(h);
  chk(h.hits === 8 && h.selected === 8 && h.emitted === 2 && h.sampledOut === 5 && h.limited === 1,
    `unexpected sampling/quota counters: ${JSON.stringify(h)}`);
  await mcp('native_look', { action: 'read', hookId: armed }); // force a drain before inspecting raw records
  const rows = (await mcp('live_captures', { hookId: armed, includeText: true, encoding: 'b64', limit: 30 })).captures;
  const events = rows.map((c) => ({ func: c.func, data: JSON.parse(Buffer.from(c.b64, 'base64').toString()) }));
  const entries = events.filter((e) => e.func === 'NATIVE_HOOK');
  const afters = events.filter((e) => e.func === 'NATIVE_HOOK_MEM' && e.data.phase === 'after');
  chk(entries.length === 2 && afters.length === 2, `quota leaked memory companions: ${entries.length}/${afters.length}`);
  chk(entries.every((e) => e.data.seq > 0) && afters.every((e) => entries.some((r) => r.data.seq === e.data.seq)), 'missing or unrelated memAfter seq');
  const caller = entries[0].data.x30;
  chk(entries.every((e) => e.data.tid === tid && e.data.x30 === caller), 'probe did not use stable thread/caller');
  await stop();

  // Same stub shape reactivation must reset quotas and update selection fields.
  await install({ maxEvents: 1, sampleEvery: 2, tid, returnAddress: caller, memAfter: 'x0:8', skipOriginal: true, returnValue: '0x7b' });
  for (let i = 0; i < 3; i++) chk(await java('siteProbe') === 123, 'sampling/quota suppressed replacement behavior');
  h = await status(); totals(h);
  chk(h.hits === 3 && h.emitted === 1 && h.sampledOut === 1 && h.limited === 1 && h.filtered === 0, 'reactivation retained old controls/counters');
  await stop();

  for (const selector of [{ tid: tid === 1 ? 2 : 1 }, { returnAddress: '0x1' }]) {
    await install({ ...selector, memAfter: 'x0:8', skipOriginal: true, returnValue: '0x7b' });
    for (let i = 0; i < 2; i++) chk(await java('siteProbe') === 84, 'unmatched call received a replacement');
    h = await status(); totals(h);
    chk(h.hits === 2 && h.filtered === 2 && h.selected === 0 && h.emitted === 0, 'unmatched calls disappeared from accounting');
    await stop();
  }
  await install({ throttleMs: 60000, memAfter: 'x0:8', skipOriginal: true, returnValue: '0x7b' });
  for (let i = 0; i < 5; i++) chk(await java('siteProbe') === 123, 'throttle suppressed replacement behavior');
  h = await status(); totals(h);
  chk(h.hits === 5 && h.emitted === 1 && h.throttled === 4, 'time throttle counters incorrect');
  await stop();
  chk(await java('siteProbe') === 84, 'soft unhook did not restore original behavior');
  console.log('native controls: quota/sample/filter/throttle accounting and replacement invariance PASS');
  console.log('sites default scope PASS (memfd injected-agent regression requires an injected fixture)');
  console.log('RESULT:PASS');
} finally {
  for (const hookId of active) await mcp('native_hook', { action: 'unhook', hookId }).catch((e) => console.error('cleanup:', e.message));
}
EOF
)"
echo "$OUT"
if [[ "$OUT" == *"RESULT:SKIP"* ]]; then exit 0; fi
verify_gate "native controls" 0
