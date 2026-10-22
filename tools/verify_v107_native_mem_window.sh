#!/usr/bin/env bash
# Hit-time native memory windows (device).
#
# Hooks adh_mem_window_target with mem=x0:8,x0+7:1 and calls Detection.memWindowProbe.
# The function flips byte 0 before returning, so the companion record must still be
# the original 8 bytes (4144484d454d3031) and the last byte alone (31). A second hook
# on adh_add_target asks for 16 bytes at x0, which is the integer 20: that must come
# back unreadable, the original must still return 84, and the process must still be
# online. A bad spec is a 400 from the host, before any install.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v107_native_mem_window (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : [])
  .filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) { console.log('SKIP  verify_v107_native_mem_window (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;

async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  let parsed = null;
  try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const fail = async (msg, hookId, extra) => {
  if (hookId) await post('/api/native/hook', { session, action: 'unhook', hookId, hard: true });
  if (extra !== undefined) console.log(JSON.stringify(extra));
  console.log('FAIL ' + msg);
  console.log('RESULT:FAIL');
  process.exit(0);
};
async function captureText(func, hookId) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=300`)).json().catch(() => ({}));
    for (const item of (list.captures ?? [])) {
      if (item.func !== func) continue;
      const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json().catch(() => null);
      const text = Buffer.from(String(detail?.hex ?? ''), 'hex').toString('utf8');
      if (text.includes(`"hookId":${hookId}`)) {
        try { return JSON.parse(text); } catch { return null; }
      }
    }
    await sleep(120);
  }
  return null;
}

const rejected = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_mem_window_target', mem: 'x9:8',
});
if (rejected.status !== 400) await fail(`a bad mem spec returned ${rejected.status}, expected 400`, 0, rejected.body);

const hook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_mem_window_target',
  mem: 'x0:8,x0+7:1',
});
if (!hook.body?.ok) {
  const err = String(hook.body?.error ?? '');
  if (/not found|symbol|no such/i.test(err)) {
    console.log('SKIP  verify_v107_native_mem_window (sandbox fixture adh_mem_window_target missing; rebuild + install the sandbox APK and redeploy the agent)');
    process.exit(0);
  }
  await fail(`hooking adh_mem_window_target failed: ${err}`, 0, hook.body);
}
const hookId = Number(hook.body.hookId);
const status = await post('/api/native/hook', { session, action: 'status' });
const entry = (status.body?.status?.hooks ?? []).find((x) => x.id === hookId);
if (!entry || entry.mem !== 'x0:8,x0+7:1') await fail(`status did not echo the window spec (mem=${entry?.mem})`, hookId, entry);

const call = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.Detection', method: 'memWindowProbe', params: '', args: [],
});
if (!call.body?.ok) {
  const err = String(call.body?.error ?? '');
  if (/not found|NoSuchMethod|memWindowProbe/i.test(err)) {
    await post('/api/native/hook', { session, action: 'unhook', hookId, hard: true });
    console.log('SKIP  verify_v107_native_mem_window (Detection.memWindowProbe missing; rebuild + install the sandbox APK)');
    process.exit(0);
  }
  await fail(`memWindowProbe failed: ${err}`, hookId, call.body);
}
const probeValue = call.body?.result?.result ?? call.body?.result;
if (String(probeValue) !== '48653') await fail(`memWindowProbe returned ${probeValue}, expected 48653`, hookId, call.body);

const mem = await captureText('NATIVE_HOOK_MEM', hookId);
if (!mem) await fail('no NATIVE_HOOK_MEM event', hookId);
if (!Array.isArray(mem.mem) || mem.mem.length !== 2) await fail('companion did not carry two windows', hookId, mem);
const [full, last] = mem.mem;
if (full.hex !== '4144484d454d3031' || full.got !== 8 || full.short !== false) {
  await fail('the 8-byte window is not the pre-call buffer', hookId, full);
}
if (last.hex !== '31' || last.offset !== 7 || last.got !== 1) {
  await fail('the offset window is not the last original byte', hookId, last);
}
const hit = await captureText('NATIVE_HOOK', hookId);
if (!hit || hit.memWindows !== 2 || hit.seq !== mem.seq) await fail('the register event is not paired with the companion', hookId, { hit, memSeq: mem.seq });

const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId, hard: true });
if (unhook.body?.ok !== true) await fail('hard unhook of the window hook failed', hookId, unhook.body);

const bad = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target', mem: 'x0:16',
});
if (!bad.body?.ok) await fail(`hooking adh_add_target failed: ${bad.body?.error}`, 0, bad.body);
const badId = Number(bad.body.hookId);
const probe = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.Detection', method: 'siteProbe', params: '', args: [],
});
const siteValue = probe.body?.result?.result ?? probe.body?.result;
if (!probe.body?.ok || String(siteValue) !== '84') await fail(`siteProbe returned ${siteValue}, expected 84`, badId, probe.body);
const badMem = await captureText('NATIVE_HOOK_MEM', badId);
if (!badMem?.mem?.[0] || badMem.mem[0].error !== 'unreadable' || badMem.mem[0].got !== 0) {
  await fail('a small integer register was not reported unreadable', badId, badMem);
}
const cleaned = await post('/api/native/hook', { session, action: 'unhook', hookId: badId, hard: true });
const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');
if (cleaned.body?.ok !== true || !online) await fail('process did not survive the unreadable window', badId, { cleaned: cleaned.body, online });

console.log(JSON.stringify({ hookId, result: probeValue, full: full.hex, last: last.hex, badId, unreadable: badMem.mem[0].error, online }));
console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v107 native hook hit-time memory windows (device)" 0 && exit 0 || exit 1
