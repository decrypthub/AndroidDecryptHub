#!/usr/bin/env bash
# v4.36 pointer-slot coverage: real OBJECT dispatch + writable function pointer.
#
# v4.35 proved a named function-pointer table. Two things were still missing:
#   * the real C++ call shape - the object holds a vptr, the slot is read from a RELRO vtable
#     (ldr vptr / ldr slot / blr) rather than from a global the probe names directly;
#   * a function pointer living in WRITABLE data, which the backend skips unless the operator opts in
#     (a writable word that merely equals the target is as likely to be a constant).
# Assertions: object vcall intercepted (hits moves after calling ONLY that probe), no code written
# (24 bytes at the function read directly, before/after), slot restore bit-exact, thunk page gone;
# the writable case must fail loudly by default with the hint, then work with slotsWritable:true.
# Exit 0 = PASS. Device-only; SKIPs when no sandbox agent is connected.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" "$SERIAL" <<'EOF'
const [http, serial] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const pidOfSandbox = () => String(adb('shell', 'pidof', 'com.adh.sandbox').stdout ?? '').trim();
const restartSandbox = () => {
  const before = pidOfSandbox();
  adb('shell', 'am', 'force-stop', 'com.adh.sandbox');
  adb('shell', 'am', 'start', '-n', 'com.adh.sandbox/.MainActivity');
  return before;
};
const waitFreshAgent = async (oldPid, timeoutMs = 40000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pid = pidOfSandbox();
    if (pid && pid !== oldPid) {
      const agents = await (await fetch(`${base}/api/agents`)).json();
      const a = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
        .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
      if (a) return a;
    }
    await sleep(700);
  }
  return null;
};
let session = null;
async function mcp(name, args, timeoutMs = 60000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctl.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session, ...args } } }) });
    const j = await r.json();
    const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
    try { return JSON.parse(c); } catch { return c; }
  } finally { clearTimeout(t); }
}
const jc = async (m) => (await mcp('java_call', { className: 'com.adh.sandbox.Detection', method: m, params: '', args: [] }))?.result?.result;
const hexOf = (v) => '0x' + BigInt(v).toString(16);
const leHex = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b.toString('hex'); };
const readHex = async (addr, size) => {
  const r = await mcp('memory_read', { addr, size });
  const b64 = String(r?.b64 ?? '');
  return r?.ok && b64 ? Buffer.from(b64, 'base64').toString('hex') : null;
};
const readPtr = async (addr) => {
  const h = await readHex(addr, 8);
  return h ? '0x' + BigInt('0x' + Buffer.from(h, 'hex').reverse().toString('hex')).toString(16) : null;
};
const hookStatus = async () => (await mcp('native_hook', { action: 'status' })).status?.hooks ?? [];
const hitsNow = async () => Number(((await hookStatus())[0]?.hits) ?? 0);
const regions = async () => (await mcp('memory_maps', {})).regions ?? [];
const mappingOf = (rs, addr) => rs.find((m) => BigInt('0x' + m.start) <= BigInt(addr) && BigInt(addr) < BigInt('0x' + m.end));

const pid = restartSandbox();
const agent = await waitFreshAgent(pid);
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
session = agent.sessionId;

// ---- A: real object dispatch (vptr in the object, slot in a RELRO vtable) -----------------
const objVt = hexOf(await jc('objVtableAddress'));
const objFn = await readPtr(objVt);
const objBase = { call: Number(await jc('objCall')), entry: await readHex(objFn, 24) };
const objHook = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'vtable', module: 'libadhdetect.so', symbol: 'adh_obj_add', slots: 4 });
const objInfo = objHook.status?.hooks?.[0];
const objSlots = objInfo?.slots ?? [];
const objSlot = objSlots.find((s) => s.at.toLowerCase() === objVt.toLowerCase());
const objSlotRead = objSlot ? await readPtr(objSlot.at) : null;
const objRs = await regions();
const objThunkPath = objSlot ? String(mappingOf(objRs, objSlot.thunk)?.path ?? '') : '';
const objCallHooked = Number(await jc('objCall'));
const objHits = await hitsNow();                       // only the vcall probe ran
const objEntryAfter = await readHex(objFn, 24);
const objUnhook = await mcp('native_hook', { action: 'unhook', hookId: objInfo?.id, hard: true });
const objSlotRestored = objSlot ? await readPtr(objSlot.at) : null;
const rsAfterObj = await regions();
const objPagesGone = rsAfterObj.length > 0 && objSlots.every((s) => mappingOf(rsAfterObj, s.thunk) == null);
const objCallAfter = Number(await jc('objCall'));

// ---- B: function pointer in writable data (opt-in) ---------------------------------------
const cbAddr = hexOf(await jc('cbTargetAddress'));
const cbBase = Number(await jc('cbCall'));
const cbDefault = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'vtable', addr: cbAddr, slots: 2 });
const cbOptIn = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'vtable', addr: cbAddr, slots: 2, slotsWritable: true });
const cbInfo = cbOptIn.status?.hooks?.[0];
const cbSlots = cbInfo?.slots ?? [];
const cbSlot = cbSlots[0];
const cbEntryBefore = await readHex(cbAddr, 24);
const cbSlotRead = cbSlot ? await readPtr(cbSlot.at) : null;
const cbThunkPath = cbSlot ? String(mappingOf(await regions(), cbSlot.thunk)?.path ?? '') : '';
const cbCallHooked = Number(await jc('cbCall'));
const cbHits = await hitsNow();
const cbUnhook = await mcp('native_hook', { action: 'unhook', hookId: cbInfo?.id, hard: true });
const cbSlotRestored = cbSlot ? await readPtr(cbSlot.at) : null;
const cbEntryAfter = await readHex(cbAddr, 24);
const rsAfterCb = await regions();
const cbPagesGone = rsAfterCb.length > 0 && cbSlots.every((s) => mappingOf(rsAfterCb, s.thunk) == null);
const cbCallAfter = Number(await jc('cbCall'));
const alive = pidOfSandbox().length > 0;

const pass =
  objBase.call === 84 && objBase.entry !== null &&
  objHook.ok === true && objSlots.length === 1 &&          // only the object table holds this function
  Number(objInfo?.skippedWritable ?? 0) === 0 &&
  objSlot != null && objSlot.kind === 'data' && /^r/.test(objSlot.perms) && !/w/.test(objSlot.perms) &&
  objSlot.orig === objFn && objSlotRead === objSlot.now && objSlotRead === objSlot.thunk &&
  objSlot.now !== objSlot.orig && /^\/memfd:jit-cache/.test(objThunkPath) &&
  objCallHooked === 84 && objHits >= 1 &&                    // the OBJECT vcall entered the thunk
  objEntryAfter === objBase.entry &&                        // no code written anywhere
  objUnhook.ok === true && objSlotRestored === objSlot.orig && objPagesGone && objCallAfter === 84 &&
  cbBase === 304 &&
  cbDefault.ok === false && /writable slots were skipped/.test(String(cbDefault.error || '')) &&
  cbOptIn.ok === true && cbSlots.length >= 1 &&
  Number(cbInfo?.skippedWritable ?? -1) === 0 &&
  cbSlot != null && /w/.test(cbSlot.perms) && cbSlot.kind === 'data' &&
  cbSlotRead === cbSlot.now && cbSlotRead === cbSlot.thunk && cbSlot.now !== cbSlot.orig &&
  /^\/memfd:jit-cache/.test(cbThunkPath) &&
  cbEntryAfter === cbEntryBefore &&                       // the callback target code is untouched too
  cbCallHooked === 304 && cbHits >= 1 &&
  cbUnhook.ok === true && cbSlotRestored === cbSlot.orig && cbPagesGone && cbCallAfter === 304 &&
  alive;

console.log(JSON.stringify({
  object: { vtable: objVt, fn: objFn, baselineCall: objBase.call, install: { ok: objHook.ok, error: objHook.error, slotCount: objInfo?.slotCount },
            slot: objSlot && { at: objSlot.at, kind: objSlot.kind, perms: objSlot.perms, orig: objSlot.orig, now: objSlot.now },
            slotRead: objSlotRead, thunkPath: objThunkPath, callHooked: objCallHooked, hits: objHits, entryUnchanged: objEntryAfter === objBase.entry,
            unhook: objUnhook.ok, slotRestored: objSlotRestored, pagesGone: objPagesGone, callAfter: objCallAfter },
  writable: { target: cbAddr, baselineCall: cbBase, defaultHook: { ok: cbDefault.ok, error: cbDefault.error },
              optIn: { ok: cbOptIn.ok, error: cbOptIn.error, slotCount: cbInfo?.slotCount },
              slot: cbSlot && { at: cbSlot.at, kind: cbSlot.kind, perms: cbSlot.perms, orig: cbSlot.orig, now: cbSlot.now },
              slotRead: cbSlotRead, thunkPath: cbThunkPath, entryUnchanged: cbEntryAfter === cbEntryBefore,
              callHooked: cbCallHooked, hits: cbHits, pagesGone: cbPagesGone,
              unhook: cbUnhook.ok, slotRestored: cbSlotRestored, callAfter: cbCallAfter },
  alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP v4.36 object dispatch + writable pointer slot (no fresh sandbox agent)"
  exit 0
fi
verify_sandbox_alive
verify_gate "v4.36 object vcall + writable function pointer (opt-in)" 0