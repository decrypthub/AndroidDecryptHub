#!/usr/bin/env bash
# v9.8 injected-agent Java surface acceptance (device): an agent that arrived through the Zygisk
# loader must still be able to reach Java and ART.
#
# Why this exists (it is the regression guard for a real defect): when the agent is loaded from a
# memfd by the module, nothing calls JNI_OnLoad, so the agent has no JavaVM unless it can find one
# itself. `dlopen("libart.so")` is refused by the linker for the namespace "(default)" when the
# caller is a memfd-loaded library, so jelly `art_dexfiles` / `java_hook` / `trigger` / `object_*`
# answered "no JavaVM" on every real injected target — while the whole device gate stayed green,
# because all the other device checks run against the sandbox, which self-loads through
# System.loadLibrary and gets its VM from JNI_OnLoad.
#
# verify_v75_zygisk_memfd.sh already creates the exact condition (inject into a non-sandbox app,
# entry=start, memfd identity) but only asserts `compat_probe.agentExecMappings >= 1` — it never
# asserts a Java capability. This is the sibling that does.
#
# Device-only. A missing precondition prints "SKIP ..." and exits 0 WITHOUT the RESULT:PASS
# sentinel, so tools/verify_all.sh counts it as a skip, not as a passing acceptance.
# Restores the operator's Zygisk scope and force-stops the target on exit.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v98_injected_java_surface (no device)"
  exit 0
fi
ROOT_MGR="$(adb -s "$SERIAL" shell 'su -c "if test -x /data/adb/ksud || test -x /data/adb/ksu/bin/ksud; then echo KSU; elif test -d /data/adb/magisk; then echo MAGISK; else echo NO; fi"' 2>/dev/null | tr -d '\r' || true)"
if [ "$ROOT_MGR" != "KSU" ] && [ "$ROOT_MGR" != "MAGISK" ]; then
  echo "SKIP  verify_v98_injected_java_surface (no Magisk/KernelSU on device)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh"' >/dev/null 2>&1; then
  echo "SKIP  verify_v98_injected_java_surface (adh Zygisk module not installed)"
  exit 0
fi
if ! adb -s "$SERIAL" reverse --list 2>/dev/null | grep -q 'tcp:876'; then
  echo "SKIP  verify_v98_injected_java_surface (no adb reverse tunnel; run tools/dev_up.sh first)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" "$SERIAL" <<'EOF'
const [http, serial] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const target = process.env.ADH_JAVA_TARGET || 'com.android.settings';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const sh = (...args) => String(adb('shell', ...args).stdout ?? '').replace(/\r/g, '');
const root = (cmd) => sh(`su -c ${JSON.stringify(cmd)}`);

const priorScope = root('base64 /data/adb/adh/scope.json 2>/dev/null || true').replace(/\s+/g, '');
let restored = false;
const restore = () => {
  if (restored) return;
  restored = true;
  const b64 = priorScope || Buffer.from('{"version":1,"mode":"allowlist","packages":[]}').toString('base64');
  root(`echo ${b64} | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json`);
  adb('shell', 'am', 'force-stop', target);
};
process.on('exit', restore);
process.on('SIGINT', () => { restore(); process.exit(130); });

const fail = (msg, extra) => {
  restore();
  if (extra) console.error('---- evidence ----\n' + extra);
  console.error('FAIL: ' + msg);
  console.log('RESULT:FAIL');
  process.exit(1);
};

const scope = JSON.stringify({ version: 1, mode: 'allowlist', packages: [target] });
root(`echo ${Buffer.from(scope).toString('base64')} | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json`);
const applied = root('cat /data/adb/adh/scope.json').trim();
if (!applied.includes(target)) fail(`scope write did not round-trip (got: ${applied.slice(0, 120)})`);

// Cold start so the loader is the only thing that can have loaded the agent.
const startedAt = Date.now();
adb('shell', 'am', 'force-stop', target);
const launch = () => {
  const out = sh('cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', target);
  const component = out.trim().split(/\s+/).find((t) => /^[A-Za-z0-9._]+\/[A-Za-z0-9._$]+$/.test(t));
  if (component) { adb('shell', 'am', 'start', '-n', component); return `am start -n ${component}`; }
  adb('shell', 'monkey', '-p', target, '-c', 'android.intent.category.LAUNCHER', '1');
  return 'monkey (no component resolved)';
};
let launchMode = launch();
let session = null;
let retried = false;
const deadline = Date.now() + 45000;
while (Date.now() < deadline) {
  if (!retried && Date.now() > deadline - 35000 && sh('pidof', target).trim() === '') {
    retried = true; launchMode += ' -> retry ' + launch();
  }
  let agents = [];
  try { agents = await (await fetch(`${base}/api/agents`)).json(); } catch { /* daemon down -> handled below */ }
  session = (Array.isArray(agents) ? agents : [])
    .filter((a) => a.online && a.package === target && (a.connectedAt ?? 0) >= startedAt)
    .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0] ?? null;
  if (session) break;
  await sleep(700);
}

const focusLine = sh('dumpsys window | grep -E "mCurrentFocus" | head -n1').trim();
const evidence = () => [
  `target=${target} pid=${session?.pid ?? '?'} entry=${session?.entry ?? '?'} selfModule=${session?.selfModule ?? '?'}`,
  `launch: ${launchMode}`,
  `current focus: ${focusLine || '(unknown)'}`,
].join('\n');

if (!session) fail(`no FRESH (connectedAt >= ${startedAt}) online agent session for ${target} within 45s`, evidence());
if (session.entry !== 'start') {
  fail(`the fresh session was not started by the loader (entry=${session.entry}, expected "start") — `
     + `a self-loaded agent gets its JavaVM from JNI_OnLoad and would make this check vacuous`, evidence());
}

async function mcp(name, args) {
  const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name, arguments: { session: session.sessionId, ...args } } }) });
  const j = await r.json();
  const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
  try { return JSON.parse(c); } catch { return c; }
}

const probe = await mcp('compat_probe', {});
const backends = probe?.backends ?? {};
const jniReflect = backends.jniReflect === true;
const artDexCapture = backends.artDexCapture === true;
const symbolResolves = probe?.libartJniGetVms === true;

const dex = await mcp('art_dexfiles', {});
// The discriminator is `ok`, not the count: before the fix this command answered
// ok:false error:"no JavaVM". How many DexFiles a SYSTEM app exposes depends on whether any live
// thread carries an app class loader — com.android.settings legitimately yields 0 — so the count is
// reported, not asserted here.
const dexOk = dex?.ok === true;

// One Java operation that cannot work without a VM: enumerate a class that always exists and go
// through reflection (the reply carries the resolved class loader and its member lists).
const enumd = await mcp('java_enum', { className: 'java.lang.String' });
const enumRes = enumd?.result ?? {};
const enumOk = enumd?.ok === true && enumRes.className === 'java.lang.String' &&
  Array.isArray(enumRes.methods) && enumRes.methods.length >= 1 &&
  typeof enumRes.classLoader === 'string' && enumRes.classLoader.length > 0;

const evidence2 = () => [
  evidence(),
  `compat_probe: jniReflect=${backends.jniReflect} artDexCapture=${backends.artDexCapture} `
    + `libartJniGetVms=${probe?.libartJniGetVms} memBackend=${probe?.memBackend}`,
  `art_dexfiles: ok=${dex?.ok} count=${dex?.count} error=${dex?.error ?? '-'}`,
  `java_enum(java.lang.String): ok=${enumd?.ok} methods=${enumRes.methods?.length ?? '-'} `
    + `classLoader=${enumRes.classLoader ?? '-'} error=${enumd?.error ?? '-'}`,
].join('\n');

if (!jniReflect || !artDexCapture) {
  fail('the injected agent has no JavaVM: compat_probe reports jniReflect/artDexCapture false, so every Java '
     + 'and ART command is dead on this injection path', evidence2());
}
if (!symbolResolves) {
  fail('the agent cannot resolve JNI_GetCreatedJavaVMs out of the loaded libart.so — this is the mechanism '
     + 'that replaces the dlopen the linker refuses for a memfd-loaded library', evidence2());
}
if (!dexOk) fail('art_dexfiles answered with an error through the injected agent (expected ok:true)', evidence2());
if (!enumOk) fail('java_enum could not enumerate a boot classpath class through the injected agent', evidence2());

console.log(`ok  injected agent (entry=${session.entry}, selfModule=${session.selfModule}) pid=${session.pid}`);
console.log(`ok  compat_probe: jniReflect=${backends.jniReflect} artDexCapture=${backends.artDexCapture} libartJniGetVms=${probe?.libartJniGetVms} memBackend=${probe?.memBackend}`);
console.log(`ok  art_dexfiles: ok, ${dex.count} DexFile(s) visible to a system app`);
console.log(`ok  java_enum(java.lang.String): ${enumRes.methods.length} method(s), loader ${enumRes.classLoader}`);
console.log('RESULT:PASS');
restore();
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v9.8 injected-agent Java surface (memfd-loaded agent still reaches a JavaVM, ART and reflection)" 0 && exit 0 || exit 1
