#!/usr/bin/env bash
# v10.2 per-package hook policy acceptance: the scope file's per-app policy must decide which crypto
# hook families are INSTALLED inside that app — not merely which records are reported afterwards.
#
# Two round trips, each one cold-starting the target, so the assertion is about a FLIP and not about
# one lucky configuration:
#   round 1  hmac + AEAD off, the rest on  → the agent's install must report exactly those two skipped
#   round 2  everything on               → nothing skipped
#
# What is asserted, and where each fact comes from:
#   * the agent's own hello carries the policy the companion read out of scope.json and handed over
#     (the phone-side hop — no host command is involved in getting it there)
#   * the install verdict comes from the ordinary install path (MCP capture_start, i.e. the daemon's
#     ONE setCapture implementation), which is where the families are actually skipped: the reply's
#     `skipped` list must name exactly the switched-off families, and every switched-ON family must
#     carry a real counter (-1 would mean the policy skipped it anyway).
# Note what the policy does NOT do: it does not arm anything by itself. The agent holds no module
# name to arm with (WS-B red line), so it applies the policy to the next install, whoever issues it.
#
# The script writes its own scope.json for one target, cold-starts it, and restores the operator's
# scope file (plus force-stops the target) on exit — pass or fail.
#
# SKIPs (exit 0, no RESULT:PASS) when a precondition is missing: no device, no root manager, no adh
# module, no adb reverse tunnel (tools/dev_up.sh), or the target package is not installed.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

TARGET="${ADH_POLICY_TARGET:-com.adh.sandbox}"

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v102_policy (no device)"
  exit 0
fi
ROOT_MGR="$(adb -s "$SERIAL" shell 'su -c "if test -x /data/adb/ksud || test -x /data/adb/ksu/bin/ksud; then echo KSU; elif test -d /data/adb/magisk; then echo MAGISK; else echo NO; fi"' 2>/dev/null | tr -d '\r' || true)"
if [ "$ROOT_MGR" != "KSU" ] && [ "$ROOT_MGR" != "MAGISK" ]; then
  echo "SKIP  verify_v102_policy (no Magisk/KernelSU on device)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh"' >/dev/null 2>&1; then
  echo "SKIP  verify_v102_policy (adh Zygisk module not installed)"
  exit 0
fi
# The install verdict is read back over the Host ADH Daemon's own MCP surface; without the tunnel
# there is nothing to talk to (tools/dev_up.sh sets it up).
if ! adb -s "$SERIAL" reverse --list 2>/dev/null | grep -q 'tcp:876'; then
  echo "SKIP  verify_v102_policy (no adb reverse tunnel; run tools/dev_up.sh first)"
  exit 0
fi
if ! adb -s "$SERIAL" shell "pm list packages" 2>/dev/null | tr -d '\r' | grep -q "^package:${TARGET}\$"; then
  echo "SKIP  verify_v102_policy (target ${TARGET} not installed)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" "$SERIAL" "$TARGET" <<'EOF'
const [http, serial, target] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const sh = (...args) => String(adb('shell', ...args).stdout ?? '').replace(/\r/g, '');
const root = (cmd) => sh(`su -c ${JSON.stringify(cmd)}`);
const rpc = (m, p) => fetch(`${base}/mcp`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: Math.floor(Math.random() * 1e6), method: m, params: p }),
}).then((r) => r.json());
const call = async (name, args) => {
  const r = await rpc('tools/call', { name, arguments: args });
  if (r.error) throw new Error(`${name}: ${r.error.message}`);
  const t = r.result?.content?.[0]?.text ?? 'null';
  try { return JSON.parse(t); } catch { return t; }
};

// The module the install targets is the caller's choice (the agent has none) — pass the documented
// default explicitly so this gate does not depend on whatever the daemon's settings say.
const CRYPTO_MODULE = 'libjavacrypto.so';

// hmac OFF and AEAD OFF first: EVP_DigestSign* is shared by the hmac and asymmetric paths, so it
// must still install (the rule is "at least one of them on") — that is asserted in `on` below.
// `skipped` names the GROUPS the policy turned off (as the agent reports them: the AEAD group is
// `aead`, while the per-symbol counters below are `aeadSeal`), so the two lists are kept apart.
const ROUNDS = [
  {
    c: { d: true, h: false, s: true, a: true, t: true, e: false },
    policy: 'd=1,h=0,s=1,a=1,t=1,e=0',
    skipped: ['aead', 'hmac'],
    offCounters: ['hmac', 'aeadSeal'],
    on: ['evp', 'cipherInit', 'cipherCtxFree', 'digest', 'digestSign', 'sslWrite', 'sslRead', 'pkeySign'],
  },
  {
    c: { d: true, h: true, s: true, a: true, t: true, e: true },
    policy: 'd=1,h=1,s=1,a=1,t=1,e=1',
    skipped: [],
    offCounters: [],
    on: ['evp', 'cipherInit', 'cipherCtxFree', 'digest', 'hmac', 'digestSign', 'sslWrite', 'sslRead', 'pkeySign', 'aeadSeal'],
  },
];

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

const writeScope = (c) => root(`echo ${Buffer.from(JSON.stringify({
  version: 2, mode: 'allowlist', packages: [target], policy: { [target]: { c } },
})).toString('base64')} | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json`);

// Per-family install counter as the agent reports it: -1 = the policy skipped it, 0 = asked for but
// this module does not import the symbol, >=1 = installed.
const counterOf = (reply, name) => {
  if (name === 'pkeySign') return reply?.pkey?.sign;
  if (name === 'aeadSeal') return reply?.aead?.seal;
  return reply?.[name];
};

const startTarget = () => {
  adb('shell', 'am', 'force-stop', target);
  const out = sh('cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', target);
  const component = out.trim().split(/\s+/).find((t) => /^[A-Za-z0-9._]+\/[A-Za-z0-9._$]+$/.test(t));
  if (component) adb('shell', 'am', 'start', '-n', component);
  else adb('shell', 'monkey', '-p', target, '-c', 'android.intent.category.LAUNCHER', '1');
  return Date.now();
};

for (const [i, round] of ROUNDS.entries()) {
  const label = `round ${i + 1} (${round.policy})`;
  writeScope(round.c);
  const applied = root('cat /data/adb/adh/scope.json').trim();
  if (!applied.includes(target) || !applied.includes('"policy"'))
    fail(`[${label}] policy write did not round-trip (got: ${applied.slice(0, 200)})`);

  const startedAt = startTarget();
  let session = null;
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    let agents = [];
    try { agents = await (await fetch(`${base}/api/agents`)).json(); } catch { /* daemon down */ }
    session = (Array.isArray(agents) ? agents : [])
      .filter((a) => a.online && a.package === target && (a.connectedAt ?? 0) >= startedAt && String(a.policy || ''))
      .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0] ?? null;
    if (session) break;
    await sleep(700);
  }
  const evidence = () => `target=${target} pid=${session?.pid ?? '?'} hello.policy=${JSON.stringify(session?.policy)}`;
  if (!session) fail(`[${label}] no FRESH session for ${target} carrying a policy within 45s (was the scope written and the app cold-started?)`, evidence());
  if (session.policy !== round.policy) fail(`[${label}] companion delivered "${session.policy}", expected "${round.policy}"`, evidence());

  // The install itself: the daemon's ONE setCapture implementation, so this is the real path a
  // user's (or an AI's) capture_start takes — not a private test hook.
  let toggle;
  try { toggle = await call('capture_start', { session: session.sessionId, cryptoModule: CRYPTO_MODULE }); }
  catch (e) { fail(`[${label}] capture_start failed: ${e.message}`, evidence()); }
  const reply = toggle?.reply ?? {};
  const skipped = String(reply.skipped ?? '').split(',').map((s) => s.trim()).filter(Boolean).sort();
  const wantSkipped = [...round.skipped].sort();
  const dump = `skipped=${JSON.stringify(reply.skipped)} installed=${toggle?.installed}/${toggle?.attempted} counter=${JSON.stringify(Object.fromEntries(round.on.concat(round.offCounters).map((n) => [n, counterOf(reply, n)])))}`;
  if (JSON.stringify(skipped) !== JSON.stringify(wantSkipped))
    fail(`[${label}] families skipped by the policy were ${JSON.stringify(skipped)}, expected ${JSON.stringify(wantSkipped)}`, `${evidence()}\n${dump}`);
  for (const name of round.on)
    if (counterOf(reply, name) === -1)
      fail(`[${label}] ${name} was switched ON but the install reports it as skipped (-1)`, `${evidence()}\n${dump}`);
  for (const name of round.offCounters)
    if (counterOf(reply, name) !== -1)
      fail(`[${label}] ${name} was switched OFF but the install reports ${counterOf(reply, name)}, not -1`, `${evidence()}\n${dump}`);

  console.log(`ok  ${label}: companion delivered it — companion → agent, no host command involved`);
  console.log(`ok  ${label}: skipped by policy = [${wantSkipped.join(',') || '(none)'}], all ${round.on.length} selected families were installed or absent-from-module, never skipped`);
}

console.log('ok  the policy is install-time: switched-off families are never installed, not filtered later');
console.log('ok  digestSign survives hmac=0 because asymmetric=1 (the two share EVP_DigestSign*)');
console.log('RESULT:PASS');
restore();
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v10.2 per-package hook policy (scope policy → companion → agent → install, unselected families never installed)" 0 && exit 0 || exit 1
