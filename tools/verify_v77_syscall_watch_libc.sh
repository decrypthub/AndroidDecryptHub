#!/usr/bin/env bash
# v4.38 libc-mediated syscall watch acceptance (device).
#
# The v4.10 watch could only find `svc #0` sites inside a module the target itself carries. Real apps
# do not issue syscalls: they call bionic wrappers, whose stubs live in libc.so. This check proves the
# upgraded watch can (a) attribute a site to a syscall number statically, (b) select sites by name in
# both the target module and libc.so, and (c) really intercept a libc-mediated syscall -
# the sandbox fixture calls uname(2) through libc, and the hook must report x8=0xa0 (uname).
#
# Missing preconditions (no device / no agent / old daemon / sandbox without the fixture) print
# "SKIP ..." and exit 0 WITHOUT RESULT:PASS, so the runner counts them as skips, not as passes.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v77_syscall_watch_libc (no device)"
  exit 0
fi
verify_restart_sandbox || { echo "FAIL  could not restart sandbox before syscall scan"; exit 1; }

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : [])
  .filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) { console.log('SKIP  verify_v77_syscall_watch_libc (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;

async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  let parsed = null;
  try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const fail = (msg, extra) => {
  if (extra !== undefined) console.log(JSON.stringify(extra));
  console.log('FAIL ' + msg);
  console.log('RESULT:FAIL');
  process.exit(0);
};
const unhookAll = async (hooks) => {
  const rs = [];
  for (const h of hooks ?? []) rs.push(await post('/api/native/hook', { session, action: 'unhook', hookId: Number(h.hookId) }));
  return rs.every((r) => r.body?.ok === true);
};

// (1) the target's own direct svc must be attributed to the right number and selectable by name.
const direct = await post('/api/native/syscall_watch', { session, module: 'libadhdetect.so', syscalls: ['gettid'], limit: 4 });
if (direct.status === 404 || /unknown|unsupported/i.test(String(direct.body?.error ?? ''))) {
  console.log('SKIP  verify_v77_syscall_watch_libc (daemon predates syscall attribution; restart it)');
  process.exit(0);
}
if (direct.body?.attributedCount === undefined) {
  console.log('SKIP  verify_v77_syscall_watch_libc (daemon response has no attribution counters)');
  process.exit(0);
}
// Positive control for the "sandbox fixture missing" SKIP further down: a symbol that must resolve on
// any sandbox build, so a real resolver regression cannot be excused as "the APK is old".
const control = await post('/api/native/call', { session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['2', '3'], confirm: true });
if (control.body?.ok !== true) {
  fail(`positive control failed: libadhdetect.so:adh_add_target is not callable (${control.body?.error ?? control.status}) - resolver problem, not an old APK`, control);
}
if (!direct.body || Number(direct.body.installedCount) < 1) {
  fail('expected at least one gettid svc site in libadhdetect.so', direct);
}
const directHooks = direct.body.hooks ?? [];
if (directHooks.some((hook) => hook?.syscall?.nr !== 178 || hook?.attribution === 'unknown')) {
  fail('a selected direct site was not attributed to gettid(178)', direct.body);
}
if (!(await unhookAll(directHooks))) fail('unhook of the direct-site hooks failed');

// (2) libc coverage: only the sites attributed to uname(160) may be hooked, even though libc has
// hundreds of svc sites.
const libc = await post('/api/native/syscall_watch', { session, module: 'libc.so', syscalls: ['uname'], limit: 2 });
if (!libc.body || Number(libc.body.installedCount) < 1) {
  fail('no uname svc site found/hooked in libc.so', libc);
}
if (Number(libc.body.svcCount) < 50) fail(`libc scan looks wrong (svcCount=${libc.body.svcCount})`, libc.body);
// The header claims libc attribution IN GENERAL, not just "one uname site exists": a decoder that
// could only resolve uname would otherwise still go green.
const attributed = Number(libc.body.attributedCount ?? 0);
const unknown = Number(libc.body.unknownCount ?? (Number(libc.body.svcCount) - attributed));
if (!(attributed >= Math.floor(Number(libc.body.svcCount) * 0.9))) {
  fail(`attribution coverage too low: attributed ${attributed} of ${libc.body.svcCount} svc sites`, libc.body);
}
if (unknown > Math.ceil(Number(libc.body.svcCount) * 0.1)) {
  fail(`too many unattributed sites: unknown=${unknown} of ${libc.body.svcCount}`, libc.body);
}
const wrong = (libc.body.hooks ?? []).filter((h) => h?.syscall?.nr !== 160);
if (wrong.length) fail(`filter hooked a non-uname site: ${JSON.stringify(wrong)}`, libc.body);

// (3) trigger through libc and require the hook to fire with x8=0xa0.
const call = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_libc_uname_probe', args: [], confirm: true,
});
if (!call.body?.ok) {
  const err = String(call.body?.error ?? '');
  if (/not found|no such|symbol/i.test(err)) {
    // The positive control above proved symbol resolution works, so this really is the fixture being
    // absent (an older sandbox APK) rather than a resolver regression.
    if (!(await unhookAll(libc.body.hooks))) console.log('WARN  libc hooks could not be removed before skipping');
    console.log('SKIP  verify_v77_syscall_watch_libc (sandbox fixture adh_libc_uname_probe missing; rebuild + install the sandbox APK)');
    process.exit(0);
  }
  fail(`native_call of the uname probe failed: ${err}`, call);
}
const hookIds = (libc.body.hooks ?? []).map((h) => Number(h.hookId));
let found = null;
const deadline = Date.now() + 12_000;
while (Date.now() < deadline) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=200`)).json().catch(() => ({}));
  for (const item of (list.captures ?? [])) {
    if (item.func !== 'NATIVE_HOOK') continue;
    const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json().catch(() => null);
    const text = String(detail?.text ?? '');
    if (hookIds.some((id) => text.includes(`"hookId":${id}`)) && text.includes('"x8":"0xa0"')) { found = detail; break; }
  }
  if (found) break;
  await sleep(120);
}

const unhooked = await unhookAll(libc.body.hooks);
const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');
console.log(JSON.stringify({
  direct: { svcCount: direct.body.svcCount, hooks: directHooks },
  libc: {
    svcCount: libc.body.svcCount, attributed: libc.body.attributedCount, unknown: libc.body.unknownCount,
    matched: libc.body.matchedCount, hooks: libc.body.hooks,
  },
  call: { ok: call.body.ok, resultDecimal: call.body.resultDecimal },
  event: found ? { id: found.id, preview: found.preview } : null,
  unhooked, online,
}));
const pass = call.body?.ok === true && found != null && unhooked && online;
if (!found) console.log(`FAIL no NATIVE_HOOK event with x8=0xa0 was captured for hookIds=${hookIds.join(',')}`);
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.38 libc-mediated syscall watch (attribution + filter + x8=0xa0)" 0 && exit 0 || exit 1
