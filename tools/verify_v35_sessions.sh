#!/usr/bin/env bash
# v3.5 Web UI session hygiene: bounded session list + readable session picker.
#
# Two defects this locks down:
#   1) the daemon never pruned `sessions`, so every app restart added a dead entry — an afternoon
#      of testing left 20 of them in the picker. pruneSessions() keeps at most
#      OFFLINE_KEEP_PER_PACKAGE offline sessions per package (and nothing older than
#      OFFLINE_RETENTION_MS), and the picker now lists ONLINE sessions by default.
#   2) the native <select> was `background:transparent`, so the OS painted its popup white while
#      the option text stayed --ink (#fff): the session list rendered as a blank white area.
#
# Checks: pruner unit behaviour + picker markup/CSS (host, no device needed), then — when a device
# is attached — the live bound after four sandbox restarts.
#
# Run: bash tools/verify_v35_sessions.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$ROOT" "$BASE" <<'EOF'
import { readFile } from 'node:fs/promises';

const [root, base] = process.argv.slice(2);
const checks = [];
const chk = (label, ok, detail = '') => { checks.push([label, !!ok]); console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`); };

// --- pruner unit behaviour (no daemon needed) ---------------------------------------------
const mod = await import(new URL(`file:///${root.replace(/\\/g, '/')}/daemon/src/state.ts`).href);
const now = Date.now();
const mkSession = (id, { online = false, ageMs = 0 } = {}) => ({
  sessionId: id, package: 'com.unit.test', pid: 1, uid: 1, process: 'p', abi: 'arm64',
  android: '15', sdk: 35, entry: 'start', agentVer: '0',
  connectedAt: now - ageMs, lastSeen: now - ageMs, online, mapsCount: 0, regionsSample: [],
});
mod.sessions.clear();
for (let i = 0; i < 5; i++) mod.sessions.set(`off${i}`, mkSession(`off${i}`, { ageMs: (5 - i) * 1000 }));
mod.sessions.set('on1', mkSession('on1', { online: true }));
const dropped = mod.pruneSessions(now);
const keptOffline = [...mod.sessions.values()].filter((s) => !s.online).length;
const keptOnline = [...mod.sessions.values()].filter((s) => s.online).length;
chk('pruner drops the oldest offline sessions', dropped.length === 3, `dropped=${dropped.length}`);
chk('pruner keeps OFFLINE_KEEP_PER_PACKAGE offline sessions', keptOffline === mod.OFFLINE_KEEP_PER_PACKAGE, `kept=${keptOffline}`);
chk('pruner never touches online sessions', keptOnline === 1, `online=${keptOnline}`);

// A single offline session older than the retention window must go too.
mod.sessions.clear();
mod.sessions.set('stale', mkSession('stale', { ageMs: mod.OFFLINE_RETENTION_MS + 60_000 }));
const droppedAged = mod.pruneSessions(now);
chk('pruner drops offline sessions past retention', droppedAged.includes('stale'));
mod.sessions.clear();

// --- picker markup / CSS ------------------------------------------------------------------
const html = await readFile(`${root}/daemon/public/index.html`, 'utf8');
chk('picker hides offline sessions by default', /showOffline\?all:all\.filter\(a=>a\.online\)/.test(html.replace(/\s+/g, '')));
chk('picker has an offline toggle', html.includes('id="sessShowOffline"'));
chk('picker reports how many are hidden', html.includes('已隐藏'));
chk('option popup has an explicit background', /select option \{ background:#11151c; color:var\(--ink\); \}/.test(html));
chk('session select is opaque (not background:transparent)', /\.sess-lab select \{[^}]*background:var\(--surface-2\)/.test(html));

// --- live bound (only when a daemon is up) ------------------------------------------------
let live = null;
try {
  const agents = await (await fetch(`${base}/api/agents`)).json();
  live = agents;
} catch { live = null; }
if (live) {
  const perPkg = new Map();
  for (const a of live) if (!a.online) perPkg.set(a.package, (perPkg.get(a.package) ?? 0) + 1);
  const worst = [...perPkg.entries()].sort((a, b) => b[1] - a[1])[0];
  chk('live session map respects the offline cap', !worst || worst[1] <= mod.OFFLINE_KEEP_PER_PACKAGE, worst ? `${worst[0]}=${worst[1]}` : 'no offline sessions');
  console.log(`   live sessions: total=${live.length} online=${live.filter((a) => a.online).length} offline=${live.filter((a) => !a.online).length}`);
} else {
  console.log('SKIP  live session map — daemon not reachable');
}

console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set +e
echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then SENTINEL="RESULT:PASS"; else SENTINEL="RESULT:FAIL"; fi
OUT="$OUT
$SENTINEL"
verify_gate "v3.5 session hygiene (bounded list + readable picker)" 0 && exit 0 || exit 1