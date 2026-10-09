#!/usr/bin/env bash
# v9.9 artifact store acceptance (HOST-ONLY — no device needed).
#
# Two things went wrong with captures/ and both are fixed here:
#   * the runtime `dumps` map was in-memory only, so restarting the daemon made every artifact
#     invisible — dumps_list / /api/dumps / download-by-sha / dex_index all answered "nothing"
#     while the bytes sat on disk (the artifacts survive, only the daemon forgot them);
#   * nothing ever reclaimed that directory (the only `retain` was for the in-memory capture list),
#     so one packed-app run left ~1.1 GB behind.
#
# This checks the unit-tested policy AND the end-to-end behaviour the bug was reported as:
#   1) the eviction policy + filename mapping (node --test on the pure module)
#   2) restart the daemon, then every artifact file on disk must be listed again, labelled
#      'disk-reload' (not invented provenance), and the retention budget must be exposed
#
# The daemon is restarted by this script (same technique as verify_v37), so it is registered last.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

if ! verify_unit_pass "artifact-store eviction policy" artifact_store.test.ts 8; then
  echo "RESULT:FAIL (eviction-policy unit tests did not all pass)"
  exit 1
fi

DAEMON_PID="$(daemon_pid_on_port "$HTTP")"   # ss/lsof on Linux, netstat on Windows
if [ -z "$DAEMON_PID" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v9.9 artifact store SKIP (no daemon listening on :$HTTP to restart)"
  exit 0
fi

echo ">> restarting adhd (pid $DAEMON_PID)"
# verify_stop_pid: PowerShell on Windows, kill elsewhere - either way the stop is verified below
# (with the port still bound, the test would silently keep the warm daemon and fake a pass).
verify_stop_pid "$DAEMON_PID"
STOPPED=""
for _ in $(seq 1 12); do
  if [ -z "$(daemon_pid_on_port "$HTTP")" ]; then STOPPED=1; break; fi
  sleep 0.5
done
if [ -z "$STOPPED" ]; then
  echo "RESULT:FAIL"
  echo "❌ v9.9 artifact store FAIL (daemon pid $DAEMON_PID did not stop)"
  exit 1
fi
if ! verify_start_daemon "$HTTP"; then
  echo "RESULT:FAIL"
  echo "❌ v9.9 artifact store FAIL (daemon did not come back within the cold-start budget)"
  exit 1
fi

set +e
OUT="$(node - "$BASE" "$ROOT" <<'EOF'
const [base, root] = process.argv.slice(2);
const fs = await import('node:fs');
const path = await import('node:path');
const captures = path.join(root, 'captures');

// Same naming scheme as daemon/src/artifacts.ts — kept literal here so the test would catch a
// change in either place rather than silently matching nothing.
const KIND = /^([0-9a-f]{16})(?:\.([a-z0-9]+))?\.(bin|so|dex)$/;
const disk = [];
for (const name of fs.readdirSync(captures)) {
  const m = KIND.exec(name);
  if (!m) continue;
  const p = path.join(captures, name);
  if (!fs.statSync(p).isFile()) continue;
  disk.push({ prefix: m[1], kind: m[3] === 'bin' ? (m[2] ?? 'region') : m[3], size: fs.statSync(p).size });
}

const dumped = await (await fetch(`${base}/api/dumps`)).json();
// /api/settings/export returns the settings object directly (there is no GET /api/settings).
const settingsBody = await (await fetch(`${base}/api/settings/export`)).json();
const byPrefix = new Map(dumped.map((d) => [String(d.sha256).slice(0, 16), d]));
const missing = disk.filter((f) => !byPrefix.has(f.prefix));
const reloaded = dumped.filter((d) => d.source === 'disk-reload');
// Every listed entry must point at a file that is really there — a reload that invents paths would
// make download-by-sha fail later, which is the failure this whole check exists to prevent.
const dangling = dumped.filter((d) => !fs.existsSync(d.path));

const budget = settingsBody?.artifacts;
const budgetOk = budget && Number.isFinite(budget.maxBytes) && Number.isFinite(budget.maxAgeDays);

console.log(`disk artifacts: ${disk.length} (${(disk.reduce((a, f) => a + f.size, 0) / 1048576).toFixed(1)} MiB)`);
console.log(`/api/dumps after restart: ${dumped.length} entries, ${reloaded.length} labelled disk-reload`);
console.log(`settings.artifacts: ${JSON.stringify(budget)}`);
if (missing.length) console.log(`MISSING from /api/dumps: ${missing.slice(0, 5).map((f) => f.prefix).join(', ')}${missing.length > 5 ? ` (+${missing.length - 5})` : ''}`);
if (dangling.length) console.log(`DANGLING paths: ${dangling.slice(0, 3).map((d) => d.path).join(', ')}`);

const pass = disk.length > 0 && dumped.length > 0 && missing.length === 0 && dangling.length === 0 &&
  reloaded.length > 0 && !!budgetOk;
console.log(`checks: disk>0=${disk.length > 0} listed>0=${dumped.length > 0} allDiskListed=${missing.length === 0} noDangling=${dangling.length === 0} reloadLabelled=${reloaded.length > 0} budgetExposed=${!!budgetOk}`);
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
verify_gate "v9.9 artifact store (eviction policy unit-tested; artifacts survive a daemon restart, labelled honestly, budget exposed)" 0 && exit 0 || exit 1
