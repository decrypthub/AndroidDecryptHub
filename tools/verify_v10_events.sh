#!/usr/bin/env bash
# v1.0 session record/replay. Events (agent lifecycle, dumps) are persisted to
# adhd-data/events.jsonl and reloaded on startup. Launch the app (records agent.hello),
# confirm it's in /api/events, RESTART adhd, and confirm it STILL appears (replayed
# from disk). Exit 0 = PASS. Prereq: device + sandbox.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_data_dir

# ensure a fresh agent.hello is recorded
adb -s "$SERIAL" reverse tcp:8761 tcp:8761 >/dev/null 2>&1 || true
adb -s "$SERIAL" shell am force-stop com.adh.sandbox >/dev/null 2>&1
adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1; sleep 3

before=$(curl -s "http://127.0.0.1:$HTTP/api/events?type=agent.hello")
BEFORE_HAS=$(echo "$before" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const r=JSON.parse(d);process.stdout.write(String(r.events.filter(e=>e.data&&e.data.package==='com.adh.sandbox').length))}catch(e){process.stdout.write('0')}})")
echo "agent.hello (sandbox) before restart: $BEFORE_HAS"

# restart adhd -> must reload events from disk.
# Cross-platform (ss/lsof on Linux, netstat+PowerShell on Windows): the old powershell/taskkill pair
# was a silent no-op on Linux, so the "restart" never happened and the events check compared the
# SAME daemon with itself - a pass that proved nothing.
PID="$(daemon_pid_on_port "$HTTP")"
[ -n "$PID" ] && verify_stop_pid "$PID"
for _ in $(seq 1 12); do [ -z "$(daemon_pid_on_port "$HTTP")" ] && break; sleep 0.5; done
if ! verify_start_daemon "$HTTP"; then
  echo "RESULT:FAIL"
  echo "❌ v1.0 event store FAIL (daemon did not come back within the cold-start budget)"
  exit 1
fi

after=$(curl -s "http://127.0.0.1:$HTTP/api/events?type=agent.hello")
AFTER_HAS=$(echo "$after" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const r=JSON.parse(d);process.stdout.write(String(r.events.filter(e=>e.data&&e.data.package==='com.adh.sandbox').length))}catch(e){process.stdout.write('0')}})")
echo "agent.hello (sandbox) after restart (replayed from disk): $AFTER_HAS"

# also confirm the jsonl file exists — in the daemon's ACTUAL data dir, not a hardcoded one. Reading
# the old path passed on a stale file after ADH_DATA_DIR was introduced, i.e. a false green.
[ -f "${ADH_DATA:-$ROOT/adhd-data}/events.jsonl" ] && FILE_OK=1 || FILE_OK=0
echo "events.jsonl present: $FILE_OK"

if [ "$BEFORE_HAS" -ge 1 ] && [ "$AFTER_HAS" -ge 1 ] && [ "$FILE_OK" = 1 ]; then
  echo "✅ v1.0 session record/replay PASS (event survived adhd restart)"; exit 0
else echo "❌ FAIL"; exit 1; fi
