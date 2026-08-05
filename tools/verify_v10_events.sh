#!/usr/bin/env bash
# v1.0 session record/replay. Events (agent lifecycle, dumps) are persisted to
# idhd-data/events.jsonl and reloaded on startup. Launch the app (records agent.hello),
# confirm it's in /api/events, RESTART idhd, and confirm it STILL appears (replayed
# from disk). Exit 0 = PASS. Prereq: device + sandbox.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

# ensure a fresh agent.hello is recorded
adb -s "$SERIAL" reverse tcp:8761 tcp:8761 >/dev/null 2>&1 || true
adb -s "$SERIAL" shell am force-stop com.adh.sandbox >/dev/null 2>&1
adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1; sleep 3

before=$(curl -s "http://127.0.0.1:$HTTP/api/events?type=agent.hello")
BEFORE_HAS=$(echo "$before" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const r=JSON.parse(d);process.stdout.write(String(r.events.filter(e=>e.data&&e.data.package==='com.adh.sandbox').length))}catch(e){process.stdout.write('0')}})")
echo "agent.hello (sandbox) before restart: $BEFORE_HAS"

# restart idhd -> must reload events from disk
PID=$(powershell.exe -NoProfile -Command "(Get-NetTCPConnection -LocalPort $HTTP -State Listen -ErrorAction SilentlyContinue).OwningProcess" 2>/dev/null | tr -d '\r')
[ -n "$PID" ] && taskkill //F //PID "$PID" >/dev/null 2>&1
sleep 1; ( cd "$ROOT/daemon" && node src/index.ts > /tmp/idhd.log 2>&1 & ); sleep 2

after=$(curl -s "http://127.0.0.1:$HTTP/api/events?type=agent.hello")
AFTER_HAS=$(echo "$after" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const r=JSON.parse(d);process.stdout.write(String(r.events.filter(e=>e.data&&e.data.package==='com.adh.sandbox').length))}catch(e){process.stdout.write('0')}})")
echo "agent.hello (sandbox) after restart (replayed from disk): $AFTER_HAS"

# also confirm the jsonl file exists
[ -f "$ROOT/idhd-data/events.jsonl" ] && FILE_OK=1 || FILE_OK=0
echo "events.jsonl present: $FILE_OK"

if [ "$BEFORE_HAS" -ge 1 ] && [ "$AFTER_HAS" -ge 1 ] && [ "$FILE_OK" = 1 ]; then
  echo "✅ v1.0 session record/replay PASS (event survived idhd restart)"; exit 0
else echo "❌ FAIL"; exit 1; fi
