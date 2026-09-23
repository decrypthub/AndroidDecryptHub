#!/usr/bin/env bash
# Idempotent dev environment bring-up: ensure ADH Daemon is running and adb reverse is set.
# Safe to call at the start of every autonomous loop iteration.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
AGENT="${ADH_AGENT_PORT:-8761}"

# 1) ADH Daemon up?
if curl -s -m 2 "http://127.0.0.1:$HTTP/health" >/dev/null 2>&1; then
  echo "adhd: already running"
else
  echo "adhd: starting ADH Daemon"
  ( cd "$ROOT/daemon" && node src/index.ts > /tmp/adhd.log 2>&1 & )
  sleep 2
  curl -s -m 2 "http://127.0.0.1:$HTTP/health" >/dev/null 2>&1 && echo "adhd: up" || echo "adhd: FAILED (see /tmp/adhd.log)"
fi

# 2) device + adb reverse
#    - AGENT (8761): agent in the target process dials host ADH Daemon
#    - HTTP  (8088): so the phone's own browser can reach the host web console at
#      127.0.0.1:8088 through the reverse tunnel; prefer the Host LAN IP on the same Wi-Fi
STATE="$(adb get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" = "device" ]; then
  SERIAL="${ANDROID_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"
  adb -s "$SERIAL" reverse tcp:$AGENT tcp:$AGENT >/dev/null 2>&1
  adb -s "$SERIAL" reverse tcp:$HTTP tcp:$HTTP >/dev/null 2>&1
  echo "adb reverse: set ($SERIAL) agent:$AGENT web:$HTTP"
  echo "device: online ($SERIAL)"
  echo "web console: http://127.0.0.1:$HTTP  (open on PC, or in the phone browser via the demo app)"
else
  echo "device: OFFLINE (state='$STATE') — device-only verification must be marked PENDING"
fi
