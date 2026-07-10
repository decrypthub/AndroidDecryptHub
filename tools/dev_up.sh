#!/usr/bin/env bash
# Idempotent dev environment bring-up: ensure idhd is running and adb reverse is set.
# Safe to call at the start of every autonomous loop iteration.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
AGENT="${IDH_AGENT_PORT:-8761}"

# 1) idhd up?
if curl -s -m 2 "http://127.0.0.1:$HTTP/health" >/dev/null 2>&1; then
  echo "idhd: already running"
else
  echo "idhd: starting"
  ( cd "$ROOT/daemon" && node src/index.ts > /tmp/idhd.log 2>&1 & )
  sleep 2
  curl -s -m 2 "http://127.0.0.1:$HTTP/health" >/dev/null 2>&1 && echo "idhd: up" || echo "idhd: FAILED (see /tmp/idhd.log)"
fi

# 2) device + adb reverse
#    - AGENT (8761): agent in the target process dials host idhd
#    - HTTP  (8760): so the phone's own browser can reach the host web console at
#      127.0.0.1:8760 through the reverse tunnel (same URL works on the PC browser too)
STATE="$(adb get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" = "device" ]; then
  SERIAL="$(adb devices | awk 'NR==2{print $1}')"
  adb -s "$SERIAL" reverse tcp:$AGENT tcp:$AGENT >/dev/null 2>&1
  adb -s "$SERIAL" reverse tcp:$HTTP tcp:$HTTP >/dev/null 2>&1
  echo "adb reverse: set ($SERIAL) agent:$AGENT web:$HTTP"
  echo "device: online ($SERIAL)"
  echo "web console: http://127.0.0.1:$HTTP  (open on PC, or in the phone browser via the demo app)"
else
  echo "device: OFFLINE (state='$STATE') — device-only verification must be marked PENDING"
fi
