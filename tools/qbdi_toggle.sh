#!/usr/bin/env bash
# Enable/disable the optional QBDI instruction-trace payload for real targets.
#
# The tracer (libQBDI.so) ships inside the module but is NOT loaded by default: the Zygisk companion
# hands an fd to allowlisted processes only while /data/adb/adh/qbdi.enabled exists, and the agent
# copies that fd into a memfd on the first qbdi_trace. With the flag absent the default injection
# surface is unchanged (no library, no mapping, no extra fd).
#
# Usage:
#   bash tools/qbdi_toggle.sh status
#   bash tools/qbdi_toggle.sh on  [--restart <package>]
#   bash tools/qbdi_toggle.sh off [--restart <package>]
#
# Changing the flag only affects processes started AFTER the change: the decision is made when a
# process is specialized. --restart cold-starts one package so it picks the new state up.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

FLAG="/data/adb/adh/qbdi.enabled"
MODE="${1:-status}"
shift || true
PKG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --restart) PKG="${2:-}"; shift 2 || shift ;;
    *) echo "!! unknown argument: $1" >&2; exit 2 ;;
  esac
done

SERIAL="${ANDROID_SERIAL:-$(adb devices | tr -d '\r' | awk 'NR>1 && $2=="device" {print $1; exit}')}"
[ -n "$SERIAL" ] || { echo "!! no adb device in 'device' state" >&2; exit 1; }

dev_root() { adb -s "$SERIAL" shell "su -c '$1'" | tr -d '\r'; }

case "$MODE" in
  status)
    if [ "$(dev_root "test -f $FLAG && echo yes || echo no" | tail -n 1)" = "yes" ]; then
      echo "qbdi: on  (delivered to allowlisted processes at specialization)"
    else
      echo "qbdi: off (default injection surface: no QBDI library / mapping / fd)"
    fi
    ;;
  on)
    dev_root "mkdir -p /data/adb/adh && touch $FLAG" >/dev/null
    echo "qbdi: on"
    ;;
  off)
    dev_root "rm -f $FLAG" >/dev/null
    echo "qbdi: off"
    ;;
  *)
    echo "!! mode must be status, on or off (got '$MODE')" >&2
    exit 2
    ;;
esac

if [ -n "$PKG" ]; then
  echo ">> cold-starting $PKG so it re-specializes"
  adb -s "$SERIAL" shell am force-stop "$PKG" >/dev/null 2>&1
  sleep 1
  adb -s "$SERIAL" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
fi
echo ">> target must be cold-started after a change (scope decision happens at specialization)"
