#!/usr/bin/env bash
# Install / enable / disable the optional ADH Xposed module (module W optional backend).
#
# Usage:
#   tools/install_xposed.sh [--apk PATH] [--package PKG] [--no-install] [--disable] [--status]
#
# enable (default):
#   1. root `pm install -r -t` of the module APK (never plain `adb install` on ColorOS)
#   2. framework CLI: modules enable com.adh.xposed
#   3. framework CLI: scope set com.adh.xposed <PKG>/0   (overwrites THIS module's scope)
# disable: scope set (empty) + modules disable — the backend stays opt-in, nothing else changes.
#
# The framework CLI is /data/adb/lspd/cli (LSPosed and Vector builds expose the same
# `modules enable|disable|ls` + `scope set|add|rm|ls` surface).
#
# Env: ANDROID_SERIAL, ADB (optional)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

MODULE_PKG="com.adh.xposed"
TARGET="com.adh.manager"
APK="$ROOT/injector/xposed/dist/adh-xposed.apk"
DO_INSTALL=1
MODE="enable"

usage() { sed -n '2,15p' "$0"; }
die() { echo "!! $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apk) APK="${2:?--apk needs a value}"; shift 2 ;;
    --package) TARGET="${2:?--package needs a value}"; shift 2 ;;
    --no-install) DO_INSTALL=0; shift ;;
    --disable) MODE="disable"; shift ;;
    --status) MODE="status"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-}}"
[ -n "$SERIAL" ] || die "no device serial; set ANDROID_SERIAL"
ADB="${ADB:-adb}"
CLI="/data/adb/lspd/cli"

cli() { "$ADB" -s "$SERIAL" shell "su -c '$CLI $1'" 2>/dev/null | tr -d '\r'; }

STATUS="$(cli 'status' || true)"
case "$STATUS" in
  *Framework*) ;;
  *) die "framework CLI unusable at $CLI (is LSPosed/Vector installed?)" ;;
esac

case "$MODE" in
  enable)
    if [ "$DO_INSTALL" = "1" ]; then
      [ -f "$APK" ] || die "module APK missing: $APK (run tools/build_xposed.sh)"
      echo ">> installing $(basename "$APK")" >&2
      install_apk_root "$APK" /data/local/tmp/adh-xposed.apk "$SERIAL" >&2
    fi
    echo ">> enabling module $MODULE_PKG" >&2
    cli "modules enable $MODULE_PKG"
    echo ">> scope = $TARGET/0 (overwrites this module's scope)" >&2
    cli "scope set $MODULE_PKG $TARGET/0"
    echo ">> module list:" >&2
    cli "modules ls" | grep -E "PACKAGE|$MODULE_PKG" >&2 || true
    echo ">> scope list:" >&2
    cli "scope ls $MODULE_PKG" >&2 || true
    ;;
  disable)
    # `scope set <module>` with no apps throws inside the CLI (verified on Vector 2.2), so
    # clear the scope entry by entry instead.
    ENTRIES="$(cli "scope ls $MODULE_PKG" | awk 'NR>2 && NF>=2 {print $1"/"$2}')"
    if [ -n "$ENTRIES" ]; then
      for e in $ENTRIES; do
        echo ">> scope rm $e" >&2
        cli "scope rm $MODULE_PKG $e" >&2 || true
      done
    else
      echo ">> scope already empty" >&2
    fi
    echo ">> disabling module $MODULE_PKG" >&2
    cli "modules disable $MODULE_PKG" >&2 || true
    ;;
  status)
    cli "modules ls"
    echo "--- scope ---"
    cli "scope ls $MODULE_PKG"
    ;;
esac