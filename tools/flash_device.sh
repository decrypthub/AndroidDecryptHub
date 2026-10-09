#!/usr/bin/env bash
# Build (optional), push, and install the ADH Magisk/KernelSU bundle on the
# attached phone. This is the repeatable "I update code, you only test" path.
#
# Usage:
#   bash tools/flash_device.sh              # rebuild + install (no reboot)
#   bash tools/flash_device.sh --reboot     # also reboot so Zygisk/Device Daemon load
#   bash tools/flash_device.sh --no-build   # install the already-built bundle
#
# Serial: ANDROID_SERIAL / ADH_SERIAL, else the single attached device.
set -euo pipefail
# Git Bash rewrites leading-/ args into C:/Program Files/Git/... when calling
# Windows adb.exe. Keep POSIX device paths intact, and convert only host files
# we pass to `adb push` / root `pm install`.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

DO_BUILD=1
DO_REBOOT=0
for arg in "$@"; do
  case "$arg" in
    --no-build) DO_BUILD=0 ;;
    --reboot)   DO_REBOOT=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "!! unknown arg: $arg (expected --no-build and/or --reboot)" >&2
      exit 1
      ;;
  esac
done

adb_bin() {
  if command -v adb.exe >/dev/null 2>&1; then
    command -v adb.exe
  else
    command -v adb
  fi
}
ADB="$(adb_bin)"
[ -n "$ADB" ] || { echo "!! adb not on PATH" >&2; exit 1; }

resolve_serial() {
  if [ -n "${ANDROID_SERIAL:-}" ]; then echo "$ANDROID_SERIAL"; return 0; fi
  if [ -n "${ADH_SERIAL:-}" ]; then echo "$ADH_SERIAL"; return 0; fi
  local list
  list="$("$ADB" devices | awk 'NR>1 && $2=="device" { print $1 }')"
  local n
  n="$(printf '%s\n' "$list" | awk 'NF{c++} END{print c+0}')"
  if [ "$n" -eq 0 ]; then
    echo "!! no adb device in 'device' state" >&2
    exit 1
  fi
  if [ "$n" -gt 1 ]; then
    echo "!! multiple devices; set ANDROID_SERIAL to one of:" >&2
    printf '%s\n' "$list" >&2
    exit 1
  fi
  printf '%s\n' "$list"
}

win_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

SERIAL="$(resolve_serial)"
export ANDROID_SERIAL="$SERIAL"
echo ">> device: $SERIAL"

device_root() {
  # su -c '<cmd>' — cmd must not contain single quotes. Strip CR from adb.
  "$ADB" -s "$SERIAL" shell "su -c '$1'" | tr -d '\r'
}

if ! "$ADB" -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "!! device $SERIAL is not reachable" >&2
  exit 1
fi
uid="$(device_root 'id -u' | tail -n 1)"
if [ "$uid" != "0" ]; then
  echo "!! su is not root on $SERIAL (got uid='$uid')" >&2
  exit 1
fi

if [ "$DO_BUILD" = 1 ]; then
  echo ">> building combined bundle"
  bash "$ROOT/tools/build_bundle.sh"
else
  echo ">> skipping build (--no-build)"
fi

VERSION="$(awk -F= '$1 == "version" { print $2 }' "$ROOT/injector/zygisk/module/module.prop" | tr -d '\r')"
BUNDLE="$ROOT/injector/zygisk/dist/adh-bundle-$VERSION.zip"
MANAGER_APK="$ROOT/device/manager/build/outputs/apk/debug/manager-debug.apk"
[ -f "$BUNDLE" ] || { echo "!! bundle missing: $BUNDLE (run without --no-build)" >&2; exit 1; }
[ -f "$MANAGER_APK" ] || { echo "!! Manager APK missing: $MANAGER_APK" >&2; exit 1; }
echo ">> bundle: $BUNDLE ($(wc -c <"$BUNDLE" | tr -d ' ') bytes)"

REMOTE_ZIP="/data/local/tmp/adh-bundle.zip"
echo ">> push $REMOTE_ZIP"
"$ADB" -s "$SERIAL" push "$(win_path "$BUNDLE")" "$REMOTE_ZIP" >/dev/null

KSUD=""
for cand in /data/adb/ksud /data/adb/ksu/bin/ksud; do
  if [ "$(device_root "test -x $cand && echo YES || echo NO" | tail -n 1)" = "YES" ]; then
    KSUD="$cand"
    break
  fi
done
MAGISK_OK="$(device_root 'command -v magisk >/dev/null && echo YES || echo NO' | tail -n 1)"

echo ">> installing module $VERSION"
if [ -n "$KSUD" ]; then
  echo ">> installer: KernelSU ($KSUD)"
  device_root "$KSUD module install $REMOTE_ZIP"
elif [ "$MAGISK_OK" = "YES" ]; then
  echo ">> installer: Magisk"
  device_root "magisk --install-module $REMOTE_ZIP"
else
  echo "!! neither KernelSU (ksud) nor Magisk found on $SERIAL" >&2
  exit 1
fi
device_root "rm -f $REMOTE_ZIP" >/dev/null || true

echo ">> installing Manager APK via root pm (skip ColorOS USB confirm)"
install_apk_root "$MANAGER_APK" /data/local/tmp/adh-manager.apk "$SERIAL"

mod_now="$(device_root 'test -d /data/adb/modules/adh && echo YES || echo NO' | tail -n 1)"
mod_upd="$(device_root 'test -d /data/adb/modules_update/adh && echo YES || echo NO' | tail -n 1)"
echo ">> modules/adh=$mod_now  modules_update/adh=$mod_upd"

if [ "$mod_now" != "YES" ] && [ "$mod_upd" != "YES" ]; then
  echo "!! module directory missing after install" >&2
  exit 1
fi

if [ "$DO_REBOOT" = 1 ]; then
  echo ">> rebooting $SERIAL so Zygisk + Device Daemon load"
  "$ADB" -s "$SERIAL" reboot
  echo ">> waiting for boot"
  "$ADB" -s "$SERIAL" wait-for-device
  # ColorOS can take a while after adb is up before boot_completed flips.
  for _ in $(seq 1 90); do
    boot="$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    if [ "$boot" = "1" ]; then
      break
    fi
    sleep 2
  done
  if [ "${boot:-}" != "1" ]; then
    echo "!! device came back but sys.boot_completed != 1" >&2
    exit 1
  fi
  # su / zygote settle
  sleep 8
  echo ">> post-boot check"
  for _ in $(seq 1 30); do
    if [ "$(device_root 'id -u' | tail -n 1)" = "0" ]; then
      break
    fi
    sleep 2
  done
  device_root 'cat /data/adb/modules/adh/module.prop' || true
  echo ">> zygisk_loaded=$(device_root 'test -f /data/adb/adh/zygisk_loaded && echo YES || echo NO' | tail -n 1)"
  echo ">> device_daemon_ready=$(device_root 'test -f /data/adb/adh/device_daemon_ready && echo YES || echo NO' | tail -n 1)"
  echo ">> manager=$("$ADB" -s "$SERIAL" shell pm path com.adh.manager 2>/dev/null | tr -d '\r')"
else
  echo ">> not rebooting. Zygisk companion + Device Daemon need a reboot to load."
  echo ">> re-run: bash tools/flash_device.sh --no-build --reboot"
fi

echo ">> flash done ($VERSION) on $SERIAL"
echo ">> next: open ADH Manager, pick allowlist packages, cold-start those apps"
