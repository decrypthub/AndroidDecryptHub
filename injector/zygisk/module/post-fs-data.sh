#!/system/bin/sh
MODDIR="${0%/*}"
STATE_DIR="/data/adb/adh"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/zygisk_loaded" \
  "$STATE_DIR/device_daemon_ready" \
  "$STATE_DIR/device_daemon.pid"
sed -i 's/^description=.*/description=状态：等待 Zygisk 加载/' "$MODDIR/module.prop"

# KernelSU does not consistently apply module sepolicy.rule before zygote here;
# apply the two minimal scope-read rules explicitly (Magisk still uses sepolicy.rule).
KSUD=""
for cand in /data/adb/ksud /data/adb/ksu/bin/ksud; do
  if [ -x "$cand" ]; then KSUD="$cand"; break; fi
done
if [ -n "$KSUD" ]; then
  "$KSUD" sepolicy patch 'allow zygote adb_data_file dir search' >/dev/null 2>&1 || true
  "$KSUD" sepolicy patch 'allow zygote adb_data_file file { open read getattr }' >/dev/null 2>&1 || true
fi
