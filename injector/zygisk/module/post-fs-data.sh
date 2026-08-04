#!/system/bin/sh
MODDIR="${0%/*}"
STATE_DIR="/data/adb/adh"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/zygisk_loaded" \
  "$STATE_DIR/device_daemon_ready" \
  "$STATE_DIR/device_daemon.pid"
sed -i 's/^description=.*/description=状态：等待 Zygisk 加载/' "$MODDIR/module.prop"
