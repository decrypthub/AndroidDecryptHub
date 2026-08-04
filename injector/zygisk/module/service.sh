#!/system/bin/sh
MODDIR="${0%/*}"
MARKER="/data/adb/adh/zygisk_loaded"
DAEMON_READY="/data/adb/adh/device_daemon_ready"
DAEMON_PID="/data/adb/adh/device_daemon.pid"
DAEMON_LOG="/data/adb/adh/device_daemon.log"

mkdir -p /data/adb/adh
rm -f "$DAEMON_READY" "$DAEMON_PID"
if [ -r "$MODDIR/daemon.apk" ] && [ -x "$MODDIR/device-daemon" ]; then
  unshare --propagation slave -m "$MODDIR/device-daemon" >>"$DAEMON_LOG" 2>&1 &
else
  echo "ADH Device Daemon payload missing" >>"$DAEMON_LOG"
fi

count=0
while [ "$count" -lt 30 ] && [ ! -f "$MARKER" ]; do
  sleep 1
  count=$((count + 1))
done

if [ -f "$MARKER" ]; then
  status='状态：运行中'
else
  status='状态：未加载，请检查 Zygisk'
fi
sed -i "s/^description=.*/description=$status/" "$MODDIR/module.prop"
