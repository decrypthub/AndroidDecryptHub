#!/system/bin/sh
# Magisk module action: open the standalone AndroidDecryptHub app bundled with this module.
MODDIR="${0%/*}"
PACKAGE="com.adh.manager"
ACTIVITY="com.adh.manager/.MainActivity"

if ! /system/bin/pm path "$PACKAGE" >/dev/null 2>&1; then
  if [ ! -f "$MODDIR/manager.apk" ]; then
    echo "AndroidDecryptHub is not installed and manager.apk is not bundled"
    exit 1
  fi
  echo "Installing bundled AndroidDecryptHub..."
  /system/bin/pm install -r "$MODDIR/manager.apk" || exit 1
fi

echo "Opening AndroidDecryptHub..."
exec /system/bin/am start -n "$ACTIVITY"
