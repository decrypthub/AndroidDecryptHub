#!/system/bin/sh
# Magisk module action: open the standalone ADH Manager bundled with this module.
MODDIR="${0%/*}"
PACKAGE="com.adh.manager"
ACTIVITY="com.adh.manager/.MainActivity"

if ! /system/bin/pm path "$PACKAGE" >/dev/null 2>&1; then
  if [ ! -f "$MODDIR/manager.apk" ]; then
    echo "ADH Manager is not installed and manager.apk is not bundled"
    exit 1
  fi
  echo "Installing bundled ADH Manager..."
  /system/bin/pm install -r "$MODDIR/manager.apk" || exit 1
fi

echo "Opening ADH Manager..."
exec /system/bin/am start -n "$ACTIVITY"
