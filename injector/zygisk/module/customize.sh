#!/system/bin/sh
# Magisk module install script (minimal).
SKIPUNZIP=1
ui_print "- Installing ADH Zygisk module"
unzip -o "$ZIPFILE" 'module.prop' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'zygisk/*' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'libidh_agent.so' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'customize.sh' -d "$TMPDIR" >&2
set_perm_recursive "$MODPATH" 0 0 0755 0644
# Ensure /data/adb/adh exists for Manager scope file
mkdir -p /data/adb/adh
[ -f /data/adb/adh/scope.json ] || printf '%s\n' '{"version":1,"mode":"allowlist","packages":[]}' > /data/adb/adh/scope.json
ui_print "- Done. Install ADH Manager, pick apps, reboot targets."
