#!/system/bin/sh
# Magisk module install script (minimal).
SKIPUNZIP=1
ui_print "- Installing ADH Zygisk module"
unzip -o "$ZIPFILE" 'module.prop' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'zygisk/*' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'libadh_agent.so' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'daemon.apk' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'device-daemon' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'action.sh' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'post-fs-data.sh' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'sepolicy.rule' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'service.sh' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'customize.sh' -d "$TMPDIR" >&2
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/device-daemon" 0 0 0755
set_perm "$MODPATH/daemon.apk" 0 0 0644

# The optional combined bundle carries the Manager APK at the ZIP root. A
# normal adh-zygisk.zip does not, so its installation behavior stays unchanged.
MANAGER_BUNDLED=0
if unzip -l "$ZIPFILE" 'manager.apk' >/dev/null 2>&1; then
  MANAGER_BUNDLED=1
  unzip -o "$ZIPFILE" 'manager.apk' 'manager.apk.sha256' -d "$MODPATH" >&2
  set_perm "$MODPATH/manager.apk" 0 0 0644
  set_perm "$MODPATH/manager.apk.sha256" 0 0 0644
  if ! (cd "$MODPATH" && sha256sum -c -s manager.apk.sha256); then
    abort "! Bundled AndroidDecryptHub checksum verification failed"
  fi
  ui_print "- Verified AndroidDecryptHub APK"
  if [ "$BOOTMODE" = true ] && [ -x /system/bin/pm ]; then
    if /system/bin/pm install -r "$MODPATH/manager.apk" >/dev/null 2>&1; then
      ui_print "- AndroidDecryptHub installed"
    else
      ui_print "! AndroidDecryptHub APK install failed"
      ui_print "! Use the module Action button to retry or install manager.apk manually"
    fi
  else
    ui_print "! Manager auto-install requires installation from the running Magisk app"
    ui_print "! Use the Magisk module Action button after boot"
  fi
fi

# Ensure /data/adb/adh exists for Manager scope file
mkdir -p /data/adb/adh
[ -f /data/adb/adh/scope.json ] || printf '%s\n' '{"version":1,"mode":"allowlist","packages":[]}' > /data/adb/adh/scope.json
if [ "$MANAGER_BUNDLED" = 1 ]; then
  ui_print "- Done. Open AndroidDecryptHub, pick apps, then reboot targets."
else
  ui_print "- Done. Install AndroidDecryptHub, pick apps, then reboot targets."
fi
