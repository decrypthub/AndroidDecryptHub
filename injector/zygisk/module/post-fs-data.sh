#!/system/bin/sh
MODDIR="${0%/*}"
STATE_DIR="/data/adb/adh"
# Keep in sync with AdhPaths.CACERTS_DIR.
USER_CA_DIR="$STATE_DIR/cacerts"
CA_LOG="$STATE_DIR/cacert-inject.log"

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

# User CAs are copied into a tmpfs and bind-mounted over the trust store in init's
# namespace before zygote starts. No imported certificate means no mount at all.
ca_log() {
  echo "$*" >>"$CA_LOG"
}

ca_context() {
  [ "$(getenforce)" = "Enforcing" ] || return 0
  ctx=$(ls -Zd "$1" 2>/dev/null | awk '{print $1}')
  if [ -n "$ctx" ] && [ "$ctx" != "?" ]; then
    chcon -R "$ctx" "$2" || ca_log "chcon failed $2"
  else
    chcon -R u:object_r:system_file:s0 "$2" || ca_log "chcon fallback failed $2"
  fi
}

ca_bind() {
  src="$1"
  dest="$2"
  mount --bind "$src" "$dest" || ca_log "bind failed $dest"
  pids="1"
  for name in zygote zygote64; do
    pids="$pids $(pgrep -x "$name" 2>/dev/null)"
  done
  for pid in $pids; do
    [ -r "/proc/$pid/ns/mnt" ] || continue
    nsenter --mount="/proc/$pid/ns/mnt" -- mount --bind "$src" "$dest" \
      || ca_log "nsenter $pid failed $dest"
  done
}

ca_cleanup() {
  stage="$1"
  pids="1"
  for name in zygote zygote64; do
    pids="$pids $(pgrep -x "$name" 2>/dev/null)"
  done
  for pid in $pids; do
    [ -r "/proc/$pid/ns/mnt" ] || continue
    nsenter --mount="/proc/$pid/ns/mnt" -- umount "$stage" >/dev/null 2>&1 || true
  done
  umount "$stage" >/dev/null 2>&1 || true
  rmdir "$stage" >/dev/null 2>&1 || true
}

ca_merge() {
  target="$1"
  stage="$2"
  [ -d "$target" ] || return 0
  umount "$stage" >/dev/null 2>&1 || true
  rmdir "$stage" >/dev/null 2>&1 || true
  mkdir -p "$stage" || return 0
  if ! mount -t tmpfs tmpfs "$stage"; then
    ca_log "tmpfs failed $stage"
    rmdir "$stage" >/dev/null 2>&1 || true
    return 0
  fi
  cp -f "$target"/* "$stage"/ 2>/dev/null || true
  for cert in $USER_CA_FILES; do
    cp -f "$cert" "$stage"/ || ca_log "copy failed $cert"
  done
  chown -R 0:0 "$stage" || true
  chmod 755 "$stage" || true
  chmod 644 "$stage"/* >/dev/null 2>&1 || true
  ca_context "$target" "$stage"
  count=$(ls -1 "$stage" | wc -l)
  if [ "$count" -le 10 ]; then
    ca_log "refuse $target count=$count"
    umount "$stage" >/dev/null 2>&1 || true
    rmdir "$stage" >/dev/null 2>&1 || true
    return 0
  fi
  ca_bind "$stage" "$target"
  if [ "$target" = "/apex/com.android.conscrypt/cacerts" ]; then
    for apex in /apex/com.android.conscrypt@*; do
      [ -d "$apex/cacerts" ] || continue
      ca_bind "$stage" "$apex/cacerts"
    done
  fi
  ca_cleanup "$stage"
  ca_log "mounted $target ($count)"
}

: >"$CA_LOG"
USER_CA_FILES=""
if [ -d "$USER_CA_DIR" ]; then
  for cert in "$USER_CA_DIR"/*; do
    [ -f "$cert" ] || continue
    base=$(basename "$cert")
    case "$base" in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].[0-9]|[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].[0-9][0-9])
        USER_CA_FILES="$USER_CA_FILES $cert"
        ;;
    esac
  done
fi
if [ -n "$USER_CA_FILES" ]; then
  ca_log "inject$USER_CA_FILES"
  ca_merge /apex/com.android.conscrypt/cacerts /data/local/tmp/adh-ca-apex
  ca_merge /system/etc/security/cacerts /data/local/tmp/adh-ca-system
else
  ca_log "no user certificates"
fi
