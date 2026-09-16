#!/usr/bin/env bash
# Build ADH Zygisk companion .so + Magisk module zip (adh-zygisk.zip).
# Depends on libadh_agent.so (runs build_agent.sh if missing).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

ZY="$ROOT/injector/zygisk"
JNI="$ZY/jni"
MOD="$ZY/module"
DIST="$ZY/dist"
AGENT_SO="$ROOT/agent/build/libadh_agent.so"
MANAGER_APK="$ROOT/device/manager/build/outputs/apk/debug/manager-debug.apk"
DAEMON_APK="$ROOT/device/daemon/build/outputs/apk/debug/daemon-debug.apk"

[ -f "$AGENT_SO" ] || {
  echo ">> libadh_agent.so missing — building agent first"
  bash "$ROOT/tools/build_agent.sh"
}
[ -f "$AGENT_SO" ] || { echo "!! agent .so still missing"; exit 1; }

echo ">> building ADH Manager for daemon caller authentication"
(
  cd "$ROOT/device"
  ./gradlew :manager:assembleDebug --console=plain
)
[ -f "$MANAGER_APK" ] || { echo "!! Manager APK missing: $MANAGER_APK"; exit 1; }

APKSIGNER="$(find "$SDK/build-tools" -type f \( -name apksigner -o -name apksigner.bat \) 2>/dev/null | sort -V | tail -n 1)"
[ -n "$APKSIGNER" ] && [ -f "$APKSIGNER" ] || { echo "!! apksigner not found under $SDK/build-tools"; exit 1; }
MANAGER_CERT_SHA256="$("$APKSIGNER" verify --print-certs "$MANAGER_APK" \
  | awk -F': ' '/certificate SHA-256 digest/ { print $NF; exit }' \
  | tr -d '\r[:space:]')"
if [[ ! "$MANAGER_CERT_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "!! invalid Manager signing certificate digest: $MANAGER_CERT_SHA256"
  exit 1
fi
echo ">> building Root Device Daemon (Manager signer $MANAGER_CERT_SHA256)"
(
  cd "$ROOT/device"
  ./gradlew :daemon:assembleDebug \
    -PadhManagerCertSha256="$MANAGER_CERT_SHA256" \
    --console=plain
)
[ -f "$DAEMON_APK" ] || { echo "!! Device Daemon APK missing: $DAEMON_APK"; exit 1; }

NDK_BUILD="$NDK/ndk-build.cmd"
[ -f "$NDK_BUILD" ] || NDK_BUILD="$NDK/ndk-build"
[ -f "$NDK_BUILD" ] || [ -x "$NDK_BUILD" ] || { echo "missing ndk-build at $NDK"; exit 1; }

echo ">> ndk-build Zygisk companion ($ABI)"
# NDK_PROJECT_PATH must contain jni/; OUT goes under injector/zygisk/obj+libs
rm -rf "$ZY/libs" "$ZY/obj"
"$NDK_BUILD" -C "$ZY" NDK_PROJECT_PATH="$ZY" APP_BUILD_SCRIPT="$JNI/Android.mk" \
  NDK_APPLICATION_MK="$JNI/Application.mk" -j"$(nproc 2>/dev/null || echo 4)"

COMPANION="$ZY/libs/$ABI/libadh.so"
[ -f "$COMPANION" ] || { echo "!! companion missing: $COMPANION"; exit 1; }
if ! "$READELF" --dyn-syms --wide "$COMPANION" | awk '$NF == "zygisk_module_entry" { found=1 } END { exit !found }'; then
  echo "!! companion does not export the required C symbol: zygisk_module_entry"
  exit 1
fi
echo ">> verified export: zygisk_module_entry"
if ! "$READELF" --dyn-syms --wide "$COMPANION" | awk '$NF == "zygisk_companion_entry" { found=1 } END { exit !found }'; then
  echo "!! companion does not export the required C symbol: zygisk_companion_entry"
  exit 1
fi
echo ">> verified export: zygisk_companion_entry"

STAGE="$ZY/.stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/zygisk" "$STAGE/META-INF/com/google/android"
cp "$MOD/module.prop" "$STAGE/"
cp "$MOD/customize.sh" "$STAGE/"
cp "$MOD/action.sh" "$STAGE/"
cp "$MOD/post-fs-data.sh" "$STAGE/"
cp "$MOD/sepolicy.rule" "$STAGE/"
cp "$MOD/service.sh" "$STAGE/"
cp "$MOD/device-daemon" "$STAGE/"
cp "$MOD/META-INF/com/google/android/update-binary" "$STAGE/META-INF/com/google/android/"
cp "$MOD/META-INF/com/google/android/updater-script" "$STAGE/META-INF/com/google/android/"
cp "$COMPANION" "$STAGE/zygisk/$ABI.so"
cp "$AGENT_SO" "$STAGE/libadh_agent.so"
cp "$DAEMON_APK" "$STAGE/daemon.apk"

mkdir -p "$DIST"
ZIP="$DIST/adh-zygisk.zip"
rm -f "$ZIP"
(
  cd "$STAGE"
  if command -v zip >/dev/null 2>&1; then
    zip -r9 "$ZIP" . >/dev/null
  elif command -v node >/dev/null 2>&1; then
    node - "$ZIP" <<'NODE'
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const out = process.argv[2];
// Minimal store+deflate ZIP writer (no deps).
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function walk(dir, base = '') {
  const entries = [];
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    if (fs.statSync(p).isDirectory()) entries.push(...walk(p, rel));
    else entries.push({ rel: rel.replace(/\\/g, '/'), data: fs.readFileSync(p) });
  }
  return entries;
}
const files = walk('.');
const parts = [];
const central = [];
let offset = 0;
for (const f of files) {
  const name = Buffer.from(f.rel);
  const raw = f.data;
  const deflated = zlib.deflateRawSync(raw);
  const useDeflate = deflated.length < raw.length;
  const payload = useDeflate ? deflated : raw;
  const method = useDeflate ? 8 : 0;
  const crc = crc32(raw);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(method, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(payload.length, 18);
  local.writeUInt32LE(raw.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  const localOff = offset;
  parts.push(local, name, payload);
  offset += local.length + name.length + payload.length;
  const cen = Buffer.alloc(46);
  cen.writeUInt32LE(0x02014b50, 0);
  cen.writeUInt16LE(20, 4);
  cen.writeUInt16LE(20, 6);
  cen.writeUInt16LE(0, 8);
  cen.writeUInt16LE(method, 10);
  cen.writeUInt16LE(0, 12);
  cen.writeUInt16LE(0, 14);
  cen.writeUInt32LE(crc, 16);
  cen.writeUInt32LE(payload.length, 20);
  cen.writeUInt32LE(raw.length, 24);
  cen.writeUInt16LE(name.length, 28);
  cen.writeUInt16LE(0, 30);
  cen.writeUInt16LE(0, 32);
  cen.writeUInt16LE(0, 34);
  cen.writeUInt16LE(0, 36);
  cen.writeUInt32LE(0, 38);
  cen.writeUInt32LE(localOff, 42);
  central.push(cen, name);
}
const centralBuf = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(0, 4);
end.writeUInt16LE(0, 6);
end.writeUInt16LE(files.length, 8);
end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(centralBuf.length, 12);
end.writeUInt32LE(offset, 16);
end.writeUInt16LE(0, 20);
fs.writeFileSync(out, Buffer.concat([...parts, centralBuf, end]));
console.log('wrote', out, fs.statSync(out).size);
NODE
  else
    echo "!! need zip or node to pack Magisk module"; exit 1
  fi
)
[ -f "$ZIP" ] || { echo "!! zip failed"; exit 1; }
echo ">> Magisk module: $ZIP ($(wc -c <"$ZIP" | tr -d ' ') bytes)"
echo "   flash via Magisk → Modules → Install from storage"
echo "   scope file on device: /data/adb/adh/scope.json (Root Device Daemon writes it)"
