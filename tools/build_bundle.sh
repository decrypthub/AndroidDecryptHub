#!/usr/bin/env bash
# Build one Magisk-installable bundle containing the Zygisk module and Manager APK.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

ZY="$ROOT/injector/zygisk"
DIST="$ZY/dist"
MODULE_ZIP="$DIST/adh-zygisk.zip"
APK="$ROOT/device/manager/build/outputs/apk/debug/manager-debug.apk"
VERSION="$(awk -F= '$1 == "version" { print $2 }' "$ZY/module/module.prop" | tr -d '\r')"
[ -n "$VERSION" ] || { echo "!! module version is missing" >&2; exit 1; }

echo ">> building Zygisk module"
bash "$ROOT/tools/build_zygisk.sh"

[ -f "$MODULE_ZIP" ] || { echo "!! Zygisk module missing: $MODULE_ZIP" >&2; exit 1; }
[ -f "$APK" ] || { echo "!! Manager APK missing: $APK" >&2; exit 1; }

STAGE="$ZY/.bundle-stage.$$"
BUNDLE="$DIST/adh-bundle-$VERSION.zip"
rm -rf "$STAGE"
mkdir -p "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
cp -R "$ZY/.stage/." "$STAGE/"
cp "$APK" "$STAGE/manager.apk"
(cd "$STAGE" && sha256sum manager.apk > manager.apk.sha256)
cat > "$STAGE/INSTALL.txt" <<'EOF'
ADH combined Magisk installer

1. Install this ZIP from Magisk -> Modules -> Install from storage.
2. The installer attempts to install the bundled ADH Manager APK automatically.
3. Reboot so Zygisk loads the module.
4. Open ADH Manager and configure the target package allowlist.

If Manager auto-install fails, use the module Action button in Magisk. You can
also extract manager.apk from this ZIP and run:
  adb -s <serial> install -r manager.apk
EOF

rm -f "$BUNDLE"
if command -v zip >/dev/null 2>&1; then
  (cd "$STAGE" && zip -r9 "$BUNDLE" . >/dev/null)
elif command -v node >/dev/null 2>&1; then
  (cd "$STAGE" && node "$ROOT/tools/lib/pack_zip.mjs" "$BUNDLE" .)
else
  echo "!! need zip or node to pack the bundle" >&2
  exit 1
fi
rm -rf "$STAGE"
trap - EXIT
echo ">> combined bundle: $BUNDLE ($(wc -c <"$BUNDLE" | tr -d ' ') bytes)"
