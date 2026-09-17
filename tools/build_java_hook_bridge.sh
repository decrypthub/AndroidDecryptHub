#!/usr/bin/env bash
# Regenerate the fixed AdhJavaHookBridge DEX and its C array header.
#
# The generated artifacts are committed because agent builds should not require a JDK or
# Android build-tools. Run this only when the Java bridge source changes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/agent/java/com/adh/agent/AdhJavaHookBridge.java"
TMP="$ROOT/agent/build/java_hook_bridge_tmp"
DEXOUT="$ROOT/agent/src/hook/adh_java_hook_bridge.dex"
HDR="$ROOT/agent/src/hook/adh_java_hook_bridge_dex.h"
SDK="${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}"

case "$TMP" in
  "$ROOT"/agent/build/java_hook_bridge_tmp) ;;
  *) echo "!! refusing unsafe temp path: $TMP" >&2; exit 1 ;;
esac

JAVAC="${JAVAC:-}"
if [ -z "$JAVAC" ] && [ -x "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/jdk/bin/javac.exe" ]; then
  JAVAC="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/jdk/bin/javac.exe"
fi
if [ -z "$JAVAC" ]; then JAVAC="$(command -v javac || true)"; fi
if [ -z "$JAVAC" ] && [ -x "/c/Program Files/Android/Android Studio/jbr/bin/javac.exe" ]; then
  JAVAC="/c/Program Files/Android/Android Studio/jbr/bin/javac.exe"
fi
[ -n "$JAVAC" ] && [ -x "$JAVAC" ] || { echo "!! javac not found; set JAVAC"; exit 1; }

D8="$(find "$SDK/build-tools" -maxdepth 2 -type f \( -name d8 -o -name d8.bat \) 2>/dev/null | sort -V | tail -1)"
[ -n "$D8" ] && [ -f "$D8" ] || { echo "!! d8 not found under $SDK/build-tools"; exit 1; }

rm -rf "$TMP"
mkdir -p "$TMP"
"$JAVAC" -source 8 -target 8 -Xlint:-options -d "$TMP" "$SRC"
"$D8" --min-api 26 --output "$TMP" "$TMP/com/adh/agent/AdhJavaHookBridge.class"
[ -f "$TMP/classes.dex" ] || { echo "!! d8 did not produce classes.dex"; exit 1; }
cp "$TMP/classes.dex" "$DEXOUT"

node - "$DEXOUT" "$HDR" <<'EOF'
const fs = require('fs');
const [dexPath, headerPath] = process.argv.slice(2);
const bytes = fs.readFileSync(dexPath);
let out = '// Generated from agent/java/com/adh/agent/AdhJavaHookBridge.java via d8 --min-api 26.\n';
out += '// Keep this class target-agnostic: it only stores the LSPlant backup and callback state.\n';
out += '#ifndef ADH_AGENT_JAVA_HOOK_BRIDGE_DEX_H\n#define ADH_AGENT_JAVA_HOOK_BRIDGE_DEX_H\n';
out += '#include <stddef.h>\nstatic const unsigned char ADH_JAVA_HOOK_BRIDGE_DEX[] = {\n';
for (let i = 0; i < bytes.length; i += 16) {
  const row = Array.from(bytes.subarray(i, Math.min(i + 16, bytes.length)))
    .map((b) => `0x${b.toString(16).padStart(2, '0')},`).join(' ');
  out += `    ${row}\n`;
}
out += '};\nstatic const size_t ADH_JAVA_HOOK_BRIDGE_DEX_SIZE = sizeof(ADH_JAVA_HOOK_BRIDGE_DEX);\n#endif\n';
fs.writeFileSync(headerPath, out);
EOF

echo ">> wrote $DEXOUT ($(wc -c < "$DEXOUT" | tr -d ' ') bytes)"
echo ">> wrote $HDR ($(wc -c < "$HDR" | tr -d ' ') bytes)"