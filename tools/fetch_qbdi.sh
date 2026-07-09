#!/usr/bin/env bash
# Fetch the QBDI arm64-Android prebuilt (for instruction-level trace, module I.3).
# Downloads headers + libQBDI.so into agent/third_party/qbdi and stages the .so into
# the sandbox jniLibs so the app can dlopen it. Idempotent. (third_party is gitignored.)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="${QBDI_VERSION:-0.12.1}"
TAR="QBDI-$VER-android-AARCH64.tar.gz"
URL="https://github.com/QBDI/QBDI/releases/download/v$VER/$TAR"
DEST="$ROOT/agent/third_party/qbdi"
JNILIBS="$ROOT/sandbox-app/app/src/main/jniLibs/arm64-v8a"

if [ -f "$DEST/lib/libQBDI.so" ] && [ -d "$DEST/include/QBDI" ]; then
  echo ">> QBDI already present ($DEST)"
else
  echo ">> downloading $TAR"
  tmp="$(mktemp -d)"
  curl -sL --max-time 180 -o "$tmp/$TAR" "$URL"
  [ "$(wc -c < "$tmp/$TAR")" -gt 1000000 ] || { echo "!! download failed / too small"; exit 1; }
  tar xzf "$tmp/$TAR" -C "$tmp"
  rm -rf "$DEST"; mkdir -p "$DEST"
  cp -r "$tmp/usr/local/include" "$DEST/include"
  cp -r "$tmp/usr/local/lib" "$DEST/lib"
  rm -rf "$tmp"
  echo ">> extracted headers + libQBDI.so ($(wc -c < "$DEST/lib/libQBDI.so") bytes)"
fi
mkdir -p "$JNILIBS"
cp "$DEST/lib/libQBDI.so" "$JNILIBS/libQBDI.so"
echo ">> staged libQBDI.so into sandbox jniLibs"
