#!/usr/bin/env bash
# Fetch the Dobby arm64 static library — the agent's native inline-hook backend (module B/WS-A).
#
# Dobby patches a function's entry (by address) so targets that never go through a GOT slot can
# still be hooked; it links statically into libadh_agent.so (no extra .so, no JNI_OnLoad).
# Verified by tools/verify_v28_inlinehook.sh. Idempotent, gitignored under agent/third_party/dobby/.
#
# Usage: tools/fetch_dobby.sh [--force]
# Env:   DOBBY_VERSION (default 1.2)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
TP="${ADH_DOBBY_DIR:-$ROOT/agent/third_party}/dobby"
VER="${DOBBY_VERSION:-1.2}"
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "!! unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$FORCE" -ne 1 ] && [ -f "$TP/lib/arm64-v8a/libdobby.a" ] && [ -f "$TP/include/dobby.h" ]; then
  echo ">> Dobby prebuilt already present ($TP)"
  echo ">> done. Dobby $VER"
  exit 0
fi

# Static libdobby.a + dobby.h shipped inside the io.github.vvb2060.ndk:dobby AAR (Maven Central).
AAR_URL="https://repo1.maven.org/maven2/io/github/vvb2060/ndk/dobby/$VER/dobby-$VER.aar"
echo ">> downloading Dobby $VER AAR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sL --max-time 180 -o "$tmp/dobby.aar" "$AAR_URL" || { echo "!! Dobby AAR download failed"; exit 1; }
[ "$(wc -c < "$tmp/dobby.aar")" -gt 100000 ] || { echo "!! Dobby AAR too small — download failed?"; exit 1; }
unzip -oq "$tmp/dobby.aar" -d "$tmp/d"
A="$(find "$tmp/d" -name libdobby.a -path '*arm64-v8a*' | head -1)"
HDR="$(find "$tmp/d" -name 'dobby.h' | head -1)"
[ -n "$A" ] && [ -n "$HDR" ] || { echo "!! could not locate libdobby.a / dobby.h in the AAR"; exit 1; }
rm -rf "$TP"
mkdir -p "$TP/lib/arm64-v8a" "$TP/include"
cp "$A" "$TP/lib/arm64-v8a/libdobby.a"
cp "$HDR" "$TP/include/dobby.h"
echo ">> extracted libdobby.a ($(wc -c < "$TP/lib/arm64-v8a/libdobby.a" | tr -d ' ') bytes) + dobby.h"
echo ">> done. Dobby $VER"