#!/usr/bin/env bash
# Load Frida Gadget into an ADH-injected target process and run a hook script.
#
# Gadget is an OPTIONAL, high-footprint backend: the official arm64 build is ~25 MB and
# shows up as /data/data/<pkg>/code_cache/libgadget.so in the target's maps. It is never
# loaded by default — you opt in by invoking this script.
#
# Usage:
#   tools/load_frida_gadget.sh <hook.js> [--version V] [--abi arm64] [--package PKG]
#                                         [--raw] [--watch] [--wait SEC]
#                                         [--marker DEVICE_PATH]
#   tools/load_frida_gadget.sh <gadget.so> <hook.js> [package]    # legacy explicit path
#
# Chain (each link verified on a real device — tools/verify_v30_fridagadget.sh):
#   1. official Gadget, sha256-pinned per version/ABI (tools/fetch_frida_gadget.sh)
#   2. hook bundled with the language bridges when needed (tools/compile_frida_script.sh):
#      Frida 17+ no longer ships Java/ObjC bridges inside the runtime
#   3. Gadget + <soname>.config.so + hook staged into <pkg>/code_cache under the app's
#      own uid/selinux context (the config file MUST sit next to the Gadget)
#   4. POST /api/agent/load_so → dlopen inside the target. The Gadget constructor starts
#      the script by itself: there is NO entry symbol to call, and `symbolFound` is
#      informational only (frida-gadget exports no frida_agent_main).
#   5. wait for the Gadget runtime threads in /proc/<pid>/task, then optionally assert a
#      marker file the hook is expected to create
#
# Env:
#   ADH_FRIDA_VERSION   default version (latest)
#   ADH_FRIDA_ABI       default ABI (arm64)
#   ADH_FRIDA_DIR       cache root used by fetch_frida_gadget.sh
#   FRIDA_GADGET        explicit gadget .so path (skips the download)
#   ADH_HTTP_PORT       Host ADH Daemon port (default 8088)
#   ANDROID_SERIAL      target device serial
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
# Keep /data/... device paths intact when running under Git Bash.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

HTTP="${ADH_HTTP_PORT:-8088}"
SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-}}"
if [ -z "$SERIAL" ]; then
  SERIAL="$(adb devices 2>/dev/null | awk 'NR==2 && $2=="device" {print $1; exit}')"
fi
[ -n "$SERIAL" ] || { echo "!! no adb device; set ANDROID_SERIAL" >&2; exit 1; }

GADGET=""; SCRIPT=""; PKG="com.adh.sandbox"
VERSION="${ADH_FRIDA_VERSION:-latest}"
ABI="${ADH_FRIDA_ABI:-arm64}"
RAW=0; WATCH=0; WAIT=10; MARKER=""

usage() { sed -n '2,29p' "$0"; }
die() { echo "!! $*" >&2; exit 1; }

[ $# -ge 1 ] || { usage >&2; exit 1; }
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

if [ "${1##*.}" = "so" ] && [ $# -ge 2 ]; then
  GADGET="$1"; SCRIPT="$2"; PKG="${3:-com.adh.sandbox}"
else
  SCRIPT="$1"; shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
      --abi) ABI="${2:?--abi needs a value}"; shift 2 ;;
      --package) PKG="${2:?--package needs a value}"; shift 2 ;;
      --raw) RAW=1; shift ;;
      --watch) WATCH=1; shift ;;
      --wait) WAIT="${2:?--wait needs a value}"; shift 2 ;;
      --marker) MARKER="${2:?--marker needs a value}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
fi
[ -f "$SCRIPT" ] || die "hook script not found: $SCRIPT"

# ---- 1. gadget -----------------------------------------------------------------
if [ -z "$GADGET" ]; then
  if [ -n "${FRIDA_GADGET:-}" ]; then
    GADGET="$FRIDA_GADGET"
  else
    GADGET="$(bash "$ROOT/tools/fetch_frida_gadget.sh" "$VERSION" "$ABI")" ||
      die "gadget fetch failed (version=$VERSION abi=$ABI)"
  fi
fi
[ -f "$GADGET" ] || die "gadget missing: $GADGET"

# ---- 2. bundle the hook when it needs a language bridge -------------------------
if [ "$RAW" != "1" ] && ! grep -q 'adh-frida-bundle' "$SCRIPT"; then
  if grep -Eq "frida-java-bridge|(^|[^A-Za-z0-9_.])Java[[:space:]]*\." "$SCRIPT"; then
    echo ">> hook uses the Java bridge → bundling (Frida 17+ moved bridges out of the runtime)" >&2
    SCRIPT="$(bash "$ROOT/tools/compile_frida_script.sh" "$SCRIPT" --bridge java)"
  fi
fi

# ---- 3. stage gadget + config + hook inside the app's private dir ---------------
ADB="${ADB:-adb}"
DIR="/data/data/$PKG/code_cache"
GNAME="libgadget.so"
JNAME="adh_hook.js"
CFG="libgadget.config.so"

push_file() {
  local src="$1" dst="$2"
  if command -v cygpath >/dev/null 2>&1; then src="$(cygpath -w "$src")"; fi
  "$ADB" -s "$SERIAL" push "$src" "$dst" >/dev/null
}

TMPCFG="$(mktemp)"
trap 'rm -f "$TMPCFG"' EXIT
if [ "$WATCH" = "1" ]; then
  printf '{ "interaction": { "type": "script", "path": "%s", "on_change": "reload" } }\n' "$DIR/$JNAME" >"$TMPCFG"
else
  printf '{ "interaction": { "type": "script", "path": "%s" } }\n' "$DIR/$JNAME" >"$TMPCFG"
fi

echo ">> staging gadget=$(basename "$GADGET") abi=$ABI package=$PKG" >&2
push_file "$GADGET" "/data/local/tmp/$GNAME"
push_file "$SCRIPT" "/data/local/tmp/$JNAME"
push_file "$TMPCFG" "/data/local/tmp/$CFG"

REMOTE="$(cat <<EOF
set -e
DIR="$DIR"
mkdir -p "\$DIR"
cp "/data/local/tmp/$GNAME" "\$DIR/$GNAME"
cp "/data/local/tmp/$JNAME" "\$DIR/$JNAME"
cp "/data/local/tmp/$CFG" "\$DIR/$CFG"
U=\$(stat -c %u "\$DIR"); G=\$(stat -c %g "\$DIR")
chown "\$U:\$G" "\$DIR/$GNAME" "\$DIR/$JNAME" "\$DIR/$CFG" 2>/dev/null || true
CTX=\$(ls -Zd "\$DIR" | awk '{print \$1}')
chcon "\$CTX" "\$DIR/$GNAME" "\$DIR/$CFG" "\$DIR/$JNAME" 2>/dev/null || true
rm -f "/data/local/tmp/$GNAME" "/data/local/tmp/$JNAME" "/data/local/tmp/$CFG"
EOF
)"
B64="$(printf '%s' "$REMOTE" | base64 | tr -d '\r\n')"
"$ADB" -s "$SERIAL" shell "su -c 'echo $B64 | base64 -d | sh'" >/dev/null

# ---- 4. dlopen inside the target ------------------------------------------------
INFO="$(curl -fsS "http://127.0.0.1:$HTTP/api/agents" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const a=JSON.parse(s);const x=a.filter(y=>y.online&&y.package==='$PKG').sort((p,q)=>q.connectedAt-p.connectedAt)[0];console.log(x?[x.sessionId,x.pid].join(' '):'')})")"
[ -n "$INFO" ] || die "no online ADH agent for $PKG — inject the native agent first"
SID="${INFO%% *}"; PID="${INFO##* }"

echo ">> load_so $DIR/$GNAME (session $SID pid $PID)" >&2
RESP="$(curl -fsS -X POST "http://127.0.0.1:$HTTP/api/agent/load_so" -H 'content-type: application/json' \
  -d "{\"session\":\"$SID\",\"path\":\"$DIR/$GNAME\"}")"
echo "$RESP"
echo "$RESP" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);process.exit(j.ok?0:1)})" ||
  die "dlopen of the Gadget failed — see the Host ADH Daemon log"

# ---- 5. runtime + optional marker ----------------------------------------------
echo ">> waiting for Gadget runtime threads (up to ${WAIT}s)" >&2
FOUND=0
DEADLINE=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  THREADS="$("$ADB" -s "$SERIAL" shell "su -c 'cat /proc/$PID/task/*/comm 2>/dev/null'" 2>/dev/null | tr -d '\r')"
  case $'\n'"$THREADS"$'\n' in
    *$'\nfrida-gadget\n'*) FOUND=1; break ;;
  esac
  sleep 1
done
if [ "$FOUND" = "1" ]; then
  echo ">> Gadget runtime is up in pid $PID (frida-gadget / gum-js-loop threads)" >&2
else
  echo "!! Gadget threads never showed up in pid $PID — the .so is mapped but did not start" >&2
  echo "   hints: config file must sit next to the .so as <soname>.config.so; the app uid must read it" >&2
  exit 1
fi

if [ -n "$MARKER" ]; then
  # The hook may still be queued (Java.perform defers to the app's main thread), so poll.
  MDL=$((SECONDS + WAIT))
  OK=0
  while [ "$SECONDS" -le "$MDL" ]; do
    if "$ADB" -s "$SERIAL" shell "su -c 'test -f \"$MARKER\"'" >/dev/null 2>&1; then OK=1; break; fi
    sleep 1
  done
  if [ "$OK" = "1" ]; then
    CONTENT="$("$ADB" -s "$SERIAL" shell "su -c 'cat \"$MARKER\"'" 2>/dev/null | tr -d '\r')"
    echo ">> marker OK: $MARKER = $CONTENT" >&2
  else
    echo "!! marker missing: $MARKER — Gadget is up but the hook never wrote it" >&2
    echo "   hints: Java/ObjC hooks must be bundled (default), check script syntax, and the hook's own logic" >&2
    exit 1
  fi
fi

echo ">> hook delivered to $PKG: $DIR/$JNAME (gadget: $(basename "$GADGET"))" >&2