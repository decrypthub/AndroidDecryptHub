#!/usr/bin/env bash
# Run eCapture (eBPF TLS plaintext capture) against an ADH target — OPTIONAL backend.
#
# eCapture reads plaintext at the SSL_write/SSL_read boundary via eBPF uprobes, so it needs ROOT
# and an eBPF-capable kernel (aarch64 kernel >= 5.5, CONFIG_BPF_SYSCALL + UPROBES). Kernel BTF is
# NOT a hard requirement for the official Android build — verified on a 5.10 kernel with
# CONFIG_DEBUG_INFO_BTF=n, where the OpenSSL probe starts fine — so BTF is reported as a note only.
# The real capability signal is the probe itself: after the run this script greps its output for
# "probe started successfully" and fails loudly otherwise (with the first error line).
#
# Usage:
#   tools/ecapture_capture.sh [--package PKG | --pid N | --uid N]
#                             [--version V] [--abi arm64]
#                             [--seconds N] [--out DIR] [--preflight-only] [--force]
#
#   --preflight-only  print the device capability report and exit (0 = supported, 3 = not)
#   --force           run even when the preflight says the kernel is unsupported
#
# Env:
#   ANDROID_SERIAL / ADH_SERIAL      target device
#   ADH_ECAPTURE_VERSION/ABI/DIR     as in tools/fetch_ecapture.sh
#   ECAPTURE_BIN                     explicit host path to the ecapture binary
#   ECAPTURE_BTF_FILE                explicit BTF path on the device to use instead of the default
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-}}"
if [ -z "$SERIAL" ]; then
  SERIAL="$(adb devices 2>/dev/null | awk 'NR==2 && $2=="device" {print $1; exit}')"
fi
[ -n "$SERIAL" ] || { echo "!! no adb device; set ANDROID_SERIAL" >&2; exit 1; }
ADB="${ADB:-adb}"

VERSION="${ADH_ECAPTURE_VERSION:-latest}"
ABI="${ADH_ECAPTURE_ABI:-arm64}"
PKG=""; PID=""; UID_T=""; SECONDS_RUN=20
OUT_DIR="$ROOT/captures/ecapture"; PREFLIGHT_ONLY=0; FORCE=0
usage() { sed -n '2,22p' "$0"; }
die() { echo "!! $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --package) PKG="${2:?--package needs a value}"; shift 2 ;;
    --pid) PID="${2:?--pid needs a value}"; shift 2 ;;
    --uid) UID_T="${2:?--uid needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --abi) ABI="${2:?--abi needs a value}"; shift 2 ;;
    --seconds) SECONDS_RUN="${2:?--seconds needs a value}"; shift 2 ;;
    --out) OUT_DIR="${2:?--out needs a value}"; shift 2 ;;
    --preflight-only) PREFLIGHT_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
suroot() { "$ADB" -s "$SERIAL" shell "su -c '$1'" 2>/dev/null | tr -d '\r'; }

# ---- preflight: root + kernel + eBPF/BTF -------------------------------------------------
UID_NOW="$(suroot 'id -u')"
KREL="$(suroot 'uname -r')"
KMAJ="$(printf '%s' "$KREL" | cut -d. -f1)"; KMIN="$(printf '%s' "$KREL" | cut -d. -f2)"
BTF_DEFAULT="/sys/kernel/btf/vmlinux"
BTF_PATH="${ECAPTURE_BTF_FILE:-$BTF_DEFAULT}"
BTF_STATE="missing"
[ -n "$(suroot "test -f '$BTF_PATH' && echo yes")" ] && BTF_STATE="present ($BTF_PATH)"
BPF_SYSCALL="unknown"; UPROBES="unknown"
CFG="$(suroot 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(BPF_SYSCALL|UPROBES|DEBUG_INFO_BTF)="')"
if [ -n "$CFG" ]; then
  BPF_SYSCALL="$(printf '%s\n' "$CFG" | sed -n 's/^CONFIG_BPF_SYSCALL=//p')"; BPF_SYSCALL="${BPF_SYSCALL:-unknown}"
  UPROBES="$(printf '%s\n' "$CFG" | sed -n 's/^CONFIG_UPROBES=//p')"; UPROBES="${UPROBES:-unknown}"
fi
SUPPORTED=1; REASON=""
if [ "$UID_NOW" != "0" ]; then SUPPORTED=0; REASON="root required (su returned uid=$UID_NOW)"; fi
if [ "$SUPPORTED" = "1" ] && { [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 5 ]; }; }; then
  SUPPORTED=0; REASON="aarch64 needs kernel >= 5.5 (device: $KREL)"
fi
# (BTF intentionally not part of the verdict — see header. The run itself decides.)
if [ "$SUPPORTED" = "1" ] && [ "$BPF_SYSCALL" = "n" ]; then
  SUPPORTED=0; REASON="CONFIG_BPF_SYSCALL=n — eBPF programs cannot be loaded"
fi
if [ "$SUPPORTED" = "1" ] && [ "$UPROBES" = "n" ]; then
  SUPPORTED=0; REASON="CONFIG_UPROBES=n — SSL_write/SSL_read uprobes unavailable"
fi
cat <<EOF
eCapture preflight ($SERIAL)
  root          : uid=$UID_NOW
  kernel        : $KREL
  btf           : $BTF_STATE$( [ "${BTF_STATE#present}" = "$BTF_STATE" ] && echo "  (note: official Android build does not require BTF)" )
  CONFIG_BPF_SYSCALL : $BPF_SYSCALL
  CONFIG_UPROBES     : $UPROBES
  verdict       : $( [ "$SUPPORTED" = "1" ] && echo supported || echo "unsupported — $REASON" )
EOF
if [ "$PREFLIGHT_ONLY" = "1" ]; then [ "$SUPPORTED" = "1" ] && exit 0 || exit 3; fi
if [ "$SUPPORTED" != "1" ] && [ "$FORCE" != "1" ]; then
  echo "!! refusing to run: $REASON" >&2
  echo "   eCapture is an OPTIONAL backend; run with --force to see its own error, or use a kernel with BTF." >&2
  exit 3
fi
[ -n "$PKG$PID$UID_T" ] || die "need --package, --pid or --uid"

# ---- binary -------------------------------------------------------------------------------
if [ -n "${ECAPTURE_BIN:-}" ]; then BIN="$ECAPTURE_BIN"; else BIN="$(bash "$ROOT/tools/fetch_ecapture.sh" "$VERSION" "$ABI" 2>/dev/null)"; fi
[ -f "$BIN" ] || die "ecapture binary not found (run tools/fetch_ecapture.sh)"
BIN_HOST="$BIN"; command -v cygpath >/dev/null 2>&1 && BIN_HOST="$(cygpath -w "$BIN")"
"$ADB" -s "$SERIAL" push "$BIN_HOST" /data/local/tmp/ecapture >/dev/null
suroot 'chmod 755 /data/local/tmp/ecapture' >/dev/null

# ---- target -------------------------------------------------------------------------------
TARGET=""
if [ -n "$PID" ]; then TARGET="-p $PID"
elif [ -n "$PKG" ]; then
  P="$(suroot "pidof $PKG" | awk '{print $1}')"
  [ -n "$P" ] || die "package $PKG is not running (start it first)"
  TARGET="-p $P"
else TARGET="-u $UID_T"; fi

TS="$(date +%Y%m%d-%H%M%S)"
DEV_OUT="/data/local/tmp/ecapture-$TS.txt"
RUN="./ecapture tls -m text $TARGET -d > $DEV_OUT 2>&1"
echo ">> running eCapture (text, ${SECONDS_RUN}s) on $SERIAL: $TARGET" >&2
suroot "cd /data/local/tmp && timeout $SECONDS_RUN $RUN; true" >/dev/null || true

mkdir -p "$OUT_DIR"
LOCAL_OUT="$OUT_DIR/$( [ -n "$PKG" ] && echo "$PKG" || echo "pid-$PID$UID_T" )-$TS.txt"
"$ADB" -s "$SERIAL" pull "$DEV_OUT" "$LOCAL_OUT" >/dev/null 2>&1 || die "no capture produced at $DEV_OUT (see /data/local/tmp/ecapture-$TS.log on the device)"
echo ">> capture: $LOCAL_OUT ($(wc -c <"$LOCAL_OUT" | tr -d ' ') bytes)" >&2
PLAIN="$(sed -e 's/\x1b\[[0-9;]*m//g' "$LOCAL_OUT" 2>/dev/null || cat "$LOCAL_OUT")"
if printf '%s' "$PLAIN" | grep -q 'probe started successfully'; then
  echo ">> eCapture verdict: probe started successfully" >&2
else
  echo "!! eCapture verdict: probe did NOT start — first error below" >&2
  printf '%s\n' "$PLAIN" | grep -iE 'error|failed|cannot|unsupported|btf|ebpf' | head -5 >&2 || true
  exit 4
fi
echo "--- first lines ---" >&2
head -12 "$LOCAL_OUT" >&2 || true
printf '%s\n' "$LOCAL_OUT"