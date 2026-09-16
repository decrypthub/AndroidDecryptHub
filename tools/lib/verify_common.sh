#!/usr/bin/env bash
# Shared helpers for tools/verify_vXX_*.sh acceptance scripts. SOURCE this file,
# do not execute it directly.
#
# What this dedups (previously hand-copied into ~26 scripts, ~60-75% of each):
#   - env resolution (ROOT/HTTP/SERIAL/BASE; ADH_* variables)
#   - sandbox liveness probe (adb pidof com.adh.sandbox)
#   - result gate (RESULT:PASS sentinel grep + optional alive check)
#   - host-only chk accumulator + finish gate
#   - SIGPIPE-safe here-string grep
#
# Behavior contract preserved: each verify script still exits 0 on PASS / 1 on FAIL.
# The node heredoc payload (the unique per-test code) stays verbatim in each script;
# this file only factors the SHELL boilerplate around it.

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# ---------------------------------------------------------------------------
# env resolution
# ---------------------------------------------------------------------------

# verify_resolve_env        — full: ROOT/HTTP/SERIAL/BASE (device-style scripts)
# verify_resolve_env_host   — ROOT/HTTP/BASE only, no SERIAL, no adb call (host-only)
#
# BASH_SOURCE[0] here is THIS file (tools/lib/verify_common.sh) — two levels up
# is the repo root, so ROOT is correct regardless of which script sourced us.
# ADH_* env vars; ANDROID_SERIAL also honored.
verify_resolve_env() {
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if command -v cygpath >/dev/null 2>&1; then
    ROOT="$(cygpath -m "$ROOT")"
  fi
  HTTP="${ADH_HTTP_PORT:-8088}"
  BASE="http://127.0.0.1:$HTTP"
  SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-$(adb devices 2>/dev/null | awk 'NR==2{print $1}')}}"
}
verify_resolve_env_host() {
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if command -v cygpath >/dev/null 2>&1; then
    ROOT="$(cygpath -m "$ROOT")"
  fi
  HTTP="${ADH_HTTP_PORT:-8088}"
  BASE="http://127.0.0.1:$HTTP"
}

# ---------------------------------------------------------------------------
# sandbox liveness (device scripts)
# ---------------------------------------------------------------------------

# Sets ALIVE to the sandbox pid (or empty). Prints the alive line.
verify_sandbox_alive() {
  ALIVE="$(adb -s "$SERIAL" shell pidof com.adh.sandbox 2>/dev/null | tr -d '\r ')"
  echo "sandbox alive: ${ALIVE:-NO}"
}

# ---------------------------------------------------------------------------
# result gate (device + host node-heredoc scripts)
# ---------------------------------------------------------------------------

# verify_gate <label> [require_alive=1]
# Reads $OUT for the RESULT:PASS sentinel. Returns 0 (PASS) only if the sentinel
# is present AND (when require_alive=1) $ALIVE is non-empty. Prints the ✅/❌ line.
# Uses here-string grep (<<<"$OUT"), NOT `echo "$OUT"|grep -q`, to dodge the
# SIGPIPE false-FAIL on payloads large enough to fill the 64KB pipe buffer.
verify_gate() {
  local label="$1"
  local require_alive="${2:-1}"
  local ok=0
  if grep -q 'RESULT:PASS' <<<"$OUT"; then
    if [ "$require_alive" = "1" ] && [ -z "$ALIVE" ]; then ok=0; else ok=1; fi
  fi
  if [ "$ok" = "1" ]; then echo "✅ $label PASS"; return 0
  else echo "❌ $label FAIL"; return 1; fi
}

# ---------------------------------------------------------------------------
# SIGPIPE-safe grep (host scripts that grep large HTML bodies)
# ---------------------------------------------------------------------------

# verify_grep_q <haystack> <pattern> — returns 0 if pattern matches, SIGPIPE-safe.
verify_grep_q() { grep -q "$2" <<<"$1"; }

# ---------------------------------------------------------------------------
# host-only chk accumulator idiom
# (verify_v10_webui.sh / verify_v19_settings.sh / v0.8 / v0.9 host analyzers)
# ---------------------------------------------------------------------------

# verify_host_begin        — init the fail counter (call after resolve_env_host)
# verify_chk <label> <expr> — eval <expr>; PASS/FAIL line, sets fail=1 on miss
# verify_host_finish <label> — print ✅/❌ + exit 0/1
#
# The chk idiom is kept (not force-merged into the RESULT:PASS sentinel) because
# host scripts run many independent assertions per script; the sentinel model is
# one-shot. Both idioms coexist by design; this just dedups the chk definition.
verify_host_begin() { fail=0; }
verify_chk() {
  local label="$1" expr="$2"
  if eval "$expr"; then echo "PASS  $label"; else echo "FAIL  $label"; fail=1; fi
}
verify_host_finish() {
  local label="$1"
  if [ "$fail" -eq 0 ]; then echo "✅ $label PASS"; exit 0
  else echo "❌ $label FAIL"; exit 1; fi
}
