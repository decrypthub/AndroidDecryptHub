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

# verify_data_dir — sets ADH_DATA to the daemon's data directory: $ADH_DATA_DIR if set, else the
# in-repo adhd-data/. Mirrors daemon/src/state.ts. Scripts that read settings.json / events.jsonl
# off disk MUST use this instead of hardcoding "$ROOT/adhd-data": the daemon may legitimately be
# pointed elsewhere (ADH_DATA_DIR), and the hardcoded read then finds a STALE file from the old
# location and passes on it — a false green, not a failure. Measured 2026-09-30.
verify_data_dir() { ADH_DATA="${ADH_DATA_DIR:-$ROOT/adhd-data}"; }

# ---------------------------------------------------------------------------
# sandbox liveness (device scripts)
# ---------------------------------------------------------------------------
# Sets ALIVE to the sandbox pid (or empty). Prints the alive line.
verify_sandbox_alive() {
  ALIVE="$(adb -s "$SERIAL" shell pidof com.adh.sandbox 2>/dev/null | tr -d '\r ')"
  echo "sandbox alive: ${ALIVE:-NO}"
}

# Restart the sandbox when a check scans live code bytes: soft-unhooked syscall/native sites keep
# their branch stubs installed until process exit, so later scanners must start from fresh mappings.
verify_restart_sandbox() {
  adb -s "$SERIAL" shell am force-stop com.adh.sandbox >/dev/null 2>&1 || return 1
  adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1 || return 1
  sleep "${ADH_SANDBOX_START_WAIT:-4}"
}

# ---------------------------------------------------------------------------
# result gate (device + host node-heredoc scripts)
# ---------------------------------------------------------------------------

# verify_gate <label> [require_alive=1]
# Reads $OUT for the RESULT:PASS sentinel. Returns 0 (PASS) only if the sentinel
# is present AND (when require_alive=1) $ALIVE is non-empty. Prints the ✅/❌ line.
# Uses here-string grep (<<<"$OUT"), NOT `echo "$OUT"|grep -q`, to dodge the
# SIGPIPE false-FAIL on payloads large enough to fill the 64KB pipe buffer.
# ---- daemon process control (cross-platform) ------------------------------------------------
# Two acceptance scripts must restart the Host ADH Daemon to prove a property (v37 agent
# reconnect, v99 artifact re-adoption). They used to do it with Windows-only tooling
# (`netstat -ano` + `powershell Stop-Process`), which made both SKIP on Linux — a real check
# silently not running. These helpers do the same job on either host.

# PID of the process LISTENING on <port>, or empty.
daemon_pid_on_port() {
  local port="$1" pid=""
  if command -v ss >/dev/null 2>&1; then
    pid="$(ss -ltnp 2>/dev/null | grep -E "[:.]$port[[:space:]]" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
  fi
  if [ -z "$pid" ] && command -v lsof >/dev/null 2>&1; then
    pid="$(lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null | head -1)"
  fi
  if [ -z "$pid" ] && command -v netstat >/dev/null 2>&1; then
    # Windows (Git Bash): the owning PID is the last column of a LISTENING line.
    pid="$(netstat -ano 2>/dev/null | grep -E "[:.]$port[[:space:]]" | grep -i LISTENING | awk '{print $NF}' | head -1 | tr -d '\r')"
  fi
  printf '%s' "$pid"
}

# Stop one PID. PowerShell on Windows (taskkill /F gets mangled under MSYS_NO_PATHCONV and fails
# silently, which would fake a pass by leaving the daemon running); kill elsewhere.
verify_stop_pid() {
  local pid="$1"
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) powershell -NoProfile -Command "Stop-Process -Id $pid -Force" >/dev/null 2>&1 ;;
    *) kill "$pid" 2>/dev/null ;;
  esac
}

# Kill whatever is LISTENING on <port>; echoes how many it stopped. The TLS-fixture scripts
# (v07/v07_flow/v34) used `powershell Get-NetTCPConnection` + `taskkill`, which is a silent no-op
# on Linux: the previous run's server stayed up, and the next run could pass by talking to THAT
# one instead of a fresh fixture - the "test passes for the wrong reason" class.
verify_kill_port() {
  local port="$1" pid killed=0
  pid="$(daemon_pid_on_port "$port")"
  if [ -n "$pid" ]; then verify_stop_pid "$pid"; killed=1; sleep 1; fi
  printf '%s' "$killed"
}

# Start the Host ADH Daemon detached and wait until /health answers. The cold start re-hashes the
# artifact store - measured ~45s on this checkout's SMB tree - and the scripts that restart it
# (v37/v99) used a 10s budget, so on a slow host the very next request hit ECONNREFUSED and the
# test crashed instead of testing anything. Fully detached (setsid + all three fds) so the caller
# never ends up waiting on the daemon it just launched.
verify_start_daemon() {
  local port="${1:-8088}" budget="${2:-240}" waited=0
  if command -v setsid >/dev/null 2>&1; then
    ( cd "$ROOT/daemon" && setsid nohup node src/index.ts >/tmp/adhd.log 2>&1 </dev/null & ) >/dev/null 2>&1
  else
    ( cd "$ROOT/daemon" && nohup node src/index.ts >/tmp/adhd.log 2>&1 </dev/null & ) >/dev/null 2>&1
  fi
  while [ "$waited" -lt "$budget" ]; do
    curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null 2>&1 && return 0
    sleep 1; waited=$((waited + 1))
  done
  return 1
}

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
# node --test unit gate (scripts whose subject has pure unit tests)
# ---------------------------------------------------------------------------

# verify_unit_pass <label> <test-file> [min_pass]
# Runs `node --test test/<test-file>` from daemon/ and returns 0 only when the run exits
# clean AND its own summary reports zero failures. [min_pass] asserts a floor on the
# passing count, so a test file that silently stopped loading — or lost cases — cannot
# pass vacuously.
#
# Parses BOTH summary shapes node emits for the same run:
#   ℹ fail 0  — spec reporter, used only when stdout is a TTY (or colour is forced)
#   # fail 0  — TAP reporter, used whenever stdout is NOT a TTY
# The callers capture output with `UNIT="$(…)"`, i.e. command substitution, i.e. a pipe —
# so they always get TAP. The spec-only pattern this replaces (`grep -qE '^ℹ fail 0$'`)
# was hand-copied into three scripts and could never match there: each one reported
# FAIL regardless of what the tests actually did. Keep new unit gates on this helper.
verify_unit_pass() {
  local label="$1" testfile="$2" min_pass="${3:-0}"
  local raw rc clean passes fails
  raw="$(cd "$ROOT/daemon" && node --test "test/$testfile" 2>&1)"; rc=$?
  # Strip ANSI: a TTY or a forced colour level makes the spec reporter wrap its lines.
  clean="$(printf '%s\n' "$raw" | sed $'s/\033\\[[0-9;]*[a-zA-Z]//g')"
  passes="$(grep -m1 -oE '^(#|ℹ) pass [0-9]+$' <<<"$clean")"; passes="${passes##* }"
  fails="$(grep -m1 -oE '^(#|ℹ) fail [0-9]+$' <<<"$clean")"; fails="${fails##* }"
  echo "  $label: unit pass=${passes:-?} fail=${fails:-?} rc=$rc (floor $min_pass)"
  if [ "$rc" = "0" ] && [ "${fails:-1}" = "0" ] && [ "${passes:-0}" -ge "$min_pass" ]; then
    return 0
  fi
  printf '%s\n' "$raw" | tail -20
  return 1
}

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
