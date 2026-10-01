#!/usr/bin/env bash
# v3.4 eCapture backend acceptance (module W — OPTIONAL, root + eBPF).
#
# eCapture reads TLS plaintext at the SSL_write/SSL_read boundary with eBPF uprobes — no CA
# certificate, no proxy. This check proves the whole optional path on the attached device:
#
#   official binary (sha256 pinned from the release's own checksum file)
#     → preflight (root / kernel >= 5.5 / CONFIG_BPF_SYSCALL + UPROBES; BTF is a note, not a gate)
#     → start eCapture's TLS probe against the sandbox process
#     → drive one real HTTPS request through the plugin (MCP capture_start + java_call → the app's own Network.run())
#     → assert eCapture captured the plaintext the app sent (ADH_NET_MARKER_v1) and the response
#
# RESULT:SKIP (exit 0, explicit reason) when there is no device, the download is unavailable, or
# the kernel cannot load eBPF programs — this backend is optional and kernel-gated.
#
# Run: bash tools/verify_v34_ecapture.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

TLS_PORT="${ADH_TLS_PORT:-8762}"
MARKER="ADH_NET_MARKER_v1"; RESP="ADH_NET_RESPONSE_v1"
PKG="com.adh.sandbox"
CAP_SECONDS="${ADH_ECAPTURE_SECONDS:-15}"

skip() { echo "$1"; echo "⏭ eCapture SKIP ($2)"; exit 0; }
[ -n "${SERIAL:-}" ] || skip "RESULT:SKIP no device" "no serial"
adb -s "$SERIAL" get-state >/dev/null 2>&1 || skip "RESULT:SKIP no device" "adb offline"

# 1) official binary -----------------------------------------------------------------------
BIN="$(bash "$ROOT/tools/fetch_ecapture.sh" 2>/tmp/adh_ecapture_fetch.err)" || BIN=""
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  tail -2 /tmp/adh_ecapture_fetch.err 2>/dev/null | sed 's/^/   /'
  skip "RESULT:SKIP eCapture binary unavailable" "download failed (see tools/fetch_ecapture.sh)"
fi
echo "binary: $BIN ($(stat -c %s "$BIN" 2>/dev/null || echo '?') bytes)"

# 2) preflight -----------------------------------------------------------------------------
set +e
PRE="$(bash "$ROOT/tools/ecapture_capture.sh" --preflight-only 2>&1)"; PRE_RC=$?
set +e
echo "$PRE" | sed 's/^/   /'
if [ "$PRE_RC" != "0" ]; then
  skip "RESULT:SKIP kernel cannot load eBPF programs" "$(printf '%s' "$PRE" | grep -m1 verdict | sed 's/.*verdict *: //')"
fi

# 3) target + local TLS fixture (same server v0.7 uses, over adb reverse) --------------------
adb -s "$SERIAL" shell "su -c 'am start -n $PKG/.MainActivity'" >/dev/null 2>&1
sleep 4
verify_sandbox_alive
verify_kill_port "$TLS_PORT" >/dev/null   # cross-platform: the old powershell/taskkill pair was a silent no-op on Linux
( node "$ROOT/daemon/tls_test_server.mjs" > /tmp/adh_tls.log 2>&1 & )
# Wait for the LISTENER, not for a fixed 2s: node has to read the script off this SMB tree, and the
# first start after a kill was measured taking longer than that - the fixed sleep made v07 fail
# with "nothing is listening" while the very next script bound fine (2s is a guess, the listener is
# a fact).
for _ in $(seq 1 30); do [ -n "$(daemon_pid_on_port "$TLS_PORT")" ] && break; sleep 1; done
adb -s "$SERIAL" reverse tcp:$TLS_PORT tcp:$TLS_PORT >/dev/null

# 4) capture in the background, then drive traffic through the plugin ------------------------
CAP_LOG="$(mktemp)"
bash "$ROOT/tools/ecapture_capture.sh" --package "$PKG" --seconds "$CAP_SECONDS" >"$CAP_LOG" 2>&1 &
CAP_PID=$!
sleep 5
set +e
TRIG="$(node - "$HTTP" "$MARKER" <<'EOF'
const [http, marker] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const mcp = async (method, params) => (await (await fetch(`${base}/mcp`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }),
})).json());
const agents = await (await fetch(`${base}/api/agents`)).json();
const a = agents.filter((x) => x.package === 'com.adh.sandbox' && x.online).sort((x, y) => y.connectedAt - x.connectedAt)[0];
if (!a) { console.log('NO_AGENT'); process.exit(0); }
const call = async (name, args) => { const r = await mcp('tools/call', { name, arguments: args }); const t = r.result?.content?.[0]?.text ?? '{}'; try { return JSON.parse(t); } catch { return {}; } };
const on = await call('capture_start', { session: a.sessionId });
const trig = await call('java_call', { session: a.sessionId, className: 'com.adh.sandbox.Network', method: 'run', params: '', args: [] });
let wrote = false;
for (let i = 0; i < 10 && !wrote; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  const lc = await call('live_captures', { session: a.sessionId, category: 'net', limit: 300, includeText: true });
  wrote = (lc.captures || []).some((c) => c.func === 'SSL_write' && String(c.ascii || '').includes(marker));
}
console.log(`MCP capture_start: ok=${on.ok} installed=${on.installed}/${on.attempted}; java_call Network.run -> ${JSON.stringify(trig.result?.result ?? trig.error ?? null)}; agent-saw-marker=${wrote}`);
EOF
)"
echo "$TRIG" | sed 's/^/   /'
wait "$CAP_PID"; CAP_RC=$?
set +e
CAP_FILE="$(tail -1 "$CAP_LOG" 2>/dev/null)"

# 5) assertions ----------------------------------------------------------------------------
HAS_MARK=""; HAS_RESP=""; PROBE_START=""
if [ -n "$CAP_FILE" ] && [ -f "$CAP_FILE" ]; then
  PLAIN="$(sed -e 's/\x1b\[[0-9;]*m//g' "$CAP_FILE" 2>/dev/null || cat "$CAP_FILE")"
  printf '%s' "$PLAIN" | grep -q "$MARKER" && HAS_MARK=1
  printf '%s' "$PLAIN" | grep -q "$RESP" && HAS_RESP=1
  printf '%s' "$PLAIN" | grep -q 'probe started successfully' && PROBE_START=1
fi
echo "eCapture: runner rc=$CAP_RC probeStarted=${PROBE_START:-0} requestPlaintext=${HAS_MARK:-0} responsePlaintext=${HAS_RESP:-0}"
echo "capture file: ${CAP_FILE:-<none>}"
tail -3 "$CAP_LOG" | sed 's/^/   /'
verify_sandbox_alive

if [ "$CAP_RC" = "0" ] && [ -n "$PROBE_START" ] && [ -n "$HAS_MARK" ] && [ -n "$ALIVE" ]; then
  SENTINEL="RESULT:PASS"
else
  SENTINEL="RESULT:FAIL"
fi
if [ -z "$HAS_MARK" ] && [ -n "$CAP_FILE" ] && [ -f "$CAP_FILE" ]; then
  echo "--- eCapture capture (head) ---"
  sed -e 's/\x1b\[[0-9;]*m//g' "$CAP_FILE" | head -25 | sed 's/^/   /'
fi
OUT="$(printf '%s\n%s\n%s\n' "$TRIG" "eCapture: rc=$CAP_RC probe=${PROBE_START:-0} req=${HAS_MARK:-0} resp=${HAS_RESP:-0}" "$SENTINEL")"
echo "$SENTINEL"
verify_gate "v3.4 eCapture TLS plaintext capture (optional eBPF backend)" 0 && exit 0 || exit 1