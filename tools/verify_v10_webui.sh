#!/usr/bin/env bash
# v1.0 Web console (HOST-ONLY). Verifies the dashboard serves and wires the API:
# page 200 + expected tabs/panels + the endpoints it calls all respond.
set -uo pipefail
HTTP="${IDH_HTTP_PORT:-8760}"
BASE="http://127.0.0.1:$HTTP"
fail=0
chk(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

HTML="$(curl -s "$BASE/")"
chk "page serves"            '[ -n "$HTML" ]'
chk "title present"         'echo "$HTML" | grep -q "IDH Runtime Workbench"'
chk "tabs present"          'echo "$HTML" | grep -q "Capture" && echo "$HTML" | grep -q "Dumps" && echo "$HTML" | grep -q "Dex" && echo "$HTML" | grep -q "Native" && echo "$HTML" | grep -q "MCP"'
chk "wires capture api"     'echo "$HTML" | grep -q "/api/crypto/hook_test" && echo "$HTML" | grep -q "/api/flow/watch" && echo "$HTML" | grep -q "/api/detect/watch"'
chk "wires dex api"         'echo "$HTML" | grep -q "/api/dex/search" && echo "$HTML" | grep -q "/api/dex/xref"'
chk "wires native api"      'echo "$HTML" | grep -q "/api/native/analyze" && echo "$HTML" | grep -q "/api/native/syscall_scan"'
chk "wires mcp"             'echo "$HTML" | grep -q "/mcp"'
# backing endpoints respond
chk "/api/dumps responds"   'curl -s "$BASE/api/dumps" | grep -q "\[" '
chk "/api/agents responds"  'curl -s "$BASE/api/agents" | grep -q "\[" '
chk "/mcp tools/list responds" 'curl -s -X POST "$BASE/mcp" -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" | grep -q "tools"'
[ "$fail" -eq 0 ] && { echo "✅ v1.0 Web console PASS"; exit 0; } || { echo "❌ FAIL"; exit 1; }
