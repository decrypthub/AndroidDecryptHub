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
chk "title present"         'echo "$HTML" | grep -q "Android DecryptHub"'
chk "tabs present (中文面板)" 'echo "$HTML" | grep -q "加解密" && echo "$HTML" | grep -q "脱壳" && echo "$HTML" | grep -q "内存" && echo "$HTML" | grep -q "原生" && echo "$HTML" | grep -q "MCP"'
chk "live capture panel"    'echo "$HTML" | grep -q "/api/captures" && echo "$HTML" | grep -q "capLoad"'
chk "wires capture api"     'echo "$HTML" | grep -q "/api/crypto/hook_test" && echo "$HTML" | grep -q "/api/flow/watch" && echo "$HTML" | grep -q "/api/detect/watch"'
chk "wires dex dump+download" 'echo "$HTML" | grep -q "/api/art/dump" && echo "$HTML" | grep -q "/api/dumps/download"'
chk "wires dex api"         'echo "$HTML" | grep -q "/api/dex/search" && echo "$HTML" | grep -q "/api/dex/xref"'
chk "wires native api"      'echo "$HTML" | grep -q "/api/native/analyze" && echo "$HTML" | grep -q "/api/native/syscall_scan"'
chk "wires mcp"             'echo "$HTML" | grep -q "/mcp"'
chk "events tab + api"      'echo "$HTML" | grep -q "事件" && echo "$HTML" | grep -q "/api/events"'
# backing endpoints respond (HTTP 200; -F avoids treating [ as a regex)
chk "/api/captures responds" '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/captures")" = 200 ]'
chk "/api/dumps responds"   '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/dumps")" = 200 ]'
chk "/api/agents responds"  '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/agents")" = 200 ]'
chk "/mcp tools/list responds" 'curl -s -X POST "$BASE/mcp" -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" | grep -qF "tools"'
[ "$fail" -eq 0 ] && { echo "✅ v1.0 Web console PASS"; exit 0; } || { echo "❌ FAIL"; exit 1; }
