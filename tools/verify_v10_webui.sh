#!/usr/bin/env bash
# v1.0 Web console (HOST-ONLY). Verifies the dashboard serves and wires the API:
# page 200 + expected tabs/panels + the endpoints it calls all respond.
set -uo pipefail
HTTP="${IDH_HTTP_PORT:-8760}"
BASE="http://127.0.0.1:$HTTP"
fail=0
chk(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

HTML="$(curl -s "$BASE/")"
# NB: use here-strings (grep <<<"$HTML"), NOT `echo "$HTML" | grep -q`. Under `set -o pipefail`
# a large page (>64KB pipe buffer) makes grep -q exit early on match, echo then hits SIGPIPE
# (141), and pipefail reports the pipeline as failed — a false FAIL unrelated to page content.
chk "page serves"            '[ -n "$HTML" ]'
chk "title present"         'grep -q "Android DecryptHub" <<<"$HTML"'
chk "tabs present (中文面板)" 'grep -q "加解密" <<<"$HTML" && grep -q "系统" <<<"$HTML" && grep -q "网络" <<<"$HTML" && grep -q "文件" <<<"$HTML" && grep -q "Dump" <<<"$HTML" && grep -q "MCP" <<<"$HTML"'
chk "advanced tools retained" 'grep -q "脱壳" <<<"$HTML" && grep -q "内存" <<<"$HTML" && grep -q "原生" <<<"$HTML"'
chk "category-split panels"  'grep -q "makeCapPanel" <<<"$HTML" && grep -q "p-system" <<<"$HTML" && grep -q "p-net" <<<"$HTML"'
chk "file browser wired"     'grep -q "/api/fs/list" <<<"$HTML" && grep -q "/api/fs/read" <<<"$HTML"'
chk "dump modules wired"     'grep -q "/api/modules" <<<"$HTML" && grep -q "/api/module/dump" <<<"$HTML" && grep -q "/api/memory/dump" <<<"$HTML"'
chk "live capture panel"    'grep -q "/api/captures" <<<"$HTML" && grep -q "capLoad" <<<"$HTML"'
chk "wires capture api"     'grep -q "/api/crypto/hook_test" <<<"$HTML" && grep -q "/api/flow/watch" <<<"$HTML" && grep -q "/api/detect/watch" <<<"$HTML"'
chk "wires dex dump+download" 'grep -q "/api/art/dump" <<<"$HTML" && grep -q "/api/dumps/download" <<<"$HTML"'
chk "wires dex api"         'grep -q "/api/dex/search" <<<"$HTML" && grep -q "/api/dex/xref" <<<"$HTML"'
chk "wires native api"      'grep -q "/api/native/analyze" <<<"$HTML" && grep -q "/api/native/syscall_scan" <<<"$HTML"'
chk "wires mcp"             'grep -q "/mcp" <<<"$HTML"'
chk "events tab + api"      'grep -q "事件" <<<"$HTML" && grep -q "/api/events" <<<"$HTML"'
chk "settings + mcp modals"  'grep -q "设置" <<<"$HTML" && grep -q "MCP 接入配置" <<<"$HTML" && grep -q "set-shell" <<<"$HTML"'
chk "hexdump + copy + filter toolbar" 'grep -q "function hexdump" <<<"$HTML" && grep -q "copyCap" <<<"$HTML" && grep -q "tb-download" <<<"$HTML"'
# backing endpoints respond (HTTP 200; -F avoids treating [ as a regex)
chk "/api/captures responds" '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/captures")" = 200 ]'
chk "/api/dumps responds"   '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/dumps")" = 200 ]'
chk "/api/agents responds"  '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/agents")" = 200 ]'
chk "/mcp tools/list responds" 'curl -s -X POST "$BASE/mcp" -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" | grep -qF "tools"'
[ "$fail" -eq 0 ] && { echo "✅ v1.0 Web console PASS"; exit 0; } || { echo "❌ FAIL"; exit 1; }
