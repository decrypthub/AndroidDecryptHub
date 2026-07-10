#!/usr/bin/env bash
# v1.0 diagnostic export + MCP inventory (HOST-ONLY). Asserts the export report is
# metadata-only, the MCP surface is complete (>=25 tools incl new device/analysis
# tools), and the generated tools doc is well-formed. Exit 0 = PASS.
set -uo pipefail
HTTP="${IDH_HTTP_PORT:-8760}"
BASE="http://127.0.0.1:$HTTP"
fail=0
chk(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

REP="$(curl -s "$BASE/api/export/report")"
chk "report shape"      'echo "$REP" | grep -q "idh-diagnostic" && echo "$REP" | grep -q "capabilities"'
chk "report no-secrets note" 'echo "$REP" | grep -q "metadata only"'
DOC="$(curl -s "$BASE/api/mcp/doc")"
chk "mcp doc header"    'echo "$DOC" | grep -q "MCP Tools"'
chk "mcp doc has tools" 'echo "$DOC" | grep -q "process_list" && echo "$DOC" | grep -q "trace_function"'

TOOLS="$(curl -s -X POST "$BASE/mcp" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
COUNT=$(echo "$TOOLS" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{process.stdout.write(String(JSON.parse(d).result.tools.length))}catch(e){process.stdout.write('0')}})")
echo "mcp tool count = $COUNT"
chk "mcp >=25 tools"    '[ "$COUNT" -ge 25 ]'
chk "new tools present" 'echo "$TOOLS" | grep -q memory_dump && echo "$TOOLS" | grep -q dex_method_code && echo "$TOOLS" | grep -q dex_repair'

[ "$fail" -eq 0 ] && { echo "✅ v1.0 export + MCP inventory PASS"; exit 0; } || { echo "❌ FAIL"; exit 1; }
