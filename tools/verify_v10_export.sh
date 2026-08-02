#!/usr/bin/env bash
# v1.0 diagnostic export + MCP inventory (HOST-ONLY). Asserts the export report is
# metadata-only, the MCP surface is complete (>=25 tools incl new device/analysis
# tools), and the generated tools doc is well-formed. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_host_begin

REP="$(curl -s "$BASE/api/export/report")"
verify_chk "report shape"      'echo "$REP" | grep -q "idh-diagnostic" && echo "$REP" | grep -q "capabilities"'
verify_chk "report no-secrets note" 'echo "$REP" | grep -q "metadata only"'
DOC="$(curl -s "$BASE/api/mcp/doc")"
verify_chk "mcp doc header"    'echo "$DOC" | grep -q "MCP Tools"'
verify_chk "mcp doc has tools" 'echo "$DOC" | grep -q "process_list" && echo "$DOC" | grep -q "trace_function"'

TOOLS="$(curl -s -X POST "$BASE/mcp" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
COUNT=$(echo "$TOOLS" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{process.stdout.write(String(JSON.parse(d).result.tools.length))}catch(e){process.stdout.write('0')}})")
echo "mcp tool count = $COUNT"
verify_chk "mcp >=25 tools"    '[ "$COUNT" -ge 25 ]'
verify_chk "new tools present" 'echo "$TOOLS" | grep -q memory_dump && echo "$TOOLS" | grep -q dex_method_code && echo "$TOOLS" | grep -q dex_repair'

verify_host_finish "v1.0 export + MCP inventory"
