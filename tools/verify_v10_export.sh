#!/usr/bin/env bash
# v1.0 diagnostic export + MCP inventory (HOST-ONLY). Asserts the export report is
# metadata-only, the MCP surface is complete (>=25 tools incl new device/analysis
# tools), and the generated tools doc is well-formed. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_host_begin

REP="$(curl -s "$BASE/api/export/report")"
# verify_grep_q, not `echo | grep -q`: this payload lists every artifact in the store, so it grows
# with the number of dumps and crosses the 64 KiB pipe buffer (67 KB with ~280 artifacts). Past that
# point the writer gets SIGPIPE, pipefail turns it into a non-zero status, and the match is reported
# as a failure even though the text is there — the exact landmine tools/MAP.md documents.
verify_chk "report shape"      'verify_grep_q "$REP" "idh-diagnostic" && verify_grep_q "$REP" "capabilities"'
verify_chk "report no-secrets note" 'verify_grep_q "$REP" "metadata only"'
DOC="$(curl -s "$BASE/api/mcp/doc")"
verify_chk "mcp doc header"    'verify_grep_q "$DOC" "MCP Tools"'
verify_chk "mcp doc has tools" 'verify_grep_q "$DOC" "process_list" && verify_grep_q "$DOC" "capture_start" && verify_grep_q "$DOC" "flow_correlate"'

TOOLS="$(curl -s -X POST "$BASE/mcp" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
COUNT=$(echo "$TOOLS" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{process.stdout.write(String(JSON.parse(d).result.tools.length))}catch(e){process.stdout.write('0')}})")
echo "mcp tool count = $COUNT"
verify_chk "mcp >=25 tools"    '[ "$COUNT" -ge 25 ]'
verify_chk "new tools present" 'echo "$TOOLS" | grep -q memory_dump && echo "$TOOLS" | grep -q dex_method_code && echo "$TOOLS" | grep -q dex_repair'

verify_host_finish "v1.0 export + MCP inventory"
