#!/usr/bin/env bash
# v1.9 Settings / config / import-export (HOST-ONLY). Verifies the ADH-style 设置 surface:
# /api/config roundtrip + disk persist, /api/settings export→import section-merge, /api/data/clear,
# and the web page wires the modals. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_data_dir
verify_host_begin

jget(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);let v=j;for(const k of process.argv[1].split("."))v=v?.[k];console.log(typeof v==="object"?JSON.stringify(v):v)}catch(e){console.log("ERR")}})' "$1"; }

# 1) GET /api/config exposes the settings schema
CFG="$(curl -s "$BASE/api/config")"
verify_chk "GET /api/config 200 + schema"  '[ "$(echo "$CFG" | jget settings.capture.retain)" != "ERR" ] && [ -n "$(echo "$CFG" | jget settings.capture.retain)" ]'
verify_chk "config has family filter"      '[ "$(echo "$CFG" | jget settings.capture.families.digest)" != "ERR" ]'
verify_chk "config has stats"             '[ "$(echo "$CFG" | jget stats.captures)" != "ERR" ]'

# 2) POST /api/config {capture:{retain:2000}} → persist + readback
POST="$(curl -s -X POST "$BASE/api/config" -H 'content-type: application/json' -d '{"capture":{"retain":2000}}')"
verify_chk "POST applies capture"          '[ "$(echo "$POST" | jget applied)" = "[\"capture\"]" ]'
verify_chk "POST reports persisted (honest)" '[ "$(echo "$POST" | jget persisted)" = "true" ]'  # fail-loud: success must be disk-confirmed, not assumed
verify_chk "readback retain == 2000"       '[ "$(curl -s "$BASE/api/config" | jget settings.capture.retain)" = "2000" ]'
verify_chk "persisted to settings.json"    '[ "$(cat "${ADH_DATA:-$ROOT/adhd-data}/settings.json" | jget capture.retain)" = "2000" ]'

# 3) settings export / import (section-merge on ui)
verify_chk "GET /api/settings/export 200"  '[ "$(curl -s "$BASE/api/settings/export" | jget ui.displayCap)" != "ERR" ]'
IMP="$(curl -s -X POST "$BASE/api/settings/import" -H 'content-type: application/json' -d '{"ui":{"displayCap":150}}')"
verify_chk "import applied ui"             'grep -q "\"ui\"" <<<"$IMP"'
verify_chk "import readback displayCap"    '[ "$(curl -s "$BASE/api/config" | jget settings.ui.displayCap)" = "150" ]'
verify_chk "import rejects empty segs"     '[ "$(curl -s -o /dev/null -w %{http_code} -X POST "$BASE/api/settings/import" -H "content-type: application/json" -d "{\"nope\":1}")" = "400" ]'

# 4) MCP config carries the CLI-equivalent line
verify_chk "mcp config has HTTP endpoint"   'curl -s "$BASE/api/mcp/config" | grep -q "/mcp"'

# 5) data clear endpoint validates input
verify_chk "/api/data/clear bad what=400"  '[ "$(curl -s -o /dev/null -w %{http_code} -X POST "$BASE/api/data/clear" -H "content-type: application/json" -d "{\"what\":\"bogus\"}")" = "400" ]'

# 6) web wires the modals — use here-strings (grep <<<"$HTML"), NOT `echo "$HTML" | grep -q`:
# under `pipefail` a >64KB page makes grep -q exit early on match → echo SIGPIPE(141) → false FAIL.
HTML="$(curl -s "$BASE/")"
verify_chk "web has settings modal"        'grep -q "set-shell" <<<"$HTML" && grep -q "set-switch" <<<"$HTML"'
verify_chk "web has mcp modal"             'grep -q "mcpMask" <<<"$HTML"'
verify_chk "web wires import/export"        'grep -q "settings/export" <<<"$HTML" && grep -q "settings/import" <<<"$HTML"'

# reset to defaults so downstream/repeat runs are stable
curl -s -X POST "$BASE/api/config" -H 'content-type: application/json' -d '{"capture":{"retain":1000},"ui":{"displayCap":300}}' >/dev/null

verify_host_finish "v1.9 Settings/config (config 回读+落盘 · export/import 板块合并 · MCP CLI · 模态已接线)"
