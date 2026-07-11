#!/usr/bin/env bash
# v1.9 Settings / config / import-export (HOST-ONLY). Verifies the IDH-style 设置 surface:
# /api/config roundtrip + disk persist, /api/settings export→import section-merge, /api/data/clear,
# and the web page wires the modals. Exit 0 = PASS.
set -uo pipefail
HTTP="${IDH_HTTP_PORT:-8760}"
BASE="http://127.0.0.1:$HTTP"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0
chk(){ if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

jget(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);let v=j;for(const k of process.argv[1].split("."))v=v?.[k];console.log(typeof v==="object"?JSON.stringify(v):v)}catch(e){console.log("ERR")}})' "$1"; }

# 1) GET /api/config exposes the settings schema
CFG="$(curl -s "$BASE/api/config")"
chk "GET /api/config 200 + schema"  '[ "$(echo "$CFG" | jget settings.capture.retain)" != "ERR" ] && [ -n "$(echo "$CFG" | jget settings.capture.retain)" ]'
chk "config has family filter"      '[ "$(echo "$CFG" | jget settings.capture.families.digest)" != "ERR" ]'
chk "config has stats"             '[ "$(echo "$CFG" | jget stats.captures)" != "ERR" ]'

# 2) POST /api/config {capture:{retain:2000}} → persist + readback
POST="$(curl -s -X POST "$BASE/api/config" -H 'content-type: application/json' -d '{"capture":{"retain":2000}}')"
chk "POST applies capture"          '[ "$(echo "$POST" | jget applied)" = "[\"capture\"]" ]'
chk "readback retain == 2000"       '[ "$(curl -s "$BASE/api/config" | jget settings.capture.retain)" = "2000" ]'
chk "persisted to settings.json"    '[ "$(cat "$ROOT/idhd-data/settings.json" | jget capture.retain)" = "2000" ]'

# 3) settings export / import (section-merge on ui)
chk "GET /api/settings/export 200"  '[ "$(curl -s "$BASE/api/settings/export" | jget ui.displayCap)" != "ERR" ]'
IMP="$(curl -s -X POST "$BASE/api/settings/import" -H 'content-type: application/json' -d '{"ui":{"displayCap":150}}')"
chk "import applied ui"             'echo "$IMP" | grep -q "\"ui\""'
chk "import readback displayCap"    '[ "$(curl -s "$BASE/api/config" | jget settings.ui.displayCap)" = "150" ]'
chk "import rejects empty segs"     '[ "$(curl -s -o /dev/null -w %{http_code} -X POST "$BASE/api/settings/import" -H "content-type: application/json" -d "{\"nope\":1}")" = "400" ]'

# 4) MCP config carries the CLI-equivalent line
chk "mcp config has cli equiv"      'curl -s "$BASE/api/mcp/config" | grep -q "claude mcp add --transport http"'

# 5) data clear endpoint validates input
chk "/api/data/clear bad what=400"  '[ "$(curl -s -o /dev/null -w %{http_code} -X POST "$BASE/api/data/clear" -H "content-type: application/json" -d "{\"what\":\"bogus\"}")" = "400" ]'

# 6) web wires the modals
HTML="$(curl -s "$BASE/")"
chk "web has settings modal"        'echo "$HTML" | grep -q "set-shell" && echo "$HTML" | grep -q "set-switch"'
chk "web has mcp modal"             'echo "$HTML" | grep -q "mcpMask"'
chk "web wires import/export"        'echo "$HTML" | grep -q "settings/export" && echo "$HTML" | grep -q "settings/import"'

# reset to defaults so downstream/repeat runs are stable
curl -s -X POST "$BASE/api/config" -H 'content-type: application/json' -d '{"capture":{"retain":1000},"ui":{"displayCap":300}}' >/dev/null

[ "$fail" -eq 0 ] && { echo "✅ v1.9 Settings/config PASS (config 回读+落盘 · export/import 板块合并 · MCP CLI · 模态已接线)"; exit 0; } \
                  || { echo "❌ v1.9 Settings FAIL"; exit 1; }
