#!/usr/bin/env bash
# v1.0 Web console (HOST-ONLY). Verifies the dashboard serves and wires the API:
# page 200 + expected tabs/panels + the endpoints it calls all respond.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_host_begin

HTML="$(curl -s "$BASE/")"
# NB: use here-strings (grep <<<"$HTML"), NOT `echo "$HTML" | grep -q`. Under `set -o pipefail`
# a large page (>64KB pipe buffer) makes grep -q exit early on match, echo then hits SIGPIPE
# (141), and pipefail reports the pipeline as failed — a false FAIL unrelated to page content.
verify_chk "page serves"            '[ -n "$HTML" ]'
verify_chk "title present"         'grep -q "Android DecryptHub" <<<"$HTML"'
verify_chk "raven brand mark"      'grep -q "/raven.svg" <<<"$HTML" && ! grep -q "hdr-mark\">A" <<<"$HTML"'
verify_chk "tabs present (中文面板)" 'grep -q "加解密" <<<"$HTML" && grep -q "系统" <<<"$HTML" && grep -q "网络" <<<"$HTML" && grep -q "文件" <<<"$HTML" && grep -q "脱壳" <<<"$HTML"'
verify_chk "no advanced fold / LAN URL" '! grep -q "id=\"access\"" <<<"$HTML" && ! grep -q "id=\"p-mem\"" <<<"$HTML" && ! grep -q "id=\"p-native\"" <<<"$HTML" && ! grep -q ">高级<" <<<"$HTML"'
verify_chk "category-split panels"  'grep -q "makeCapPanel" <<<"$HTML" && grep -q "p-system" <<<"$HTML" && grep -q "p-net" <<<"$HTML"'
verify_chk "file browser split pane" 'grep -q "files-workspace" <<<"$HTML" && grep -q "filesBreadcrumb" <<<"$HTML" && grep -q "应用私有目录" <<<"$HTML" && grep -q "/api/fs/list?package=" <<<"$HTML" && grep -q "/api/fs/read" <<<"$HTML" && ! grep -q "没有连上的进程" <<<"$HTML" && ! grep -q "没有在跑的进程，捕获记录仍可查看" <<<"$HTML"'
verify_chk "one-click unpack wired" 'grep -qF "/api/unpack/run" <<<"$HTML" && grep -qF "一键脱壳" <<<"$HTML" && grep -qF "runOneClickUnpack()" <<<"$HTML"'
verify_chk "live capture panel"    'grep -q "/api/captures" <<<"$HTML" && grep -q "capLoad" <<<"$HTML"'
verify_chk "capture KEY/IV cards"  'grep -q "function ioKV" <<<"$HTML" && grep -q "输入 / INPUT" <<<"$HTML" && grep -q "输出 / OUTPUT" <<<"$HTML"'
verify_chk "wires dump download"   'grep -qF "/api/dumps/download" <<<"$HTML" && grep -qF "unpackDetailRows" <<<"$HTML"'
verify_chk "header keeps app, summary and one settings entry" 'grep -q "id=\"appBtn\"" <<<"$HTML" && grep -q "id=\"processBtn\"" <<<"$HTML" && grep -q "id=\"setBtn\"[^>]*>设置</button>" <<<"$HTML" && ! grep -q "id=\"opBtn\"" <<<"$HTML"'
verify_chk "settings contains algorithms and execution history" 'grep -q "id=\"setCaptureTab\"[^>]*>算法采集</button>" <<<"$HTML" && grep -q "id=\"setRecordsTab\"[^>]*>执行记录</button>" <<<"$HTML"'
verify_chk "analysis omits WeChat, MCP onboarding and Hook editor" '! grep -qE "wechat(Btn|Popover)|wechat-follow\.png|公众号|mcp(Btn|Mask|Install|Connect|Config)|/api/mcp/config|hook-plans-panel\.js|AdhHookPlansPanel" <<<"$HTML"'
verify_chk "workbench chrome"     'grep -q "process-trigger" <<<"$HTML" && grep -q "block-copy" <<<"$HTML" && grep -q "jumpLatest" <<<"$HTML" && grep -q "unpackRows" <<<"$HTML"'
# backing endpoints respond (HTTP 200; -F avoids treating [ as a regex)
verify_chk "/api/captures responds" '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/captures")" = 200 ]'
verify_chk "/api/dumps responds"   '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/dumps")" = 200 ]'
verify_chk "/api/agents responds"  '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/agents")" = 200 ]'
verify_chk "/mcp tools/list responds" 'curl -s -X POST "$BASE/mcp" -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" | grep -qF "tools"'
verify_host_finish "v1.0 Web console"
