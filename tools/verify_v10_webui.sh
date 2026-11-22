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
verify_chk "file IO events in system and APP directory in files" 'grep -qF "文件 · APP 目录" <<<"$HTML" && grep -q "id=\"directoryState\"" <<<"$HTML" && grep -q "data-system-kind=\"file\"" <<<"$HTML" && ! grep -q "id=\"fl-list\"" <<<"$HTML"'
verify_chk "dump view shows scoped artifact metadata" 'grep -qF "dump · 产物记录" <<<"$HTML" && grep -q "id=\"artifactRows\"" <<<"$HTML" && grep -qF "scopedArtifactRows" <<<"$HTML"'
verify_chk "live capture panel"    'grep -q "/api/captures" <<<"$HTML" && grep -q "capLoad" <<<"$HTML"'
verify_chk "capture KEY/IV cards"  'grep -q "function ioKV" <<<"$HTML" && grep -q "输入 / INPUT" <<<"$HTML" && grep -q "输出 / OUTPUT" <<<"$HTML"'
verify_chk "viewer keeps APP and session summary in one entry beside settings" 'grep -q "id=\"appBtn\"" <<<"$HTML" && grep -q "id=\"appChoices\"" <<<"$HTML" && grep -q "id=\"sessRows\"" <<<"$HTML" && grep -q "id=\"setBtn\"[^>]*>设置</button>" <<<"$HTML" && ! grep -Eq "id=\"(opBtn|processBtn)\"" <<<"$HTML"'
verify_chk "device picker and APP sessions have separate contexts" 'grep -q "id=\"deviceChoices\"" <<<"$HTML" && grep -q "id=\"appContext\"" <<<"$HTML" && grep -qF "/api/devices?action=list" <<<"$HTML" && grep -q "设备归属未核验" <<<"$HTML"'
verify_chk "capture toolbar and tabbed list/detail layout" 'grep -q "toolbar-search capture-toolbar" <<<"$HTML" && grep -q "toolbar-actions capture-toolbar" <<<"$HTML" && grep -q "capture-list-head" <<<"$HTML" && grep -q "record-tabs" <<<"$HTML" && grep -q "data-capture-back=\"cc\"" <<<"$HTML"'
verify_chk "settings separates scope, observed capability and record presentation" 'grep -q "id=\"setScopeTab\"[^>]*aria-label=\"分析范围\"" <<<"$HTML" && grep -q "id=\"setCaptureTab\"[^>]*aria-label=\"功能与 Hook 状态\"" <<<"$HTML" && grep -q "id=\"setHooksTab\"[^>]*aria-label=\"记录显示\"" <<<"$HTML" && ! grep -qE "setRecordsTab|setRecordsPage|workbench(-model)?\.js" <<<"$HTML"'
verify_chk "legacy history entry redirects to the viewer" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/workbench?taskId=fixture")" = 302 ]'
verify_chk "settings contains display preferences and connection status" 'grep -q "id=\"setDisplayTab\"[^>]*aria-label=\"显示\"" <<<"$HTML" && grep -q "id=\"setDisplayCap\"" <<<"$HTML" && grep -q "id=\"setTimeFormat\"" <<<"$HTML" && grep -q "id=\"setRowDensity\"" <<<"$HTML" && grep -q "id=\"setStatusTab\"[^>]*aria-label=\"连接与数据\"" <<<"$HTML"'
verify_chk "two-pane settings have group selection counts and a fixed action footer" 'grep -q "class=\"set-sidebar\"" <<<"$HTML" && grep -q "set-group-count" <<<"$HTML" && grep -q "id=\"setObservationFooter\"" <<<"$HTML"'
verify_chk "algorithm-first settings show method metadata with a secondary Hook filter" 'grep -q "id=\"setAlgorithmListTab\"[^>]*aria-pressed=\"true\">按算法</button>" <<<"$HTML" && grep -q "id=\"setHookListTab\"[^>]*>按 Hook</button>" <<<"$HTML" && grep -q "搜索算法、类或方法" <<<"$HTML" && [ "$(curl -s -o /dev/null -w %{http_code} "$BASE/algorithm-observations.js")" = 200 ]'
verify_chk "analysis omits WeChat, MCP onboarding and Hook editor" '! grep -qE "wechat(Btn|Popover)|wechat-follow\.png|公众号|mcp(Btn|Mask|Install|Connect|Config)|/api/mcp/config|hook-plans-panel\.js|AdhHookPlansPanel" <<<"$HTML"'
verify_chk "workbench chrome"     'grep -q "process-trigger" <<<"$HTML" && grep -q "block-copy" <<<"$HTML" && grep -q "jumpLatest" <<<"$HTML" && grep -q "artifactRows" <<<"$HTML"'
# backing endpoints respond (HTTP 200; -F avoids treating [ as a regex)
verify_chk "/api/captures responds" '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/captures")" = 200 ]'
verify_chk "/api/dumps responds"   '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/dumps")" = 200 ]'
verify_chk "/api/agents responds"  '[ "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/agents")" = 200 ]'
verify_chk "/mcp tools/list responds" 'curl -s -X POST "$BASE/mcp" -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" | grep -qF "tools"'
verify_host_finish "v1.0 Web console"
