#!/usr/bin/env bash
# Load frida-gadget into the target (com.adh.sandbox) and auto-run a frida script — via the
# agent's load_so, no repackaging. Uses root (su) to place the files in an exec-allowed
# path and fix the SELinux label. Internal test only.
#
# Usage: tools/load_frida_gadget.sh <gadget-arm64.so> <hook.js> [package]
#   <gadget.so>  a frida-gadget-*-android-arm64.so (download from frida releases)
#   <hook.js>    your frida script (Interceptor/Java.perform/Stalker …)
#
# What it does:
#   1. push gadget.so + a script-mode config + hook.js into the app's code_cache
#   2. chcon them to the app's exec context (root)
#   3. POST /api/agent/load_so → agent dlopen()s the gadget → gadget auto-runs hook.js
set -euo pipefail
GADGET="${1:?need path to frida-gadget arm64 .so}"
SCRIPT="${2:?need path to a frida .js}"
PKG="${3:-com.adh.sandbox}"
HTTP="${IDH_HTTP_PORT:-8760}"
[ -f "$GADGET" ] || { echo "no gadget: $GADGET"; exit 1; }
[ -f "$SCRIPT" ] || { echo "no script: $SCRIPT"; exit 1; }

DIR="/data/data/$PKG/code_cache"
GNAME="libgadget.so"
echo ">> staging into $DIR (root)"
adb push "$GADGET" "/data/local/tmp/$GNAME" >/dev/null
adb push "$SCRIPT" "/data/local/tmp/idh_hook.js" >/dev/null
# script-mode config: gadget looks for <soname-without-.so>.config.so next to itself
cat > /tmp/libgadget.config <<JSON
{ "interaction": { "type": "script", "path": "$DIR/idh_hook.js", "on_change": "reload" } }
JSON
adb push /tmp/libgadget.config "/data/local/tmp/libgadget.config.so" >/dev/null

adb shell "su 0 sh -c '
  mkdir -p $DIR
  cp /data/local/tmp/$GNAME $DIR/$GNAME
  cp /data/local/tmp/idh_hook.js $DIR/idh_hook.js
  cp /data/local/tmp/libgadget.config.so $DIR/libgadget.config.so
  chown $(adb shell stat -c %U $DIR 2>/dev/null | tr -d "\r"): $DIR/* 2>/dev/null || true
  CTX=\$(ls -Zd $DIR | awk "{print \$1}")
  chcon \$CTX $DIR/$GNAME $DIR/libgadget.config.so $DIR/idh_hook.js 2>/dev/null || true
'" || echo "!! root staging had warnings (check SELinux)"

SID=$(curl -s "http://127.0.0.1:$HTTP/api/agents" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const a=JSON.parse(s);const x=a.filter(y=>y.online&&y.package==='$PKG').sort((p,q)=>q.connectedAt-p.connectedAt)[0];console.log(x?x.sessionId:'')})")
[ -n "$SID" ] || { echo "no online agent for $PKG"; exit 1; }
echo ">> load_so $DIR/$GNAME  (session $SID)"
curl -s -X POST "http://127.0.0.1:$HTTP/api/agent/load_so" -H 'content-type: application/json' \
  -d "{\"session\":\"$SID\",\"path\":\"$DIR/$GNAME\",\"symbol\":\"frida_agent_main\"}"
echo
echo ">> if ok=true, the gadget is in-process and running $DIR/idh_hook.js"
echo "   (若 SELinux 挡执行：adb shell 'su 0 setenforce 0' 后重试——内网测试可接受)"
