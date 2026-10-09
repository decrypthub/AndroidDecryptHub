#!/usr/bin/env bash
# v0.1 acceptance: build agent + sandbox, deploy to device, launch via 模拟注入,
# confirm the agent registers with adhd and every sampled /proc/self/maps region
# matches the kernel verbatim. Exit 0 = PASS.
#
# Prereq: adhd running on host (cd daemon && node src/index.ts), and a device attached.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}}"
HTTP="${ADH_HTTP_PORT:-8088}"
AGENT="${ADH_AGENT_PORT:-8761}"
JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Android\\Android Studio\\jbr}"; export JAVA_HOME
PKG=com.adh.sandbox

echo ">> device: $SERIAL"
bash "$ROOT/tools/build_agent.sh"

echo ">> building sandbox APK"
( cd "$ROOT/sandbox-app" && ./gradlew :app:assembleDebug --console=plain >/dev/null )
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"

echo ">> deploy + launch"
adb -s "$SERIAL" reverse tcp:$AGENT tcp:$AGENT >/dev/null
install_apk_root "$APK" /data/local/tmp/adh-sandbox.apk "$SERIAL" >/dev/null
adb -s "$SERIAL" shell am force-stop $PKG
adb -s "$SERIAL" shell am start -n $PKG/.MainActivity >/dev/null
sleep 4

PID=$(adb -s "$SERIAL" shell pidof $PKG | tr -d '\r ')
echo ">> app pid=$PID"
adb -s "$SERIAL" shell su -c "cat /proc/$PID/maps" 2>/dev/null | tr -d '\r' > "$ROOT/_kmaps.txt"

node - "$ROOT/_kmaps.txt" "$HTTP" <<'EOF'
import fs from 'node:fs';
const [file, http] = process.argv.slice(2);
const kmaps = fs.readFileSync(file,'utf8').split('\n');
const list = await (await fetch(`http://127.0.0.1:${http}/api/agents`)).json();
const a = list.filter(x=>x.package==='com.adh.sandbox'&&x.online).pop();
if(!a){ console.log('❌ agent not registered in adhd'); process.exit(1); }
const s = a.regionsSample||[];
const ok = s.filter(r=>kmaps.some(l=>l.startsWith(`${r.start}-${r.end} ${r.perms}`))).length;
console.log(`agent: pid=${a.pid} abi=${a.abi} android=${a.android} sdk=${a.sdk} entry=${a.entry} mapsCount=${a.mapsCount}`);
console.log(`kernel maps lines=${kmaps.filter(Boolean).length} | sampled=${s.length} | verbatim-match=${ok}`);
const pass = a.online && ok===s.length && s.length>0 && a.mapsCount>100;
console.log(pass ? '✅ v0.1 PASS' : '❌ v0.1 FAIL');
process.exit(pass?0:1);
EOF
RC=$?
rm -f "$ROOT/_kmaps.txt"
exit $RC
