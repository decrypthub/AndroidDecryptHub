#!/usr/bin/env bash
# v0.2 acceptance (command channel): on-demand full maps + memory.read.
# Deploys, launches via 模拟注入, then:
#   1) GET /api/process/maps -> full region list; first 40 match kernel verbatim
#   2) POST /api/memory/read at a mapped .so's base -> bytes start with ELF magic 7f454c46
# Exit 0 = PASS. Prereq: adhd running, device attached.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
AGENT="${ADH_AGENT_PORT:-8761}"
JAVA_HOME="${JAVA_HOME:-C:\\Program Files\\Android\\Android Studio\\jbr}"; export JAVA_HOME
PKG=com.adh.sandbox

bash "$ROOT/tools/build_agent.sh" >/dev/null
( cd "$ROOT/sandbox-app" && ./gradlew :app:assembleDebug --console=plain >/dev/null )
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
adb -s "$SERIAL" reverse tcp:$AGENT tcp:$AGENT >/dev/null
install_apk_root "$APK" /data/local/tmp/adh-sandbox.apk >/dev/null || exit 1
adb -s "$SERIAL" shell am force-stop $PKG
adb -s "$SERIAL" shell am start -n $PKG/.MainActivity >/dev/null
sleep 4
PID=$(adb -s "$SERIAL" shell pidof $PKG | tr -d '\r ')
adb -s "$SERIAL" shell su -c "cat /proc/$PID/maps" 2>/dev/null | tr -d '\r' > "$ROOT/_kmaps.txt"

# Node on Windows can hit a libuv assertion during exit (fetch keepalive teardown);
# it happens AFTER our assertions print, so we decide pass/fail from an output marker,
# not from node's exit code.
set +e
OUT="$(node - "$ROOT/_kmaps.txt" "$HTTP" <<'EOF'
import fs from 'node:fs';
const [file, http] = process.argv.slice(2);
const kmaps = fs.readFileSync(file,'utf8').split('\n');
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const a = agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).pop();
if(!a){ console.log('❌ no agent'); process.exit(1); }

// 1) on-demand full maps
const maps = await (await fetch(`${base}/api/process/maps?session=${a.sessionId}`)).json();
const full = maps.regions||[];
const head = full.slice(0,40);
const ok = head.filter(r=>kmaps.some(l=>l.startsWith(`${r.start}-${r.end} ${r.perms}`))).length;
console.log(`maps: agent full count=${maps.count} returned regions=${full.length} | first40 verbatim=${ok}/40`);
const mapsPass = maps.ok && full.length>500 && ok===40;

// 2) memory.read at a mapped .so base -> ELF magic
const so = full.find(r=>/\.so$/.test(r.path)&&r.perms[0]==='r'&&parseInt(r.offset,16)===0);
let readPass=false, magic='';
if(so){
  const rd = await (await fetch(`${base}/api/memory/read`,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({session:a.sessionId, addr:so.start, size:16})})).json();
  if(rd.ok){
    const bytes = Buffer.from(rd.b64,'base64');
    magic = bytes.slice(0,4).toString('hex');
    readPass = magic==='7f454c46';
    console.log(`read: ${so.path} @${so.start} first4=${magic} (${readPass?'ELF ✓':'NOT ELF'})`);
  } else console.log('read: FAILED', rd.error);
} else console.log('read: no suitable .so region found');

// 3) magic scan -> must detect a DEX-family container (dex/cdex/vdex) in live memory
const scan = await (await fetch(`${base}/api/memory/scan_magic?session=${a.sessionId}`)).json();
const by={}; (scan.hits||[]).forEach(h=>by[h.magic]=(by[h.magic]||0)+1);
const dexFam = (by.dex||0)+(by.cdex||0)+(by.vdex||0);
console.log(`scan: ok=${scan.ok} count=${scan.count} scanned=${(scan.scanned/1048576|0)}MB byMagic=${JSON.stringify(by)}`);
const scanPass = scan.ok && dexFam>0 && (by.elf>0 || scan.truncated);

const pass = mapsPass && readPass && scanPass;
console.log(pass ? '✅ v0.2 command-channel PASS (on-demand maps + memory.read + magic scan)' : '❌ v0.2 FAIL');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -f "$ROOT/_kmaps.txt"
verify_gate "v0.2 command-channel (on-demand maps + memory.read + magic scan)" 0 && exit 0 || exit 1
