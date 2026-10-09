#!/usr/bin/env bash
# v0.3 acceptance — ART structural dex capture. Prereq: adhd running, device attached, sandbox running.
#   (1) java_call: the agent reflects System.getProperty from a native thread through the app
#       ClassLoader -> the SDK it reads must equal the device's actual SDK
#   (2) art_dexfiles: structural enumeration (ClassLoader cookie -> art::DexFile* -> begin_),
#       no magic scan; must find the 728-byte probe dex under InMemoryDexClassLoader
#   (3) art dump: dump the probe dex from begin -> sha256 == known d8 output (byte-exact)
# Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
KNOWN_SHA="b10aea0308a7e7ccaa100a5cb53a0bfdec74c1f2dfe9184c256edd673339df6b"
# Expected SDK = whatever the target device reports (works on SDK 35 / 36 / any).
SDK_EXP="${ADH_SDK:-$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')}"

set +e
OUT="$(node - "$HTTP" "$KNOWN_SHA" "$SDK_EXP" <<'EOF'
const [http, knownSha, sdkExp] = process.argv.slice(2);
const base=`http://127.0.0.1:${http}`;
const P=(o)=>fetch(`${base}${o.path}`,o.body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o.body)}:{}).then(r=>r.json());
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const agents=await P({path:'/api/agents'});
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}

// (1) JNI foundation — the agent reflects through the app ClassLoader from a native thread and
//     reads a value the DEVICE independently reports. NOTE on the route (2026-10-01):
//     System.getProperty("ro.build.version.sdk") is NOT how Android exposes system properties
//     (that is android.os.SystemProperties), so it answers null; the SDK level lives in the
//     static field android.os.Build$VERSION.SDK_INT, which object_inspect reads as the boxed
//     Integer it is (fields[].value on java.lang.Integer).
const jc=await rpc('tools/call',{name:'java_call',arguments:{session:a.sessionId,className:'java.lang.System',method:'getProperty',params:'java.lang.String',args:['java.vm.version']}});
const jr=JSON.parse(jc.result?.content?.[0]?.text ?? 'null');
const vmVer=jr?.result?.result;
const oi=await rpc('tools/call',{name:'object_inspect',arguments:{session:a.sessionId,className:'android.os.Build$VERSION',field:'SDK_INT'}});
const ob=JSON.parse(oi.result?.content?.[0]?.text ?? 'null');
const sdkField=(ob?.fields||[]).find(f=>f.name==='value');
const jSdk=Number(sdkField?.value);
console.log(`java_call System.getProperty(java.vm.version): ok=${jr?.ok} vm=${vmVer}`);
console.log(`object_inspect Build$VERSION.SDK_INT: objectClass=${ob?.objectClass} value=${sdkField?.value} (device reports ${sdkExp})`);
const jniPass = jr?.ok===true && /^\d+\.\d+/.test(String(vmVer||''))
             && ob?.ok===true && !!sdkExp && jSdk===Number(sdkExp);

// (2) ART structural enumeration
const r=await P({path:`/api/art/dexfiles?session=${a.sessionId}`});
console.log(`art_dexfiles: ok=${r.ok} loaders=${r.loaders} dexfiles=${r.count}`);
(r.dexfiles||[]).forEach(x=>console.log(`   ${x.magic} size=${x.size} begin=${x.begin} ${x.loader}`));
const probe=(r.dexfiles||[]).find(x=>x.size===728 && /InMemoryDexClassLoader/.test(x.loader));
const enumPass = r.ok && r.count>=1 && !!probe;
console.log(`probe dex via InMemoryDexClassLoader: ${probe?'FOUND @'+probe.begin:'MISSING'}`);

// (3) structural dump + sha256 vs known
let dumpPass=false;
if(probe){
  const d=await P({path:'/api/art/dump',body:{session:a.sessionId,begin:probe.begin,size:probe.size}});
  console.log(`art dump: kind=${d.kind} size=${d.size} sha=${(d.sha256||'').slice(0,16)}…`);
  dumpPass = d.sha256===knownSha && d.kind==='dex' && d.size===728;
  console.log(`sha256 == known d8 dex: ${d.sha256===knownSha}`);
}

const pass = jniPass && enumPass && dumpPass;
console.log(pass?'✅ v0.3 PASS (JNI + ART structural dex capture, byte-exact)':'❌ v0.3 FAIL');
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
echo "$OUT" | grep -q 'RESULT:PASS' && exit 0 || exit 1
