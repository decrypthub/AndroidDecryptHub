#!/usr/bin/env bash
# v0.3 acceptance — ART structural dex capture. Prereq: idhd running, device attached, sandbox running.
#   (1) jni_probe: agent JNI reflection from native thread -> SDK_INT==36
#   (2) art_dexfiles: structural enumeration (ClassLoader cookie -> art::DexFile* -> begin_),
#       no magic scan; must find the 728-byte probe dex under InMemoryDexClassLoader
#   (3) art dump: dump the probe dex from begin -> sha256 == known d8 output (byte-exact)
# Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
KNOWN_SHA="b10aea0308a7e7ccaa100a5cb53a0bfdec74c1f2dfe9184c256edd673339df6b"

set +e
OUT="$(node - "$HTTP" "$KNOWN_SHA" <<'EOF'
const [http, knownSha] = process.argv.slice(2);
const base=`http://127.0.0.1:${http}`;
const P=(o)=>fetch(`${base}${o.path}`,o.body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o.body)}:{}).then(r=>r.json());
const agents=await P({path:'/api/agents'});
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}

// (1) JNI foundation
const j=await P({path:`/api/jni/probe?session=${a.sessionId}`});
console.log(`jni_probe: ok=${j.ok} sdk_int=${j.sdk_int}`);
const jniPass = j.ok && j.sdk_int===36;

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
