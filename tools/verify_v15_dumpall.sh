#!/usr/bin/env bash
# v1.5 One-click dump-all DEX (device). Enumerates every loaded DexFile via ART structures
# and dumps each region; no T0/T1 snapshots, no coverage pass, no recover/rebuild.
# Asserts: non-empty result, every dex has a valid stored artifact, download works, and a
# second run reports SHA-256 dedup. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const dump=async()=> (await fetch(`${base}/api/unpack/dump-all`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({session:a.sessionId})})).json();
const r1=await dump();
if(r1.error){console.log('ERR',r1.error);console.log('RESULT:FAIL');process.exit(0);}
const okDex=(r1.dexes||[]).filter(d=>!d.error && d.sha256);
console.log(`count=${r1.count} dumped=${r1.dumped} deduped=${r1.deduped} failed=${r1.failed}`);
for(const d of okDex.slice(0,3)) console.log(`  [${d.format}] ${d.size}B @${d.begin} sha=${d.sha256.slice(0,16)}`);
const sample=okDex[0];
const dl=sample ? await fetch(`${base}/api/dumps/download?sha=${sample.sha256}`) : null;
const dlOk=!!dl && dl.ok && Number((await dl.arrayBuffer()).byteLength)===sample.bytes;
const r2=await dump();
const dedupOk=(r2.deduped||0)>=1;
console.log(`download=${dlOk} secondRunDedup=${dedupOk}`);
const pass = r1.ok===true && r1.count>=1 && r1.dumped>=1 && r1.failed===0 && dlOk && dedupOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.5 one-click dump-all DEX (ART DexFile 枚举 → dump → SHA-256 去重 → 下载)" 0 && exit 0 || exit 1
