#!/usr/bin/env bash
# v1.5 One-click dump-all DEX (device). Enumerates every loaded DexFile via ART structures
# and dumps each region; no T0/T1 snapshots, no coverage pass, no recover/rebuild.
# Asserts: non-empty result, every dex has a valid stored artifact, download works, a second run
# reports SHA-256 dedup, and every entry is CLASSIFIED (classes/methods/carrier) and indexed in the
# same pass - a bare count cannot tell a packer carrier from real code. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# The shape rule (real code vs a packer carrier) is unit tested with a synthetic
# sparse carrier, because the sandbox has no carrier to demonstrate it on.
if ! verify_unit_pass "dex artifact shape rule" dex_artifact_shape.test.ts 4; then
  echo "RESULT:FAIL (dex shape unit tests did not all pass)"
  exit 1
fi

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
// The report must say what each dex IS, not just how many there were: a carrier whose header
// parses looks exactly like real code in a bare count.
const shaped=(r1.dexes||[]).filter(d=>!d.error && typeof d.classes==='number' && typeof d.carrier==='boolean');
const shapeOk = shaped.length === okDex.length && shaped.length >= 1;
// The accounting identity, made non-vacuous: it used to be `realDexCount + carrierCount === dexCount`,
// but realDexCount was itself derived as `dexCount - carrierCount`, so it could never fail — and a run
// where 3 of 4 dexes failed to index satisfied it while looking complete. `unclassified` is the third
// bucket (a daemon ERROR, not a verdict), so a dex nobody accounted for now breaks the sum.
const totalsOk = r1.dexCount===r1.count &&
  r1.realDexCount + r1.carrierCount + (r1.unclassified || 0) === r1.dexCount;
// The sandbox's own dexes are real code, so nothing may be flagged here; the positive case (a
// synthetic sparse carrier) is covered by the unit test above.
const noFalseCarrier = r1.carrierCount === 0 && shaped.every(d=>d.carrier===false);
const indexOk = r1.index && r1.index.built >= 1;
console.log(`shaped=${shaped.length}/${okDex.length} dexCount=${r1.dexCount} real=${r1.realDexCount} carrier=${r1.carrierCount} unclassified=${r1.unclassified ?? 0} indexBuilt=${r1.index?.built} reused=${r1.index?.reused}`);
// Name the reason instead of leaving a bare count mismatch: this is the line that turned four gate
// runs' worth of "intermittent device flake" into a corrupted-SQLite diagnosis.
if (!shapeOk && r1.unclassified > 0) console.log(`  ${r1.unclassified} dex(es) unclassified — ${r1.classifyError ?? 'see per-dex classifyError'}`);
const pass = r1.ok===true && r1.count>=1 && r1.dumped>=1 && r1.failed===0 && dlOk && dedupOk &&
  shapeOk && totalsOk && noFalseCarrier && !!indexOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.5 one-click dump-all DEX (ART DexFile 枚举 → dump → 去重 → 下载 → 逐 dex 分类/索引)" 0 && exit 0 || exit 1
