#!/usr/bin/env bash
# v1.2 Unpack foundation (HOST-ONLY): method-gap/coverage report + structural DEX
# rebuilder. Uses the app's real classes.dex (from the debug APK). Asserts:
#   - coverage report is honest (total/concreteJava/basePresent computed; recovery rate)
#   - the rebuilder merges a captured CodeItem into the base dex, the result PARSES, and
#     the injected method's bytecode round-trips byte-identical (structural correctness).
# This is the "index + rebuilder" foundation (no live packer needed). Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
DEX="/tmp/base.dex"
[ -s "$DEX" ] || unzip -p "$APK" classes.dex > "$DEX" 2>/dev/null
[ -s "$DEX" ] || { echo "no base dex (build the app first)"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$DEX" <<'EOF'
const http=process.argv[2], dexPath=process.argv[3];
const base=`http://127.0.0.1:${http}`;
const { readFileSync }=await import('node:fs');
const b64=readFileSync(dexPath).toString('base64');
const post=async(path,body)=>(await (await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})).json());

// 1) coverage report
const cov=await post('/api/dex/coverage',{b64,limitMissing:5});
console.log(`coverage: total=${cov.total} concreteJava=${cov.concreteJava} basePresent=${cov.basePresent} baseEmpty=${cov.baseEmpty} native=${cov.native} abstract=${cov.abstract} recovery=${cov.recoveryPct}%`);
const covOk = cov.total>0 && cov.concreteJava>0 && cov.basePresent>0 && typeof cov.recoveryPct==='number';

// 2) pick a concrete method with a full code_item (no tries) to inject
const mc=await post('/api/dex/method_code',{b64,class:'/'});
const list=mc.methods||[];
const pick=list.find(m=>m.codeItemHex && m.insnsSize>0 && m.tries===0);
if(!pick){ console.log('no injectable method found', JSON.stringify(mc).slice(0,200)); console.log('RESULT:FAIL'); process.exit(0); }
console.log(`inject: ${pick.method} midx=${pick.midx} insnsSize=${pick.insnsSize}`);

// 3) rebuild base dex with that captured code_item
const rb=await post('/api/dex/rebuild',{b64,captures:[{midx:pick.midx,codeItemHex:pick.codeItemHex}]});
console.log(`rebuild: injected=${rb.injected} classesRewritten=${rb.classesRewritten} parseOk=${rb.parseOk} methods=${rb.methods} sha=${(rb.sha256||'').slice(0,16)}`);
const rebuildOk = rb.ok && rb.parseOk===true && rb.injected>=1 && rb.sha256;

// 4) round-trip: the injected method's bytecode in the rebuilt dex must match the original
let rtOk=false;
if(rb.sha256){
  const mc2=await post('/api/dex/method_code',{sha:rb.sha256,class:'/'});
  const same=(mc2.methods||[]).find(m=>m.midx===pick.midx);
  rtOk = !!same && same.insnsHex===pick.insnsHex;
  console.log(`roundtrip: rebuilt method insns ${rtOk?'MATCH':'MISMATCH'} (${(same&&same.insnsHex||'').length/2}B)`);
}
console.log((covOk&&rebuildOk&&rtOk)?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v1.2 unpack foundation (覆盖率报告 + 结构化重建器: 注入 CodeItem → 可解析 → 字节码一致)" 0 && exit 0 || exit 1
