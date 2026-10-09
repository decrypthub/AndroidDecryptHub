#!/usr/bin/env bash
# v1.3 Gen-2 recovery loop (HOST-ONLY). Simulates an extraction shell on the app's real
# classes.dex: strip one method's code (code_off=0), then RECOVER it by lifting the
# CodeItem out of a RESTORED snapshot (here the original image) and rebuilding. Asserts the
# stripped method is BASE_EMPTY, recovery captures it, the rebuilt dex parses, and the
# recovered method's bytecode is byte-identical. This exercises the whole capture→rebuild
# pipeline (the design's P1) with a deterministic signal — no live packer needed.
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
DEX="/tmp/base.dex"
[ -s "$DEX" ] || unzip -p "$APK" classes.dex > "$DEX" 2>/dev/null
[ -s "$DEX" ] || { echo "no base dex"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$DEX" <<'EOF'
const http=process.argv[2], dexPath=process.argv[3];
const base=`http://127.0.0.1:${http}`;
const { readFileSync }=await import('node:fs');
const orig=readFileSync(dexPath).toString('base64');
const post=async(p,b)=>(await (await fetch(base+p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)})).json());

// 1) pick a concrete method with a full code_item (no tries)
const mc=await post('/api/dex/method_code',{b64:orig,class:'/'});
const pick=(mc.methods||[]).find(m=>m.codeItemHex && m.insnsSize>0 && m.tries===0);
if(!pick){ console.log('no method'); console.log('RESULT:FAIL'); process.exit(0); }
console.log(`target: ${pick.method} midx=${pick.midx} insns=${pick.insnsSize*2}B`);

// 2) simulate extraction: strip its code_off
const st=await post('/api/dex/strip',{b64:orig,midx:pick.midx});
if(!st.ok){ console.log('strip failed'); console.log('RESULT:FAIL'); process.exit(0); }

// 3) coverage on the stripped base must show the method as missing (BASE_EMPTY)
const cov=await post('/api/dex/coverage',{b64:st.b64,limitMissing:5000});
const isMissing=(cov.missing||[]).some(m=>m.midx===pick.midx);
console.log(`stripped coverage: baseEmpty=${cov.baseEmpty} recovery=${cov.recoveryPct}% targetMissing=${isMissing}`);

// 4) recover: lift the CodeItem from the RESTORED snapshot (original image) + rebuild
const rec=await post('/api/dex/recover',{baseB64:st.b64, restoredB64:orig});
console.log(`recover: recovered=${rec.recovered} stillMissing=${rec.stillMissing} injected=${rec.injected} parseOk=${rec.parseOk} sha=${(rec.sha256||'').slice(0,16)}`);

// 5) the recovered method's bytecode must be byte-identical to the original
let rtOk=false;
if(rec.sha256){
  const mc2=await post('/api/dex/method_code',{sha:rec.sha256,class:'/'});
  const same=(mc2.methods||[]).find(m=>m.midx===pick.midx);
  rtOk=!!same && same.insnsHex===pick.insnsHex;
  console.log(`recovered method bytecode ${rtOk?'MATCH':'MISMATCH'}`);
}
const pass = isMissing && rec.ok && rec.recovered>=1 && rec.parseOk===true && rtOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.3 gen-2 recovery (抽取→从恢复镜像捕获 CodeItem→重建→字节码一致)" 0 && exit 0 || exit 1
