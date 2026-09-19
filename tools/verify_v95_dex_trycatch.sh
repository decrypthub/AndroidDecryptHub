#!/usr/bin/env bash
# v2.4 WS-E slice 1 (HOST-ONLY): methods with try/catch are no longer silently skipped.
#
# The old code_item reader stopped at the insns and returned "" for every method with tries>0
# (1166 of 46228 concrete methods in the sandbox dex) - so those methods could never be injected
# or recovered while the recovery report still read 100%. This asserts:
#   - coverage counts an unwalkable code_item as `unresolvable`, never as present;
#   - a try/catch method's code_item is walked past the insns to the end of its handler list;
#   - strip -> missing -> recover -> rebuild keeps the WHOLE item byte-identical
#     (insns + padding + tries[] + encoded_catch_handler_list);
#   - the rebuilder refuses a truncated capture (HTTP 422) instead of appending half an item.
# Exit 0 = PASS.
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
const orig=readFileSync(dexPath).toString('base64');
const post=async(p,b)=>(await (await fetch(base+p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)})).json());
const postRaw=(p,b)=>fetch(base+p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});

// 1) coverage must not claim a method whose code_item it cannot walk
const cov=await post('/api/dex/coverage',{b64:orig});
console.log(`coverage: concreteJava=${cov.concreteJava} present=${cov.basePresent} empty=${cov.baseEmpty} unresolvable=${cov.unresolvable} rate=${cov.recoveryPct}%`);
const covOk = cov.concreteJava>0 && cov.basePresent>0 && cov.unresolvable===0;

// 2) a try/catch method carries its FULL code_item (the insns tail is part of it)
const mc=await post('/api/dex/method_code',{b64:orig,class:'/',limit:5000});
const pick=(mc.methods||[]).find(m=>m.tries>0 && m.codeItemHex && m.insnsSize>0);
if(!pick){ console.log('no try/catch method found'); console.log('RESULT:FAIL'); process.exit(0); }
const itemBytes=pick.codeItemHex.length/2, insnsBytes=pick.insnsSize*2;
const fullItemOk = itemBytes > 16 + insnsBytes;
console.log(`target: ${pick.method} midx=${pick.midx} tries=${pick.tries} item=${itemBytes}B (insns ${insnsBytes}B, tail ${itemBytes-16-insnsBytes}B)`);

// 3) strip it -> the method is missing, not "present"
const st=await post('/api/dex/strip',{b64:orig,midx:pick.midx});
const cov2=await post('/api/dex/coverage',{b64:st.b64,limitMissing:5000});
const isMissing=(cov2.missing||[]).some(m=>m.midx===pick.midx);
console.log(`stripped: empty=${cov2.baseEmpty} targetMissing=${isMissing}`);

// 4) recover it from the restored image and rebuild
const rec=await post('/api/dex/recover',{baseB64:st.b64,restoredB64:orig});
const recOk = rec.ok===true && rec.recovered>=1 && rec.parseOk===true && Array.isArray(rec.unresolvable) && rec.unresolvable.length===0;
console.log(`recover: recovered=${rec.recovered} stillMissing=${rec.stillMissing} injected=${rec.injected} parseOk=${rec.parseOk} unresolvable=${(rec.unresolvable||[]).length}`);

// 5) the whole item (insns + tries[] + handler list) must round-trip byte-identically
let rtOk=false, triesOk=false;
if(rec.sha256){
  const mc2=await post('/api/dex/method_code',{sha:rec.sha256,class:'/',limit:5000});
  const same=(mc2.methods||[]).find(m=>m.midx===pick.midx);
  rtOk = !!same && same.codeItemHex===pick.codeItemHex;
  triesOk = !!same && same.tries===pick.tries && same.insnsHex===pick.insnsHex;
  console.log(`roundtrip: full item ${rtOk?'MATCH':'MISMATCH'} (${((same&&same.codeItemHex)||'').length/2}B) tries ${triesOk?'MATCH':'MISMATCH'}`);
}

// 6) negative control: half an item must be refused, not appended
let rejOk=false;
if(pick.codeItemHex.length>8){
  const r=await postRaw('/api/dex/rebuild',{b64:orig,captures:[{midx:pick.midx,codeItemHex:pick.codeItemHex.slice(0,-2)}]});
  const body=await r.json().catch(()=>({}));
  rejOk = r.status===422 && /not a complete code_item/.test(String(body.error||''));
  console.log(`negative control: truncated capture -> HTTP ${r.status} ${rejOk?'(refused)':'(NOT refused)'}`);
}

const pass = covOk && fullItemOk && isMissing && recOk && rtOk && triesOk && rejOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v2.4 WS-E try/catch code_item (完整读取 + 重建字节一致 + 半截件被拒)" 0 && exit 0 || exit 1
