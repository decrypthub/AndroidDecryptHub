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
OUT="$(node - "$HTTP" "$DEX" "$ROOT" <<'EOF'
const http=process.argv[2], dexPath=process.argv[3], rootPath=process.argv[4];
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

// 6) a method whose code_off points at a broken item is reported per method, never as a 500 or as
//    "recovered": corrupt one code_off uleb (same byte length, value past the file) and check the
//    route's recovered/empty/unresolvable partition plus the coverage counters.
const { parseDex, extractMethodCode, analyzeCoverage } = await import('file:///' + String(rootPath).replace(/\\/g, '/').replace(/^\//, '') + '/daemon/src/dex.ts');
const raw = Buffer.from(orig, 'base64');
const uleb = (buf, p) => { let r = 0, s = 0, b; do { b = buf[p++]; r |= (b & 0x7f) << s; s += 7; } while (b & 0x80); return [r >>> 0, p]; };
function findCodeOff(buf, wanted) {
  const u32 = (o) => buf.readUInt32LE(o);
  const n = u32(96), off = u32(100);
  for (let i = 0; i < n; i++) {
    const cdOff = u32(off + i * 32 + 24); if (!cdOff) continue;
    let p = cdOff, sf, inf, dm, vm;
    [sf, p] = uleb(buf, p); [inf, p] = uleb(buf, p); [dm, p] = uleb(buf, p); [vm, p] = uleb(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = uleb(buf, p); [, p] = uleb(buf, p); }
    for (const count of [dm, vm]) {
      let mi = 0;
      for (let k = 0; k < count; k++) {
        let diff, af, co; [diff, p] = uleb(buf, p); mi += diff; [af, p] = uleb(buf, p);
        const pos = p; [co, p] = uleb(buf, p);
        // Only a 4-byte uleb is useful: its maximum value (2^28-1) lies beyond the file, so the
        // corrupted code_off is guaranteed to point outside the buffer. A 3-byte maximum can still
        // land inside the file and parse as garbage - the GIGO case, not the bug under test.
        if (mi === wanted && co && p - pos >= 4) return { pos, len: p - pos };
      }
    }
  }
  return null;
}
// Any method with a 4-byte code_off uleb will do; its midx is what the assertions below use.
let wanted = -1;
for (const c of (mc.methods || [])) { if (findCodeOff(raw, c.midx)) { wanted = c.midx; break; } }
const target = wanted >= 0 ? findCodeOff(raw, wanted) : null;
let corruptOk = false, routeOk = false, covOk2 = false;
if (target) {
  const bad = Buffer.from(raw);
  const maxForLen = Math.pow(2, 7 * target.len) - 1;              // largest value the uleb can hold
  let v = maxForLen, p = target.pos;
  for (let i = 0; i < target.len; i++) { bad[p++] = (v & 0x7f) | (i === target.len - 1 ? 0 : 0x80); v = Math.floor(v / 128); }
  const entries = extractMethodCode(bad, parseDex(bad), '/');
  const entry = entries.find((c) => c.midx === wanted);
  corruptOk = !!entry && !entry.codeItemHex && !!entry.unresolvable;   // per-method reason, not a throw
  const covBad = analyzeCoverage(bad, parseDex(bad));
  covOk2 = covBad.unresolvable >= 1 && covBad.missingTotal >= 1 && covBad.basePresent === cov.basePresent - 1;
  const r = await post('/api/dex/method_code', { b64: bad.toString('base64'), class: '/', limit: 1 });
  const sum = Number(r.recovered) + Number(r.empty) + Number(r.unresolvable);
  routeOk = r.recovered !== undefined && sum === Number(r.count) && Number(r.unresolvable) >= 1;
  console.log(`corrupt code_off: entryUnresolvable=${corruptOk} coverageUnresolvable=${covBad.unresolvable} missingTotal=${covBad.missingTotal} routeSum=${sum}/${r.count} routeUnresolvable=${r.unresolvable}`);
} else {
  console.log('corrupt code_off: could not locate a code_off uleb');
}

// 7) negative control: half an item must be refused, not appended
let rejOk=false;
if(pick.codeItemHex.length>8){
  const r=await postRaw('/api/dex/rebuild',{b64:orig,captures:[{midx:pick.midx,codeItemHex:pick.codeItemHex.slice(0,-2)}]});
  const body=await r.json().catch(()=>({}));
  rejOk = r.status===422 && /not a complete code_item/.test(String(body.error||''));
  console.log(`negative control: truncated capture -> HTTP ${r.status} ${rejOk?'(refused)':'(NOT refused)'}`);
}

const pass = covOk && fullItemOk && isMissing && recOk && rtOk && triesOk && rejOk && corruptOk && routeOk && covOk2;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v2.4 WS-E try/catch code_item (完整读取 + 重建字节一致 + 半截件被拒)" 0 && exit 0 || exit 1
