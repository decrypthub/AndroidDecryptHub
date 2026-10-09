#!/usr/bin/env bash
# v0.2 dump acceptance: memory.search + region dump + sha256 dedup, verified against
# the sandbox's deterministic mock dex (known content -> known sha256).
#   1) search for marker "ADH_MOCK_DEX_v1" -> address
#   2) dump 4096 bytes from (markerAddr - 8) [buffer base] -> file + sha256
#   3) recompute expected sha256 of buildMockDexBytes() and assert equal
#   4) dump again -> dedup=true (same sha, not rewritten)
# Exit 0 = PASS. Prereq: adhd running, device attached, sandbox deployed+running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
import crypto from 'node:crypto';
const http = process.argv[2];
const base = `http://127.0.0.1:${http}`;
const P = (o)=>fetch(`${base}${o.path}`, o.body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o.body)}:{}).then(r=>r.json());

// Expected mock dex bytes (mirror of MainActivity.buildMockDexBytes)
const MOCK=4096, MARKER='ADH_MOCK_DEX_v1';
const exp=Buffer.alloc(MOCK); for(let i=0;i<MOCK;i++) exp[i]=i&0xff;
Buffer.from([0x64,0x65,0x78,0x0a,0x30,0x33,0x35,0x00]).copy(exp,0);
Buffer.from(MARKER,'ascii').copy(exp,8);
const expSha=crypto.createHash('sha256').update(exp).digest('hex');

const agents=await P({path:'/api/agents'});
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).pop();
if(!a){console.log('❌ no agent');console.log('RESULT:FAIL');process.exit(0);}

// 1) search for the UNIQUE magic+marker sequence so the hit is exactly the buffer base
//    (the marker alone also appears as a Java String literal on the dalvik heap).
const seq=Buffer.concat([Buffer.from([0x64,0x65,0x78,0x0a,0x30,0x33,0x35,0x00]), Buffer.from(MARKER,'ascii')]);
const s=await P({path:'/api/memory/search',body:{session:a.sessionId,hex:seq.toString('hex'),limit:16}});
console.log(`search: ok=${s.ok} hits=${s.count}`);
// pick the hit that is NOT on the dalvik heap (the direct ByteBuffer is native memory)
if(!(s.hits||[]).length){console.log('❌ mock dex sequence not found');console.log('RESULT:FAIL');process.exit(0);}
console.log('candidates:', s.hits.map(h=>`${h.addr}(${(h.path||'anon').slice(0,28)})`).join(' '));

// 2+3) dump each candidate; the real 4096-byte direct buffer matches expected sha exactly
let match=null;
for(const h of s.hits){
  const d=await P({path:'/api/memory/dump',body:{session:a.sessionId,addr:h.addr,size:MOCK,tag:'mockdex'}});
  // v4.91: the reply has to say the dump is complete, not just hand back a sha.
  const good = d.sha256===expSha && d.size===MOCK && d.kind==='dex' && d.complete===true && d.requestedSize===MOCK;
  console.log(`  @${h.addr} -> kind=${d.kind} sha=${(d.sha256||'').slice(0,16)}… ${good?'✓ MATCH':''}`);
  if(good){ match=h; break; }
}
const shaPass = !!match;
console.log(`expected sha=${expSha.slice(0,16)}…  ${shaPass?'✓ located byte-exact mock dex':'✗ no candidate matched'}`);

// 4) dedup on re-dump of the matched buffer
let dedupPass=false;
if(match){
  const d2=await P({path:'/api/memory/dump',body:{session:a.sessionId,addr:match.addr,size:MOCK,tag:'mockdex2'}});
  dedupPass = d2.dedup===true && d2.sha256===expSha;
  console.log(`re-dump: dedup=${d2.dedup} ${dedupPass?'✓':'✗'}`);
}

// 5) an unmapped range must not come back as a successful artifact. Take the first >=4 KiB gap
//    between two mapped regions; if the process has none, say so instead of pretending to test.
const maps = await P({path:`/api/process/maps?session=${a.sessionId}`});
const regs = (maps.regions??[]).map(r=>({s:BigInt('0x'+r.start), e:BigInt('0x'+r.end)}))
  .filter(r=>r.e>r.s).sort((x,y)=>(x.s<y.s?-1:(x.s>y.s?1:0)));
let gap=null;
for(let i=0;i+1<regs.length;i++){ if(regs[i+1].s-regs[i].e>=4096n){ gap=regs[i].e; break; } }
let gapPass=null;
if(gap){
  const bad=await P({path:'/api/memory/dump',body:{session:a.sessionId,addr:gap.toString(16),size:4096,tag:'gap'}});
  gapPass = bad.sha256===undefined || bad.complete===false;
  console.log(`unmapped dump: sha=${bad.sha256?'present':'(none)'} complete=${bad.complete ?? '(n/a)'} ${gapPass?'✓ refused/flagged':'✗ looked successful'}`);
} else {
  console.log('unmapped dump: (no >=4 KiB gap in maps, sub-check skipped)');
}

const pass=shaPass && dedupPass && gapPass!==false;
console.log(pass?'✅ v0.2 dump PASS (search + dump + sha256 verified vs known content + dedup)':'❌ v0.2 dump FAIL');
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v0.2 dump (search + dump + sha256 verified vs known content + dedup)" 0 && exit 0 || exit 1
