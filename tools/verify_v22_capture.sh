#!/usr/bin/env bash
# v2.0 WS-C — capture ring buffer: honest accounting, no silent drop.
# The old fixed g_caps[64] silently discarded everything past 64 records and reported success.
# The ring counts every capture() attempt (seq), applies bounded-blocking backpressure, and on
# overflow increments dropped + first/last drop ts — nothing vanishes silently. This test:
#   1) Drives a high-rate burst (20k AES ops) via BurstProbe.run(), triggered from OUTSIDE the
#      agent (idhd passes the class name; the agent has no knowledge of it — WS-B-clean).
#   2) Waits for the agent to finish counting, polling /api/captures `health`.
#   3) Asserts HONEST accounting:
#        - seq >> 64  (thousands of attempts COUNTED, not silently capped)
#        - invariant  emitted + backlog + dropped == seq  (complete accounting; nothing silent)
#        - complete flag consistent with dropped (complete === dropped==0 && jdropped==0)
#      The old impl exposed neither seq nor dropped, so their presence + a large honest seq is
#      itself the proof the silent-drop bug is gone.
# Exit 0 = PASS. Prereq: idhd running, device, sandbox running, capture enabled.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const J=(p,b)=>fetch(`${base}${p}`,b?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}:{}).then(r=>r.json());
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const agents=await J('/api/agents');
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;

// baseline (capture must be on so the persistent EVP hook feeds the ring)
const c0=await J('/api/captures');
console.log(`baseline: on=${c0.on} seq=${c0.seq} total=${c0.total}`);

// fire the burst from outside — class name is a parameter, agent has no BurstProbe knowledge
const trg=await J(`/api/unpack/trigger?session=${sid}&class=com.adh.sandbox.BurstProbe&method=run&level=3`);
console.log(`trigger: loaded=${trg.loaded} invoked=${trg.invoked} result=${trg.result} reason=${trg.reason||''}`);
if(!trg.invoked){ console.log('RESULT:FAIL (burst not invoked)'); process.exit(0); }

// poll until seq stops growing (burst finished + drained)
let h, stable=0, last=-1;
for(let i=0;i<30;i++){
  await sleep(1000);
  const c=await J('/api/captures'); h=c.health;
  console.log(`  t+${i+1}s seq=${h.seq} emitted=${h.emitted} backlog=${h.backlog} dropped=${h.dropped} jdropped=${h.jdropped} accountedFor=${h.accountedFor} complete=${h.complete} total=${c.total}`);
  if(h.seq===last) stable++; else stable=0;
  last=h.seq;
  if(stable>=3 && h.backlog===0) break;   // settled: seq frozen + ring emptied
}

const seqLarge   = h.seq >= 5000;                        // thousands counted (old cap was 64)
const accounted  = (h.emitted + h.backlog + h.dropped) === h.seq;   // nothing silent
const flagHonest = h.complete === (h.dropped===0 && h.jdropped===0);
console.log(`checks: seqLarge=${seqLarge} accounted(emitted+backlog+dropped==seq)=${accounted} flagHonest=${flagHonest}`);
const pass = seqLarge && accounted && flagHonest;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v2.0 WS-C capture ring (high-rate burst: honest seq/dropped, invariant emitted+backlog+dropped==seq, no silent loss)" 1 && exit 0 || exit 1
