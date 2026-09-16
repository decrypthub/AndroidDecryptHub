#!/usr/bin/env bash
# v0.4 GOT hook engine self-test. Prereq: adhd running, device, sandbox running.
#   Hooks the agent's own close() GOT slot, triggers a close, asserts:
#   replaced>=1 (slot found+swapped) AND fired (wrapper ran) AND process alive
#   (proves interception + trampoline-through-to-original without crash/hang).
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/hook/selftest?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`gothook: replaced=${r.replaced} fired=${r.fired} hits=${r.hitsAfter-r.hitsBefore}`);
console.log(`page prot: orig=${r.origPerms} afterHook=${r.slotPerms} restored=${r.protRestored}`);
// protRestored proves the page protection was put back after the swap (RELRO r-- stays
// r--) — no rw-flipped page left behind. Also assert the hooked slot is NOT writable now.
const notWritable = typeof r.slotPerms==='string' && r.slotPerms[1]==='-';
const pass = r.ok && r.replaced>=1 && r.fired===true && r.protRestored===true && notWritable;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.4 GOT hook engine (intercept + trampoline, no crash)" 1 && exit 0 || exit 1
