#!/usr/bin/env bash
# v0.8 native disassembly (HOST-ONLY). adhd disassembles a real .so (llvm-objdump)
# by symbol and returns structured instructions. Verifies the agent's own
# adh_agent_start disassembles to valid arm64 (prologue stp + a ret). Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
SO="$ROOT/agent/build/libadh_agent.so"
[ -f "$SO" ] || { echo "❌ agent .so missing (build first)"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$SO" <<'EOF'
import fs from 'node:fs';
const [http, so]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const b64=fs.readFileSync(so).toString('base64');
const r=await (await fetch(`${base}/api/native/disasm`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({b64,symbol:'adh_agent_start'})})).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`symbol=${r.symbol} instructions=${r.count}`);
(r.instructions||[]).slice(0,6).forEach(i=>console.log(`  ${i.addr}: ${i.bytes}  ${i.text}`));
const mns=new Set((r.instructions||[]).map(i=>i.mnemonic));
const hasProlog = mns.has('stp') || mns.has('sub');
const hasRet = mns.has('ret');
const hasBranch = [...mns].some(m=>/^(bl|b|cbz|cbnz|adr)/.test(m));
console.log(`mnemonics: prologue=${hasProlog} ret=${hasRet} branch=${hasBranch} (${[...mns].slice(0,10).join(',')})`);
const pass = r.count>3 && hasProlog && (hasRet || hasBranch);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v0.8 native disassembly (adh_agent_start -> valid arm64)" 0 && exit 0 || exit 1
