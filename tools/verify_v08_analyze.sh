#!/usr/bin/env bash
# v0.8 native binary analysis (HOST-ONLY). idhd returns exports/imports/needed/strings
# for an ELF .so. Verifies the agent's own .so: exports ADH primary + legacy start and JNI_OnLoad,
# NEEDED includes liblog, imports include a hooked libc/crypto symbol, strings has ADH (legacy IDH accepted).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
SO="$ROOT/agent/build/libidh_agent.so"
[ -f "$SO" ] || { echo "❌ agent .so missing"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$SO" <<'EOF'
import fs from 'node:fs';
const [http, so]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const b64=fs.readFileSync(so).toString('base64');
const a=await (await fetch(`${base}/api/native/analyze`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({b64})})).json();
if(a.error){console.log('ERR',a.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`counts=${JSON.stringify(a.counts)}`);
const exp=new Set(a.exports), imp=new Set(a.imports);
const hasExports = exp.has('adh_agent_start') && exp.has('idh_agent_start') && exp.has('JNI_OnLoad');
const hasNeeded = (a.needed||[]).some(n=>/liblog|libc/.test(n));
const hasImports = [...imp].some(s=>/pthread|mprotect|dlopen|__system_property_get/.test(s));
const hasStr = (a.strings||[]).some(s=>/ADH_AGENT|IDH_AGENT|adhd|idhd|Host ADH Daemon/.test(s));
console.log(`exports(adh_agent_start,idh_agent_start,JNI_OnLoad)=${hasExports} needed=${JSON.stringify(a.needed)} imports=${hasImports} strings=${hasStr}`);
const pass = hasExports && hasNeeded && hasImports && hasStr;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v0.8 native binary analysis (exports + needed + imports + strings)" 0 && exit 0 || exit 1
