#!/usr/bin/env bash
# v0.20 file I/O capture through the persistent hook set. Arms open/openat/read/write plus
# __read_chk/__write_chk (bionic FORTIFY_SOURCE wrappers — the real path behind
# java.io.FileInputStream/FileOutputStream on this ART version) in libjavacore.so, provokes a
# real file write+read+verify through java_call, and asserts the agent captured the real file
# path at open and the real marker bytes at both write and read.
# Exit 0 = PASS. Prereq: adhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
MARKER="ADH_FILE_MARKER_v1"; FNAME="adh_file_test.txt"
CLASS="com.adh.sandbox.FileIO"

set +e
OUT="$(node - "$HTTP" "$MARKER" "$FNAME" "$CLASS" <<'EOF'
const [http, marker, fname, cls]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  const on=await call('capture_start',{session:sid,fileModule:'libjavacore.so'});
  const f=on.reply?.file ?? {};
  console.log(`capture_start: ok=${on.ok} installed=${on.installed}/${on.attempted} file=${JSON.stringify(f)}`);
  if(!on.ok){ console.log('FAIL capture_start did not install the hook set'); console.log('RESULT:FAIL'); process.exit(0); }
  const invoked=await call('java_call',{session:sid,className:cls,method:'run',params:'',args:[]});
  console.log(`java_call ${cls}.run -> result="${String(invoked.result ?? invoked.error ?? '').slice(0,40)}"`);
  let opened=null, wrote=null, read=null, caps=[];
  for(let i=0;i<12 && !(opened&&wrote&&read);i++){
    await sleep(1000);
    const lc=await call('live_captures',{session:sid,limit:400,includeText:true});
    caps=lc.captures||[];
    opened=caps.find(c=>c.func==='open' && String(c.ascii||'').includes(fname));
    wrote =caps.find(c=>c.func==='write' && String(c.ascii||'').includes(marker));
    read  =caps.find(c=>c.func==='read'  && String(c.ascii||'').includes(marker));
  }
  caps.filter(c=>['open','openat','write','read'].includes(c.func)).slice(0,8)
      .forEach(c=>console.log(`  [${c.func} inl=${c.inl}] ${String(c.ascii||'').slice(0,80)}`));
  const pass = on.ok && Number(f.readChk)>=1 && Number(f.writeChk)>=1
    && /校验OK/.test(String(invoked.result?.result??'')) && !!opened && !!wrote && !!read;
  console.log(`open path captured: ${!!opened}; write marker captured: ${!!wrote}; read marker captured: ${!!read}`);
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.20 file I/O capture (open path + write/read marker bytes, real java.io.File round-trip)" 1 && exit 0 || exit 1
