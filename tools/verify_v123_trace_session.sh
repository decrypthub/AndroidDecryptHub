#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
export MSYS2_ENV_CONV_EXCL="${MSYS2_ENV_CONV_EXCL:+$MSYS2_ENV_CONV_EXCL;}ADH_TEST_LIBDIR"
verify_unit_pass 'trace persistence, query and conservative dependency slice' trace_store.test.ts 5 || exit 1
cd "$ROOT"
OUT="$(node --input-type=module - "$BASE" "$SERIAL" "$ROOT" <<'EOF'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID, randomBytes } from 'node:crypto';
const [base,serial,repo]=process.argv.slice(2), fixture=join(repo,'agent/build/libadh_trace_fixture.so');
if(!serial||!existsSync(fixture)) {console.log('RESULT:SKIP device or built trace fixture missing');process.exit(0);}
const adb=(args)=>{const r=spawnSync('adb',['-s',serial,...args],{encoding:'utf8',timeout:20000,windowsHide:true});if(r.error||r.status!==0)throw new Error(String(r.error??r.stderr));return r.stdout.trim();};
if(adb(['shell','su','-c','id -u'])!=='0'){console.log('RESULT:SKIP rooted test device required');process.exit(0);}
const all=await(await fetch(`${base}/api/agents`)).json();
const testPackage=process.env.ADH_TEST_PACKAGE??'com.adh.sandbox';
assert.ok(['com.adh.sandbox','com.adh.nativefixture'].includes(testPackage));
const target=all.filter(a=>a.online&&a.package===testPackage).sort((a,b)=>b.connectedAt-a.connectedAt)[0];
if(!target){console.log('RESULT:SKIP no online sandbox');process.exit(0);}
if(!target.caps?.ops?.includes('qbdi_read')){console.log('RESULT:SKIP current agent with qbdi_read required');process.exit(0);}
const call=async(name,args={})=>{
  const r=await(await fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:{session:target.sessionId,...args}}})})).json();
  if(r.error)throw new Error(JSON.stringify(r.error));const text=r.result?.content?.find(c=>c.type==='text')?.text;
  if(r.result?.isError)throw new Error(text);const value=JSON.parse(text);if(value.ok===false)throw new Error(JSON.stringify(value));return value;
};
const libdir=testPackage==='com.adh.nativefixture'?process.env.ADH_TEST_LIBDIR:adb(['shell','su','-c','ls -d /data/app/*/com.adh.sandbox*/lib/arm64']);
if(testPackage==='com.adh.nativefixture') assert.match(libdir??'',/^\/data\/local\/tmp\/adh-native-[a-f0-9-]{36}$/);
else assert.match(libdir,/^\/data\/app\/[^\r\n]+\/com\.adh\.sandbox[^\r\n]*\/lib\/arm64$/);
const token=randomUUID(), staged=`/data/local/tmp/adh-trace-${token}.so`, lib=`${libdir}/libadh_trace_fixture_${token.replaceAll('-','')}.so`;
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
try {
  adb(['push',fixture,staged]);
  const stage=`cp ${quote(staged)} ${quote(lib)} && chmod 755 ${quote(lib)}${testPackage==='com.adh.sandbox'?` && chcon u:object_r:apk_data_file:s0 ${quote(lib)}`:''}`;
  adb(['shell',testPackage==='com.adh.nativefixture'?stage:`su -c ${quote(stage)}`]);
  const tools=await(await fetch(`${base}/api/mcp/doc`)).text();
  assert.ok(tools.includes('trace_session'));
  await call('load_library',{path:lib});
  await call('trace_session',{action:'prepare',path:`${libdir}/libQBDI.so`,confirm:true});
  const symLib=lib.split('/').at(-1);
  const seed=BigInt('0x'+randomBytes(7).toString('hex')), rounds=256;
  let expected=seed;const mask=(1n<<64n)-1n;
  for(let i=0;i<rounds;i++){expected=(expected+(seed^BigInt(i)))&mask;expected=((expected<<7n)|(expected>>57n))&mask;expected^=0x9e3779b97f4a7c15n;}
  const run=await call('trace_session',{action:'record',confirm:true,symLib,symbol:'adh_trace_challenge',args:[seed.toString(),String(rounds)],budget:500000,timeMs:10000,capacity:65536});
  assert.equal(run.stopReason,'completed');assert.equal(run.retvalValid,true);assert.equal(BigInt(run.retvalHex),expected);
  assert.ok(run.recorded>8192,`fixture needs to exceed old recording cap, got ${run.recorded}`);
  assert.equal(run.complete,true);assert.equal(run.transportComplete,true);assert.equal(run.released,true);
  assert.equal(run.execution,'active-call');assert.equal(run.coverage,'instrumented-module');
  const legacy=await call('qbdi_trace',{symLib,symbol:'adh_trace_challenge',args:[seed.toString(),String(rounds)]});
  assert.equal(legacy.count,legacy.insns.length);assert.equal(legacy.truncated,true);
  assert.ok(legacy.count<run.recorded,'new recording must retain data missing from the legacy reply');
  const page=await call('trace_session',{action:'query',id:run.id,afterSeq:9000,limit:3});
  assert.deepEqual(page.rows.map(r=>r.seq),[9001,9002,9003]);assert.equal(page.more,true);
  const stat=await call('trace_session',{action:'stats',id:run.id});assert.equal(stat.count,run.recorded);assert.ok(stat.observedBlockEntries.length>0);
  const clipped=await call('trace_session',{action:'record',confirm:true,symLib,symbol:'adh_trace_challenge',args:[seed.toString(),'16'],capacity:8});
  assert.equal(clipped.stopReason,'completed');assert.equal(clipped.complete,false);assert.equal(clipped.truncated,true);assert.equal(clipped.recorded,8);assert.equal(clipped.transportComplete,true);
  const budget=await call('trace_session',{action:'record',confirm:true,symLib,symbol:'adh_trace_challenge',args:[seed.toString(),'16'],budget:16,capacity:128});
  assert.equal(budget.stopReason,'instruction-budget');assert.equal(budget.complete,false);assert.equal(budget.retvalValid,false);assert.equal(budget.recorded,16);
  const diagnosis=await call('runtime_diagnostics',{serial,limit:8});assert.equal(diagnosis.identityVerified,true);assert.ok(diagnosis.threads.length>0);assert.equal(diagnosis.sessionGenerationVerified,true);
  const list=await call('trace_session',{action:'list'});assert.ok(list.some(x=>x.id===run.id));
  console.log(JSON.stringify({seed:seed.toString(),rounds,recorded:run.recorded,legacyReplyInstructions:legacy.count,complete:run.complete,coverage:run.coverage,truncatedRecords:clipped.recorded,budgetRecords:budget.recorded,diagnosis:diagnosis.state,sessionGenerationVerified:diagnosis.sessionGenerationVerified}));
  console.log('RESULT:PASS');
}finally{
  // The fixture can stay mapped after unlink; never overwrite a library mapped by the sandbox.
  const cleanup=`rm -f ${quote(staged)} ${quote(lib)}`;
  adb(['shell',testPackage==='com.adh.nativefixture'?cleanup:`su -c ${quote(cleanup)}`]);
}
EOF
)"
echo "$OUT"
verify_gate 'real QBDI paged trace and process diagnostics' 0
