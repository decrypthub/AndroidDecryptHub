#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_unit_pass 'root watch validation and snapshot windows' root_watch.test.ts 2 || exit 1
verify_unit_pass 'process generation identity' proc_identity.test.ts 2 || exit 1
cd "$ROOT"
if ! OUT="$(node --input-type=module - "$BASE" "$SERIAL" "$ROOT" <<'EOF'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { pickSession } from './daemon/src/cli.ts';
const [base,serial,repo]=process.argv.slice(2);
const fixture=join(repo,'agent/build/libadh_native_controls.so');
const skip=reason=>{console.log(`SKIP verify_v126_root_watch_native (${reason})`);process.exit(0);};
if(!serial||!existsSync(fixture)||!existsSync(join(repo,'agent/build/adh-root-watch')))skip('device, built root collector and native controls fixture required');
const adb=args=>{const r=spawnSync('adb',['-s',serial,...args],{encoding:'utf8',timeout:20000,windowsHide:true});if(r.error||r.status!==0)throw new Error(String(r.error??r.stderr));return r.stdout.trim();};
if(adb(['shell','su','-c','id -u'])!=='0')skip('rooted verification device required');
const agents=await(await fetch(`${base}/api/agents`)).json();
if(!agents.some(a=>a.online&&a.package==='com.adh.nativefixture'))skip('no online dedicated native verification host; never starts another process');
const target=pickSession(agents,'com.adh.nativefixture',process.env.ADH_TEST_SESSION);
assert.equal(target.package,'com.adh.nativefixture');
if(!target.starttimeTicks)skip('current agent hello starttimeTicks required');
const call=async(name,args={})=>{
 const res=await fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:{session:target.sessionId,...args}}})});
 const r=await res.json();if(r.error)throw new Error(JSON.stringify(r.error));
 const text=r.result?.content?.find(c=>c.type==='text')?.text;
 if(r.result?.isError)throw new Error(text);const value=JSON.parse(text);if(value.ok===false)throw new Error(JSON.stringify(value));return value;
};
const lib=`/data/local/tmp/adh-native-watch-${randomUUID()}.so`,module=lib.split('/').at(-1);
const native=async symbol=>call('native_call',{module,symbol,args:[],confirm:true});
// resultDecimal is a JSON number and loses uint64 precision; hex is exact.
const uint=r=>BigInt(r.result??r.resultDecimal);
const root=args=>call('root_watch',args), active=new Set();
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let started=false;
const finished=async id=>{for(let i=0;i<160;i++){const r=await root({action:'status',id});if(!r.running)return r;await delay(50);}throw new Error('collector exceeded its bounded lifetime');};
try{
 adb(['push',fixture,lib]);
 await call('load_library',{path:lib});
 const prepared=await root({action:'prepare',serial});
 assert.equal(prepared.selfTest.selfTest,true);assert.equal(prepared.selfTest.complete,true);assert.equal(prepared.selfTest.samples,1);
 const tid=Number(uint(await native('adh_watch_start')));started=true;
 assert.ok(Number.isSafeInteger(tid)&&tid>0);
 const address='0x'+uint(await native('adh_watch_address')).toString(16);
 assert.notEqual(address,'0x0');assert.equal(BigInt(address)%8n,0n);
 assert.equal(uint(await native('adh_watch_count')),0n);
 const diagnose=await call('runtime_diagnostics',{serial,limit:256});
 assert.equal(diagnose.identityVerified,true);assert.equal(diagnose.sessionGenerationVerified,true);
 assert.ok(diagnose.threads.some(t=>t.tid===tid&&t.eligibleForRootWatch),'persistent writer TID was not a current target thread');
 const start=async extra=>{const r=await root({action:'start',serial,tid,addr:address,width:8,mode:'w',durationMs:2500,maxEvents:8,stackBytes:512,...extra});active.add(r.id);assert.equal(r.sessionGenerationVerified,true);assert.equal(r.starttimeTicks,target.starttimeTicks);return r.id;};
 const trigger=async expected=>{await native('adh_watch_trigger');for(let i=0;i<100;i++){const count=uint(await native('adh_watch_count'));if(count===expected)break;await delay(20);}assert.equal(uint(await native('adh_watch_count')),expected);assert.equal(uint(await native('adh_watch_value')),0x8877665544332211n);};
 const id=await start({});await trigger(2n);const status=await finished(id);
 assert.equal(status.error,undefined);assert.equal(status.complete,true);assert.equal(status.sessionGenerationVerified,true);
 assert.equal(status.summary.samples,2);assert.equal(status.summary.lost,0);assert.equal(status.summary.throttles,0);assert.equal(status.summary.malformed,0);
 const page=await root({action:'read',id,registers:true,stackSize:16,limit:1});
 assert.equal(page.events.length,1);assert.equal(page.hasMore,true);
 const second=await root({action:'read',id,registers:true,stackSize:16,afterSeq:page.nextSeq,limit:1});
 assert.equal(second.events.length,1);assert.equal(second.hasMore,false);
 const events=[page.events[0],second.events[0]],values=['0x1122334455667788','0x8877665544332211'];
 for(let i=0;i<events.length;i++){
  const event=events[i];assert.equal(event.pid,target.pid);assert.equal(event.tid,tid);assert.equal(event.regs.length,33);
  assert.ok(event.regs.includes(values[i]),'kernel GPR snapshot lost the known stored value');
  assert.equal(event.stack.addr,event.regs[31]);assert.equal(event.stack.got,512);assert.equal(event.stackWindow.got,16);
  const disasm=await call('memory_disasm',{addr:event.ip,size:4});assert.match(disasm.instructions[0].mnemonic,/^(str|stlr|stp)/);
 }
 assert.equal((await root({action:'read',id,afterSeq:second.nextSeq})).events.length,0);
 const capped=await start({maxEvents:1});await trigger(4n);const cap=await finished(capped);
 assert.equal(cap.complete,false);assert.equal(cap.summary.stopReason,'event-limit');
 const stopped=await start({durationMs:5000});await root({action:'stop',id:stopped});const stop=await finished(stopped);
 assert.equal(stop.summary.stopReason,'stopped');assert.equal(stop.complete,false);
 await assert.rejects(()=>root({action:'start',serial,tid:1,addr:address,width:8}),/tid-does-not-belong/);
 assert.equal(uint(await native('adh_watch_stop')),0n);started=false;
 assert.equal(uint(await native('adh_watch_state')),4n);
 console.log(JSON.stringify({stores:2,tid,kernelGprs:33,stackBytes:512,complete:status.complete,generationVerified:true,paged:true,eventLimitIncomplete:true,cooperativeStop:true,wrongTidRejected:true}));
 console.log('RESULT:PASS');
}finally{
 for(const id of active)await root({action:'stop',id}).catch(()=>{});
 if(started)await native('adh_watch_stop').catch(()=>{});
 // Unique test image can stay mapped after unlink. No installed app/library is replaced.
 adb(['shell','rm','-f',lib]);
}
EOF
)"; then
  echo "$OUT"
  exit 1
fi
echo "$OUT"
if [[ "$OUT" == *"SKIP verify_v126_root_watch_native"* ]]; then exit 0; fi
verify_gate 'native host root hardware writes, kernel snapshots and generation checks' 0
