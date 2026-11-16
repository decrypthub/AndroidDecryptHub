import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,existsSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {HookPlans,FAMILY_KEYS,validatePlan,legacyPlan} from '../src/hook_plans.ts';
import {MCP_MAP} from '../src/mcp.ts';
import {Operations} from '../src/operations.ts';
import {describeTool} from '../src/operation_registry.ts';
import {sessions,agentSockets,pending,captureTimers,settings} from '../src/state.ts';
import {startCaptureLoop} from '../src/service.ts';

const lookup=(name:string)=>MCP_MAP.get(name),ai={role:'ai' as const,id:'fixture',source:'test'};
const plan=()=>({schemaVersion:1 as const,id:'fixture',title:'Fixture Hook',package:'com.fixture.app',families:Object.fromEntries(FAMILY_KEYS.map(k=>[k,k==='digest'])),steps:[{id:'native',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libfixture.so',symbol:'read'}}]});
function fixture(){
  const root=mkdtempSync(join(tmpdir(),'adh-p5-plans-')),plans=new HookPlans(join(root,'plans')),engine=new Operations(join(root,'operations'));
  const calls:any[]=[],hooks:any[]=[];let policy='d=0,h=0,s=0,a=0,t=0,e=0,y=0',stopAfterFirst=false,loseNative=false;
  sessions.set('p5',{sessionId:'p5',online:true,package:'com.fixture.app',process:'com.fixture.app',pid:71,uid:10001,starttimeTicks:'55',policy,caps:{ops:['native_hook','capture_start','capture_policy']}} as any);
  agentSockets.set('p5',{destroyed:false,write(frame:Buffer){const msg=JSON.parse(frame.subarray(5).toString());calls.push(msg);
    queueMicrotask(()=>{let reply:any={ok:true};if(msg.op==='capture_policy'){if(msg.action!=='status')policy=msg.families;reply.policy=policy;}
      else if(msg.op==='native_hook'){if(msg.action==='hook'){reply.hookId=hooks.length+1;hooks.push({id:reply.hookId,module:msg.module,symbol:msg.symbol});if(stopAfterFirst){const c=engine.snapshot('target:p5');engine.control('takeover','target:p5',{role:'operator',id:'human',source:'test'},{expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch});}}
        else if(msg.action==='status')reply.status={hooks};else hooks.splice(hooks.findIndex(h=>h.id===msg.hookId),1);}
      else if(msg.op==='capture_start')reply={ok:true,digest:1};else if(msg.op==='capture_drain')reply={ok:true,count:0,captures:[],jcaptures:[],complete:true};
      if(msg.op==='native_hook'&&msg.action==='hook'&&loseNative)pending.get(msg.id)?.reject(Object.assign(new Error('synthetic response lost'),{code:'COMMAND_TIMEOUT',uncertain:true}));else pending.get(msg.id)?.resolve(reply);});return true;}} as any);
  function execute(action:string,fn:()=>Promise<any>){const c=engine.snapshot('target:p5');return engine.execute(describeTool('hook_plans',{action,session:'p5'}),{},ai,{expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch},fn);}
  return {root,plans,engine,calls,hooks,execute,setPolicy:(p:string)=>{policy=p;},stop:()=>{stopAfterFirst=true;},lose:()=>{loseNative=true;},close(){for(const timer of captureTimers.values())clearInterval(timer);captureTimers.clear();agentSockets.delete('p5');sessions.delete('p5');engine.close();rmSync(root,{recursive:true,force:true});}};
}

test('immutable library CAS, schema and legacy import preserve evidence without automatic effects',()=>{
  const f=fixture();try{assert.equal(existsSync(join(f.root,'plans')),false);assert.equal(f.plans.list().revision,0);
    const first=f.plans.put(plan(),0,lookup);assert.equal(first.applied,false);assert.equal(first.revision,1);assert.equal(f.calls.length,0);
    assert.throws(()=>f.plans.put(plan(),0,lookup),(e:any)=>e.code==='STALE_PLAN_LIBRARY');
    const changed=plan();changed.title='Human edit';const next=f.plans.put(changed,1,lookup);assert.notEqual(next.digest,first.digest);assert.equal(f.plans.get(first.digest).plan.title,'Fixture Hook');
    for(const invalid of [{...plan(),autoApply:true},{...plan(),families:{digest:true}},{...plan(),steps:[{id:'bad',tool:'native_hook',arguments:{action:'hook',session:'other'}}]}])assert.throws(()=>validatePlan(invalid,lookup));
    const scope={packages:['com.fixture.app'],policy:{'com.fixture.app':{c:{d:false,h:true,future:7},unknown:{nested:true}}},future:'kept'};
    const migrated=legacyPlan(scope,{capture:{cryptoModule:'libfixture.so'},startup:{antiDebug:false},future:13},'com.fixture.app','migrated');assert.deepEqual(migrated.metadata.legacy.scope,scope);assert.equal(migrated.families.digest,false);assert.equal(migrated.families.hmac,true);
    writeFileSync(join(f.root,'plans','versions',first.digest+'.json'),'{}');assert.throws(()=>f.plans.get(first.digest),(e:any)=>e.code==='PLAN_LIBRARY_CORRUPT');
  }finally{f.close();}
});
test('live plans dispatch actual primitives, preserve receipts and undo only verified owned hooks',async()=>{
  const f=fixture();try{const saved=f.plans.put(plan(),0,lookup);assert.equal(f.plans.preflight(saved.digest,'p5',lookup).ok,true);
    const op=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));assert.equal(op.state,'succeeded');const run=f.plans.run(op.id);assert.equal(run.state,'applied');assert.equal(run.receipts[1].reply.hookId,1);
    assert.deepEqual(f.calls.map(x=>x.op),['capture_policy','capture_policy','native_hook']);const undo=await f.execute('undo',()=>f.plans.undo(op.id,lookup));assert.equal(undo.state,'succeeded');assert.equal(f.hooks.length,0);assert.equal(f.plans.run(op.id).state,'undone');
  }finally{f.close();}
});
test('old capability, changed generation, and human runtime changes fail before unsafe writes',async()=>{
  const f=fixture();try{const saved=f.plans.put(plan(),0,lookup);sessions.get('p5')!.caps!.ops=['native_hook'];assert.equal(f.plans.preflight(saved.digest,'p5',lookup).ok,false);
    const bad=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));assert.equal(bad.state,'failed');assert.equal(f.calls.length,0);
    sessions.get('p5')!.caps!.ops!.push('capture_policy');const op=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));f.setPolicy('d=0,h=1,s=0,a=0,t=0,e=0,y=0');
    const undo=await f.execute('undo',()=>f.plans.undo(op.id,lookup));assert.equal(undo.state,'failed');assert.equal(undo.error.code,'STALE_RUNTIME');assert.equal(f.hooks.length,1);
    sessions.get('p5')!.starttimeTicks='other';await assert.rejects(()=>f.plans.observe(op.id,lookup),(e:any)=>e.code==='PLAN_TARGET_MISMATCH');
  }finally{f.close();}
});
test('human takeover between plan steps fences the remaining program; hello draining never arms defaults',async()=>{
  const f=fixture();try{const p=plan();p.steps.push({...p.steps[0],id:'second'});const saved=f.plans.put(p,0,lookup);f.stop();
    const op=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));assert.notEqual(op.state,'succeeded');assert.equal(f.calls.filter(x=>x.op==='native_hook').length,1);assert.equal(f.plans.run(op.id).state,'partial-or-failed');
    settings.capture.enabled=true;settings.startup.antiDebug=true;startCaptureLoop('p5');await new Promise(r=>setTimeout(r,300));assert.equal(f.calls.filter(x=>x.op==='capture_start').length,0);
  }finally{f.close();}
});
test('lost step acknowledgement is unknown, keeps prior effects and never replays the plan',async()=>{
  const f=fixture();try{const p=plan();p.steps.push({...p.steps[0],id:'later'});const saved=f.plans.put(p,0,lookup);f.lose();
    const op=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));assert.equal(op.state,'unknown');assert.equal(f.plans.run(op.id).state,'unknown');assert.equal(f.hooks.length,1);assert.equal(f.calls.filter(x=>x.op==='native_hook').length,1);assert.ok(f.engine.snapshot('target:p5').uncertain);
    const count=f.calls.length;await assert.rejects(()=>f.plans.undo(op.id,lookup),(e:any)=>e.code==='UNSUPPORTED_UNDO');assert.equal(f.calls.length,count,'unknown effects cannot be declared undone');
  }finally{f.close();}
});
test('explicit capture module blanks cannot inherit broad legacy settings',async()=>{
  const f=fixture(),before=structuredClone(settings.capture);try{settings.capture.fileModule='legacy-file.so';settings.capture.sysModule='legacy-sys.so';settings.capture.cryptoModule='legacy-crypto.so';
    const p:any=plan();p.steps=[{id:'capture',tool:'capture_start',arguments:{cryptoModule:'libfixture.so',fileModule:'',sysModule:''}}];const saved=f.plans.put(p,0,lookup);const op=await f.execute('apply',()=>f.plans.apply(saved.digest,'p5',lookup));assert.equal(op.state,'succeeded');const armed=f.calls.find(x=>x.op==='capture_start');assert.equal(armed.cryptoModule,'libfixture.so');assert.equal(armed.fileModule,'');assert.equal(armed.sysModule,'');
    const stopped=f.calls.filter(x=>x.op==='capture_stop').length;await assert.rejects(()=>f.plans.undo(op.id,lookup),(e:any)=>e.code==='UNSUPPORTED_UNDO');assert.equal(f.calls.filter(x=>x.op==='capture_stop').length,stopped);
  }finally{Object.assign(settings.capture,before);f.close();}
});
