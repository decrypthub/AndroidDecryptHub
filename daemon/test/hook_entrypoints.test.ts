import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {handleHttp} from '../src/http/router.ts';
import {getOperations,operationsRoot} from '../src/operation_host.ts';
import {initializeOperatorAccess} from '../src/access_context.ts';
import {DATA_DIR} from '../src/state.ts';
import {FAMILY_KEYS} from '../src/hook_plans.ts';

test('MCP, panel REST and published CLI share immutable plans, CAS and durable write intents',async t=>{
  const engine=getOperations(),key=initializeOperatorAccess(operationsRoot),server=http.createServer((req,res)=>handleHttp(req,res).catch(error=>{res.writeHead(500);res.end(String(error));}));
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+(server.address() as any).port;
  const meta=()=>{const s=engine.snapshot('host');return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
  const rpc=async(name:string,args:any)=>{const v=await(await fetch(base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})})).json() as any;return JSON.parse(v.result.content[0].text);};
  try{
    const plan={schemaVersion:1,id:'unified',title:'Entry fixture',package:'com.fixture.app',families:Object.fromEntries(FAMILY_KEYS.map(k=>[k,false])),steps:[{id:'got',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libfixture.so',symbol:'read'}}]};
    const intent={...meta(),idempotencyKey:'p5-shared-intent'},args={action:'put',plan,expectedLibraryRevision:0};const saved=await rpc('hook_plans',{...args,_operation:intent});assert.equal(saved.applied,false);assert.equal(saved.revision,1);
    const repeated=await(await fetch(base+'/api/hook-plans',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operation':JSON.stringify(intent)},body:JSON.stringify(args)})).json() as any;assert.equal(repeated._operation.id,saved._operation.id);assert.equal(repeated.revision,1);
    const asset=await fetch(base+'/hook-plans-panel.js');assert.equal(asset.status,200);assert.match(await asset.text(),/tool:'hook_plans'/);
    const stale=await rpc('hook_plans',{...args,expectedLibraryRevision:0,_operation:meta()});assert.equal(stale.code,'STALE_PLAN_LIBRARY');
    const cliSource=process.env.ADH_CLI_SOURCE||resolve('../..','adh-cli','src');if(!existsSync(join(cliSource,'adh','__init__.py'))){t.diagnostic('CLI source absent; set ADH_CLI_SOURCE for public CLI check');return;}
    const execute=promisify(execFile),env={...process.env,PYTHONPATH:cliSource,ADH_CONFIG_PATH:join(DATA_DIR,'p5-cli.json'),ADH_OPERATOR_TOKEN:key,PYTHONIOENCODING:'utf-8'};
    try{await execute('python',['--version'],{windowsHide:true,timeout:5000});}catch(error){if((error as any).code==='ENOENT'){t.diagnostic('Python unavailable');return;}throw error;}
    const output=await execute('python',['-m','adh','run','hook_plans','--arguments',JSON.stringify({...args,plan:{...plan,title:'CLI edited'},expectedLibraryRevision:1}),'--endpoint',base,'--json'],{env,windowsHide:true,timeout:15000});const submitted=JSON.parse(output.stdout).operation;
    for(let n=0;n<100&&!engine.getOperation(submitted.id).settled;n++)await new Promise(r=>setTimeout(r,10));assert.equal(engine.getOperation(submitted.id).state,'succeeded');
    const list=await rpc('hook_plans',{action:'list'});assert.equal(list.revision,2);assert.equal(list.plans[0].title,'CLI edited');assert.equal((await rpc('hook_plans',{action:'get',digest:saved.digest})).plan.title,'Entry fixture');
  }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));engine.close();}
});
