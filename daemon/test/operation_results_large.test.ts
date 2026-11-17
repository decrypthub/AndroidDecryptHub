import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {Operations} from '../src/operations.ts';
import {responseForOperation} from '../src/operation_host.ts';

test('large operation results survive restart and retain their HTTP/MCP payloads',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-large-result-'));let engine=new Operations(root);
  const payload='A'.repeat(9*1024*1024),hash=(s:string)=>createHash('sha256').update(s).digest('hex');
  try{
    const op=await engine.execute({name:'large-fixture',mode:'analysis'},{},{id:'fixture',role:'ai',source:'test'},{},async()=>({httpStatus:200,body:{ok:true,b64:payload},contentType:'application/json'}));
    assert.equal(op.state,'succeeded');assert.ok(statSync(op.resultFile).size>8*1024*1024);
    engine.close();engine=new Operations(root);
    const restored=engine.getOperation(op.id,true);
    for(const transport of ['http','mcp'] as const){
      const response=responseForOperation(restored,transport) as any;
      const body=transport==='http'?response.body:response;
      assert.equal(response._operation.state,'succeeded');assert.equal(body.b64.length,payload.length);assert.equal(hash(body.b64),hash(payload));
    }
  }finally{engine.close();rmSync(root,{recursive:true,force:true});}
});

test('omitted legacy results fail explicitly while retaining execution and unknown states',()=>{
  const result={omitted:true,bytes:9*1024*1024,sha256:'a'.repeat(64)};
  const succeeded={id:'executed-fixture',state:'succeeded',mayHaveExecuted:true,result};
  const http=responseForOperation(succeeded,'http') as any;
  assert.equal(http.httpStatus,422);assert.equal(http.body.code,'RESULT_OMITTED');assert.equal(http.body.ok,false);assert.equal(http._operation.state,'succeeded');
  const mcp=responseForOperation(succeeded,'mcp') as any;
  assert.equal(mcp.code,'RESULT_OMITTED');assert.equal(mcp._operation.mayHaveExecuted,true);
  const unknown=responseForOperation({...succeeded,state:'unknown'},'http') as any;
  assert.equal(unknown.httpStatus,504);assert.equal(unknown.body.code,'UNKNOWN_EXECUTION');assert.equal(unknown._operation.state,'unknown');
});
