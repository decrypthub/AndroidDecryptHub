import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {Readable} from 'node:stream';
import {handleHttp} from '../src/http/router.ts';
import {readRequestBody,ARTIFACT_BODY_BYTES} from '../src/http/request_body.ts';
import {getOperations} from '../src/operation_host.ts';
import {sendHttpError} from '../src/http/response_error.ts';

test('large artifacts share REST, MCP, pinned MCP and preparation bounds without widening controls',async()=>{
  const server=http.createServer((req,res)=>{handleHttp(req,res).catch(error=>sendHttpError(req,res,error));});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const base='http://127.0.0.1:'+(server.address() as any).port;
  const dex=Buffer.alloc(7*1024*1024);dex.write('dex\n035\0',0,'binary');
  dex.writeUInt32LE(dex.length,32);dex.writeUInt32LE(112,36);dex.writeUInt32LE(0x12345678,40);
  const args={b64:dex.toString('base64'),query:'absent-synthetic-marker'};
  const post=(path:string,body:any)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const rpc=async(path:string,name:string,arguments_:any)=>{
    const response=await post(path,{jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:arguments_}});
    assert.equal(response.status,200);const body=await response.json() as any;
    assert.ok(!body.error,JSON.stringify(body.error));return JSON.parse(body.result.content[0].text);
  };
  try{
    assert.ok(Buffer.byteLength(JSON.stringify(args))>8*1024*1024);
    const parsed=await post('/api/dex/parse',args);assert.equal(parsed.status,200,await parsed.text());
    const prepared=await post('/api/operations/prepare',{path:'/api/dex/repair',method:'POST',arguments:args});
    assert.equal(prepared.status,200);assert.equal((await prepared.json() as any).ok,true);
    const observed=await rpc('/mcp','operations',{action:'snapshot',tool:'dex_search',arguments:args});
    assert.equal(observed.ok,true);
    const result=await rpc('/mcp','dex_search',{...args,_operation:{expectedRevision:observed.revision,controlEpoch:observed.epoch,hostEpoch:observed.hostEpoch}});
    assert.equal(result._operation.state,'succeeded');
    // Package pinning still admits artifact envelopes; the target/shape guard may refuse
    // the synthetic package, but it must not turn a body limit into HTTP 403.
    const pinned=await rpc('/com.fixture.app/mcp','operations',{action:'snapshot',tool:'dex_search',arguments:args});
    assert.equal(pinned.ok,true);
    for(const transport of ['mcp','rest']){
      const submitted=transport==='mcp'
        ?await rpc('/mcp','operations',{action:'submit',tool:'dex_search',arguments:args})
        :await (await post('/api/operations',{action:'submit',tool:'dex_search',arguments:args})).json() as any;
      assert.equal(submitted.ok,true);assert.ok(submitted.operation.id);
      let operation=getOperations().getOperation(submitted.operation.id);
      for(let i=0;i<200&&!operation.settled;i++){
        await new Promise(r=>setTimeout(r,5));operation=getOperations().getOperation(operation.id);
      }
      assert.equal(operation.state,'succeeded');
    }
    for(const [path,body] of [
      ['/api/config',args],
      ['/mcp',{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'settings',arguments:{action:'get',...args}}}],
      ['/com.fixture.app/mcp',{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'settings',arguments:args}}],
      ['/api/operations/prepare',{path:'/api/config',method:'POST',arguments:args}],
      ['/api/operations',{action:'submit',tool:'settings',arguments:args}],
      ['/mcp',{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'operations',arguments:{action:'snapshot',tool:'settings',arguments:args}}}],
    ] as const){
      const response=await post(path,body);assert.equal(response.status,413,path);await response.text();
    }
  }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));getOperations().close();}
});

test('artifact requests still reject a chunked body beyond the absolute cap',async()=>{
  const chunk=Buffer.alloc(1024*1024,32);
  const input=Readable.from(Array(ARTIFACT_BODY_BYTES/chunk.length+1).fill(chunk));
  const req=Object.assign(input,{url:'/api/dex/parse',method:'POST'}) as unknown as http.IncomingMessage;
  try{await assert.rejects(readRequestBody(req),(error:any)=>error.status===413&&error.message.includes(String(ARTIFACT_BODY_BYTES)));}
  finally{input.destroy();}
});

test('an unfinished oversized upload cannot hold the 413 response open indefinitely',async()=>{
  const server=http.createServer((req,res)=>{handleHttp(req,res).catch(error=>sendHttpError(req,res,error));});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const port=(server.address() as any).port;
  try{
    const response=await new Promise<{status:number;body:string}>((resolve,reject)=>{
      const req=http.request({hostname:'127.0.0.1',port,path:'/api/config',method:'POST',headers:{'transfer-encoding':'chunked'}},res=>{
        let body='';res.on('data',chunk=>body+=chunk);res.on('error',reject);
        res.on('end',()=>resolve({status:res.statusCode!,body}));
      });
      req.on('error',reject);req.setTimeout(7000,()=>req.destroy(new Error('no bounded 413 response')));
      req.write(Buffer.alloc(9*1024*1024,32));
      // Intentionally omit end(): the peer has not completed the upload.
    });
    assert.equal(response.status,413);assert.match(response.body,/body too large/);
  }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}
});
