import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const shim=new URL('../../tools/lib/verify_fetch.mjs',import.meta.url).href;

test('legacy acceptance client observes once, retains explicit versions, and never retries a conflict',async()=>{
  const calls:any[]=[];
  const server=http.createServer(async(req,res)=>{
    let text='';for await(const chunk of req)text+=chunk;
    const body=text?JSON.parse(text):null;calls.push({path:req.url,body,operation:req.headers['x-adh-operation']});
    res.setHeader('content-type','application/json');
    if(req.url==='/api/operations/prepare')res.end(JSON.stringify({ok:true,spec:{mode:'write'},revision:7,epoch:2,hostEpoch:3}));
    else{res.statusCode=409;res.end(JSON.stringify({ok:false,code:'STALE_CONTROL'}));}
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const base='http://127.0.0.1:'+(server.address() as any).port;
  const directory=mkdtempSync(join(tmpdir(),'adh-verify-fetch-'));
  const execute=(args:string[],input='')=>new Promise<{code:number|null,stdout:string,stderr:string}>((yes,no)=>{
    const child=spawn(process.execPath,['--import',shim,...(args[0]==='-'?['--input-type=module']:[]),...args],{windowsHide:true,env:{...process.env,ADH_VERIFY_FETCH_COORDINATED:'1',ADH_VERIFY_FETCH_BASE:base}});
    let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.on('error',no);child.stdin.end(input);child.on('exit',code=>yes({code,stdout,stderr}));
  });
  try{
    const r=await execute(['-'],`const first=await fetch('${base}/api/java/probe?session=s1');console.log(first.status);
const explicit={expectedRevision:0,controlEpoch:0,hostEpoch:0};await fetch('${base}/api/java/probe',{headers:{'x-adh-operation':JSON.stringify(explicit)}});
await fetch('${base}/api/java/probe',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({_operation:null})});`);
    assert.equal(r.code,0,r.stderr);assert.match(r.stdout,/409/);
    assert.equal(calls.filter(c=>c.path==='/api/operations/prepare').length,1);
    assert.equal(calls.filter(c=>c.path?.startsWith('/api/java/probe')).length,3,'conflict must not replay a write');
    assert.equal(calls[0].body.arguments.session,'s1');assert.equal(calls[0].body.method,'GET');
    const first=JSON.parse(String(calls[1].operation));assert.equal(first.expectedRevision,7);assert.equal(first.controlEpoch,2);assert.equal(first.hostEpoch,3);
    assert.equal(JSON.parse(String(calls[2].operation)).expectedRevision,0);assert.equal(calls[3].body._operation,null);assert.equal(calls[3].operation,undefined);
    // A server or CLI module process must not inherit the stdin-only adapter behavior.
    const module=join(directory,'module.mjs');writeFileSync(module,`await fetch('${base}/api/java/probe');`);
    const plain=await execute([module]);assert.equal(plain.code,0,plain.stderr);
    assert.equal(calls.length,5);assert.equal(calls[4].operation,undefined);
  }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));rmSync(directory,{recursive:true,force:true});}
});
