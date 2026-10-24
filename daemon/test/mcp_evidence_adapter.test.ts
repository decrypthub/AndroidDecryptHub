import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MCP_TOOLS } from '../src/mcp.ts';
import { captures, capStats } from '../src/state.ts';
const handler=MCP_TOOLS.find(t=>t.name==='crypto_evidence')!.handler;
const sid='synthetic-mcp-evidence-adapter';
const id=900000001;
const args=()=>({action:'analyze',observations:[{id:'digest',role:'intermediate',algorithms:['md5'],
  input:{captureId:id,field:'payload'},output:{captureId:id,field:'output',expectedBytes:16}}],loss:{complete:true}});
const record=()=>({id,sessionId:sid,pid:999,tid:100,hookId:3,seq:1,hex:'616263',inl:3,
  outHex:createHash('md5').update('abc').digest('hex'),func:'MD5',ts:Date.now()});

test('MCP exact selectors propagate known collection loss even when a caller claims complete',async()=>{
  captures.push(record() as any);
  capStats.set(sid,{seq:3,emitted:1,dropped:2,jdropped:0,backlog:0,drained:1,firstDropNs:1,lastDropNs:1,complete:false,ring:128,ts:Date.now()});
  try {
    const report=await handler(args());
    assert.equal(report.counts.matched,1); assert.equal(report.rows[0].role,'intermediate');
    assert.equal(report.analysisComplete,true); assert.equal(report.captureCollectionComplete,false);
    assert.equal(report.complete,false); assert.equal(report.loss.dropped,2);
  } finally {captures.splice(captures.findIndex(r=>r.id===id),1);capStats.delete(sid);}
});
test('unknown live collection health stays unknown and cannot be upgraded by caller complete:true',async()=>{
  captures.push(record() as any);
  try {
    const report=await handler(args());
    assert.equal(report.counts.matched,1); assert.equal(report.captureCollectionComplete,null);
    assert.equal(report.complete,false); assert.match(report.loss.note,/health unknown/);
  } finally {captures.splice(captures.findIndex(r=>r.id===id),1);}
});
test('MCP capture selectors cannot relabel a short prefix as a complete original payload',async()=>{
  captures.push(record() as any);
  try {
    const input=args(); (input.observations[0].input as any).expectedBytes=1;
    await assert.rejects(handler(input),/conflict|original|length|inl/i);
  } finally {captures.splice(captures.findIndex(r=>r.id===id),1);}
});
