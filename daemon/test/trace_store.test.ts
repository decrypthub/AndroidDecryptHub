import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordTrace, queryTrace, traceStats, sliceTrace, listTraces } from '../src/trace_store.ts';

function command(rows: Array<{addr:string;text:string}>, overrides: any = {}, badPage = false) {
  let released = false;
  return { get released() { return released; }, run: async (op:string,a:any) => {
    if(op==='qbdi_trace') { assert.equal(a.paged,'true','agent wire flags are strings'); return {ok:true,traceId:7,count:rows.length,seen:rows.length,complete:true,stopReason:'completed',...overrides}; }
    if(a.release) { assert.equal(a.release,'true','agent release flag is a string'); released=true; return {ok:true}; }
    const insns=rows.slice(a.offset,a.offset+a.limit).map((r,i)=>({...r,seq:a.offset+i}));
    return {ok:true,traceId:badPage?8:7,offset:a.offset,nextOffset:a.offset+insns.length,total:rows.length,insns};
  }};
}
const options={confirm:true,symLib:'fixture',symbol:'run'};

test('trace survives host restart and queries past the old reply cap without returning the whole trace', async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-'));
  try {
    const rows=Array.from({length:12000},(_,i)=>({addr:`0x${(0x1000+(i%5)*4).toString(16)}`,text:i%5===4?'b #0x1000':'add x0, x0, #1'}));
    const cmd=command(rows), receipt=await recordTrace(root,'session',options,cmd.run);
    assert.equal(receipt.recorded,12000); assert.equal(receipt.complete,true); assert.equal(cmd.released,true);
    assert.equal(listTraces(root)[0].id,receipt.id);
    const page=await queryTrace(root,receipt.id,{afterSeq:10000,limit:3,mnemonic:'b'});
    assert.deepEqual(page.rows.map(r=>r.seq),[10004,10009,10014]); assert.equal(page.more,true);
    const stats=await traceStats(root,receipt.id); assert.equal(stats.count,12000); assert.equal(stats.uniquePcs,5);
    assert.equal(stats.observedBlockEntries[0].count,2400);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('completed execution with record loss stays incomplete; mismatched run pages cannot be spliced',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-'));
  try {
    const rows=[{addr:'0x1000',text:'ret'}];
    const clipped=await recordTrace(root,'s',options,command(rows,{complete:false,seen:200,truncated:true}).run);
    assert.equal(clipped.complete,false); assert.equal(clipped.transportComplete,true);
    const cmd=command(rows,{},true), bad=await recordTrace(root,'s',options,cmd.run);
    assert.equal(bad.complete,false); assert.equal(bad.recorded,0); assert.match(bad.error,/discontinuity/); assert.equal(cmd.released,true);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('backward slice resolves known arithmetic but stops at memory and call boundaries',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-'));
  try {
    const rows=[{addr:'0x1000',text:'mov x1, #0x13'},{addr:'0x1004',text:'mov x2, #0x29'},{addr:'0x1008',text:'eor x0, x1, x2'},{addr:'0x100c',text:'ldr x3, [x0]'},{addr:'0x1010',text:'bl #0x2000'}];
    const r=await recordTrace(root,'s',options,command(rows).run);
    const a=await sliceTrace(root,r.id,{register:'w0',beforeSeq:3}); assert.equal(a.complete,true); assert.deepEqual(a.selected.map(r=>r.seq),[0,1,2]);
    const b=await sliceTrace(root,r.id,{register:'x3',beforeSeq:4}); assert.equal(b.complete,false); assert.match(b.barrier.reason,/memory provenance/);
    const c=await sliceTrace(root,r.id,{register:'x0'}); assert.equal(c.complete,false); assert.match(c.barrier.reason,/call/);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('bad trace options and absent confirmation do not invoke the target',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-')); let called=false;
  const cmd=async()=>{called=true;throw new Error('must not run');};
  try {
    await assert.rejects(recordTrace(root,'s',{...options,confirm:false},cmd),/confirm/);
    await assert.rejects(recordTrace(root,'s',{...options,args:[Number.MAX_SAFE_INTEGER+1]},cmd),/large/);
    await assert.rejects(recordTrace(root,'s',{...options,capacity:65537},cmd),/capacity/); assert.equal(called,false);
    await assert.rejects(queryTrace(root,'../outside'),/invalid trace/);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('zero-register writes cannot resolve source dependencies, and wsp aliases sp',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-'));
  try {
    const rows=[{addr:'0X1000',text:'mov xzr, x0'},{addr:'0x1004',text:'add wzr, w0, #1'},{addr:'0x1008',text:'mov wsp, #16'}];
    const r=await recordTrace(root,'s',options,command(rows).run);
    const a=await sliceTrace(root,r.id,{register:'x0'}); assert.equal(a.complete,false); assert.deepEqual(a.unresolved,['x0']);
    const b=await sliceTrace(root,r.id,{register:'sp'}); assert.equal(b.complete,true); assert.deepEqual(b.selected.map(r=>r.seq),[2]);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('Host output directory failure still releases the agent recording',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-trace-')), blocked=join(root,'not-a-directory');
  writeFileSync(blocked,'test');
  const cmd=command([{addr:'0x1000',text:'ret'}]);
  try { await assert.rejects(recordTrace(blocked,'s',options,cmd.run)); assert.equal(cmd.released,true); }
  finally { rmSync(root,{recursive:true,force:true}); }
});
