// Explicit device acceptance (not part of npm test). The existing daemon triggers
// the real sandbox; an isolated HTTP MCP listener serves the new source. Only
// authentic /api/agents metadata is copied for root-watch's independent PID/UID
// check. No target command or hardware response is mocked.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export async function runRootWatchAcceptance(base: string, serial: string) {
  process.env.ADH_DATA_DIR = join(tmpdir(), `adh-root-watch-acceptance-${process.pid}`);
  process.env.ADH_SKIP_ARTIFACT_LOAD = '1';
  const { handleMcp } = await import('../src/mcp.ts');
  const { sessions } = await import('../src/state.ts');
  const list = await (await fetch(`${base}/api/agents`)).json() as any[];
  const target = list.find((x: any) => x.online && x.package === 'com.adh.sandbox');
  if (!target) { console.log('SKIP verify_v121_root_watch (no online sandbox agent)'); return; }
  sessions.set(target.sessionId, target);
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    await handleMcp(Buffer.concat(chunks).toString(), res);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const isolated = `http://127.0.0.1:${(server.address() as any).port}`;
  const rpc = async (url: string, method: string, params?: any) => {
    const res = await fetch(`${url}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const reply: any = await res.json();
    if (reply.error) throw new Error(JSON.stringify(reply.error));
    return reply.result;
  };
  const call = async (url: string, name: string, args: any) => {
    const r = await rpc(url, 'tools/call', { name, arguments: args });
    const text = r.content?.find((x: any) => x.type === 'text')?.text;
    if (r.isError) throw new Error(text);
    return JSON.parse(text);
  };
  const root = (args: any) => call(isolated, 'root_watch', args);
  const agent = (name: string, args: any) => call(base, name, { session: target.sessionId, ...args });
  const active: string[] = [];
  let buf: string | undefined;
  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
  const finished = async (id: string) => {
    for (let n = 0; n < 100; n++) { const s = await root({ action: 'status', id }); if (!s.running) return s; await sleep(50); }
    throw new Error('collector failed to close within its bound');
  };
  try {
    assert.equal((await rpc(isolated, 'initialize')).serverInfo.name, 'adhd');
    assert.ok((await rpc(isolated, 'tools/list')).tools.some((x: any) => x.name === 'root_watch'));
    const prepared = await root({ action: 'prepare', serial });
    assert.equal(prepared.selfTest.selfTest, true); assert.equal(prepared.selfTest.samples, 1);
    assert.equal(prepared.selfTest.complete, true);
    // native_call uses a short-lived watchdog worker. Synchronous java_call uses
    // the persistent command thread, which the one-existing-TID contract needs.
    const t = await agent('java_call', { className: 'android.os.Process', method: 'myTid' });
    const tid = Number(t.result.result);
    await agent('capture_stop', {});
    const hook = await agent('native_hook', { action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_mem_window_target', mem: 'x0:8', confirm: true });
    assert.equal(hook.ok, true);
    const trigger = () => agent('java_call', { className: 'com.adh.sandbox.Detection', method: 'memWindowProbe' });
    try {
      assert.equal((await trigger()).ok, true);
      const hit = await agent('native_look', { action: 'read', hookId: hook.hookId });
      buf = hit.regs.x0;
      assert.match(buf, /^0x[0-9a-f]+$/i);
    } finally { await agent('native_hook', { action: 'unhook', hookId: hook.hookId }); }
    const start = async (extra: any) => {
      const r = await root({ action: 'start', serial, session: target.sessionId, tid, addr: buf, width: 8,
        durationMs: 1200, maxEvents: 8, stackBytes: 512, ...extra }); active.push(r.id); return r.id;
    };
    const write = async () => {
      const r = await trigger();
      assert.equal(r.ok, true); assert.equal(Number(r.result.result), 48653);
      const after = await agent('memory_read', { addr: buf, size: 8 });
      // memory_read's wire representation is Base64, not a missing hex field.
      assert.equal(Buffer.from(after.b64, 'base64')[0], 0xbe);
    };
    const id = await start({}); await write();
    const status = await finished(id);
    assert.equal(status.error, undefined); assert.equal(status.complete, true);
    // The JNI fixture seeds its eight bytes, then the callee flips exactly one.
    assert.equal(status.summary.samples, 2); assert.equal(status.summary.lost, 0);
    const read = await root({ action: 'read', id, registers: true, stackSize: 16 });
    assert.equal(read.events.length, 2);
    const event = read.events[0]; assert.equal(event.pid, target.pid); assert.equal(event.tid, tid);
    assert.equal(event.regs.length, 33); assert.equal(event.stack.addr, event.regs[31]);
    assert.equal(event.stack.got, 512); assert.equal(event.stackWindow.got, 16);
    const disasm = await agent('memory_disasm', { addr: event.ip, size: 4 });
    assert.match(disasm.instructions[0].mnemonic, /^(str|stp)/);
    assert.equal((await root({ action: 'read', id, afterSeq: read.events.at(-1).seq })).events.length, 0);
    const capped = await start({ maxEvents: 1 }); await write();
    const cappedStatus = await finished(capped);
    assert.equal(cappedStatus.summary.stopReason, 'event-limit'); assert.equal(cappedStatus.complete, false);
    const stopped = await start({ durationMs: 5000 });
    await root({ action: 'stop', id: stopped });
    assert.equal((await finished(stopped)).summary.stopReason, 'stopped');
    await assert.rejects(() => root({ action: 'start', serial, session: target.sessionId, tid: 1, addr: buf }), /tid-does-not-belong/);
    console.log('root perf self-test: PASS; real sandbox stores: 2/2; kernel GPR/stack + MCP paging: PASS; event-limit/stop/wrong-TID: PASS');
    console.log('RESULT:PASS');
  } finally {
    for (const id of active) await root({ action: 'stop', id }).catch(() => {});
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}
