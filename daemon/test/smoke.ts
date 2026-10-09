// Host-only smoke test for adhd: boots nothing itself; assumes adhd already running.
// Simulates an agent over TCP using the WS-D length-framed protocol
// ([u32 len BE][u8 type][JSON payload] — see proto/PROTOCOL.md), then checks HTTP /health
// and /api/agents reflect it.
import net from 'node:net';

const HTTP = Number(process.env.ADH_HTTP_PORT ?? 8088);
const AGENT = Number(process.env.ADH_AGENT_PORT ?? 8761);

const FRAME_JSON = 0x01;
function frame(obj: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const hdr = Buffer.alloc(5);
  hdr.writeUInt32BE(payload.length, 0);
  hdr.writeUInt8(FRAME_JSON, 4);
  return Buffer.concat([hdr, payload]);
}

function agentConnect(): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect(AGENT, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
}
async function getJson(path: string): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${HTTP}${path}`);
  return r.json();
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let failed = false;
function check(name: string, cond: boolean, extra?: unknown) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`, extra ?? '');
  if (!cond) failed = true;
}

const health = await getJson('/health');
check('health.ok', health.ok === true, health);

const sock = await agentConnect();
sock.write(frame({
  t: 'hello', agentVer: '0.1.0-smoke', pid: 4242, uid: 10999,
  package: 'com.smoke.test', process: 'com.smoke.test',
  abi: 'arm64-v8a', android: '16', sdk: 36, entry: 'smoke',
}));
sock.write(frame({ t: 'maps', count: 777, regions: [
  { start: '7f00', end: '7f10', perms: 'r-xp', offset: '0', dev: 'fd:00', inode: 1, path: '/system/lib64/libc.so' },
]}));

await sleep(300);
const agents = await getJson('/api/agents');
const found = agents.find((a: any) => a.pid === 4242);
check('agent registered via TCP', !!found, found?.sessionId);
check('maps count propagated', found?.mapsCount === 777, found?.mapsCount);
check('package captured', found?.package === 'com.smoke.test');

sock.end();
await sleep(200);
const after = await getJson('/api/agents');
check('agent marked offline on disconnect', after.find((a: any) => a.pid === 4242)?.online === false);

console.log(failed ? '\nSMOKE FAILED' : '\nSMOKE OK');
process.exit(failed ? 1 : 0);
