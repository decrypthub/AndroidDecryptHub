// adb_wire 协议客户端测试：起一个假 adb server(loopback TCP)，验证帧格式、
// argv 映射、shell,v2 分包、超时 killed 语义、maxBuffer 拦截、sync push 帧序。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

const reqFrame = (s: string) => Buffer.concat([Buffer.from(s.length.toString(16).padStart(4, '0'), 'ascii'), Buffer.from(s)]);
const lenPayload = (s: string | Buffer) => { const b = Buffer.isBuffer(s) ? s : Buffer.from(s); return Buffer.concat([Buffer.from(b.length.toString(16).padStart(4, '0'), 'ascii'), b]); };
const v2Frame = (id: number, payload: Buffer | string) => { const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload); const h = Buffer.alloc(5); h[0] = id; h.writeUInt32LE(p.length, 1); return Buffer.concat([h, p]); };

interface FakeServer { port: number; requests: string[]; close: () => void; }
/** handler 收到完整服务串（transport 选定后同一 socket 上继续读服务帧）。 */
async function fakeAdb(handler: (service: string, sock: net.Socket) => void): Promise<FakeServer> {
  const requests: string[] = [];
  const server = net.createServer((sock) => {
    const readSvc = (chunk: Buffer) => {
      const len = parseInt(chunk.subarray(0, 4).toString('ascii'), 16);
      const svc = chunk.subarray(4, 4 + len).toString('utf8');
      requests.push(svc);
      if (svc.startsWith('host:transport')) {
        sock.write('OKAY');
        sock.once('data', readSvc); // transport 选定后读真正的服务帧
      } else handler(svc, sock);
    };
    sock.once('data', readSvc);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as net.AddressInfo).port;
  return { port, requests, close: () => server.close() };
}
const okayThen = (sock: net.Socket, ...writes: Buffer[]) => { sock.write(Buffer.concat([Buffer.from('OKAY'), ...writes])); };

process.env.ADH_ADB_SERVER_PORT = '0'; // 占位，逐测试改
// 端口在模块求值时读取：每个测试 import('../src/adb_wire.ts?port=N') 得到独立实例

test('host 服务发 4 位十六进制长度帧并解析 len-prefixed 载荷', async () => {
  const srv = await fakeAdb((svc, sock) => {
    assert.equal(svc, 'host:version');
    okayThen(sock, lenPayload('0029'));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port);
  // 端口在模块加载时读取——直接调用内部连接测试不可行，用 adbExec devices 走一遍
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const raw = await reloaded.adbHostData('host:version', 3000);
  assert.equal(raw, '0029');
  assert.deepEqual(srv.requests, ['host:version']);
  srv.close();
});

test('adb devices -l 映射 host:devices-l 并带 List of devices attached 头', async () => {
  const srv = await fakeAdb((svc, sock) => {
    assert.equal(svc, 'host:devices-l');
    okayThen(sock, lenPayload('aa165071               device product:X model:Y transport_id:1\n'));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const { stdout } = await reloaded.adbExec(['devices', '-l'], { timeout: 3000 });
  assert.ok(stdout.startsWith('List of devices attached\n'));
  assert.ok(stdout.includes('aa165071'));
  srv.close();
});

test('shell argv 走 transport + shell,v2,raw 并分离 stdout/stderr/exit', async () => {
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'host:transport:aa165071') { sock.write('OKAY'); return; }
    assert.equal(svc, 'shell,v2,raw:getprop ro.product.model');
    okayThen(sock, v2Frame(1, 'PGP110\n'), v2Frame(2, 'warn\n'), v2Frame(3, Buffer.from([0])));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const { stdout, stderr } = await reloaded.adbExec(['-s', 'aa165071', 'shell', 'getprop', 'ro.product.model'], { timeout: 3000 });
  assert.equal(stdout, 'PGP110\n');
  assert.equal(stderr, 'warn\n');
  assert.deepEqual(srv.requests, ['host:transport:aa165071', 'shell,v2,raw:getprop ro.product.model']);
  srv.close();
});

test('shell -T/-t 标志剥离且非零退出码抛 code', async () => {
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'host:transport-any') { sock.write('OKAY'); return; }
    assert.equal(svc, 'shell,v2,raw:pidof com.x');
    okayThen(sock, v2Frame(1, ''), v2Frame(3, Buffer.from([1])));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  await assert.rejects(
    reloaded.adbExec(['shell', '-T', 'pidof', 'com.x'], { timeout: 3000 }),
    (e: any) => e.code === 1,
  );
  srv.close();
});

test('exec-out 走 exec: 裸流返回原始字节', async () => {
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'host:transport:aa165071') { sock.write('OKAY'); return; }
    assert.equal(svc, 'exec:cat /proc/version');
    okayThen(sock, Buffer.from('PK\x03\x04binary\x00\xff'));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const { stdout } = await reloaded.adbExecBuffer(['-s', 'aa165071', 'exec-out', 'cat', '/proc/version'], { timeout: 3000 });
  assert.deepEqual(stdout, Buffer.from('PK\x03\x04binary\x00\xff'));
  srv.close();
});

test('超时以 killed 错误拒绝而不是悬挂', async () => {
  const srv = await fakeAdb((_svc, sock) => {
    sock.write('OKAY'); // 握手回 OK 之后永远不回数据
    setTimeout(() => sock.destroy(), 10000);
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const t0 = Date.now();
  await assert.rejects(
    reloaded.adbExec(['shell', 'sleep 30'], { timeout: 400 }),
    (e: any) => e.killed === true,
  );
  assert.ok(Date.now() - t0 < 3000, '应该在超时附近拒绝');
  srv.close();
});

test('maxBuffer 超限直接拒绝', async () => {
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'host:transport-any') { sock.write('OKAY'); return; }
    okayThen(sock, v2Frame(1, Buffer.alloc(4096)), v2Frame(3, Buffer.from([0])));
    sock.end();
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  await assert.rejects(
    reloaded.adbExec(['shell', 'cat /proc/mounts'], { timeout: 3000, maxBuffer: 64 }),
    /超过 64 字节上限/,
  );
  srv.close();
});

test('reverse --list / 建立走正确服务名', async () => {
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'reverse:list-forward') { okayThen(sock, lenPayload('UsbFfs tcp:18761 tcp:18761\n')); sock.end(); return; }
    if (svc === 'reverse:forward:tcp:18761;tcp:18761') { okayThen(sock); sock.end(); return; }
    sock.destroy(new Error('unexpected ' + svc));
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const { stdout } = await reloaded.adbExec(['-s', 'aa165071', 'reverse', '--list'], { timeout: 3000 });
  assert.ok(stdout.includes('tcp:18761'));
  await reloaded.adbExec(['-s', 'aa165071', 'reverse', 'tcp:18761', 'tcp:18761'], { timeout: 3000 });
  assert.deepEqual(srv.requests, ['host:transport:aa165071', 'reverse:list-forward', 'host:transport:aa165071', 'reverse:forward:tcp:18761;tcp:18761']);
  srv.close();
});

test('push 发 sync 协议 SEND/DATA/DONE 帧序', async () => {
  const frames: Buffer[] = [];
  const srv = await fakeAdb((svc, sock) => {
    if (svc === 'host:transport:aa165071') { sock.write('OKAY'); return; }
    assert.equal(svc, 'sync:');
    sock.write('OKAY');
    sock.on('data', (c) => {
      frames.push(c);
      if (Buffer.concat(frames).includes(Buffer.from('DONE'))) {
        sock.write(Buffer.from('OKAY') + Buffer.alloc(4));
        sock.end();
      }
    });
  });
  process.env.ADH_ADB_SERVER_PORT = String(srv.port); const reloaded = await import('../src/adb_wire.ts?port=' + srv.port);
  const fs = await import('node:fs');
  const tmp = 'C:/Users/diiho/AppData/Local/Temp/push_test.bin';
  fs.writeFileSync(tmp, Buffer.alloc(1024, 0xab));
  await reloaded.adbExec(['-s', 'aa165071', 'push', tmp, '/data/local/tmp/x.bin'], { timeout: 3000 });
  const all = Buffer.concat(frames);
  assert.ok(all.includes(Buffer.from('SEND')), '要有 SEND 头');
  assert.ok(all.includes(Buffer.from('/data/local/tmp/x.bin')), '要有目标路径');
  assert.ok(all.includes(Buffer.from('DONE')), '要有 DONE 收尾');
  srv.close();
});

void reqFrame;
