import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SANDBOX_READ_CAP, assertPackage, confinePackagePath, confineSandboxPath, listSandboxDir,
  parseSandboxOutput, pathInSandbox, pathOwnedByPackage, readSandboxFile, sandboxListCommand,
  sandboxReadCommand, shQuote,
} from '../src/sandbox_fs.ts';

function unquoteShellWord(s: string): string {
  if (!s.startsWith("'") || !s.endsWith("'")) throw new Error('not a single-quoted word');
  let out = '';
  for (let i = 1; i < s.length - 1; i++) {
    if (s[i] !== "'") { out += s[i]; continue; }
    if (s.slice(i, i + 4) === "'\\''") { out += "'"; i += 3; continue; }
    throw new Error(`quote closed early at ${i}`);
  }
  return out;
}

test('sandbox paths stay inside the selected package', () => {
  assert.equal(confineSandboxPath('com.a', '/data/data/com.a'), '/data/data/com.a');
  assert.equal(confineSandboxPath('com.a', '/data/data/com.a/./files'), '/data/data/com.a/files');
  assert.equal(pathInSandbox('com.a', '/data/user/0/com.a/files'), true);
  assert.equal(pathInSandbox('com.a', '/data/user_de/10/com.a'), true);
  assert.equal(pathInSandbox('com.a', '/storage/emulated/0/Android/data/com.a/files'), true);
  assert.throws(() => confineSandboxPath('com.a', '/data/data/com.a/../../etc/passwd'), /沙盒/);
  assert.throws(() => confineSandboxPath('com.a', '/data/data/com.ab'), /沙盒/);
  assert.throws(() => confineSandboxPath('com.a', '/proc/self'), /沙盒/);
  assert.throws(() => confineSandboxPath('com.a', '/data/data/com.a/x\ny'), /沙盒/);
  assert.throws(() => assertPackage('not a package'), /包名/);
  assert.equal(pathInSandbox('com.a', '/data/user/0/com.ab'), false);
});

test('APK lib paths under /data/app belong to the package', () => {
  assert.equal(pathOwnedByPackage('com.chaoxing.mobile', '/data/app/~~x==/com.chaoxing.mobile-abc/lib/arm64/libx.so'), true);
  assert.equal(pathOwnedByPackage('com.chaoxing.mobile', '/data/app/com.chaoxing.mobile-abc/lib/arm64/libx.so'), true);
  assert.equal(pathOwnedByPackage('com.chaoxing.mobile', '/data/app/~~x==/com.other-abc/lib/arm64/libx.so'), false);
  assert.equal(confinePackagePath('com.a', '/data/data/com.a/files/lib.so'), '/data/data/com.a/files/lib.so');
  assert.throws(() => confinePackagePath('com.a', '/system/lib64/libc.so'), /不属于/);
});

test('a quote or semicolon in a file name cannot break out of su -c', () => {
  const abs = confineSandboxPath('com.a', "/data/data/com.a/a'b;echo PWN");
  const cmd = sandboxListCommand(abs);
  const script = unquoteShellWord(cmd.slice('su -c '.length));
  assert.ok(script.startsWith(`p=${shQuote(abs)}`));
  assert.match(script, /echo PWN/);
  assert.doesNotMatch(script, /\n/);
});

test('listing output becomes entries, and a symlink target outside the sandbox is refused', async () => {
  const name = Buffer.from('笔记.txt').toString('base64');
  const listed = await listSandboxDir('com.a', '/data/data/com.a', {
    shell: async (cmd) => {
      assert.match(cmd, /^su -c '/);
      return `REAL /data/user/0/com.a\nOK\nE d 4096 170 755 ${Buffer.from('files').toString('base64')}\nE f 3 171 600 ${name}\n`;
    },
    execOut: async () => { throw new Error('list must not read file bytes'); },
  });
  assert.equal(listed.count, 2);
  assert.equal(listed.entries[0].type, 'd');
  assert.equal(listed.entries[1].name, '笔记.txt');
  assert.equal(listed.entries[1].mode, 0o600);

  await assert.rejects(() => listSandboxDir('com.a', '/data/data/com.a', {
    shell: async () => 'REAL /data/data/com.other\nOK\nE f 1 1 644 YQ==\n',
    execOut: async () => Buffer.alloc(0),
  }), /沙盒/);
});

test('a missing sandbox is a clear error and does not look like an empty directory', async () => {
  await assert.rejects(() => listSandboxDir('com.a', '/data/data/com.a', {
    shell: async () => 'MISSING\n',
    execOut: async () => Buffer.alloc(0),
  }), /沙盒目录不存在/);
  await assert.rejects(() => listSandboxDir('com.a', '/data/data/com.a/gone', {
    shell: async () => 'MISSING\n',
    execOut: async () => Buffer.alloc(0),
  }), /目录不存在/);
});

test('reading follows a resolved path only when it is still inside the sandbox', async () => {
  let reads = 0;
  const body = Buffer.from('hello');
  const ok = await readSandboxFile('com.a', '/data/data/com.a/files/a.txt', {
    shell: async () => 'REAL /data/user/0/com.a/files/a.txt\nSIZE 5\n',
    execOut: async (cmd) => {
      reads++;
      assert.equal(cmd, sandboxReadCommand('/data/user/0/com.a/files/a.txt'));
      return body;
    },
  });
  assert.equal(reads, 1);
  assert.equal(ok.truncated, false);
  assert.equal(ok.fsize, 5);
  assert.equal(Buffer.from(ok.b64, 'base64').toString(), 'hello');

  reads = 0;
  await assert.rejects(() => readSandboxFile('com.a', '/data/data/com.a/files/link', {
    shell: async () => 'REAL /system/build.prop\nSIZE 10\n',
    execOut: async () => { reads++; return Buffer.alloc(0); },
  }), /沙盒/);
  assert.equal(reads, 0);
});

test('a read larger than the cap is truncated and still reports the real size', async () => {
  const chunk = Buffer.alloc(SANDBOX_READ_CAP, 1);
  const r = await readSandboxFile('com.a', '/data/data/com.a/big', {
    shell: async () => `REAL /data/data/com.a/big\nSIZE ${SANDBOX_READ_CAP + 50}\n`,
    execOut: async () => chunk,
  });
  assert.equal(r.truncated, true);
  assert.equal(r.size, SANDBOX_READ_CAP);
  assert.equal(r.fsize, SANDBOX_READ_CAP + 50);
});

test('parser ignores noise and keeps the truncation flag', () => {
  const parsed = parseSandboxOutput('su: ignored\nREAL /data/user/0/com.a\nOK\nTRUNC\nE f 1 2 644 YQ==\n');
  assert.equal(parsed.real, '/data/user/0/com.a');
  assert.equal(parsed.truncated, true);
  assert.equal(parsed.entries[0].name, 'a');
  assert.equal(parsed.code, null);
});
