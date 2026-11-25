import test from 'node:test';
import assert from 'node:assert/strict';

const { captureInstallVerdict } = await import('../src/service.ts');

function captureReply() {
  return {
    op: 'capture_start', ok: true, cryptoModule: '',
    evp: 1, cipherInit: 1, cipherCtxFree: 1, digest: 2, hmac: 2, digestSign: 1, sslWrite: 2, sslRead: 2,
    pkey: { sign: 1, verify: 1, encrypt: 1, decrypt: 1 },
    aead: { seal: 1, open: 2 },
    digestSignVerify: { signInit: 2, verifyInit: 2, signFinal: 1, verifyUpdate: 1, verifyFinal: 1 },
    fileModule: 'libc.so',
    file: { open: 1, openat: 0, read: 1, write: 1, syscall: 1, readChk: 1, writeChk: 1 },
    sysModule: 'libc.so',
    sys: { ptrace: 1, access: 1, faccessat: 1, prop: 1, propread: 1 },
    skipped: '', on: true,
  };
}

test('a missing file symbol in the explicitly named file module is partial, not a failed crypto scan', () => {
  const verdict = captureInstallVerdict(captureReply());
  assert.equal(verdict.attempted, 31);
  assert.equal(verdict.installed, 30);
  assert.deepEqual(verdict.notInstalled, ['file.openat']);
  assert.equal(verdict.partial, true);
  assert.equal(verdict.complete, false);
  assert.equal(verdict.ok, true);
});

test('an all-module crypto scan still fails when a requested crypto symbol installs nowhere', () => {
  const reply = captureReply();
  reply.evp = 0;
  const verdict = captureInstallVerdict(reply);
  assert.equal(verdict.notInstalled.includes('evp'), true);
  assert.equal(verdict.ok, false);
});

test('a named crypto module may be partial as long as some requested crypto hook installed', () => {
  const reply = captureReply();
  reply.cryptoModule = 'libjavacrypto.so';
  reply.aead.seal = 0;
  const verdict = captureInstallVerdict(reply);
  assert.equal(verdict.partial, true);
  assert.equal(verdict.ok, true);
});

test('requesting file hooks in a module that installs none of them is a real failure', () => {
  const reply = captureReply();
  for (const key of Object.keys(reply.file)) reply.file[key] = 0;
  const verdict = captureInstallVerdict(reply);
  assert.equal(verdict.ok, false);
});
