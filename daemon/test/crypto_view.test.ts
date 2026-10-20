import test from 'node:test';
import assert from 'node:assert/strict';
import { cryptoView, javaHook, readablePreview } from '../src/crypto_view.ts';

const hex = (text: string) => Buffer.from(text, 'utf8').toString('hex');

test('a Java digest row names the algorithm, the direction, both sizes, and the hook', () => {
  const input = 'h'.repeat(48);
  const view = cryptoView({
    source: 'java', func: 'MessageDigest.digest', algo: 'SHA-256', op: 'digest',
    inl: 48, hex: hex(input), outHex: hex('x'.repeat(32)), preview: input,
  });
  assert.equal(view.title, 'SHA-256');
  assert.equal(view.direction, '哈希');
  assert.equal(view.hook, 'MessageDigest.digest');
  assert.equal(view.sizeLabel, '48 B → 32 B');
  assert.equal(view.preview, input);
  assert.equal(view.show, true);
  assert.equal(view.hasKey, false);
});

test('a Java cipher row shows the transformation, decrypt, the key mark, and Cipher.doFinal', () => {
  const input = '{"token":"a"}';
  const view = cryptoView({
    source: 'java', func: 'Cipher.doFinal', algo: 'AES/CBC/PKCS5Padding', op: 'decrypt',
    inl: Buffer.byteLength(input), hex: hex(input), outHex: hex('plain'), keyHex: '0011', preview: input,
  });
  assert.equal(view.title, 'AES/CBC/PKCS5Padding');
  assert.equal(view.direction, '解密');
  assert.equal(view.hook, 'Cipher.doFinal');
  assert.equal(view.sizeLabel, Buffer.byteLength(input) + ' B → 5 B');
  assert.equal(view.hasKey, true);
  assert.equal(view.truncated, false);
});

test('a Java init with no bytes stays out of the list', () => {
  const view = cryptoView({ source: 'java', algo: 'AES/CBC/PKCS5Padding', op: 'encrypt', keyHex: 'aa', inl: 0, hex: '' });
  assert.equal(view.show, false);
  assert.equal(view.hook, 'Cipher.init');
  assert.equal(view.sizeLabel, '');
});

test('native digest does not pretend Digest is the algorithm', () => {
  const input = 'h'.repeat(48);
  const view = cryptoView({
    source: 'native', func: 'EVP_DigestUpdate', algo: '摘要 Digest', op: '输入',
    inl: 48, hex: hex(input), preview: input,
  });
  assert.equal(view.title, '摘要 · 未识别');
  assert.equal(view.direction, '哈希');
  assert.equal(view.hook, 'EVP_DigestUpdate');
  assert.equal(view.sizeLabel, '48 B');
  assert.equal(view.preview, input);
  assert.equal(view.outBytes, 0);
});

test('a clipped native buffer keeps the real length and says it was cut', () => {
  const view = cryptoView({
    source: 'native', func: 'EVP_CipherUpdate', algo: '对称加解密', op: '明文',
    inl: 20000, hex: '0011', keyHex: 'ff', preview: '..',
  });
  assert.equal(view.title, '对称 · 未识别');
  assert.equal(view.direction, '');
  assert.equal(view.truncated, true);
  assert.equal(view.sizeLabel, '20000 B 截断');
  assert.equal(view.hasKey, true);
  assert.equal(view.preview, '');
});

test('a concrete algorithm on a native record replaces the vague title', () => {
  const view = cryptoView({
    source: 'native', func: 'EVP_DigestUpdate', algo: 'SHA-256', op: '输入',
    inl: 4, hex: hex('abcd'), preview: 'abcd',
  });
  assert.equal(view.title, 'SHA-256');
  assert.equal(view.direction, '哈希');
  assert.equal(view.hook, 'EVP_DigestUpdate');
});

test('javaHook names the method from the operation and whether a body was present', () => {
  assert.equal(javaHook('digest', true), 'MessageDigest.digest');
  assert.equal(javaHook('mac', false), 'Mac.init');
  assert.equal(javaHook('mac', true), 'Mac.doFinal');
  assert.equal(javaHook('verify', true), 'Signature.verify');
  assert.equal(javaHook('sign', false), 'Signature.initSign');
  assert.equal(javaHook('encrypt', true), 'Cipher.doFinal');
});

test('an all-dot preview is not readable text', () => {
  assert.equal(readablePreview('....'), '');
  assert.equal(readablePreview('  hi'), 'hi');
});
