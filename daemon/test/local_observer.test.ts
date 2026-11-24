import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptsLocalHello } from '../src/local_observer.ts';

const observer = { package: 'com.example.owned', pid: 47, model: 'test' };
const hello = { t: 'hello', package: observer.package, pid: observer.pid, entry: 'jni_onload' };

test('USB observation admits the selected process from its own loader or an injection start', () => {
  assert.equal(acceptsLocalHello(observer, hello), true);
  assert.equal(acceptsLocalHello(observer, { ...hello, entry: 'start' }), true);
  // A restart arrives with a new pid and must still be admitted — the pid gate deadlocked the
  // panel every time the app was killed outside it. Other packages and message shapes stay out.
  assert.equal(acceptsLocalHello(observer, { ...hello, pid: 48 }), true);
  for (const change of [
    { t: 'cmdResult' }, { package: 'com.example.other' }, { entry: 'gadget' },
  ]) {
    assert.equal(acceptsLocalHello(observer, { ...hello, ...change }), false);
  }
});
