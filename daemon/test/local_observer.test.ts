import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptsLocalHello, localViewAllows } from '../src/local_observer.ts';

const observer = { package: 'com.example.owned', pid: 47, model: 'test' };
const hello = { t: 'hello', package: observer.package, pid: observer.pid, entry: 'jni_onload' };

test('USB observation admits only the selected app, exact process and self-loaded connection', () => {
  assert.equal(acceptsLocalHello(observer, hello), true);
  for (const change of [
    { t: 'cmdResult' }, { package: 'com.example.other' }, { pid: 48 }, { entry: 'start' },
  ]) {
    assert.equal(acceptsLocalHello(observer, { ...hello, ...change }), false);
  }
});

test('local observer permits only the read-only, package-scoped Web viewer routes', () => {
  const allows = (path: string, method = 'GET') =>
    localViewAllows(observer, method, new URL(path, 'http://127.0.0.1'));
  assert.equal(allows('/com.example.owned'), true);
  assert.equal(allows('/api/devices?action=list'), true);
  assert.equal(allows('/api/captures/17'), true);
  for (const route of ['/api/captures', '/api/events', '/api/http/exchanges', '/api/detect/summary']) {
    assert.equal(allows(route + '?package=com.example.owned'), true);
    assert.equal(allows(route), false);
    assert.equal(allows(route + '?package=com.example.other'), false);
    assert.equal(allows(route + '?package=com.example.owned&package=com.example.other'), false);
  }
  for (const route of ['/com.example.other', '/api/devices?action=connect', '/mcp', '/api/fs/list', '/api/maintenance']) {
    assert.equal(allows(route), false);
  }
  assert.equal(allows('/api/config', 'POST'), false);
});
