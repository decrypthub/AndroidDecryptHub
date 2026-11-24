import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptsLocalHello, localViewAllows } from '../src/local_observer.ts';

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

test('optional debug-App files route cannot select another target or request a write', () => {
  const path='/api/observer/app-files';
  const url=(q:string)=>new URL(path+'?'+q,'http://127.0.0.1');
  const opted={...observer,ownFilesSerial:'usb-selected'};
  assert.equal(localViewAllows(observer,'GET',url('action=list')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=list')),true);
  assert.equal(localViewAllows(opted,'GET',url('action=preview&path=readme.txt')),true);
  assert.equal(localViewAllows(opted,'POST',url('action=list')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=remove&path=readme.txt')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=list&package=com.example.other')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=list&serial=other')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=list&action=preview')),false);
  assert.equal(localViewAllows(opted,'GET',url('action=list&path=a&path=b')),false);
});
