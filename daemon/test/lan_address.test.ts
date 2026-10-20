import test from 'node:test';
import assert from 'node:assert/strict';

import { isUsefulLanIPv4 } from '../src/config.ts';

test('keeps a real ethernet address and drops virtual or link-local ones', () => {
  assert.equal(isUsefulLanIPv4('以太网', '192.168.200.108'), true);
  assert.equal(isUsefulLanIPv4('wlan0', '10.0.0.8'), true);
  assert.equal(isUsefulLanIPv4('VMware Network Adapter VMnet8', '192.168.159.1'), false);
  assert.equal(isUsefulLanIPv4('VMware Network Adapter VMnet1', '192.168.150.1'), false);
  assert.equal(isUsefulLanIPv4('vEthernet (WSL)', '172.22.32.1'), false);
  assert.equal(isUsefulLanIPv4('WLAN', '169.254.100.122'), false);
  assert.equal(isUsefulLanIPv4('Loopback Pseudo-Interface 1', '127.0.0.1'), false);
  assert.equal(isUsefulLanIPv4('以太网', '192.168.1.2', true), false);
});
