import assert from 'node:assert/strict';
import test from 'node:test';
import {localUsbLink,localUsbView,makeUsbInventory} from '../src/local_usb_status.ts';
import {type AdbRunner} from '../src/transport/adb_device.ts';

function adb(rows:string,usbOnly?:string):AdbRunner {
  return async args=>{
    if(args.join(' ')==='devices -l') return 'List of devices attached\n'+rows;
    if(args.join(' ')==='-d get-serialno'&&usbOnly) return usbOnly+'\n';
    throw Error('ADB probe failed');
  };
}
const observer={package:'com.example.demo',model:'PGP110',pid:42,usbSerial:'one',ownFilesSerial:'one'};
test('USB is independent of the matching APP session, while the file gate stays scoped',async()=>{
  const active=adb('one device model:PGP110 transport_id:4','one');
  const waiting=await localUsbView(observer,false,active);
  assert.equal(waiting.online,true); assert.equal(waiting.transport,'usb');
  assert.equal(waiting.appSession,'waiting'); assert.equal(waiting.appFiles,false);
  const demo={...observer,package:'com.adh.sandbox'};
  assert.equal((await localUsbView(demo,false,active)).appFiles,true);
  assert.equal((await localUsbView({...demo,ownFilesSerial:undefined},false,active)).appFiles,false);
  assert.equal((await localUsbView({...demo,ownFilesSerial:'other'},false,active)).appFiles,false);
  assert.equal((await localUsbView(demo,false,adb('one offline'))).appFiles,false);
  assert.equal((await localUsbView(observer,true,active)).appFiles,true);
  const independent=await localUsbView({...observer,fileBrowserOnly:true},false,active);
  assert.equal(independent.appSession,'not-required'); assert.equal(independent.appFiles,true);
  const inventory=await localUsbView({...demo,declaredApiSerial:'one'},false,active);
  assert.deepEqual(inventory.declaredApiPackages,['com.adh.sandbox.apilab']);
  assert.equal(inventory.demoApi,undefined);
  assert.equal(inventory.rootSandbox,true);
  assert.equal((await localUsbView({...demo,declaredApiSerial:'one'},false,adb('one offline'))).declaredApiPackages,undefined);
  assert.equal((await localUsbView({...observer,fileBrowserOnly:true,declaredApiSerial:'one'},false,active)).rootSandbox,undefined);
  const dedicated=await localUsbView({package:'com.adh.sandbox.apilab',model:'PGP110',pid:0,usbSerial:'one',demoApiSerial:'one'},false,active);
  assert.equal(dedicated.demoApi,true);
  assert.equal(dedicated.declaredApiPackages,undefined);
  assert.equal(dedicated.rootSandbox,undefined);
});
test('a missing cable, ADB offline, pending authorization and unknown transport are distinct',async()=>{
  assert.equal(await localUsbLink('one',adb('one device usb:2-1 transport_id:4\nanother device usb:2-2')),'online');
  assert.equal(await localUsbLink('one',adb('one device transport_id:4','other')),'unknown');
  assert.equal(await localUsbLink('one',adb('another device usb:2-2')),'disconnected');
  assert.equal(await localUsbLink('one',adb('one offline')),'offline');
  assert.equal(await localUsbLink('one',adb('one unauthorized')),'unauthorized');
  assert.equal(await localUsbLink('one',async()=>{throw Error('adb unavailable');}),'unknown');
  assert.equal(await localUsbLink('one',async()=>''),'unknown');
});

test('USB inventory includes single-segment system packages and never uses an implicit device',async()=>{
  let calls=0;
  const reader=makeUsbInventory(async args=>{
    if(args.join(' ')==='devices -l') return 'List of devices attached\none device usb:2-1';
    if(args.join(' ')==='-s one shell am get-current-user')return '0';
    assert.equal(args.join(' '),'-s one shell pm list packages --user 0');calls++;return 'package:android\npackage:com.adh.sandbox\npackage:android';
  });
  assert.deepEqual(await reader('one'),[{package:'android'},{package:'com.adh.sandbox'}]);await reader('one');assert.equal(calls,1);await assert.rejects(reader('other'));
});
