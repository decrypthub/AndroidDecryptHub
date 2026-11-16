import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync,writeFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {DeviceClientIdentity} from '../src/device_client_identity.ts';

test('Host key reads never enroll implicitly; corruption is preserved and never resets identity',()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-p4-client-')),file=join(root,'client.json'),identity=new DeviceClientIdentity(file);
  try{
    assert.throws(()=>identity.read(),(e:any)=>e.code==='CLIENT_IDENTITY_UNAVAILABLE');assert.equal(existsSync(file),false);
    const first=identity.ensure();assert.equal(identity.ensure().clientId,first.clientId);
    writeFileSync(file,'corrupt');assert.throws(()=>identity.ensure(),(e:any)=>e.code==='CLIENT_IDENTITY_UNAVAILABLE');assert.equal(readFileSync(file,'utf8'),'corrupt');
  }finally{assert.ok(root.startsWith(join(tmpdir(),'adh-p4-client-')));rmSync(root,{recursive:true,force:true});}
});

test('two independent Hosts creating the same client identity cannot replace each other\'s key',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-p4-client-')),file=join(root,'client.json');
  try{
    const source=new URL('../src/device_client_identity.ts',import.meta.url).href;
    const script=`const {DeviceClientIdentity}=await import(${JSON.stringify(source)});process.stdout.write(new DeviceClientIdentity(process.argv[1]).ensure().clientId);`;
    const run=()=>promisify(execFile)(process.execPath,['--input-type=module','-e',script,file],{windowsHide:true,timeout:15000});
    const [one,two]=await Promise.all([run(),run()]);assert.equal(String(one.stdout),String(two.stdout));assert.equal(new DeviceClientIdentity(file).read().clientId,String(one.stdout));
  }finally{assert.ok(root.startsWith(join(tmpdir(),'adh-p4-client-')));rmSync(root,{recursive:true,force:true});}
});
