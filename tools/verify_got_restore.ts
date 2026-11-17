// Explicit, short-lived native fixture; no Host, installed package, or Zygisk changes.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomUUID} from 'node:crypto';
import {existsSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
const [serial,binary,output,...extra]=process.argv.slice(2);
if(!serial||serial==='a22fecdd'||!binary||!output||extra.length)
  throw new Error('usage: verify_got_restore.ts TEST_SERIAL BUILT_BINARY NEW_PRIVATE_OUTPUT; daily device refused');
assert.ok(existsSync(binary),'built fixture missing');
const dir=resolve(output);assert.ok(!existsSync(dir),'output must be new');
const run=promisify(execFile),remote='/data/local/tmp/adh-got-'+randomUUID();
const adb=async(args:string[])=>(await run('adb',['-s',serial,...args],{timeout:20000,windowsHide:true})).stdout.trim();
const report:any={startedAt:new Date().toISOString(),serial,passed:0,cleanupVerified:false};let owned=false;
mkdirSync(dir,{recursive:true});
try{
  assert.equal(await adb(['get-state']),'device');
  report.device={model:await adb(['shell','getprop','ro.product.model']),sdk:await adb(['shell','getprop','ro.build.version.sdk']),abi:await adb(['shell','getprop','ro.product.cpu.abi'])};
  assert.equal(report.device.abi,'arm64-v8a');
  await adb(['shell','mkdir',remote]);owned=true;
  await adb(['push',resolve(binary),remote+'/verify']);await adb(['shell','chmod','700',remote+'/verify']);
  const stdout=await adb(['shell',remote+'/verify']);writeFileSync(join(dir,'stdout.txt'),stdout+'\n');
  assert.match(stdout,/ADH_GOT_RESTORE_PASS 9/);
  assert.equal(stdout.split(/\r?\n/).filter(s=>s.startsWith('PASS ')).length,9);
  report.passed=9;
}catch(error){report.failure=(error as Error).message;process.exitCode=1;}
finally{
  try{if(owned){const files=await adb(['shell','ls','-A',remote]);assert.ok(files===''||files==='verify','unexpected fixture files; retain for inspection');await adb(['shell','rm','-f',remote+'/verify']);await adb(['shell','rmdir',remote]);}report.cleanupVerified=true;}
  catch(error){report.cleanupError=(error as Error).message;process.exitCode=1;}
  report.completedAt=new Date().toISOString();writeFileSync(join(dir,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}
