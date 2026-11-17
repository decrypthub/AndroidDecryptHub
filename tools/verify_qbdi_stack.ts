// A short-lived self-contained Android process. No Host, APK, scope, module or reverse changes.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomUUID} from 'node:crypto';
import {existsSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
const [serial,binary,qbdi,output,...extra]=process.argv.slice(2);
assert.ok(serial&&serial!=='a22fecdd'&&binary&&qbdi&&output&&!extra.length,'explicit test serial/binary/QBDI/new output required; daily device refused');
assert.ok(existsSync(binary)&&existsSync(qbdi),'build fixture and prepare QBDI first');
const dir=resolve(output);assert.ok(!existsSync(dir),'output must be new');mkdirSync(dir,{recursive:true});
const run=promisify(execFile),remote='/data/local/tmp/adh-qbdi-stack-'+randomUUID();
const adb=async(args:string[])=>(await run('adb',['-s',serial,...args],{timeout:20000,windowsHide:true})).stdout.trim();
const report:any={serial,startedAt:new Date().toISOString(),passed:0,cleanupVerified:false};let owned=false;
try{
  assert.equal(await adb(['get-state']),'device');assert.equal(await adb(['shell','getprop','ro.product.cpu.abi']),'arm64-v8a');
  await adb(['shell','mkdir',remote]);owned=true;
  await adb(['push',resolve(binary),remote+'/verify']);await adb(['push',resolve(qbdi),remote+'/libQBDI.so']);
  await adb(['shell','chmod','700',remote+'/verify']);
  const stdout=await adb(['shell','LD_LIBRARY_PATH='+remote+' '+remote+'/verify']);
  writeFileSync(join(dir,'stdout.txt'),stdout+'\n');assert.match(stdout,/ADH_QBDI_STACK_PASS 4/);
  assert.equal(stdout.split(/\r?\n/).filter(s=>s.startsWith('PASS ')).length,4);report.passed=4;
}catch(error){
  report.failure=(error as Error).message;const failure=error as Error&{stdout?:string;stderr?:string};
  if(typeof failure.stdout==='string')writeFileSync(join(dir,'failed-stdout.txt'),failure.stdout);
  if(typeof failure.stderr==='string')writeFileSync(join(dir,'failed-stderr.txt'),failure.stderr);
  process.exitCode=1;
}finally{
  try{
    if(owned){const files=(await adb(['shell','ls','-A',remote])).split(/\r?\n/).filter(Boolean);assert.ok(files.every(f=>['verify','libQBDI.so'].includes(f)),'unexpected fixture file; retain directory');await adb(['shell','rm','-f',remote+'/verify',remote+'/libQBDI.so']);await adb(['shell','rmdir',remote]);}
    report.cleanupVerified=true;
  }catch(error){report.cleanupError=(error as Error).message;process.exitCode=1;}
  report.completedAt=new Date().toISOString();writeFileSync(join(dir,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}
