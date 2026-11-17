// Read-only snapshot of ADH installation/state. Only creates a private, owned backup directory.
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdirSync,existsSync,readFileSync,writeFileSync,openSync,closeSync} from 'node:fs';
import {resolve,relative,join,sep,isAbsolute} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
const [serial,output,...extra]=process.argv.slice(2);
assert.ok(serial&&serial!=='a22fecdd'&&output&&!extra.length,'explicit dedicated serial and new private output required; daily device refused');
const dir=resolve(output),repo=resolve(import.meta.dirname,'..'),inside=relative(repo,dir);
assert.ok(inside==='..'||inside.startsWith('..'+sep)||isAbsolute(inside),'credential-bearing backups must be outside the source repository');
assert.ok(!existsSync(dir),'backup output must be new');mkdirSync(dir,{recursive:true,mode:0o700});
const run=promisify(execFile),adb=process.env.ADH_ADB_PATH||'adb';
const command=async(args:string[],timeout=20000)=>(await run(adb,['-s',serial,...args],{windowsHide:true,timeout,maxBuffer:1024*1024})).stdout.trim();
const su=(cmd:string,timeout=20000)=>command(['exec-out','su','-c',cmd],timeout);
const nonce=randomBytes(6).toString('hex'),remote='/data/local/tmp/adh-upgrade-'+nonce;
const report:any={schemaVersion:1,serial,remote,startedAt:new Date().toISOString(),verified:false};
try{
  if(process.platform==='win32'){
    const sid=(await run('powershell.exe',['-NoProfile','-NonInteractive','-Command','[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],{windowsHide:true})).stdout.trim();
    assert.match(sid,/^S-1-[0-9-]+$/);await run('icacls.exe',[dir,'/inheritance:r','/grant:r',`*${sid}:(OI)(CI)F`,'*S-1-5-18:(OI)(CI)F'],{windowsHide:true});
  }
  assert.match(await su('id'),/uid=0\(root\)/);
  const critical='/data/adb/adh/scope.json /data/adb/adh/host.endpoint /data/adb/modules/adh/module.prop';
  const before=await su('sha256sum '+critical);assert.equal(before.split('\n').length,3);
  const targets=['/data/adb/modules/adh','/data/adb/adh'];
  for(const pkg of ['com.adh.manager','com.adh.sandbox']){
    const paths=(await command(['shell','pm','path',pkg])).split(/\r?\n/).filter(Boolean).map(p=>p.replace(/^package:/,''));
    assert.ok(paths.length,pkg+' must be installed for rollback');
    for(const path of paths){assert.match(path,/^\/data\/app\/[A-Za-z0-9_~+\/.=\-]+\.apk$/);targets.push(path);}
    targets.push('/data/user/0/'+pkg);
  }
  report.targets=targets;report.criticalBefore=before;
  await su(`umask 077; mkdir ${remote} && echo ${nonce} > ${remote}/owner`);
  assert.equal(await su('cat '+remote+'/owner'),nonce);
  await su(`tar -czf ${remote}/backup.tar.gz -C / ${targets.map(p=>p.slice(1)).join(' ')}`,90000);
  const remoteSha=(await su('sha256sum '+remote+'/backup.tar.gz')).split(/\s+/)[0];assert.match(remoteSha,/^[a-f0-9]{64}$/);
  const archive=join(dir,'backup.tar.gz'),errPath=join(dir,'transfer.stderr'),out=openSync(archive,'wx',0o600),err=openSync(errPath,'wx',0o600);
  try{
    await new Promise<void>((yes,no)=>{const child=spawn(adb,['-s',serial,'exec-out','su','-c','cat '+remote+'/backup.tar.gz'],{windowsHide:true,stdio:['ignore',out,err]});const timer=setTimeout(()=>{child.kill();no(new Error('backup transfer timed out; retain remote snapshot'));},90000);child.once('error',error=>{clearTimeout(timer);no(error)});child.once('exit',(code,signal)=>{clearTimeout(timer);code===0?yes():no(new Error('backup transfer failed '+code+'/'+signal));});});
  }finally{closeSync(out);closeSync(err);}
  assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'),remoteSha,'raw ADB archive transfer changed bytes');
  writeFileSync(join(dir,'targets.json'),JSON.stringify(targets));
  const validate=`import sys,json,tarfile,posixpath
targets=[p.lstrip('/') for p in json.load(open(sys.argv[2]))]
with tarfile.open(sys.argv[1],'r:gz') as archive:
 names=[]
 for member in archive:
  name=posixpath.normpath(member.name)
  assert not name.startswith('/') and '..' not in name.split('/'), 'unsafe archive path'
  assert any(name==p or name.startswith(p+'/') for p in targets), 'unexpected archive member'
  names.append(name)
 assert all(p in names for p in targets), 'missing backup target'
 print(len(names))
`;
  const validated=await run('python',['-c',validate,archive,join(dir,'targets.json')],{windowsHide:true,timeout:30000});
  report.members=Number(validated.stdout.trim());report.sha256=remoteSha;
  assert.equal(await su('sha256sum '+critical),before,'critical state changed while backing up; do not upgrade');
  report.verified=true;
}catch(error){report.failure=(error as Error).message;process.exitCode=1;}
finally{report.completedAt=new Date().toISOString();writeFileSync(join(dir,'report.json'),JSON.stringify(report,null,2),{mode:0o600});console.log(JSON.stringify({verified:report.verified,members:report.members,failure:report.failure,report:join(dir,'report.json')}));}
