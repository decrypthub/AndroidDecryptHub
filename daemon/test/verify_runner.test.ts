import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync,existsSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

const shell=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'bash';
const script=fileURLToPath(new URL('../../tools/verify_all.sh',import.meta.url)).replaceAll('\\','/');
const wrapper=`
adb(){ printf 'adb %s\\n' "$*" >> "$ADH_RUNNER_CALLS"; return 1; }
bash(){ if [[ "$1" == *dev_up.sh ]]; then printf 'bootstrap\\n' >> "$ADH_RUNNER_CALLS"; return 1; fi; printf 'RESULT:PASS\\n'; }
source "$1"
`;

test('runner rejects a zero-exit failure even when followed by a skip marker',t=>{
  if(process.platform==='win32'&&!existsSync(shell)){t.skip('Git Bash unavailable');return;}
  const directory=mkdtempSync(join(tmpdir(),'adh-verify-verdict-'));
  const input=wrapper.replace("printf 'RESULT:PASS\\n'", "printf 'RESULT:FAIL\\nRESULT:SKIP unavailable\\n'");
  try{
    const r=spawnSync(shell,['-s','--',script],{input,encoding:'utf8',timeout:30000,windowsHide:true,env:{...process.env,ADH_VERIFY_MODE:'host',ADH_VERIFY_LOG_DIR:join(directory,'logs').replaceAll('\\','/'),ADH_RUNNER_CALLS:join(directory,'calls').replaceAll('\\','/')}});
    if(r.error&&(r.error as NodeJS.ErrnoException).code==='ENOENT'){t.skip('Bash unavailable');return;}
    assert.equal(r.status,1,r.stdout+r.stderr);assert.match(r.stdout,/FAIL  verify_/);assert.doesNotMatch(r.stdout,/^PASS  /m);
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('verification gate distinguishes unavailable fixtures without concealing failure',t=>{
  if(process.platform==='win32'&&!existsSync(shell)){t.skip('Git Bash unavailable');return;}
  const helper=fileURLToPath(new URL('../../tools/lib/verify_common.sh',import.meta.url)).replaceAll('\\','/');
  for(const [out,code,label] of [['RESULT:SKIP fixture unavailable',0,'SKIP'],['RESULT:FAIL\nRESULT:SKIP fixture unavailable',1,'FAIL'],['RESULT:PASS',0,'PASS']] as const){
    const r=spawnSync(shell,['-s','--',helper],{input:'source "$1"\nALIVE=fixture\nverify_gate fixture 1\n',encoding:'utf8',timeout:30000,windowsHide:true,env:{...process.env,OUT:out}});
    if(r.error&&(r.error as NodeJS.ErrnoException).code==='ENOENT'){t.skip('Bash unavailable');return;}
    assert.equal(r.status,code,r.stdout+r.stderr);assert.match(r.stdout,new RegExp('fixture '+label));
  }
});
for(const mode of ['host','full'])test('verify runner '+mode+' respects device/service boundary before dispatch',t=>{
  if(process.platform==='win32'&&!existsSync(shell)){t.skip('Git Bash unavailable');return;}
  const directory=mkdtempSync(join(tmpdir(),'adh-verify-runner-')),logs=join(directory,'logs');
  const calls=join(directory,'calls');
  try{
    const result=spawnSync(shell,['-s','--',script],{input:wrapper,encoding:'utf8',timeout:30000,windowsHide:true,
      env:{...process.env,ADH_VERIFY_MODE:mode,ANDROID_SERIAL:'a22fecdd',ADH_VERIFY_BOOTSTRAP:'auto',
        ADH_VERIFY_LOG_DIR:logs.replaceAll('\\','/'),ADH_RUNNER_CALLS:calls.replaceAll('\\','/')}});
    if(result.error&&(result.error as NodeJS.ErrnoException).code==='ENOENT'){t.skip('Bash unavailable');return;}
    assert.equal(existsSync(calls),false,'runner invoked ADB or service bootstrap');
    if(mode==='host'){assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stdout,/fail=0/);assert.equal(existsSync(logs),true);}
    else{assert.equal(result.status,2,result.stdout+result.stderr);assert.match(result.stderr,/daily device.*refused before bootstrap/);assert.equal(existsSync(logs),false);}
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('APK installation never implicitly deploys an Agent into sandbox or production module',t=>{
  if(process.platform==='win32'&&!existsSync(shell)){t.skip('Git Bash unavailable');return;}
  const directory=mkdtempSync(join(tmpdir(),'adh-apk-install-')),apk=join(directory,'fixture.apk'),calls=join(directory,'calls'),bad=join(directory,'unexpected-refresh');
  writeFileSync(apk,'synthetic installer fixture, never sent to a real device');
  const envScript=fileURLToPath(new URL('../../tools/lib/env.sh',import.meta.url)).replaceAll('\\','/');
  const input=`source "$1"
adb(){ printf '%s\\n' "$*" >> "$ADH_INSTALL_CALLS"; if [ "$3" = shell ]; then printf 'Success\\n'; fi; }
refresh_agent_so(){ printf 'unexpected\\n' > "$ADH_INSTALL_BAD"; }
ADB=adb install_apk_root "$2" /data/local/tmp/adh-install-fixture.apk fixture-serial
`;
  try{
    const r=spawnSync(shell,['-s','--',envScript,apk.replaceAll('\\','/')],{input,encoding:'utf8',timeout:30000,windowsHide:true,env:{...process.env,ADH_INSTALL_CALLS:calls.replaceAll('\\','/'),ADH_INSTALL_BAD:bad.replaceAll('\\','/')}});
    if(r.error&&(r.error as NodeJS.ErrnoException).code==='ENOENT'){t.skip('Bash unavailable');return;}
    assert.equal(r.status,0,r.stdout+r.stderr);assert.equal(existsSync(bad),false);
    const rows=readFileSync(calls,'utf8').trim().split(/\r?\n/);assert.equal(rows.length,2);assert.match(rows[0],/push .*fixture\.apk/);assert.match(rows[1],/pm install -r -t/);
  }finally{rmSync(directory,{recursive:true,force:true});}
});
