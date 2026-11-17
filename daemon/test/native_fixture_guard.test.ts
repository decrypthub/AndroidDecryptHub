import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,existsSync,rmSync} from 'node:fs';
import {join,resolve,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';

for(const [script,args] of [['verify_got_restore.ts',['missing-binary']],['verify_qbdi_stack.ts',['missing-binary','missing-qbdi']]] as const){
  test(script+' refuses daily device before probe or filesystem writes',()=>{
    const root=mkdtempSync(join(tmpdir(),'adh-native-guard-')),output=join(root,'must-not-exist');
    try{
      const tool=fileURLToPath(new URL('../../tools/'+script,import.meta.url));
      // Even a regressed verifier cannot discover a real adb executable in this test.
      const result=spawnSync(process.execPath,[tool,'a22fecdd',...args,output],{encoding:'utf8',windowsHide:true,timeout:15000,env:{...process.env,PATH:''}});
      assert.notEqual(result.status,0);assert.match(result.stderr,/daily device refused/);assert.equal(existsSync(output),false);
    }finally{assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep)&&root.includes('adh-native-guard-'));rmSync(root,{recursive:true,force:true});}
  });
}
