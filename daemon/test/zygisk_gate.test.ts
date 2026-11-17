import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmdirSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

test('real Zygisk gate refuses missing reboot opt-in and the daily device before creating state or invoking ADB',()=>{
  const directory=mkdtempSync(join(tmpdir(),'adh-p5-zygisk-refuse-')),output=join(directory,'must-not-exist');
  try{for(const args of [['aa165071','no-assets',output],['a22fecdd','no-assets',output,'--allow-device-reboot']]){
    const result=spawnSync(process.execPath,[fileURLToPath(new URL('../../tools/verify_p5_zygisk.ts',import.meta.url)),...args],{windowsHide:true,encoding:'utf8',env:{...process.env,ADH_ADB_PATH:'must-never-run-this-adb.exe'}});
    assert.notEqual(result.status,0);assert.match(result.stderr,/explicit dedicated serial, assets, fresh output and --allow-device-reboot required/);assert.doesNotMatch(result.stderr,/ENOENT/);assert.equal(existsSync(output),false);
  }}finally{rmdirSync(directory);}
});
