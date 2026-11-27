#!/usr/bin/env bash
# Host-only settings/import/persistence acceptance through current P1 version fences.
set -uo pipefail
source "$(dirname "$0")/lib/verify_common.sh"
verify_resolve_env_host
if [ -z "$(printenv ADH_VERIFY_OWNED_ROOT)" ] || [ -z "$(printenv ADH_DATA_DIR)" ] ||
   ! verify_pid_owned "$(daemon_pid_on_port "$HTTP")"; then
  echo 'RESULT:SKIP settings acceptance requires an explicitly isolated, owned Host/data root'
  exit 0
fi
OUT="$(node --input-type=module - "$ROOT" "$BASE" <<'EOF'
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const [root,base]=process.argv.slice(2),client=randomUUID(),failures=[];
const chk=(label,ok)=>{console.log((ok?'PASS ':'FAIL ')+label);if(!ok)failures.push(label);};
async function get(path){return (await fetch(base+path,{headers:{'x-adh-client-id':client}})).json();}
async function post(path,body){
  const headers={'content-type':'application/json','x-adh-client-id':client};
  const prepared=await (await fetch(base+'/api/operations/prepare',{method:'POST',headers,body:JSON.stringify({path,method:'POST',arguments:body})})).json();
  if(!prepared.ok)throw Error('operation preparation refused for '+path);
  headers['x-adh-operation']=JSON.stringify({expectedRevision:prepared.revision,controlEpoch:prepared.epoch,hostEpoch:prepared.hostEpoch,idempotencyKey:randomUUID()});
  const response=await fetch(base+path,{method:'POST',headers,body:JSON.stringify(body)});
  return {status:response.status,body:await response.json()};
}
const original=await get('/api/config');
chk('GET config schema, family filters and stats',!!original.settings?.capture?.families&&!!original.stats);
const retain=original.settings.capture.retain===2000?2100:2000;
const displayCap=original.settings.ui.displayCap===150?175:150;
try{
  const changed=await post('/api/config',{capture:{retain}});
  chk('POST applies capture and confirms persistence',changed.status===200&&changed.body.persisted===true&&changed.body.applied?.includes('capture'));
  chk('config readback matches changed retain',(await get('/api/config')).settings.capture.retain===retain);
  const {resolveStoragePaths}=await import(pathToFileURL(join(root,'daemon/src/storage.ts')).href);
  const disk=JSON.parse(await readFile(join(resolveStoragePaths().dataDir,'settings.json'),'utf8'));
  chk('isolated settings.json matches readback',disk.capture.retain===retain);
  const exported=await get('/api/settings/export');
  chk('export keeps settings schema',typeof exported.ui?.displayCap==='number');
  const imported=await post('/api/settings/import',{ui:{displayCap}});
  chk('import merges and persists the requested section',imported.status===200&&imported.body.persisted===true&&imported.body.applied?.includes('ui'));
  chk('import readback matches display cap',(await get('/api/config')).settings.ui.displayCap===displayCap);
  const rejected=await post('/api/settings/import',{nope:1});
  chk('unsupported import is rejected',rejected.status===400&&rejected.body.code==='INVALID_SETTINGS');
  const cleared=await post('/api/data/clear',{what:'bogus'});
  chk('invalid legacy cleanup is rejected without clearing',cleared.status===400&&cleared.body.ok!==true);
  const guide=await (await fetch(base+'/api/mcp/config')).text();
  chk('MCP config uses the published CLI guide',['pip install android-decrypt-hub','adh connect','mcpServers'].every(s=>guide.includes(s)));
  const html=await (await fetch(base+'/')).text();
  chk('web keeps compact advanced Host settings and MCP/import-export entries',['advanced-host-settings','/api/mcp/config','settings/export','settings/import'].every(s=>html.includes(s)));
  const ui=spawnSync(process.execPath,['--test','--test-reporter=tap',root+'/panel/test/host-settings.test.mjs'],{encoding:'utf8',env:{...process.env,ADH_PANEL_ROOT:root+'/panel'}});
  chk('actual Vue/API import confirmation, observed versions, no replay and LAN-safe ID',ui.status===0&&Number(/# pass (\d+)/.exec(ui.stdout??'')?.[1]??0)>=7&&Number(/# fail (\d+)/.exec(ui.stdout??'')?.[1]??-1)===0);if(ui.status!==0)console.log(ui.stdout,ui.stderr);
}catch(error){chk('settings roundtrip threw: '+error.message,false);}
finally{
  // Restore only fields still holding our values; never replace a later human edit.
  try{
    const current=(await get('/api/config')).settings,patch={};
    if(current.capture.retain===retain)patch.capture={retain:original.settings.capture.retain};
    else chk('retain changed independently; leave it intact',current.capture.retain===original.settings.capture.retain);
    if(current.ui.displayCap===displayCap)patch.ui={displayCap:original.settings.ui.displayCap};
    else chk('display cap changed independently; leave it intact',current.ui.displayCap===original.settings.ui.displayCap);
    if(Object.keys(patch).length){const restored=await post('/api/config',patch);chk('restore owned settings changes',restored.status===200&&restored.body.persisted===true);}
  }catch(error){chk('settings restore refused: '+error.message,false);}
}
console.log(failures.length?'RESULT:FAIL':'RESULT:PASS');
process.exitCode=failures.length?1:0;
EOF
)"
echo "$OUT"
verify_gate 'v1.9 settings: shared versions, persistence, import and owned restore' 0
