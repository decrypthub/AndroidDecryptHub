// Opt-in real Zygisk integration. Two phone reboots; never restarts the existing PC Host.
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import net from 'node:net';
const [serial,assets,output,approval]=process.argv.slice(2);
assert.ok(serial&&serial!=='a22fecdd'&&assets&&output&&approval==='--allow-device-reboot','explicit dedicated serial, assets, fresh output and --allow-device-reboot required');
const root=resolve(import.meta.dirname,'..'),dir=resolve(output);assert.ok(!existsSync(dir),'fresh output required');mkdirSync(dir,{recursive:true});
const nonce=randomBytes(6).toString('hex'),remote='/data/local/tmp/adh-p5-'+nonce,socket='adh_p5_'+nonce,pkg='com.adh.p5sandbox',moduleId='adh_p5_'+nonce,modulePath='/data/adb/modules/'+moduleId,stateRoot='/data/adb/adh-p5-'+nonce;
const run=promisify(execFile),adb=process.env.ADH_ADB_PATH||'adb';
const command=async(args:string[],timeout=15000)=>(await run(adb,['-s',serial,...args],{windowsHide:true,timeout,maxBuffer:1024*1024})).stdout.trim();
const su=(cmd:string,timeout=15000)=>command(['exec-out','su','-c',cmd],timeout);
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const report:any={schemaVersion:2,mode:'real-zygisk-private-namespace',deviceRebootAuthorized:true,ownFixtureForeground:true,nonce,remote,stateRoot,moduleId,cases:[],reboots:[],unverified:['default production namespace deployment/upgrade','other ROMs/architectures','init_array-before-load and Java/inline early steps','all algorithms/module combinations beyond the named representative probes']};
let host:ReturnType<typeof spawn>|undefined,deviceChild:ReturnType<typeof spawn>|undefined,usb:any,installed=false,moduleInstalled=false,baseline:any,fixturePid:number|undefined,binding:any,planDigest:string;
const base='http://127.0.0.1:18088';let sequence=0;
const request=async(path:string,body?:any)=>{const response=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return response.json() as Promise<any>;};
async function tool(name:string,args:any,write=false){if(write){const path=name==='devices'?'/api/devices':'/api/hook-plans';const c=await request('/api/operations/prepare',{path,method:'POST',arguments:args});assert.equal(c.ok,true,JSON.stringify(c));args={...args,_operation:{expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch,idempotencyKey:'p5-'+nonce+'-'+(++sequence)}};}
  const response=await request('/mcp',{jsonrpc:'2.0',id:sequence,method:'tools/call',params:{name,arguments:args}});if(!response.result)throw Error(JSON.stringify(response));const value=JSON.parse(response.result.content[0].text);if(value._operation?.state==='unknown')(report.unknownOperations??=[]).push(value._operation);return value;}
async function read(peer:any,method:string,params:any={}){const v=await tool('devices',{action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,method,params});assert.equal(v.ok,true,JSON.stringify(v));return v.result;}
async function deviceWrite(peer:any,method:string,params:any={}){const state=await read(peer,'device.state');const value=await tool('devices',{action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.stateRevision,method,params},true);assert.equal(value._operation?.state,'succeeded',JSON.stringify(value));return value.result.result;}
async function hookDevice(peer:any,action:string,extra:any={},write=false){const state=await read(peer,'device.state');const value=await tool('hook_plans',{action,deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.stateRevision,package:pkg,...extra},write);return value;}
async function until(fn:()=>Promise<any>,label:string,budget=12000){const deadline=Date.now()+budget;let last;do{try{const v=await fn();if(v)return v;}catch(e){last=e;}await pause(150);}while(Date.now()<deadline);throw Error(label+': '+String(last||'condition not observed'));}
async function check(name:string,fn:()=>Promise<any>){console.log('RUN '+name);try{const result=await fn();report.cases.push({name,state:'pass',evidence:result??null});console.log('PASS '+name);}catch(error){report.cases.push({name,state:report.unknownOperations?.length?'unknown':'fail',error:(error as Error).message});throw error;}}
const unwrap=(v:any)=>{assert.equal(v._operation?.state,'succeeded',JSON.stringify(v));return v.result.result;};
const protectedFiles='/data/adb/adh/scope.json /data/adb/adh/host.endpoint /data/adb/modules/adh/libadh_agent.so /data/adb/modules/adh/zygisk/arm64-v8a.so /data/adb/modules/adh/daemon.apk /data/adb/modules/adh/module.prop';
async function hostIdentity(){const value=await run('powershell.exe',['-NoProfile','-NonInteractive','-Command',"$adhConnection=Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $adhConnection) { 'null'; exit 0 }; $adhProcess=Get-Process -Id $adhConnection.OwningProcess -ErrorAction Stop; @{pid=$adhProcess.Id;started=$adhProcess.StartTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress"],{windowsHide:true});return JSON.parse(value.stdout);}
async function originalHostIdle(){const identity=await hostIdentity();if(identity){const response=await fetch('http://127.0.0.1:8088/api/agents',{signal:AbortSignal.timeout(5000)});assert.equal(response.ok,true,'occupied original Host cannot be inspected');const all=await response.json() as any[];assert.ok(Array.isArray(all));assert.equal(all.filter(s=>s.online).length,0,'active original Host analysis appeared; refuse reboot');}return identity;}
async function mappings(){return (await command(['reverse','--list'])).split('\n').filter(Boolean).map(line=>line.trim().split(/\s+/).slice(-2).join(' ')).sort();}
async function restoreMappings(){for(const row of baseline.reverse){const [source,destination]=row.split(' ');assert.match(source,/^tcp:\d+$/);assert.match(destination,/^tcp:\d+$/);const current=(await mappings()).find(line=>line.startsWith(source+' '));if(current){assert.equal(current,row,'a mapping was replaced; never overwrite it');continue;}await command(['reverse','--no-rebind',source,destination]);}}
async function reboot(label:string){
  if(baseline)assert.deepEqual(await originalHostIdle(),baseline.host,'original Host changed; refuse reboot');
  const before=await su('cat /proc/sys/kernel/random/boot_id');console.log('REBOOT '+label);await command(['reboot']);await pause(2500);const deadline=Date.now()+240000;let logged=0;
  while(Date.now()<deadline){try{const boot=await su('cat /proc/sys/kernel/random/boot_id',4000);if(boot!==before&&(await command(['shell','getprop','sys.boot_completed'],4000))==='1'){
        report.reboots.push({label,before,after:boot});await restoreMappings();console.log('BOOT_READY '+label);return;
      }}catch{}if(Date.now()-logged>20000){console.log('BOOT_WAIT '+label);logged=Date.now();}await pause(2000);}
  throw Error('device boot deadline; phone state and cleanup unconfirmed');
}
async function stage(ttl=180,peer=usb){const p=(await hookDevice(peer,'early-prepare')).result;binding=p.binding;return unwrap(await hookDevice(peer,'early-stage',{digest:planDigest,binding,expectedCacheRevision:p.cacheRevision,expiresAt:Math.floor(Date.now()/1000)+ttl,offline:'keep-until-expiry'},true));}
async function launch(expect:boolean,opts:any={}){
  await command(['shell','am','force-stop',pkg]);await su(`mkdir -p /data/user/0/${pkg}/cache /data/user/0/${pkg}/files; chown ${binding.uid}:${binding.uid} /data/user/0/${pkg}/cache /data/user/0/${pkg}/files; rm -f /data/user/0/${pkg}/cache/adh_zygisk.log /data/user/0/${pkg}/files/p5-result.json /data/user/0/${pkg}/files/p5-zygisk-application.json /data/user/0/${pkg}/files/p5-zygisk-probes.json; : > ${stateRoot}/zygisk_inject.log`);
  if(opts.marker){const local=join(dir,'probe-config.json');writeFileSync(local,JSON.stringify({marker:opts.marker,tlsPort:opts.tlsPort}));await command(['push',local,remote+'/probe-config.json']);await su(`cp ${remote}/probe-config.json /data/user/0/${pkg}/files/p5-zygisk-probes.json; chown ${binding.uid}:${binding.uid} /data/user/0/${pkg}/files/p5-zygisk-probes.json; chmod 600 /data/user/0/${pkg}/files/p5-zygisk-probes.json`);}
  const launchedAt=Date.now();const started=await command(['shell','am','start','-W','-n',pkg+'/.ProbeActivity']);assert.ok(!started.includes('Error'),started);
  const latest=await request('/api/agents');const injected=latest.filter((s:any)=>s.package===pkg&&s.connectedAt>=launchedAt).sort((a:any,b:any)=>b.connectedAt-a.connectedAt)[0];if(injected)report.lastPid=injected.pid;
  const receipt=await until(async()=>{try{return JSON.parse(await su(`cat /data/user/0/${pkg}/files/p5-result.json`));}catch{return null;}},'Application receipt',18000);assert.ok(!receipt.error,JSON.stringify(receipt));assert.equal(receipt.selfLoad,false);assert.equal(receipt.applicationCallback,true);assert.equal(receipt.servicePid,receipt.pid);assert.equal(receipt.uid,binding.uid);assert.equal(receipt.agentMemfdBeforeApplicationProbe,true,'Agent must already be present at the first app callback; no self-load allowed');
  report.lastPid=receipt.pid;writeFileSync(join(dir,'application-'+receipt.pid+'.json'),JSON.stringify(receipt));
  const session=await until(async()=>{const all=await request('/api/agents');return all.find((s:any)=>s.online&&s.package===pkg&&s.pid===receipt.pid);},'injected Agent hello');assert.match(session.selfModule||'',/memfd:jit-cache/);
  report.lastSession=session.sessionId;const status=await tool('native_hook',{action:'status',session:session.sessionId});const hooks=status.status?.hooks||status.hooks||[];
  const decisions=await su('cat '+stateRoot+'/zygisk_inject.log');const appLog=await su(`cat /data/user/0/${pkg}/cache/adh_zygisk.log`).catch(()=>'');const logcat=await command(['logcat','-d','--pid',String(receipt.pid),'-s','adh-zygisk:I','*:S']);
  writeFileSync(join(dir,'launch-'+receipt.pid+'.json'),JSON.stringify({receipt,early:session.earlyPlan,status,decisions,appLog,logcat},null,2));
  const pattern=new RegExp('early companion pkg='+pkg.replaceAll('.','\\.')+' uid='+binding.uid+' bytes=(\\d+)');const bytes=Number(pattern.exec(decisions)?.[1]);assert.ok(Number.isFinite(bytes),'real companion delivery audit missing');assert.equal(bytes>0,expect,decisions);
  if(expect){assert.equal(session.earlyPlan?.state,opts.captureOnly&&opts.allOff?'partial-or-failed':'applied',JSON.stringify(session.earlyPlan));assert.equal(session.earlyPlan.digest,planDigest);
    assert.match(appLog+logcat,new RegExp('early post-specialize .*result='+(opts.allOff?'0':'1')+' before_agent_start=1'));
    if(opts.captureOnly){assert.equal(hooks.length,0);return {receipt,session,early:session.earlyPlan,companionBytes:bytes,postLogSource:appLog?'own-app-debug-file':'logcat'};}
    const owned=hooks.find((h:any)=>h.id===session.earlyPlan.steps[0].hookId);assert.ok(owned);assert.equal(owned.module,'libjavacore.so');assert.equal(owned.symbol,'getpid');assert.ok(owned.hits>=1,JSON.stringify(owned));assert.equal(session.uid,binding.uid);assert.equal(owned.slotCurrent,owned.replacement,'Hook must still be installed at Application startup');assert.equal(owned.slotOwned,true);
    const evidence=await until(async()=>{const list=await tool('live_captures',{session:session.sessionId,includeText:true,encoding:'b64',limit:1000});writeFileSync(join(dir,'capture-window-'+receipt.pid+'.json'),JSON.stringify(list));return list.captures?.find((r:any)=>r.func==='NATIVE_HOOK'&&r.hookId===owned.id&&BigInt(String(r.tsNs))>=BigInt(receipt.beforeNs)&&BigInt(String(r.tsNs))<=BigInt(receipt.afterNs));},'Hook event inside first Application call window');
    assert.equal(evidence.tid,receipt.pid);writeFileSync(join(dir,'early-hit-'+receipt.pid+'.json'),JSON.stringify({hookId:owned.id,eventId:evidence.id,tsNs:evidence.tsNs,window:[receipt.beforeNs,receipt.afterNs],sameMainThread:true}));
    assert.match(appLog+logcat,/early post-specialize .*result=1 before_agent_start=1/);return {receipt,session,companionBytes:bytes,early:session.earlyPlan,hits:owned.hits,firstApplicationEvent:evidence.id,postLogSource:appLog?'own-app-debug-file':'logcat'};}
  assert.equal(session.earlyPlan,null);assert.equal(hooks.length,0);return {receipt,companionBytes:bytes,early:null,hooks:0};
}
try{
  for(const port of [18088,18761])await new Promise<void>((yes,no)=>{const server=net.createServer();server.once('error',no);server.listen(port,'0.0.0.0',()=>server.close(()=>yes()));});
  assert.match(await su('id'),/uid=0\(root\)/);assert.equal(await su('getenforce'),'Enforcing');assert.equal(await command(['shell','getprop','ro.product.cpu.abi']),'arm64-v8a');
  const packagePath=await command(['shell','pm','path',pkg]).catch((e:any)=>{if(e.code===1&&!String(e.stdout||'').trim())return '';throw e;});assert.equal(packagePath,'','existing test package must not be overwritten');
  const originalHost=await originalHostIdle();
  const hashes=await su('sha256sum '+protectedFiles);assert.equal(hashes.split('\n').length,6);baseline={host:originalHost,hashes,reverse:await mappings()};report.before=baseline;for(const mapping of baseline.reverse)assert.match(mapping,/^tcp:\d+ tcp:\d+$/,'only existing TCP reverse mappings are supported; refuse before device mutation');
  assert.ok(!baseline.reverse.some((r:string)=>/^tcp:(18088|18761) /.test(r)));assert.ok(!(await su('cat /data/adb/adh/scope.json')).includes(pkg),'test package is in the original module scope');
  report.artifacts={agentSha256:createHash('sha256').update(readFileSync(join(root,'agent/build-isolated-18761/libadh_agent.so'))).digest('hex'),
    daemonApkSha256:createHash('sha256').update(readFileSync(join(assets,'daemon.apk'))).digest('hex'),
    sandboxApkSha256:createHash('sha256').update(readFileSync(join(assets,'sandbox-v1.apk'))).digest('hex')};
  assert.match(readFileSync(join(root,'agent/build-isolated-18761/CMakeCache.txt'),'utf8'),/ADH_AGENT_CONNECT_PORT:STRING=18761/);
  const buildLog=await run('C:/Program Files/Git/bin/bash.exe',['-lc',`bash tools/build_p5_zygisk.sh ${nonce} '${dir.replaceAll('\\','/')}'`],{cwd:root,windowsHide:true,timeout:90000,maxBuffer:1024*1024});writeFileSync(join(dir,'companion-build.log'),buildLog.stdout+buildLog.stderr);
  await command(['shell','mkdir','-m','755',remote]);for(const [file,name] of [[join(assets,'daemon.apk'),'daemon.apk'],[join(assets,'sandbox-v1.apk'),'sandbox.apk'],[join(root,'agent/build-isolated-18761/libadh_agent.so'),'libadh_agent.so'],[join(dir,'companion-build/libadh.so'),'arm64-v8a.so']])await command(['push',file,remote+'/'+name]);
  await su(`chmod 444 ${remote}/daemon.apk`);assert.match(await su(`pm install ${remote}/sandbox.apk`,90000),/Success/);installed=true;
  const document={version:1,mode:'allowlist',packages:[pkg],policy:{[pkg]:{c:{d:false,h:false,s:false,a:false,t:false,e:false,y:false}}}};writeFileSync(join(dir,'scope.json'),JSON.stringify(document));await command(['push',join(dir,'scope.json'),remote+'/scope.json']);
  // No installer/action/boot script from the production module is invoked.
  assert.equal(await su(`if [ -e ${modulePath} ] || [ -e ${stateRoot} ]; then echo exists; fi`),'');moduleInstalled=true;
  await su(`mkdir ${modulePath} && echo ${nonce} > ${modulePath}/p5-owner && mkdir ${modulePath}/zygisk && cp ${remote}/arm64-v8a.so ${modulePath}/zygisk/arm64-v8a.so && cp ${remote}/libadh_agent.so ${modulePath}/libadh_agent.so && chmod 755 ${modulePath} ${modulePath}/zygisk ${modulePath}/zygisk/arm64-v8a.so && touch ${modulePath}/skip_mount && printf 'id=${moduleId}\nname=ADH P5 isolated Zygisk test\nversion=0.0.0-test\nversionCode=1\nauthor=ADH test\ndescription=Temporary own-package-only fixture\n' > ${modulePath}/module.prop && mkdir -m 700 ${stateRoot} && cp ${remote}/scope.json ${stateRoot}/scope.json && : > ${stateRoot}/host.endpoint && touch ${stateRoot}/zygisk_debug`);
  // Match existing module labels instead of widening SELinux or trusting mkdir defaults.
  for(const [source,target] of [['/data/adb/modules/adh',modulePath],['/data/adb/modules/adh/zygisk',modulePath+'/zygisk'],['/data/adb/modules/adh/libadh_agent.so',modulePath+'/libadh_agent.so'],['/data/adb/modules/adh/zygisk/arm64-v8a.so',modulePath+'/zygisk/arm64-v8a.so']]){
    const context=(await su('ls -Zd '+source)).split(/\s+/)[0];assert.match(context,/^[A-Za-z0-9_:,.-]+$/);await su(`chcon ${context} ${target}`);
  }
  await reboot('load isolated module');
  const deviceLog=openSync(join(dir,'device.log'),'a');deviceChild=spawn(adb,['-s',serial,'exec-out','su','-c',`CLASSPATH=${remote}/daemon.apk app_process /system/bin --nice-name=adh-p5-${nonce} com.adh.daemon.P5DeviceFixture ${remote} ${socket} ${moduleId}`],{windowsHide:true,stdio:['ignore',deviceLog,deviceLog]});closeSync(deviceLog);
  const ready=await until(async()=>{try{return JSON.parse(await su('cat '+remote+'/ready.json'));}catch{return null;}},'private root domain');fixturePid=ready.pid;assert.equal(ready.agentPath,modulePath+'/libadh_agent.so');
  const discovery=(await run(adb,['devices','-l'],{windowsHide:true})).stdout;const row=discovery.split('\n').find(s=>s.startsWith(serial+' '));const transport=/transport_id:(\d+)/.exec(row||'')?.[1];assert.ok(transport);
  const hostLog=openSync(join(dir,'host.log'),'a');host=spawn(process.execPath,[join(root,'tools/p5_isolated_host.ts'),serial,transport,remote,socket,join(dir,'host')],{cwd:join(root,'daemon'),windowsHide:true,stdio:['ignore',hostLog,hostLog]});closeSync(hostLog);await until(()=>request('/health'),'private Host');
  usb=await tool('devices',{action:'connect',serial,transportId:transport,usbMode:'stdio'},true);assert.equal(usb._operation?.state,'succeeded',JSON.stringify(usb));
  const plan={schemaVersion:1,id:'zygisk-before-application',title:'Actual post-specialize early GOT',package:pkg,families:{digest:false,hmac:false,symmetric:false,asymmetric:false,tls:false,aead:false,system:false},steps:[{id:'runtime-getpid',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libjavacore.so',symbol:'getpid'}}]};
  const saved=await tool('hook_plans',{action:'put',plan,expectedLibraryRevision:0},true);assert.equal(saved.ok,true);planDigest=saved.digest;const preview=(await hookDevice(usb,'migration-preview')).result;unwrap(await hookDevice(usb,'migration-apply',{digest:planDigest,scopeRevision:preview.scopeRevision},true));
  await check('real companion delivery, post-specialize apply and pre-Application GOT hit',async()=>{await stage();return launch(true);});
  await check('expired cache is refused by actual companion; no Hook',async()=>{const s=await stage(3);await pause(Math.max(0,s.entry.expiresAt*1000-Date.now()+300));return launch(false);});
  await check('revoked cache is refused by actual companion; no Hook',async()=>{const s=await stage();unwrap(await hookDevice(usb,'early-revoke',{deploymentId:s.entry.deploymentId,expectedCacheRevision:s.cacheRevision},true));return launch(false);});
  const {zygiskExtendedCases}=await import('./p5_zygisk_cases.ts');
  await zygiskExtendedCases({check,tool,read,deviceWrite,hookDevice,stage,launch,command,su,until,pause,usb,remote,pkg,dir,nonce,
    get planDigest(){return planDigest},set planDigest(value){planDigest=value}});
  await check('actual UID change rejects old cache through Zygisk',async()=>{await stage();await launch(true);const old=structuredClone(binding);await command(['shell','am','force-stop',pkg]);assert.match(await su('pm uninstall '+pkg),/Success/);assert.match(await su(`pm install ${remote}/sandbox.apk`,90000),/Success/);binding=(await hookDevice(usb,'early-prepare')).result.binding;assert.notEqual(binding.uid,old.uid);assert.equal(binding.agentSha256,old.agentSha256);return {oldUid:old.uid,newUid:binding.uid,...await launch(false)};});
  await check('module Agent bytes alone change; actual FD load rejects old cache',async()=>{await stage();await launch(true);const before=structuredClone(binding);await command(['shell','am','force-stop',pkg]);const variant=Buffer.concat([readFileSync(join(root,'agent/build-isolated-18761/libadh_agent.so')),Buffer.from('\nP5-ZYGISK-REPLACEMENT\n')]);writeFileSync(join(dir,'agent-variant.so'),variant);await command(['push',join(dir,'agent-variant.so'),remote+'/agent-variant.so']);await su(`cp ${remote}/agent-variant.so ${modulePath}/libadh_agent.so`);binding=(await hookDevice(usb,'early-prepare')).result.binding;const {agentSha256:oldHash,...old}=before,{agentSha256:newHash,...fresh}=binding;assert.deepEqual(fresh,old);assert.equal(newHash,createHash('sha256').update(variant).digest('hex'));assert.notEqual(oldHash,newHash);return {onlyAgentHashChanged:true,...await launch(false)};});
  await check('missing root broker fails closed through actual companion',async()=>{await stage();await launch(true);await su('touch '+remote+'/stop');await until(async()=>await su(`if [ ! -d /proc/${fixturePid} ]; then echo stopped; fi`)==='stopped','own broker stopped');return launch(false);});
}catch(error){
  if(report.lastPid)try{writeFileSync(join(dir,'failure-own-app-crash.txt'),await command(['logcat','-b','crash','-d','--pid',String(report.lastPid)]));}catch{}
  try{writeFileSync(join(dir,'failure-decisions.txt'),await su('cat '+stateRoot+'/zygisk_inject.log'));if(report.lastPid)writeFileSync(join(dir,'failure-logcat.txt'),await command(['logcat','-d','--pid',String(report.lastPid),'-s','adh-zygisk:I','*:S']));}catch{}
  if(report.lastPid)try{
    const pid=String(report.lastPid);assert.match(pid,/^\d+$/);assert.ok((await su(`cat /proc/${pid}/cmdline`)).startsWith(pkg));
    writeFileSync(join(dir,'failure-threads.txt'),await su(`cat /proc/${pid}/status; for p5task in /proc/${pid}/task/*; do echo TASK:$p5task; cat $p5task/comm $p5task/wchan $p5task/stack; done`));
    writeFileSync(join(dir,'failure-backtrace.txt'),await su(`debuggerd -b ${pid}`,18000));
  }catch{}
  report.failure={message:(error as Error).message,stack:(error as Error).stack};console.error('FAIL '+(error as Error).message);process.exitCode=1;}
finally{
  const errors:string[]=[];
  const cleanup=async(label:string,fn:()=>Promise<void>)=>{try{await fn();}catch(error){errors.push(label+': '+(error as Error).message);process.exitCode=1;}};
  await cleanup('own package',async()=>{if(installed){await command(['shell','am','force-stop',pkg]);assert.match(await su('pm uninstall '+pkg),/Success/);}});
  await cleanup('own Host',async()=>{if(host&&host.exitCode===null&&host.signalCode===null){host.kill();await new Promise<void>(r=>{host!.once('exit',()=>r());setTimeout(r,3000);});assert.ok(host.exitCode!==null||host.signalCode!==null,'own Host did not exit');}});
  await cleanup('own broker',async()=>{if(deviceChild?.exitCode===null)await su('touch '+remote+'/stop');});
  // Each step runs even if an earlier independent cleanup failed. Ownership and idle-Host
  // checks still gate module removal/reboot; a failed cleanup is never reported as PASS.
  await cleanup('own module',async()=>{if(moduleInstalled){assert.equal(await su('cat '+modulePath+'/p5-owner'),nonce,'never remove an unowned module');await su('rm -rf '+modulePath);await reboot('unload isolated module');assert.equal(await su(`if [ -e ${modulePath} ]; then echo exists; fi`),'');}});
  await cleanup('original scene',async()=>{if(baseline){assert.equal(await su('sha256sum '+protectedFiles),baseline.hashes);assert.deepEqual(await hostIdentity(),baseline.host);assert.deepEqual(await mappings(),baseline.reverse);report.originalHostAndFilesUnchanged=true;}});
  await cleanup('private ports',async()=>{for(const port of [18088,18761])await new Promise<void>((yes,no)=>{const server=net.createServer();server.once('error',no);server.listen(port,'0.0.0.0',()=>server.close(()=>yes()));});});
  report.cleanupVerified=errors.length===0;if(errors.length)report.cleanupErrors=errors;
  if(host?.exitCode===null)host.kill();if(deviceChild?.exitCode===null)deviceChild.kill();report.completedAt=new Date().toISOString();writeFileSync(join(dir,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({passed:report.cases.filter((c:any)=>c.state==='pass').length,failure:report.failure?.message,cleanupVerified:report.cleanupVerified,hostAndFilesUnchanged:report.originalHostAndFilesUnchanged,report:join(dir,'report.json')}));
}
