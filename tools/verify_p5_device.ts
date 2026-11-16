// Explicit opt-in real-device sandbox. Never installs the production module/Manager/daemon.
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import net from 'node:net';
const [serial,transport,assets,output,suite]=process.argv.slice(2);
assert.ok(suite===undefined||suite==='final','suite must be omitted (baseline) or final');
assert.ok(serial&&serial!=='a22fecdd'&&/^\d+$/.test(transport)&&assets&&output,'explicit dedicated root serial, transport id, built assets and private output required');
const root=resolve(import.meta.dirname,'..'),dir=resolve(output);assert.ok(!existsSync(dir),'use a fresh private result directory');mkdirSync(dir,{recursive:true});
const nonce=randomBytes(6).toString('hex'),remote='/data/local/tmp/adh-p5-'+nonce,socket='adh_p5_'+nonce,pkg='com.adh.p5sandbox';
const run=promisify(execFile),adb=process.env.ADH_ADB_PATH||'adb',prefix=['-t',transport];
const command=async(args:string[],timeout=20000)=>(await run(adb,[...prefix,...args],{windowsHide:true,timeout,maxBuffer:1024*1024})).stdout.trim();
const quote=(v:string)=>"'"+v.replaceAll("'","'\\''")+"'";
const su=(cmd:string,timeout=20000)=>command(['exec-out','su','-c',cmd],timeout);
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const report:any={schemaVersion:1,mode:'real-android-sandbox',cases:[],unverified:['production Zygisk pre/post-specialize delivery (module unchanged)','full-device reboot and reconnect','Java/inline early steps (unsupported)'],remote};
let host:ReturnType<typeof spawn>|undefined,deviceChild:ReturnType<typeof spawn>|undefined,usb:any,lan:any,installed=false,started=false,baseline:any;
const base='http://127.0.0.1:18088';let sequence=0;
const request=async(path:string,body?:any)=>{const response=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return response.json() as Promise<any>;};
async function tool(name:string,args:any,write=false){if(write){const path=name==='devices'?'/api/devices':'/api/hook-plans';const c=await request('/api/operations/prepare',{path,method:'POST',arguments:args});assert.equal(c.ok,true,JSON.stringify(c));args={...args,_operation:{expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch,idempotencyKey:'p5-'+nonce+'-'+(++sequence)}};}
  const response=await request('/mcp',{jsonrpc:'2.0',id:sequence,method:'tools/call',params:{name,arguments:args}});if(!response.result)throw Error(JSON.stringify(response));const value=JSON.parse(response.result.content[0].text);if(value._operation?.state==='unknown')(report.unknownOperations??=[]).push(value._operation);return value;}
async function read(peer:any,method:string,params:any={}){const v=await tool('devices',{action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,method,params});assert.equal(v.ok,true,JSON.stringify(v));return v.result;}
async function deviceWrite(peer:any,method:string,params:any={}){const state=await read(peer,'device.state');const value=await tool('devices',{action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.stateRevision,method,params},true);assert.equal(value._operation?.state,'succeeded',JSON.stringify(value));return value.result.result;}
async function hookDevice(peer:any,action:string,extra:any={},write=false){const state=await read(peer,'device.state');const value=await tool('hook_plans',{action,deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.stateRevision,package:pkg,...extra},write);return value;}
async function until(fn:()=>Promise<any>,label:string,budget=12000){const deadline=Date.now()+budget;let last;do{try{const v=await fn();if(v)return v;}catch(e){last=e;}await pause(150);}while(Date.now()<deadline);throw Error(label+': '+String(last||'condition not observed'));}
async function check(name:string,fn:()=>Promise<any>){console.log('RUN '+name);try{const result=await fn();report.cases.push({name,state:'pass',evidence:result??null});console.log('PASS '+name);}catch(error){report.cases.push({name,state:report.unknownOperations?.length?'unknown':'fail',error:(error as Error).message});throw error;}}
async function baselineNow(){const live:any=await(await fetch('http://127.0.0.1:8088/api/agents')).json();const hashes=await su('sha256sum /data/adb/adh/scope.json /data/adb/adh/host.endpoint /data/adb/modules/adh/libadh_agent.so');assert.equal(hashes.split('\n').filter(line=>/^[a-f0-9]{64}\s/.test(line)).length,3,'real scene hashes required');return {hashes,sessions:live.filter((s:any)=>s.online).map((s:any)=>({id:s.sessionId,pid:s.pid,start:s.starttimeTicks})),processes:await su("ps -A -o PID,NAME | grep -E 'adh-device-daemon|com.shizhuang.duapp'"),reverse:await command(['reverse','--list'])};}
const unwrap=(v:any)=>{assert.equal(v._operation?.state,'succeeded',JSON.stringify(v));return v.result.result;};
let binding:any,cacheRevision:number,migration:any,originalScope:string,planDigest:string;
async function stage(peer:any,ttl=180){const prepared=(await hookDevice(peer,'early-prepare')).result;binding=prepared.binding;cacheRevision=prepared.cacheRevision;const info=await hookDevice(peer,'early-stage',{digest:planDigest,binding,expectedCacheRevision:cacheRevision,expiresAt:Math.floor(Date.now()/1000)+ttl,offline:'keep-until-expiry'},true);return unwrap(info);}
async function brokerWire(){return su(`CLASSPATH=${remote}/daemon.apk app_process /system/bin com.adh.daemon.P5BrokerFetch ${socket}_early ${binding.uid} ${remote}/wire.bin`);}
async function launch(expect:boolean,opts:any={}){
  await command(['shell','am','force-stop',pkg]);const wire=await brokerWire();const count=Number(/WIRE_BYTES=(\d+)/.exec(wire)?.[1]);assert.equal(count>0,expect,wire);
  await su(`mkdir -p /data/user/0/${pkg}/files; rm -f /data/user/0/${pkg}/files/p5-result.json; cp ${opts.stalePath||remote+'/wire.bin'} /data/user/0/${pkg}/files/p5-wire.bin; chown -R ${binding.uid}:${binding.uid} /data/user/0/${pkg}/files; chmod 600 /data/user/0/${pkg}/files/p5-wire.bin`);
  const extras=opts.marker?['--es','marker',opts.marker,'--ei','tlsPort',String(opts.tlsPort)]:[];
  const result=await command(['shell','am','start-foreground-service','-n',pkg+'/.ProbeService','--es','agentSha',binding.agentSha256,...extras]);assert.ok(!result.includes('Error'),result);
  const receipt=await until(async()=>{try{return JSON.parse(await su(`cat /data/user/0/${pkg}/files/p5-result.json`))}catch{return null;}},'sandbox bootstrap');
  assert.ok(!receipt.error,JSON.stringify(receipt));writeFileSync(join(dir,'bootstrap-'+receipt.pid+'.json'),JSON.stringify(receipt));assert.equal(receipt.probeReturn,receipt.pid);assert.equal(receipt.probeBeforeAgentStart,true);assert.equal(receipt.earlyApply,opts.earlyApply??(expect?1:-1),JSON.stringify(receipt));
  const session=await until(async()=>{const all=await request('/api/agents');return all.find((s:any)=>s.online&&s.package===pkg&&s.pid===receipt.pid);},'isolated agent hello');
  const status=await tool('native_hook',{action:'status',session:session.sessionId});const hooks=status.status?.hooks||status.hooks||[];
  if(opts.marker){assert.equal(receipt.allProbesBeforeAgentStart,true);for(const [family,ok] of Object.entries(receipt.probes))assert.equal(ok,true,family);return {receipt,session,hooks};}
  if(opts.rejected){assert.equal(session.earlyPlan?.state,'rejected');assert.equal(hooks.length,0);return {receipt,early:session.earlyPlan};}
  if(expect){assert.equal(session.earlyPlan?.state,'applied',JSON.stringify(session.earlyPlan));const owned=hooks.find((h:any)=>h.id===session.earlyPlan.steps[0].hookId);assert.ok(owned,JSON.stringify(status));assert.ok(owned.hits>=1,JSON.stringify(owned));assert.equal(owned.symbol,'getpid');return {receipt,early:session.earlyPlan,hits:owned.hits};}
  assert.equal(session.earlyPlan,null);assert.equal(hooks.length,0);return {receipt,early:null};
}
try{
  for(const port of [18088,18761])await new Promise<void>((yes,no)=>{const s=net.createServer();s.once('error',no);s.listen(port,'0.0.0.0',()=>s.close(()=>yes()));});
  const discovery=await(await run(adb,['devices','-l'],{windowsHide:true})).stdout;assert.ok(discovery.split('\n').some(s=>s.startsWith(serial+' ')&&s.includes('transport_id:'+transport)),'selected serial/transport changed');assert.match(await su('id'),/uid=0\(root\)/);
  assert.equal(await command(['shell','getprop','ro.product.cpu.abi']),'arm64-v8a');const existing=await command(['shell','pm','path',pkg]).catch(error=>{if(error.code===1&&!String(error.stdout||'').trim())return '';throw error;});assert.equal(existing,'','sandbox package already exists; do not overwrite unknown work');
  baseline=await baselineNow();assert.ok(!baseline.reverse.includes('tcp:18088')&&!baseline.reverse.includes('tcp:18761'),'isolated reverse ports already owned');assert.ok(!(await su('cat /data/adb/adh/scope.json')).includes(pkg),'sandbox must not enter the active Zygisk scope');
  const cache=readFileSync(join(root,'agent','build-isolated-18761','CMakeCache.txt'),'utf8');assert.match(cache,/ADH_AGENT_CONNECT_PORT:STRING=18761/,'build agent with ADH_AGENT_CONNECT_PORT=18761 first');
  await command(['shell','mkdir','-m','755',remote]);await command(['push',join(assets,'daemon.apk'),remote+'/daemon.apk']);await su(`chmod 444 ${remote}/daemon.apk`);await command(['push',join(assets,'sandbox-v1.apk'),remote+'/sandbox.apk']);assert.match(await su(`pm install -r ${remote}/sandbox.apk`,90000),/Success/);installed=true;
  originalScope='{\n "version":19,"mode":"allowlist","packages":["com.adh.p5sandbox"],"policy":{"com.adh.p5sandbox":{"c":{"d":false,"h":true,"future":7},"retired":{"bypass":true}}},"future":{"preserved":[1,2]}\n}\n';writeFileSync(join(dir,'scope-before.json'),originalScope);await command(['push',join(dir,'scope-before.json'),remote+'/scope.json']);
  const deviceLog=openSync(join(dir,'device.log'),'a');deviceChild=spawn(adb,[...prefix,'exec-out','su','-c',`CLASSPATH=${remote}/daemon.apk app_process /system/bin --nice-name=adh-p5-${nonce} com.adh.daemon.P5DeviceFixture ${remote} ${socket}`],{windowsHide:true,stdio:['ignore',deviceLog,deviceLog]});closeSync(deviceLog);started=true;
  const ready=await until(async()=>{try{return JSON.parse(await su(`cat ${remote}/ready.json`));}catch{return null;}},'private device domain ready');report.fixturePid=ready.pid;report.device={serial,model:await command(['shell','getprop','ro.product.model']),sdk:await command(['shell','getprop','ro.build.version.sdk']),abi:'arm64-v8a'};
  const log=openSync(join(dir,'host.log'),'a');host=spawn(process.execPath,[join(root,'tools','p5_isolated_host.ts'),serial,transport,remote,socket,join(dir,'host')],{cwd:join(root,'daemon'),windowsHide:true,stdio:['ignore',log,log]});closeSync(log);await until(()=>request('/health'),'private Host ready');
  usb=await tool('devices',{action:'connect',serial,transportId:transport,usbMode:'stdio'},true);assert.equal(usb._operation?.state,'succeeded',JSON.stringify(usb));
  const plan={schemaVersion:1,id:'p5-early-device',title:'Isolated Android GOT proof',package:pkg,families:{digest:false,hmac:false,symmetric:false,asymmetric:false,tls:false,aead:false,system:false},steps:[{id:'getpid-before-host',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libp5target.so',symbol:'getpid'}}]};
  const saved=await tool('hook_plans',{action:'put',plan,expectedLibraryRevision:0},true);assert.equal(saved.applied,false);planDigest=saved.digest;
  const preview=await hookDevice(usb,'migration-preview');assert.equal(preview.result.scopeRaw,originalScope);migration=unwrap(await hookDevice(usb,'migration-apply',{digest:planDigest,scopeRevision:preview.result.scopeRevision},true));
  if(suite==='final'){
    const {finalCases}=await import('./p5_final_cases.ts');
    await finalCases({check,tool,read,deviceWrite,hookDevice,stage,launch,brokerWire,command,su,until,pause,usb,remote,pkg,dir,assets,root,ready,
      get binding(){return binding},set binding(value){binding=value},set planDigest(value){planDigest=value}});
  }else{
  await check('Android PackageManager and release ABI binding',async()=>{const p=(await hookDevice(usb,'early-prepare')).result;assert.equal(p.supported,true);const expected=createHash('sha256').update(readFileSync(join(root,'agent','build-isolated-18761','libadh_agent.so'))).digest('hex');assert.equal(p.binding.agentSha256,expected,'APK must contain the port-isolated Agent before starting it');binding=p.binding;assert.equal(binding.uid,ready.uid);return {supported:true,uid:binding.uid,signers:binding.signers.length,apkFiles:binding.apks.length};});
  await check('early GOT installed and hit before Agent Host connection',async()=>{await stage(usb);return launch(true);});
  await check('expired cache denies real broker delivery and installs no Hook',async()=>{const s=await stage(usb,3);const delay=s.entry.expiresAt*1000-Date.now()+300;await pause(Math.max(0,delay));return launch(false);});
  await check('real APK replacement invalidates the cached binding',async()=>{await stage(usb);await command(['shell','am','force-stop',pkg]);await command(['push',join(assets,'sandbox-v2.apk'),remote+'/sandbox-v2.apk']);assert.match(await su(`pm install -r ${remote}/sandbox-v2.apk`,90000),/Success/);const after=(await hookDevice(usb,'early-prepare')).result.binding;assert.notDeepEqual(after,binding);const result=await launch(false);return {...result,beforeVersion:binding.versionCode,afterVersion:after.versionCode};});
  await check('LAN grant revocation denies future early cache delivery',async()=>{const address=(await command(['shell','ip','-4','addr','show','wlan0'])).match(/inet (\d+\.\d+\.\d+\.\d+)/)?.[1];assert.ok(address);const cfg=await deviceWrite(usb,'lan.configure',{enabled:true,address,port:0});const state=await read(usb,'device.state');const paired=await tool('devices',{action:'pair',deviceId:usb.deviceId,connectionId:usb.connectionId,bootId:usb.bootId,daemonInstanceId:usb.daemonInstanceId,expectedDeviceRevision:state.stateRevision,permissions:['read','write','manage']},true);assert.equal(paired.ok,true,JSON.stringify(paired));const grant=paired.result.result;lan=await tool('devices',{action:'connect',transport:'lan',deviceId:usb.deviceId,address,port:cfg.port},true);assert.equal(lan._operation?.state,'succeeded',JSON.stringify(lan));const staged=await stage(lan);assert.equal(staged.entry.sourceGrant,grant.grantId);await launch(true);await deviceWrite(usb,'pairings.revoke',{grantId:grant.grantId});const result=await launch(false);return {...result,tls:lan.tlsVersion};});
  await check('explicit early revoke blocks future delivery',async()=>{const staged=await stage(usb);unwrap(await hookDevice(usb,'early-revoke',{deploymentId:staged.entry.deploymentId,expectedCacheRevision:staged.cacheRevision},true));return launch(false);});
  await check('legacy rollback refuses concurrent scope edits then restores exact bytes',async()=>{const scope=await read(usb,'scope.get'),migratedRaw=await su(`cat ${remote}/scope.json`);await deviceWrite(usb,'scope.patch',{scopeRevision:scope.scopeRevision,add:['com.fixture.concurrent']});const conflict=await hookDevice(usb,'migration-rollback',{migrationId:migration.migrationId,scopeRevision:migration.scopeRevision},true);assert.equal(conflict.result?.code||conflict.code,'STALE_SCOPE',JSON.stringify(conflict));assert.ok((await read(usb,'scope.get')).document.packages.includes('com.fixture.concurrent'));
    // Repair only our fixture document with the exact pre-edit bytes from the private domain.
    writeFileSync(join(dir,'scope-migrated.json'),migratedRaw);await command(['push',join(dir,'scope-migrated.json'),remote+'/scope.json']);const restored=await hookDevice(usb,'migration-rollback',{migrationId:migration.migrationId,scopeRevision:migration.scopeRevision},true);const outcome=unwrap(restored);assert.equal(outcome.scopeRevision,createHash('sha256').update(originalScope).digest('hex'));assert.equal(await su('cat '+remote+'/scope.json'),originalScope.trimEnd());assert.ok((await su('sha256sum '+remote+'/scope.json')).startsWith(outcome.scopeRevision+' '),'actual restored bytes must match the original raw hash');return {exactHash:outcome.scopeRevision,concurrentEditRejected:true};});
  }
}catch(error){
  if(report.unknownOperations?.length&&started){
    // Diagnose only this fixture. Never replay a timed-out write or turn a later result into success.
    await su(`touch ${remote}/stacks-request`).catch(()=>{});await pause(600);
    for(const [name,path] of [['device-stacks.txt','stacks.txt'],['device-ledger.json','domain/operations.json']])try{writeFileSync(join(dir,name),await su(`cat ${remote}/${path}`));}catch{}
  }
  report.failure={message:(error as Error).message,stack:(error as Error).stack};console.error('FAIL '+(error as Error).message);process.exitCode=1;}
finally{
  if(installed){await command(['shell','am','force-stop',pkg]).catch(()=>{});await su('pm uninstall '+pkg).catch(()=>{});}
  if(usb&&host?.exitCode===null){for(const peer of [lan,usb].filter(Boolean))await tool('devices',{action:'disconnect',deviceId:peer.deviceId,connectionId:peer.connectionId},true).catch(()=>{});}
  if(host&&host.exitCode===null){host.kill();await new Promise<void>(r=>{host!.once('exit',()=>r());setTimeout(r,3000);});}
  if(started)await su(`touch ${remote}/stop`).catch(()=>{});
  if(deviceChild&&deviceChild.exitCode===null){await new Promise<void>(r=>{deviceChild!.once('exit',()=>r());setTimeout(r,3000);});if(deviceChild.exitCode===null)deviceChild.kill();}
  if(host)for(const port of [18088,18761]){const rows=await command(['reverse','--list']).catch(()=>'');if(rows.split('\n').some(line=>line.trim().endsWith(`tcp:${port} tcp:${port}`)))await command(['reverse','--remove','tcp:'+port]).catch(()=>{});}
  if(baseline)try{await pause(500);const after=await baselineNow();assert.equal(after.hashes,baseline.hashes);assert.deepEqual(after.sessions,baseline.sessions);assert.equal(after.processes,baseline.processes);assert.equal(after.reverse,baseline.reverse);report.sceneUnchanged=true;}catch(error){report.sceneUnchanged=false;report.protectionError=(error as Error).message;process.exitCode=1;}
  if(started)try{
    assert.ok(Number.isInteger(report.fixturePid)&&report.fixturePid>1,'root fixture PID unavailable; cleanup unconfirmed');
    await until(async()=>await su(`if [ ! -d /proc/${report.fixturePid} ]; then echo stopped; fi`)==='stopped','own root fixture stopped',6000);
    const packagePath=await command(['shell','pm','path',pkg]).catch((error:any)=>{if(error.code===1&&!String(error.stdout||'').trim())return '';throw error;});assert.equal(packagePath,'','own test package must be uninstalled');
    for(const port of [18088,18761])await new Promise<void>((yes,no)=>{const server=net.createServer();server.once('error',no);server.listen(port,'0.0.0.0',()=>server.close(()=>yes()));});
    report.cleanupVerified=true;
  }catch(error){report.cleanupVerified=false;report.cleanupError=(error as Error).message;process.exitCode=1;}
  report.completedAt=new Date().toISOString();writeFileSync(join(dir,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({passed:report.cases.filter((c:any)=>c.state==='pass').length,notPassed:report.cases.filter((c:any)=>c.state!=='pass').length,failure:report.failure?.message,sceneUnchanged:report.sceneUnchanged,cleanupVerified:report.cleanupVerified,report:join(dir,'report.json')}));
}
