import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import net from 'node:net';
import vm from 'node:vm';import {createRequire} from 'node:module';import {pathToFileURL,fileURLToPath} from 'node:url';
const root=process.env.ADH_DEVICE_SCOPE_ROOT?pathToFileURL(process.env.ADH_DEVICE_SCOPE_ROOT.replace(/\/$/,'')+'/'):new URL('../../',import.meta.url);
const load=(name:string)=>import(new URL(`daemon/src/${name}.ts`,root).href);
let scope:any;try{scope=await load('agent_scope');}catch(e){if((e as any).code!=='ERR_MODULE_NOT_FOUND')throw e;}
const withScope=(s:any,fn:()=>any)=>scope?scope.withDeviceScope(s,fn):fn();
const state=await load('state'),service=await load('service'),persist=await load('capture_persist');
const pkg='com.adh.scopefixture';
function binding(serial:string){return {kind:'usb-route',package:pkg,serial,transportId:serial==='phoneA'?'1':'2',leaseId:serial,bootId:'12345678-1234-1234-1234-123456789abc',deviceAgentPort:20761,hostAgentPort:30000,verifiedAt:1,assurance:'explicit-usb-route',process:{pid:123,uid:10123,starttimeTicks:'555',name:pkg}};}
function session(serial:string,id=serial){return {sessionId:id,package:pkg,process:pkg,pid:123,uid:10123,starttimeTicks:'555',online:true,connectedAt:serial==='phoneA'?1:2,deviceBinding:binding(serial)};}
function cap(id:number,serial?:string){return {id,sessionId:serial??'gone',package:pkg,source:'native',func:'SSL_write',algo:'tls',op:'write',category:'net',inl:1,tid:1,tsNs:id,ts:id,hex:'41',preview:'A',...(serial?{deviceBinding:binding(serial)}:{})};}
function clean(){state.sessions.clear();state.captures.length=0;}
test.after(()=>{clean();for(const t of state.captureTimers.values())clearInterval(t);state.captureTimers.clear();});

test('default same-package session refuses ambiguous two-phone routing',()=>{clean();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));assert.throws(()=>service.pickSid(),/设备|device/i);});
test('concurrent async request scopes retain separate serials across awaits',async()=>{clean();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));const out=await Promise.all(['phoneA','phoneB'].map(serial=>withScope({serial,package:pkg},async()=>{await new Promise(r=>setTimeout(r,serial==='phoneA'?15:1));return service.sessionForPackage(pkg);})));assert.deepEqual(out,['a','b']);});
test('explicit other-phone session is rejected before any socket write',async()=>{clean();state.sessions.set('b',session('phoneB','b'));let writes=0;state.agentSockets.set('b',{destroyed:false,write(){writes++;}});try{await assert.rejects(withScope({serial:'phoneA',package:pkg},()=>service.sendCmd('b','ping',{},15)),/设备|一致|scope/i);assert.equal(writes,0);}finally{state.agentSockets.delete('b');}});
test('package fanout cannot quietly combine same-package two-device generations',()=>{clean();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));assert.throws(()=>service.onlineSessionsForPackage(pkg),/设备|device/i);});
test('scoped package fanout includes only the selected phone',()=>{clean();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));assert.deepEqual(withScope({serial:'phoneA'},()=>service.onlineSessionsForPackage(pkg).map((s:any)=>s.sessionId)),['a']);});
test('same PID with changed starttime cannot pass immutable session proof',()=>{const s=session('phoneA');s.starttimeTicks='556';assert.ok(scope,'identity guard required');assert.throws(()=>scope.assertSessionScope(s),/身份|进程/);});
test('nested target contradictions are rejected instead of retargeting an in-flight action',()=>{assert.throws(()=>withScope({serial:'phoneA'},()=>withScope({serial:'phoneB'},()=>1)),/一致|scope/i);});
test('unpack protection on phoneA does not suppress phoneB',()=>{withScope({serial:'phoneA'},()=>service.protectCaptureArmAfterUnpack(pkg));try{assert.equal(withScope({serial:'phoneB'},()=>service.isCaptureArmProtected(pkg)),false);assert.equal(withScope({serial:'phoneA'},()=>service.isCaptureArmProtected(pkg)),true);}finally{withScope({serial:'phoneA'},()=>service.clearCaptureArmProtect(pkg));}});
test('new live capture stamps the session proof, without stamping unrelated history',()=>{clean();state.sessions.set('phoneA',session('phoneA'));const entry=cap(9901);entry.sessionId='phoneA';delete (entry as any).deviceBinding;state.pushCapture(entry);assert.equal(state.captures.at(-1).deviceBinding?.serial,'phoneA');assert.equal(withScope({serial:'phoneA'},()=>state.filterLiveCaptures([cap(9900)],{})).length,0);});
test('same-package memory retention budgets each phone independently',()=>{const list=[cap(1,'phoneA'),cap(2,'phoneA'),cap(3,'phoneB'),cap(4,'phoneB')];persist.evictPackageFromMemory(list,pkg,2);assert.deepEqual(list.map(c=>c.id),[1,2,3,4]);});
test('known-app summary is not borrowed from another phone or unknown history',()=>{clean();state.captures.push(cap(1,'phoneB'));assert.deepEqual(withScope({serial:'phoneA'},()=>state.knownApps()),[]);});
test('identical bytes on another phone are not discarded as a Java/native echo',()=>{clean();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));state.recentJavaIn.clear();service.ingestAgentCaptureFrame('a',{jcaptures:[{in:'41',out:'42',inl:1,outl:1,op:'digest',algo:'SHA-256',tid:1}],captures:[]});service.ingestAgentCaptureFrame('b',{jcaptures:[],captures:[{hex:'41',inl:1,func:'EVP_DigestUpdate',tid:1,tsNs:1}]});assert.equal(state.captures.filter((c:any)=>c.sessionId==='b').length,1);state.recentJavaIn.clear();});
test('scope headers validate serial and reject multi-value headers',()=>{assert.ok(scope);assert.throws(()=>scope.withDeviceScope({serial:'a\n'},()=>1));assert.throws(()=>scope.httpDeviceScope({'x-adh-device-serial':['a','b']}));});

for(const scenario of ['paging','detail','export','clear','load-retain','disk-retain'] as const)test(`persisted ${scenario} preserves device provenance and unknown history`,()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'adh-scope-test-'));
 try{
  for(const c of [cap(1,'phoneA'),cap(2,'phoneA'),cap(3,'phoneB'),cap(4,'phoneB'),cap(5)])persist.appendCaptureLine(dir,c);
  withScope({serial:'phoneA',package:pkg},()=>{
   if(scenario==='paging')assert.deepEqual(persist.queryPersistedCapturesPage(dir,{package:pkg,limit:10}).items.map((c:any)=>c.id),[1,2]);
   if(scenario==='detail')assert.equal(persist.findPersistedCaptureById(dir,3,pkg),null);
   if(scenario==='export')assert.deepEqual(persist.readPackageCapturesJsonl(dir,pkg).split('\n').filter(Boolean).map((l:string)=>JSON.parse(l).id),[1,2]);
   if(scenario==='clear')assert.deepEqual(persist.clearPackagePersistedCaptures(dir,pkg),[]);
  });
  if(scenario==='clear')assert.deepEqual(persist.queryPersistedCapturesPage(dir,{package:pkg,limit:10}).items.map((c:any)=>c.id),[3,4,5]);
  if(scenario==='load-retain')assert.deepEqual(persist.loadCapturesFromDisk(dir,1).map((c:any)=>c.id),[2,4,5]);
  if(scenario==='disk-retain'){persist.trimPackageCapturesFile(dir,pkg,1);assert.deepEqual(persist.loadCapturesFromDisk(dir,0).map((c:any)=>c.id),[2,4,5]);}
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

const productRequire=createRequire(new URL('daemon/package.json',root));
const ts=productRequire('typescript');
const panelRequire=createRequire(new URL('panel/package.json',root));
function panelStore(){
 const a:any={getCaptures:async()=>({captures:[]}),getApps:async()=>({apps:[]}),getScope:async()=>({ok:true,packages:[]}),setApiScopeProvider(fn:any){a.provider=fn;}};
 const source=fs.readFileSync(new URL('panel/src/store.ts',root),'utf8');
 const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 const cacheSource=fs.readFileSync(new URL('panel/src/log_cache.ts',root),'utf8'),cacheModule={exports:{}};vm.runInNewContext(ts.transpileModule(cacheSource,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,{module:cacheModule,exports:cacheModule.exports,console,localStorage:{getItem:()=>null,setItem:()=>{}}});
 const module={exports:{}};vm.runInNewContext(compiled,{module,exports:module.exports,require:(name:string)=>name==='vue'?panelRequire('vue'):name==='./log_cache'?cacheModule.exports:name==='./api'?a:name==='./observations'?{recordVisible:()=>true}:panelRequire(name),console,setTimeout:()=>0,clearTimeout,localStorage:{getItem:()=>null,setItem:()=>{}},window:undefined});
 return {s:module.exports as any,a};
}
function select(s:any){s.store.devices=[{key:'a',serial:'phoneA',observed:pkg},{key:'b',serial:'phoneB',observed:pkg}];s.store.selectedDeviceKey='a';s.store.chosenPkg=pkg;}
test('actual panel store rejects other-phone and provenance-free captures',()=>{const {s}=panelStore();select(s);assert.equal(s.belongsToApp(cap(1,'phoneB')),false);assert.equal(s.belongsToApp(cap(2)),false);assert.equal(s.belongsToApp(cap(3,'phoneA')),true);});
test('actual panel websocket buffer does not evict selected phone with other-phone traffic',()=>{const {s}=panelStore();select(s);s.capPush(cap(1,'phoneA'));for(let i=2;i<1600;i++)s.capPush(cap(i,'phoneB'));assert.deepEqual(Array.from(s.store.capItems,(c:any)=>c.id),[1]);});
test('actual panel same-package switch clears prior-device snapshot and session target',async()=>{const {s}=panelStore();select(s);s.store.sessions.set('a',session('phoneA','a'));s.store.sessions.set('b',session('phoneB','b'));s.store.capItems=[cap(1,'phoneA')];await s.syncCapScope();s.store.capItems=[cap(1,'phoneA')];s.selectDevice('b');assert.equal(s.store.capItems.length,0);assert.equal(s.liveSession.value?.sessionId,'b');});
test('actual panel late capture response cannot paint the next phone',async()=>{const {s,a}=panelStore();select(s);const pending:any[]=[];a.getCaptures=()=>new Promise(r=>pending.push(r));const p=s.capLoad();s.store.selectedDeviceKey='b';s.store.capItems=[cap(8,'phoneB')];for(const resolve of pending)resolve({captures:[cap(1,'phoneA')]});await p;assert.deepEqual(Array.from(s.store.capItems,(c:any)=>c.id),[8]);});
test('actual panel late app inventory response cannot replace next-phone apps',async()=>{const {s,a}=panelStore();select(s);let resolve:any;a.getApps=()=>new Promise(r=>resolve=r);const p=s.refreshApps();s.store.selectedDeviceKey='b';s.store.apps=[{package:'com.phone.b'}];resolve({apps:[{package:'com.phone.a'}]});await p;assert.equal(s.store.apps[0].package,'com.phone.b');});

function fakeAdb(){
 const devices=new Map([['phoneA',{transport:'1',pid:123,uid:10123,start:'555',name:pkg,boot:'12345678-1234-1234-1234-123456789abc',usb:true}],['phoneB',{transport:'2',pid:123,uid:10123,start:'555',name:pkg,boot:'87654321-1234-1234-1234-123456789abc',usb:true}]]);
 const mappings=new Map<string,Map<number,number>>([['phoneA',new Map()],['phoneB',new Map()]]);const calls:string[][]=[];
 const run=async(args:string[])=>{calls.push([...args]);if(args[0]==='devices')return [...devices].map(([serial,d])=>`${serial}\tdevice usb:1 model:Fixture transport_id:${d.transport}`).join('\n');assert.equal(args[0],'-t');const pair=[...devices].find(([,d])=>d.transport===args[1]);if(!pair)throw Error('transport gone');const [serial,d]=pair,m=mappings.get(serial)!;const tail=args.slice(2);
  if(tail[0]==='get-serialno')return serial;if(tail[0]==='get-devpath')return d.usb?'usb:1':'local';
  if(tail[0]==='reverse'){if(tail[1]==='--list')return [...m].map(([a,b])=>`UsbFfs tcp:${a} tcp:${b}`).join('\n');if(tail[1]==='--remove'){m.delete(Number(tail[2].slice(4)));return '';}
   const no=tail[1]==='--no-rebind',offset=no?2:1,a=Number(tail[offset].slice(4)),b=Number(tail[offset+1].slice(4));if(no&&m.has(a))throw Error('cannot rebind');m.set(a,b);return '';}
  assert.equal(tail[0],'exec-out');const script=tail.at(-1)!;if(!script.includes('__STAT1__'))return d.boot;
  const stat=`${d.pid} (fixture) S ${[...Array(18).fill('0'),d.start,'0'].join(' ')}`,b64=(s:string)=>Buffer.from(s).toString('base64');
  return `__BOOT__\n${d.boot}\n__STAT1__\n${b64(stat)}\n__UID__\n${d.uid}\n__CMD__\n${b64(d.name+'\0')}\n__PKG__\npackage:${pkg} uid:${d.uid}\n__STAT2__\n${b64(stat)}\n__END__\n`;
 };return {devices,mappings,calls,run};
}
async function routesFixture(){assert.ok(scope,'verified route implementation required');const {UsbAgentRoutes}=await load('usb_agent_routes');const fake=fakeAdb();const routes=new UsbAgentRoutes({deviceAgentPort:20761,legacyHostPort:19761,onConnection:(s:net.Socket)=>s.destroy(),run:fake.run});return {routes,...fake};}
test('same Host allocates distinct loopback listeners and no-rebind device routes',async()=>{const f=await routesFixture();try{const [a,b]=await Promise.all([f.routes.ensure('phoneA'),f.routes.ensure('phoneB')]);assert.notEqual(a.hostAgentPort,b.hostAgentPort);assert.equal(f.calls.filter(c=>c.includes('--no-rebind')).length,2);const [aa,bb]=await Promise.all([a.attest({t:'hello',package:pkg,process:pkg,pid:123,uid:10123,starttimeTicks:'555'}),b.attest({t:'hello',package:pkg,process:pkg,pid:123,uid:10123,starttimeTicks:'555'})]);assert.equal(aa.serial,'phoneA');assert.equal(bb.serial,'phoneB');assert.equal(Object.isFrozen(aa.process),true);}finally{await f.routes.closeAll();}});
for(const changed of ['transport','start','name','uid','boot','alias','mapping'] as const)test(`route validation rejects changed ${changed} before a scoped command`,async()=>{const f=await routesFixture();try{const a=await f.routes.ensure('phoneA');const d=f.devices.get('phoneA')!;if(changed==='transport')d.transport='9';if(changed==='start')d.start='556';if(changed==='name')d.name='com.other.app';if(changed==='uid')d.uid=10124;if(changed==='boot')d.boot='ffffffff-1234-1234-1234-123456789abc';if(changed==='alias')f.mappings.get('phoneB')!.set(20761,a.hostAgentPort);if(changed==='mapping')f.mappings.get('phoneA')!.set(20761,9999);await assert.rejects(a.attest({t:'hello',package:pkg,process:pkg,pid:123,uid:10123,starttimeTicks:'555'}));}finally{await f.routes.closeAll();}});
test('owned lease close preserves an external replacement mapping',async()=>{const f=await routesFixture();await f.routes.ensure('phoneA');f.mappings.get('phoneA')!.set(20761,9999);assert.equal((await f.routes.close('phoneA')).conflict,true);assert.equal(f.mappings.get('phoneA')!.get(20761),9999);});
test('route refuses an already occupied foreign Agent port and wireless attribution',async()=>{const f=await routesFixture();try{f.mappings.get('phoneA')!.set(20761,9999);await assert.rejects(f.routes.ensure('phoneA'),/其他|覆盖/);f.devices.get('phoneB')!.usb=false;await assert.rejects(f.routes.ensure('phoneB'),/USB/);}finally{await f.routes.closeAll();}});

test('real ADB wire sends identity queries to host transport namespace, not device adbd',async()=>{
 const requests:string[]=[];const server=net.createServer(sock=>sock.on('data',chunk=>{const name=chunk.subarray(4).toString();requests.push(name);const text='phoneA';if(name.startsWith('host-transport-id:1:')){sock.end(Buffer.concat([Buffer.from('OKAY'),Buffer.from(text.length.toString(16).padStart(4,'0')),Buffer.from(text)]));}else sock.end('FAIL0005wrong');}));
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as net.AddressInfo).port,prior=process.env.ADH_ADB_SERVER_PORT;process.env.ADH_ADB_SERVER_PORT=String(port);
 try{const wire=await import(new URL(`daemon/src/adb_wire.ts?scope-identity=${port}`,root).href);for(const query of ['get-serialno','get-state','get-devpath'])assert.equal((await wire.adbExec(['-t','1',query],{timeout:300})).stdout,'phoneA');assert.deepEqual(requests,['host-transport-id:1:get-serialno','host-transport-id:1:get-state','host-transport-id:1:get-devpath']);}
 finally{if(prior===undefined)delete process.env.ADH_ADB_SERVER_PORT;else process.env.ADH_ADB_SERVER_PORT=prior;await new Promise<void>(r=>server.close(()=>r()));}
});
test('real ADB wire preserves --no-rebind in reverse service',async()=>{
 const requests:string[]=[];const server=net.createServer(sock=>sock.on('data',chunk=>{const name=chunk.subarray(4).toString();requests.push(name);if(name==='host:transport-id:1')sock.write('OKAY');else sock.end('OKAY');}));
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as net.AddressInfo).port,prior=process.env.ADH_ADB_SERVER_PORT;process.env.ADH_ADB_SERVER_PORT=String(port);
 try{const wire=await import(new URL(`daemon/src/adb_wire.ts?scope-norebind=${port}`,root).href);await wire.adbExec(['-t','1','reverse','--no-rebind','tcp:20761','tcp:30000'],{timeout:300});assert.deepEqual(requests,['host:transport-id:1','reverse:forward:norebind:tcp:20761;tcp:30000']);}
 finally{if(prior===undefined)delete process.env.ADH_ADB_SERVER_PORT;else process.env.ADH_ADB_SERVER_PORT=prior;await new Promise<void>(r=>server.close(()=>r()));}
});
async function transportPair(lease?:any){const transport=await load('agent_transport');const server=net.createServer(sock=>transport.acceptAgentSocket(sock,lease));await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const client=net.connect((server.address() as net.AddressInfo).port,'127.0.0.1');client.on('data',()=>{});client.on('error',()=>{});await new Promise<void>(r=>client.once('connect',r));return {client,close:async()=>{client.destroy();await new Promise<void>(r=>server.close(()=>r()));}};}
const sleep=(n:number)=>new Promise(r=>setTimeout(r,n));
test('actual Agent transport cannot resolve another socket session command result',async()=>{
 clean();assert.ok(scope);const a=await transportPair(),b=await transportPair();let timer:any;
 try{a.client.write(state.frameJson({t:'hello',package:pkg,pid:1}));b.client.write(state.frameJson({t:'hello',package:pkg,pid:2}));for(let i=0;i<40&&state.sessions.size<2;i++)await sleep(5);assert.equal(state.sessions.size,2);const target=[...state.sessions.values()].find((s:any)=>s.pid===1);let resolved=false;timer=setTimeout(()=>{},1000);state.pending.set('scope-spoof',{sessionId:target.sessionId,timer,resolve:()=>{resolved=true;},reject:()=>{}});b.client.write(state.frameJson({t:'cmdResult',id:'scope-spoof',op:'ping',ok:true}));await sleep(20);assert.equal(resolved,false);assert.equal(state.pending.has('scope-spoof'),true);a.client.write(state.frameJson({t:'cmdResult',id:'scope-spoof',op:'ping',ok:true}));await sleep(20);assert.equal(resolved,true);}
 finally{clearTimeout(timer);state.pending.delete('scope-spoof');await a.close();await b.close();}
});
test('hello proof resolving after socket close cannot create a phantom online session',async()=>{
 clean();assert.ok(scope);let resolve:any,started=false;const proof=new Promise(r=>resolve=r);const p=await transportPair({attest:()=>{started=true;return proof;}});
 try{p.client.write(state.frameJson({t:'hello',package:pkg,pid:123,uid:10123,starttimeTicks:'555'}));for(let i=0;i<40&&!started;i++)await sleep(5);assert.equal(started,true);p.client.destroy();await sleep(20);resolve(binding('phoneA'));await sleep(20);assert.equal(state.sessions.size,0);}finally{resolve?.(binding('phoneA'));await p.close();}
});
test('actual API snapshots tab target headers while global inventory stays unscoped',async()=>{
 const source=fs.readFileSync(new URL('panel/src/api.ts',root),'utf8');const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,module={exports:{}};const calls:any[]=[];
 vm.runInNewContext(compiled,{module,exports:module.exports,Headers,AbortSignal,performance,window:undefined,fetch:async(path:string,init:any)=>{calls.push({path,serial:init.headers?.get?.('x-adh-device-serial'),package:init.headers?.get?.('x-adh-package')});return {ok:true,json:async()=>({ok:true,apps:[]})};}});
 const api=module.exports as any;assert.equal(typeof api.setApiScopeProvider,'function');api.setApiScopeProvider(()=>({serial:'phoneA',package:pkg}));await api.getApps();await api.getDevices();await api.observePackage('phoneB','com.other.app');assert.equal(calls[0].serial,'phoneA');assert.equal(calls[0].package,pkg);assert.equal(calls[1].serial,null);assert.equal(calls[2].serial,'phoneB');assert.equal(calls[2].package,'com.other.app');
});
