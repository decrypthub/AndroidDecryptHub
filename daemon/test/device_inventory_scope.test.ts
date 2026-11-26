import test from'node:test';import assert from'node:assert/strict';import http from'node:http';import{pathToFileURL}from'node:url';
const root=process.env.ADH_HOOK_UI_ROOT?pathToFileURL(process.env.ADH_HOOK_UI_ROOT.replace(/\/$/,'')+'/'):new URL('../../',import.meta.url),load=(n:string)=>import(new URL(`daemon/src/${n}.ts`,root).href);
const state=await load('state'),scope=await load('agent_scope'),routes=await load('http/routes_devices'),router=await load('http/router');
const pkg='com.adh.inventory';
const session=(serial:string,id:string,app=pkg)=>({sessionId:id,package:app,process:app,pid:123,uid:10123,starttimeTicks:'1',online:true,connectedAt:1,lastSeen:1,deviceBinding:{serial,package:app,process:{pid:123,uid:10123,starttimeTicks:'1',name:app}}});
test.after(()=>state.sessions.clear());
test('normal Host device list includes both ADB phones without requiring paired RPC devices',async()=>{
 state.sessions.clear();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneB','b'));
 let result:any;const calls:any[]=[];const list=routes.deviceRoutes({req:{method:'GET',headers:{}} as any,url:new URL('http://localhost/api/devices?action=list'),send:(status:number,body:any)=>{result={status,body};},res:{} as any},{observer:null,run:async(args:string[])=>{calls.push(args);return 'phoneA device usb:1 model:A transport_id:1\nphoneB device usb:2 model:B transport_id:2';},list:()=>({devices:[]})});
 await list[0].handler();assert.equal(result.status,200);assert.deepEqual(result.body.transports.map((d:any)=>[d.serial,d.observed,d.agent?.sessionId]),[['phoneA',pkg,'a'],['phoneB',pkg,'b']]);assert.equal(calls.length,1);
});
test('an ambiguous multi-app phone inventory never borrows an arbitrary observed app',()=>{state.sessions.clear();state.sessions.set('a',session('phoneA','a'));state.sessions.set('b',session('phoneA','b','com.other.app'));assert.equal(typeof routes.observedAgentView,'function');assert.equal(routes.observedAgentView('phoneA'),null);assert.equal(routes.observedAgentView('phoneB'),null);});
for(const [name,url,body]of [
 ['body package','/api/native/call',{package:'com.other.app'}],
 ['body serial','/api/devices',{action:'connect',serial:'phoneB'}],
 ['query package','/api/native/call?package=com.other.app',{}],
 ['query serial','/api/devices?serial=phoneB',{action:'connect'}],
 ['scope add','/api/scope',{add:['com.other.app']}],
 ['scope remove','/api/scope',{remove:['com.other.app']}],
 ['scope set','/api/scope',{set:[pkg,'com.other.app']}],
]as const)test(`actual router rejects ${name} contradicting immutable request target before dispatch`,async()=>{
 const server=http.createServer((req,res)=>{scope.withDeviceScope({serial:'phoneA',package:pkg},()=>router.handleHttp(req,res)).catch((e:any)=>{res.writeHead(e.status??500,{'content-type':'application/json'});res.end(JSON.stringify({code:e.code,error:e.message}));});});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));try{const port=(server.address()as any).port;const r=await fetch(`http://127.0.0.1:${port}${url}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});assert.equal(r.status,409);assert.equal((await r.json()as any).code,'TARGET_SCOPE_CONFLICT');}finally{await new Promise<void>(r=>server.close(()=>r()));}
});
