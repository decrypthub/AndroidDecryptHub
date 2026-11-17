// Test-client adapter for legacy stdin acceptance scripts. Never enables a product bypass.
// Observe once before a new intent; retain explicit versions and never retry a conflict/timeout.
import {randomUUID} from 'node:crypto';
if(process.argv[1]==='-'&&process.env.ADH_VERIFY_FETCH_COORDINATED==='1'){
  const base=new URL(process.env.ADH_VERIFY_FETCH_BASE),original=globalThis.fetch,client=randomUUID();
  const metadata=s=>({expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch,idempotencyKey:randomUUID()});
  globalThis.fetch=async(input,init={})=>{
    if(typeof input!=='string'&&!(input instanceof URL))return original(input,init);
    const url=new URL(input),method=(init.method||'GET').toUpperCase();
    if(url.origin!==base.origin)return original(input,init);
    const headers=new Headers(init.headers);if(!headers.has('x-adh-client-id'))headers.set('x-adh-client-id',client);
    let body={};if(init.body!==undefined){if(typeof init.body!=='string')return original(input,init);try{body=JSON.parse(init.body);}catch{return original(input,init);}if(!body||typeof body!=='object'||Array.isArray(body))return original(input,init);}
    if(headers.has('x-adh-operation')||Object.hasOwn(body,'_operation')||url.searchParams.has('_operation'))return original(input,{...init,headers});
    if(url.pathname==='/mcp'&&body.method==='tools/call'&&body.params?.name!=='operations'){
      const args=body.params.arguments;
      if(args!==undefined&&(!args||typeof args!=='object'||Array.isArray(args)||Object.hasOwn(args,'_operation')))return original(input,{...init,headers});
      const observed=await original(base.origin+'/mcp',{method:'POST',headers:{...Object.fromEntries(headers),'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:'verify-observe',method:'tools/call',params:{name:'operations',arguments:{action:'snapshot',tool:body.params.name,arguments:body.params.arguments||{}}}})});
      const response=await observed.json(),snapshot=JSON.parse(response.result?.content?.[0]?.text||'null');
      if(!observed.ok||!snapshot?.ok)throw new Error('verification snapshot refused; write not dispatched');
      return original(input,{...init,headers,body:JSON.stringify({...body,params:{...body.params,arguments:{...body.params.arguments,_operation:metadata(snapshot)}}})});
    }
    if(!url.pathname.startsWith('/api/')||url.pathname.startsWith('/api/operations'))return original(input,{...init,headers});
    const args={...Object.fromEntries(url.searchParams),...body};
    const prepared=await original(base.origin+'/api/operations/prepare',{method:'POST',headers:{...Object.fromEntries(headers),'content-type':'application/json'},body:JSON.stringify({path:url.pathname,method,arguments:args})});
    const snapshot=await prepared.json();if(!prepared.ok||!snapshot.ok)throw new Error('verification snapshot refused; request not dispatched');
    if(snapshot.spec.mode==='write')headers.set('x-adh-operation',JSON.stringify(metadata(snapshot)));
    return original(input,{...init,headers});
  };
}
