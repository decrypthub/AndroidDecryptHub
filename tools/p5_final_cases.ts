// Invoked only by verify_p5_device.ts after its device, package and scene isolation checks.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
const families=['digest','hmac','symmetric','asymmetric','tls','aead','system'];
const off=()=>Object.fromEntries(families.map(k=>[k,false]));
export async function finalCases(c:any){
  const {check,tool,deviceWrite,hookDevice,stage,launch,command,su,until,pause,usb,remote,pkg,dir,assets,root}=c;
  const prepared=(await hookDevice(usb,'early-prepare')).result;c.binding=prepared.binding;
  const originalSha=createHash('sha256').update(readFileSync(join(root,'agent/build-isolated-18761/libadh_agent.so'))).digest('hex');
  assert.equal(c.binding.agentSha256,originalSha);assert.equal(prepared.supported,true);
  await check('USB stdio/2 preserves all 256 frame-length low bytes and control payloads',async()=>{
    const marker='P5\r\n\u0003\u001a\0/\\☃';for(let n=0;n<256;n++){const padding=marker+'x'.repeat(n);const info=await c.read(usb,'device.info',{padding});assert.equal(info.info.padding,padding);}
    return {roundTrips:256,allLowBytes:true,innerProtocolUnchanged:true};
  });
  const tls=await deviceWrite(usb,'lan.configure',{enabled:true,address:'127.0.0.1',port:0});
  const save=async(family:string,got=false)=>{
    const plan={schemaVersion:1,id:'p5-final-'+family,title:'P5 isolated '+family,package:pkg,families:{...off(),...(families.includes(family)?{[family]:true}:{})},steps:got?
      [{id:'before-host',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libp5target.so',symbol:'getpid'}}]:
      [{id:'before-host',tool:'capture_start',arguments:{cryptoModule:'libjavacrypto.so',fileModule:'',sysModule:'libp5target.so'}}]};
    const library=await tool('hook_plans',{action:'list'});const saved=await tool('hook_plans',{action:'put',plan,expectedLibraryRevision:library.revision},true);assert.equal(saved.ok,true,JSON.stringify(saved));c.planDigest=saved.digest;
  };
  for(const family of [...families,'off'])await check('early capture_start '+family+': real probes and disabled-family isolation',async()=>{
    await save(family);await stage(usb,600);const marker='P5_'+family+'_'+Date.now();
    const result=await launch(true,{marker,tlsPort:tls.port,earlyApply:family==='off'?0:1});const {session,receipt,hooks}=result;
    assert.equal(hooks.length,0,'capture_start must not create native_hook entries');
    const install=session.earlyPlan?.lastCaptureInstall;assert.ok(install,JSON.stringify(session.earlyPlan));
    const counters:any={digest:[install.digest],hmac:[install.hmac],symmetric:[install.evp,install.cipherInit,install.cipherCtxFree],asymmetric:Object.values(install.pkey),tls:[install.sslWrite,install.sslRead],aead:Object.values(install.aead),system:Object.values(install.sys)};
    for(const key of families){assert.ok(counters[key].every((v:any)=>Number.isInteger(v)),key+' counters missing');if(key===family)assert.ok(counters[key].some((v:number)=>v>0),key+' was not installed');else assert.ok(counters[key].every((v:number)=>v<=0),key+' unexpectedly armed');}
    // Shared DigestSign symbols are needed by HMAC and signatures. They must be absent if both are off.
    if(family!=='hmac'&&family!=='asymmetric'){assert.ok(install.digestSign<=0);assert.ok(Object.values(install.digestSignVerify).every((n:any)=>n<=0));}
    const health=await until(async()=>{const all=JSON.parse(readFileSync(join(dir,'host/p5-capture-health.json'),'utf8'));const h=all.sessions[session.sessionId];return h&&h.ts&&h.backlog===0?h:null;},'fully drained sandbox ring');
    assert.equal(health.dropped,0);assert.equal(health.jdropped,0);assert.equal(health.complete,true);
    await pause(400);const captures=await tool('live_captures',{session:session.sessionId,includeText:true,encoding:'b64',limit:1000});
    assert.equal(captures.total,captures.captures.length,'acceptance must inspect the full session window');
    const rows=captures.captures.map((r:any)=>({...r,bytes:Buffer.from(r.b64||'','base64')}));
    const matches:any={
      digest:(r:any)=>r.func==='EVP_DigestUpdate'&&r.bytes.includes(Buffer.from(marker+'_digest')),
      hmac:(r:any)=>['HMAC_Update','EVP_DigestSignUpdate'].includes(r.func)&&r.bytes.includes(Buffer.from(marker+'_hmac')),
      symmetric:(r:any)=>r.func==='EVP_CipherUpdate'&&r.bytes.includes(Buffer.from(marker+'_symmetric')),
      asymmetric:(r:any)=>(r.func==='ECDSA_sign_digest'&&r.bytes.includes(createHash('sha256').update(marker+'_asymmetric').digest()))||(r.func==='EVP_DSignUpdate_asym'&&r.bytes.includes(Buffer.from(marker+'_asymmetric'))),
      tls:(r:any)=>r.func==='SSL_write'&&r.bytes.includes(Buffer.from(marker+'_tls')),
      aead:(r:any)=>r.func.includes('AEAD')&&r.bytes.includes(Buffer.from(marker+'_aead')),
      system:(r:any)=>r.func==='access'&&r.bytes.includes(Buffer.from(marker+'_system')),
    };
    const hitCounts=Object.fromEntries(families.map(k=>[k,rows.filter(matches[k]).length]));
    writeFileSync(join(dir,'family-'+family+'.json'),JSON.stringify({receipt,early:session.earlyPlan,health,hitCounts,functions:[...new Set(rows.map((r:any)=>r.func))]},null,2));
    for(const k of families)assert.equal(hitCounts[k]>0,k===family,k+' marker evidence '+JSON.stringify({hitCounts,functions:rows.map((r:any)=>r.func)}));
    if(family==='off')assert.equal(rows.length,0,'all-off policy must capture nothing');
    return {beforeAgentStart:true,install:counters,sharedDigestSign:install.digestSign,hitCounts,health:{dropped:health.dropped,jdropped:health.jdropped,backlog:health.backlog,complete:health.complete}};
  });
  await check('real UID change rejects cached delivery and stale-wire installation',async()=>{
    await save('uid',true);await stage(usb,600);await launch(true);const before=structuredClone(c.binding);
    await c.brokerWire();await su(`cp ${remote}/wire.bin ${remote}/uid-stale.bin`);await command(['shell','am','force-stop',pkg]);
    assert.match(await su('pm uninstall '+pkg),/Success/);assert.match(await su(`pm install ${remote}/sandbox.apk`,90000),/Success/);
    c.binding=(await hookDevice(usb,'early-prepare')).result.binding;assert.notEqual(c.binding.uid,before.uid,'OS did not allocate a new UID; cannot claim this case');assert.equal(c.binding.agentSha256,before.agentSha256);
    await launch(false);const rejected=await launch(false,{stalePath:remote+'/uid-stale.bin',earlyApply:0,rejected:true});
    return {oldUid:before.uid,newUid:c.binding.uid,agentHashUnchanged:true,brokerDenied:true,staleWire:rejected};
  });
  await check('actual Agent replacement alone rejects cached delivery and stale-wire installation',async()=>{
    await save('agent',true);await stage(usb,600);await launch(true);const before=structuredClone(c.binding);await c.brokerWire();await su(`cp ${remote}/wire.bin ${remote}/agent-stale.bin`);await command(['shell','am','force-stop',pkg]);
    const apk=(await command(['shell','pm','path',pkg])).replace(/^package:/,'');assert.match(apk,/^\/data\/app\/[A-Za-z0-9_~+\/=.\-]+\/com\.adh\.p5sandbox-[A-Za-z0-9_~+=.\-]+\/base\.apk$/);
    const agent=apk.replace(/base\.apk$/,'lib/arm64/libadh_agent.so');assert.equal((await su('sha256sum '+agent)).split(' ')[0],before.agentSha256);
    // A valid ELF with a different byte hash, without changing APK/UID/signers or executable code.
    const variant=Buffer.concat([readFileSync(join(root,'agent/build-isolated-18761/libadh_agent.so')),Buffer.from('\nP5-SANDBOX-REPLACEMENT\n')]);const variantFile=join(dir,'agent-variant.so');writeFileSync(variantFile,variant);
    await command(['push',variantFile,remote+'/agent-variant.so']);await su(`cp ${remote}/agent-variant.so ${agent}; chmod 755 ${agent}`);
    c.binding=(await hookDevice(usb,'early-prepare')).result.binding;assert.equal(c.binding.agentSha256,createHash('sha256').update(variant).digest('hex'));assert.notEqual(c.binding.agentSha256,before.agentSha256);assert.equal(c.binding.earlySupported,true);
    const {agentSha256:oldHash,...rest}=before;const {agentSha256:newHash,...after}=c.binding;assert.deepEqual(after,rest,'only Agent hash may change in this case');
    await launch(false);const rejected=await launch(false,{stalePath:remote+'/agent-stale.bin',earlyApply:0,rejected:true});
    return {uid:c.binding.uid,apkMetadataUnchanged:true,actualAgentHashChanged:true,brokerDenied:true,staleWire:rejected};
  });
}
