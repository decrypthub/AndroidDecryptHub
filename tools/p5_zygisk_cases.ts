// Invoked only after the real Zygisk runner's device/module/namespace preflight.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
const families=['digest','hmac','symmetric','asymmetric','tls','aead','system'];
const off=()=>Object.fromEntries(families.map(k=>[k,false]));
export async function zygiskExtendedCases(c:any){
  const {check,tool,deviceWrite,read,stage,launch,command,until,pause,usb,dir,nonce}=c;
  const originalDigest=c.planDigest;
  const tls=await deviceWrite(usb,'lan.configure',{enabled:true,address:'127.0.0.1',port:0});
  for(const family of [...families,'off'])await check('Zygisk early capture_start '+family+': Application hits and disabled-family isolation',async()=>{
    const plan={schemaVersion:1,id:'zygisk-capture-'+family,title:'Actual post-specialize '+family,package:c.pkg,
      families:{...off(),...(families.includes(family)?{[family]:true}:{})},
      steps:[{id:'before-application',tool:'capture_start',arguments:{cryptoModule:'libjavacrypto.so',fileModule:'',sysModule:'libjavacore.so'}}]};
    const library=await tool('hook_plans',{action:'list'}),saved=await tool('hook_plans',{action:'put',plan,expectedLibraryRevision:library.revision},true);
    assert.equal(saved.ok,true,JSON.stringify(saved));c.planDigest=saved.digest;await stage(600);
    const marker='P5Z_'+family+'_'+nonce;
    const result=await launch(true,{captureOnly:true,allOff:family==='off',marker,tlsPort:tls.port});
    const {receipt,session}=result;assert.equal(receipt.probesInApplicationCallback,true);
    assert.equal(receipt.marker,marker);for(const key of families)assert.equal(receipt.probes[key],true,key+' probe did not succeed');
    const install=session.earlyPlan?.lastCaptureInstall;assert.ok(install,JSON.stringify(session.earlyPlan));
    const counters:any={digest:[install.digest],hmac:[install.hmac],symmetric:[install.evp,install.cipherInit,install.cipherCtxFree],asymmetric:Object.values(install.pkey),tls:[install.sslWrite,install.sslRead],aead:Object.values(install.aead),system:Object.values(install.sys)};
    for(const key of families){assert.ok(counters[key].every((v:any)=>Number.isInteger(v)),key+' counters missing');assert.equal(counters[key].some((v:number)=>v>0),key===family,key+' install mismatch');}
    if(family!=='hmac'&&family!=='asymmetric'){assert.ok(install.digestSign<=0);assert.ok(Object.values(install.digestSignVerify).every((n:any)=>n<=0));}
    const health=await until(async()=>{const all=JSON.parse(readFileSync(join(dir,'host/p5-capture-health.json'),'utf8'));const h=all.sessions[session.sessionId];return h&&h.ts&&h.backlog===0?h:null;},'Application capture ring fully drained');
    assert.equal(health.dropped,0);assert.equal(health.jdropped,0);assert.equal(health.complete,true);await pause(400);
    const captures=await tool('live_captures',{session:session.sessionId,includeText:true,encoding:'b64',limit:1000});
    assert.equal(captures.total,captures.captures.length,'full session window required');
    const rows=captures.captures.map((r:any)=>({...r,bytes:Buffer.from(r.b64||'','base64')}));
    const matches:any={digest:(r:any)=>r.func==='EVP_DigestUpdate'&&r.bytes.includes(Buffer.from(marker+'_digest')),
      hmac:(r:any)=>['HMAC_Update','EVP_DigestSignUpdate'].includes(r.func)&&r.bytes.includes(Buffer.from(marker+'_hmac')),
      symmetric:(r:any)=>r.func==='EVP_CipherUpdate'&&r.bytes.includes(Buffer.from(marker+'_symmetric')),
      asymmetric:(r:any)=>(r.func==='ECDSA_sign_digest'&&r.bytes.includes(createHash('sha256').update(marker+'_asymmetric').digest()))||(r.func==='EVP_DSignUpdate_asym'&&r.bytes.includes(Buffer.from(marker+'_asymmetric'))),
      tls:(r:any)=>r.func==='SSL_write'&&r.bytes.includes(Buffer.from(marker+'_tls')),
      aead:(r:any)=>r.func.includes('AEAD')&&r.bytes.includes(Buffer.from(marker+'_aead')),
      system:(r:any)=>r.func==='access'&&r.bytes.includes(Buffer.from(marker+'_system'))};
    const counts=Object.fromEntries(families.map(k=>[k,rows.filter(matches[k]).length]));
    for(const key of families){const hits=rows.filter(matches[key]);assert.equal(hits.length>0,key===family,key+' marker mismatch '+JSON.stringify(counts));for(const hit of hits){assert.equal(hit.tid,key==='tls'?receipt.tlsTid:receipt.pid);assert.ok(BigInt(hit.tsNs)>=BigInt(receipt.captureBeforeNs)&&BigInt(hit.tsNs)<=BigInt(receipt.captureAfterNs),'hit outside first Application probe window');}}
    if(family==='off')assert.equal(rows.length,0,'all-off must capture nothing');
    const evidence={receipt,early:session.earlyPlan,companionBytes:result.companionBytes,hitCounts:counts,health:{dropped:health.dropped,jdropped:health.jdropped,backlog:health.backlog,complete:health.complete}};
    writeFileSync(join(dir,'zygisk-family-'+family+'.json'),JSON.stringify(evidence,null,2));return evidence;
  });
  c.planDigest=originalDigest;
  await check('real LAN grant revoke denies companion delivery; existing process remains untouched',async()=>{
    const address=(await command(['shell','ip','-4','addr','show','wlan0'])).match(/inet (\d+\.\d+\.\d+\.\d+)/)?.[1];assert.ok(address,'real Wi-Fi address required');
    const cfg=await deviceWrite(usb,'lan.configure',{enabled:true,address,port:0}),state=await read(usb,'device.state');
    const paired=await tool('devices',{action:'pair',deviceId:usb.deviceId,connectionId:usb.connectionId,bootId:usb.bootId,daemonInstanceId:usb.daemonInstanceId,expectedDeviceRevision:state.stateRevision,permissions:['read','write','manage']},true);assert.equal(paired.ok,true,JSON.stringify(paired));
    const grant=paired.result.result,lan=await tool('devices',{action:'connect',transport:'lan',deviceId:usb.deviceId,address,port:cfg.port},true);assert.equal(lan._operation?.state,'succeeded',JSON.stringify(lan));
    const staged=await stage(600,lan);assert.equal(staged.entry.sourceGrant,grant.grantId);
    const positive=await launch(true);await deviceWrite(usb,'pairings.revoke',{grantId:grant.grantId});
    const status=await tool('native_hook',{action:'status',session:positive.session.sessionId});const hook=status.status.hooks.find((h:any)=>h.id===positive.early.steps[0].hookId);assert.ok(hook);assert.equal(hook.slotOwned,true);
    const rejected=await launch(false);return {tls:lan.tlsVersion,sourceGrantBound:true,existingProcessHookRetained:true,positivePid:positive.receipt.pid,...rejected};
  });
}
