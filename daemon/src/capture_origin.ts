import {createHash} from 'node:crypto';
/** Hash only retained bytes on Host, so LAN HTTP browsers need no secure-context WebCrypto. */
export function retainedByteEvidence(c:Record<string,unknown>) {
  const result:Record<string,{capturedBytes:number;sha256:string}>={};
  for(const field of ['hex','outHex','keyHex','ivHex']) {
    const hex=c[field];if(typeof hex!=='string'||hex.length>2*1024*1024||!/^(?:[a-f\d]{2})*$/i.test(hex))continue;
    const bytes=Buffer.from(hex,'hex');result[field]={capturedBytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
  }
  return result;
}
/** Parse only explicitly supplied rich-capture evidence; never infer an overload from lengths/op. */
export function richCaptureEvidence(c:Record<string,unknown>): {
  recordSchema?:string; javaTarget?:string; javaTargetTruncated?:boolean; javaHookId?:number;
  captureMethodId?:string; inputBytesPresent?:boolean; inputScope?:string;
  outl?:number; keyl?:number; ivl?:number;
} {
  const result:any={};
  const integer=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=0x7fffffff;
  if(c.recordSchema==='java-rich/2')result.recordSchema=c.recordSchema;
  for(const key of ['outl','keyl','ivl'] as const)if(integer(c[key]))result[key]=c[key];
  if(typeof c.inputBytesPresent==='boolean')result.inputBytesPresent=c.inputBytesPresent;
  if(c.inputScope==='call-argument-snapshot-after-return')result.inputScope=c.inputScope;
  if(typeof c.javaTargetTruncated==='boolean')result.javaTargetTruncated=c.javaTargetTruncated;
  if(integer(c.javaHookId)&&Number(c.javaHookId)>0)result.javaHookId=c.javaHookId;
  if(typeof c.javaTarget==='string'&&c.javaTarget.length<=255){
    result.javaTarget=c.javaTarget;
    const m=/^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\.([A-Za-z_$][\w$]*|<init>)\(([A-Za-z\d_.$\[\],;]*)\)$/.exec(c.javaTarget);
    if(m&&c.javaTargetTruncated===false)result.captureMethodId=`java.${m[1]}#${m[2]}(${m[3]})`;
  }
  return result;
}
