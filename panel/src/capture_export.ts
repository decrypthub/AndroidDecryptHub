import type {Cap} from './api';
export interface ExportScope {serial:string;package:string;kind:string}
export interface ExportSnapshot extends ExportScope {ids:number[]}
const BYTE_FIELDS=['hex','outHex','keyHex','ivHex'] as const;
const LENGTH_FIELDS=['inl','outl','keyl','ivl'] as const;
/** Metadata still contains previews; it is not a sanitized/public report. */
export function metadataExport(scope:ExportScope,items:Cap[]) {
 return {schema:'adh.capture-export/1',mode:'metadata-only',...scope,
  note:'本页元数据与预览；不含输入、输出、密钥或 IV 的字节内容。预览仍可能含敏感信息。',
  records:items.map(c=>{const record={...c};for(const field of [...BYTE_FIELDS,'text'])delete record[field];return record;})};
}
/** Fail closed: a missing/foreign record or target switch never becomes a silent partial export. */
export async function createCaptureExport(snapshot:ExportSnapshot,load:(id:number)=>Promise<Record<string,unknown>>,check:()=>void,
 options:{maxRecords?:number;maxBytes?:number;digest?:(bytes:Uint8Array)=>Promise<string>}={}) {
 const scope={serial:snapshot.serial,package:snapshot.package,kind:snapshot.kind},ids=[...snapshot.ids];
 if(!scope.serial||!scope.package)throw new Error('缺少明确设备或应用，无法导出字节');
 if(ids.length>(options.maxRecords??1000)||new Set(ids).size!==ids.length||ids.some(id=>!Number.isSafeInteger(id)||id<=0))throw new Error('记录数量或编号无效，请缩小导出范围');
 const digest=options.digest??(globalThis.crypto?.subtle?async(bytes:Uint8Array)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes as BufferSource)),b=>b.toString(16).padStart(2,'0')).join(''):null);
 const records:Record<string,unknown>[]=new Array(ids.length);let next=0,total=0,stopped=false;
 const worker=async()=>{while(!stopped){const i=next++;if(i>=ids.length)return;
  try{
   check();const c=await load(ids[i]);check();
   const binding=c.deviceBinding as {serial?:string}|undefined;
   if(c.id!==ids[i]||c.package!==scope.package||binding?.serial!==scope.serial)throw new Error(`记录 #${ids[i]} 的设备或应用不一致`);
   const serialized=JSON.stringify(c),n=new TextEncoder().encode(serialized).byteLength;
   total+=n;if(n>1024*1024||total>(options.maxBytes??16*1024*1024))throw new Error('超过导出大小上限，请缩小范围');
   const bytes:Record<string,unknown>={};
   for(let f=0;f<BYTE_FIELDS.length;f++){
    const field=BYTE_FIELDS[f],hex=c[field],reported=c[LENGTH_FIELDS[f]];
    if(hex===undefined){bytes[field]={state:'not-recorded'};continue;}
    if(typeof hex!=='string'||!/^(?:[0-9a-f]{2})*$/i.test(hex))throw new Error(`记录 #${ids[i]} 的 ${field} 不是有效字节`);
    const data=Uint8Array.from(hex.match(/../g)??[],b=>parseInt(b,16)),length=typeof reported==='number'&&Number.isSafeInteger(reported)&&reported>=0?reported:null;
    const host=(c.byteEvidence as Record<string,{capturedBytes?:number;sha256?:string}>|undefined)?.[field];
    const hostHash=host?.capturedBytes===data.length&&typeof host.sha256==='string'&&/^[a-f\d]{64}$/.test(host.sha256)?host.sha256:null;
    const hash=digest?await digest(data):hostHash;if(!hash)throw new Error('此记录缺少字节校验信息，请更新 Host 后重试');
    if(digest&&hostHash&&hash!==hostHash)throw new Error(`记录 #${ids[i]} 的 ${field} 校验不一致`);
    bytes[field]={state:'retained',capturedBytes:data.length,reportedBytes:length,truncated:length!==null&&length>data.length,inconsistent:length!==null&&length<data.length,sha256:hash,checksumSource:digest?'browser-retained-bytes':'host-retained-bytes'};
   }
   check();records[i]={...c,byteEvidence:bytes};
  }catch(e){stopped=true;throw e;}
 }};
 // Settle every in-flight read before returning an error; nothing is downloaded on partial failure.
 const results=await Promise.allSettled(Array.from({length:Math.min(4,ids.length)},worker));
 const error=results.find(r=>r.status==='rejected');if(error?.status==='rejected')throw error.reason;
 check();
 return {schema:'adh.capture-export/1',mode:'retained-bytes',...scope,ids,
  note:'只含本页服务端仍保留的字节。SHA-256 校验这些已保留字节，不证明原始完整输入；未采集或截断内容无法补回。Java 参数采样可能包含输出缓冲区。',records};
}
