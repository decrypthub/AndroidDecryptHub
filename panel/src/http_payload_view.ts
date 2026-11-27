/** Render only retained HTTP body bytes. Raw is not a reconstructed wire packet. */
export interface HttpBodyPart {startLine?:string;headerText?:string;bodyText?:string;bodyHex?:string;bodyBytes?:number;binary?:boolean;decoded?:boolean;contentEncoding?:string;[key:string]:unknown}
export type BodyFormat='raw'|'utf8'|'hex'|'b64'|'hexdump';
export const BODY_FORMATS:[BodyFormat,string][]=[['raw','Raw'],['utf8','UTF-8'],['hex','Hex'],['b64','Base64'],['hexdump','Hexdump']];
function dump(bytes:Uint8Array){const lines:string[]=[];for(let i=0;i<bytes.length;i+=16){const row=bytes.slice(i,i+16),hex=[...row].map(b=>b.toString(16).padStart(2,'0')).join(' '),ascii=[...row].map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join('');lines.push(i.toString(16).padStart(8,'0')+': '+hex.padEnd(47)+' |'+ascii+'|');}return lines.join('\n');}
export function bodyView(p:HttpBodyPart|undefined,mode:BodyFormat){
 if(!p)return {display:'（尚未捕获）',copy:'',bytes:0,known:false,copyLabel:'复制正文'};
 let bytes:Uint8Array;
 if(p.bodyHex!==undefined){if(!/^(?:[a-f\d]{2})*$/i.test(p.bodyHex))return {display:'（已保留字节格式无效）',copy:'',bytes:0,known:false,copyLabel:'复制正文'};bytes=Uint8Array.from(p.bodyHex.match(/../g)??[],s=>parseInt(s,16));}
 else if(p.binary&&p.bodyBytes!==0)return {display:'（此记录未保留正文的原始字节）',copy:'',bytes:0,known:false,copyLabel:'复制正文'};
 else if(typeof p.bodyText==='string')bytes=new TextEncoder().encode(p.bodyText);
 else if(p.bodyBytes===0)bytes=new Uint8Array();
 else return {display:'（尚未保留正文）',copy:'',bytes:0,known:false,copyLabel:'复制正文'};
 const hex=[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');let value='',copy='',copyLabel='复制正文';
 if(mode==='hex'){value=hex.match(/../g)?.join(' ')??'';copy=hex;copyLabel='复制 Hex';}
 else if(mode==='b64'){value=btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));copy=value;copyLabel='复制 Base64';}
 else if(mode==='hexdump'||mode==='raw'&&(p.binary||p.bodyHex!==undefined)){value=dump(bytes);copy=hex;copyLabel='复制 Hex';}
 else{value=new TextDecoder('utf-8').decode(bytes);copy=value;}
 return {display:value||'（空正文）',copy,bytes:bytes.length,known:true,copyLabel};
}
export function exchangeIdentity(ex:{label?:unknown;request?:HttpBodyPart;status?:unknown}){
 const label=String(ex.label??''),start=String(ex.request?.startLine??''),match=/^([A-Z]+)\s+(\S+)/.exec(label)||/^([A-Z]+)\s+(\S+)/.exec(start);
 if(!match||match[1]==='HTTP')return {title:ex.status?'HTTP '+ex.status:'网络事件',url:'',host:''};
 const [,method,target]=match;
 try{const absolute=/^https?:\/\//i.test(target),url=new URL(target,'http://adh.invalid');return{title:method+' '+url.pathname+(url.search?'?…':''),url:target,host:absolute?url.host:''};}
 catch{return{title:method+' '+target.split('?')[0],url:target,host:''};}
}
