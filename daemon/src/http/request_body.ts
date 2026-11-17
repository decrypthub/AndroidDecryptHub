// Bounded artifact JSON inputs. Control/config requests retain their 8 MiB limit.
import type {IncomingMessage} from 'node:http';
import {readBody,MAX_BODY_BYTES} from '../state.ts';

export const ARTIFACT_BODY_BYTES=64*1024*1024;
const artifactPaths=new Set([
  '/api/native/syscall_scan','/api/native/crypto_const','/api/native/crypto_variants',
  '/api/native/analyze','/api/native/disasm','/api/dex/method_code','/api/dex/index',
  '/api/dex/xref','/api/dex/coverage','/api/dex/recover','/api/dex/strip','/api/dex/rebuild',
  '/api/dex/parse','/api/dex/crypto_scan','/api/dex/search','/api/dex/repair',
]);
const artifactTools=new Set([
  'native_syscall_scan','native_crypto_const','crypto_variant_scan','native_analyze','native_disasm',
  'dex_method_code','dex_index','dex_xref','dex_coverage','dex_recover','dex_search','dex_crypto_scan','dex_repair',
]);
function tooLarge(cap:number):never{
  throw Object.assign(new Error(`request body too large (> ${cap} bytes)`),{status:413});
}
function artifactHttp(path:unknown,method:unknown){return method==='POST'&&typeof path==='string'&&artifactPaths.has(path);}
function artifactMcp(body:any):boolean{
  if(body?.method!=='tools/call')return false;
  if(artifactTools.has(body.params?.name))return true;
  const args=body.params?.arguments;
  return body.params?.name==='operations'&&['snapshot','submit'].includes(args?.action)&&artifactTools.has(args.tool);
}
export async function readRequestBody(req:IncomingMessage,kind?:'mcp'):Promise<string>{
  const url=new URL(req.url||'/','http://localhost');
  const mcp=kind==='mcp';
  const prepare=url.pathname==='/api/operations/prepare'&&req.method==='POST';
  const operations=url.pathname==='/api/operations'&&req.method==='POST';
  const artifact=artifactHttp(url.pathname,req.method);
  const text=await readBody(req,artifact||mcp||prepare||operations?ARTIFACT_BODY_BYTES:MAX_BODY_BYTES);
  if(Buffer.byteLength(text)<=MAX_BODY_BYTES||artifact)return text;
  // An MCP/prepare envelope cannot be classified until it is read. Its allocation is
  // still capped at 64 MiB; unrelated control requests are then rejected, never dispatched.
  let body:any;try{body=JSON.parse(text);}catch{tooLarge(MAX_BODY_BYTES);}
  if(mcp&&artifactMcp(body))return text;
  if(prepare&&artifactHttp(body?.path,body?.method||'GET'))return text;
  if(operations&&body?.action==='submit'&&artifactTools.has(body.tool))return text;
  return tooLarge(MAX_BODY_BYTES);
}
