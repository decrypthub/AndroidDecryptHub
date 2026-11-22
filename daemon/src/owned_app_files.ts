import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { LocalObserver } from './local_observer.ts';

const run = promisify(execFile);
const MAX_ENTRIES = 320;
const PREVIEW_BYTES = 32 * 1024;
const TEXT_FILE = /\.(?:txt|log|md|json|jsonl|csv|tsv|xml|yaml|yml|ini|properties)$/i;

export class AppFilesError extends Error {
  readonly status:number;
  constructor(status:number,message:string){ super(message); this.status=status; }
}

export function ownAppFilePath(path:string):string {
  if(typeof path!=='string'||Buffer.byteLength(path)>2048||/[\u0000-\u001F\u007F\\\uFFFD]/u.test(path)){
    throw new AppFilesError(400,'不是有效的 APP 目录相对路径。');
  }
  if(path==='') return path;
  const parts=path.split('/');
  if(parts.length>24||parts.some(p=>!p||p.startsWith('.')||Buffer.byteLength(p)>240)){
    throw new AppFilesError(400,'只能浏览 APP 的 files 目录及普通子项。');
  }
  return path;
}

export function allowsTextPreview(path:string):boolean {
  return TEXT_FILE.test(path);
}

function shellArg(value:string):string { return "'"+value.replaceAll("'","'\\''")+"'"; }

// Runs under the selected debuggable App's UID, not root. Every directory must stay in files/.
// Preview checks the opened descriptor before reading, so a swapped link doesn't escape the root.
const APP_FILES_SH = String.raw`set -eu
home=$(pwd -P)
[ ! -L files ] && [ -d files ] && cd -P ./files || exit 44
root=$(pwd -P)
[ "$root" = "$home/files" ] || exit 44
enter(){
  remain=$1
  while [ -n "$remain" ]; do
    part=@{remain%%/*}
    [ ! -L "./$part" ] && [ -d "./$part" ] && cd -P "./$part" || exit 44
    case "$(pwd -P)" in "$root"|"$root/"*) ;; *) exit 44;; esac
    if [ "$part" = "$remain" ]; then break; fi
    remain=@{remain#*/}
  done
}
case "$1" in
  list)
    enter "$2"
    count=0
    for entry in ./*; do
      [ ! -L "$entry" ] || continue
      if [ -d "$entry" ]; then kind=directory
      elif [ -f "$entry" ]; then kind=file
      else continue
      fi
      meta=$(toybox stat -c '%s %Y' "$entry") || continue
      set -- $meta
      printf '%s\000%s\000%s\000%s\000' "@{entry#./}" "$kind" "$1" "$2"
      count=$((count+1))
      [ "$count" -lt 321 ] || break
    done
    ;;
  preview)
    name=@{2##*/}
    case "$2" in */*) enter "@{2%/*}" ;; esac
    [ ! -L "./$name" ] && [ -f "./$name" ] || exit 44
    exec 3<"./$name" || exit 45
    fd=/proc/$$/fd/3
    expected="$(pwd -P)/$name"
    [ "$(toybox readlink -f "$fd")" = "$expected" ] && [ -f "$fd" ] || exit 44
    toybox head -c 32769 <&3
    ;;
  *) exit 64 ;;
esac
`.replaceAll('@{','${');

export function parseAppFileListing(raw:Buffer) {
  if(!raw.length) return {entries:[],limited:false};
  const words=raw.toString('utf8').split('\0');
  if(words.pop()!==''||words.length%4!==0||words.length/4>MAX_ENTRIES+1){
    throw new AppFilesError(502,'目录列表格式无效。');
  }
  const entries=[];
  for(let i=0;i<Math.min(words.length,MAX_ENTRIES*4);i+=4){
    const [name,type,sizeText,timeText]=words.slice(i,i+4);
    try{ if(!name||ownAppFilePath(name)!==name||name.includes('/')) continue; }catch{ continue; }
    if(!/^\d+$/.test(sizeText)||!/^\d+$/.test(timeText)) continue;
    const size=Number(sizeText), modified=Number(timeText)*1000;
    if(!Number.isSafeInteger(size)||!Number.isSafeInteger(modified)||!['directory','file'].includes(type)) continue;
    entries.push({name,type,size:type==='file'?size:null,modifiedAt:modified});
  }
  entries.sort((a,b)=>Number(b.type==='directory')-Number(a.type==='directory')||a.name.localeCompare(b.name));
  return {entries,limited:words.length/4>MAX_ENTRIES};
}

let pending=0;
export async function readOwnedAppFiles(observer:LocalObserver,mode:string,path:string) {
  const serial=observer.ownFilesSerial;
  if(!serial||!/^[A-Za-z0-9_-]+$/.test(serial)||!/^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$/.test(observer.package)){
    throw new AppFilesError(403,'当前连接未授权调试 APP 的目录访问。');
  }
  if(mode!=='list'&&mode!=='preview') throw new AppFilesError(400,'不支持的文件查看操作。');
  const relative=ownAppFilePath(path);
  if(mode==='preview'&&!allowsTextPreview(relative)) throw new AppFilesError(415,'只预览常见文本格式；其它文件只显示元数据。');
  if(pending>=4) throw new AppFilesError(429,'文件请求过多，请稍后重试。');
  pending++;
  try{
    const options={encoding:'buffer' as const,windowsHide:true,timeout:6000,maxBuffer:256*1024};
    const current=await run('adb',['-s',serial,'shell','-T','pidof',observer.package],options);
    if(current.stdout.toString().trim()!==String(observer.pid)){
      throw new AppFilesError(409,'APP 进程已变化，请回到当前会话重试。');
    }
    const cmd=['run-as',observer.package,'sh','-c',shellArg(APP_FILES_SH),'adh-files',shellArg(mode),shellArg(relative)].join(' ');
    const {stdout}=await run('adb',['-s',serial,'shell','-T',cmd],options);
    if(mode==='list') return {ok:true,package:observer.package,path:relative,...parseAppFileListing(stdout)};
    const truncated=stdout.length>PREVIEW_BYTES, bytes=stdout.subarray(0,PREVIEW_BYTES);
    if(bytes.includes(0)) throw new AppFilesError(415,'此文件不能作为文本预览。');
    let text:string;
    try{ text=new TextDecoder('utf-8',{fatal:true}).decode(bytes,{stream:truncated}); }
    catch{ throw new AppFilesError(415,'此文件不是可预览的 UTF-8 文本。'); }
    return {ok:true,package:observer.package,path:relative,text,truncated};
  }catch(error) {
    if(error instanceof AppFilesError) throw error;
    const failure=error as {code?:number|string;stderr?:Buffer| string};
    if(failure.code===44) throw new AppFilesError(404,'文件或目录不存在，或不是允许浏览的普通路径。');
    if(failure.code===45||/not debuggable|permission denied|run-as:/i.test(String(failure.stderr??''))){
      throw new AppFilesError(403,'APP 调试身份没有权限读取此目录或文件。');
    }
    throw new AppFilesError(503,'未能读取此设备的 APP 文件；请确认 USB 和 APP 会话在线。');
  }finally{ pending--; }
}
