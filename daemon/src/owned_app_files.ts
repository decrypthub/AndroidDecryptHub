import { createHash } from 'node:crypto';
import { adbExecBuffer, adbExecStream } from './adb_wire.ts';
import { allowedOwnedRoot, allowedOwnedSave, usesDemoExternal, OWN_FILE_DEMO_PACKAGE, type LocalObserver } from './local_observer.ts';

const run = (cmd: string, args: string[], _opts?: unknown) => adbExecBuffer(args, { timeout: ADB_TIMEOUT_MS, maxBuffer: 256 * 1024 });
const MAX_ENTRIES = 320;
const PREVIEW_BYTES = 32 * 1024;
const DEMO_EDIT_BYTES = 8 * 1024;
const ADB_TIMEOUT_MS = 6000;
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
    throw new AppFilesError(400,'只能使用已授权目录下的普通相对路径。');
  }
  return path;
}

export function allowsTextPreview(path:string):boolean {
  return TEXT_FILE.test(path);
}

function shellArg(value:string):string { return "'"+value.replaceAll("'","'\\''")+"'"; }

// Runs under the opted-in debuggable App's UID and checks directories and the opened preview descriptor.
const APP_FILES_SH = String.raw`set -eu
home=$(pwd -P)
case "$3" in
  files)
    [ ! -L files ] && [ -d files ] && cd -P ./files || exit 44
    [ "$(pwd -P)" = "$home/files" ] || exit 44
    ;;
  app) ;;
  external)
    [ -n "$4" ] && [ ! -L "$4" ] && [ -d "$4" ] && cd -P "$4" || exit 46
    [ "$(pwd -P)" = "$4" ] || exit 46
    ;;
  *) exit 44 ;;
esac
root=$(pwd -P)
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
    if [ "$3" = files ]; then toybox head -c 32769 <&3
    else (set -o pipefail; toybox head -c 32769 <&3 | toybox base64); fi
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

// The only editable path is one opted-in plain text file under the debug App's own files directory.
// Bytes are passed via stdin; verify them and the existing file before an atomic replacement.
const APP_SAVE_SH = String.raw`set -eu
home=$(pwd -P)
[ ! -L files ] && [ -d files ] && cd -P ./files || exit 44
root=$(pwd -P)
[ "$root" = "$home/files" ] || exit 44
name=$1
check_fd(){
  [ ! -L "./$name" ] && [ -f "./$name" ] || exit 44
  [ "$(toybox readlink -f "$1")" = "$root/$name" ] && [ -f "$1" ] || exit 44
}
hash_of(){
  entry=$(toybox sha256sum "$1") || exit 45
  printf '%s' "@{entry%% *}"
}
[ ! -L "./$name" ] && [ -f "./$name" ] || exit 44
exec 3<"./$name" || exit 45
desc=/proc/$$/fd/3
check_fd "$desc"
[ "$(hash_of "$desc")" = "$2" ] || exit 47
mode=$(toybox stat -L -c '%a' "$desc") || exit 45
case "$mode" in [0-7][0-7][0-7]) ;; *) exit 44 ;; esac
temp=$(toybox mktemp './.adh-text.XXXXXX') || exit 45
trap 'toybox rm -f "$temp"' EXIT
toybox base64 -d > "$temp" || exit 45
[ "$(hash_of "$temp")" = "$3" ] || exit 45
toybox chmod "$mode" "$temp" || exit 45
[ "$(pwd -P)" = "$root" ] && [ ! -L "./$name" ] && [ -f "./$name" ] || exit 44
exec 4<"./$name" || exit 45
desc=/proc/$$/fd/4
check_fd "$desc"
[ "$(hash_of "$desc")" = "$2" ] || exit 47
toybox mv -T "$temp" "./$name" || exit 45
exec 5<"./$name" || exit 48
desc=/proc/$$/fd/5
check_fd "$desc"
[ "$(hash_of "$desc")" = "$3" ] || exit 48
`.replaceAll('@{','${');
const digest=(bytes:Buffer)=>createHash('sha256').update(bytes).digest('hex');

// ADB on some Windows hosts changes newline bytes in stdout. Decode the byte-safe
// representation before hashing or previewing an eligible file.
export function decodeOwnedPreview(stdout:Buffer,encoded:boolean):Buffer {
  if(!encoded) return stdout;
  const input=stdout.toString('latin1').replace(/[\t\r\n ]+/g,'');
  if(input.length>4*Math.ceil((PREVIEW_BYTES+1)/3)||!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new AppFilesError(502,'设备返回的文件字节格式无效。');
  }
  const bytes=Buffer.from(input,'base64');
  if(bytes.length>PREVIEW_BYTES+1||bytes.toString('base64')!==input) throw new AppFilesError(502,'设备返回的文件字节格式无效。');
  return bytes;
}
function verifiedSerial(observer:LocalObserver):string {
  if(!observer.ownFilesSerial||!/^[A-Za-z0-9_-]+$/.test(observer.ownFilesSerial)||!/^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$/.test(observer.package)){
    throw new AppFilesError(403,'当前连接未授权调试 APP 的目录访问。');
  }
  return observer.ownFilesSerial;
}

export async function ownFileBrowserOnline(observer:LocalObserver):Promise<boolean> {
  if(!observer.fileBrowserOnly) return false;
  try{
    const {stdout}=await run('adb',['-s',verifiedSerial(observer),'get-state']);
    return stdout.toString().trim()==='device';
  }catch{ return false; }
}

export function decodeDemoFileReply(stdout:Buffer):Buffer {
  const match=/^Result: Bundle\[\{adhFile=(200|400|403|404|409|413|415|503)\.([A-Za-z0-9_-]*)\}\]$/.exec(stdout.toString('ascii').trim());
  if(!match) throw new AppFilesError(502,'Demo 外部目录接口未返回有效结果，请确认已安装文件验收版。');
  const [,code,encoded]=match;
  if(code!=='200'){
    const message:Record<string,string>={
      400:'Demo 拒绝了无效的文件请求。',403:'Demo 未授权外部目录访问。',
      404:'文件或目录不存在，或不是允许访问的普通路径。',409:'源文件已变化，重新读取后再保存。',
      413:'Demo 外部目录的文本编辑上限是 8 KiB。',415:'此文件不是可编辑的 UTF-8 文本。',
      503:'Demo 暂时无法访问应用专属外部目录。'
    };
    throw new AppFilesError(Number(code),message[code]);
  }
  const bytes=Buffer.from(encoded,'base64url');
  if(bytes.toString('base64url')!==encoded) throw new AppFilesError(502,'Demo 返回的文件字节格式无效。');
  return bytes;
}

async function demoExternal(serial:string,method:'list'|'preview'|'save',arg:string):Promise<Buffer>{
  // Keep all shell arguments ASCII and unambiguous, including names and file contents.
  if(!/^[A-Za-z0-9_.-]*$/.test(arg)) throw new AppFilesError(400,'Demo 文件参数格式无效。');
  const {stdout}=await run('adb',['-s',serial,'shell','-T','content','call','--user','0','--uri',
    'content://'+OWN_FILE_DEMO_PACKAGE+'.adh-demo-files','--method',method,...(arg?['--arg',arg]:[])]);
  return decodeDemoFileReply(stdout);
}

async function ensureAppFileTransport(observer:LocalObserver,serial:string):Promise<void>{
  if(observer.fileBrowserOnly){
    if(!await ownFileBrowserOnline(observer)) throw new AppFilesError(503,'USB 设备未连接。');
  }else{
    const current=await run('adb',['-s',serial,'shell','-T','pidof',observer.package]);
    if(current.stdout.toString().trim()!==String(observer.pid)) throw new AppFilesError(409,'APP 进程已变化，请回到当前会话重试。');
  }
}
function asFileError(error:unknown,fileBrowserOnly:boolean):AppFilesError {
  if(error instanceof AppFilesError) return error;
  const failure=error as {code?:number|string;stderr?:Buffer|string};
  if(failure.code===44) return new AppFilesError(404,'文件或目录不存在，或不是允许访问的普通路径。');
  if(failure.code===46) return new AppFilesError(403,'APP 专属外部目录不可读取：目录不存在或设备未授予应用访问权限。');
  if(failure.code===47) return new AppFilesError(409,'源文件已变化，重新读取后再保存。');
  if(failure.code===48) return new AppFilesError(409,'保存结果未复核，请重新读取文件确认。');
  if(failure.code===45||/not debuggable|permission denied|run-as:/i.test(String(failure.stderr??''))){
    return new AppFilesError(403,'APP 调试身份没有权限完成此文件操作。');
  }
  return new AppFilesError(503,fileBrowserOnly?'无法访问 APP 文件，请确认 USB 与应用调试权限。':'未能读取此设备的 APP 文件；请确认 USB 和 APP 会话在线。');
}

let pending=0;
let saving=false;
export async function readOwnedAppFiles(observer:LocalObserver,mode:string,path:string,root='files') {
  const serial=verifiedSerial(observer);
  if(!allowedOwnedRoot(observer,root)) throw new AppFilesError(403,'此目录范围未授权。');
  if(mode!=='list'&&mode!=='preview') throw new AppFilesError(400,'不支持的文件查看操作。');
  const relative=ownAppFilePath(path);
  if(mode==='preview'&&!allowsTextPreview(relative)) throw new AppFilesError(415,'只预览常见文本格式；其它文件只显示元数据。');
  if(pending>=4) throw new AppFilesError(429,'文件请求过多，请稍后重试。');
  pending++;
  try{
    await ensureAppFileTransport(observer,serial);
    const inDemo=usesDemoExternal(observer,root);
    let stdout:Buffer;
    if(inDemo){
      stdout=await demoExternal(serial,mode,Buffer.from(relative,'utf8').toString('base64url'));
    }else{
      const external=root==='external'?'/storage/emulated/'+observer.externalUser+'/Android/data/'+observer.package+'/files':'';
      const cmd=['run-as',observer.package,'sh','-c',shellArg(APP_FILES_SH),'adh-files',shellArg(mode),shellArg(relative),root,shellArg(external)].join(' ');
      ({stdout}=await run('adb',['-s',serial,'shell','-T',cmd]));
    }
    const identity={ok:true,package:observer.package,path:relative,root};
    if(mode==='list') return {...identity,...parseAppFileListing(stdout)};
    const source=inDemo?stdout:decodeOwnedPreview(stdout,observer.fileBrowserOnly===true);
    const truncated=source.length>PREVIEW_BYTES, bytes=source.subarray(0,PREVIEW_BYTES);
    if(bytes.includes(0)) throw new AppFilesError(415,'此文件不能作为文本预览。');
    let text:string;
    try{ text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes,{stream:truncated}); }
    catch{ throw new AppFilesError(415,'此文件不是可预览的 UTF-8 文本。'); }
    const editLimit=inDemo?DEMO_EDIT_BYTES:PREVIEW_BYTES;
    const editable=allowedOwnedSave(observer,root,relative)&&!truncated&&bytes.length<=editLimit&&!/[\r\uFEFF]/u.test(text);
    return {...identity,text,truncated,editable,...(editable?{revision:digest(bytes),editLimit}:{})};
  }catch(error){ throw asFileError(error,!!observer.fileBrowserOnly); }
  finally{ pending--; }
}
export function parseOwnedTextEdit(body:unknown):{bytes:Buffer;revision:string} {
  if(!body||typeof body!=='object'||Array.isArray(body)) throw new AppFilesError(400,'未收到待保存的文本和版本。');
  const item=body as {text?:unknown;revision?:unknown};
  if(Object.keys(item).length!==2||typeof item.text!=='string'||typeof item.revision!=='string'||
     !/^[0-9a-f]{64}$/.test(item.revision)||/[\x00\r\uFEFF]/u.test(item.text)){
    throw new AppFilesError(400,'只接受附带版本的 UTF-8、LF 纯文本。');
  }
  const bytes=Buffer.from(item.text,'utf8');
  if(bytes.length>PREVIEW_BYTES) throw new AppFilesError(413,'文本超过 32 KiB。');
  if(bytes.toString('utf8')!==item.text) throw new AppFilesError(400,'文本中有不完整的 Unicode 字符。');
  return {bytes,revision:item.revision};
}
async function sendAppText(serial:string,cmd:string,bytes:Buffer):Promise<void>{
  await new Promise<void>((done,fail)=>{
    const proc=adbExecStream(['-s',serial,'shell','-T',cmd]) as import('./adb_wire.ts').AdbStream;
    proc.on('error',fail);
    proc.on('end',()=>done());
    proc.onStderr=()=>{};
    proc.onExit=(code)=>{ if(code!==0) fail(new AppFilesError(503,'文件保存命令退出码 '+code)); };
    proc.end(bytes.toString('base64'),'ascii');
  });
}
export async function saveOwnedAppText(observer:LocalObserver,root:string,path:string,body:unknown) {
  const serial=verifiedSerial(observer);
  const relative=ownAppFilePath(path);
  if(!allowedOwnedSave(observer,root,relative)) throw new AppFilesError(403,'仅可保存明确授权的手机文本文件。');
  const {bytes,revision}=parseOwnedTextEdit(body);
  const inDemo=usesDemoExternal(observer,root);
  if(inDemo&&bytes.length>DEMO_EDIT_BYTES) throw new AppFilesError(413,'Demo 外部目录的文本编辑上限是 8 KiB。');
  if(saving) throw new AppFilesError(409,'已有一次保存正在执行。');
  saving=true;
  try{
    const prior=await readOwnedAppFiles(observer,'preview',relative,root);
    if(!('editable' in prior)||!prior.editable) throw new AppFilesError(403,'原文件不可按当前文本权限编辑。');
    if(prior.revision!==revision) throw new AppFilesError(409,'源文件已变化，重新读取后再保存。');
    const next=digest(bytes);
    if(inDemo){
      const saved=await demoExternal(serial,'save',revision+'.'+bytes.toString('base64url'));
      if(!saved.equals(Buffer.from(next,'ascii'))) throw new AppFilesError(409,'保存结果未复核，请重新读取文件确认。');
    }else{
      const cmd=['run-as',observer.package,'sh','-c',shellArg(APP_SAVE_SH),'adh-save',
        shellArg(observer.editableText!),revision,next].join(' ');
      await sendAppText(serial,cmd,bytes);
    }
    return {ok:true,package:observer.package,path:relative,root,revision:next};
  }catch(error){ throw asFileError(error,true); }
  finally{ saving=false; }
}
