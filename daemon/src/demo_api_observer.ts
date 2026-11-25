import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {OWN_API_DEMO_PACKAGE, type LocalObserver} from './local_observer.ts';

const exec=promisify(execFile);
const adbOptions={encoding:'utf8' as const,windowsHide:true,timeout:6000,maxBuffer:16*1024};
const allowed=new Map([
  ['digest',['java.security.MessageDigest','digest(byte[])']],
  ['crc32',['java.util.zip.CRC32','update(byte[])']],
]);
const revisionId=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
export class DemoApiError extends Error {
  readonly status:number;
  constructor(status:number,message:string){ super(message); this.status=status; }
}

type Toggle={id:string;enabled:boolean;revision:string};
export function parseDemoApiToggle(raw:unknown):Toggle {
  if(!raw||typeof raw!=='object'||Array.isArray(raw)) throw new DemoApiError(400,'无效的 API 设置。');
  const {id,enabled,revision}=raw as Toggle;
  if(Object.keys(raw).length!==3||typeof id!=='string'||!allowed.has(id)||typeof enabled!=='boolean'||
     typeof revision!=='string'||!revisionId.test(revision)) throw new DemoApiError(400,'只接受此 Demo 已声明的 API 与设置版本。');
  return {id,enabled,revision};
}

export function parseDemoApiCatalog(stdout:string) {
  const result=/^Result: Bundle\[\{adhApi=(200|400|409|503)\.([A-Za-z0-9_-]*)\}\]$/.exec(stdout.trim());
  if(!result) throw new DemoApiError(502,'没有收到 Demo 的有效回执。');
  const [,status,payload]=result;
  if(status==='409') throw new DemoApiError(409,'设备设置已变化，请刷新后重试。');
  if(status==='400') throw new DemoApiError(400,'Demo 没有授权此 API 设置。');
  if(status==='503') throw new DemoApiError(503,'Demo 无法保存设置。');
  try {
    const bytes=Buffer.from(payload,'base64url');
    if(bytes.toString('base64url')!==payload) throw Error();
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if(typeof value?.revision!=='string'||!revisionId.test(value.revision)||!Array.isArray(value.apis)||
       value.apis.length!==allowed.size) throw Error();
    const seen=new Set<string>();
    const apis=value.apis.map((row:{id:string;className:string;method:string;enabled:boolean})=>{
      const expected=allowed.get(row?.id);
      if(!expected||seen.has(row.id)||row.className!==expected[0]||row.method!==expected[1]||typeof row.enabled!=='boolean') throw Error();
      seen.add(row.id);
      return {id:row.id,className:row.className,method:row.method,enabled:row.enabled};
    });
    return {revision:value.revision as string,apis};
  } catch { throw new DemoApiError(502,'设备能力或设置回执格式无效。'); }
}

export function demoApiDeviceSerial(observer:LocalObserver,pkg:string=observer.demoApiSerial?observer.package:''):string {
  const serial=observer.demoApiSerial??(pkg===OWN_API_DEMO_PACKAGE?observer.declaredApiSerial:'');
  if(pkg!==OWN_API_DEMO_PACKAGE||!serial||observer.fileBrowserOnly||!/^[A-Za-z0-9_-]+$/.test(serial)||
     (observer.demoApiSerial&&(observer.package!==OWN_API_DEMO_PACKAGE||observer.declaredApiSerial))) {
    throw new DemoApiError(403,'此入口未授权自有 Demo 的 API 采集设置。');
  }
  return serial;
}
export async function demoApiOnline(observer:LocalObserver):Promise<boolean> {
  try { return (await exec('adb',['-s',demoApiDeviceSerial(observer),'get-state'],adbOptions)).stdout.trim()==='device'; }
  catch { return false; }
}

export async function changeDemoApi(observer:LocalObserver,raw?:unknown,pkg:string=observer.demoApiSerial?observer.package:'') {
  const serial=demoApiDeviceSerial(observer,pkg);
  const change=raw===undefined?undefined:parseDemoApiToggle(raw);
  const args=['-s',serial,'shell','-T','content','call','--user','0','--uri','content://'+OWN_API_DEMO_PACKAGE+'.adh-demo-api',
    '--method',change?'set':'catalog'];
  if(change) args.push('--arg',Buffer.from(JSON.stringify(change),'utf8').toString('base64url'));
  let stdout:string;
  try { ({stdout}=await exec('adb',args,adbOptions)); }
  catch { throw new DemoApiError(503,'设备未连接，或没有收到 Demo 的回执。'); }
  const catalog=parseDemoApiCatalog(stdout);
  if(change&&catalog.apis.find(a=>a.id===change.id)?.enabled!==change.enabled) {
    throw new DemoApiError(502,'未核实设备设置是否生效；请重新读取。');
  }
  return {ok:true,package:OWN_API_DEMO_PACKAGE,...catalog};
}
