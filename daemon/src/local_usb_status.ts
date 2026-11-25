import { OWN_API_DEMO_PACKAGE, usesDemoExternal, type LocalObserver } from './local_observer.ts';
import { checkAdbLink, parseAdbDevices, realAdbRunner, type AdbRunner } from './transport/adb_device.ts';

export type UsbLinkState = 'online' | 'disconnected' | 'offline' | 'unauthorized' | 'unknown';

export async function localUsbLink(serial:string|undefined,run:AdbRunner=realAdbRunner):Promise<UsbLinkState>{
  if(!serial||!/^[A-Za-z0-9_-]+$/.test(serial)) return 'unknown';
  try{
    const text=await run(['devices','-l'],{timeout:2200});
    if(!/^List of devices attached\b/m.test(text)) return 'unknown';
    const rows=parseAdbDevices(text).filter(row=>row.serial===serial);
    if(!rows.length) return 'disconnected';
    if(rows.length!==1||rows[0].link==='adb-tcp') return 'unknown';
    const [row]=rows;
    if(row.state==='unauthorized'||row.state==='offline') return row.state;
    return row.state==='device'&&await checkAdbLink(row,run)==='usb'?'online':'unknown';
  }catch{ return 'unknown'; }
}

// Only the explicitly configured, self-owned Demo may browse files without an Agent session.
export function hasIndependentDemoFiles(o:LocalObserver){
  return o.package==='com.adh.sandbox'&&!!o.usbSerial&&o.ownFilesSerial===o.usbSerial;
}

/** A package listing is metadata, not permission to open files or an Agent session. */
export function makeUsbInventory(run:AdbRunner=realAdbRunner,now=Date.now){
  let cached:{key:string;until:number;rows:{package:string}[]}|undefined;
  return async function(serial:string|undefined){
    if(!serial||await localUsbLink(serial,run)!=='online'){ cached=undefined; throw Error('手机没有通过 USB 连上'); }
    const user=(await run(['-s',serial,'shell','am','get-current-user'],{timeout:2200})).trim();
    if(!/^\d+$/.test(user)) throw Error('读不到当前手机用户');
    const key=serial+':'+user;
    if(cached?.key===key&&now()<cached.until) return cached.rows;
    const raw=await run(['-s',serial,'shell','pm','list','packages','--user',user],{timeout:4000,maxBuffer:1024*1024});
    const lines=raw.trim().split(/\r?\n/);
    if(lines.some(l=>!/^package:[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$/.test(l))) throw Error('手机没有返回完整的应用列表');
    const rows=[...new Set(lines.map(l=>l.slice(8)))].sort().map(value=>({package:value}));
    cached={key,until:now()+10000,rows};
    return rows;
  };
}
export const readUsbInventory=makeUsbInventory();

export async function localUsbView(observer:LocalObserver,matchingAppSession:boolean,run?:AdbRunner){
  const linkState=await localUsbLink(observer.usbSerial,run);
  const online=linkState==='online';
  const fileOnly=observer.fileBrowserOnly===true;
  const demoApi=!!observer.demoApiSerial;
  const appSession=fileOnly||demoApi?'not-required':matchingAppSession?'online':'waiting';
  return {model:observer.model,transport:'usb',online,linkState,appSession,observedPackage:observer.package,
    appFiles:online&&!!observer.ownFilesSerial&&(fileOnly||appSession==='online'||hasIndependentDemoFiles(observer)),
    independentFiles:online&&hasIndependentDemoFiles(observer),
    ...(demoApi?{demoApi:true}:{}),
    ...(online&&observer.declaredApiSerial&&!fileOnly&&!demoApi?{declaredApiPackages:[OWN_API_DEMO_PACKAGE]}:{}),
    ...(online&&!!observer.usbSerial&&!fileOnly&&!demoApi?{rootSandbox:true}:{}),
    ...(fileOnly?{fileBrowserOnly:true,appFileRoots:usesDemoExternal(observer,'external')?['external','app']:['app','external']}:{}),
  };
}
