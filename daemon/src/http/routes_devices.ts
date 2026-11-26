import {deviceAction} from '../device_host.ts';
import {agentSockets,readBody,sessions} from '../state.ts';
import {demoApiRequest,localObserver,localObserverHost,OWN_APP_FILES_ROUTE,OWN_DEMO_API_ROUTE,retargetObserver} from '../local_observer.ts';
import {hasIndependentDemoFiles,localUsbLink,localUsbView} from '../local_usb_status.ts';
import {changeDemoApi,DemoApiError} from '../demo_api_observer.ts';
import {AppFilesError,readOwnedAppFiles,saveOwnedAppText} from '../owned_app_files.ts';
import {connectDevice,deviceRpcLive,dropDevice} from '../device_bridge.ts';
import {connectNetDevice,reconnectDevice} from '../device_actions.ts';
import {parseAdbDevices,realAdbRunner,type AdbRunner} from '../transport/adb_device.ts';
import type {Route,RouteContext} from './types.ts';

/** The observed app's agent session, for the device manager: online first, else the newest dead one. */
function observedAgentView(){
  const pkg=localObserver?.package;
  if(!pkg) return null;
  let best:{online:boolean;pid:number;sessionId:string;lastSeen:number;version:string}|null=null;
  for(const session of sessions.values()){
    if(session.package!==pkg) continue;
    // 插件版本就是 agent .so 自报的版本（AGENT_VER，与 module.prop 同步升）。面板设备页直接展示。
    const row={online:session.online===true,pid:session.pid,sessionId:session.sessionId,lastSeen:session.lastSeen,
      version:String(session.agentVer??'')};
    if(row.online) return row;
    if(!best||row.lastSeen>best.lastSeen) best=row;
  }
  return best;
}

/** Wrapped by the same router/operation registry as MCP; no privileged second execution path. */
export function deviceRoutes({req,url,send}:RouteContext):Route[]{
  const online=()=>!!localObserver&&[...sessions.values()].some(s=>
    s.online&&s.package===localObserver.package);
  return [{path:'/api/devices',handler:async()=>{
  if(localObserver && req.method==='GET' && url.searchParams.get('action')==='list'){
    // This is one exact local USB device, not a paired Device identity or a proxy for the App session.
    let transports:{serial:string;model:string;state:string;link:string;observed:boolean;rpc:boolean;
      net:boolean;agent:{online:boolean;pid:number;sessionId:string;lastSeen:number;version:string}|null}[]=[];
    // One `adb devices -l` per request: the panel polls this every few seconds and each extra
    // spawn queues behind the serialized adb server — the double read used to disagree with
    // itself under contention (transports empty while localUsb said online, or vice versa).
    let devs='';
    if(!localObserver.fileBrowserOnly&&!localObserver.demoApiSerial){
      try{ devs=await realAdbRunner(['devices','-l'],{timeout:2200}); }
      catch(e){ return send(502,{ok:false,error:(e as Error).message}); }
      transports=parseAdbDevices(devs)
        .map(row=>({serial:row.serial,model:row.model||'',state:row.state,link:row.link,
          observed:row.serial===localObserver.usbSerial,rpc:deviceRpcLive(row.serial),
          net:row.link==='adb-tcp'||row.serial.includes(':'),
          agent:row.serial===localObserver.usbSerial?observedAgentView():null}));
    }
    const run:AdbRunner=devs?(args,opts)=>args.join(' ')==='devices -l'?Promise.resolve(devs):realAdbRunner(args,opts):realAdbRunner;
    return send(200,{ok:true,devices:[],transports,localUsb:await localUsbView(localObserver,online(),run)});
  }
  // Panel device management on the local USB entry: connect/disconnect the RPC
  // channel, or move the observation binding to another USB device+app.
  if(localObserver&&req.method==='POST'){
    if(req.headers.origin!=='http://'+localObserverHost)
      return send(403,{ok:false,error:'只能从本机面板管理设备。'});
    let body:any;
    try{body=JSON.parse(await readBody(req)||'{}');}catch{return send(400,{ok:false,error:'缺少有效的请求。'});}
    const action=String(body?.action||'');
    const serial=String(body?.serial||'');
    try{
      if(action==='connect'){
        const c=await connectDevice(serial);
        return send(200,{ok:true,serial,deviceId:c.peer.deviceId});
      }
      if(action==='disconnect'){
        const dropped=await dropDevice(serial);
        return send(200,{ok:true,serial,dropped});
      }
      // 重连：ADB 链路 → reverse 隧道 → 设备域通道 → （观察设备）强制 agent 重拨。
      // 三层结果各自返回，面板据此说清楚是哪一层没通。
      if(action==='reconnect'){
        const result=await reconnectDevice(serial);
        return send(result.ok?200:502,result);
      }
      // 无线调试添加：校验 host:port 后 adb connect，并回读这台设备的真实状态。
      if(action==='adb-connect'){
        const result=await connectNetDevice(String(body?.address||''));
        return send(result.ok?200:502,result);
      }
      if(action==='observe'){
        const pkg=String(body?.package||'');
        const next=await retargetObserver(serial,pkg);
        // Agent sessions belong to the previous device; sever them so a
        // same-named package on the old phone cannot keep feeding the panel.
        for(const sock of agentSockets.values()) sock.destroy();
        agentSockets.clear();
        for(const s of sessions.values()) s.online=false;
        return send(200,{ok:true,serial,package:next.package,pid:next.pid,model:next.model,
          localUsb:await localUsbView(next,false)});
      }
      return send(400,{ok:false,error:'未知的设备操作'});
    }catch(error){
      const code=(error as any)?.code;
      return send(502,{ok:false,error:(error as Error).message,...(code?{code}:{})});
    }
  }
  const args=req.method==='GET'?Object.fromEntries(url.searchParams):JSON.parse(await readBody(req)||'{}');
  const result=await deviceAction(args);return send(result.ok===false?400:200,result);
  }},{path:OWN_DEMO_API_ROUTE,handler:async()=>{
    const target=localObserver?demoApiRequest(localObserver,req.method,url):null;
    if(!localObserver||!target) return send(403,{ok:false,error:'此入口未启用 Demo 的 API 采集。'});
    const write=req.method==='POST';
    if(write&&(req.headers.origin!=='http://'+localObserverHost||
       !/^application\/json(?:\s*;|$)/i.test(String(req.headers['content-type']??'')))) {
      return send(403,{ok:false,error:'只能从本机面板修改 Demo 的 API 采集设置。'});
    }
    let body:unknown;
    if(write){
      const text=await readBody(req,2048);
      try{ body=JSON.parse(text); }catch{ return send(400,{ok:false,error:'缺少有效的 API 设置。'}); }
    }
    try { return send(200,await changeDemoApi(localObserver,body,target.package)); }
    catch(error){
      if(error instanceof DemoApiError) return send(error.status,{ok:false,error:error.message});
      return send(503,{ok:false,error:'暂时无法联系手机上的 Demo。'});
    }
  }},{path:OWN_APP_FILES_ROUTE,handler:async()=>{
    if(!localObserver?.ownFilesSerial) return send(403,{ok:false,error:'此入口未启用调试 APP 的目录。'});
    const onlyFiles=localObserver.fileBrowserOnly===true;
    const independent=hasIndependentDemoFiles(localObserver);
    if(independent&&await localUsbLink(localObserver.usbSerial)!=='online') return send(503,{ok:false,error:'电脑现在连不上这台 USB 手机。'});
    if(!onlyFiles&&!independent&&!online()) return send(409,{ok:false,error:'还没有连上这个 APP。'});
    const root=url.searchParams.get('root')??(onlyFiles?'app':'files');
    const relative=url.searchParams.get('path')??'';
    if(req.method==='POST'){
      if(!onlyFiles||url.searchParams.get('action')!=='save'||req.headers.origin!=='http://'+localObserverHost||
         typeof req.headers['content-type']!=='string'||!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'])){
        return send(403,{ok:false,error:'保存请求不属于本机授权的文件页面。'});
      }
    }
    const body=req.method==='POST'?JSON.parse(await readBody(req,128*1024)):undefined;
    try{
      const result=req.method==='POST'?await saveOwnedAppText(localObserver,root,relative,body):
        await readOwnedAppFiles(localObserver,url.searchParams.get('action')||'',relative,root);
      if(!onlyFiles&&!independent&&!online()) return send(409,{ok:false,error:'当前 APP 会话已断开。'});
      return send(200,result);
    }catch(e){
      if(e instanceof AppFilesError) return send(e.status,{ok:false,error:e.message});
      return send(503,{ok:false,error:'文件操作失败。'});
    }
  }}];
}
