import net from 'node:net';
import {randomUUID} from 'node:crypto';
import {realAdbRunner,parseAdbDevices,type AdbRunner,type AdbDevice} from './transport/adb_device.ts';
import {parseProcStat,normalizeStarttimeTicks} from './proc_identity.ts';
import {AgentScopeError,freezeDeviceBinding,independentDeviceScope,registerAgentRouteValidator,validDeviceSerial,validPackage,type AgentDeviceBinding} from './agent_scope.ts';

export interface AgentHello {t?:string;package?:string;process?:string;pid?:number;uid?:number;starttimeTicks?:string}
export interface UsbAgentLease {
  readonly id:string;readonly serial:string;readonly transportId:string;readonly deviceAgentPort:number;
  readonly hostAgentPort:number;readonly bootId:string;
  readonly linkEvidence?:'usb-devpath'|'windows-adb-roster';
  attest(hello:AgentHello):Promise<Readonly<AgentDeviceBinding>>;
}
type OwnedLease=UsbAgentLease&{server:net.Server;sockets:Set<net.Socket>;removeValidator:()=>void;previousRemote?:number};
type RouteOptions={deviceAgentPort:number;legacyHostPort:number;
  onConnection:(socket:net.Socket,lease:UsbAgentLease)=>void;run?:AdbRunner;allowPackage?:(serial:string,pkg:string)=>boolean;ownsLegacyListener?:()=>boolean};
const quote=(s:string)=>"'"+s.replaceAll("'","'\\''")+"'";
function fail(code:string,message:string):never{throw new AgentScopeError(code,message);}
const remoteFor=(raw:string,port:number)=>raw.split(/\r?\n/).filter(Boolean).flatMap(line=>{
  const m=/\btcp:(\d+)\s+tcp:(\d+)\s*$/.exec(line);return m&&Number(m[1])===port?[Number(m[2])]:[];
});
export class UsbAgentRoutes {
  private leases=new Map<string,OwnedLease>();private jobs=new Map<string,Promise<UsbAgentLease>>();
  private known=new Set<string>();private nextRoster:AdbDevice[]|undefined;
  private reconcileJob:Promise<{serial:string;action:string;error?:string}[]>|undefined;
  private readonly options:RouteOptions;
  constructor(options:RouteOptions){
    this.options=options;
    for(const p of [options.deviceAgentPort,options.legacyHostPort])if(!Number.isInteger(p)||p<1||p>65535)fail('INVALID_PORT','无效的 Agent 端口');
  }
  private run(args:string[],timeout=8000){return (this.options.run??realAdbRunner)(args,{timeout,maxBuffer:1024*1024});}
  private async roster(){return parseAdbDevices(await this.run(['devices','-l']));}
  private async select(serial:string,transportId?:string):Promise<AdbDevice&{transportId:string}>{
    if(!validDeviceSerial(serial))fail('INVALID_DEVICE_SCOPE','无效的设备串号');
    const rows=(await this.roster()).filter(d=>d.serial===serial&&d.state==='device'&&(!transportId||d.transportId===transportId));
    if(rows.length!==1||!rows[0].transportId)fail('DEVICE_ROUTE_STALE','需要唯一在线的设备传输');
    const row=rows[0] as AdbDevice&{transportId:string};
    if((await this.run(['-t',row.transportId,'get-serialno'])).trim()!==serial)fail('DEVICE_ROUTE_STALE','ADB 传输的设备已改变');
    const devpath=(await this.run(['-t',row.transportId,'get-devpath'])).trim();
    if(!devpath.startsWith('usb:')&&!(process.platform==='win32'&&devpath==='unknown'&&row.link==='usb'&&!serial.includes(':')&&!serial.includes('._tcp')&&!/^emulator-/i.test(serial)))
      fail('USB_ROUTE_REQUIRED','此 Agent 绑定只接受明确的 USB 传输；无线会话不可冒充 USB 认证');
    return row;
  }
  private async boot(transport:string){
    const id=(await this.run(['-t',transport,'exec-out','su','-c',quote('cat /proc/sys/kernel/random/boot_id')])).trim();
    if(!/^[a-f0-9-]{36}$/i.test(id))fail('PROCESS_PROOF_UNAVAILABLE','无法读取设备启动身份');return id;
  }
  private async checkRoute(lease:UsbAgentLease){
    await this.select(lease.serial,lease.transportId);
    const mapping=remoteFor(await this.run(['-t',lease.transportId,'reverse','--list']),lease.deviceAgentPort);
    if(mapping.length!==1||mapping[0]!==lease.hostAgentPort)fail('DEVICE_ROUTE_CHANGED','USB 路由已改变，未发送目标命令');
    // A second phone routed into this listener would defeat source attribution. Never
    // infer its identity from package/PID coincidence or from a globally selected phone.
    for(let pass=0;pass<2;pass++){
      let changed=false;
      for(const other of await this.roster())if(other.state==='device'&&other.serial!==lease.serial&&other.transportId){
        let rows:string;
        try{rows=await this.run(['-t',other.transportId,'reverse','--list']);}
        catch(error){
          // Another phone may disappear between discovery and probing. Re-check the
          // roster, not the error text; a still-present or aliased peer stays fail-closed.
          const live=await this.roster();
          if(live.some(d=>d.serial===other.serial&&d.transportId===other.transportId&&d.state==='device'))throw error;
          changed=true;break;
        }
        if(rows.split(/\r?\n/).some(line=>new RegExp(`\\btcp:\\d+\\s+tcp:${lease.hostAgentPort}\\s*$`).test(line)))
          fail('DEVICE_ROUTE_ALIASED','其他设备也映射到此监听端口，不能证明会话归属');
      }
      if(!changed)return;
    }
    fail('DEVICE_ROSTER_UNSTABLE','设备连接持续变化，请稍后重试；未发送目标命令');
  }
  private async prove(lease:UsbAgentLease,hello:AgentHello,checkPackage:boolean):Promise<Readonly<AgentDeviceBinding>>{
    const pkg=hello.package??'',name=hello.process??pkg,pid=hello.pid,uid=hello.uid,start=normalizeStarttimeTicks(hello.starttimeTicks);
    if(hello.t!=='hello'||!validPackage(pkg)||!/^[A-Za-z0-9_.:]{1,256}$/.test(name)||typeof pid!=='number'||!Number.isSafeInteger(pid)||pid<=0||
       typeof uid!=='number'||!Number.isSafeInteger(uid)||uid<0||!start)fail('INVALID_AGENT_IDENTITY','Agent 缺少精确的进程身份');
    if(this.options.allowPackage&&!this.options.allowPackage(lease.serial,pkg))fail('PACKAGE_NOT_SELECTED','此 USB 入口尚未选择这个应用');
    await this.checkRoute(lease);
    const script=[
      "printf '__BOOT__\\n'; cat /proc/sys/kernel/random/boot_id",
      `printf '__STAT1__\\n'; base64 /proc/${pid}/stat`,
      `printf '__UID__\\n'; stat -c %u /proc/${pid}`,
      `printf '__CMD__\\n'; base64 /proc/${pid}/cmdline`,
      ...(checkPackage?[`printf '__PKG__\\n'; cmd package list packages -U --user ${Math.floor(uid!/100000)} ${pkg}`]:[]),
      `printf '__STAT2__\\n'; base64 /proc/${pid}/stat`,"printf '__END__\\n'",
    ].join('; ');
    const text=await this.run(['-t',lease.transportId,'exec-out','su','-c',quote(script)]);
    const part=(key:string)=>{const m=new RegExp(`(?:^|\\n)__${key}__\\r?\\n([\\s\\S]*?)(?=__[A-Z0-9]+__\\r?\\n)`).exec(text);return m?.[1].trim()??'';};
    const decode=(key:string)=>{const s=part(key);if(!s||!/^[A-Za-z0-9+/=\r\n]+$/.test(s))fail('PROCESS_PROOF_UNAVAILABLE','进程身份读取失败');return Buffer.from(s,'base64').toString('utf8');};
    const first=parseProcStat(decode('STAT1')),last=parseProcStat(decode('STAT2'));
    if(part('BOOT')!==lease.bootId||first?.pid!==pid||last?.pid!==pid||first.starttime!==start||last.starttime!==start||
       part('UID')!==String(uid)||decode('CMD').split('\0')[0]!==name)fail('PROCESS_GENERATION_CHANGED','手机进程已改变，未发送目标命令');
    if(checkPackage&&!part('PKG').split(/\r?\n/).some(line=>line.trim()===`package:${pkg} uid:${uid}`))
      fail('PACKAGE_UID_MISMATCH','安装包 UID 与 Agent 进程不一致');
    return freezeDeviceBinding({kind:'usb-route',package:pkg,serial:lease.serial,transportId:lease.transportId,leaseId:lease.id,
      bootId:lease.bootId,deviceAgentPort:lease.deviceAgentPort,hostAgentPort:lease.hostAgentPort,verifiedAt:Date.now(),
      assurance:'explicit-usb-route',linkEvidence:lease.linkEvidence,process:{pid:pid!,uid:uid!,starttimeTicks:start,name}});
  }
  ensure(serial:string):Promise<UsbAgentLease>{
    if(!validDeviceSerial(serial))fail('INVALID_DEVICE_SCOPE','无效的设备串号');this.known.add(serial);
    let job=this.jobs.get(serial);if(!job){job=this.open(serial).finally(()=>this.jobs.delete(serial));this.jobs.set(serial,job);}return job;
  }
  private async open(serial:string):Promise<UsbAgentLease>{
    const existing=this.leases.get(serial);if(existing){try{await this.checkRoute(existing);return existing;}catch{await this.close(serial,false);}}
    const row=await this.select(serial),bootId=await this.boot(row.transportId);
    const old=remoteFor(await this.run(['-t',row.transportId,'reverse','--list']),this.options.deviceAgentPort);
    if(old.length>1||old.length===1&&(old[0]!==this.options.legacyHostPort||!this.options.ownsLegacyListener?.()))fail('DEVICE_ROUTE_OCCUPIED','现有 USB 路由属于其他入口，未覆盖');
    const sockets=new Set<net.Socket>();let lease:OwnedLease|undefined;
    const server=net.createServer(sock=>{if(!lease){sock.destroy();return;}sockets.add(sock);sock.once('close',()=>sockets.delete(sock));independentDeviceScope({serial:lease.serial},()=>this.options.onConnection(sock,lease!));});
    await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.off('error',reject);resolve();});});
    const hostPort=(server.address() as net.AddressInfo).port;
    const id=randomUUID();
    const devpath=(await this.run(['-t',row.transportId,'get-devpath'])).trim();
    lease={id,serial,transportId:row.transportId,deviceAgentPort:this.options.deviceAgentPort,hostAgentPort:hostPort,bootId,linkEvidence:devpath.startsWith('usb:')?'usb-devpath':'windows-adb-roster',server,sockets,previousRemote:old[0],
      attest:hello=>this.prove(lease!,hello,true),removeValidator:()=>{}};
    lease.removeValidator=registerAgentRouteValidator(id,async binding=>{
      if(this.leases.get(serial)!==lease)fail('DEVICE_ROUTE_EXPIRED','设备路由已关闭');
      await this.prove(lease!,{t:'hello',package:binding.package,process:binding.process.name,pid:binding.process.pid,uid:binding.process.uid,starttimeTicks:binding.process.starttimeTicks},false);
    });
    this.leases.set(serial,lease);
    try{
      // The listener and its registry exist before publication. Do not race a blind rebind:
      // re-read the old mapping immediately before publishing the owned replacement.
      await this.select(serial,row.transportId);
      const current=remoteFor(await this.run(['-t',row.transportId,'reverse','--list']),lease.deviceAgentPort);
      if(JSON.stringify(current)!==JSON.stringify(old))fail('DEVICE_ROUTE_CHANGED','USB 路由在建立期间改变');
      await this.run(['-t',row.transportId,'reverse',...(old.length?[]:['--no-rebind']),`tcp:${lease.deviceAgentPort}`,`tcp:${hostPort}`]);
      await this.checkRoute(lease);return lease;
    }catch(e){await this.close(serial,false);throw e;}
  }
  /** Reconcile only previously selected devices; never auto-enroll a newly plugged phone. */
  reconcileKnown(rows:AdbDevice[]):Promise<{serial:string;action:string;error?:string}[]>{
    this.nextRoster=rows.map(row=>({...row}));
    if(!this.reconcileJob)this.reconcileJob=this.reconcileLoop().finally(()=>{this.reconcileJob=undefined;});
    return this.reconcileJob;
  }
  private async reconcileLoop(){
    const results:{serial:string;action:string;error?:string}[]=[];
    while(this.nextRoster){const rows=this.nextRoster;this.nextRoster=undefined;
      for(const serial of [...this.known]){
        const online=rows.filter(r=>r.serial===serial&&r.state==='device'),lease=this.leases.get(serial);
        try{
          if(online.length!==1){if(lease){await this.close(serial,false);results.push({serial,action:'offline'});}continue;}
          if(lease&&online[0].transportId&&lease.transportId===online[0].transportId)continue;
          await this.ensure(serial);results.push({serial,action:'reconnected'});
        }catch(error){results.push({serial,action:'failed',error:(error as Error).message});}
      }
    }return results;
  }
  get(serial:string):UsbAgentLease|undefined{return this.leases.get(serial);}
  list():UsbAgentLease[]{return [...this.leases.values()];}
  async close(serial:string,forget=true):Promise<{removed:boolean;restoredPrevious:boolean;conflict:boolean}>{
    if(forget)this.known.delete(serial);
    const lease=this.leases.get(serial);if(!lease)return {removed:false,restoredPrevious:false,conflict:false};
    this.leases.delete(serial);lease.removeValidator();for(const sock of lease.sockets)sock.destroy();
    await new Promise<void>(resolve=>lease.server.close(()=>resolve()));
    try{
      const currentDevice=await this.select(serial);
      if(await this.boot(currentDevice.transportId)!==lease.bootId)return {removed:false,restoredPrevious:false,conflict:true};
      const prefix=['-t',currentDevice.transportId];
      const current=remoteFor(await this.run([...prefix,'reverse','--list']),lease.deviceAgentPort);
      if(current.length!==1||current[0]!==lease.hostAgentPort)return {removed:false,restoredPrevious:false,conflict:true};
      if(lease.previousRemote!==undefined){await this.run([...prefix,'reverse',`tcp:${lease.deviceAgentPort}`,`tcp:${lease.previousRemote}`]);return {removed:true,restoredPrevious:true,conflict:false};}
      await this.run([...prefix,'reverse','--remove',`tcp:${lease.deviceAgentPort}`]);return {removed:true,restoredPrevious:false,conflict:false};
    }catch{return {removed:false,restoredPrevious:false,conflict:true};}
  }
  async closeAll(){return Promise.all([...this.leases.keys()].map(serial=>this.close(serial)));}
}
let active:UsbAgentRoutes|undefined;
export const setUsbAgentRoutes=(routes:UsbAgentRoutes)=>{if(active&&active!==routes)throw Error('Agent route controller already initialized');active=routes;};
export const usbAgentRoutes=()=>active;
