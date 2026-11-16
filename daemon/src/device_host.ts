import {join} from 'node:path';
import {DATA_DIR} from './state.ts';
import {Devices} from './devices.ts';
import {getOperations} from './operation_host.ts';
import {deviceFail} from './device_protocol.ts';

let devices:Devices|undefined;
export function getDevices(){return devices??=new Devices(join(DATA_DIR,'devices.json'),undefined,id=>getOperations().invalidateResource('device:'+id));}
export function setDevicesForTests(value:Devices){if(process.env.ADH_SKIP_ARTIFACT_LOAD!=='1')throw Error('test device adapter is unavailable outside isolated tests');devices=value;}
export async function deviceAction(a:any){
  const service=getDevices();
  switch(a.action||'list'){
    case 'list':return {ok:true,...service.list()};
    case 'discover':return {ok:true,...await service.discover(a.transport)};
    case 'connect':{
      if(a.transport==='lan')return service.connectLan(a.deviceId,a.address,a.port);
      if(a.transport&&a.transport!=='adb')return deviceFail('UNSUPPORTED_TRANSPORT','only adb and paired LAN are implemented');
      return service.connect(String(a.serial||''),a.transportId,a.expectedDeviceId,a.usbMode);
    }
    case 'pair':return service.pair(a);
    case 'reconcile':{
      const engine=getOperations(),ids=a.operationIds;
      if(!Array.isArray(ids)||ids.length<1||ids.length>100)return deviceFail('INVALID_ARGUMENT','select 1..100 Host device mutation ids');
      for(const id of ids){const op=engine.getOperation(id);if(op.resource!=='device:'+a.deviceId||!['devices','hook_plans'].includes(op.name)||op.mode!=='write'||op.connectionOnly)return deviceFail('TARGET_CHANGED','operation belongs to another device or is not a device mutation');}
      const result=await service.reconcile(a.deviceId,ids,a.connectionId);
      const rows=result.result?.operations;
      if(!Array.isArray(rows)||rows.length!==ids.length||new Set(rows.map((r:any)=>r.operationId)).size!==ids.length||rows.some((r:any)=>!ids.includes(r.operationId)))return deviceFail('RECONCILIATION_INVALID','device did not return the exact requested operation set; no evidence attached');
      const reconciled=rows.map((evidence:any)=>{
        const op=engine.recordDeviceReconciliation(evidence.operationId,a.deviceId,{...evidence,observedOn:{bootId:result.bootId,connectionId:result.connectionId},notFoundDoesNotProveUnsent:true,replayed:false});
        return {operationId:op.id,hostState:op.state,deviceEvidence:evidence};
      });
      return {ok:true,deviceId:a.deviceId,reconciled,replayed:false,hostStateUnchanged:true};
    }
    case 'disconnect':return service.disconnect(a.deviceId,a.connectionId);
    case 'info':return service.call({...a,method:'device.info'});
    case 'capabilities':return service.call({...a,method:'device.capabilities'});
    case 'call':return service.call(a);
    default:return deviceFail('INVALID_ACTION','unknown device action');
  }
}
