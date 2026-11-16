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
    case 'discover':return {ok:true,...await service.discover()};
    case 'connect':return service.connect(String(a.serial||''),a.transportId,a.expectedDeviceId);
    case 'disconnect':return service.disconnect(a.deviceId,a.connectionId);
    case 'info':return service.call({...a,method:'device.info'});
    case 'capabilities':return service.call({...a,method:'device.capabilities'});
    case 'call':return service.call(a);
    default:return deviceFail('INVALID_ACTION','unknown device action');
  }
}
