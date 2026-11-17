import type {DevicePeer,DeviceRpcClient} from '../device_protocol.ts';
/** Business logic consumes an authenticated stream, not ADB or TLS implementation details. */
export interface DeviceConnection {
  id:string;transport:'adb'|'lan';serial?:string;transportId?:string;address?:string;port:number;
  peer:DevicePeer;rpc:DeviceRpcClient;clientId?:string;grantId?:string;
  tlsVersion?:string;
  usbMode?:'forward'|'stdio';
  close():Promise<{removed:boolean;confirmed:boolean;reason?:string}>;
}
