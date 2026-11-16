import tls from 'node:tls';
import {isIP} from 'node:net';
import {randomBytes,randomUUID,createHash,sign,X509Certificate} from 'node:crypto';
import {DEVICE_PROTOCOL,DeviceRpcClient,verifyHello,deviceFail,DeviceError,type DevicePeer} from '../device_protocol.ts';
import type {ClientIdentity} from '../device_client_identity.ts';
import type {DeviceConnection} from './device_transport.ts';
import {checkpoint} from '../execution_context.ts';

export interface LanEnrollment {grantId:string;clientId:string;permissions:string[]}
export class LanDeviceTransport {
  async connect(peer:DevicePeer,enrollment:LanEnrollment,identity:ClientIdentity,address:string,port:number):Promise<DeviceConnection>{
    if(!isIP(address)||!Number.isInteger(port)||port<1||port>65535)deviceFail('INVALID_ARGUMENT','select an explicit numeric LAN address and port');
    if(enrollment.clientId!==identity.clientId)deviceFail('CLIENT_IDENTITY_MISMATCH','pairing belongs to another Host key');
    checkpoint();
    const stream=await new Promise<tls.TLSSocket>((resolve,reject)=>{
      // Private self-signed installation PKI: TLS proof + mandatory SPKI pin replace public CA/hostname trust.
      // Absolutely no RPC/client proof is sent until this pin check has succeeded.
      const socket=tls.connect({host:address,port,minVersion:'TLSv1.2',rejectUnauthorized:false});
      const timer=setTimeout(()=>{socket.destroy();reject(new DeviceError('TLS_TIMEOUT','TLS connection deadline expired'));},5000);
      socket.once('error',()=>{clearTimeout(timer);reject(new DeviceError('TLS_FAILED','TLS transport could not be established'));});
      socket.once('secureConnect',()=>{
        clearTimeout(timer);
        try{
          const raw=socket.getPeerCertificate().raw;if(!raw||raw.length>16384)throw Error();const cert=new X509Certificate(raw);
          const der=cert.publicKey.export({type:'spki',format:'der'}) as Buffer;
          if(createHash('sha256').update(der).digest('hex')!==peer.identityFingerprint||!cert.verify(cert.publicKey)||Date.now()<Date.parse(cert.validFrom)||Date.now()>Date.parse(cert.validTo))throw Error();
          resolve(socket);
        }catch{socket.destroy();reject(new DeviceError('TLS_IDENTITY_MISMATCH','TLS certificate does not match the paired installation key or validity'));}
      });
    });
    const rpc=new DeviceRpcClient(stream);
    try{
      checkpoint();const challenge=await rpc.request('device.challenge',{},undefined,undefined,5000);
      if(challenge.deviceId!==peer.deviceId||!/^[a-f0-9]{64}$/.test(challenge.challenge))deviceFail('IDENTITY_UNVERIFIED','TLS challenge does not match selected device');
      const id=randomUUID(),nonce=randomBytes(32).toString('hex');
      const message=JSON.stringify([DEVICE_PROTOCOL,'lan-auth/1',challenge.deviceId,challenge.bootId,challenge.daemonInstanceId,challenge.challenge,nonce,id,identity.clientId,enrollment.grantId]);
      const signature=sign('sha256',Buffer.from(message),identity.privateKey).toString('base64');
      const reply=await rpc.request('device.hello',{clientNonce:nonce,authentication:{type:'client-signature',clientId:identity.clientId,grantId:enrollment.grantId,signature}},undefined,undefined,5000,id);
      const verified=verifyHello(reply,{schemaVersion:1,deviceId:peer.deviceId,identityFingerprint:peer.identityFingerprint,token:''},id,nonce);
      return {id:randomUUID(),transport:'lan',address,port,peer:verified,rpc,tlsVersion:stream.getProtocol()||undefined,clientId:identity.clientId,grantId:enrollment.grantId,close:async()=>{rpc.close();return {removed:false,confirmed:true};}};
    }catch(error){rpc.close();throw error;}
  }
}
