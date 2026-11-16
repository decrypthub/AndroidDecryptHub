import {existsSync,readFileSync,linkSync,unlinkSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {createHash,createPublicKey,createPrivateKey,generateKeyPairSync,sign,verify} from 'node:crypto';
import {atomicWriteJson} from './storage.ts';
import {deviceFail} from './device_protocol.ts';

export interface ClientIdentity {schemaVersion:1;clientId:string;publicKey:string;privateKey:string}
/** One explicit Host client key. Never stored in a task, device cache, response or tool arguments. */
export class DeviceClientIdentity {
  readonly file:string;
  constructor(file:string){this.file=file;}
  read():ClientIdentity {
    try{
      const raw=readFileSync(this.file);if(raw.length>16384)throw Error();const value=JSON.parse(raw.toString()) as ClientIdentity;
      const key=createPrivateKey(value.privateKey),publicKey=createPublicKey(key).export({type:'spki',format:'der'}) as Buffer;
      if(value.schemaVersion!==1||publicKey.toString('base64')!==value.publicKey||createHash('sha256').update(publicKey).digest('hex')!==value.clientId)throw Error();
      const parsed=createPublicKey({key:Buffer.from(value.publicKey,'base64'),format:'der',type:'spki'});
      if(parsed.asymmetricKeyType!=='rsa'||(parsed.asymmetricKeyDetails?.modulusLength||0)<2048||!verify('sha256',Buffer.from('client-key-check'),parsed,sign('sha256',Buffer.from('client-key-check'),key)))throw Error();return value;
    }catch{deviceFail('CLIENT_IDENTITY_UNAVAILABLE','Host client key is absent or invalid; pair through trusted USB, never regenerate an existing identity automatically');}
  }
  ensure():ClientIdentity {
    if(!existsSync(this.file)){
      const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});const der=publicKey.export({type:'spki',format:'der'}) as Buffer;
      const temporary=this.file+'.'+randomUUID()+'.new';
      try{
        atomicWriteJson(temporary,{schemaVersion:1,clientId:createHash('sha256').update(der).digest('hex'),publicKey:der.toString('base64'),privateKey:privateKey.export({type:'pkcs8',format:'pem'})});
        try{linkSync(temporary,this.file);}catch(error){if((error as any).code!=='EEXIST')throw error;}
      }finally{try{unlinkSync(temporary);}catch{}}
    }
    return this.read();
  }
}
