import { randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { IncomingHttpHeaders } from 'node:http';
import { atomicWriteJson } from './storage.ts';
import { OperationError } from './execution_context.ts';
import type { Principal } from './operations.ts';

export function initializeOperatorAccess(root: string): string {
  if (process.env.ADH_OPERATOR_TOKEN) return process.env.ADH_OPERATOR_TOKEN;
  const file=join(root,'operator-access.json');
  if (!existsSync(file)) atomicWriteJson(file,{ schemaVersion:1, operatorKey:randomBytes(32).toString('hex') });
  const value=JSON.parse(readFileSync(file,'utf8'));
  if(value.schemaVersion!==1 || typeof value.operatorKey!=='string' || value.operatorKey.length<32)throw Error('invalid operator access file; refusing to replace it');
  return value.operatorKey;
}
export function requestPrincipal(headers: IncomingHttpHeaders, source: string, root: string): Principal {
  const value=headers['x-adh-operator-key'];
  if(value!==undefined) {
    if(typeof value!=='string')throw new OperationError('AUTH_FAILED','invalid operator credential');
    const expected=Buffer.from(initializeOperatorAccess(root)), actual=Buffer.from(value);
    if(actual.length!==expected.length || !timingSafeEqual(actual,expected))throw new OperationError('AUTH_FAILED','invalid operator credential');
    return {role:'operator',id:'operator',source};
  }
  const client=headers['x-adh-client-id'];
  return {role:'ai',id:typeof client==='string' && /^[\w-]{1,80}$/.test(client)?client:'legacy',source};
}
