import type {Cap,Session} from './api';
/** No overload inference from bytes, operation name, or historical process IDs. */
export function captureHookMethod(c:Cap,methods:any[]):any|null {
 if(!c.deviceBinding?.serial||!c.package)return null;
 const found=methods.filter(m=>c.source==='native'?m.backend==='native'&&m.symbol===c.func&&m.id==='native.'+c.func:
  c.source==='java'&&c.javaTargetTruncated===false&&typeof c.captureMethodId==='string'&&m.backend==='java'&&m.id===c.captureMethodId&&c.javaTarget===`${m.class}.${m.method}(${m.params??''})`);
 return found.length===1?found[0]:null;
}
/** A historical record defaults to offline config unless its full immutable process proof survives. */
export function captureHookSession(c:Cap,sessions:Session[]):string {
 const b=c.deviceBinding,s=sessions.find(s=>s.sessionId===c.sessionId),p=s?.deviceBinding?.process;
 return b&&!!b.leaseId&&!!b.transportId&&s?.deviceBinding?.leaseId===b.leaseId&&s.deviceBinding.transportId===b.transportId&&s?.online&&s.package===c.package&&s.deviceBinding?.serial===b.serial&&p&&p.pid===b.process.pid&&p.uid===b.process.uid&&p.starttimeTicks===b.process.starttimeTicks?s.sessionId:'';
}
