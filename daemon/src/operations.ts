import { createHash, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { atomicWriteJson } from './storage.ts';
import { executionContext, OperationError, type ExecutionContext } from './execution_context.ts';
import { freshControl, TaskStore, type Control, type Ledger, type Operation, type Role, type Task } from './task_store.ts';
import type { OperationSpec } from './operation_registry.ts';

export interface Principal { role: Role; id: string; source: string }
export interface OperationMeta {
  expectedRevision?: number; controlEpoch?: number; hostEpoch?: number;
  idempotencyKey?: string; taskId?: string; timeoutMs?: number;
  expectedTaskRevision?: number;
}
const terminal = new Set(['succeeded','failed','cancelled','unknown']);
function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value) ?? 'null';
}
const fail = (code: string, message: string): never => { throw new OperationError(code, message); };
function touchTask(task: Task) { task.revision=(task.revision ?? 0)+1;task.updatedAt=Date.now(); }
function validResource(resource: string) {
  if(resource!=='host' && !/^target:[\w:.-]{1,400}$/.test(resource) && !/^device:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(resource))fail('INVALID_RESOURCE','invalid control resource');
}
function resourcesConflict(a:string,b:string){return a==='host'||b==='host'||a===b||a.startsWith('device:')&&b.startsWith('target:')||b.startsWith('device:')&&a.startsWith('target:');}
function crossHeld(data:Ledger,resource:string){return Object.entries(data.controls).some(([key,c])=>(c.owner==='operator'||c.paused)&&(resource.startsWith('device:')&&key.startsWith('target:')||resource.startsWith('target:')&&key.startsWith('device:')));}
export function operationFailure(error: unknown) {
  return { ok: false, code: (error as any)?.code || 'OPERATION_FAILED', error: (error as Error)?.message || String(error) };
}

/** Shared Host execution coordinator. Constructors are explicit; importing it performs no I/O. */
export class Operations {
  readonly host = randomUUID();
  readonly store: TaskStore;
  private queue: { id: string; fn: () => Promise<any> }[] = [];
  private running = new Set<string>();
  private waiters = new Map<string, (value: any) => void>();
  private completions = new Map<string, Promise<any>>();
  private poll?: ReturnType<typeof setInterval>;
  private closed = false;
  private targetResource: (session: string) => string;

  constructor(root: string, targetResource: (session: string) => string = session => `target:${session}`) {
    this.targetResource=targetResource;
    this.store = new TaskStore(root);
    this.store.update(data => {
      const dead = (id: string) => {
        const owner = data.hosts[id];
        if (!owner || !owner.active) return true;
        if (owner.hostname !== hostname()) return false; // never guess another host is dead
        try { process.kill(owner.pid, 0); return false; } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') return false;
          owner.active=false; return true;
        }
      };
      for (const op of Object.values(data.operations)) {
        if (terminal.has(op.state) || !dead(op.host)) continue;
        op.state = op.state === 'queued' ? 'cancelled' : 'unknown';
        op.error = { code: 'HOST_RESTARTED', message: 'Host stopped; execution is not replayed' };
        op.updatedAt = Date.now();
        for(const effect of op.effects || [])if(effect.state==='dispatched'){effect.state='unknown';effect.uncertainAt=Date.now();}
        let control = data.controls[op.resource];
        if (control?.active === op.id) delete control.active;
        if (op.mode === 'write' && op.state === 'unknown') (control ??= data.controls[op.resource] = freshControl()).uncertain = op.id;
        if (data.tasks[op.taskId]) {data.tasks[op.taskId].state = op.state === 'unknown' ? 'unknown' : 'paused';touchTask(data.tasks[op.taskId]);}
      }
      data.hosts[this.host] = { pid: process.pid, hostname: hostname(), active: true };
    });
  }
  snapshot(resource = 'host') {
    validResource(resource);
    const data = this.store.read(), control = data.controls[resource] ?? freshControl();
    return { resource, ...control, hostEpoch: data.controls.host.epoch };
  }
  resource(spec: OperationSpec) {const resource=spec.deviceId?'device:'+spec.deviceId:spec.global || !spec.session ? 'host' : this.targetResource(spec.session);validResource(resource);return resource;}
  invalidateResource(resource:string){
    validResource(resource);this.store.update(data=>{const c=data.controls[resource]??=freshControl();c.epoch++;c.revision++;
      for(const op of Object.values(data.operations))if(op.resource===resource&&op.state==='queued'){op.state='failed';op.settled=true;op.updatedAt=Date.now();op.error={code:'TARGET_CHANGED',message:'verified device generation changed; old work is not rebound'};data.tasks[op.taskId].state='paused';touchTask(data.tasks[op.taskId]);}
    });this.pump();
  }
  createTask(title: string, principal: Principal, implicit = false): Task {
    return this.store.update(data => {
      const task: Task = { id: randomUUID(), title: String(title || 'analysis').slice(0,256), owner: principal.role,
        state: 'active', createdAt: Date.now(), updatedAt: Date.now(), implicit, revision:0,createdBy:principal.id,source:principal.source };
      data.tasks[task.id] = task; return task;
    });
  }
  private assertVersion(data: Ledger, resource: string, principal: Principal, meta: OperationMeta) {
    const control = data.controls[resource] ?? freshControl(), host = data.controls.host;
    if (![meta.expectedRevision, meta.controlEpoch, meta.hostEpoch].every(n => Number.isSafeInteger(n) && n! >= 0)) {
      fail('CONTROL_REQUIRED', 'read an operations snapshot and send expectedRevision, controlEpoch and hostEpoch');
    }
    if (meta.expectedRevision !== control.revision || meta.controlEpoch !== control.epoch || meta.hostEpoch !== host.epoch) {
      fail('STALE_CONTROL', 'state/control version changed; reload and re-plan, do not retry the old request');
    }
    if (principal.role !== 'operator' && (control.owner === 'operator' || host.owner === 'operator' || control.paused || host.paused)) {
      fail('CONTROL_HELD', 'operator holds control; AI writes remain paused until explicit release');
    }
    if(resource==='host' && principal.role!=='operator' && Object.values(data.controls).some(c=>c.owner==='operator'||c.paused)) {
      fail('CONTROL_HELD','a target is operator-held; Host-wide AI mutations are blocked');
    }
    if(principal.role!=='operator'&&crossHeld(data,resource))fail('CONTROL_HELD','unassociated legacy targets/device control are operator-held; no identity is guessed');
  }
  private take(data: Ledger, resource: string) {
    const control = data.controls[resource] ??= freshControl();
    control.owner = 'operator'; control.epoch++; control.revision++; control.paused = true;
    for (const op of Object.values(data.operations)) {
      if (op.owner !== 'ai' || op.state !== 'queued' || resource !== 'host' && op.resource !== resource) continue;
      op.state = 'failed'; op.error = { code: 'STALE_CONTROL', message: 'operator changed control before dispatch' };
      op.updatedAt = Date.now();op.finishedAt=Date.now();op.settled=true;
      if (data.tasks[op.taskId]) {data.tasks[op.taskId].state = 'paused';touchTask(data.tasks[op.taskId]);}
    }
    return control;
  }
  control(action: string, resource: string, principal: Principal, meta: OperationMeta, acknowledge = false) {
    validResource(resource);
    if (principal.role !== 'operator') fail('OPERATOR_REQUIRED', 'operator credential required for control changes');
    const out = this.store.update(data => {
      this.assertVersion(data, resource, principal, meta);
      let control = data.controls[resource] ??= freshControl();
      if (action === 'takeover' || action === 'pause') control = this.take(data, resource);
      else if (action === 'release') { control.owner = 'ai'; control.paused = false; control.epoch++; control.revision++; }
      else if (action === 'resolve') {
        if (!acknowledge) fail('ACKNOWLEDGEMENT_REQUIRED', 'inspect actual state and acknowledge unknown side effects explicitly');
        if (control.active) fail('OPERATION_RUNNING', 'a Host handler is still running; its later effects cannot be released');
        const uncertain = control.uncertain && data.operations[control.uncertain];
        if (uncertain && !uncertain.settled && data.hosts[uncertain.host]?.active) fail('OPERATION_RUNNING','a timed-out handler is still awaiting target completion');
        delete control.uncertain; control.epoch++; control.revision++;
        if(uncertain)uncertain.resolvedAt=Date.now();
        if(uncertain && data.tasks[uncertain.taskId]?.state==='unknown'){data.tasks[uncertain.taskId].state='paused';touchTask(data.tasks[uncertain.taskId]);}
      } else fail('INVALID_ACTION', 'control action must be takeover|pause|release|resolve');
      return { resource, ...control, hostEpoch: data.controls.host.epoch };
    });
    this.pump(); return out;
  }
  submit(spec: OperationSpec, args: any, principal: Principal, meta: OperationMeta, fn: () => Promise<any>) {
    if (this.closed) fail('HOST_CLOSED', 'operation coordinator is closed');
    const resource = this.resource(spec);
    const businessArgs={...args};delete businessArgs._operation;
    const fingerprint = createHash('sha256').update(canonical({ name: spec.name, resource, args:businessArgs })).digest('hex');
    const key = String(meta.idempotencyKey || randomUUID());
    if (key.length > 128) fail('INVALID_KEY', 'idempotency key too long');
    const operation = this.store.update(data => {
      const existing = Object.values(data.operations).find(op => op.owner === principal.role && op.key === key);
      if (existing) {
        if (existing.fingerprint !== fingerprint) fail('IDEMPOTENCY_CONFLICT', 'same key identifies different arguments/target');
        return existing;
      }
      if (Object.keys(data.operations).length >= 10000) fail('LEDGER_FULL', 'explicit archival required; nothing was executed');
      let expected = { expectedRevision:meta.expectedRevision, controlEpoch:meta.controlEpoch, hostEpoch:meta.hostEpoch };
      if (spec.mode === 'write') {
        this.assertVersion(data, resource, principal, expected);
        const control = data.controls[resource] ??= freshControl();
        if (principal.role === 'operator' && control.owner !== 'operator') {
          this.take(data, resource);
          expected = { ...expected, expectedRevision: control.revision, controlEpoch: control.epoch, hostEpoch: data.controls.host.epoch };
        }
      }
      if(meta.taskId && !Object.hasOwn(data.tasks,meta.taskId))fail('TASK_NOT_FOUND','task does not exist');
      let task = meta.taskId ? data.tasks[meta.taskId] : undefined;
      if (meta.taskId && !task) fail('TASK_NOT_FOUND', 'task does not exist');
      if (task && (task.owner !== principal.role && principal.role !== 'operator' || task.state !== 'active')) fail('TASK_PAUSED', 'task is not active or is owned by the operator');
      if (!task) {
        task = { id: randomUUID(), title: spec.name, owner: principal.role, state: 'active', createdAt: Date.now(), updatedAt: Date.now(), implicit: true,revision:0,createdBy:principal.id,source:principal.source };
        data.tasks[task.id] = task;
      }
      const timeout = meta.timeoutMs ?? 120000;
      if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 600000) fail('INVALID_DEADLINE', 'timeoutMs must be 1..600000');
      const op: Operation = { id: randomUUID(), taskId: task.id, name: spec.name, resource, mode: spec.mode, owner: principal.role,
        actorId: principal.id, source: principal.source, host: this.host, state: 'queued', createdAt: Date.now(), updatedAt: Date.now(),
        deadline: Date.now() + timeout, ...expected, key, fingerprint, mayHaveExecuted: false, inFlight: 0,
        uncertainEffect: false, cancelRequested: false, settled: false,effects:[],effectsDropped:0 };
      data.operations[op.id] = op; return op;
    });
    if (operation.host === this.host && operation.state === 'queued' && !this.completions.has(operation.id)) {
      this.completions.set(operation.id, new Promise(resolve => this.waiters.set(operation.id, resolve)));
      this.queue.push({ id: operation.id, fn });
      queueMicrotask(() => this.pump());
    }
    return operation;
  }
  async execute(spec: OperationSpec, args: any, principal: Principal, meta: OperationMeta, fn: () => Promise<any>) {
    const op = this.submit(spec, args, principal, meta, fn);
    if (!terminal.has(op.state)) await this.completions.get(op.id);
    return this.getOperation(op.id, true);
  }
  getOperation(id: string, includeResult = false) {
    const records=this.store.read().operations;
    const op = Object.hasOwn(records,id)?records[id]:undefined;
    if (!op) fail('OPERATION_NOT_FOUND', 'operation does not exist');
    const out: any = structuredClone(op);
    if (includeResult && op.resultFile) out.result = JSON.parse(readFileSync(op.resultFile, 'utf8'));
    if (includeResult && op.lateResultFile) out.lateResult = JSON.parse(readFileSync(op.lateResultFile, 'utf8'));
    return out;
  }
  findOperation(key: string, principal: Principal, includeResult = false) {
    const op=Object.values(this.store.read().operations).find(op=>op.key===key && op.owner===principal.role);
    if(!op)fail('OPERATION_NOT_FOUND','no operation is recorded for this intent key; pending transport is not proof of non-execution');
    return this.getOperation(op.id,includeResult);
  }
  getTask(id: string) {
    const data=this.store.read(),task=Object.hasOwn(data.tasks,id)?data.tasks[id]:undefined;
    if(!task)fail('TASK_NOT_FOUND','task does not exist');
    const ops=Object.values(data.operations).filter(op=>op.taskId===id),counts:Record<string,number>={};
    for(const op of ops)counts[op.state]=(counts[op.state]||0)+1;
    return {...task,revision:task.revision ?? 0,operationCounts:counts,totalOperations:ops.length,
      resources:[...new Set(ops.map(op=>op.resource))],unresolved:ops.filter(op=>op.state==='unknown'&&!op.resolvedAt).length};
  }
  list(taskId?: string, limit = 50, offset = 0, filters: {q?:string;state?:string;owner?:string} = {}) {
    const data = this.store.read();
    const query=String(filters.q||'').slice(0,256).toLowerCase();
    const tasks=Object.values(data.tasks).filter(t=>(!taskId||t.id===taskId)&&(!query||[t.title,t.id,t.source,t.createdBy].join(' ').toLowerCase().includes(query))&&(!filters.state||t.state===filters.state)&&(!filters.owner||t.owner===filters.owner))
      .sort((a,b) => b.createdAt-a.createdAt || b.id.localeCompare(a.id)).map(t=>({...t,revision:t.revision ?? 0}));
    const selected=new Set(tasks.map(t=>t.id));
    const operations=Object.values(data.operations).filter(op => selected.has(op.taskId)).sort((a,b) => b.createdAt-a.createdAt || b.id.localeCompare(a.id));
    return {tasks:tasks.slice(offset,offset+limit),operations:operations.slice(offset,offset+limit),totalTasks:tasks.length,totalOperations:operations.length,
      nextTaskOffset:offset+limit<tasks.length?offset+limit:null,nextOperationOffset:offset+limit<operations.length?offset+limit:null,
      nextOffset:offset+limit<Math.max(tasks.length,operations.length)?offset+limit:null};
  }
  taskAction(id: string, action: string, principal: Principal, expectedRevision?: number) {
    const out = this.store.update(data => {
      const task = Object.hasOwn(data.tasks,id)?data.tasks[id]:undefined; if (!task) fail('TASK_NOT_FOUND', 'task does not exist');
      if(expectedRevision!==undefined && (!Number.isSafeInteger(expectedRevision)||expectedRevision<0))fail('INVALID_TASK_VERSION','expectedTaskRevision must be a non-negative integer');
      if(expectedRevision!==undefined && expectedRevision!==(task.revision ?? 0))fail('STALE_TASK','task version changed; reload and review before changing its state');
      if (principal.role !== 'operator' && task.owner !== principal.role) fail('OPERATOR_REQUIRED', 'task is owned by operator');
      if(principal.role!=='operator' && task.heldByOperator)fail('OPERATOR_REQUIRED','operator paused this task; explicit operator resume required');
      if(principal.role!=='operator' && Object.values(data.operations).some(op=>op.taskId===id && op.owner==='operator' && (!terminal.has(op.state)||op.state==='unknown'&&!op.resolvedAt)))fail('OPERATOR_REQUIRED','task contains unfinished operator work');
      if (task.state === 'completed' || task.state === 'cancelled') {
        if (action === 'cancel' || action === 'complete') return task;
        fail('TASK_TERMINAL', 'create a new task instead of reopening a completed/cancelled task');
      }
      if(task.state==='unknown' && ['pause','resume'].includes(action))fail('UNKNOWN_EXECUTION','resolve unknown operations first');
      if (action === 'pause') {task.state = 'paused';if(principal.role==='operator')task.heldByOperator=true;}
      else if (action === 'resume') { if (task.state === 'unknown') fail('UNKNOWN_EXECUTION', 'resolve unknown operations first'); task.state = 'active';if(principal.role==='operator')task.heldByOperator=false; }
      else if (action === 'complete') {
        if (Object.values(data.operations).some(op => op.taskId === id && (!terminal.has(op.state) || op.state === 'unknown' && !op.resolvedAt))) fail('OPERATION_RUNNING', 'task has unfinished/unknown operations');
        task.state = 'completed';
      } else if (action === 'cancel') {
        task.state = 'cancel_requested';
        for (const op of Object.values(data.operations)) {
          if (op.taskId !== id || terminal.has(op.state)) continue;
          op.cancelRequested = true;
          if (op.state === 'queued') { op.state = 'cancelled'; op.settled = true; }
          else op.state = 'cancel_requested';
        }
        if (Object.values(data.operations).some(op=>op.taskId===id && op.state==='unknown' && !op.resolvedAt))task.state='unknown';
        else if (!Object.values(data.operations).some(op => op.taskId === id && !terminal.has(op.state))) task.state = 'cancelled';
      } else fail('INVALID_ACTION', 'task action must be pause|resume|cancel|complete');
      touchTask(task); return task;
    });
    this.pump(); return out;
  }
  cancelOperation(id: string, principal: Principal) {
    const op = this.getOperation(id); if(terminal.has(op.state))return op;
    this.store.update(data=>{
      const current=data.operations[id];
      if(principal.role!=='operator' && current.owner!==principal.role)fail('OPERATOR_REQUIRED','operation is operator-owned');
      if(terminal.has(current.state))return;
      current.cancelRequested=true;
      if(current.state==='queued'){current.state='cancelled';current.settled=true;}else current.state='cancel_requested';
      current.updatedAt=Date.now();
      if(data.tasks[current.taskId].implicit){data.tasks[current.taskId].state=current.state==='cancelled'?'cancelled':'cancel_requested';touchTask(data.tasks[current.taskId]);}
    });
    this.pump();return this.getOperation(id);
  }
  private saveResult(id: string, value: any, late = false) {
    const text = JSON.stringify(value ?? null);
    const file = join(this.store.root, 'results', `${id}${late ? '.late' : ''}.json`);
    atomicWriteJson(file, Buffer.byteLength(text) > 8*1024*1024
      ? { omitted: true, bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') } : value ?? null);
    return file;
  }
  private notify(id: string) { this.waiters.get(id)?.(undefined); this.waiters.delete(id); }
  private finish(id: string, state: Operation['state'], result?: any, error?: { code: string; message: string }) {
    let file: string | undefined;
    try { if (result !== undefined) file = this.saveResult(id,result); }
    catch (failure) { state = 'unknown'; error = { code: 'RESULT_PERSIST_FAILED', message: (failure as Error).message }; }
    this.store.update(data => {
      const op = data.operations[id]; op.state = state; op.updatedAt = Date.now(); op.error = error; op.resultFile = file;
      if(!this.running.has(id)&&!op.inFlight)op.settled=true;
      op.finishedAt=Date.now();
      if(state==='unknown')for(const effect of op.effects || [])if(effect.state==='dispatched'){effect.state='unknown';effect.uncertainAt=Date.now();}
      const control = data.controls[op.resource];
      if (control?.active === id) delete control.active;
      if (op.mode === 'write' && state === 'unknown') (data.controls[op.resource] ??= freshControl()).uncertain = id;
      const task = data.tasks[op.taskId];
      if (state === 'unknown') task.state = 'unknown';
      else if (task.state === 'cancel_requested' && !Object.values(data.operations).some(x => x.taskId === task.id && !terminal.has(x.state))) {
        task.state=Object.values(data.operations).some(x=>x.taskId===task.id && x.state==='unknown' && !x.resolvedAt)?'unknown':task.implicit && state==='succeeded'?'completed':'cancelled';
      }
      else if (task.implicit && task.state === 'active') task.state = 'completed';
      touchTask(task);
    });
    this.notify(id);
  }
  private pump() {
    if (this.closed) return;
    let rootWaiting = false;
    for (const item of [...this.queue]) {
      const data = this.store.read(), op = data.operations[item.id];
      if (terminal.has(op.state)) { this.queue = this.queue.filter(x => x.id !== item.id); this.notify(item.id); continue; }
      if (op.cancelRequested) { this.finish(op.id,'cancelled'); continue; }
      if (Date.now() >= op.deadline) { this.finish(op.id,'failed',undefined,{code:'DEADLINE_EXCEEDED',message:'deadline expired before dispatch'}); continue; }
      if (data.tasks[op.taskId].state === 'paused') continue;
      const busy = Object.entries(data.controls).some(([key,c]) => c.active && resourcesConflict(op.resource,key));
      if (op.mode === 'write' && (busy || rootWaiting)) { if(op.resource === 'host')rootWaiting=true; continue; }
      this.queue = this.queue.filter(x => x.id !== item.id);
      void this.run(item).catch(error => {
        if(!this.closed) {
          const op=this.getOperation(item.id);
          this.finish(item.id,op.mayHaveExecuted?'unknown':'failed',undefined,{code:(error as any).code || 'COORDINATOR_ERROR',message:String(error)});
        }
      });
    }
    if (this.queue.length && !this.poll) this.poll = setInterval(() => this.pump(),50).unref();
    if (!this.queue.length && this.poll) { clearInterval(this.poll); this.poll=undefined; }
  }
  private async run(item: { id: string; fn: () => Promise<any> }) {
    const op = this.store.update(data => {
      const op = data.operations[item.id];
      if (op.mode === 'write') {
        this.assertVersion(data,op.resource,{role:op.owner,id:op.actorId,source:op.source},op);
        const control = data.controls[op.resource] ??= freshControl();
        if(Object.entries(data.controls).some(([key,c])=>c.active && resourcesConflict(op.resource,key)))fail('OPERATION_BUSY','resource is in use by another Host operation');
        if (Object.entries(data.controls).some(([key,c])=>c.uncertain && resourcesConflict(op.resource,key))) fail('UNKNOWN_EXECUTION','resource has unresolved side effects; inspect and resolve first');
        control.revision++; control.active=op.id; op.appliedRevision=control.revision;
      }
      op.state='running'; op.startedAt=Date.now();op.updatedAt=Date.now(); return op;
    });
    this.running.add(op.id);
    const targetEpochs = new Map<string,{resource:string;epoch:number}>();
    const initial = this.store.read();
    const context: ExecutionContext = {
      operationId:op.id,resource:op.resource,principalRole:op.owner,remainingMs:()=>Math.max(1,op.deadline-Date.now()),
      checkpoint: session => {
        if(this.closed)fail('HOST_CLOSED','coordinator closed');
        const data=this.store.read(), current=data.operations[op.id];
        if(data.tasks[op.taskId].state==='paused')fail('TASK_PAUSED','task paused; later effects blocked');
        if(current.cancelRequested)fail('CANCEL_REQUESTED','operation cancellation requested; no further effects');
        if(Date.now()>=current.deadline || terminal.has(current.state))fail('DEADLINE_EXCEEDED','operation deadline/state no longer permits effects');
        if(op.mode==='write') {
          if(op.owner!=='operator'&&crossHeld(data,op.resource))fail('STALE_CONTROL','operator changed control across an unverified legacy/device boundary');
          const control=data.controls[op.resource] ?? freshControl();
          if(control.epoch!==op.controlEpoch || control.revision!==op.appliedRevision || data.controls.host.epoch!==op.hostEpoch)fail('STALE_CONTROL','control changed during operation; later effects blocked');
          if(op.resource==='host' && op.owner!=='operator' && Object.values(data.controls).some(c=>c.owner==='operator'||c.paused))fail('STALE_CONTROL','operator took target control; later Host-wide effects blocked');
          if(session) {
            const resource=this.targetResource(session), prior=targetEpochs.get(session);
            if(op.resource!=='host' && resource!==op.resource)fail('TARGET_CHANGED','operation is bound to a different process generation');
            if(prior && prior.resource!==resource)fail('TARGET_CHANGED','process generation changed');
            const target=data.controls[resource] ?? freshControl();
            const epoch=prior?.epoch ?? initial.controls[resource]?.epoch ?? target.epoch;
            targetEpochs.set(session,{resource,epoch});
            if(target.epoch!==epoch || op.owner!=='operator' && target.owner==='operator')fail('STALE_CONTROL','target control changed during operation');
          }
        }
      },
      dispatched: description => this.store.update(data => {
        const x=data.operations[op.id];x.mayHaveExecuted=true;x.inFlight++;
        if((x.effects?.length||0)>=64){x.effectsDropped=(x.effectsDropped||0)+1;return;}
        const id=randomUUID();(x.effects??=[]).push({id,kind:String(description?.kind||'external').slice(0,40),action:String(description?.action||'external request').slice(0,160),
          session:description?.session,state:'dispatched',startedAt:Date.now()});return id;
      }),
      acknowledged: (uncertain,id,failed) => { if(!this.closed)this.store.update(data => {
        const x=data.operations[op.id];x.inFlight=Math.max(0,x.inFlight-1);x.uncertainEffect ||= uncertain;
        const effect=id&&x.effects?.find(effect=>effect.id===id);
        if(effect){effect.state=uncertain?'unknown':failed?'failed':'acknowledged';effect.completedAt=Date.now();if(uncertain)effect.uncertainAt=Date.now();}
      }); },
    };
    const timer=setTimeout(() => {
      if(this.closed)return;
      const current=this.getOperation(op.id);
      this.finish(op.id,current.mayHaveExecuted || current.inFlight ? 'unknown':'failed',undefined,{code:'DEADLINE_EXCEEDED',message:'deadline expired; target execution was not stopped or replayed'});
    },Math.max(1,op.deadline-Date.now()));
    try {
      context.checkpoint();
      const value=await executionContext.run(context,item.fn);
      if(this.closed)return;
      const current=this.getOperation(op.id);
      if(terminal.has(current.state)) {
        const file=this.saveResult(op.id,value,true); this.store.update(data => { data.operations[op.id].lateResultFile=file; });
      } else {
        const failed=value?.ok===false || Number(value?.httpStatus)>=400 || value?.body?.ok===false;
        this.finish(op.id,current.uncertainEffect?'unknown':failed?'failed':'succeeded',value);
      }
    } catch(error) {
      if(!this.closed && !terminal.has(this.getOperation(op.id).state)) {
        const current=this.getOperation(op.id);
        this.finish(op.id,current.uncertainEffect || current.inFlight?'unknown':current.cancelRequested?'cancelled':'failed',undefined,
          {code:(error as any).code || 'OPERATION_FAILED',message:(error as Error).message});
      } else if (!this.closed) {
        const file=this.saveResult(op.id,operationFailure(error),true);
        this.store.update(data => { data.operations[op.id].lateResultFile=file; });
      }
    } finally {
      clearTimeout(timer); this.running.delete(op.id);
      if(!this.closed) {
        this.store.update(data => { const x=data.operations[op.id]; x.settled=true; x.partialEffects=x.mayHaveExecuted && (x.state==='cancelled'||x.state==='failed'); });
        this.pump();
      }
    }
  }
  close() {
    this.closed=true; if(this.poll)clearInterval(this.poll);
    this.store.update(data => { data.hosts[this.host].active=false; }); this.store.close();
  }
}
