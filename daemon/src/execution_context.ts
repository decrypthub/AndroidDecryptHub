import { AsyncLocalStorage } from 'node:async_hooks';

export class OperationError extends Error {
  code: string; uncertain: boolean;
  constructor(code: string, message: string, uncertain = false) { super(message); this.code=code;this.uncertain=uncertain; }
}
export interface ExecutionContext {
  operationId?: string;
  resource?: string;
  principalRole?: 'ai' | 'operator';
  remainingMs?(): number;
  checkpoint(session?: string): void;
  dispatched(description?: EffectDescription): string | void;
  acknowledged(uncertain: boolean, id?: string | void, failed?: boolean): void;
}
export interface EffectDescription { kind: string; action: string; session?: string }
export const executionContext = new AsyncLocalStorage<ExecutionContext>();
export function checkpoint(session?: string) { executionContext.getStore()?.checkpoint(session); }
export function detached<T>(fn: () => T): T { return executionContext.exit(fn); }
export async function trackedEffect<T>(fn: () => Promise<T>, session?: string, description?: EffectDescription): Promise<T> {
  const context = executionContext.getStore();
  context?.checkpoint(session); const id=context?.dispatched(description);
  try { const value = await fn(); context?.acknowledged(false,id); return value; }
  catch (error) { context?.acknowledged(true,id,true); throw error; }
}
export function localEffect<T>(fn: () => T, description?: EffectDescription): T {
  const context = executionContext.getStore();
  context?.checkpoint(); const id=context?.dispatched(description || {kind:'host',action:'local mutation'});
  try { const value = fn(); context?.acknowledged(false,id); return value; }
  catch (error) { context?.acknowledged(false,id,true); throw error; }
}
