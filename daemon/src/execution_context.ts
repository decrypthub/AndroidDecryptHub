import { AsyncLocalStorage } from 'node:async_hooks';

export class OperationError extends Error {
  code: string; uncertain: boolean;
  constructor(code: string, message: string, uncertain = false) { super(message); this.code=code;this.uncertain=uncertain; }
}
export interface ExecutionContext {
  checkpoint(session?: string): void;
  dispatched(): void;
  acknowledged(uncertain: boolean): void;
}
export const executionContext = new AsyncLocalStorage<ExecutionContext>();
export function checkpoint(session?: string) { executionContext.getStore()?.checkpoint(session); }
export function detached<T>(fn: () => T): T { return executionContext.exit(fn); }
export async function trackedEffect<T>(fn: () => Promise<T>, session?: string): Promise<T> {
  const context = executionContext.getStore();
  context?.checkpoint(session); context?.dispatched();
  try { const value = await fn(); context?.acknowledged(false); return value; }
  catch (error) { context?.acknowledged(true); throw error; }
}
export function localEffect<T>(fn: () => T): T {
  const context = executionContext.getStore();
  context?.checkpoint(); context?.dispatched();
  try { const value = fn(); context?.acknowledged(false); return value; }
  catch (error) { context?.acknowledged(false); throw error; }
}
