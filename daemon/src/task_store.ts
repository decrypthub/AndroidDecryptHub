import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export type Role = 'ai' | 'operator';
export type OperationState = 'queued' | 'running' | 'cancel_requested' | 'succeeded' | 'failed' | 'cancelled' | 'unknown';
export interface Control { revision: number; epoch: number; owner: Role; paused: boolean; active?: string; uncertain?: string }
export interface Task {
  id: string; title: string; owner: Role; state: 'active' | 'paused' | 'cancel_requested' | 'cancelled' | 'completed' | 'unknown';
  createdAt: number; updatedAt: number; implicit: boolean;
  heldByOperator?: boolean;
  revision?: number;
  createdBy?: string;
  source?: string;
}
export interface Effect {
  id: string; kind: string; action: string; session?: string;
  state: 'dispatched' | 'acknowledged' | 'failed' | 'unknown';
  startedAt: number; completedAt?: number; uncertainAt?: number;
}
export interface Operation {
  id: string; taskId: string; name: string; resource: string; mode: 'read' | 'analysis' | 'write'; owner: Role;
  actorId: string; source: string; host: string; state: OperationState; createdAt: number; updatedAt: number;
  deadline: number; expectedRevision?: number; controlEpoch?: number; hostEpoch?: number;
  key: string; fingerprint: string; mayHaveExecuted: boolean; inFlight: number; uncertainEffect: boolean;
  cancelRequested: boolean; settled: boolean; error?: { code: string; message: string }; resultFile?: string;
  lateResultFile?: string; partialEffects?: boolean;
  appliedRevision?: number;
  resolvedAt?: number;
  startedAt?: number; finishedAt?: number; effects?: Effect[]; effectsDropped?: number;
}
export interface Ledger {
  schemaVersion: 1; controls: Record<string, Control>; tasks: Record<string, Task>; operations: Record<string, Operation>;
  hosts: Record<string, { pid: number; hostname: string; active: boolean }>;
}
export const freshControl = (): Control => ({ revision: 0, epoch: 0, owner: 'ai', paused: false });

/** Authoritative metadata, never auto-discarded/rebuilt on corruption. No import-time I/O. */
export class TaskStore {
  private db: DatabaseSync;
  readonly root: string;
  constructor(root: string) {
    this.root=root;
    mkdirSync(root, { recursive: true });
    this.db = new DatabaseSync(join(root, 'operations.sqlite'));
    try {
    this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS operation_state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)');
    const initial: Ledger = { schemaVersion: 1, controls: { host: freshControl() }, tasks: {}, operations: {}, hosts: {} };
    this.db.prepare('INSERT OR IGNORE INTO operation_state(id,data) VALUES(1,?)').run(JSON.stringify(initial));
    this.read();
    } catch (error) { this.db.close(); throw error; }
  }
  read(): Ledger {
    const value = JSON.parse((this.db.prepare('SELECT data FROM operation_state WHERE id=1').get() as { data: string }).data);
    if (value.schemaVersion !== 1 || !value.controls || !value.tasks || !value.operations || !value.hosts) throw Error('unsupported or corrupt operation ledger');
    return value;
  }
  update<T>(fn: (data: Ledger) => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const data = this.read(), result = fn(data), text = JSON.stringify(data);
      if (Buffer.byteLength(text) > 32 * 1024 * 1024) throw Error('operation ledger is full; explicit archival required');
      this.db.prepare('UPDATE operation_state SET data=? WHERE id=1').run(text);
      this.db.exec('COMMIT'); return structuredClone(result);
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  close() { this.db.close(); }
}
