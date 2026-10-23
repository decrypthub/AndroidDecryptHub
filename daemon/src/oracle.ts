// Oracle + differential harness (host side, pure core + thin agent wiring).
//
// The single most useful analysis primitive is not a better trace: it is being able to call the target's
// own entry point with controlled arguments and ask "which output moved when I changed THIS input field".
// Every session of real protocol work reimplements it by hand (build the args array, replay it, compare
// two captures), and the answer - a dependency surface - is what turns an unknown parameter into a small
// search space.
//
// Two pure pieces are tested without a device: `setPath`/`getPath` (a tiny path language over the args
// JSON, including byte payloads) and `summarizeDiff` (baseline vs variants -> which patches changed the
// observed value). `recordCall`/`replayCall` only wire those to the agent's detached java_call, so a
// blocking target method parks one thread instead of the session.
import { agentCmd } from './service.ts';

/** A path is dot/bracket notation over JSON: `args[1][0].$bytesHex`, `result[0].b5`, `[0]`. */
type Json = unknown;

function splitPath(path: string): string[] {
  const out: string[] = [];
  const re = /([^.[\]]+)|\[(\d+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(path))) {
    out.push(m[1] !== undefined ? m[1] : m[2]);
  }
  return out;
}

/** Walk a path; a string that looks like JSON is parsed before the next step (see module comment). */
export function getPath(value: Json, path: string): unknown {
  let cur: Json = value;
  for (const key of splitPath(path)) {
    if (typeof cur === 'string') {
      const t = cur.trim();
      if (t.startsWith('{') || t.startsWith('[')) {
        try { cur = JSON.parse(t); } catch { /* not JSON after all: fall through as a string */ }
      }
    }
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      const i = Number(key);
      if (!Number.isInteger(i)) return undefined;
      cur = cur[i];
    } else if (typeof cur === 'object') {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** Immutable deep set: returns a copy with `path` replaced (arrays are grown with nulls as needed). */
export function setPath(value: Json, path: string, next: unknown): Json {
  const keys = splitPath(path);
  if (!keys.length) return next;
  const root: Json = Array.isArray(value) ? value.slice() : (value && typeof value === 'object' ? { ...(value as object) } : {});
  let cur: any = root;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const last = i === keys.length - 1;
    const wantArray = !last ? /^\d+$/.test(keys[i + 1]) : /^\d+$/.test(key);
    if (last) {
      if (Array.isArray(cur) && /^\d+$/.test(key)) cur[Number(key)] = next;
      else if (cur && typeof cur === 'object') cur[key] = next;
      break;
    }
    let child = Array.isArray(cur) ? cur[Number(key)] : cur?.[key];
    if (child === null || typeof child !== 'object') {
      child = wantArray ? [] : {};
      if (Array.isArray(cur)) cur[Number(key)] = child; else if (cur) cur[key] = child;
    } else {
      child = Array.isArray(child) ? child.slice() : { ...child };
      if (Array.isArray(cur)) cur[Number(key)] = child; else if (cur) cur[key] = child;
    }
    cur = child;
  }
  return root;
}

export interface Patch { path: string; value: unknown }
export interface Variant { label: string; patches: Patch[] }

/** Deep clone that keeps byte payload wrappers (`{$bytesHex}`) intact (they are plain JSON). */
export function cloneJson<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export interface DiffRow {
  label: string;
  value: unknown;
  same: boolean;
  changedPaths: string[];
}

export interface DiffResult {
  baseline: unknown;
  rows: DiffRow[];
  /** Patch paths whose change always moved the output, and those that never did. */
  sensitive: string[];
  insensitive: string[];
}

/**
 * Compare a baseline observation with one observation per variant. `sensitive` is the answer the caller
 * wants: those input fields are (at least sometimes) part of the output's preimage; `insensitive` fields
 * provably are not, for the variants that were tried. A path counts as sensitive if it is the ONLY patch
 * in a variant whose output changed; with several patches per variant this stays conservative (it only
 * reports paths that were alone in some changing variant).
 */
export function summarizeDiff(baseline: unknown, rows: { label: string; patches: Patch[]; value: unknown }[]): DiffResult {
  const base = JSON.stringify(baseline);
  const out: DiffRow[] = rows.map((r) => ({
    label: r.label,
    value: r.value,
    same: JSON.stringify(r.value) === base,
    changedPaths: r.patches.map((p) => p.path),
  }));
  const sensitive = new Set<string>();
  const insensitive = new Set<string>();
  for (let i = 0; i < rows.length; i++) {
    const row = out[i];
    const one = rows[i].patches.length === 1;
    if (!one) continue;
    const p = rows[i].patches[0].path;
    if (row.same) insensitive.add(p); else sensitive.add(p);
  }
  for (const p of sensitive) insensitive.delete(p);
  return { baseline, rows: out, sensitive: [...sensitive], insensitive: [...insensitive] };
}

// --- agent wiring --------------------------------------------------------------------------------

export interface OracleTemplate {
  id: number;
  session: string;
  /** Java facade: the entry a caller would use for this parameter. */
  className: string;
  method: string;
  params: string;
  field: string;
  args: unknown[];
  /** The observation of the recorded call: the whole java_call result object. */
  result: unknown;
  /** Last observed value at `extract` (kept so a replay can be compared without re-deriving it). */
  baseline: unknown;
  extract: string;
  createdAt: number;
}

export interface OracleDeps {
  sendCmd: (session: string, op: string, args: Record<string, unknown>, timeout?: number) => Promise<any>;
  sleep?: (ms: number) => Promise<void>;
}

const defaultDeps: OracleDeps = {
  sendCmd: (session, op, args, timeout) => agentCmd(session, op, args, timeout),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

let nextId = 1;
const templates = new Map<number, OracleTemplate>();

export function listOracles(): Array<Omit<OracleTemplate, 'result'>> {
  return [...templates.values()].map(({ result, ...rest }) => rest);
}
export function dropOracle(id: number): boolean { return templates.delete(id); }
export function getOracle(id: number): OracleTemplate | undefined { return templates.get(id); }

/** One detached java_call, waited to completion. A blocking target method parks its own thread. */
async function invoke(session: string, t: Pick<OracleTemplate, 'className' | 'method' | 'params' | 'field'>, args: unknown[], timeoutMs: number, deps: OracleDeps): Promise<any> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const start = await deps.sendCmd(session, 'java_call', {
    className: t.className, method: t.method, params: t.params, field: t.field,
    args: JSON.stringify(args), detach: 'true',
  }, 20_000);
  if (!start?.ok) return start ?? { ok: false, error: 'java_call was refused' };
  if (!start.callId) return start;                       // agent without detached calls: answer as-is
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await deps.sendCmd(session, 'java_call_result', { callId: Number(start.callId) }, 15_000);
    const call = r?.call;
    if (call && call.state !== 'running') {
      if (call.state === 'failed') return { ok: false, error: call.error ?? 'call failed', call };
      return { ok: true, ...call.result, call };
    }
    if (Date.now() >= deadline) return { ok: false, error: `oracle call still running after ${timeoutMs} ms`, call };
    await sleep(120);
  }
}

/**
 * Record one call and keep its arguments as a template. `extract` is the path (in the reply object) of
 * the value to watch - for a signature facade usually `result[0].b5` or `result.b5`.
 */
export async function oracleRecord(
  session: string,
  opts: { className: string; method: string; params?: string; field?: string; args?: unknown[]; extract?: string; timeoutMs?: number },
  deps: OracleDeps = defaultDeps,
): Promise<{ ok: boolean; id?: number; baseline?: unknown; result?: unknown; error?: string }> {
  const t = {
    className: String(opts.className ?? ''),
    method: String(opts.method ?? ''),
    params: String(opts.params ?? ''),
    field: String(opts.field ?? ''),
    args: opts.args ?? [],
    extract: String(opts.extract ?? 'result'),
  };
  if (!t.className || !t.method) return { ok: false, error: 'record needs className and method' };
  const reply = await invoke(session, t, t.args, opts.timeoutMs ?? 20_000, deps);
  if (!reply?.ok) return { ok: false, error: String(reply?.error ?? 'call failed'), result: reply };
  const baseline = getPath(reply, t.extract);
  const id = nextId++;
  templates.set(id, { id, session, ...t, result: reply, baseline, createdAt: Date.now() });
  return { ok: true, id, baseline, result: reply };
}

/** Replay a template with patches applied to its recorded arguments. */
export async function oracleReplay(
  session: string,
  opts: { id: number; patches?: Patch[]; timeoutMs?: number },
  deps: OracleDeps = defaultDeps,
): Promise<{ ok: boolean; id?: number; value?: unknown; changed?: boolean; patches?: Patch[]; error?: string }> {
  const t = templates.get(Number(opts.id));
  if (!t) return { ok: false, error: `unknown oracle id ${opts.id} (record one first)` };
  let args: unknown = cloneJson(t.args);
  for (const p of opts.patches ?? []) args = setPath(args, p.path, p.value);
  const reply = await invoke(session, t, args as unknown[], opts.timeoutMs ?? 20_000, deps);
  if (!reply?.ok) return { ok: false, error: String(reply?.error ?? 'call failed') };
  const value = getPath(reply, t.extract);
  return { ok: true, id: t.id, value, changed: JSON.stringify(value) !== JSON.stringify(t.baseline), patches: opts.patches ?? [] };
}

/**
 * Variants x patches -> dependency matrix. Each variant is one replay with its patches applied; the reply
 * says which single-field patches moved the observed value, i.e. which inputs are part of the preimage.
 */
export async function oracleDiff(
  session: string,
  opts: { id: number; variants: Variant[]; timeoutMs?: number },
  deps: OracleDeps = defaultDeps,
): Promise<{ ok: boolean; id?: number; extract?: string; diff?: DiffResult; error?: string }> {
  const t = templates.get(Number(opts.id));
  if (!t) return { ok: false, error: `unknown oracle id ${opts.id} (record one first)` };
  const variants = Array.isArray(opts.variants) ? opts.variants : [];
  if (!variants.length) return { ok: false, error: 'diff needs at least one variant' };
  const rows: { label: string; patches: Patch[]; value: unknown }[] = [];
  for (const v of variants) {
    const r = await oracleReplay(session, { id: t.id, patches: v.patches ?? [], timeoutMs: opts.timeoutMs }, deps);
    if (!r.ok) return { ok: false, error: `variant ${v.label}: ${r.error}` };
    rows.push({ label: String(v.label ?? rows.length), patches: v.patches ?? [], value: r.value });
  }
  return { ok: true, id: t.id, extract: t.extract, diff: summarizeDiff(t.baseline, rows) };
}
