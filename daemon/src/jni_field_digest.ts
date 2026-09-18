// JNIEnv field events -> "which fields did native code read or write, how often, with what last value".
//
// The access events (Get/Set<Type>Field, added in v4.55) carry an opaque jfieldID in their detail
// ("field=0x.."); the ID lookup events (GetFieldID / GetStaticFieldID) carry the name and, since
// v4.56, the id they handed out ("Class#name:sig -> 0x.."). Joining the two is what turns a pointer
// into "com.example.Foo#isDebug:Z" - the thing an analyst can actually read, and the signal that
// says which fields a target probes through native code.
import { captures, storeLossNote } from './state.ts';
import { drainSession } from './service.ts';

export interface JniEnvEvent {
  function: string;
  value: string;
  ok?: boolean;
  ts?: number;
  tid?: number;
}

export interface JniFieldGroup {
  accessor: string;
  /** Resolved "Class#name:sig" when the id was seen, otherwise the raw id. */
  field: string;
  fieldId: string;
  resolved: boolean;
  count: number;
  lastValue: string | null;
  /** Writes whose stored value was REWRITTEN by a setValue override (v4.58). */
  rewritten: number;
  /** What the target tried to store the last time it was rewritten. */
  lastRequested: string | null;
  tids: number[];
  firstTs: number | null;
  lastTs: number | null;
}

export interface JniFieldDigest {
  samples: number;
  idEvents: number;
  resolvedIds: number;
  unresolvedAccesses: number;
  /** Writes where an override changed what the target stored (requested != applied). */
  rewrittenSamples: number;
  groups: JniFieldGroup[];
  notes: string[];
}

const ACCESS_RE = /^(Get|Set)(Static)?(Object|Boolean|Byte|Char|Short|Int|Long|Float|Double)Field$/;
const ID_RE = /^(.*?) -> (0x[0-9a-fA-F]+)$/;
const DETAIL_RE = /^field=(0x[0-9a-fA-F]+)(?: value=(.*?))?(?: requested=(.*))?$/;

/** Pure so it is unit-tested away from a device (the runner below only feeds it real events). */
export function digestJniFields(events: JniEnvEvent[], opts: { maxGroups?: number } = {}): JniFieldDigest {
  const ids = new Map<string, string>();
  let idEvents = 0;
  for (const ev of events ?? []) {
    if (ev?.function !== 'GetFieldID' && ev?.function !== 'GetStaticFieldID') continue;
    idEvents++;
    const m = ID_RE.exec(String(ev.value ?? ''));
    if (m && m[1]) ids.set(m[2].toLowerCase(), m[1]);
  }

  const groups = new Map<string, JniFieldGroup>();
  let samples = 0;
  let unresolvedAccesses = 0;
  let rewrittenSamples = 0;
  for (const ev of events ?? []) {
    if (!ACCESS_RE.test(String(ev?.function ?? ''))) continue;
    const m = DETAIL_RE.exec(String(ev.value ?? ''));
    if (!m) continue;
    samples++;
    const fieldId = m[1].toLowerCase();
    const resolved = ids.get(fieldId);
    if (!resolved) unresolvedAccesses++;
    const key = `${ev.function}|${fieldId}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        accessor: ev.function, field: resolved ?? m[1], fieldId, resolved: Boolean(resolved),
        count: 0, lastValue: null, rewritten: 0, lastRequested: null,
        tids: [], firstTs: null, lastTs: null,
      };
      groups.set(key, g);
    }
    g.count++;
    if (m[2] !== undefined) g.lastValue = m[2];
    // "value=42 requested=7" is a REWRITTEN write: the target asked for 7 and the hook stored 42.
    // Surfacing it separately matters because that difference IS the finding - an unfiltered digest
    // would just show the applied value and hide that anything intervened.
    if (m[3] !== undefined) { g.rewritten++; g.lastRequested = m[3]; rewrittenSamples++; }
    const tid = Number(ev.tid ?? 0);
    if (tid && g.tids.length < 16 && !g.tids.includes(tid)) g.tids.push(tid);
    const ts = Number(ev.ts ?? 0);
    if (ts) { if (g.firstTs == null) g.firstTs = ts; g.lastTs = ts; }
  }

  const maxGroups = Math.max(1, Math.min(200, Math.trunc(Number(opts.maxGroups ?? 50))));
  const sorted = [...groups.values()].sort((a, b) => (b.count - a.count) || a.accessor.localeCompare(b.accessor) || a.field.localeCompare(b.field));
  const notes: string[] = [];
  if (!samples) notes.push('no JNIEnv field-access event in this window: hook Get/Set<Type>Field first (jni_env_hook) and trigger the target');
  if (unresolvedAccesses) notes.push(`${unresolvedAccesses} access(es) could not be attributed: their jfieldID was never seen in a GetFieldID event of this window (hook GetFieldID too, or widen sinceMs)`);
  if (rewrittenSamples) notes.push(`${rewrittenSamples} write(s) were REWRITTEN by an active setValue override: see each group's rewritten/lastRequested (requested != applied)`);
  if (groups.size > maxGroups) notes.push(`only the top ${maxGroups} of ${groups.size} (accessor, field) groups are listed`);

  return {
    samples, idEvents, resolvedIds: ids.size, unresolvedAccesses, rewrittenSamples,
    groups: sorted.slice(0, maxGroups), notes,
  };
}

export interface JniFieldDigestResult extends JniFieldDigest {
  drain: { ok: boolean; error?: string };
  window: { sinceMs: number | null; limit: number };
}

/** Read the session's JNI_ENV captures through the shared drain path and join them. */
export async function jniFieldDigest(session: string, opts: { sinceMs?: number; limit?: number; maxGroups?: number } = {}): Promise<JniFieldDigestResult> {
  // Same rule as java_trace/syscall_digest: only drainSession may take records out of the agent ring.
  const drain = await drainSession(session).catch(() => ({ ok: false, error: 'drainSession threw' }));
  const limit = Math.max(1, Math.min(5000, Math.trunc(Number(opts.limit ?? 2000))));
  const sinceMs = Number.isFinite(Number(opts.sinceMs)) ? Number(opts.sinceMs) : null;
  const events: JniEnvEvent[] = [];
  for (let i = captures.length - 1; i >= 0 && events.length < limit; i--) {
    const c: any = captures[i];
    if (c.sessionId !== session || c.func !== 'JNI_ENV') continue;
    if (sinceMs != null && Number(c.ts) < sinceMs) break;     // the store is append-ordered
    let text = '';
    try { text = Buffer.from(String(c.hex ?? ''), 'hex').toString('utf8'); } catch { text = ''; }
    if (!text) continue;
    try {
      const ev = JSON.parse(text);
      events.push({ function: String(ev?.function ?? ''), value: String(ev?.value ?? ''), ok: ev?.ok === true, ts: Number(c.ts ?? 0), tid: Number(c.tid ?? 0) });
    } catch { /* not our event shape */ }
  }
  events.reverse();   // oldest first, so firstTs/lastTs/lastValue are chronological
  const digest = { drain, window: { sinceMs, limit }, ...digestJniFields(events, opts) };
  // A window whose records were evicted from the store can look like "the field was never
  // accessed" - say so instead (v4.96).
  const storeNote = storeLossNote(session, { sinceMs });
  if (storeNote) digest.notes.push(storeNote);
  return digest;
}
