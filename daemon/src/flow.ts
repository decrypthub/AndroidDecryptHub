// flow.ts — network ↔ crypto correlation, as a PURE policy module.
//
// Why this lives here: the correlation between "this plaintext was encrypted" and "this
// ciphertext went out over TLS" used to be computed inline inside the /api/flow/watch route
// handler, next to a one-shot agent op (flow_watch) that hardcoded the target's trigger
// contract. Both are gone (2026-10-01): the capture half now comes from the persistent
// capture set (capture_start streams EVP_*/HMAC_*/SSL_* from every module that holds them,
// with the target triggered through java_call), and the join half is this module.
//
// What it is NOT: this is a thread + time-window join, the same heuristic the old route used.
// It is not the deterministic content-hash correlation that WS-I still owes (the EVP output
// buffer hash intersecting the SSL_write buffer hash). Every reply carries `caveat` saying so:
// a correlation that reads as proof when it is only co-occurrence is worse than no answer.
//
// Pure: no state, no I/O, no daemon imports beyond the record/type it reads. `flowCorrelate`
// is the thin impure shell that reads the live capture store.
import { captures, storeLossNote } from './state.ts';
import type { Capture } from './state.ts';

/** A crypto record and a net record correlate when they ran on the same thread within this window. */
export const WINDOW_NS = 200_000_000;

/** The caveat every reply carries. One string, so the MCP tool and any future caller cannot drift. */
export const FLOW_CAVEAT =
  'thread + time-window correlation (not content-hash): a pair means the two calls ran on the same ' +
  'thread inside the window, not that this plaintext is provably the payload of that record. ' +
  'Deterministic content-hash correlation is WS-I and is not implemented yet.';

/** Render a hex capture payload as printable ascii (one char per byte, non-printables as '.'). */
export function asciiOf(hex: string): string {
  if (typeof hex !== 'string' || !hex) return '';
  let out = '';
  for (let i = 0; i + 1 < hex.length; i += 2) {
    const code = Number.parseInt(hex.slice(i, i + 2), 16);
    if (!Number.isFinite(code)) return out;
    out += code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '.';
  }
  return out;
}

export interface FlowRecord {
  tid: number; tsNs: number; func: string; hex: string;
  /** The store's own classification ('crypto' | 'net'). When present it decides the side; the
   *  func prefix is only the fallback for callers handing over raw agent records. The store is
   *  the better signal because the JAVA-layer rich capture names its records by operation
   *  (encrypt / digest / hmac), not by the native symbol - a prefix test alone quietly drops
   *  every Java-layer crypto capture (measured 2026-10-01: 65 crypto records, only the 4 native
   *  EVP_* ones would have matched). */
  category?: string;
}

export interface FlowCorrelation {
  tid: number;
  deltaMs: number;
  cryptoFunc: string;
  netFunc: string;
  plaintext: string;
  request: string;
}

export interface FlowResult {
  correlations: FlowCorrelation[];
  considered: { crypto: number; net: number };
  /** Pairs found before the reply cap; correlations.length is min(totalPairs, maxPairs). */
  totalPairs: number;
  /** Records whose payload could not be rendered (odd-length or malformed hex) - never silently zero. */
  skipped: number;
  caveat: string;
  /** Present only when the join produced nothing, so an empty answer says WHY it is empty. */
  reason?: string;
  /** Set by flowCorrelate when the store evicted records the requested window reaches back into. */
  storeLoss?: string | null;
}

const isCryptoRecord = (r: FlowRecord): boolean =>
  r.category ? r.category === 'crypto' : (String(r.func).startsWith('EVP_') || r.func === 'HMAC_Update');
const isNetRecord = (r: FlowRecord): boolean =>
  r.category ? r.category === 'net' : String(r.func).startsWith('SSL_');

/**
 * Join crypto records to net records by thread + time window.
 * `considered` counts what the join actually saw, so "0 correlations" can be told apart from
 * "0 candidates" - the same fail-loud rule the capture store follows.
 */
export function correlateFlow(records: FlowRecord[], opts: { windowNs?: number; maxPairs?: number } = {}): FlowResult {
  const windowNs = opts.windowNs ?? WINDOW_NS;
  const maxPairs = opts.maxPairs && opts.maxPairs > 0 ? opts.maxPairs : 200;  const crypto = records.filter(isCryptoRecord);
  const net = records.filter(isNetRecord);
  const correlations: FlowCorrelation[] = [];
  let skipped = 0;
  let totalPairs = 0;

  for (const cr of crypto) {
    const plaintext = asciiOf(cr.hex);
    if (!plaintext) skipped++;
    for (const nw of net) {
      if (cr.tid !== nw.tid) continue;                       // cross-thread is never a pair
      const delta = Math.abs(Number(cr.tsNs) - Number(nw.tsNs));
      if (!(delta <= windowNs)) continue;                     // boundary is inclusive; NaN never matches
      totalPairs++;
      if (correlations.length >= maxPairs) continue;          // keep counting, stop growing the reply
      const request = asciiOf(nw.hex);
      correlations.push({
        tid: cr.tid,
        deltaMs: delta / 1e6,
        cryptoFunc: String(cr.func),
        netFunc: String(nw.func),
        plaintext,
        request: request.slice(0, 120),
      });
    }
  }

  const result: FlowResult = {
    correlations,
    considered: { crypto: crypto.length, net: net.length },
    totalPairs,
    skipped,
    caveat: FLOW_CAVEAT,
  };
  if (!correlations.length) {
    result.reason = crypto.length === 0 && net.length === 0
      ? 'no captures in window: the crypto and TLS streams are both empty (is capture_start on?)'
      : crypto.length === 0
        ? `no crypto record in window (${net.length} net records) - nothing to correlate`
        : net.length === 0
          ? `no net record in window (${crypto.length} crypto records) - nothing to correlate`
          : `no crypto/net pair shared a thread inside ${windowNs / 1e6}ms`;
  }
  return result;
}

/**
 * Read the live capture store for one session and join it. `sinceMs`/`sinceCaptureId` bound the
 * window; a window that reaches past evicted records is reported (storeLoss) instead of looking
 * complete.
 */
export function flowCorrelate(session: string, opts: { sinceMs?: number | null; sinceCaptureId?: number | null; windowNs?: number; maxPairs?: number } = {}): FlowResult {
  const sinceMs = opts.sinceMs ?? null;
  const sinceId = opts.sinceCaptureId ?? null;
  const window: FlowRecord[] = [];
  for (const c of captures as Capture[]) {
    if (session && c.sessionId !== session) continue;
    if (sinceMs != null && Number(c.ts) < sinceMs) continue;   // c.ts is the host-side arrival stamp
    if (sinceId != null && Number(c.id) <= sinceId) continue;
    window.push({ tid: Number(c.tid), tsNs: Number(c.tsNs), func: String(c.func), hex: String(c.hex), category: String(c.category ?? '') });
  }
  const result = correlateFlow(window, { windowNs: opts.windowNs, maxPairs: opts.maxPairs });
  result.storeLoss = storeLossNote(session, { sinceMs, sinceCaptureId: sinceId });
  return result;
}
