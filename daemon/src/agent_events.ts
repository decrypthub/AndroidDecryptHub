// Host-side agent-signal matching for phone_wait.
//
// The agent .so stays a pure collector: hook events stream through broadcast -> recordEvent,
// capture records stream through the service capture loop -> captures. Matching those signals
// to an AI wait request happens here, on the host, so the target process never carries wait logic.
//
// Semantics: filters of the same kind are ANDed; event and capture filters are ORed; the newest
// match wins. Both stores are append-ordered, so each scan walks newest -> oldest and stops as
// soon as a record falls outside the window (a timestamp, or an explicit cursor).

export interface WaitEvent { seq: number; ts: number; type: string; data: any }
export interface WaitCapture { id: number; ts: number; category: string; [key: string]: any }
export interface AgentWaitMatch { kind: 'event' | 'capture'; item: any }

const EVENT_DATA_CAP = 4_000;
const CAPTURE_HEX_INLINE_CAP = 512;

export function hasAgentWaitFilters(args: any): boolean {
  return args?.agentEvent != null || args?.agentEventContains != null || args?.captureCategory != null || args?.captureContains != null;
}

function jsonOf(value: any): string {
  try { return JSON.stringify(value) ?? ''; } catch { return ''; }
}

function compactEvent(event: WaitEvent) {
  const json = jsonOf(event.data);
  return {
    seq: event.seq,
    ts: event.ts,
    type: event.type,
    data: json.length > EVENT_DATA_CAP ? { truncated: true, bytes: json.length, json: json.slice(0, EVENT_DATA_CAP) } : event.data,
  };
}

// The capture store keeps bytes as hex; an AI thinks in text. Decode UTF-8 when the bytes are
// valid UTF-8 (the Java layer captures UTF-8 plaintext), so CJK and ASCII markers are searchable
// and readable. Binary blobs decode to U+FFFD and are dropped.
function decodeUtf8(hex: unknown): string {
  if (typeof hex !== 'string' || !hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) return '';
  try {
    const text = Buffer.from(hex, 'hex').toString('utf8');
    return text.includes('\uFFFD') ? '' : text;
  } catch { return ''; }
}

// What captureContains searches: the readable metadata plus the decoded text of the byte fields.
function captureIndex(capture: WaitCapture): string {
  const parts: string[] = [];
  for (const key of ['sessionId', 'source', 'func', 'algo', 'op', 'category', 'preview']) {
    const value = capture[key];
    if (value != null) parts.push(String(value));
  }
  for (const key of ['hex', 'outHex', 'keyHex', 'ivHex']) {
    const text = decodeUtf8(capture[key]);
    if (text) parts.push(text);
  }
  return parts.join(' | ');
}

function compactCapture(capture: WaitCapture) {
  const { hex, ...rest } = capture;
  const hexText = typeof hex === 'string' ? hex : '';
  const text = decodeUtf8(hexText);
  return {
    ...rest,
    text: text ? text.slice(0, 256) : undefined,
    hexLen: hexText.length,
    ...(hexText.length && hexText.length <= CAPTURE_HEX_INLINE_CAP ? { hex: hexText } : {}),
  };
}

function matchEvent(args: any, event: WaitEvent): boolean {
  if (args.agentEvent != null && String(event.type) !== String(args.agentEvent)) return false;
  if (args.agentEventContains != null && !jsonOf(event).includes(String(args.agentEventContains))) return false;
  return true;
}

function matchCapture(args: any, capture: WaitCapture): boolean {
  if (args.captureCategory != null && String(capture.category) !== String(args.captureCategory)) return false;
  if (args.captureContains != null && !captureIndex(capture).includes(String(args.captureContains))) return false;
  return true;
}

export interface AgentWaitWindow {
  since?: number;            // host timestamp the wait started at (lookback already applied)
  afterEventSeq?: number;    // cursor mode: match events newer than this seq
  afterCaptureId?: number;   // cursor mode: match captures newer than this id
}

// Window rule per kind: a cursor (when given) is authoritative and ignores the timestamp;
// otherwise only records at/after `since` qualify. Both stores are append-ordered, so an
// out-of-window record means every older record is out of window too.
function inWindow(record: WaitEvent | WaitCapture, cursor: number | undefined, since: number): boolean {
  if (cursor != null) return Number((record as any).seq ?? (record as any).id) > cursor;
  return Number(record.ts) >= since;
}

// A wait that times out should still teach the AI something: what actually arrived inside the
// window while the filter did not match. Compact and bounded — this rides along the timeout reply.
export function agentWaitSightings(window: AgentWaitWindow, events: WaitEvent[], captures: WaitCapture[], limit = 5) {
  const sinceTs = Number.isFinite(Number(window?.since)) ? Number(window.since) : 0;
  const seenCaptures: any[] = [];
  const seenEvents: any[] = [];
  let captureTotal = 0;
  let eventTotal = 0;
  for (let i = captures.length - 1; i >= 0; i--) {
    const capture = captures[i];
    if (!capture) continue;
    if (!inWindow(capture, window?.afterCaptureId, sinceTs)) break;
    captureTotal++;
    if (seenCaptures.length < limit) seenCaptures.push(compactCapture(capture));
  }
  for (let i = events.length - 1; i >= 0; i--) {
    const event = events[i];
    if (!event) continue;
    if (!inWindow(event, window?.afterEventSeq, sinceTs)) break;
    eventTotal++;
    if (seenEvents.length < limit) seenEvents.push(compactEvent(event));
  }
  return { captures: seenCaptures, events: seenEvents, totals: { captures: captureTotal, events: eventTotal } };
}

export function findAgentWaitMatch(args: any, window: AgentWaitWindow, events: WaitEvent[], captures: WaitCapture[]): AgentWaitMatch | null {
  if (!hasAgentWaitFilters(args)) return null;
  const sinceTs = Number.isFinite(Number(window?.since)) ? Number(window.since) : 0;
  let hit: AgentWaitMatch | null = null;
  if (args.agentEvent != null || args.agentEventContains != null) {
    for (let i = events.length - 1; i >= 0; i--) {   // append order: newest is last
      const event = events[i];
      if (!event) continue;
      if (!inWindow(event, window?.afterEventSeq, sinceTs)) break;
      if (matchEvent(args, event)) { hit = { kind: 'event', item: compactEvent(event) }; break; }
    }
  }
  if (args.captureCategory != null || args.captureContains != null) {
    for (let i = captures.length - 1; i >= 0; i--) {
      const capture = captures[i];
      if (!capture) continue;
      if (!inWindow(capture, window?.afterCaptureId, sinceTs)) break;
      if (matchCapture(args, capture)) {
        const item = compactCapture(capture);
        if (!hit || Number(item.ts) >= Number(hit.item.ts)) hit = { kind: 'capture', item };
        break;
      }
    }
  }
  return hit;
}
