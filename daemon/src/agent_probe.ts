// Agent liveness and channel/engine diagnostics (host side).
//
// Three questions come before trusting a session, and all three used to be answerable only by
// firing a real command and waiting for a timeout:
//   - is the agent still answering, and how fast?            -> agentPing (the agent op existed
//     since v0.2 but NO host code ever sent it - the op-level audit found it as dead code)
//   - does the native hook engine actually fire in THIS target, and did it leave the RELRO page
//     protection alone?                                      -> hookEngineSelftest
//   - is the command channel still delivering whole frames?  -> protocolSelfTest
// The agent only executes; the "what does this result mean" logic lives in the pure verdict
// functions below so it is unit-tested without a device (the runner answers with raw fields).
import { sendCmd } from './service.ts';

export interface ProbeDeps {
  send: typeof sendCmd;
  now: () => number;
}

const defaultDeps: ProbeDeps = {
  send: sendCmd,
  now: () => performance.now(),
};

export interface PingResult { ok: true; op: 'ping'; latencyMs: number }

/** Round-trip liveness check. Throws when the agent does not answer (or answers without ok). */
export async function agentPing(session: string, deps: ProbeDeps = defaultDeps): Promise<PingResult> {
  const started = deps.now();
  const r = await deps.send(session, 'ping', {}, 5_000);
  const elapsed = deps.now() - started;
  if (!r?.ok) throw new Error(`agent ping failed: ${r?.error ?? 'no ok:true in the reply'}`);
  return { ok: true, op: 'ping', latencyMs: Math.max(0, Math.round(elapsed * 100) / 100) };
}

export interface EngineSelftestFields {
  commandOk?: boolean;
  error?: string;
  replaced?: number;
  fired?: boolean;
  protRestored?: boolean;
  origPerms?: string;
  slotPerms?: string;
  hitsBefore?: number;
  hitsAfter?: number;
}

export interface EngineVerdict { ok: boolean; verdict: string }

/**
 * Interpret a gothook_selftest result. Two independent things must hold: the hook fired (a close()
 * from agent code went through the replaced GOT slot) and the slot page protection was restored
 * (a build that leaves RELRO pages writable is itself a detection signal - the v26 footprint check
 * exists for the same reason).
 */
export function engineVerdict(r: EngineSelftestFields): EngineVerdict {
  // A failed COMMAND and a broken ENGINE are different findings: the fields are missing in the first
  // case, and reading that as "the engine cannot install" would send the operator hunting a bug that
  // is not there.
  if (r?.commandOk === false) {
    return { ok: false, verdict: `the selftest command itself failed: ${r?.error ?? 'the agent did not answer ok:true'}` };
  }
  const replaced = Number(r?.replaced ?? -1);
  const hits = Number(r?.hitsAfter ?? 0) - Number(r?.hitsBefore ?? 0);
  if (replaced <= 0) return { ok: false, verdict: `GOT slot was not replaced (replaced=${replaced}) - the hook engine cannot install into this module` };
  if (!r?.fired) return { ok: false, verdict: `hook installed but never fired (replaced=${replaced}, hits=${hits}) - the engine is not intercepting calls in this target` };
  if (!r?.protRestored) {
    return { ok: false, verdict: `hook fired (hits=${hits}) but the slot page protection was NOT restored (${r?.origPerms ?? '?'} -> ${r?.slotPerms ?? '?'}): this build leaves weakened RELRO behind and is detectable` };
  }
  return { ok: true, verdict: `GOT engine OK: hook fired (hits=${hits}) and the slot page protection was restored (${r?.origPerms ?? '?'})` };
}

export interface EngineSelftestResult extends EngineVerdict, EngineSelftestFields {
  /** The raw reply ok (the command ran). `ok` above is the VERDICT: the engine was verified. */
  commandOk: boolean;
  raw: any;
}

export async function hookEngineSelftest(session: string, deps: ProbeDeps = defaultDeps): Promise<EngineSelftestResult> {
  const raw = await deps.send(session, 'gothook_selftest', {}, 15_000);
  const verdict = engineVerdict({ ...(raw ?? {}), commandOk: raw?.ok === true });
  // Agent fields stay top level so the pre-existing consumers (the REST route, the v04/v26
  // acceptance scripts and the web diagnostics panel) keep reading replaced/fired/protRestored.
  // commandOk is passed INTO the verdict as well, so a failed command cannot be misread as a
  // broken engine (see engineVerdict).
  return { ...(raw ?? {}), ...verdict, commandOk: raw?.ok === true, raw };
}

export const FRAME_ECHO_TAIL = 'ADH_FRAME_TAIL_v1';

export interface FrameEchoFields { recvBytes?: number; tail?: string; padLen?: number; commandOk?: boolean; error?: string }
export interface FrameEchoVerdict { ok: boolean; tailOk: boolean; notTruncated: boolean; problems: string[] }

/**
 * The tail sits past the old 8192-byte single-line cap on purpose: if inbound framing regressed, the
 * tail comes back empty (or the frame never arrives) and this says so instead of reporting a pass.
 */
export function frameEchoVerdict(r: FrameEchoFields, expected: { tail: string; padLen: number }): FrameEchoVerdict {
  const problems: string[] = [];
  if (r?.commandOk === false) problems.push(`the frame_echo command failed: ${r?.error ?? 'no ok:true'}`);
  const tailOk = r?.tail === expected.tail;
  // padLen sits AFTER the pad in the frame, so a truncated frame comes back without it (or with a
  // wrong value). Checking the echo is a stronger signal than "the frame was longer than the pad".
  const padLenOk = Number(r?.padLen) === expected.padLen;
  const notTruncated = Number(r?.recvBytes ?? 0) > expected.padLen && padLenOk;
  if (!tailOk) problems.push(`tail mismatch: expected ${JSON.stringify(expected.tail)}, got ${JSON.stringify(r?.tail ?? null)}`);
  if (!notTruncated) problems.push(`the frame was truncated or malformed: recvBytes=${r?.recvBytes ?? 0} (must exceed padLen=${expected.padLen}) and the echoed padLen=${JSON.stringify(r?.padLen ?? null)} must match`);
  return { ok: tailOk && notTruncated, tailOk, notTruncated, problems };
}

export interface ProtocolSelftestResult extends FrameEchoVerdict {
  kb: number;
  sentPadLen: number;
  recvBytes: number;
  verdict: string;
}

/** Send one oversized frame and check it arrived whole. kb is clamped to 1..4096 (4MB). */
export async function protocolSelfTest(session: string, kb = 64, deps: ProbeDeps = defaultDeps): Promise<ProtocolSelftestResult> {
  // Same clamp as the REST route (they share this helper): 1..4096 KB, and only a MISSING size falls
  // back to the 64 KB default - an explicit 0 is clamped to 1 instead of silently meaning 64.
  const requested = kb === undefined || kb === null || (kb as unknown) === '' ? 64 : Number(kb);
  const n = Math.max(1, Math.min(4096, Number.isFinite(requested) ? Math.trunc(requested) : 64));
  const padLen = n * 1024;
  const r = await deps.send(session, 'frame_echo', { pad: 'A'.repeat(padLen), tail: FRAME_ECHO_TAIL, padLen }, 30_000);
  const check = frameEchoVerdict(r ?? {}, { tail: FRAME_ECHO_TAIL, padLen });
  return {
    ...check,
    kb: n,
    sentPadLen: padLen,
    recvBytes: Number(r?.recvBytes ?? 0),
    verdict: check.ok
      ? `channel OK: a ${padLen}-byte command arrived whole (recvBytes=${r?.recvBytes}) and the tail survived`
      : `channel BROKEN at ${n} KB: ${check.problems.join('; ')}`,
  };
}
