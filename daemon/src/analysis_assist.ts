// Evidence-based routing for low-context clients. No hooks, triggers or target writes here.
import { ANALYSIS_GUIDE_TOPICS, type AnalysisGuideTopic } from './analysis_guide.ts';

interface Session {
  sessionId: string; package: string; process: string; pid: number; online: boolean;
  starttimeTicks?: string; caps?: { ops?: string[] };
}
interface RecordRef {
  id: number; sessionId: string; func: string; algo?: string; hookId?: number; seq?: number;
  hex?: string; outHex?: string; keyHex?: string;
}
interface Health {
  dropped: number; jdropped: number; complete: boolean; ts: number;
  base?: { dropped: number; jdropped: number };
}
export interface AssessmentDeps {
  sessions: ReadonlyMap<string, Session>;
  captures: readonly RecordRef[];
  stats: ReadonlyMap<string, Health>;
  storeLoss: (session: string) => string | null;
  readHookStatus: (session: string) => Promise<any>;
  now: () => number;
}
export interface AssessmentOptions {
  topic: AnalysisGuideTopic; session?: string; hookId?: number; buffer?: string; tid?: number;
}
interface Next {
  tool: string; arguments: Record<string, unknown>; purpose: string; expect: string;
  effect: 'host-read' | 'target-read' | 'drain-existing-captures' | 'prepare-root-helper';
  when?: string;
}

function positive(v: unknown, name: string) {
  if (v !== undefined && (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > 0x7fffffff))
    throw new Error(`${name} must be a positive integer`);
}
const small = (v: unknown) => String(v ?? '').slice(0, 240);

export async function assessAnalysis(options: AssessmentOptions, deps: AssessmentDeps) {
  if (!ANALYSIS_GUIDE_TOPICS.includes(options.topic)) throw new Error('unknown analysis topic');
  positive(options.hookId, 'hookId'); positive(options.tid, 'tid');
  if (options.session !== undefined && (typeof options.session !== 'string' || !options.session || options.session.length > 256)) throw new Error('invalid session');
  if (options.buffer !== undefined && (typeof options.buffer !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(options.buffer) || BigInt(options.buffer) === 0n)) throw new Error('buffer must be a nonzero hex address');
  const now = deps.now(), session = options.session ? deps.sessions.get(options.session) : undefined;
  const report = {
    action: 'assess', topic: options.topic, observedAt: now, executedMutations: false,
    readOperations: [] as string[], stage: '', summary: '', facts: {} as Record<string, unknown>,
    missingEvidence: [] as string[], doNotConclude: [] as string[], next: null as Next | null,
    checkpoint: { tool: 'analysis_guide', arguments: { action: 'assess', ...options },
      note: 'Re-run to refresh live facts. This checkpoint carries identifiers, not keys, plaintext or a complete case history. A new session must be selected after reconnect.' },
    limits: ['Only current Host-retained records are inspected (at most 64); records and hook counters may cover different windows.',
      'No automatic trigger, hook install/unhook, restart, replay, root upload, or algorithm conclusion is performed.',
      'Proposed next calls may have the explicitly stated effects; execute them only within the authorized task.',
      'A stalled screen or a hung command is a state, not a diagnosis. Before this assessment is used to claim anti-debugging, hardening or injection detection, the ordinary causes must be ruled out on the device: a normal user-interaction gate (privacy consent, permission, login, SMS code, onboarding), a command that never reached the device, and a target that is simply idle. adb (dumpsys activity activities, uiautomator dump, screencap) is the supported channel for that check.'],
  };
  const finish = (stage: string, summary: string, next: Next | null, missing: string[] = [], forbidden: string[] = []) => {
    report.stage = stage; report.summary = summary; report.next = next;
    report.missingEvidence.push(...missing); report.doNotConclude.push(...forbidden);
    return report;
  };
  const guide = (topic: AnalysisGuideTopic): Next => ({ tool: 'analysis_guide', arguments: { topic }, effect: 'host-read',
    purpose: 'Read the focused workflow and its missing-input/failed-step branches.', expect: 'Ordered templates; replace variables with evidence before executing.' });
  if (!session) {
    const online = [...deps.sessions.values()].filter(s => s.online);
    report.facts = { onlineCandidates: online.slice(0, 8).map(s => ({ session: s.sessionId, package: s.package, process: s.process, pid: s.pid })), moreCandidates: online.length > 8 };
    return finish('choose-session', options.session ? 'The supplied session is unknown; it may have changed after reconnect.' : 'Select the intended process before assessing evidence.',
      { tool: 'process_list', arguments: {}, effect: 'host-read', purpose: 'Select an explicit session for the intended package/process.', expect: 'Use its actual sessionId; never silently switch processes.' }, ['Explicit current session.']);
  }
  report.facts.target = { session: session.sessionId, pid: session.pid, process: session.process, package: session.package,
    online: session.online, starttimeTicks: session.starttimeTicks ?? null };
  if (!session.online) return finish('session-offline', 'This session is offline; old addresses and thread IDs must not be reused in a replacement process.',
    { tool: 'process_list', arguments: {}, effect: 'host-read', purpose: 'Select the intended live process again.', expect: 'Re-establish buffer/TID evidence for the new session.' }, ['Current process identity.'], ['An old address remains valid after restart.']);
  const sid = session.sessionId, ops = session.caps?.ops;
  report.facts.agentCapabilitiesKnown = Array.isArray(ops);
  const records = deps.captures.filter(r => r.sessionId === sid).slice(-64);
  report.facts.captureWindow = { inspected: records.length, cap: 64, refs: records.slice(-8).map(r => ({
    id: r.id, func: small(r.func), algo: small(r.algo), hookId: r.hookId ?? null, seq: r.seq ?? null,
    hasOutput: !!r.outHex, hasKey: !!r.keyHex,
  })) };
  const health = deps.stats.get(sid), storeLoss = deps.storeLoss(sid);
  const dropped = health ? Math.max(0, health.dropped - (health.base?.dropped ?? 0)) + Math.max(0, health.jdropped - (health.base?.jdropped ?? 0)) : null;
  const stale = !health || !Number.isFinite(health.ts) || Math.abs(now - health.ts) > 30000;
  const knownLoss = !!storeLoss || (dropped ?? 0) > 0 || health?.complete === false;
  report.facts.captureHealth = { scope: 'last reported session ring window relative to its baseline; Host retention is separate', asOf: health?.ts ?? null, stale, dropped, storeLoss: storeLoss ? small(storeLoss) : null,
    complete: knownLoss ? false : stale ? null : health?.complete === true ? true : null };
  if (knownLoss) report.doNotConclude.push('The retained records cover the whole request or execution; known capture/store loss limits the conclusion.');
  if (stale) report.missingEvidence.push('Fresh capture-health accounting; an old snapshot is not current completeness proof.');

  if (options.topic === 'writer' && options.buffer && options.tid) {
    report.facts.suppliedWatch = { addr: options.buffer, tid: options.tid, provenance: 'caller-supplied; writer role not established by this assessment' };
    return finish('watch-inputs-supplied', 'A candidate address and thread were supplied. Validate them against the actual operation before arming; this assessment has not observed a write.',
      { tool: 'root_watch', arguments: { action: 'prepare' }, effect: 'prepare-root-helper', purpose: 'Prove root/kernel hardware support before collecting.', expect: 'Require ok=true and selfTest.complete=true; then follow the writer guide start template with these observed inputs.' },
      ['Evidence that this existing TID writes this live buffer; correct alignment/width.'], ['A supplied address/TID is automatically the correct writer.', 'A diagnostic thread candidate proves a write.']);
  }
  if (options.topic === 'trace') {
    if (!ops?.includes('qbdi_read')) return finish('trace-capability-unverified', 'This running build has not advertised paged trace support.',
      { tool: 'capabilities', arguments: { session: sid }, effect: 'host-read', purpose: 'Verify the running agent build, not just source code.', expect: 'Require qbdi_read for trace_session; absence cannot be silently replaced by a clipped legacy trace.' }, ['Advertised qbdi_read capability.']);
    return finish('trace-needs-call-evidence', 'Paged trace support is advertised. An actual entry, arguments, QBDI path and authorization for side effects are still required.', guide('trace'),
      ['Verified function entry and argument values; staged QBDI library and authorized active invocation.'], ['A replay or module-only trace is a complete recording of the original execution.']);
  }
  let status: any = null;
  if (ops?.includes('native_hook') && options.topic !== 'start') {
    report.readOperations.push('native_hook action=status (3 second transport budget; no install or drain)');
    try {
      const reply = await deps.readHookStatus(sid);
      if (reply?.ok !== true || !Array.isArray(reply.status?.hooks)) {
        report.facts.hookStatusError = small(reply?.error ?? 'missing hook status');
        return finish('hook-status-rejected', 'A reply arrived, but it did not provide usable hook status. This is different from a transport timeout.',
          { tool: 'capabilities', arguments: { session: sid }, effect: 'host-read', purpose: 'Compare the actual agent capability and the returned error.', expect: 'An unsupported operation or bad reply is not proof of a frozen process.' }, ['Usable hook status.']);
      }
      status = reply.status;
    } catch (error) {
      report.facts.hookStatusError = small((error as Error).message);
      return finish('agent-status-unavailable', 'The status query failed. Online socket metadata does not establish that the command channel responds.',
        { tool: 'runtime_diagnostics', arguments: { session: sid, limit: 32 }, effect: 'target-read', purpose: 'Inspect procfs identity, freezer and tracing facts independently of the agent channel.', expect: 'Read actual facts/errors; root may be unavailable. Do not infer anti-debugging from a timeout.' },
        ['Independent process/thread diagnosis.'], ['The timeout proves anti-debugging, a deadlock, or that the process exited.']);
    }
  }
  const active: any[] = Array.isArray(status?.hooks) ? status.hooks.slice(0, 16) : [];
  const inactive: any[] = Array.isArray(status?.inactive) ? status.inactive.slice(0, 16) : [];
  report.facts.hooks = { statusKnown: !!status, free: status?.slots?.free ?? null, retired: status?.slots?.retired ?? null,
    active: active.slice(0, 8).map(h => ({ id: h.id, mode: small(h.mode), symbol: small(h.symbol), hits: h.hits ?? null })) };
  const selected = options.hookId === undefined ? active.length === 1 ? active[0] : null : [...active, ...inactive].find(h => h.id === options.hookId);
  if (options.hookId !== undefined && !selected && status) return finish('hook-not-found', 'The supplied hookId is absent from this session status. Retained data is not proof that this hook is still active.',
    { tool: 'native_hook', arguments: { session: sid, action: 'status' }, effect: 'target-read', purpose: 'Select the actual hookId or inspect its inactive/retired state.', expect: 'Use an actual id from this session, not an id from another run.' }, ['Current hook identity.']);
  if (!selected && active.length > 1 && options.topic !== 'crypto') return finish('choose-hook', 'Several hooks are active. Choosing the newest would not establish which one belongs to this investigation.', guide('stuck'), ['Explicit hookId for the operation under investigation.']);
  const wantedHook = options.hookId ?? selected?.id;
  const hookRecords = wantedHook !== undefined ? records.filter(r => r.hookId === wantedHook) : records;
  if (selected) {
    report.facts.selectedHook = Object.fromEntries(['id', 'mode', 'state', 'hits', 'selected', 'filtered', 'sampledOut', 'throttled', 'limited', 'emitted', 'maxEvents', 'sampleEvery', 'inFlight'].map(k => [k, selected[k] ?? null]));
    const read: Next = { tool: 'native_look', arguments: { action: 'read', session: sid, hookId: selected.id }, effect: 'drain-existing-captures', purpose: 'Drain existing events and read matching before/after records with explicit counters and errors.', expect: 'Join only the same hook invocation; inspect drainError/observationError and capture completeness.' };
    if (selected.inFlight > 0 && selected.emitted === 0) return finish('callbacks-in-flight', 'Callbacks are still in flight and no event has yet been submitted. A concurrent snapshot cannot establish suppression or a missing final output.',
      { ...read, when: 'After the intended call has returned, or after an appropriate bounded observation interval.' }, ['A settled observation and any after-call records.']);
    if (selected.hits === 0) return finish('await-known-trigger', 'The current hook counter is zero. Any retained records may belong to an earlier observation window.',
      { ...read, when: 'After triggering the intended operation on the intended process; do not repeatedly poll without a trigger.' }, ['A known operation that reaches this exact target.'], ['This function is unrelated to the algorithm merely because the current counter is zero.']);
    if (selected.filtered > 0 && selected.selected === 0) return finish('all-hits-filtered', 'Current counters include filtered calls and no selected calls. Check the configured filters; live counters can change concurrently.', read,
      ['A call known to satisfy the intended thread/return-address/register filter.'], ['No traffic reached the function.', 'Removing filters automatically is an equivalent experiment.']);
    if (selected.selected > 0 && selected.emitted === 0 && (selected.sampledOut > 0 || selected.throttled > 0 || selected.limited > 0)) return finish('observation-suppressed', 'Calls were selected, and sampling/throttle/quota counters report suppressed observations; no observation event has been submitted.', read,
      ['The intended observation policy and a selected hit admitted by it.'], ['No selected calls happened.', 'Suppressed observation means selected replacements were disabled.']);
    if (selected.selected > 0 && selected.emitted === 0) return finish('submission-not-established', 'Selected calls exist, but this snapshot neither contains submitted events nor proves a suppression cause.', read, ['A settled counter snapshot or corresponding event.']);
    if (selected.emitted > 0 && !hookRecords.length) return finish('submitted-without-retained-record', 'The hook submitted events, but none for this hook remain in the inspected Host window. Pending drain and retention/loss are different possibilities.', read,
      ['A successful drain and corresponding retained records.'], ['Submitted means delivered and retained.', 'An empty window proves no function call happened.']);
  }
  if (options.topic === 'writer') return finish('writer-needs-buffer-and-thread', 'A hardware watchpoint needs evidence for both a live buffer and its writer thread.',
    hookRecords.length ? { tool: 'capture_detail', arguments: { id: hookRecords.at(-1)!.id }, effect: 'host-read', purpose: 'Inspect the exact record for pointer, length, phase and invocation provenance.', expect: 'A pointer argument is not automatically an output buffer; correlate before/after and the actual writing thread.' } : guide('writer'),
    [!options.buffer ? 'Observed live buffer address.' : '', !options.tid ? 'Existing writer TID tied to the intended operation.' : ''].filter(Boolean), ['A random eligible thread or readable pointer is a suitable writer observation.']);
  const record = hookRecords.at(-1);
  if (record && options.topic === 'crypto' && record.hex && record.outHex) return finish('verify-observed-boundary', 'One retained record contains input/output fields. Test the boundary without assuming it is the final requested signature.',
    { tool: 'crypto_evidence', arguments: { action: 'analyze', observations: [{ id: `capture-${record.id}`, role: 'unspecified', input: { captureId: record.id, field: 'payload' }, output: { captureId: record.id, field: 'output' }, ...(record.keyHex ? { key: { captureId: record.id, field: 'key' } } : {}) }] }, effect: 'host-read',
      purpose: 'Check exact same-record bytes with the supported candidates; selectors preserve actual length/loss metadata.', expect: 'Output/key original lengths are not recorded by whole-capture selectors: expect unavailable until expectedBytes is independently established and supplied. Never substitute the received prefix length. Check collection completeness separately; a digest mismatch does not exclude ciphers or custom transformations.' },
    ['Independently established output length, and key length when keyed, before declaring byte completeness.', 'Evidence linking this boundary to the requested final field.'], ['The capture algorithm label or an intermediate primitive match proves the whole algorithm.', 'The received output/key prefix length proves the original length.']);
  if (record) return finish('inspect-retained-evidence', 'Retained records are available; their relationship to the requested computation is not established yet.',
    { tool: 'capture_detail', arguments: { id: record.id }, effect: 'host-read', purpose: 'Inspect exact bytes, original length and invocation identity before pairing or choosing an algorithm.', expect: 'Preserve raw bytes and explicit pairing. Do not combine nearby timestamps or different seq values.' }, ['Relevant complete input/output pairing.']);
  if (status?.slots?.free === 0) return finish('hook-budget-exhausted', 'No free physical hook slots remain. Unhook does not replenish permanently retired slots.', guide('stuck'),
    ['An authorized new-process workflow if further hook installations are required.'], ['All other analysis is impossible: retained evidence and root-side observation may still be usable.']);
  return finish('evidence-not-yet-retained', 'No records for this investigation were found in the bounded current-session window. This is not proof that no cryptography ran.',
    { tool: 'capabilities', arguments: { session: sid }, effect: 'host-read', purpose: 'Choose supported observation before setting up a controlled capture/trigger.', expect: 'Use the crypto/writer guide for setup, then trigger one known operation and reassess; never invent a Java/native trigger.' },
    ['An authorized observation setup, one known operation, and retained relevant records.'], ['No retained records means no encryption/signing.', 'An online session alone is a responsive or complete observation.']);
}
