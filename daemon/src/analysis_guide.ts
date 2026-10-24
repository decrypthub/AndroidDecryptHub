// Host-only help, served through MCP so remote clients need no repository access.
// Templates are instructions, never executed here; all $variables need live evidence.
export const ANALYSIS_GUIDE_TOPICS = ['start', 'writer', 'crypto', 'trace', 'stuck'] as const;
export type AnalysisGuideTopic = typeof ANALYSIS_GUIDE_TOPICS[number];

export const MCP_INSTRUCTIONS = 'ADH is an Android runtime analysis workbench. Start with analysis_guide(topic="start"), ' +
  'then process_list and capabilities for one explicit session; sessions change after reconnect. ' +
  'When context is missing, call analysis_guide(action="assess",topic="stuck",session=theSelectedId,hookId=theActualIdIfKnown). ' +
  'Assessment reads current Host evidence and at most one bounded native-hook status query, then returns facts, missing evidence, one proposed next call and a resumable identifier checkpoint; it installs nothing. ' +
  'Use analysis_guide(topic="writer") to find who writes a known buffer via root_watch; ' +
  'topic="crypto" for paired input/output evidence, "trace" for bounded instruction records, and "stuck" for failures. ' +
  'Guides return ordered tool-call templates, prerequisites, checks and failure branches, without executing target operations. ' +
  'Replace $variables from live results, never guess an address, TID, key or invocation pairing. ' +
  'An online socket does not prove responsiveness; use runtime_diagnostics when commands hang. ' +
  'Check capture loss and completeness before making claims. In-hook QBDI is replay with side effects and incomplete context; ' +
  'active-call traces cover the instrumented module, not the original whole execution. A primitive match does not prove a final signature.';

interface Step {
  goal: string;
  tool: string;
  arguments: Record<string, unknown>;
  check: string;
  onFailure?: string;
}
interface Guide {
  title: string;
  prerequisites: string[];
  variables: Record<string, string>;
  steps: Step[];
  limits: string[];
}

const guides: Record<AnalysisGuideTopic, Guide> = {
  start: {
    title: 'Choose a target and a workflow',
    prerequisites: ['Connected to ADH through MCP; fetching this guide does not require an online agent or root.'],
    variables: { session: 'Exact sessionId selected from process_list using the intended package/process; reselect after reconnect.' },
    steps: [
      { goal: 'Choose the intended process explicitly.', tool: 'process_list', arguments: {}, check: 'Use sessionId, package, process, online and PID; never silently choose another process.' },
      { goal: 'Read capabilities of that running build.', tool: 'capabilities', arguments: { session: '$session' }, check: 'Inspect caps.ops and limits. Different processes may run different agent builds.' },
      { goal: 'Assess actual retained evidence without reconstructing the full conversation.', tool: 'analysis_guide', arguments: { action: 'assess', topic: 'start', session: '$session' }, check: 'Read stage/facts/missingEvidence/doNotConclude and the proposed next call. Then choose writer, crypto, trace or stuck for the intended task.' },
    ],
    limits: ['Guidance is not an automatic algorithm solver.', 'No session: diagnose connection/injection setup; do not fabricate a session.', 'Purpose-built recipes are listed by recipe(action="list"); inspect their effects and prerequisites before running one.'],
  },
  writer: {
    title: 'Find the real writer of a known buffer',
    prerequisites: ['A rooted supported device, an online session, a live target buffer address, and evidence for the thread that will write it.', 'Obtain the buffer from native_hook mem/memAfter or native_look/live_captures; use memory_read when necessary. An address is not inferred from buffer contents.'],
    variables: {
      session: 'Selected sessionId from process_list.',
      tid: 'Existing writer TID, corroborated by capture/trigger evidence and runtime_diagnostics. eligibleForRootWatch means a valid candidate, not proof that it writes this buffer.',
      buffer: 'Live, 8-byte-aligned hex address in that same process; choose a smaller aligned width when needed.',
      runId: 'id returned by root_watch start. This is different from the sessionId or hookId.',
      pc: 'Relevant event ip/pc returned by root_watch read; inspect nearby instructions rather than assuming zero sampling skid.',
    },
    steps: [
      { goal: 'Check identity, generation, freezer state and existing threads.', tool: 'runtime_diagnostics', arguments: { session: '$session', limit: 32 }, check: 'Verify process identity and inspect threads[].eligibleForRootWatch, tid and frozen; page using page.nextTid/afterTid if needed.', onFailure: 'No root or unreadable facts: report the missing evidence. Frozen/exited/mismatched process: resolve that state before collecting; this tool does not resume it.' },
      { goal: 'Upload the collector and prove hardware support.', tool: 'root_watch', arguments: { action: 'prepare' }, check: 'Expect ok=true and selfTest.complete=true. An ambiguous device requires an explicit serial from the operator.', onFailure: 'Missing helper: the Host needs bash tools/build_root_watch.sh. A remote AI cannot assume repository shell access. Root/kernel errors are actual failures, not permission to alter SELinux.' },
      { goal: 'Arm before triggering the known operation on that same thread.', tool: 'root_watch', arguments: { action: 'start', session: '$session', tid: '$tid', addr: '$buffer', width: 8, mode: 'w', durationMs: 5000, maxEvents: 128, stackBytes: 8192 }, check: 'Keep returned id. Trigger only the intended operation after start succeeds; do not replace a natural-execution observation with an arbitrary replay.', onFailure: 'Wrong/expired TID, stale generation or bad address: refresh facts. native_call runs a short-lived worker; a gettid result from it is not a persistent writer thread.' },
      { goal: 'Read bounded kernel evidence.', tool: 'root_watch', arguments: { action: 'read', id: '$runId', afterSeq: 0, limit: 8, registers: true }, check: 'Use nextSeq/hasMore for paging; query status until running=false. Inspect complete, summary.lost/throttles and stopReason. Request stackAddress/stackSize explicitly to read a bounded saved stack window.' },
      { goal: 'Inspect the recorded instruction location.', tool: 'memory_disasm', arguments: { session: '$session', addr: '$pc', size: 64 }, check: 'Correlate the writer, registers and saved stack with the same captured computation; a later heap read may observe reused memory.' },
      { goal: 'Stop an unfinished collection when no longer needed.', tool: 'root_watch', arguments: { action: 'stop', id: '$runId' }, check: 'Poll status for the final accounting. Event limits, dropped/throttled events or manual stop limit the conclusion.' },
    ],
    limits: ['One existing TID and one small watched region; future threads are not inherited.', 'A PC/register/stack sample is not an atomic snapshot of the whole heap or an automatic key identification.', 'w is verified on the reference ROM; r/rw remain separately unverified and x has not produced a verified hit.'],
  },
  crypto: {
    title: 'Verify paired bytes without promoting an intermediate match to the final algorithm',
    prerequisites: ['Complete input/output bytes, an explicit pairing basis, and actual key/mask bytes for candidates that need them.'],
    variables: { captureId: 'Exact capture id returned by live_captures; identify the particular mem window with reg/offset rather than nearest timestamp.' },
    steps: [
      { goal: 'Inspect supported candidates.', tool: 'crypto_evidence', arguments: { action: 'algorithms' }, check: 'Use known candidates and observed parameters; the tool does not derive an unknown key or mask.' },
      { goal: 'Inspect one exact record before choosing its fields.', tool: 'capture_detail', arguments: { id: '$captureId' }, check: 'Check session/PID/TID, hookId/seq/callId, original length, phase, requested/got and truncation. Same TID/time alone does not prove pairing.' },
      { goal: 'Learn the complete observation shape with a public format-only vector.', tool: 'crypto_evidence', arguments: {
        action: 'analyze', observations: [{ id: 'public-format-example', role: 'intermediate', algorithms: ['md5'],
          pairing: { basis: 'analyst', note: 'Public abc MD5 vector demonstrates input format only; this is not target evidence.' },
          input: { utf8: 'abc', expectedBytes: 3, source: { kind: 'manual', note: 'Public example only.' } },
          output: { hex: '900150983cd24fb0d6963f7d28e17f72', expectedBytes: 16, source: { kind: 'manual', note: 'Public expected digest.' } },
        }],
      }, check: 'This example should match once. For real data replace the entire observation with actual sources; a selector can be {captureId,field:"mem",reg:"x0",offset:0}. Whole-capture selectors also support payload/key/output. Use key or params:{add,xor} when required.' },
    ],
    limits: ['Select exactly one hex/b64/utf8 encoding per explicit field; preserve raw JSON/request bytes.', 'Missing/truncated/mispaired bytes are unavailable, not a mismatch. Never relabel a prefix complete or override known capture loss.', 'Inspect analysisComplete and captureCollectionComplete separately. Matching one intermediate stage does not prove the final field, initialization, causality or cross-device derivation.', 'Use action save/read/list/drop for the private ledger. Ordinary read is bounded; includePayload=true explicitly expands raw material.'],
  },
  trace: {
    title: 'Record and query a bounded active-call instruction trace',
    prerequisites: ['An actual function entry and its integer/pointer arguments, a suitable QBDI library already staged on the device, and explicit authorization for the call and its side effects.', 'capabilities must advertise qbdi_read; old agents must be updated rather than silently using a shorter legacy reply.'],
    variables: { session: 'Selected online sessionId.', qbdiPath: 'Existing absolute device path to the matching QBDI library.', entry: 'Verified executable function entry, not an arbitrary BL inside it.', integerArgs: 'Array of at most eight unsigned integer/pointer strings from the real call.', traceId: 'Host id returned by trace_session record.' },
    steps: [
      { goal: 'Load QBDI explicitly.', tool: 'trace_session', arguments: { action: 'prepare', session: '$session', path: '$qbdiPath', confirm: true }, check: 'Check load success before recording; this does not upload a missing file.' },
      { goal: 'Record a deliberately active invocation.', tool: 'trace_session', arguments: { action: 'record', session: '$session', addr: '$entry', args: '$integerArgs', confirm: true, capacity: 65536, budget: 200000, timeMs: 4000 }, check: 'Keep id; inspect stopReason, retvalValid, complete, transportComplete, truncated, coverage and released. Refuse replay when the intended side effects are not authorized.' },
      { goal: 'Query only useful pages.', tool: 'trace_session', arguments: { action: 'query', id: '$traceId', afterSeq: -1, limit: 32 }, check: 'Use nextAfterSeq/more, or pc/minPc/maxPc/mnemonic filters; stats summarizes the stored records.' },
      { goal: 'Trace a register dependency conservatively.', tool: 'trace_session', arguments: { action: 'slice', id: '$traceId', register: 'x0', maxScan: 4096 }, check: 'A barrier/unresolved register remains unresolved; memory aliases, flags, vectors and external calls need extra evidence.' },
    ],
    limits: ['Virtual-stack active call, instrumented-module coverage; not the original complete application execution.', 'In-hook traceInsns is a separate replay with incomplete context and side effects before the original runs again; absence in that replay is not whole-path exclusion.', 'The cooperative time guard cannot interrupt a blocking external native call.'],
  },
  stuck: {
    title: 'Diagnose missing events and unresponsive commands',
    prerequisites: ['Retain the explicit session and actual error text; do not guess that every timeout is anti-debugging.'],
    variables: { session: 'Known sessionId, including an offline one for runtime_diagnostics.', hookId: 'id of the hook you actually armed.' },
    steps: [
      { goal: 'Interpret current counters and retained records first.', tool: 'analysis_guide', arguments: { action: 'assess', topic: 'stuck', session: '$session', hookId: '$hookId' }, check: 'Read facts and missingEvidence. Assessment performs at most one bounded read-only native hook status query; it does not install, drain or trigger anything. A proposed next call is not an executed call.' },
      { goal: 'Inspect process facts independently of the agent channel.', tool: 'runtime_diagnostics', arguments: { session: '$session', limit: 32 }, check: 'Distinguish frozen, traced, process-exited, identity-mismatch, running and unknown. Check errors and completeness of thread paging.' },
      { goal: 'Read stored hook evidence and observation counts.', tool: 'native_look', arguments: { action: 'read', session: '$session', hookId: '$hookId' }, check: 'Distinguish hits=0 from filtered/sampledOut/throttled/limited, stored record loss, drainError and observationError.', onFailure: 'Unknown hook/session: re-list sessions and actual hook status. Do not invent a replacement hookId.' },
      { goal: 'Inspect current physical hook budget when the agent responds.', tool: 'native_hook', arguments: { action: 'status', session: '$session' }, check: 'Non-default new observation controls require observationControlsVersion>=1. Retired slots are not reclaimed by unhook; exhausted 16-slot budget requires a new target process, never an automatic restart.' },
    ],
    limits: ['No hardware events can also mean wrong address/TID, no trigger, a frozen thread, or an unsupported kernel; absence alone proves none of these.', 'Missing facts stay unknown; report the failed prerequisite instead of silently dropping filters or substituting replay.', 'Read diagnostics first; target restarts and other changes require an authorized workflow.'],
  },
};

export function analysisGuide(topic: unknown = 'start') {
  if (typeof topic !== 'string' || !Object.hasOwn(guides, topic)) throw new Error(`topic must be ${ANALYSIS_GUIDE_TOPICS.join('|')}`);
  return { topic, executesTools: false, templateRule: 'These are templates, not ready-to-run calls. Replace each $variable with the correct typed value from live evidence before executing; never fabricate a value.',
    availableTopics: ANALYSIS_GUIDE_TOPICS, ...structuredClone(guides[topic as AnalysisGuideTopic]) };
}
