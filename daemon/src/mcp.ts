// mcp.ts — MCP Server (Streamable HTTP / JSON-RPC).
// Exposes the workbench Service Layer as MCP tools for AI clients. Shares the same
// logic as the REST API (no duplicate business logic) — handlers delegate to service.ts
// primitives (agentCmd/dumpBuf/dumpRegion/dumpAllDex/...) + state.ts (captures/...).
// Adding a tool = add one entry to MCP_TOOLS below.
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeSo, cryptoConstScan, svcScan, disasmSo } from './analysis.ts';
import { parseDex, cryptoScan, searchDex, invokeXref, extractMethodCode, analyzeCoverage, rebuildStandardDex, recoverFromSnapshots } from './dex.ts';
import { ensureDexIndex, searchDexIndex, listDexReflections } from './dex_index.ts';
import { agentCmd, dumpAllDex, dumpBuf, dumpBufPath, dumpRegion, pickSid, repairDexHeader, sessionForPackage } from './service.ts';
import { liveDisasm } from './memory.ts';
import { watchSyscalls, attributeSite, syscallName } from './syscall_watch.ts';
import { nativeBacktrace } from './backtrace.ts';
import { traceDigest } from './trace_digest.ts';
import { syscallDigest } from './syscall_digest.ts';
import { javaTraceStart, javaTraceDigest, javaTraceStop } from './java_trace.ts';
import { nativeHookAll, nativeUnhookAll } from './native_hook_all.ts';
import { normalizeThrottleMs } from './native_hook_args.ts';
import { agentPing, hookEngineSelftest, protocolSelfTest } from './agent_probe.ts';
import { listDeviceDir, readDeviceFile } from './fs_browse.ts';
import { syscallTraceStart, syscallTraceDigest, syscallTraceStop } from './syscall_trace.ts';
import { backendMatrix, classifySession } from './backends.ts';
import { automation } from './automation.ts';
import { agentWaitSightings, findAgentWaitMatch, hasAgentWaitFilters } from './agent_events.ts';
import { implicitSelectorFor, selectorFrom } from './phone_selectors.ts';
import { PhoneSkillStore, resolveSkillInputs, skillPreflightIssues } from './phone_skills.ts';
import { normalizeAxis, swipePath } from './phone_gestures.ts';
import { isSettled, noteSample, screenSignature } from './phone_stability.ts';
import { resolveTemplates } from './phone_templates.ts';
import { renderScreenText } from './phone_text.ts';
import { blockedPackageFromError, needsDismissRetry, openOutcomeHint } from './phone_foreground.ts';
import { recordBlockedPackage } from './phone_blocked.ts';
import { sessions, dumps, captures, captureTimers, events, agentCursor, DATA_DIR, SANDBOX, settings, CAPTURES, cryptoIdentify } from './state.ts';
import type { DumpMeta } from './state.ts';

const S = { type: 'string' }, N = { type: 'number' };
export const MCP_TOOLS: { name: string; description: string; inputSchema: any; handler: (a: any) => Promise<any>; raw?: boolean }[] = [
  { name: 'process_list', description: 'List connected target agent sessions', inputSchema: { type: 'object', properties: {} }, handler: async () => [...sessions.values()] },
  { name: 'backends', description: 'Injection-backend matrix: sessions by entry, host-side Frida Gadget cache + loader command, device-side backend pointers. Pass session to classify which injection paths are really loaded in that process (zygisk / xposed_module / frida_gadget / self_load).', inputSchema: { type: 'object', properties: { session: S } }, handler: async (a) => { const m = backendMatrix(); return a.session ? { ...m, sessionBackends: await classifySession(a.session) } : m; } },
  { name: 'dumps_list', description: 'List captured dump artifacts (dex/so/region)', inputSchema: { type: 'object', properties: {} }, handler: async () => [...dumps.values()] },
  { name: 'compat_probe', description: 'Self-assess agent env + injection footprint: tracer/seccomp/backends/exec/anon/rwx', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'compat_probe') },
{ name: 'jni_onload', description: 'List, hook, unhook, inspect or manually invoke JNI_OnLoad. hook/call work on an already-loaded module; watch arms a one-shot LOAD-TIME interception: the agent hooks the dlopen entry point and patches the JNI_OnLoad of that module as soon as it is mapped, before the VM calls it (skipOriginal+returnValue can then replace that load-time call). call is dangerous and requires confirm:true. Events are emitted as JNI_ONLOAD with phase=manual|load.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['list', 'hook', 'unhook', 'call', 'status', 'watch', 'unwatch'] }, module: S, confirm: { type: 'boolean' }, skipOriginal: { type: 'boolean' }, returnValue: N }, required: ['action'] }, handler: (a) => { if (a.action === 'call' && a.confirm !== true) return Promise.resolve({ ok: false, error: 'jni_onload call requires confirm:true' }); return agentCmd(a.session, 'jni_onload', { action: a.action, module: a.module ?? '', skipOriginal: a.skipOriginal ? 'true' : 'false', returnValue: String(a.returnValue ?? 0) }, 30_000); } },
{ name: 'jni_hook', description: 'Install, remove or inspect the global JNIEnv->RegisterNatives hook. Each registration emits a JNI_NATIVE capture event with class, method, signature and native function pointer.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['install', 'uninstall', 'status'] } }, required: ['action'] }, handler: (a) => agentCmd(a.session, 'jni_hook', { action: a.action }, 20_000) },
{ name: 'jni_env_hook', description: 'Install, remove or inspect table-slot hooks on individual JNIEnv function-table entries (FindClass / GetMethodID / GetStaticMethodID / NewStringUTF / GetStringUTFChars / GetFieldID / GetStaticFieldID / byte-array read+writeback including the primitive-array critical pair, plus every Call*Method / NewObject family in all three JNI forms - varargs, V and A - with resolved member label and rendered argument values; wildcard patterns install or remove whole families at once). Each captured call emits a JNI_ENV event up to a per-slot budget (then only hit/drop counters move); the hook swaps one JNIEnv table slot, so uninstall restores the original pointer and status reports the live slot value next to original.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['install', 'uninstall', 'status'] }, function: { type: 'string', description: 'Fixed entry (GetStringUTFChars / FindClass / GetMethodID / GetStaticMethodID / NewStringUTF / GetFieldID / GetStaticFieldID / GetByteArrayElements / SetByteArrayRegion / ReleaseByteArrayElements / GetByteArrayRegion / GetPrimitiveArrayCritical / ReleasePrimitiveArrayCritical) or a Call* family in any of the three JNI forms: CallObjectMethod[V|A], CallBooleanMethod[V|A], CallByteMethod[V|A], CallCharMethod[V|A], CallShortMethod[V|A], CallIntMethod[V|A], CallLongMethod[V|A], CallFloatMethod[V|A], CallDoubleMethod[V|A], CallVoidMethod[V|A], CallStaticObjectMethod[V|A], CallStaticBooleanMethod[V|A], CallStaticByteMethod[V|A], CallStaticCharMethod[V|A], CallStaticShortMethod[V|A], CallStaticIntMethod[V|A], CallStaticLongMethod[V|A], CallStaticFloatMethod[V|A], CallStaticDoubleMethod[V|A], CallStaticVoidMethod[V|A], NewObject[V|A]. Wildcards install/uninstall many slots at once: "*" or "all" (every entry) or a prefix such as "CallIntMethod*" / "Call*"; the reply reports applied/failed. Status reports per slot installed/active/hits/dropped/slotValue/original/last, so the most recent event of a slot survives a flooded capture ring. The agent rejects unknown names.' } }, required: ['action'] }, handler: (a) => agentCmd(a.session, 'jni_env_hook', { action: a.action, function: a.function ?? '' }, 20_000) },
{ name: 'javahook_probe', description: 'Probe the optional statically linked LSPlant Java-method hook backend: compile-time availability and one-time ART initialization status. It does not install a hook by itself.', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'javahook_probe', {}, 20_000) },
{ name: 'java_hook', description: 'Install, remove or inspect Java method hooks through the LSPlant backend. action:hookAll installs every method of one class in a single call and returns hookIds plus matched (how many methods matched) - hooking all overloads or a whole class no longer needs a hand-written loop. Filter semantics differ per action: for action:hook, params is the exact parameter-type list and an empty list means a no-arg method; for action:hookAll, an empty/omitted method or params means ANY (the "*" spelling is also accepted). matched is the size of the match set and never shrinks to the install count, so a batch cut short by limit (clamped to the 16-slot ceiling and echoed back as limit) or by per-method failures is visible: the response then carries partial:true, plus matchedCapped/hookIdsTruncated when the 64-member collection budget or the response buffer was hit. stack:true captures a bounded caller chain at the hit (Class#method:line, innermost first, hook plumbing filtered) and reports it as stack in every JAVA_HOOK event plus lastStack in status - the Java analogue of the native backtrace; off by default because it walks the stack on every hit. params is a comma-separated Java parameter-type list (empty means no-arg); the target class is loaded through the app ClassLoader (inherited members are resolved through the superclass chain and the signature reports the declaring class; method "<init>" hooks a constructor, whose callback sees the arguments and whose result must remain the new object, so skipOriginal/returnValue are rejected for constructors). Multiple hooks are supported (bounded); status lists every hook with hit count, last argument, last return value and last error. Each callback also emits a JAVA_HOOK event into the bounded live-capture stream.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['hook', 'hookAll', 'unhook', 'status'] }, hookId: N, className: S, method: S, params: S, skipOriginal: { type: 'boolean' }, returnValue: S, argIndex: N, argValue: S, stack: { type: 'boolean' }, limit: N }, required: ['action'] }, handler: (a) => agentCmd(a.session, 'java_hook', { action: a.action === 'hookAll' ? 'hook_all' : a.action, limit: a.limit ?? 0, hookId: a.hookId ?? 0, className: a.className ?? '', method: a.method ?? '', params: a.params ?? '', skipOriginal: a.skipOriginal ? 'true' : 'false', returnValue: a.returnValue ?? '', argIndex: a.argIndex ?? -1, argValue: a.argValue ?? '', stack: a.stack ? 'true' : 'false' }, 30_000) },
{ name: 'java_enum', description: 'Enumerate a live Java class through reflection: modifiers, superclass, interfaces, constructors, overloaded methods and fields. Read-only and uses the app ClassLoader.', inputSchema: { type: 'object', properties: { session: S, className: S }, required: ['className'] }, handler: (a) => agentCmd(a.session, 'java_enum', { className: a.className }, 20_000) },
{ name: 'java_call', description: 'Invoke a live Java method through reflection. params is a comma-separated parameter-type list; args is a JSON array of string/number/boolean/null values; field names a static field holding the receiver for instance methods. Returns the original result or a fail-loud exception.', inputSchema: { type: 'object', properties: { session: S, className: S, method: S, params: S, field: S, args: { type: 'array' } }, required: ['className', 'method'] }, handler: (a) => agentCmd(a.session, 'java_call', { className: a.className, method: a.method, params: a.params ?? '', field: a.field ?? '', args: JSON.stringify(a.args ?? []) }, 20_000) },
{ name: 'native_hook', description: 'Install, remove or inspect native hooks. backtrace:true makes every event carry the caller chain captured AT THE HIT (x30 + the x29 walk inside the thread stack), which native_backtrace then symbolizes. mode=got needs module+symbol; mode=inline accepts module+symbol or addr; mode=sites (module+symbol) rewrites the B/BL call sites that reach the function instead of the function entry, so the prologue of the target stays byte-identical while the CALLER bytes change (use it when the target verifies the prologue of the function itself). scope picks where to look: module (default, the target module), all (every file-backed module except JIT memfds, app code first; status reports scanned bytes and truncated when the budget stops it), or one module name/basename; sites bounds how many call sites are patched, and status lists each site with its form (b or bl), module, original and current instruction. for mode=got/inline unhook is soft by default (the patch stays installed but inactive, safe to reactivate) and hard:true really restores the original bytes after a quiesce window; mode=sites always restores the rewritten call-site instructions (the patch belongs to the agent, so there is no Dobby state to keep) and, in the rare case where a thunk page had to stay mapped because a thread was still inside it, reports the kept page as sitesPageKept in the status response (the hook itself is already gone at that point). mode=vtable (module+symbol) patches DATA slots holding the function address (function-pointer tables such as C++ vtables, callback tables, and the module own GOT entries) instead of any code, so neither the function nor any call site changes - use it for indirect calls. By default only slots in read-only mappings are touched, because a writable word that merely equals the target is as likely to be a constant; pass slotsWritable:true to include writable slots. Patching a GOT slot also redirects direct calls in that module and changes what the symbol address resolves to there (the code itself is unchanged). slots bounds how many are patched, scope works like for sites, and status lists each slot with its module, mapping permissions, kind (got|data), original and current value. throttleMs (ms, clamped to 0..60000, 0 = off) keeps a hot hook such as read/write/futex from flooding the capture ring: the agent still applies argIndex/returnValue/skipOriginal to EVERY hit, but emits at most one event per hook per window and counts the hits it did not emit. The next emitted event carries throttled (how many hits it stands for) and status carries throttleMs plus the running throttled total, so emitted events = hits - throttled and a thinned log never looks like a quiet target. Each callback emits a NATIVE_HOOK event with the x0-x8/x18 registers through the bounded live-capture stream.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['hook', 'unhook', 'status'] }, hookId: N, mode: { type: 'string', enum: ['got', 'inline', 'sites', 'vtable'] }, module: S, symbol: S, addr: S, skipOriginal: { type: 'boolean' }, returnValue: S, argIndex: N, argValue: S, confirm: { type: 'boolean' }, hard: { type: 'boolean' }, sites: N, scope: S, slotsWritable: { type: 'boolean' }, backtrace: { type: 'boolean' }, throttleMs: N }, required: ['action'] }, handler: (a) => { if (a.mode === 'inline' && a.addr && a.confirm !== true) return Promise.resolve({ ok: false, error: 'native_hook inline addr requires confirm:true' }); return agentCmd(a.session, 'native_hook', { action: a.action, hookId: a.hookId ?? 0, mode: a.mode ?? '', module: a.module ?? '', symbol: a.symbol ?? '', addr: a.addr ?? '', skipOriginal: a.skipOriginal ? 'true' : 'false', returnValue: a.returnValue ?? '', argIndex: a.argIndex ?? -1, argValue: a.argValue ?? '', hard: a.hard ? 'true' : 'false', sites: a.sites ?? 0, scope: a.scope ?? '', slotsWritable: a.slotsWritable ? 'true' : 'false', backtrace: a.backtrace ? 'true' : 'false', throttleMs: normalizeThrottleMs(a.throttleMs) }, 20_000); } },
{ name: 'syscall_digest', description: 'Turn watched syscall hits into an answer: groups the NATIVE_HOOK events of the hooks you pass by (syscall number, CALLER frame) with counts, time window and threads, picks the first caller frame outside libc (that is the code that issued the syscall, which is what fingerprint-collection hunting needs), decodes the argument registers through the pointers the syscall actually uses (openat/faccessat/newfstatat paths, memfd_create names, uname utsname fields, connect IPv4/IPv6, ioctl request, socket domain/type) into a per-group example plus a paths histogram - which files does this code probe - and compares the runtime x8 with the statically attributed number so a wrong attribution shows up as a mismatch instead of a mislabel. Argument decoding reads target memory, so it is bounded by decodeLimit (default 40 samples) and can be turned off with decode:false. Install the watch with syscall_watch (it sets backtrace:true) and pass its hookIds plus expected {hookId: nr}.', inputSchema: { type: 'object', properties: { session: S, hookIds: { type: 'array', items: { type: 'number' } }, expected: { type: 'object' }, sinceMs: N, limit: N, maxGroups: N, decode: { type: 'boolean' }, decodeLimit: N } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return syscallDigest(sid, { hookIds: a.hookIds, expected: a.expected, sinceMs: a.sinceMs, limit: a.limit, maxGroups: a.maxGroups, decode: a.decode, decodeLimit: a.decodeLimit }); } },
{ name: 'java_trace', description: 'Class-level Java tracing in three explicit phases. action:start hooks every matching method of a class (hook_all semantics: method/params are optional filters, "*"/empty = any) and returns hookIds + matched + a capture cursor, KEEPING the hooks installed. action:digest drains the agent capture ring and turns the JAVA_HOOK events of those hook ids into a digest: per-method counts, first/last timestamp, threads, last argument and return, error counts, a chronological timeline (newest window) and a caller histogram when the hooks were started with stack:true. action:stop unhooks exactly the given ids (id 0 means every Java hook in the agent and is refused). Pass the cursor from start as sinceCaptureId on digest to see only events newer than that point. The digest drains the agent ring through the shared drainSession path, so it never eats records that another consumer still needs; a failed drain is reported in drain.ok instead of silently returning an empty trace. Trigger the target or let natural traffic run between start and digest.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['start', 'digest', 'stop'] }, className: S, method: S, params: S, limit: N, stack: { type: 'boolean' }, hookIds: { type: 'array', items: { type: 'number' } }, sinceCaptureId: N, maxTimeline: N, maxMethods: N, maxCallers: N }, required: ['action'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); if (a.action === 'start') return javaTraceStart(sid, { className: String(a.className ?? ''), method: a.method, params: a.params, limit: a.limit, stack: a.stack === true }); if (a.action === 'digest') return javaTraceDigest(sid, { hookIds: a.hookIds, sinceCaptureId: a.sinceCaptureId, maxTimeline: a.maxTimeline, maxMethods: a.maxMethods, maxCallers: a.maxCallers }); if (a.action === 'stop') return javaTraceStop(sid, { hookIds: a.hookIds }); throw new Error('action must be start | digest | stop'); } },
{ name: 'native_hook_all', description: 'Batch native hooking by exported-symbol pattern: give a module and a prefix/contains/exact filter and it resolves every matching exported FUNCTION from the module dump (not a hand-typed address list), installs inline hooks on up to limit of them (clamped to the 16 concurrent native slots) and returns hookIds with matched vs installedCount so truncation is visible. Address hooks are powerful, so confirm:true is required. action:unhook takes hookIds and removes exactly those. Filters are deterministic (address order), exclude can drop noisy names, and backtrace/throttleMs/skipOriginal/returnValue/argIndex/argValue are passed through to each hook (throttleMs keeps a hot symbol from flooding the ring; the response echoes the effective window).', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['hook', 'unhook'] }, module: S, prefix: S, contains: S, exact: S, exclude: { type: 'array', items: { type: 'string' } }, limit: N, backtrace: { type: 'boolean' }, throttleMs: N, skipOriginal: { type: 'boolean' }, returnValue: S, argIndex: N, argValue: S, hookIds: { type: 'array', items: { type: 'number' } }, confirm: { type: 'boolean' } }, required: ['action'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); if (a.action === 'unhook') return nativeUnhookAll(sid, a.hookIds); if (a.confirm !== true) return { ok: false, error: 'native_hook_all requires confirm:true (it installs inline hooks in the target)' }; return nativeHookAll(sid, { module: String(a.module ?? ''), prefix: a.prefix, contains: a.contains, exact: a.exact, exclude: a.exclude, limit: a.limit, backtrace: a.backtrace === true, throttleMs: a.throttleMs, skipOriginal: a.skipOriginal === true, returnValue: a.returnValue, argIndex: a.argIndex, argValue: a.argValue }); } },
{ name: 'syscall_trace', description: 'One-shot syscall tracing in three phases, with the static attribution threaded automatically: action:start runs syscall_watch (module + optional syscalls filter name/number) and returns hookIds plus the expected {hookId: nr} map built from the watch response, so a mis-attribution later shows up as a mismatch instead of being copied wrong. Trigger the target in between. action:digest drains the agent ring through the shared drain path and returns the syscall digest of those hooks (callers outside libc, counts, paths histogram, runtime-x8 vs attributed mismatches). action:stop unhooks exactly the ids it was given - there is deliberately no unhook-all. Sites whose number could not be attributed are reported in unattributed and their events carry the runtime x8 only. start forwards throttleMs (0 = off) to the watch, which caps how often each site reports an event.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['start', 'digest', 'stop'] }, module: S, syscalls: { anyOf: [ { type: 'array', items: { anyOf: [ { type: 'string' }, { type: 'number' } ] } }, { type: 'string' } ] }, limit: N, throttleMs: N, hookIds: { type: 'array', items: { type: 'number' } }, expected: { type: 'object' }, sinceMs: N, decode: { type: 'boolean' }, decodeLimit: N, maxGroups: N }, required: ['action'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); if (a.action === 'start') return syscallTraceStart(sid, { module: String(a.module ?? ''), syscalls: a.syscalls, limit: a.limit, throttleMs: a.throttleMs }); if (a.action === 'digest') return syscallTraceDigest(sid, { hookIds: a.hookIds, expected: a.expected, sinceMs: a.sinceMs, decode: a.decode, decodeLimit: a.decodeLimit, maxGroups: a.maxGroups }); if (a.action === 'stop') return syscallTraceStop(sid, { hookIds: a.hookIds }); throw new Error('action must be start | digest | stop'); } },
{ name: 'trace_digest', description: 'Run a QBDI instruction trace of one native function and hand back a DIGEST instead of thousands of raw instructions: loops (header, body size, iterations), call targets with counts (symbolized when the module dump allows it), memory access shapes, materialised constants with known crypto magics flagged, branch shape and the hottest instructions. The raw stream stays available through qbdi_trace; use this one when the question is what the function DOES rather than what the exact instruction order was.', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S, args: { type: 'array' } }, required: ['symbol'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return traceDigest(sid, { symLib: a.symLib, symbol: String(a.symbol ?? ''), args: a.args }); } },
{ name: 'native_backtrace', description: 'Caller backtrace at a native hook hit (the native analogue of Thread.backtrace). With hookId it uses the newest event of that hook: when the hook was installed with backtrace:true the agent captured the chain AT THE HIT (x30 plus the x29 walk inside the thread stack), which is the trustworthy form - reading the stack later finds memory the process has already reused. Each frame is resolved to module + offset + the nearest dynamic symbol (exact when the symbol size covers the address). Explicit fp/lr instead performs a live x29 walk, which is best effort and reports its stopReason (unreadable stack, pointer outside a writable mapping, not ascending, loop) rather than inventing frames. A library mapped straight out of an APK is reported with symbolSource=archive-mapped because no standalone ELF image exists to symbolize against.', inputSchema: { type: 'object', properties: { session: S, hookId: N, fp: S, lr: S, maxFrames: N } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return nativeBacktrace({ session: sid, hookId: a.hookId, fp: a.fp, lr: a.lr, maxFrames: a.maxFrames }); } },
  { name: 'native_call', description: 'Actively call a native function by module+symbol or absolute addr. AAPCS64: integer/pointer args go to x0-x7 (up to 8), typed f:<float> / d:<double> args go to the FP bank (up to 8; the i-th FP argument uses d_i, and a float only fills its low 32 bits, i.e. s_i). Malformed input is rejected rather than guessed: unknown type prefix, empty argument, out-of-range number, more than 8 args per bank, or an args string over 279 bytes. The integer return is result/resultDecimal (x0); when FP args are used the d0 return is reported as fpResult/fpResultDouble/fpResultFloat with returnBank:"d0" and x0MayBeStale:true - a float return is the low 32 bits of d0, and x0 is only the answer if the target returns an int. This is an arbitrary target call and requires confirm:true; it can crash the target, so use only on authorized targets.', inputSchema: { type: 'object', properties: { session: S, module: S, symbol: S, addr: S, args: { type: 'array' }, confirm: { type: 'boolean' } } }, handler: (a) => { if (a.confirm !== true) return Promise.resolve({ ok: false, error: 'native_call requires confirm:true (arbitrary target call can crash the process)' }); return agentCmd(a.session, 'native_call', { module: a.module ?? '', symbol: a.symbol ?? '', addr: a.addr ?? '', args: (a.args ?? []).map((v: any) => String(v)).join(',') }, 20_000); } },
{ name: 'stealth', description: 'Opt-in anti-detection for this session: with action:"on" the allocations the inline-hook backend makes while it is inside a Dobby call (typically its trampoline arena) stop being anonymous executable pages and land in a memfd-backed mapping named like the ART JIT cache, so a target that scans its own /proc/self/maps for an executable mapping without a path no longer sees the hook pool. It changes what the target process looks like (authorized use only) and requires confirm:true for on/off; status reports enabled/installed/active, the live GOT slot value next to the original mmap, how many allocations were redirected, and the memfd error when the platform refuses (then the real mmap is used and nothing is hidden). Default off; pools created by earlier hooks are not moved.', inputSchema: { type: 'object', properties: { session: S, action: { type: 'string', enum: ['on', 'off', 'status'] }, confirm: { type: 'boolean' } }, required: ['action'] }, handler: (a) => { const act = String(a.action ?? ''); if (act !== 'status' && a.confirm !== true) return Promise.resolve({ ok: false, error: 'stealth on/off requires confirm:true (it changes the target process footprint; authorized use only)' }); return agentCmd(a.session, 'stealth', { action: act }, 15_000); } },
{ name: 'syscall_watch', description: 'Scan one loaded module for direct svc #0 sites (libc.so is the interesting one: its stubs are what ordinary app code reaches the kernel through), attribute each site to a syscall number by decoding the MOV that precedes the svc, inline-hook up to limit of the matching sites, and report hooks whose NATIVE_HOOK events carry x8 as the runtime syscall number. syscalls filters by name or number and accepts a CSV or an array ("uname,openat,117"); a filter that matches nothing fails loud. throttleMs (0 = off) caps how often each site reports an event - hot syscalls such as read/write/futex otherwise overflow the ring and make the digest look quiet; the response echoes the effective window. Host-side orchestration: dump + static scan + native_hook; agent remains execution-only.', inputSchema: { type: 'object', properties: { session: S, module: S, limit: N, throttleMs: N, syscalls: { anyOf: [ { type: 'array', items: { anyOf: [ { type: 'string' }, { type: 'number' } ] } }, { type: 'string' } ] } }, required: ['module'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return watchSyscalls(sid, { module: a.module, limit: a.limit, syscalls: a.syscalls, throttleMs: a.throttleMs }); } },
{ name: 'got_enum', description: 'Enumerate relocation/GOT entries for one loaded module: slot address, symbol name, current resolved value and relocation type. Optional filter matches one symbol exactly.', inputSchema: { type: 'object', properties: { session: S, module: S, filter: S }, required: ['module'] }, handler: (a) => agentCmd(a.session, 'got_enum', { module: a.module, filter: a.filter ?? '' }, 20_000) },
  { name: 'memory_maps', description: 'On-demand full /proc/self/maps of the target', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'maps') },
  { name: 'memory_read', description: 'Read target memory at hex addr for size bytes (base64 out)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: (a) => agentCmd(a.session, 'read', { addr: a.addr, size: a.size }) },
  { name: 'memory_disasm', description: 'Disassemble live target memory with host-side Capstone 5 (WASM). addr is an absolute hex address, or pass module plus offset to resolve the module base from live maps. size is bounded to 64 KiB and aligned to AArch64 instructions.', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N, module: S, offset: S } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return liveDisasm(sid, { addr: a.addr, size: a.size, module: a.module, offset: a.offset }); } },
  { name: 'memory_search', description: 'Search target memory for hex or text pattern', inputSchema: { type: 'object', properties: { session: S, hex: S, text: S, limit: N } }, handler: (a) => agentCmd(a.session, 'search', { pat: a.hex ?? Buffer.from(String(a.text ?? ''), 'utf8').toString('hex'), limit: a.limit ?? 256 }, 90_000) },
  { name: 'memory_scan_magic', description: 'Scan target memory for dex/elf/oat/vdex/zip magics', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'scan_magic', {}, 90_000) },
  { name: 'art_dexfiles', description: 'Enumerate loaded DexFiles via ART ClassLoader structures (no magic scan)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'art_dexfiles', {}, 30_000) },
  { name: 'crypto_capture', description: 'Hook EVP_CipherUpdate + trigger the target’s crypto workload class; return captured plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'crypto_hook_test', { className: a.class ?? SANDBOX.crypto }, 20_000) },
  { name: 'net_capture', description: 'Hook SSL_write/SSL_read + trigger HTTPS; return captured TLS plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'net_hook_test', { className: a.class ?? SANDBOX.net }, 25_000) },
  { name: 'file_probe', description: 'Recon which loaded module’s GOT holds open/openat/read/write/close pointers (guides file_capture’s module arg)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'file_probe', {}, 20_000) },
  { name: 'file_capture', description: 'Hook open/openat/read/write/close + trigger the target’s file I/O; return captured paths + read/write bytes', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'file_hook_test', { module: a.module ?? settings.capture.fileModule, className: a.class ?? SANDBOX.file }, 25_000) },
  { name: 'detect_watch', description: 'Observe the target’s own anti-analysis checks (debug/root/prop)', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'detect_watch', { module: a.module ?? settings.capture.sysModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'object_inspect', description: 'Read a live Java object’s fields via reflection (static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S }, required: ['className', 'field'] }, handler: (a) => agentCmd(a.session, 'object_inspect', { className: a.className, field: a.field }) },
  { name: 'dex_search', description: 'Search a dex (b64|sha) for strings/classes/methods', inputSchema: { type: 'object', properties: { b64: S, sha: S, query: S, kinds: { type: 'array', items: S } }, required: ['query'] }, handler: async (a) => searchDex(parseDex(await dumpBuf(a)), a.query, a.kinds) },
  { name: 'dex_index', description: 'Build or reuse the persistent SQLite index for a dex (b64|known dump sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => ensureDexIndex(await dumpBuf(a)) },
  { name: 'dex_index_search', description: 'Search an indexed dex for strings, string callers, classes, fields, methods and reflection targets', inputSchema: { type: 'object', properties: { sha: S, query: S, limit: N }, required: ['sha', 'query'] }, handler: async (a) => searchDexIndex(String(a.sha), String(a.query), a.limit) },
  { name: 'dex_reflections', description: 'List statically resolved Class.forName targets and their callers from an indexed dex', inputSchema: { type: 'object', properties: { sha: S, limit: N }, required: ['sha'] }, handler: async (a) => ({ sha: a.sha, reflections: listDexReflections(String(a.sha), a.limit) }) },
  { name: 'dex_xref', description: 'Find callers of a method in a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, method: S }, required: ['method'] }, handler: async (a) => { const buf = await dumpBuf(a); const { xref } = invokeXref(buf, parseDex(buf)); const q = String(a.method).toLowerCase(); const out: Record<string, string[]> = {}; for (const [c, cs] of xref) if (c.toLowerCase().includes(q)) out[c] = cs.slice(0, 200); return out; } },
  { name: 'dex_crypto_scan', description: 'Static crypto scan of a dex (API refs + algorithm strings)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoScan(parseDex(await dumpBuf(a))) },
  { name: 'native_disasm', description: 'Disassemble an ELF .so (b64|sha) by symbol', inputSchema: { type: 'object', properties: { b64: S, sha: S, symbol: S }, required: ['symbol'] }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await disasmSo(t, { symbol: a.symbol }); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_analyze', description: 'Exports/imports/NEEDED/strings of an ELF .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await analyzeSo(t); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_crypto_const', description: 'Locate crypto by constant signatures in a stripped .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoConstScan(await dumpBuf(a)) },
  { name: 'native_syscall_scan', description: 'Find direct svc #0 syscalls in a .so (b64|sha) and attribute every site to a syscall number by decoding the MOV that materialises x8 before it (arm64 number table; a number that cannot be decoded statically stays unknown instead of being guessed). The same attribution backs syscall_watch, which can then hook only the sites matching a name/number filter.', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const buf = await dumpBuf(a); const scan = svcScan(buf); const hits = scan.hits.map((h) => { const off = Number(BigInt(h.fileOff)); const at = attributeSite(buf, off); return { ...h, syscall: at.nr == null ? null : { nr: at.nr, name: syscallName(at.nr) }, attribution: at.how }; }); return { ...scan, hits, attributedCount: hits.filter((h) => h.syscall).length, unknownCount: hits.filter((h) => !h.syscall).length }; } },
  { name: 'memory_dump', description: 'Dump target memory [addr,addr+size) to a capture artifact (sha256 dedup)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); const { meta, dedup } = await dumpRegion(sid, String(a.addr).replace(/^0x/, ''), Number(a.size), 'mcp'); return { ...meta, dedup }; } },
  { name: 'flow_correlate', description: 'Hook EVP+SSL_write, trigger encrypt-then-send, capture plaintext+request (tid/ts)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'object_invoke', description: 'Call a no-arg method on a live object (via static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S, method: S }, required: ['className', 'field', 'method'] }, handler: (a) => agentCmd(a.session, 'object_invoke', { className: a.className, field: a.field, method: a.method }) },
  { name: 'trace_function', description: 'Trace calls to a native symbol (args+tid+ts) while the target’s detection workload runs', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S, hookModule: S, class: S }, required: ['symbol', 'hookModule'] }, handler: (a) => agentCmd(a.session, 'trace_run', { symLib: a.symLib ?? 'libc.so', symbol: a.symbol, hookModule: a.hookModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'dex_method_code', description: 'Extract a method’s runtime code_item bytecode from a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, class: S, method: S }, required: ['class'] }, handler: async (a) => { const buf = await dumpBuf(a); return extractMethodCode(buf, parseDex(buf), String(a.class), a.method); } },
  { name: 'dex_repair', description: 'Repair a dumped dex header (file_size/checksum/signature)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const buf = await dumpBuf(a); const info = repairDexHeader(buf); return { ...info, repairedB64: buf.toString('base64') }; } },
  // ---- axis 1: one-glance crypto algorithm identification ----
  { name: 'crypto_identify', description: '一眼看清目标 App 用了哪些加密算法/密钥/IV — summarize all captured crypto (algorithm, key, iv, plaintext) into a plain-language report for non-experts', inputSchema: { type: 'object', properties: {} }, handler: async () => cryptoIdentify() },
  { name: 'live_captures', description: 'List the live captures streamed by the persistent hooks — crypto / net(TLS) / file / system, filterable by category (algorithm+op+preview, newest last)', inputSchema: { type: 'object', properties: { limit: N, category: S } }, handler: async (a) => { const cat = a.category ? String(a.category) : ''; const list = cat ? captures.filter(c => c.category === cat) : captures; return { total: list.length, on: captureTimers.size > 0, captures: list.slice(-(Number(a.limit) || 50)).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, inl: c.inl, tid: c.tid, ts: c.ts, preview: c.preview })) }; } },
  { name: 'capture_detail', description: 'Full detail of one capture by id: algorithm, key(hex), iv(hex), plaintext(utf8+hex), ciphertext(hex)', inputSchema: { type: 'object', properties: { id: N }, required: ['id'] }, handler: async (a) => { const c = captures.find(x => x.id === Number(a.id)); if (!c) throw new Error('not found'); const text = Buffer.from(c.hex, 'hex').toString('utf8'); return { ...c, text }; } },
  // ---- axis 2: one-click unpack (no AOSP flashing needed) ----
  { name: 'dex_coverage', description: '方法恢复率报告 — per-method state (native/abstract/present/extracted) + recovery rate over a dumped dex', inputSchema: { type: 'object', properties: { b64: S, sha: S }, required: [] }, handler: async (a) => { const buf = await dumpBuf(a); return analyzeCoverage(buf, parseDex(buf)); } },
  { name: 'dump_all_dex', description: '一键 dump 当前目标进程所有已加载 DEX：ART DexFile 枚举 + 逐个 dump + SHA-256 去重', inputSchema: { type: 'object', properties: { session: S } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return dumpAllDex(sid); } },
  { name: 'dex_recover', description: 'Recover extracted CodeItems from a restored snapshot into a base dex + rebuild (baseSha/baseB64 + restoredSha/restoredB64)', inputSchema: { type: 'object', properties: { baseB64: S, baseSha: S, restoredB64: S, restoredSha: S } }, handler: async (a) => { const base = await dumpBuf({ b64: a.baseB64, sha: a.baseSha }); const restored = await dumpBuf({ b64: a.restoredB64, sha: a.restoredSha }); const pd = parseDex(base); const { captures: caps, report } = recoverFromSnapshots(base, restored, pd); const rb = rebuildStandardDex(base, caps); const outSha = createHash('sha256').update(rb.dex).digest('hex'); const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`); if (!existsSync(path)) writeFileSync(path, rb.dex); const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' }; dumps.set(outSha, meta); return { ...report, injected: rb.injected, sha256: outSha }; } },
  // ---- axis 3: everything the AI needs to drive a reversing session ----
  { name: 'trigger', description: 'Actively load a class (level 1) and invoke a safe static no-arg method (level 3) to force code paths — a trigger source for unpacking', inputSchema: { type: 'object', properties: { session: S, class: S, method: S, level: N }, required: ['class'] }, handler: (a) => agentCmd(a.session, 'trigger', { className: a.class, method: a.method ?? '', level: Number(a.level ?? 1) }, 20_000) },
  { name: 'qbdi_trace', description: 'QBDI instruction-level dynamic trace of a native function (per-instruction disassembly + return value), invoked with up to 8 unsigned integer/pointer args.', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S, args: { type: 'array' } }, required: ['symbol'] }, handler: (a) => agentCmd(a.session, 'qbdi_trace', { symLib: a.symLib ?? 'libadhdetect.so', symbol: a.symbol, args: (a.args ?? []).map((v: any) => String(v)).join(',') }, 30_000) },
  { name: 'net_correlate', description: 'Network↔crypto correlation: pair plaintext with the TLS request carrying its ciphertext (same thread + time window)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'agent_ping', description: 'Liveness and latency check for one session: sends the cheapest command the agent has and reports the measured round trip in ms. Use it to tell "the target is gone" from "this command is just slow", before and after a crash-prone operation, or when a session looks hung. It fails fast (5s) instead of sitting on a normal command timeout.', inputSchema: { type: 'object', properties: { session: S }, required: ['session'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return agentPing(sid); } },
  { name: 'engine_selftest', description: 'Prove the native hook engine works in THIS target: the agent replaces a GOT slot in its own module, triggers a controlled call, restores it, and reports replaced / hits / fired plus the slot page permissions before and after. ok is the VERDICT (the hook fired AND the RELRO page protection was restored); commandOk only says the agent answered. A build that left the page writable comes back ok:false with a note that it is detectable, so run this before trusting hook results.', inputSchema: { type: 'object', properties: { session: S }, required: ['session'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return hookEngineSelftest(sid); } },
  { name: 'protocol_selftest', description: 'Command-channel integrity check: send one oversized frame whose tail marker sits past the old 8192-byte single-line cap and verify the tail survived and the whole frame arrived. Use it when replies look truncated or a session looks half-dead; kb is clamped to 1..4096. ok:false here means the channel (adb reverse / framing) is at fault, not the target.', inputSchema: { type: 'object', properties: { session: S, kb: N }, required: ['session'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return protocolSelfTest(sid, a.kb); } },
  { name: 'fs_list', description: 'List a directory on the DEVICE through the target process, so it sees the sandbox the way the app does (its private /data/data/... dir, /data/local/tmp, /proc/self/...). Returns name/type/size/mode/mtime per entry plus count and truncated. Start here to find shared_prefs, databases, keystores or dropped scripts, then pull one with fs_read.', inputSchema: { type: 'object', properties: { session: S, path: S }, required: ['session', 'path'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return listDeviceDir(sid, String(a.path ?? '')); } },
  { name: 'fs_read', description: 'Read one device file through the target process. The agent caps a read at 1MB and reports truncated honestly. Returns size, byte count, a binary flag (NUL byte present), a printable preview and the line count, plus the whole text when the file is text and is at most 256KB. Binary or oversized files come back with textOmitted saying why; pass includeBase64:true for the raw bytes.', inputSchema: { type: 'object', properties: { session: S, path: S, includeBase64: { type: 'boolean' }, includeText: { type: 'boolean' }, previewBytes: N }, required: ['session', 'path'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return readDeviceFile(sid, String(a.path ?? ''), { includeBase64: a.includeBase64 === true, includeText: a.includeText !== false, previewBytes: a.previewBytes }); } },
  { name: 'load_library', description: '把任意 .so 加载进目标进程（如 frida-gadget，随后 gadget 会按 script 模式自动跑你的 frida 脚本）。可选 symbol 探测。dlopen from inside the target.', inputSchema: { type: 'object', properties: { session: S, path: S, symbol: S }, required: ['path'] }, handler: (a) => agentCmd(a.session, 'load_so', { path: a.path, symbol: a.symbol ?? '' }, 30_000) },
];

const SEL = {
  text: S,
  textContains: S,
  resourceId: S,
  contentDescription: S,
  contentDescriptionContains: S,
  clickable: { type: 'boolean' },
  editable: { type: 'boolean' },
  scrollable: { type: 'boolean' },
  index: N,
};

MCP_TOOLS.push(
  { name: 'automation_status', description: 'Read-only phone automation status: user toggle, privacy switches, package allowlist, bridge/device state (foreground package, snapshots, notification grant/ring, watchdog counters). This tool never enables automation.', inputSchema: { type: 'object', properties: {} }, handler: async () => ({ enabled: settings.automation.enabled, packages: settings.automation.packages, settings: { screenshot: settings.automation.screenshot, notifications: settings.automation.notifications, maxNodes: settings.automation.maxNodes }, bridge: automation.status(), device: await automationDeviceStatus() }) },
  { name: 'phone_observe', description: 'Observe the active phone screen. Prefer the AccessibilityService node tree; when it is empty or non-semantic, fall back to a screenshot that the AI can inspect. Returns snapshotId plus nodes or an image. mode=text renders the same tree as terse plain-text lines (refs stay usable) to save context, and includeScreenshot:true adds a JPEG alongside that text.', inputSchema: { type: 'object', properties: { mode: { type: 'string', enum: ['auto', 'tree', 'visual', 'text'] }, includeScreenshot: { type: 'boolean' }, maxNodes: N, maxDepth: N, interactiveOnly: { type: 'boolean' }, package: S } }, raw: true, handler: async (a) => observePhone(a) },
  { name: 'phone_find', description: 'Find compact, actionable nodes without transferring the whole tree. Supports text/resourceId/contentDescription and interaction flags; returns refs valid for snapshotId.', inputSchema: { type: 'object', properties: { ...SEL, implicitOnly: { type: 'boolean' }, limit: N, maxNodes: N, interactiveOnly: { type: 'boolean' }, package: S } }, handler: async (a) => findPhone(a) },
  { name: 'phone_wait', description: 'Wait until a screen state / selector matches, until the screen settles (stable:true, stableMs holds still), or until the injected agent reports a signal. Agent filters: agentEvent (exact event type), agentEventContains (substring of the event JSON), captureCategory (crypto/net/file/system), captureContains (substring of the decoded capture text + metadata). Notification filters: notificationContains (substring of title/text, needs the opt-in notification listener) and notificationFrom (package). With scroll:true the wait scrolls a container until the target shows up — scrollMode=gesture swipes instead of sending ACTION_SCROLL, which is what pagers and custom lists (e.g. launcher pages) require, and axis picks vertical or horizontal. Same-kind filters are ANDed; the two kinds race and whichever fires first wins. Race-free pattern: take the cursor from the preceding observe/act response and pass it as afterCaptureId / afterEventSeq; lookbackMs is the coarse alternative (bounded 0..300000). On an agent-signal timeout the reply carries saw (recent captures/events from the window plus totals) and the live cursor, so the filter can be retargeted.', inputSchema: { type: 'object', properties: { ...SEL, activePackage: S, activityContains: S, gone: { type: 'boolean' }, agentEvent: S, agentEventContains: S, captureCategory: { type: 'string', enum: ['crypto', 'net', 'file', 'system'] }, captureContains: S, notificationContains: S, notificationFrom: S, afterEventSeq: N, afterCaptureId: N, lookbackMs: N, timeoutMs: N, intervalMs: N, scroll: { type: 'boolean' }, scrollMode: { type: 'string', enum: ['action', 'gesture'] }, stable: { type: 'boolean' }, stableMs: N, axis: { type: 'string', enum: ['vertical', 'horizontal'] }, direction: { type: 'string', enum: ['forward', 'backward'] }, maxScrolls: N, maxNodes: N, interactiveOnly: { type: 'boolean' }, package: S } }, handler: async (a) => waitPhone(a) },
  { name: 'phone_wait_any', description: 'Wait until any one of several conditions matches and report which one did. Use when an app can resume into different states (a browser opening on its home page or on existing results, settings on its home page or inside search): one plain phone_wait can only express a single expectation, so recipes would break. Each condition is the same shape as phone_wait args (selector / activePackage / stable / notification / agent filter).', inputSchema: { type: 'object', properties: { conditions: { type: 'array', minItems: 1, maxItems: 8, items: { type: 'object' } }, timeoutMs: N, intervalMs: N }, required: ['conditions'] }, raw: true, handler: async (a) => ({ content: [{ type: 'text', text: JSON.stringify(await runTaskStep('wait_any', a), null, 2) }] }) },
  { name: 'phone_act', description: 'Act on the active phone screen. Prefer a selector or snapshotId+ref from phone_observe; use normalized coordinates only as the visual fallback. Supports tap, long_press, swipe, input, scroll, set_text, global back/home/recents/notifications/quick_settings/power/lock/screenshot, and ime (press the keyboard action key on the focused field — use it when an app ignores its own submit button). Set inputMode:"root" when the accessibility gesture is accepted but the screen does not change (some Compose UIs, e.g. SukiSU Ultra or the LSPosed/Vector manager, swallow dispatchGesture): it injects the tap/swipe through the root Device Daemon instead, which needs protocol v9. For set_text the text argument is the payload to write, not a filter (target the field with ref, resourceId, editable or selector); the value can be read back with phone_find. set_text takes submit:true to press the field’s keyboard action button (search / send / done) afterwards, and reports submitted:true when the field accepted it. A failed action answers with the compact current screen so the target can be re-derived without another observe.', inputSchema: { type: 'object', properties: { ...SEL, snapshotId: S, action: { type: 'string', enum: ['tap', 'long_press', 'swipe', 'input', 'scroll', 'set_text', 'global', 'ime'] }, ref: S, x: N, y: N, x2: N, y2: N, coordinateSpace: { type: 'string', enum: ['normalized', 'pixel'] }, inputMode: { type: 'string', enum: ['accessibility', 'root'] }, text: S, submit: { type: 'boolean' }, key: { type: 'string', enum: ['back', 'home', 'recents', 'notifications', 'quick_settings', 'power', 'lock', 'screenshot'] }, direction: { type: 'string', enum: ['forward', 'backward'] }, durationMs: N, submit: { type: 'boolean' }, observeAfter: { type: 'boolean' }, package: S }, required: ['action'] }, raw: true, handler: async (a) => actPhone(a) },
  { name: 'phone_app', description: 'Open, stop or restart an allowlisted app by package name. open verifies that the app really reached the foreground and reports verified/foreground/warning when an OEM dialog swallowed the launch (with a hint on how to unblock). Open uses the root Device Daemon when protocol v6+ is available, with a compatibility fallback for older daemons; stop/restart delegate to the same authenticated daemon.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['open', 'stop', 'restart'] }, package: S }, required: ['action', 'package'] }, handler: async (a) => appPhone(a) },
  { name: 'phone_notifications', description: 'Recent notifications the accessibility connection saw (newest first: package, text lines, time). Needs the operator to enable automation.notifications — reading notification text is a privacy step beyond UI control and stays opt-in. Keep the returned ts to poll incrementally with sinceMs.', inputSchema: { type: 'object', properties: { limit: N, sinceMs: N } }, handler: async (a) => notificationsPhone(a) },
  { name: 'phone_device', description: 'Read or control device-level state: power (status, wake, unlock a non-secure keyguard, lock), audio volume (volume_status, volume_set with stream music|ring|alarm|voice and an index clamped to the stream range) and the clipboard (clipboard_read, clipboard_write with text, max 8 KiB). Secure credentials are never bypassed.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['status', 'wake', 'unlock', 'lock', 'volume_status', 'volume_set', 'clipboard_read', 'clipboard_write'] }, stream: { type: 'string', enum: ['music', 'ring', 'alarm', 'voice'] }, index: N, text: S }, required: ['action'] }, handler: async (a) => devicePhone(a) },
  { name: 'phone_skill', description: 'Save, list, run or delete named phone recipes (skills). A skill is a validated, bounded list of phone_task steps kept on the host, so a flow the AI worked out once replays in one call. Recipes can take params (declared on save) that steps read as {{input.<name>}} and runs pass as inputs; defaults fill the optional ones. Skills run through the same primitives, allowlist and retry semantics as phone_task; they cannot nest skills or reach a shell.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['list', 'save', 'run', 'delete'] }, name: S, description: S, overwrite: { type: 'boolean' }, stopOnError: { type: 'boolean' }, steps: { type: 'array', minItems: 1, maxItems: 30, items: { type: 'object' } }, params: { type: 'array', maxItems: 10, items: { type: 'string' } }, defaults: { type: 'object' }, inputs: { type: 'object' } }, required: ['action'] }, handler: async (a) => skillPhone(a) },
  { name: 'phone_task', description: 'Run a bounded sequence of phone primitives in one MCP call. Steps may observe, find, wait (UI state or agent signal), act, control an app, or control device power; each step supports retries and structured failure output. Steps with an id can be referenced by later steps as {{id.path}} (e.g. take the ref and snapshotId a find discovered straight into act), which avoids ref-expiry between separate calls.', inputSchema: { type: 'object', properties: { stopOnError: { type: 'boolean' }, steps: { type: 'array', minItems: 1, maxItems: 30, items: { type: 'object', properties: { id: S, type: { type: 'string', enum: ['observe', 'find', 'wait', 'wait_any', 'act', 'app', 'device'] }, args: { type: 'object' }, retries: N, retryDelayMs: N, onlyIf: { type: 'object' } }, required: ['type'] } } }, required: ['steps'] }, handler: async (a) => taskPhone(a) },
);


function matchesSelector(node: any, selector: any): boolean {
  if (selector.text != null && node.text !== selector.text) return false;
  if (selector.textContains != null && !String(node.text ?? '').includes(String(selector.textContains))) return false;
  if (selector.resourceId != null && node.resourceId !== selector.resourceId) return false;
  if (selector.contentDescription != null && node.contentDescription !== selector.contentDescription) return false;
  if (selector.contentDescriptionContains != null && !String(node.contentDescription ?? '').includes(String(selector.contentDescriptionContains))) return false;
  if (selector.clickable != null && !!node.clickable !== !!selector.clickable) return false;
  if (selector.editable != null && !!node.editable !== !!selector.editable) return false;
  if (selector.scrollable != null && !!node.scrollable !== !!selector.scrollable) return false;
  return true;
}

function findNodes(nodes: any[], selector: any, limit = 20): any[] {
  const matches = (nodes ?? []).filter((node) => matchesSelector(node, selector));
  const index = Number.isFinite(selector.index) ? Math.max(0, Math.floor(selector.index)) : null;
  const selected = index == null ? matches : matches.slice(index, index + 1);
  return selected.slice(0, Math.max(1, Math.min(200, Number(limit) || 20)));
}

function compactNode(node: any) {
  const copy: any = {};
  for (const key of ['ref', 'text', 'contentDescription', 'resourceId', 'className', 'bounds', 'actions', 'clickable', 'editable', 'scrollable', 'selected', 'checked', 'enabled']) {
    if (node?.[key] !== undefined) copy[key] = node[key];
  }
  return copy;
}

async function observeTree(args: any) {
  return await automation.cmd('observe', normalizeObserveArgs({ ...args, mode: 'tree', includeScreenshot: false }), 25_000);
}

async function findPhone(args: any) {
  assertAutomationReady();
  const result = await observeTree(args);
  const selector = selectorFrom(args);
  // implicitOnly turns "not found" into an empty result instead of a hard failure, so a recipe can
  // express an optional step (tap the search box only when it is present) without conditionals.
  if (Object.keys(selector).length === 0 && args.implicitOnly !== true) {
    throw new Error('find requires a selector (text/textContains/resourceId/contentDescription/clickable/editable/scrollable)');
  }
  const matches = findNodes(result.nodes ?? [], selector, args.limit ?? 20);
  return {
    activePackage: result.activePackage,
    screen: result.screen,
    snapshotId: result.snapshotId,
    truncated: result.truncated,
    count: matches.length,
    cursor: agentCursor(),
    nodes: matches.map(compactNode),
  };
}

// Poll the opt-in notification ring for a title/text/package match. Bounded by limit so a busy
// phone cannot flood the model; the caller sees the matched entry (ts/title/text/package) and can
// extract whatever it needs, e.g. an OTP.
async function findNotificationMatch(args: any, sinceMs: number, _timeoutMs: number): Promise<{ item: any } | null> {
  const result = await automation.cmd('notifications', {
    limit: Math.max(1, Math.min(30, Number(args.notificationLimit ?? 10))),
    sinceMs,
  }, 15_000);
  if (result?.granted === false) {
    throw new Error('notification_access_not_granted: enable "notification access" for ADH Manager in system settings (设置 → 通知 → 通知使用权), then retry');
  }
  const needle = args.notificationContains != null ? String(args.notificationContains) : null;
  const from = args.notificationFrom != null ? String(args.notificationFrom) : null;
  for (const entry of result?.notifications ?? []) {
    if (from && String(entry.package ?? '') !== from) continue;
    if (needle) {
      const haystack = [entry.title, entry.text, ...(Array.isArray(entry.lines) ? entry.lines : [])].map((value: unknown) => String(value ?? '')).join('\n');
      if (!haystack.includes(needle)) continue;
    }
    const { title, text, package: pkg, ts, key } = entry;
    return { item: { package: pkg, title, text, ts, key } };
  }
  return null;
}

async function waitPhone(args: any) {
  assertAutomationReady();
  const selector = selectorFrom(args);
  const hasState = args.activePackage != null || args.activityContains != null;
  const wantsStable = args.stable === true;
  const needsUi = Object.keys(selector).length > 0 || hasState || wantsStable;
  const wantsAgent = hasAgentWaitFilters(args);
  const wantsNotification = args.notificationContains != null || args.notificationFrom != null;
  if (!needsUi && !wantsAgent && !wantsNotification)
    throw new Error('phone_wait requires a selector, activePackage, activityContains, an agent filter (agentEvent/agentEventContains/captureCategory/captureContains) or a notification filter (notificationContains/notificationFrom)');
  if (wantsNotification && settings.automation.notifications !== true)
    throw new Error('notifications_disabled: enable automation.notifications in ADH settings to wait on notifications');
  const timeoutMs = Math.max(500, Math.min(60_000, Number(args.timeoutMs ?? 8_000)));
  const intervalMs = Math.max(100, Math.min(2_000, Number(args.intervalMs ?? 350)));
  const maxScrolls = Math.max(0, Math.min(50, Number(args.maxScrolls ?? 10)));
  const startedAt = Date.now();
  const lookbackMs = Math.max(0, Math.min(300_000, Number(args.lookbackMs ?? 0)));
  const agentWindow = { since: startedAt - lookbackMs, afterEventSeq: args.afterEventSeq, afterCaptureId: args.afterCaptureId };
  let scrolls = 0;
  let last: any = null;
  if (wantsStable) {
    const stableMs = Math.max(200, Math.min(5_000, Number(args.stableMs ?? 600)));
    let sample: { signature: string; changedAt: number } | null = null;
    for (;;) {
      const result = await observeTree(args);
      const now = Date.now();
      sample = noteSample(sample, screenSignature(result), now);
      if (isSettled(sample, now, stableMs)) {
        // Refs from this snapshot stay valid for the caller, so a settled wait is directly actionable.
        return {
          matched: true,
          stable: true,
          signature: sample.signature,
          waitedMs: now - startedAt,
          activePackage: result.activePackage,
          activity: result.activity,
          snapshotId: result.snapshotId,
          truncated: result.truncated,
          nodes: (result.nodes ?? []).slice(0, 60).map(compactNode),
        };
      }
      if (now - startedAt >= timeoutMs) {
        return {
          matched: false,
          timedOut: true,
          stable: false,
          signature: sample.signature,
          changedAgoMs: now - sample.changedAt,
          elapsedMs: now - startedAt,
          activePackage: result.activePackage,
          activity: result.activity,
          snapshotId: result.snapshotId,
        };
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }
  for (;;) {
    // Notifications first: "tap send, then wait for the SMS/OTP to arrive" is the whole point,
    // and it does not depend on the node tree either.
    if (wantsNotification) {
      const hit = await findNotificationMatch(args, startedAt - lookbackMs, timeoutMs);
      if (hit) {
        return {
          matched: true,
          kind: 'notification',
          item: hit.item,
          elapsedMs: Date.now() - startedAt,
          activePackage: last?.activePackage,
          snapshotId: last?.snapshotId,
        };
      }
    }
    // Agent signals need no node tree, so a pure signal wait never depends on the
    // AccessibilityService, and a mixed wait takes whichever condition fires first.
    if (wantsAgent) {
      const hit = findAgentWaitMatch(args, agentWindow, events, captures);
      if (hit) {
        return {
          matched: true,
          kind: hit.kind,
          item: hit.item,
          elapsedMs: Date.now() - startedAt,
          activePackage: last?.activePackage,
          activity: last?.activity,
          snapshotId: last?.snapshotId,
          scrolls,
        };
      }
    }
    if (needsUi) {
      const result = await observeTree(args);
      last = result;
      const stateMatches =
        (args.activePackage == null || result.activePackage === args.activePackage) &&
        (args.activityContains == null || String(result.activity ?? '').includes(String(args.activityContains)));
      const matches = findNodes(result.nodes ?? [], selector, 1);
      const found = stateMatches && (Object.keys(selector).length === 0 || matches.length > 0);
      if (args.gone ? !found : found) {
        return {
          matched: true,
          gone: !!args.gone,
          elapsedMs: Date.now() - startedAt,
          activePackage: result.activePackage,
          activity: result.activity,
          snapshotId: result.snapshotId,
          scrolls,
          node: found ? compactNode(matches[0]) : null,
        };
      }
    }
    if (Date.now() - startedAt >= timeoutMs) {
      return {
        matched: false,
        timedOut: true,
        elapsedMs: Date.now() - startedAt,
        activePackage: last?.activePackage,
        activity: last?.activity,
        snapshotId: last?.snapshotId,
        truncated: last?.truncated,
        scrolls,
        // On an agent-signal timeout, hand back what did arrive in the window (plus the live
        // cursor) so the AI can retarget the filter instead of guessing blind.
        ...(wantsAgent ? { cursor: agentCursor(), saw: agentWaitSightings(agentWindow, events, captures) } : {}),
      };
    }
    if (needsUi && args.scroll && !args.gone && scrolls < maxScrolls && String(args.scrollMode ?? 'action') === 'gesture') {
      // Widgets that reject ACTION_SCROLL (pagers, custom lists) still answer a real swipe.
      const path = swipePath(normalizeAxis(args.axis), (args.direction ?? 'forward') !== 'backward');
      await automation.cmd('act', {
        action: 'swipe',
        ...path,
        durationMs: 300,
        coordinateSpace: 'normalized',
        allowedPackages: settings.automation.packages,
        package: args.package,
      }, 25_000);
      scrolls++;
    } else if (needsUi && args.scroll && !args.gone && scrolls < maxScrolls) {
      const scrollable = (last?.nodes ?? []).find((node: any) => node.actions?.includes('scroll_forward'));
      if (scrollable) {
        await automation.cmd('act', {
          snapshotId: last.snapshotId,
          action: 'scroll',
          ref: scrollable.ref,
          direction: args.direction ?? 'forward',
          allowedPackages: settings.automation.packages,
          package: args.package,
        }, 25_000);
        scrolls++;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

const phoneSkills = new PhoneSkillStore(join(DATA_DIR, 'skills.json'));

async function skillPhone(args: any) {
  const action = String(args.action ?? '');
  if (action === 'list') return { skills: phoneSkills.list() };
  if (action === 'delete') {
    const name = String(args.name ?? '');
    if (!name) throw new Error('phone_skill delete requires a name');
    return { name, deleted: phoneSkills.remove(name) };
  }
  if (action === 'save') {
    const skill = phoneSkills.save(args.name, args.description, args.steps, args.overwrite === true, args.params, args.defaults);
    // Advisory preflight: tell the caller when the recipe silently depends on the screen it was
    // recorded on, so a flow that worked once does not become a flow that fails on replay.
    const issues = skillPreflightIssues(skill.steps);
    return { name: skill.name, description: skill.description ?? '', steps: skill.steps.length, params: skill.params ?? [], saved: true, ...(issues.length ? { warnings: issues } : {}) };
  }
  if (action === 'run') {
    const name = String(args.name ?? '');
    const skill = phoneSkills.get(name);
    if (!skill) throw new Error(`skill_not_found: '${name}' is not saved on this host`);
    const inputs = resolveSkillInputs(skill, args.inputs);
    const result = await taskPhone({ ...args, steps: skill.steps, inputs });
    phoneSkills.noteRun(name);
    return { name, inputs, ...result };
  }
  throw new Error('phone_skill requires action: list | save | run | delete');
}

async function taskPhone(args: any) {
  assertAutomationReady();
  const steps = Array.isArray(args.steps) ? args.steps : [];
  if (!steps.length) throw new Error('phone_task requires at least one step');
  if (steps.length > 30) throw new Error('phone_task supports at most 30 steps');
  const stopOnError = args.stopOnError !== false;
  const results: any[] = [];
  const outputs: Record<string, any> = {};   // step id -> result, plus the reserved `input` namespace
  if (args.inputs && typeof args.inputs === 'object' && !Array.isArray(args.inputs)) outputs.input = args.inputs;
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index] ?? {};
    const type = String(step.type ?? '');
    const stepArgs = step.args && typeof step.args === 'object' ? step.args : {};
    const retries = Math.max(0, Math.min(3, Number(step.retries ?? 0)));
    const retryDelayMs = Math.max(50, Math.min(3_000, Number(step.retryDelayMs ?? 300)));
    let attempt = 0;
    for (;;) {
      try {
        // Only-if guard: recipes frequently need an optional step whose target may not be on
        // screen (e.g. "return to the search box, but only when the app did not resume there").
        // When the guard selector is absent the step is skipped, not failed, and says so.
        if (step.onlyIf && typeof step.onlyIf === 'object') {
          const guard = await findPhone({ ...resolveTemplates(step.onlyIf, outputs), limit: 1 });
          if (!guard?.count) {
            results.push({ index, id: step.id, type, ok: true, skipped: true, reason: 'onlyIf not matched' });
            if (step.id) outputs[String(step.id)] = { skipped: true };
            break;
          }
        }
        const value = await runTaskStep(type, resolveTemplates(stepArgs, outputs));
        results.push({ index, id: step.id, type, ok: true, result: value });
        if (step.id) outputs[String(step.id)] = value;
        break;
      } catch (error) {
        const message = (error as Error).message || String(error);
        if (attempt >= retries) {
          results.push({ index, id: step.id, type, ok: false, error: message });
          if (stopOnError) return { ok: false, failedStep: index, steps: results };
          break;
        }
        attempt++;
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
  }
  return { ok: results.every((step) => step.ok), steps: results };
}

async function runTaskStep(type: string, args: any): Promise<any> {
  switch (type) {
    case 'observe':
      return contentToValue(await observePhone(args));
    case 'find':
      return await findPhone(args);
    case 'wait_any': {
      // Recipes have to survive apps that resume into different states (browser home vs results,
      // settings home vs search). A plain wait can express only one expectation; this succeeds
      // when the first of several selectors matches, and reports which one did.
      const conditions = Array.isArray(args.conditions) ? args.conditions.filter((item: any) => item && typeof item === 'object') : [];
      if (!conditions.length) throw new Error('wait_any requires a conditions array');
      const timeoutMs = Math.max(500, Math.min(60_000, Number(args.timeoutMs ?? 10_000)));
      const intervalMs = Math.max(150, Math.min(2_000, Number(args.intervalMs ?? 350)));
      const startedAt = Date.now();
      let lastError = '';
      for (;;) {
        for (let index = 0; index < conditions.length; index++) {
          try {
            const value = await waitPhone({ ...conditions[index], timeoutMs: 900, intervalMs: 300 });
            // waitPhone reports a miss as { timedOut: true } instead of throwing, so a plain call
            // would look like a match. Only a real match may short-circuit.
            if (value?.matched === true && value?.timedOut !== true) {
              return { matched: true, condition: index, conditionArgs: conditions[index], result: value };
            }
            lastError = 'condition ' + index + ' did not match';
          } catch (error) {
            lastError = (error as Error)?.message ?? String(error);
          }
        }
        if (Date.now() - startedAt >= timeoutMs) {
          throw new Error('wait_any_timeout: none of ' + conditions.length + ' conditions matched in ' + (Date.now() - startedAt) + 'ms; last=' + lastError.slice(0, 200));
        }
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
    }
    case 'wait': {
      const value = await waitPhone(args);
      // A timed-out wait must fail the step: otherwise the task continues as if the expected
      // UI state / agent signal had arrived. Retries and stopOnError then apply as usual.
      if (value?.timedOut) throw new Error('wait_timeout ' + JSON.stringify({ elapsedMs: value.elapsedMs, activePackage: value.activePackage, activity: value.activity, scrolls: value.scrolls }));
      return value;
    }
    case 'act':
      return contentToValue(await actPhone(args));
    case 'app':
      return await appPhone(args);
    case 'device':
      return await devicePhone(args);
    default:
      throw new Error('unsupported phone_task step: ' + type);
  }
}

function contentToValue(result: any): any {
  const text = result?.content?.find((item: any) => item.type === 'text')?.text;
  if (text == null) return result;
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

// One call should orient an AI: ask the device for its own status (foreground package, snapshot
// count, notification grant/ring, watchdog counters) but never fail the tool when it is offline.
async function automationDeviceStatus(): Promise<any> {
  try {
    return await automation.cmd('status', {}, 10_000);
  } catch (error) {
    return { error: (error as Error)?.message ?? String(error) };
  }
}

async function notificationsPhone(args: any) {
  assertAutomationReady();
  if (settings.automation.notifications !== true) {
    throw new Error('notifications_disabled: enable automation.notifications in ADH settings to let the AI read notification text');
  }
  const limit = Math.max(1, Math.min(30, Number(args.limit ?? 10)));
  const sinceMs = Number.isFinite(Number(args.sinceMs)) ? Math.max(0, Math.floor(Number(args.sinceMs))) : 0;
  const result = await automation.cmd('notifications', { limit, sinceMs }, 15_000);
  if (result?.granted === false) {
    // Reading notifications needs the user's explicit grant, so say exactly where it lives.
    throw new Error('notification_access_not_granted: enable "notification access" for ADH Manager in system settings (设置 → 通知 → 通知使用权), then retry');
  }
  return result;
}

async function devicePhone(args: any) {
  assertAutomationReady();
  return await automation.cmd('device', {
    action: args.action,
    stream: args.stream ?? 'music',
    index: args.index,
    text: args.text,
  }, 20_000);
}

async function appPhone(args: any) {
  assertAutomationReady();
  const packageName = String(args.package ?? '').trim();
  if (!packageName || !settings.automation.packages.includes(packageName)) {
    recordBlockedPackage(packageName);
    throw new Error(`blocked_package: ${packageName || '(empty)'} is not in the automation allowlist`);
  }
  const result = await automation.cmd('app', { action: args.action, package: packageName, allowedPackages: settings.automation.packages }, 25_000);
  if (args.action !== 'open' && args.action !== 'restart') return result;   // stop leaves the app, nothing to verify
  // An OEM dialog can swallow the launch while the call itself succeeds, so confirm the app
  // really reached the foreground and say what is in front when it did not.
  // Cold launches can take a while on ColorOS (splash + re-parenting); 12s keeps a slow but
  // real launch from being reported as a failure.
  const startedAt = Date.now();
  const deadline = startedAt + 12_000;
  let foreground: string | null = null;
  let blocked = false;
  let relaunched = false;
  for (;;) {
    try {
      const probe = await automation.cmd('observe', normalizeObserveArgs({ mode: 'tree', includeScreenshot: false, maxNodes: 1 }), 8_000);
      foreground = probe?.activePackage ?? null;
      blocked = false;
    } catch (error) {
      const packageFromError = blockedPackageFromError((error as Error)?.message);
      if (packageFromError) recordBlockedPackage(packageFromError);
      foreground = packageFromError;
      blocked = !!packageFromError;
    }
    if (foreground === packageName) {
      return { ...result, verified: true, foreground, ...(relaunched ? { relaunched: true } : {}) };
    }
    // One bounded re-issue: an OEM splash can swallow the first launch intent without an error.
    if (!relaunched && Date.now() - startedAt > 4_000) {
      relaunched = true;
      await automation.cmd('app', { action: 'open', package: packageName, allowedPackages: settings.automation.packages }, 25_000).catch(() => undefined);
    }
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  // ColorOS keeps some OEM settings sub-pages as floating windows that own the active
  // accessibility window: the launch lands behind them and verification fails. One BACK
  // dismisses that layer, so retry the launch exactly once before reporting failure.
  if (!blocked && needsDismissRetry(packageName, foreground)) {
    const blocker = foreground;
    await automation.cmd('act', { action: 'global', key: 'back', allowedPackages: settings.automation.packages }, 10_000).catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 350));
    await automation.cmd('app', { action: 'open', package: packageName, allowedPackages: settings.automation.packages }, 25_000).catch(() => undefined);
    const retryDeadline = Date.now() + 3_000;
    for (;;) {
      try {
        const probe = await automation.cmd('observe', normalizeObserveArgs({ mode: 'tree', includeScreenshot: false, maxNodes: 1 }), 8_000);
        foreground = probe?.activePackage ?? null;
      } catch {
        foreground = null;
      }
      if (foreground === packageName) {
        return { ...result, verified: true, foreground, dismissedBlockingPackage: blocker };
      }
      if (Date.now() >= retryDeadline) break;
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  }
  const hint = openOutcomeHint(packageName, foreground, blocked);
  return { ...result, verified: false, foreground, warning: hint };
}

async function observePhone(args: any) {
  assertAutomationReady();
  if (args.mode === 'text') {
    // Read the tree, then render it as terse lines on the host — the AI gets refs without the
    // verbose per-node JSON, which matters because every observe costs context. Asking for a
    // screenshot in the same call returns both: text to reason about, pixels to look at.
    const wantsScreenshot = args.includeScreenshot === true;
    const tree = await automation.cmd('observe', normalizeObserveArgs({ ...args, mode: 'tree', includeScreenshot: wantsScreenshot }), 25_000);
    const content: any[] = [{ type: 'text', text: renderScreenText(tree, { maxNodes: args.maxNodes }) }];
    const shot = tree?.screenshot;
    if (wantsScreenshot && shot?.base64) content.push({ type: 'image', data: shot.base64, mimeType: shot.mimeType ?? 'image/jpeg' });
    return { content };
  }
  const result = await automation.cmd('observe', normalizeObserveArgs(args), 25_000);
  return observationContent(result);
}

// A failed action should teach the AI what is actually on screen instead of costing another
// round trip. Best-effort: if the screen cannot be read (e.g. a non-allowlisted dialog is in
// front) that reason is reported instead of masking the original error.
async function screenContext(maxNodes = 25): Promise<string> {
  try {
    const tree = await automation.cmd('observe', normalizeObserveArgs({ mode: 'tree', includeScreenshot: false, maxNodes: 200 }), 8_000);
    return '\n--- current screen ---\n' + renderScreenText(tree, { maxNodes });
  } catch (error) {
    return '\n--- current screen unavailable: ' + ((error as Error)?.message ?? String(error)) + ' ---';
  }
}

async function actPhone(args: any) {
  assertAutomationReady();
  const cursorBefore = agentCursor();   // taken before dispatch: wait on it to catch this action's signals
  let effective = { ...args };
  // set_text carries its payload in `text`. Reading that same argument as a selector would demand a
  // node whose CURRENT text already equals the value we are about to write, so the field could
  // never be resolved. Exclude it from the implicit selector; selector:{text:...} still works.
  const implicitSelector = implicitSelectorFor(effective.action, effective);
  if (!effective.ref && Object.keys(implicitSelector).length) {
    // Bounded retry: the node tree churns while animations/list items settle, and a single miss
    // used to surface as a spurious selector_not_found. 3 attempts ≈ 500ms worst case.
    let match: any = null;
    let observed: any = null;
    for (let attempt = 0; attempt < 3 && !match; attempt++) {
      if (attempt) await new Promise((resolve) => setTimeout(resolve, 250));
      observed = await observeTree(effective);
      match = findNodes(observed.nodes ?? [], implicitSelector, 1)[0];
    }
    if (!match) throw new Error('selector_not_found: no node matched the selector in the current screen' + (await screenContext()));
    effective = { ...effective, snapshotId: observed.snapshotId, ref: match.ref };
  }
  // inputMode:"root" bypasses the accessibility gesture: same coordinates, injected through the
  // root Device Daemon. Some Compose UIs accept dispatchGesture but never act on it. The implicit
  // selector resolution above already turned a ref into a snapshotId+ref, so the device can derive
  // the pixel point from the node - a selector-only root tap used to fail with "requires x and y".
  if (effective.inputMode === 'root' && (effective.action === 'tap' || effective.action === 'swipe')) {
    effective = { ...effective, action: 'input', mode: effective.action === 'swipe' ? 'swipe' : 'tap' };
  }
  let result: any;
  try {
    result = await automation.cmd('act', normalizeActArgs(effective), 25_000);
  } catch (error) {
    // stale refs, rejected gestures and blocked windows all land here: hand back the screen.
    const blocked = blockedPackageFromError((error as Error)?.message);
    if (blocked) recordBlockedPackage(blocked);
    throw new Error(((error as Error)?.message ?? String(error)) + (await screenContext()));
  }
  // Self-healing fallback: some Compose UIs accept an accessibility gesture and never act on it
  // (the device reports changed:false). Re-inject the same coordinates through the root Device
  // Daemon once, so the caller does not have to know which app needs which path.
  if (
    result?.changed === false
    && (effective.action === 'tap' || effective.action === 'swipe')
    && effective.inputMode !== 'accessibility'
  ) {
    try {
      const fallbackArgs = normalizeActArgs({
        ...effective,
        action: 'input',
        mode: effective.action === 'swipe' ? 'swipe' : 'tap',
        ref: undefined,

        snapshotId: undefined,
      });
      const fallback = await automation.cmd('act', fallbackArgs, 25_000);
      result = { ...result, fallback: 'root', injected: fallback.mode, changed: fallback.changed };
    } catch (fallbackError) {
      result = { ...result, fallback: 'root_failed', fallbackError: (fallbackError as Error)?.message ?? String(fallbackError) };
    }
  }
  const parts: any[] = [{ type: 'text', text: JSON.stringify({ ...result, cursorBefore }, null, 2) }];
  if (args.observeAfter) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    parts.push(...observationContent(await automation.cmd('observe', normalizeObserveArgs(args), 25_000)).content);
  }
  return { content: parts };
}

function assertAutomationReady() {
  if (!settings.automation.enabled) throw new Error('automation_disabled: enable it in ADH settings on the host');
  if (!settings.automation.packages.length) throw new Error('automation_package_allowlist_empty: add at least one package in ADH settings');
}

function normalizeObserveArgs(args: any) {
  return {
    mode: args.mode ?? 'auto',
    includeScreenshot: args.includeScreenshot ?? 'auto',
    maxNodes: args.maxNodes ?? settings.automation.maxNodes,
    maxDepth: args.maxDepth ?? 50,
    interactiveOnly: args.interactiveOnly ?? false,
    screenshot: settings.automation.screenshot,
    screenshotMaxDimension: settings.automation.screenshotMaxDimension,
    allowedPackages: settings.automation.packages,
    package: args.package,
  };
}

function normalizeActArgs(args: any) {
  return {
    snapshotId: args.snapshotId,
    action: args.action,
    ref: args.ref,
    x: args.x,
    y: args.y,
    x2: args.x2,
    y2: args.y2,
    coordinateSpace: args.coordinateSpace ?? 'normalized',
    inputMode: args.inputMode,
    mode: args.mode,
    text: args.text,
    submit: args.submit,
    key: args.key,
    direction: args.direction,
    durationMs: args.durationMs,
    allowedPackages: settings.automation.packages,
    package: args.package,
  };
}

function observationContent(result: any) {
  const screenshot = result?.screenshot;
  const meta = { ...(result ?? {}), cursor: agentCursor() };
  if (screenshot) {
    const { base64, ...rest } = screenshot;
    meta.screenshot = rest;
  }
  const content: any[] = [{ type: 'text', text: JSON.stringify(meta, null, 2) }];
  if (screenshot?.base64) content.push({ type: 'image', data: screenshot.base64, mimeType: screenshot.mimeType ?? 'image/jpeg' });
  return { content };
}

function visibleMcpTools() {
  return MCP_TOOLS.filter((tool) => !tool.name.startsWith('phone_') || settings.automation.enabled);
}
/** REST surface for the skills panel: same implementation as the phone_skill MCP tool. */
export async function phoneSkillCommand(args: any): Promise<any> {
  return await skillPhone(args);
}

export const MCP_MAP = new Map(MCP_TOOLS.map(t => [t.name, t]));

export async function handleMcp(reqBody: string, res: ServerResponse, opts?: { package?: string }) {
  let msg: any;
  try { msg = JSON.parse(reqBody); } catch { res.writeHead(400).end('bad json'); return; }
  const pin = opts?.package;
  const reply = (result?: unknown, error?: unknown) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...(error ? { error } : { result }) });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(body);
  };
  if (msg.method === 'initialize') return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'adhd', version: '0.1.0' } });
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') { res.writeHead(202).end(); return; }
  if (msg.method === 'ping') return reply({});
  if (msg.method === 'tools/list') return reply({ tools: visibleMcpTools().map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    const t = MCP_MAP.get(name);
    if (!t) return reply(undefined, { code: -32602, message: `unknown tool: ${name}` });
    if (name.startsWith('phone_') && !settings.automation.enabled) return reply(undefined, { code: -32000, message: 'automation_disabled: user has not enabled phone automation' });
    let args = { ...(msg.params?.arguments ?? {}) };
    if (pin && name === 'process_list') {
      const out = [...sessions.values()].filter(s => s.package === pin);
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    }
    if (pin && args.session == null) {
      const sid = sessionForPackage(pin);
      if (sid) args.session = sid;
    }
    try {
      const out = await t.handler(args);
      if (t.raw) return reply(out);
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    } catch (e) { return reply({ content: [{ type: 'text', text: 'error: ' + (e as Error).message }], isError: true }); }
  }
  return reply(undefined, { code: -32601, message: `method not found: ${msg.method}` });
}
