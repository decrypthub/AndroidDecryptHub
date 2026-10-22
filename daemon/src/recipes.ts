// recipes.ts — named multi-step workflows over the primitives.
//
// The primitives answer "what CAN I do"; a recipe answers "do the thing". One call replaces the
// eight-tool sequence an operator has to get right (and the knowledge of which step needs a
// trigger, which one needs a wait, and which reply field carries the answer), which is what makes
// "analyze this app" reachable for someone who does not know the tool surface.
//
// Rules for a recipe:
//   - every step is reported with ok/ms/error, and a failed step does not stop the others: a
//     triage that cannot list dex files is still useful;
//   - a step returns a SMALL summary, never a raw multi-megabyte agent reply;
//   - no new agent capability is invented here. Recipes orchestrate; the agent executes.
import { captures, sessions } from './state.ts';
import { agentCmd, runUnpackBundle, pickSid, setCapture, drainSession, moduleLoads } from './service.ts';
import { detectionReport } from './detect.ts';
import { assembleHttpExchanges } from './http_exchange.ts';

export type RecipeOptions = Record<string, unknown>;
export interface RecipeStep { step: string; ok: boolean; ms: number; value?: unknown; error?: string }
export interface RecipeResult {
  recipe: string; session: string; package: string; ok: boolean;
  steps: RecipeStep[]; summary: Record<string, unknown>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, Math.min(120_000, ms))));

async function guard<T>(steps: RecipeStep[], name: string, fn: () => Promise<T>): Promise<T | undefined> {
  const t0 = Date.now();
  try {
    const value = await fn();
    steps.push({ step: name, ok: true, ms: Date.now() - t0, value });
    return value;
  } catch (e) {
    steps.push({ step: name, ok: false, ms: Date.now() - t0, error: (e as Error).message });
    return undefined;
  }
}

function categoryCounts(sid: string) {
  const out: Record<string, number> = { crypto: 0, net: 0, file: 0, system: 0 };
  for (const c of captures) if (c.sessionId === sid && out[c.category] !== undefined) out[c.category]++;
  return out;
}

function topAlgos(sid: string, n = 6) {
  const m = new Map<string, number>();
  for (const c of captures) {
    if (c.sessionId !== sid || c.category !== 'crypto') continue;
    const k = c.algo || '?';
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([algo, count]) => ({ algo, count }));
}

/** Fresh view of the TLS records, drained first so a recipe that just waited sees what arrived. */
async function httpSummary(sid: string, sampleLimit = 5) {
  const chunks = captures.filter((c) => c.sessionId === sid && c.category === 'net');
  const asm = assembleHttpExchanges(chunks);
  return {
    records: chunks.length,
    exchanges: asm.exchanges.length,
    unpaired: asm.noConn,
    http2: asm.http2,
    samples: asm.exchanges.slice(-Math.max(1, sampleLimit)).map((x) => ({
      startLine: x.request?.startLine ?? '',
      host: (x.request?.headerText ?? '').split('\r\n').find((l) => /^host:/i.test(l))?.slice(6).trim() ?? '',
      status: x.status,
    })),
  };
}

function requireSession(sid: string) {
  const s = sessions.get(sid);
  if (!s) throw new Error(`no session ${sid}`);
  return s;
}

async function armCapture(steps: RecipeStep[], sid: string) {
  return guard(steps, 'capture_on', async () => {
    const r: any = await setCapture(sid, true);
    // setCapture derives the verdict (installed vs attempted); ok:true alone would only mean the
    // command ran, which is why the counts are reported here too.
    return { on: r?.ok === true && r?.on !== false, installed: r?.installed ?? null, attempted: r?.attempted ?? null, skipped: r?.skipped ?? null };
  });
}

// ---- triage ------------------------------------------------------------------------------
// "What is this app doing?" in one call: what the agent can do, how big the process is, what code
// it loaded, whether capture is armed, what detection surface the target touched, and what the
// capture store has seen so far.
async function triage(sid: string, opts: RecipeOptions): Promise<RecipeResult> {
  const s = requireSession(sid);
  const steps: RecipeStep[] = [];
  await guard(steps, 'caps', async () => ({
    ops: s.caps?.ops?.length ?? null,
    limits: s.caps?.limits ?? null,
  }));
  const maps = await guard(steps, 'maps', async () => {
    const r: any = await agentCmd(sid, 'maps', {}, 30_000);
    if (!r?.ok) throw new Error(String(r?.error ?? 'maps failed'));
    return { regions: Number(r.count ?? r.regions?.length ?? 0) };
  });
  await guard(steps, 'dexfiles', async () => {
    const r: any = await agentCmd(sid, 'art_dexfiles', {}, 30_000);
    if (!r?.ok) throw new Error(String(r?.error ?? 'art_dexfiles failed'));
    return { dexFiles: Number(r.count ?? 0), loaders: Number(r.loaders ?? 0) };
  });
  await armCapture(steps, sid);
  // Module-load broadcast during the window: a payload decrypted after startup appears HERE, not in
  // the maps snapshot we took a second ago. Started before the wait so nothing is missed.
  await guard(steps, 'module_watch', async () => {
    const r: any = await agentCmd(sid, 'module_watch', { action: 'start' }, 10_000);
    if (r?.ok === false) throw new Error(String(r?.error ?? 'module_watch start failed'));
    return { watching: r?.watching === true };
  });
  const waitMs = Math.max(0, Number(opts.captureMs ?? 3000));
  await guard(steps, 'observe', async () => { await sleep(waitMs); return { waitedMs: waitMs }; });
  // One drain so the window's records (and the MODULE_LOAD events) are in the store before reading.
  await guard(steps, 'drain', async () => { await drainSession(sid); return { drained: true }; });
  await guard(steps, 'modules', async () => ({ loaded: moduleLoads(sid, 20) }));
  await guard(steps, 'module_watch_stop', async () => {
    await agentCmd(sid, 'module_watch', { action: 'stop' }, 10_000);
    return { stopped: true };
  });
  await guard(steps, 'detect', async () => {
    const d = detectionReport({ session: sid });
    return {
      armed: d.armed,
      reason: d.reason,
      hits: d.kinds.filter((k) => k.count > 0).map((k) => ({ kind: k.kind, count: k.count })),
      unchecked: d.unchecked,
    };
  });
  const counts = categoryCounts(sid);
  await guard(steps, 'captures', async () => ({ counts, topAlgos: topAlgos(sid) }));
  const loaded = (steps.find((x) => x.step === 'modules')?.value as any)?.loaded ?? [];
  return {
    recipe: 'triage', session: sid, package: s.package, ok: steps.every((x) => x.ok), steps,
    summary: {
      agentVer: s.agentVer, entry: s.entry, pid: s.pid,
      ops: s.caps?.ops?.length ?? null,
      regions: (maps as any)?.regions ?? null,
      modulesLoaded: loaded,
      crypto: counts.crypto, net: counts.net, file: counts.file, system: counts.system,
      topAlgos: topAlgos(sid),
      hint: 'counts grow only while capture is on; capture_window with a trigger attributes them to one action',
    },
  };
}

// ---- capture_window ----------------------------------------------------------------------
// Arm capture, optionally run ONE Java call as the trigger, wait, then report what arrived. That
// is the "do the thing and show me what happened" primitive: a caller supplies the trigger (the
// class/method is target knowledge, never hardcoded here) and gets a digest back.
async function captureWindow(sid: string, opts: RecipeOptions): Promise<RecipeResult> {
  const s = requireSession(sid);
  const steps: RecipeStep[] = [];
  await armCapture(steps, sid);
  const trig = opts.trigger as { className?: string; method?: string; params?: string; args?: unknown[] } | undefined;
  if (trig && trig.className && trig.method) {
    await guard(steps, 'trigger', async () => {
      const r: any = await agentCmd(sid, 'java_call', {
        className: String(trig.className),
        method: String(trig.method),
        params: String(trig.params ?? ''),
        args: Array.isArray(trig.args) ? trig.args : [],
      }, 20_000);
      if (r?.ok === false) throw new Error(String(r?.error ?? 'trigger failed'));
      return { ok: true, result: r?.result?.result ?? null };
    });
  }
  const waitMs = Math.max(0, Number(opts.ms ?? 2000));
  await guard(steps, 'observe', async () => { await sleep(waitMs); return { waitedMs: waitMs }; });
  const counts = categoryCounts(sid);
  await guard(steps, 'captures', async () => ({ counts, topAlgos: topAlgos(sid) }));
  return {
    recipe: 'capture_window', session: sid, package: s.package, ok: steps.every((x) => x.ok), steps,
    summary: {
      triggered: !!(trig && trig.className && trig.method),
      crypto: counts.crypto, net: counts.net, file: counts.file, system: counts.system,
      topAlgos: topAlgos(sid),
    },
  };
}

// ---- http_capture ------------------------------------------------------------------------
// "Show me the requests": arm TLS capture, optionally trigger, wait, drain, then pair the plaintext
// into whole HTTP exchanges. Only SSL_read/SSL_write records can be assembled - an app on QUIC or
// with its own TLS stack produces none, and the summary says that instead of returning an empty
// list that reads like "this app made no requests".
async function httpCapture(sid: string, opts: RecipeOptions): Promise<RecipeResult> {
  const s = requireSession(sid);
  const steps: RecipeStep[] = [];
  await armCapture(steps, sid);
  const trig = opts.trigger as { className?: string; method?: string; params?: string; args?: unknown[] } | undefined;
  if (trig && trig.className && trig.method) {
    await guard(steps, 'trigger', async () => {
      const r: any = await agentCmd(sid, 'java_call', {
        className: String(trig.className), method: String(trig.method),
        params: String(trig.params ?? ''), args: Array.isArray(trig.args) ? trig.args : [],
      }, 20_000);
      if (r?.ok === false) throw new Error(String(r?.error ?? 'trigger failed'));
      return { ok: true, result: r?.result?.result ?? null };
    });
  }
  const waitMs = Math.max(0, Number(opts.ms ?? 3000));
  await guard(steps, 'observe', async () => { await sleep(waitMs); return { waitedMs: waitMs }; });
  await guard(steps, 'drain', async () => { await drainSession(sid); return { drained: true }; });
  const http: any = await guard(steps, 'http', async () => httpSummary(sid, Number(opts.samples ?? 8)));
  return {
    recipe: 'http_capture', session: sid, package: s.package, ok: steps.every((x) => x.ok), steps,
    summary: {
      ...(http ?? {}),
      hint: 'records:0 is normal for QUIC or a private TLS stack; the crypto counts show whether the app encrypts on its own',
    },
  };
}

// ---- anti_debug ---------------------------------------------------------------------------
// Neutralize the checks that kill an analysis session: the return value AND errno of the libc
// entry points anti-debug code branches on. Two calls by design - without confirm:true this only
// returns the plan (what it would hook), because installing these changes how the target behaves
// for everything it does afterwards: `access`/`faccessat` then fail with EACCES for EVERY path,
// which is the point but also breaks the app's own file checks.
const ANTI_DEBUG_DEFAULTS = [
  { symbol: 'ptrace', returnValue: '0', errno: 0 },
  { symbol: 'access', returnValue: '-1', errno: 13 },
  { symbol: 'faccessat', returnValue: '-1', errno: 13 },
];

async function antiDebug(sid: string, opts: RecipeOptions): Promise<RecipeResult> {
  const s = requireSession(sid);
  const steps: RecipeStep[] = [];
  const apply = opts.confirm === true;
  const undo = Array.isArray(opts.undoHookIds) ? (opts.undoHookIds as unknown[]) : [];
  const module = String(opts.module ?? 'libc.so');
  const targets = (Array.isArray(opts.targets) && opts.targets.length)
    ? (opts.targets as Record<string, unknown>[])
    : ANTI_DEBUG_DEFAULTS;
  if (!apply && undo.length === 0) {
    steps.push({ step: 'plan', ok: true, ms: 0, value: { module, targets } });
    return {
      recipe: 'anti_debug', session: sid, package: s.package, ok: true, steps,
      summary: { applied: false, reason: 'confirm:true is required to install neutralizers', module, targets },
    };
  }
  const hookIds: number[] = [];
  if (apply) {
    for (const t of targets) {
      const symbol = String((t as any).symbol ?? '');
      if (!symbol) continue;
      await guard(steps, `hook:${symbol}`, async () => {
        const r: any = await agentCmd(sid, 'native_hook', {
          action: 'hook', mode: 'inline', module: String((t as any).module ?? module), symbol,
          skipOriginal: 'true',
          returnValue: String((t as any).returnValue ?? '-1'),
          errno: Number((t as any).errno ?? 0),
        }, 20_000);
        if (r?.ok === false) throw new Error(String(r?.error || 'install failed'));
        if (Number(r?.hookId) > 0) hookIds.push(Number(r.hookId));
        return { hookId: r?.hookId ?? 0, symbol };
      });
    }
  }
  for (const id of undo) {
    await guard(steps, `unhook:${id}`, async () => {
      const r: any = await agentCmd(sid, 'native_hook', { action: 'unhook', hookId: Number(id), hard: 'true' }, 20_000);
      if (r?.ok === false) throw new Error(String(r?.error || 'unhook failed'));
      return { unhooked: Number(id) };
    });
  }
  return {
    recipe: 'anti_debug', session: sid, package: s.package, ok: steps.every((x) => x.ok), steps,
    summary: {
      applied: apply, module, hookIds, installed: hookIds.length,
      hint: 'pass undoHookIds:[...] to remove them; while installed, every access()/faccessat() fails with EACCES',
    },
  };
}


// ---- unpack ------------------------------------------------------------------------------
// Cold start (unless told otherwise) and dump every DEX of the package, then report what landed.
// runUnpackBundle already owns the sequence; the recipe only makes it one call with a summary.
async function unpack(sid: string, opts: RecipeOptions): Promise<RecipeResult> {
  const s = requireSession(sid);
  const steps: RecipeStep[] = [];
  const pkg = String(opts.package ?? s.package ?? '');
  const out = await guard(steps, 'unpack', async () => {
    const r: any = await runUnpackBundle({
      package: pkg,
      session: sid,
      launch: opts.launch !== false,
      forceRestart: opts.forceRestart === true,
      ...(opts.launchTimeoutMs ? { launchTimeoutMs: Number(opts.launchTimeoutMs) } : {}),
    });
    if (r?.ok === false) throw new Error(String(r?.error ?? 'unpack failed'));
    return {
      package: r?.package ?? pkg,
      bundle: r?.bundle ?? null,
      included: Array.isArray(r?.included) ? r.included.length : null,
    };
  });
  return {
    recipe: 'unpack', session: sid, package: pkg, ok: steps.every((x) => x.ok), steps,
    summary: { ...(out ?? {}), hint: 'bundle is a stored zip; the artifact store lists every dex with its carrier/real classification' },
  };
}

export interface RecipeSpec { description: string; needs: string[]; run: (sid: string, opts: RecipeOptions) => Promise<RecipeResult> }

export const RECIPES: Record<string, RecipeSpec> = {
  triage: {
    description: 'What is this app doing: agent capabilities, process size, loaded dex files, capture window, detection surface, and what the capture store has seen.',
    needs: ['session'],
    run: triage,
  },
  capture_window: {
    description: 'Arm capture, optionally run one Java method as the trigger, wait, then report the crypto/net/file/system counts and the top algorithms. The trigger is supplied by the caller, never hardcoded.',
    needs: ['session', 'options.trigger?.className+method (optional)', 'options.ms'],
    run: captureWindow,
  },
  unpack: {
    description: 'Cold start (unless launch:false) and dump every DEX of the package into a stored bundle, with a summary of what landed.',
    needs: ['session', 'options.package (defaults to the session package)'],
    run: unpack,
  },
  http_capture: {
    description: 'The "show me the requests" recipe: arm TLS capture, optionally run one Java method as the trigger, wait, drain, and pair the plaintext into whole HTTP exchanges (method/path/host/status). An app on QUIC or with a private TLS stack produces no records, and the summary says so instead of looking quiet.',
    needs: ['session', 'options.ms', 'options.trigger?.className+method (optional)', 'options.samples'],
    run: httpCapture,
  },
  anti_debug: {
    description: 'Neutralize the anti-debug checks that kill a session: ptrace returns 0, access/faccessat return -1 with EACCES (return value AND errno). Without confirm:true it only returns the plan; with it, one call per symbol and the hookIds to undo. undoHookIds removes a previous run.',
    needs: ['session', 'options.confirm', 'options.targets (optional)', 'options.undoHookIds (optional)'],
    run: antiDebug,
  },
};

export function listRecipes() {
  return Object.entries(RECIPES).map(([name, r]) => ({ name, description: r.description, needs: r.needs }));
}

export async function runRecipe(name: string, session: string, options: RecipeOptions = {}): Promise<RecipeResult> {
  const spec = RECIPES[name];
  if (!spec) throw new Error(`unknown recipe '${name}' (have: ${Object.keys(RECIPES).join(', ')})`);
  const sid = pickSid(session);
  if (!sid) throw new Error('no online agent session');
  return spec.run(sid, options ?? {});
}
