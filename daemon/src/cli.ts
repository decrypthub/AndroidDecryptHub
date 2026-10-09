#!/usr/bin/env node
// ADH CLI (`adh`) — the operator's command line for a running Host ADH Daemon.
//
// It is a CLIENT, not a second server: every subcommand is one or more HTTP calls to adhd
// (default 127.0.0.1:8088; override with ADH_HTTP_PORT / --host / --port). It imports nothing from
// state.ts / service.ts / mcp.ts, so it has no way to drift from the daemon's own truth, and it
// works against a daemon running on another machine. Nothing imports THIS file.
//
// Why it exists: before this, every session — human or AI — hand-rolled the same shell + node glue
// to "find the online agent for a package and pick its session" (that block had been copied into 76
// of the 117 tools/verify_*.sh scripts, and re-derived by hand in every investigation). The block
// now has exactly one implementation, and the acceptance script exercises it through this binary.
//
// FLAG DISCIPLINE — read this before adding a flag. A flag that is accepted and then ignored is
// worse than a flag that does not exist: the command exits 0 having done something other than what
// it was asked to do, and the operator trusts the result. (That exact defect was found in a sibling
// project's diagnostic CLI: `--proxy`/`--cookie-file` were registered in the shared flag set but
// consumed by only one subcommand, so `face --proxy …` silently ignored the proxy — on the one code
// path where the egress IP was the variable under test.) Therefore:
//   1. flags are declared PER COMMAND, and an unknown or misplaced flag is a usage error (exit 2);
//   2. every declared flag must appear in that command's `handlerFlags` — asserted by
//      daemon/test/cli_args.test.ts, so a flag nobody reads fails the unit test;
//   3. every declared flag must have an observable effect — asserted by tools/verify_v100_adh_cli.sh.
//
// Exit codes mirror the acceptance gate's three states instead of inventing a second vocabulary
// (the gate calls it PASS / SKIP / FAIL; the same distinction matters here — "I could not check"
// is not "the answer is no"):
//   0 ok           the thing you asked about is true
//   1 fail         it ran, and the answer is no (no agent for that package, version drift, …)
//   2 usage        the command or its flags are wrong
//   3 unavailable  a prerequisite is missing (daemon not reachable) — the gate's SKIP

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as http from 'node:http';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

import { HTTP_PORT } from './config.ts';

const CLI_NAME = 'adh';
const DEFAULT_HOST = '127.0.0.1';
/** Per-command default request budget. `unpack` on a packer-protected target really does take tens
 *  of seconds for large targets, so a short default would abort a run
 *  that was working. */
const DEFAULT_TIMEOUT_S: Record<string, number> = { doctor: 10, target: 60, unpack: 180 };

export const EXIT = { ok: 0, fail: 1, usage: 2, unavailable: 3 } as const;

class CliError extends Error {
  // Plain fields, not TypeScript parameter properties: this repo has no build step and node runs
  // .ts in strip-only mode, which rejects `constructor(readonly x: T)` outright.
  exit: number;
  constructor(message: string, exit: number = EXIT.fail) {
    super(message);
    this.name = 'CliError';
    this.exit = exit;
  }
}

// ---------------------------------------------------------------------------------------------
// flag declarations (one table drives parsing, --help, and the unit test)
// ---------------------------------------------------------------------------------------------

export interface FlagSpec {
  name: string;
  kind: 'string' | 'bool';
  desc: string;
}

const FLAG_HOST: FlagSpec = { name: 'host', kind: 'string', desc: 'daemon host (default 127.0.0.1)' };
const FLAG_PORT: FlagSpec = { name: 'port', kind: 'string', desc: `daemon HTTP port (default ADH_HTTP_PORT ?? ${HTTP_PORT})` };
const FLAG_JSON: FlagSpec = { name: 'json', kind: 'bool', desc: 'machine-readable: one JSON object on stdout' };
const FLAG_HELP: FlagSpec = { name: 'help', kind: 'bool', desc: 'show help' };
const FLAG_PACKAGE: FlagSpec = { name: 'package', kind: 'string', desc: 'target app package (required when more than one agent is online)' };
const FLAG_SESSION: FlagSpec = { name: 'session', kind: 'string', desc: 'pin one agent session id instead of resolving by package' };
const FLAG_TIMEOUT: FlagSpec = { name: 'timeout', kind: 'string', desc: 'request budget in seconds (overrides the per-command default)' };
/** What a shell script actually wants: the one value, on one line, with nothing to parse. Without it
 *  a caller has to pipe --json back through node/jq — i.e. re-hand-roll the very glue this CLI
 *  replaces. Only `target` has a single answer; commands without one do not declare it. */
const FLAG_QUIET: FlagSpec = { name: 'quiet', kind: 'bool', desc: 'print only the answer (target: the session id)' };

export const GLOBAL_FLAGS: FlagSpec[] = [FLAG_HOST, FLAG_PORT, FLAG_JSON, FLAG_HELP];

export interface CommandSpec {
  desc: string;
  flags: FlagSpec[];
  /** Every flag the handler actually reads. The unit test asserts this covers `flags` exactly, so a
   *  declared-but-unread flag cannot land. */
  handlerFlags: string[];
}

export const COMMANDS: Record<string, CommandSpec> = {
  doctor: {
    // Deliberately target-agnostic: it reports on the daemon and on every registered agent, so it
    // takes no --package/--session (a flag that does nothing is the defect this file guards against).
    desc: 'self-check: daemon health, flashed-agent vs source version pairing, backends, agent registry',
    flags: [FLAG_TIMEOUT],
    handlerFlags: ['host', 'port', 'json', 'timeout'],
  },
  target: {
    desc: 'resolve the target agent and report its live facts (the first call of any session)',
    flags: [FLAG_PACKAGE, FLAG_SESSION, FLAG_TIMEOUT, FLAG_QUIET],
    handlerFlags: ['host', 'port', 'json', 'package', 'session', 'timeout', 'quiet'],
  },
  unpack: {
    desc: 'one-shot dump_all_dex: dump every ART DexFile, classify each one, optionally save them',
    flags: [
      FLAG_PACKAGE,
      FLAG_SESSION,
      FLAG_TIMEOUT,
      { name: 'out', kind: 'string', desc: 'directory to write the dumped dexes into' },
      { name: 'include-carriers', kind: 'bool', desc: 'also download carrier dexes (default: only real code)' },
    ],
    handlerFlags: ['host', 'port', 'json', 'package', 'session', 'timeout', 'out', 'include-carriers'],
  },
};

export interface ParsedArgs {
  cmd: string;
  opts: Record<string, string | boolean>;
  help: boolean;
  error?: string;
}

/** Strict, per-command flag parsing. Pure — the unit test drives it directly. */
export function parseArgs(argv: string[]): ParsedArgs {
  const [rawCmd, ...rest] = argv;
  // `adh --help` (no command yet) is a request for the command list, not an unknown command.
  if (rawCmd === '--help' || rawCmd === '-h') return { cmd: '', opts: { help: true }, help: true, error: undefined };
  const cmd = rawCmd ?? '';
  if (!cmd) return { cmd: '', opts: {}, help: true, error: `missing command` };
  const spec = COMMANDS[cmd];
  if (!spec) {
    return { cmd, opts: {}, help: false, error: `unknown command '${cmd}' (known: ${Object.keys(COMMANDS).join(', ')})` };
  }
  const accepted = [...spec.flags, ...GLOBAL_FLAGS];
  const byName = new Map(accepted.map((f) => [f.name, f]));
  const opts: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === '-h') { opts.help = true; continue; }
    if (!arg.startsWith('--')) {
      return { cmd, opts, help: false, error: `unexpected argument '${arg}' (flags are --name; see '${CLI_NAME} ${cmd} --help')` };
    }
    const eq = arg.indexOf('=');
    const name = (eq >= 0 ? arg.slice(2, eq) : arg.slice(2)).trim();
    const f = byName.get(name);
    if (!f) {
      const known = [...accepted].map((x) => `--${x.name}`).sort().join(' ');
      return { cmd, opts, help: false, error: `unknown flag '--${name}' for '${cmd}' (accepted: ${known})` };
    }
    if (f.kind === 'bool') {
      if (eq >= 0) return { cmd, opts, help: false, error: `'--${name}' takes no value` };
      opts[name] = true;
      continue;
    }
    const value = eq >= 0 ? arg.slice(eq + 1) : rest[++i];
    if (value === undefined || value.startsWith('--')) {
      return { cmd, opts, help: false, error: `'--${name}' needs a value` };
    }
    opts[name] = value;
  }
  return { cmd, opts, help: opts.help === true, error: undefined };
}

// ---------------------------------------------------------------------------------------------
// daemon access
// ---------------------------------------------------------------------------------------------

interface AgentSession {
  sessionId: string;
  pid: number;
  package: string;
  process?: string;
  abi?: string;
  android?: string;
  sdk?: number;
  entry?: string;
  agentVer?: string;
  selfModule?: string;
  selfBase?: string;
  connectedAt?: number;
  online?: boolean;
}

class Daemon {
  readonly host: string;
  readonly port: number;
  readonly base: string;
  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.base = `http://${host}:${port}`;
  }

  /**
   * Plain node:http rather than fetch, on purpose. fetch's AbortSignal aborts the request but on
   * Windows leaves the pending connect handle alive, so the process outlived its own timeout by
   * ~8.7s after printing the error (measured). `node:http` also needs care: `req.setTimeout` arms a
   * SOCKET-idle timer and does not bound the connect phase — with it, a `--timeout 2` run against an
   * unreachable host printed its error at 5.1s (measured) while claiming two. So the budget is an
   * explicit wall-clock timer that destroys the request, and the process exits as soon as it has an
   * answer (this CLI runs inside scripts; "printed an error and then hung" is the worst behaviour it
   * could have).
   */
  private request(method: string, path: string, opts: { body?: string; timeoutS: number }): Promise<{ status: number; buf: Buffer }> {
    const { timeoutS } = opts;
    const body = opts.body;
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (body !== undefined) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = String(Buffer.byteLength(body));
      }
      let settled = false;
      const finish = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); fn(); } };
      const timer = setTimeout(() => req.destroy(new Error(`timed out after ${timeoutS}s`)), timeoutS * 1000);
      const req = http.request({ host: this.host, port: this.port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => finish(() => resolve({ status: res.statusCode ?? 0, buf: Buffer.concat(chunks) })));
        res.on('error', (e) => finish(() => reject(new CliError(`cannot reach the ADH Daemon at ${this.base} (${e.message})`, EXIT.unavailable))));
      });
      req.on('error', (e: NodeJS.ErrnoException) => {
        const detail = e.code ?? e.message;
        finish(() => reject(new CliError(`cannot reach the ADH Daemon at ${this.base} (${detail})`, EXIT.unavailable)));
      });
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  async json(path: string, opts: { method?: string; body?: string; timeoutS: number }): Promise<any> {
    const { status, buf } = await this.request(opts.method ?? 'GET', path, opts);
    const text = buf.toString('utf8');
    if (status < 200 || status >= 300) throw new CliError(`${path} -> HTTP ${status}: ${text.slice(0, 300)}`, EXIT.fail);
    try {
      return JSON.parse(text);
    } catch {
      throw new CliError(`${path} -> not JSON: ${text.slice(0, 200)}`, EXIT.fail);
    }
  }

  async bytes(path: string, timeoutS: number): Promise<Buffer> {
    const { status, buf } = await this.request('GET', path, { timeoutS });
    if (status < 200 || status >= 300) throw new CliError(`${path} -> HTTP ${status}`, EXIT.fail);
    return buf;
  }

  /** One agent command through the MCP surface — the same implementation the AI tools call, so the
   *  CLI cannot exercise a different code path than the one under test elsewhere. */
  async mcp(name: string, args: Record<string, unknown>, session: string, timeoutS: number): Promise<any> {
    const body = JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name, arguments: { session, ...args } },
    });
    const r = await this.json('/mcp', { method: 'POST', body, timeoutS });
    const text = r?.result?.content?.[0]?.text;
    if (text === undefined) throw new CliError(`MCP ${name} -> unexpected reply: ${JSON.stringify(r).slice(0, 300)}`, EXIT.fail);
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }
}

/** Resolve THE target agent. Ambiguity is an error, never a silent pick: choosing a different
 *  process than the one asked about is the one mistake this command must not make. */
export function pickSession(agents: AgentSession[], pkg?: string, session?: string): AgentSession {
  if (session) {
    const hit = agents.find((a) => a.sessionId === session);
    if (!hit) throw new CliError(`no agent session '${session}' in the registry`, EXIT.fail);
    if (hit.online === false) throw new CliError(`agent session '${session}' (${hit.package}) is offline`, EXIT.fail);
    return hit;
  }
  const online = agents.filter((a) => a.online !== false);
  if (!online.length) {
    throw new CliError('no agent online — start the target, then check `adb reverse` (tools/dev_up.sh)', EXIT.unavailable);
  }
  const candidates = pkg ? online.filter((a) => a.package === pkg) : online;
  if (!candidates.length) {
    throw new CliError(`no online agent for package '${pkg}' (online: ${online.map((a) => a.package).join(', ')})`, EXIT.fail);
  }
  if (candidates.length > 1) {
    const list = candidates.map((a) => `${a.package} pid=${a.pid} session=${a.sessionId}`).join('; ');
    throw new CliError(`ambiguous target (${candidates.length} agents online): ${list} — pass --package or --session`, EXIT.usage);
  }
  return candidates[0];
}

// ---------------------------------------------------------------------------------------------
// local checkout facts (used by doctor's version pairing; absent when the CLI runs standalone)
// ---------------------------------------------------------------------------------------------

const repoRoot = resolvePath(dirname(fileURLToPath(import.meta.url)), '..', '..');

export interface RepoVersions {
  root: string;
  agentVer?: string;
  moduleVersion?: string;
}

/** The agent version compiled into the .so and the module version that ships it must be bumped
 *  together (agent/src/MAP.md). Reading both is how `doctor` answers "is the phone running the
 *  build this checkout produces?" without adb — the agent reports its own AGENT_VER. */
export function repoVersions(root = repoRoot): RepoVersions | null {
  const header = join(root, 'agent', 'src', 'bootstrap', 'agent_internal.h');
  const moduleProp = join(root, 'injector', 'zygisk', 'module', 'module.prop');
  if (!existsSync(header) && !existsSync(moduleProp)) return null;
  const out: RepoVersions = { root };
  try {
    out.agentVer = /^#define\s+AGENT_VER\s+"([^"]+)"/m.exec(readFileSync(header, 'utf8'))?.[1];
  } catch { /* absent header stays undefined */ }
  try {
    out.moduleVersion = /^version=(.+)$/m.exec(readFileSync(moduleProp, 'utf8'))?.[1]?.trim();
  } catch { /* absent module.prop stays undefined */ }
  return out;
}

const normVer = (v?: string) => (v ?? '').replace(/^v/, '').trim();

// ---------------------------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------------------------

interface Ctx {
  daemon: Daemon;
  opts: Record<string, string | boolean>;
  json: boolean;
  timeoutS: number;
  lines: string[];
}

function say(ctx: Ctx, line = '') {
  ctx.lines.push(line);
}

function emit(ctx: Ctx, result: Record<string, unknown>, code: number): number {
  if (ctx.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else process.stdout.write(`${ctx.lines.join('\n')}\n`);
  return code;
}

async function cmdDoctor(ctx: Ctx): Promise<number> {
  const health = await ctx.daemon.json('/health', { timeoutS: ctx.timeoutS });
  // Two different views on purpose: /api/agents carries the full session identity the agent
  // reported about itself (agentVer / selfModule / abi / sdk), while /api/backends carries the
  // injection-backend matrix (zygisk scope pointer, xposed module, gadget cache). Reading the
  // agent version off /api/backends would silently print '?' — its agent rows are pointers only.
  const agents: AgentSession[] = await ctx.daemon.json('/api/agents', { timeoutS: ctx.timeoutS });
  const backends = await ctx.daemon.json('/api/backends', { timeoutS: ctx.timeoutS });
  const repo = repoVersions();

  say(ctx, `${health.name ?? 'ADH Daemon'} @ ${ctx.daemon.base}`);
  say(ctx, `  version ${health.version} · uptime ${Math.round(Number(health.uptime ?? 0))}s · mcp tools ${health.mcpTools} · agents ${health.agents}`);
  // webUrls() returns { port, local, lan } — not a list of strings.
  const web = health.web as { local?: string; lan?: string[] } | undefined;
  if (web?.local) say(ctx, `  web        ${[web.local, ...(web.lan ?? [])].join('  ')}`);

  say(ctx, 'agents');
  if (!agents.length) {
    say(ctx, '  (none online — host-only check; start the target, then verify `adb reverse`)');
  }
  for (const a of agents) {
    const how = a.selfModule ?? '(unknown)';
    say(ctx, `  ${a.package}  pid ${a.pid}  ${a.online === false ? 'offline' : 'online'}  entry=${a.entry ?? '?'}  agentVer=${a.agentVer ?? '?'}  ${a.abi ?? ''} sdk=${a.sdk ?? '?'}`);
    say(ctx, `    loaded as: ${how}`);
  }

  const problems: string[] = [];
  say(ctx, 'version pairing');
  if (!repo) {
    say(ctx, '  (no checkout next to this CLI — skipped; run it from the repo to compare)');
  } else {
    say(ctx, `  source AGENT_VER ${repo.agentVer ?? '(missing)'} · module.prop ${repo.moduleVersion ?? '(missing)'}`);
    if (repo.agentVer && repo.moduleVersion && normVer(repo.agentVer) !== normVer(repo.moduleVersion)) {
      problems.push(`agent/src AGENT_VER (${repo.agentVer}) and module.prop (${repo.moduleVersion}) disagree — they must be bumped together (agent/src/MAP.md)`);
    }
    // Only ONLINE agents count as "the flashed agent". An offline entry is a process that has already
    // exited, and its agentVer is whatever was loaded when it started — the ADH Manager process in
    // particular lingers from flashes several versions back. Comparing those made doctor report
    // MISMATCH indefinitely after an upgrade, pointing at a reflash that cannot fix anything: the
    // .so on disk is already current, the stale number came from a process that is gone.
    const running = agents.filter((a) => a.online !== false);
    const drifted = running.filter(
      (a) => a.agentVer && repo.agentVer && normVer(a.agentVer) !== normVer(repo.agentVer));
    for (const a of drifted) {
      problems.push(`${a.package} (pid ${a.pid}) runs agent ${a.agentVer} but this checkout builds ${repo.agentVer} — rebuild+reflash: bash tools/build_agent.sh && bash tools/flash_device.sh --reboot`);
    }
    if (running.length && repo.agentVer) {
      const ignored = agents.length - running.length;
      say(ctx, `  ${drifted.length ? 'MISMATCH' : 'in-sync'} with the running agent${ignored ? ` (${ignored} offline session(s) ignored)` : ''}`);
    }
  }

  say(ctx, 'backends');
  say(ctx, `  zygisk  ${backends.zygisk?.control ?? '?'}`);
  say(ctx, `  xposed  ${backends.xposed?.module ?? '?'}`);
  const cached = backends.gadget?.cached ?? [];
  say(ctx, `  gadget  ${cached.length} cached build(s)${cached.length ? `: ${cached.map((c: any) => `${c.version}/${c.abi}`).join(', ')}` : ''}`);

  const ok = problems.length === 0;
  say(ctx, ok ? '✅ doctor: ok' : '❌ doctor: FAIL');
  for (const p of problems) say(ctx, `   - ${p}`);
  return emit(ctx, { ok, status: ok ? 'ok' : 'fail', base: ctx.daemon.base, health, agents, repo, problems }, ok ? EXIT.ok : EXIT.fail);
}

async function cmdTarget(ctx: Ctx): Promise<number> {
  // Mutually exclusive on purpose: "--quiet --json" has no single obvious meaning, and guessing is
  // how a flag ends up quietly doing nothing.
  if (ctx.opts.quiet === true && ctx.json) {
    throw new CliError('--quiet and --json are mutually exclusive (quiet prints the answer alone)', EXIT.usage);
  }
  const agents: AgentSession[] = await ctx.daemon.json('/api/agents', { timeoutS: ctx.timeoutS });
  const a = pickSession(agents, ctx.opts.package as string | undefined, ctx.opts.session as string | undefined);

  const ping = await ctx.daemon.mcp('agent_ping', {}, a.sessionId, ctx.timeoutS);
  const probe = await ctx.daemon.mcp('compat_probe', {}, a.sessionId, ctx.timeoutS);
  const dex = await ctx.daemon.mcp('art_dexfiles', {}, a.sessionId, ctx.timeoutS);

  say(ctx, `target: ${a.package}  pid ${a.pid}  session ${a.sessionId}`);
  say(ctx, `  ${a.online === false ? 'offline' : 'online'} · connected ${new Date(Number(a.connectedAt ?? 0)).toISOString()} · entry ${a.entry ?? '?'} (${a.entry === 'start' ? 'injected' : 'jni_onload: self-load / gadget / xposed'})`);
  say(ctx, `  agent ${a.agentVer ?? probe.agentVer ?? '?'} · android ${a.android ?? '?'} sdk ${a.sdk ?? '?'} ${a.abi ?? ''}`);
  say(ctx, `  loaded as ${a.selfModule ?? '(unknown)'}${a.selfBase ? ` base ${a.selfBase}` : ''}`);
  say(ctx, `  ping ${ping.ok === true ? `ok ${ping.latencyMs ?? '?'}ms` : `FAILED ${ping.error ?? '?'}`}`);
  say(ctx, '  capabilities');
  say(ctx, `    memBackend ${probe.memBackend ?? '?'}${Number.isInteger(probe.memOpenErrno) ? ` (open errno ${probe.memOpenErrno})` : ''}  ·  libartJniGetVms ${probe.libartJniGetVms ?? '?'}  ·  jniReflect ${probe.backends?.jniReflect ?? '?'}`);
  say(ctx, `    art dex files ${dex.ok === true ? dex.count : `unavailable (${dex.error ?? '?'})`}`);

  const problems: string[] = [];
  if (ping.ok !== true) problems.push('agent did not answer agent_ping');
  if (dex.ok !== true) problems.push(`art_dexfiles failed: ${dex.error ?? 'unknown'}`);
  const ok = problems.length === 0;
  say(ctx, ok ? '✅ target: ok' : '❌ target: FAIL');
  for (const p of problems) say(ctx, `   - ${p}`);
  if (ctx.opts.quiet === true) {
    // The script-facing answer: one line, nothing to parse. Diagnostics go to stderr on failure so a
    // caller that ignored the exit code still cannot mistake an error message for a session id.
    if (ok) process.stdout.write(`${a.sessionId}\n`);
    else process.stderr.write(`adh: target ${a.package} is not usable (${problems.join('; ')})\n`);
    return ok ? EXIT.ok : EXIT.fail;
  }
  return emit(ctx, {
    ok, status: ok ? 'ok' : 'fail', session: a.sessionId, package: a.package, pid: a.pid,
    entry: a.entry, agentVer: a.agentVer, selfModule: a.selfModule, ping, probe, dexFiles: dex,
    problems,
  }, ok ? EXIT.ok : EXIT.fail);
}

async function cmdUnpack(ctx: Ctx): Promise<number> {
  const agents: AgentSession[] = await ctx.daemon.json('/api/agents', { timeoutS: ctx.timeoutS });
  const a = pickSession(agents, ctx.opts.package as string | undefined, ctx.opts.session as string | undefined);

  const report = await ctx.daemon.json('/api/unpack/dump-all', {
    method: 'POST', body: JSON.stringify({ session: a.sessionId }), timeoutS: ctx.timeoutS,
  });

  say(ctx, `unpack: ${a.package} (session ${a.sessionId})`);
  say(ctx, `  ${report.dexCount} DexFile → ${report.realDexCount} real · ${report.carrierCount} carrier  ·  ${fmtBytes(report.realBytes)} of real code (${fmtBytes(report.totalBytes)} total)`);
  if (report.index) say(ctx, `  dex index ${report.index.built} built / ${report.index.reused} reused`);

  const dexes: any[] = report.dexes ?? [];
  say(ctx, 'dexes');
  for (const [i, d] of dexes.entries()) {
    // Three outcomes, not two: a dex that failed to classify is neither real code nor a carrier,
    // and tagging it 'real' contradicted the warning printed below.
    const tag = d.classifyError || d.error ? 'failed ' : d.carrier ? 'carrier' : 'real   ';
    say(ctx, `  [${String(i).padStart(2)}] ${tag}  ${fmtBytes(d.bytes ?? d.size)}  classes ${d.classes}  methods ${d.methods}  ${String(d.sha256 ?? '').slice(0, 16)}`);
  }
  for (const c of report.carriers ?? []) {
    say(ctx, `  carrier detail: classes=${c.classes} · ${c.reason ?? ''}`);
  }
  if (Number(report.unclassified ?? 0) > 0) {
    say(ctx, `  ⚠ ${report.unclassified} of ${report.dexCount} dex(es) could not be classified — ${report.classifyError ?? 'see per-dex classifyError'}`);
  }

  let saved: { file: string; sha256: string; bytes: number }[] = [];
  const outDir = ctx.opts.out as string | undefined;
  if (outDir) {
    const wantCarriers = ctx.opts['include-carriers'] === true;
    mkdirSync(outDir, { recursive: true });
    const chosen = dexes.filter((d) => (wantCarriers ? true : !d.carrier));
    for (const [i, d] of chosen.entries()) {
      const bytes = await ctx.daemon.bytes(`/api/dumps/download?sha=${d.sha256}`, ctx.timeoutS);
      const file = join(outDir, `${String(i).padStart(2, '0')}-${String(d.sha256).slice(0, 16)}.dex`);
      writeFileSync(file, bytes);
      saved.push({ file, sha256: d.sha256, bytes: bytes.length });
      say(ctx, `  saved ${file} (${fmtBytes(bytes.length)})`);
    }
  }

  const problems: string[] = [];
  if (Number(report.failed ?? 0) > 0) problems.push(`${report.failed} dex failed to dump`);
  // A dex the daemon ERRORED on is not a result — it is a failure that used to be absorbed, because
  // realDexCount counted it as real and the error was dropped from the summary. Report it, fail loud.
  if (Number(report.unclassified ?? 0) > 0) {
    problems.push(`${report.unclassified} of ${report.dexCount} dex(es) could not be classified — ${report.classifyError ?? 'see per-dex classifyError'}`);
  }
  if (!dexes.length) problems.push('no DexFile was dumped');
  if (outDir && saved.length !== dexes.filter((d) => ctx.opts['include-carriers'] === true || !d.carrier).length) {
    problems.push('saved file count does not match the dex set');
  }
  const ok = problems.length === 0;
  say(ctx, ok ? '✅ unpack: ok' : '❌ unpack: FAIL');
  for (const p of problems) say(ctx, `   - ${p}`);
  return emit(ctx, { ok, status: ok ? 'ok' : 'fail', session: a.sessionId, package: a.package, report: reportSummary(report), saved, problems },
    ok ? EXIT.ok : EXIT.fail);
}

function reportSummary(report: any) {
  return {
    dexCount: report.dexCount, realDexCount: report.realDexCount, carrierCount: report.carrierCount,
    unclassified: report.unclassified, ...(report.classifyError ? { classifyError: report.classifyError } : {}),
    dumped: report.dumped, failed: report.failed, totalBytes: report.totalBytes, realBytes: report.realBytes,
    index: report.index,
    // `classifyError` / `error` MUST ride along. Projecting only the happy fields is how a run where
    // 3 of 4 dexes failed to index still looked like a clean success: the reason was on each entry
    // and this map dropped it, leaving `problems: []`.
    dexes: (report.dexes ?? []).map((d: any) => ({
      sha256: d.sha256, bytes: d.bytes ?? d.size, classes: d.classes, methods: d.methods, carrier: d.carrier, shape: d.shape,
      ...(d.classifyError ? { classifyError: d.classifyError } : {}),
      ...(d.error ? { error: d.error } : {}),
    })),
    carriers: report.carriers ?? [],
  };
}

function fmtBytes(n: unknown): string {
  const v = Number(n ?? 0);
  if (!Number.isFinite(v)) return '?';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0;
  let x = v;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return i === 0 ? `${v} B` : `${x.toFixed(1)} ${units[i]}`;
}

// ---------------------------------------------------------------------------------------------
// entrypoint
// ---------------------------------------------------------------------------------------------

function helpFor(cmd: string): string {
  const spec = COMMANDS[cmd];
  const lines: string[] = [];
  if (!spec) {
    lines.push(`${CLI_NAME} — Host ADH Daemon command line (a client of adhd; run tools/dev_up.sh first)`);
    lines.push('');
    lines.push(`usage: ${CLI_NAME} <command> [flags]   (flags may also be given as --flag=value)`);
    lines.push('');
    lines.push('commands:');
    for (const [name, s] of Object.entries(COMMANDS)) lines.push(`  ${name.padEnd(8)} ${s.desc}`);
    lines.push('');
    lines.push(`run '${CLI_NAME} <command> --help' for a command's flags.`);
    lines.push('exit codes: 0 ok · 1 fail · 2 usage · 3 unavailable (daemon not reachable)');
    return lines.join('\n');
  }
  lines.push(`usage: ${CLI_NAME} ${cmd} [flags]`);
  lines.push('');
  lines.push(spec.desc);
  lines.push('');
  lines.push('flags:');
  for (const f of [...spec.flags, ...GLOBAL_FLAGS]) {
    lines.push(`  --${f.name}${f.kind === 'string' ? ' <value>' : ''}`.padEnd(22) + f.desc);
  }
  return lines.join('\n');
}

async function main(argv: string[]): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed.error) {
    process.stderr.write(`${CLI_NAME}: ${parsed.error}\n`);
    if (!parsed.cmd || parsed.cmd === '') process.stderr.write(`\n${helpFor('')}\n`);
    return EXIT.usage;
  }
  if (parsed.help) {
    process.stdout.write(`${helpFor(parsed.cmd)}\n`);
    return EXIT.ok;
  }
  const opts = parsed.opts;
  const ctx: Ctx = {
    daemon: new Daemon(
      String(opts.host ?? DEFAULT_HOST),
      Number(opts.port ?? process.env.ADH_HTTP_PORT ?? HTTP_PORT),
    ),
    opts,
    json: opts.json === true,
    timeoutS: opts.timeout === undefined ? DEFAULT_TIMEOUT_S[parsed.cmd] ?? 30 : Number(opts.timeout),
    lines: [],
  };
  if (!Number.isFinite(ctx.timeoutS) || ctx.timeoutS <= 0) {
    process.stderr.write(`${CLI_NAME}: --timeout must be a positive number of seconds\n`);
    return EXIT.usage;
  }
  switch (parsed.cmd) {
    case 'doctor': return await cmdDoctor(ctx);
    case 'target': return await cmdTarget(ctx);
    case 'unpack': return await cmdUnpack(ctx);
    default: return EXIT.usage;
  }
}

// Only run when executed, so the unit test can import parseArgs/repoVersions without side effects.
if (process.argv[1] && resolvePath(process.argv[1]).endsWith('cli.ts')) {
  main(process.argv.slice(2))
    // process.exit() rather than just setting exitCode: on Windows a connect attempt that never
    // completes keeps the loop alive for seconds after we have destroyed our own socket (measured
    // ~3s, on a 2s budget). This CLI is called from scripts, so it must return the moment it has an
    // answer. Safe here because the request path owns its socket and destroys it before we exit —
    // the libuv assertion this used to trip came from undici's shared dispatcher, not from node:http.
    .then((code) => process.exit(code))
    .catch((e: unknown) => {
      const err = e as CliError;
      process.stderr.write(`${CLI_NAME}: ${err?.message ?? String(e)}\n`);
      process.exit(typeof err?.exit === 'number' ? err.exit : EXIT.fail);
    });
}
