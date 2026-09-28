#!/usr/bin/env bash
# v10.0 `adh` CLI acceptance (device-flavoured: the CLI itself is host-side, but two of its three
# subcommands need a live agent to mean anything).
#
# Why this exists: before the CLI, every session hand-rolled the same shell+node glue to find the
# online agent for a package and pick its session — the same block had been copied into 76 of the
# other verify scripts, and re-derived by hand in every investigation. That block now has ONE
# implementation (daemon/src/cli.ts → target), and this script is what keeps it honest.
#
# Two things are being checked, and the second one is the interesting half:
#
#  1. the commands work: doctor reports the daemon and the flashed-vs-source version pairing,
#     target resolves one agent and reports its live facts, unpack dumps and classifies every
#     DexFile and can write them to disk;
#  2. **every declared flag has an observable effect.** A flag that is accepted and then ignored is
#     worse than no flag at all: the command exits 0 having done something other than what was
#     asked, and the operator trusts the result. That exact defect was found in a sibling project's
#     diagnostic CLI (`--proxy`/`--cookie-file` were registered in the shared flag set but consumed
#     by a single subcommand, so `face --proxy …` silently ignored the proxy — on the one code path
#     where the egress IP was the variable under test). So each flag below is asserted by its effect,
#     not by its presence in --help: --port/--host/--timeout by the base URL and budget in the
#     failure message, --json by the output shape, --package/--session by the target they refuse to
#     resolve, --out/--include-carriers by how many files land on disk.
#
# Exit-code contract (mirrors the gate's PASS/FAIL/SKIP distinction instead of a second vocabulary):
#   0 ok · 1 fail (the answer is no) · 2 usage · 3 unavailable (daemon unreachable) == the gate's SKIP
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

# The device half needs an agent. verify_all starts the sandbox before device scripts; when run by
# hand, try once ourselves — but only when adb reports a usable device (an 'unauthorized' or
# 'offline' phone must not turn into a failure of THIS script).
STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" = "device" ]; then
  ONLINE="$(node -e "fetch('http://127.0.0.1:$HTTP/api/agents').then(r=>r.json()).then(a=>console.log(a.filter(x=>x.online).length)).catch(()=>console.log(0))" 2>/dev/null)"
  if [ "${ONLINE:-0}" = "0" ]; then
    echo ">> no agent online; starting the sandbox once"
    verify_restart_sandbox >/dev/null 2>&1
    sleep 3
  fi
fi

OUT="$(node - "$ROOT" "$HTTP" <<'EOF'
const [root, http] = process.argv.slice(2);
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const cli = join(root, 'daemon', 'src', 'cli.ts');
const base = `http://127.0.0.1:${http}`;
const problems = [];
const checks = [];
const chk = (label, cond, detail) => {
  if (cond) checks.push(label);
  else problems.push(`${label}${detail ? ` — ${detail}` : ''}`);
};
const note = (s) => checks.push(s);
const run = (args, opts = {}) => {
  const r = spawnSync('node', [cli, ...args], { encoding: 'utf8', cwd: join(root, 'daemon'), ...opts });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
};

// ---- 1. the flag contract's unit tests -------------------------------------------------------
const unit = spawnSync('node', ['--test', 'test/cli_args.test.ts'], { encoding: 'utf8', cwd: join(root, 'daemon') });
const unitOut = `${unit.stdout ?? ''}${unit.stderr ?? ''}`;
chk('flag-contract unit tests pass (declared == consumed, ambiguity is an error)',
  /^ℹ fail 0$/m.test(unitOut), (unitOut.match(/^ℹ (pass|fail) \d+$/gm) ?? []).join(' '));

// ---- 2. architecture: the CLI is a CLIENT, not a second server -------------------------------
const src = readFileSync(cli, 'utf8');
const banned = ['state.ts', 'service.ts', 'mcp.ts', 'index.ts']
  .filter((m) => new RegExp(`from '\\./${m.replace('.', '\\.')}'`).test(src));
chk('the CLI imports nothing from the daemon internals (client only, no drift possible)',
  banned.length === 0, `imports: ${banned.join(', ')}`);

// ---- 3. help + usage surface -----------------------------------------------------------------
const help = run(['--help']);
chk('`adh --help` exits 0 and lists every command',
  help.code === 0 && ['doctor', 'target', 'unpack'].every((c) => help.out.includes(c)));
const cmdHelp = run(['target', '--help']);
chk('`adh target --help` documents its own flags',
  cmdHelp.code === 0 && cmdHelp.out.includes('--package') && cmdHelp.out.includes('--session'));
const unknownFlag = run(['target', '--wat']);
chk('an unknown flag is a usage error (exit 2) naming what is accepted',
  unknownFlag.code === 2 && /unknown flag '--wat'/.test(unknownFlag.err) && /accepted:/.test(unknownFlag.err),
  `exit=${unknownFlag.code}`);
const missingValue = run(['target', '--package']);
chk('a value-carrying flag with no value is a usage error',
  missingValue.code === 2 && /needs a value/.test(missingValue.err), `exit=${missingValue.code}`);

// ---- 4. the daemon side works ----------------------------------------------------------------
const doc = run(['doctor']);
chk('doctor exits 0 and reports the daemon, the version pairing and the backends',
  doc.code === 0 && doc.out.includes('doctor: ok') && doc.out.includes('version pairing') &&
  doc.out.includes('source AGENT_VER'), doc.out.split('\n').slice(0, 3).join(' | '));
const docJson = run(['doctor', '--json']);
let docParsed = null;
try { docParsed = JSON.parse(docJson.out); } catch { /* reported below */ }
chk('--json changes the output shape (machine-readable, one object)',
  docJson.code === 0 && docParsed?.status === 'ok' && !!docParsed?.repo?.agentVer,
  `exit=${docJson.code} status=${docParsed?.status ?? 'unparsable'}`);
chk('the default output is NOT json (so --json is really doing something)',
  !(() => { try { JSON.parse(doc.out); return true; } catch { return false; } })());

// ---- 5. exit-code contract + flags proven by effect ------------------------------------------
const wrongPort = run(['doctor', '--port', '8099']);
chk('--port is consumed: a wrong port is "unavailable" (exit 3), not a pass',
  wrongPort.code === 3 && wrongPort.err.includes('127.0.0.1:8099'), `exit=${wrongPort.code} ${wrongPort.err.trim()}`);
// --host and --timeout in one shot: an unroutable host must appear in the error, and the 2s budget
// must actually bound the wait. This is not a formality — node:http's req.setTimeout arms a socket
// IDLE timer and does not bound connect, so an earlier version printed "timed out after 2s" at 5.1s.
// The bound here is what keeps that claim true.
const t0 = Date.now();
const unroutable = run(['doctor', '--host', '10.255.255.1', '--port', '8099', '--timeout', '2']);
const elapsed = Date.now() - t0;
chk('--host is consumed: the error names the base URL built from it',
  unroutable.code === 3 && unroutable.err.includes('http://10.255.255.1:8099'), unroutable.err.trim());
chk(`--timeout is consumed: the 2s budget really bounded the attempt (${elapsed}ms)`, elapsed < 4000, `${elapsed}ms`);
const zeroTimeout = run(['doctor', '--timeout', '0']);
chk('--timeout rejects a non-positive value instead of silently using the default',
  zeroTimeout.code === 2 && /positive number/.test(zeroTimeout.err), `exit=${zeroTimeout.code}`);
const quietJson = run(['target', '--quiet', '--json']);
chk('--quiet and --json are refused together instead of silently choosing one',
  quietJson.code === 2 && /mutually exclusive/.test(quietJson.err), `exit=${quietJson.code}`);

// ---- 6. the agent-dependent half -------------------------------------------------------------
let agents = [];
try { agents = await (await fetch(`${base}/api/agents`)).json(); } catch { agents = []; }
const online = agents.filter((a) => a.online);
if (!online.length) {
  console.log(`daemon checks passed: ${checks.length}`);
  console.log(`  ${checks.join('\n  ')}`);
  console.log('no online agent — the target/unpack half (and their flags) cannot run');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const pkg = online[0].package;

const tgt = run(['target', '--package', pkg, '--json']);
let tgtJson = null;
try { tgtJson = JSON.parse(tgt.out); } catch { /* reported below */ }
chk('target resolves the agent and reports live facts (ping + capabilities + dex count)',
  tgt.code === 0 && tgtJson?.status === 'ok' && tgtJson?.session === online[0].sessionId &&
  tgtJson?.ping?.ok === true && tgtJson?.dexFiles?.ok === true,
  `exit=${tgt.code} session=${tgtJson?.session ?? '?'} ping=${tgtJson?.ping?.ok} dex=${tgtJson?.dexFiles?.ok}`);

const wrongPkg = run(['target', '--package', 'com.adh.definitely-not-installed', '--json']);
chk('--package is consumed: a package with no agent fails (exit 1) and lists what IS online',
  wrongPkg.code === 1 && wrongPkg.err.includes(pkg), `exit=${wrongPkg.code} ${wrongPkg.err.trim()}`);
const wrongSession = run(['target', '--session', 'nosuchsession', '--json']);
chk('--session is consumed: a pinned session that does not exist fails (exit 1)',
  wrongSession.code === 1 && /no agent session 'nosuchsession'/.test(wrongSession.err), `exit=${wrongSession.code}`);

const quiet = run(['target', '--package', pkg, '--quiet']);
chk('--quiet is consumed: it prints exactly the session id and nothing else',
  quiet.code === 0 && quiet.out.trim() === online[0].sessionId && quiet.out.trim().split('\n').length === 1,
  `stdout=${JSON.stringify(quiet.out)}`);

const dry = run(['unpack', '--package', pkg, '--json']);
let dryJson = null;
try { dryJson = JSON.parse(dry.out); } catch { /* reported below */ }
const report = dryJson?.report;
chk('unpack classifies every DexFile (real vs carrier) and saves nothing without --out',
  dry.code === 0 && report?.dexCount >= 1 && dryJson?.saved?.length === 0 && report?.realDexCount >= 1,
  `exit=${dry.code} dex=${report?.dexCount} real=${report?.realDexCount} saved=${dryJson?.saved?.length}`);

const dirReal = mkdtempSync(join(tmpdir(), 'adh-cli-real-'));
const saved = run(['unpack', '--package', pkg, '--out', dirReal, '--json']);
let savedJson = null;
try { savedJson = JSON.parse(saved.out); } catch { /* reported below */ }
const files = existsSync(dirReal) ? readdirSync(dirReal) : [];
const sizesOk = (savedJson?.saved ?? []).every((s) => existsSync(s.file) && statSync(s.file).size === s.bytes);
chk('--out is consumed: one file per REAL dex lands on disk with the reported byte count',
  saved.code === 0 && files.length === report?.realDexCount && sizesOk,
  `exit=${saved.code} files=${files.length} expected=${report?.realDexCount} sizesOk=${sizesOk}`);

const dirAll = mkdtempSync(join(tmpdir(), 'adh-cli-all-'));
const withCarriers = run(['unpack', '--package', pkg, '--out', dirAll, '--include-carriers', '--json']);
let allJson = null;
try { allJson = JSON.parse(withCarriers.out); } catch { /* reported below */ }
const allFiles = existsSync(dirAll) ? readdirSync(dirAll) : [];
if (Number(report?.carrierCount ?? 0) > 0) {
  chk('--include-carriers is consumed: it changes how many files land on disk',
    withCarriers.code === 0 && allFiles.length === report.dexCount && allFiles.length > files.length,
    `files=${allFiles.length} expected=${report.dexCount} (real-only was ${files.length})`);
} else {
  // Honest about a vacuous check rather than counting it as a pass: this target has no carrier dex,
  // so the two flag settings cannot differ (the SecNeo carrier case is in CASE_STUDIES case 1).
  chk('--include-carriers is consumed (no carrier on this target: only the count is checkable)',
    withCarriers.code === 0 && allFiles.length === report.dexCount,
    `files=${allFiles.length} expected=${report.dexCount}`);
  note('(vacuous here: carrierCount=0, so --include-carriers cannot change the set)');
}

console.log(`checks=${checks.length} problems=${problems.length} (agent ${pkg} pid=${online[0].pid})`);
console.log(`  ${checks.join('\n  ')}`);
if (problems.length) {
  console.log('problems:');
  for (const p of problems.slice(0, 20)) console.log('  ✗ ' + p);
}
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
process.exit(0);
EOF
)"
echo "$OUT"

# The agent half is a precondition, not a verdict: with no agent online those assertions cannot run,
# and the gate counts a missing precondition as SKIP. Print it as the FINAL line (the v75 convention)
# so verify_all reports "SKIP (…)" with a reason instead of turning it into a FAIL.
if grep -q '^RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP (v10.0 adh CLI: daemon-side checks ran, but no online agent for target/unpack)"
  exit 0
fi

verify_gate "v10.0 adh CLI (doctor/target/unpack work; every declared flag proven by effect)" 0
