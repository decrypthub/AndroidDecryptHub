import test from 'node:test';
import assert from 'node:assert/strict';

import { COMMANDS, GLOBAL_FLAGS, parseArgs, pickSession, repoVersions } from '../src/cli.ts';

// The ADH CLI's contract is mostly a *flag* contract, and its failure mode is quiet: a flag that is
// accepted and then ignored leaves the operator believing a check ran that never ran. That exact
// defect was found in a sibling project's diagnostic CLI (`--proxy`/`--cookie-file` registered in the
// shared flag set, consumed by one subcommand only), which is why the discipline is asserted here
// mechanically instead of being left to review.

const declaredFor = (cmd: string): string[] => {
  const spec = COMMANDS[cmd];
  // --help is consumed by main(), not by a command handler.
  return [...spec.flags, ...GLOBAL_FLAGS].map((f) => f.name).filter((n) => n !== 'help').sort();
};

test('every declared flag is claimed by the handler that runs the command', () => {
  for (const [cmd, spec] of Object.entries(COMMANDS)) {
    assert.deepEqual(
      [...spec.handlerFlags].sort(),
      declaredFor(cmd),
      `${cmd}: a flag is declared but no handler reads it (or a handler reads an undeclared flag)`,
    );
  }
});

test('every declared flag actually lands in opts when supplied', () => {
  const sample: Record<string, string> = {
    host: '127.0.0.1', port: '8088', timeout: '5', package: 'com.adh.sandbox',
    session: 'sid', out: '/tmp/out',
  };
  for (const [cmd, spec] of Object.entries(COMMANDS)) {
    for (const flag of [...spec.flags, ...GLOBAL_FLAGS]) {
      const argv = flag.kind === 'bool' ? [cmd, `--${flag.name}`] : [cmd, `--${flag.name}`, sample[flag.name]];
      const parsed = parseArgs(argv);
      assert.equal(parsed.error, undefined, `${cmd} --${flag.name}: ${parsed.error}`);
      assert.ok(parsed.opts[flag.name] !== undefined, `${cmd} --${flag.name} was parsed away`);
    }
  }
});

test('an unknown or misplaced flag is a usage error naming what is accepted', () => {
  // Generic flag from the global set is fine everywhere; a command-specific flag is not.
  const globalOk = parseArgs(['doctor', '--json']);
  assert.equal(globalOk.error, undefined);
  assert.equal(globalOk.opts.json, true);

  const misplaced = parseArgs(['doctor', '--out', '/tmp/x']);
  assert.match(String(misplaced.error), /unknown flag '--out' for 'doctor'/);
  assert.match(String(misplaced.error), /accepted: .*--host.*--json.*--port.*--timeout/);

  const unknown = parseArgs(['target', '--wat']);
  assert.match(String(unknown.error), /unknown flag '--wat'/);

  assert.match(String(parseArgs(['nope']).error), /unknown command 'nope'/);
  assert.match(String(parseArgs(['target', 'com.adh.sandbox']).error), /unexpected argument/);
  assert.match(String(parseArgs([]).error), /missing command/);
});

test('value-carrying and boolean flags are validated, not coerced', () => {
  assert.match(String(parseArgs(['target', '--package']).error), /'--package' needs a value/);
  assert.match(String(parseArgs(['target', '--package', '--json']).error), /'--package' needs a value/);
  assert.match(String(parseArgs(['unpack', '--json=1']).error), /'--json' takes no value/);
  // --flag=value and --flag value are equivalent for string flags.
  assert.equal(parseArgs(['target', '--package=a.b']).opts.package, 'a.b');
});

test('-h/--help is a request for help, not an error', () => {
  for (const argv of [['doctor', '--help'], ['target', '-h'], ['--help']]) {
    const parsed = parseArgs(argv);
    assert.equal(parsed.help, true, argv.join(' '));
    assert.equal(parsed.error, undefined);
  }
});

// ---------------------------------------------------------------------------------------------
// target resolution — the one decision this CLI must never get silently wrong
// ---------------------------------------------------------------------------------------------

const A = (over: Partial<Record<string, unknown>> = {}) =>
  ({ sessionId: 's1', pid: 100, package: 'com.a', online: true, ...over }) as any;

test('an ambiguous target is an error listing the candidates, never a silent pick', () => {
  const agents = [A(), A({ sessionId: 's2', pid: 200, package: 'com.b' })];
  assert.equal(pickSession(agents, 'com.b').sessionId, 's2');
  const err = (() => { try { pickSession(agents); return null; } catch (e) { return e as any; } })();
  assert.equal(err.exit, 2, 'ambiguity is a usage problem: name the target');
  assert.match(err.message, /ambiguous target/);
  assert.match(err.message, /s2/);
});

test('"no agent for that package" is a failure, "nobody is online" is unavailable (the gate SKIP)', () => {
  const offlineOnly = [A({ online: false })];
  const noAgent = (() => { try { pickSession(offlineOnly, 'com.a'); return null; } catch (e) { return e as any; } })();
  assert.equal(noAgent.exit, 3);
  assert.match(noAgent.message, /no agent online/);

  const online = [A()];
  const wrongPkg = (() => { try { pickSession(online, 'com.zzz'); return null; } catch (e) { return e as any; } })();
  assert.equal(wrongPkg.exit, 1);
  assert.match(wrongPkg.message, /no online agent for package 'com.zzz'/);
  assert.match(wrongPkg.message, /online: com\.a/, 'the error must list what IS online');
});

test('an explicitly pinned session is honoured, and an offline pin fails loudly', () => {
  const agents = [A(), A({ sessionId: 's9', package: 'com.b', online: false })];
  assert.equal(pickSession(agents, undefined, 's1').sessionId, 's1');
  const offline = (() => { try { pickSession(agents, undefined, 's9'); return null; } catch (e) { return e as any; } })();
  assert.equal(offline.exit, 1);
  assert.match(offline.message, /offline/);
  const missing = (() => { try { pickSession(agents, undefined, 'nope'); return null; } catch (e) { return e as any; } })();
  assert.match(missing.message, /no agent session 'nope'/);
});

// ---------------------------------------------------------------------------------------------
// local checkout facts
// ---------------------------------------------------------------------------------------------

test('the agent version and the module version that ships it agree in this checkout', () => {
  // doctor compares the flashed agent against the source; that comparison is only meaningful if the
  // two sources of truth in the tree agree with each other first (agent/src/MAP.md: bump together).
  const repo = repoVersions();
  assert.ok(repo, 'repoVersions() should find this checkout');
  assert.match(String(repo.agentVer), /^\d+\.\d+\.\d+$/, 'agent_internal.h AGENT_VER');
  assert.match(String(repo.moduleVersion), /^v?\d+\.\d+\.\d+$/, 'module.prop version');
  assert.equal(
    String(repo.agentVer).replace(/^v/, ''),
    String(repo.moduleVersion).replace(/^v/, ''),
    'AGENT_VER and module.prop version must be bumped together',
  );
});

test('a checkout that is not there is reported as unknown, not guessed', () => {
  assert.equal(repoVersions('/definitely/not/a/checkout'), null);
});
