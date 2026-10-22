import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// The agent advertises its capability list in the hello (`caps`) and dispatches commands with a
// strcmp chain. Those are two hand-written lists that must agree: advertising an op the agent does
// not dispatch makes a client plan against a capability that does not exist, and dispatching an op
// nobody advertises is invisible to the client that should be able to use it.
//
// This test is the gate. It parses the real source, so adding an op in one place and forgetting the
// other fails `npm test` instead of shipping.
const here = dirname(fileURLToPath(import.meta.url));
const AGENT_MAIN = join(here, '..', '..', 'agent', 'src', 'bootstrap', 'agent_main.c');

function readAgentMain(): string {
  return readFileSync(AGENT_MAIN, 'utf8');
}

/** Ops the dispatch chain actually answers (`strcmp(op, "name")`). */
export function dispatchedOps(source: string): string[] {
  const ops = new Set<string>();
  for (const m of source.matchAll(/strcmp\(op,\s*"([a-z_0-9]+)"\)/g)) ops.add(m[1]);
  return [...ops].sort();
}

/** Ops the caps manifest advertises (the ADH_AGENT_OPS initializer). */
export function advertisedOps(source: string): string[] {
  const block = /ADH_AGENT_OPS\[\]\s*=\s*\{([\s\S]*?)\};/.exec(source);
  assert.ok(block, 'ADH_AGENT_OPS initializer not found in agent_main.c');
  return [...block![1].matchAll(/"([a-z_0-9]+)"/g)].map((m) => m[1]).sort();
}

test('the caps manifest and the dispatch chain list the same ops', () => {
  const src = readAgentMain();
  const dispatched = dispatchedOps(src);
  const advertised = advertisedOps(src);
  assert.ok(dispatched.length >= 30, `parsed only ${dispatched.length} dispatched ops - the parser broke`);
  assert.deepEqual(advertised, dispatched,
    `advertised ops and dispatched ops differ.\n  only dispatched: ${dispatched.filter((o) => !advertised.includes(o)).join(', ') || '-'}\n  only advertised: ${advertised.filter((o) => !dispatched.includes(o)).join(', ') || '-'}`);
});

test('the caps manifest has no duplicate entries', () => {
  const advertised = advertisedOps(readAgentMain());
  assert.equal(new Set(advertised).size, advertised.length, 'duplicate op in ADH_AGENT_OPS');
});

test('write is advertised and dispatched (the primitive VMP/OLLVM work needs)', () => {
  const advertised = advertisedOps(readAgentMain());
  assert.ok(advertised.includes('write'), 'the agent must advertise write');
});
