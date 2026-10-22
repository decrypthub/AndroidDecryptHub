import test from 'node:test';
import assert from 'node:assert/strict';
import { listRecipes, runRecipe, RECIPES } from '../src/recipes.ts';

// Recipes are the "one sentence" entry point: a client that does not know the tool surface calls
// one name and gets a plan back. That only works if the registry is discoverable and the error for
// a typo names what exists.

test('every recipe is listed with a description and what it needs', () => {
  const list = listRecipes();
  const names = list.map((r) => r.name).sort();
  assert.deepEqual(names, ['anti_debug', 'capture_window', 'http_capture', 'triage', 'unpack']);
  for (const r of list) {
    assert.ok(r.description.length > 30, `${r.name}: description too short to plan from`);
    assert.ok(Array.isArray(r.needs) && r.needs.length > 0, `${r.name}: must say what it needs`);
  }
});

test('an unknown recipe names the ones that exist instead of failing silently', async () => {
  await assert.rejects(() => runRecipe('nope', 's_x'), (e: Error) => {
    assert.match(e.message, /unknown recipe 'nope'/);
    for (const name of Object.keys(RECIPES)) assert.ok(e.message.includes(name), `error must list ${name}`);
    return true;
  });
});

test('a recipe without an online session fails with a printable error', async () => {
  // No agent is connected in this process; the point is that the failure is an Error the MCP layer
  // can report, not an unhandled rejection inside the recipe body.
  await assert.rejects(() => runRecipe('triage', ''), /no online agent session/);
});
