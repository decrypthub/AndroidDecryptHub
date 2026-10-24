import test from 'node:test';
import assert from 'node:assert/strict';
import type { ServerResponse } from 'node:http';
import { ANALYSIS_GUIDE_TOPICS, analysisGuide, MCP_INSTRUCTIONS } from '../src/analysis_guide.ts';
import { handleMcp, MCP_MAP, MCP_TOOLS } from '../src/mcp.ts';

async function rpc(method: string, params: any = {}) {
  let body = '', status = 0;
  const res = { writeHead(code: number) { status = code; return this; }, end(text: string) { body = text; } };
  await handleMcp(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), res as unknown as ServerResponse);
  assert.equal(status, 200);
  return JSON.parse(body);
}

test('initialize sends a usable entry route and the tool list also exposes help', async () => {
  const init = await rpc('initialize');
  assert.equal(init.result.instructions, MCP_INSTRUCTIONS);
  assert.match(init.result.instructions, /analysis_guide\(topic="start"\)/);
  assert.match(init.result.instructions, /process_list and capabilities/);
  const list = await rpc('tools/list');
  const help = list.result.tools.find((t: any) => t.name === 'analysis_guide');
  assert.ok(help);
  assert.match(help.description, /START HERE/);
  assert.deepEqual(help.inputSchema.properties.topic.enum, ANALYSIS_GUIDE_TOPICS);
});

test('every guide can be read through MCP without a session and returns a bounded workflow', async () => {
  for (const topic of ANALYSIS_GUIDE_TOPICS) {
    const response = await rpc('tools/call', { name: 'analysis_guide', arguments: { topic } });
    assert.notEqual(response.result.isError, true);
    const guide = JSON.parse(response.result.content[0].text);
    assert.equal(guide.topic, topic);
    assert.equal(guide.executesTools, false);
    assert.ok(guide.steps.length > 0 && guide.steps.length <= 8);
    assert.ok(Buffer.byteLength(JSON.stringify(guide)) < 16384);
    assert.match(guide.templateRule, /correct typed value/);
  }
});

test('guide templates bind only declared variables and refer to actual tool schemas', () => {
  // Synthetic typed substitutions validate call shapes only. No example target call is executed.
  const values: Record<string, any> = { session: 'guide-test-no-agent', tid: 7, buffer: '0x1000', runId: 'synthetic-run', pc: '0x1000',
    captureId: 7, hookId: 7, qbdiPath: '/synthetic/libQBDI.so', entry: '0x1000', integerArgs: ['1', '2'], traceId: 'synthetic-trace' };
  for (const topic of ANALYSIS_GUIDE_TOPICS) {
    const guide = analysisGuide(topic);
    for (const step of guide.steps) {
      const tool = MCP_MAP.get(step.tool); assert.ok(tool, `unknown guide tool ${step.tool}`);
      const args = Object.fromEntries(Object.entries(step.arguments).map(([key, value]) => {
        if (typeof value !== 'string' || !value.startsWith('$')) return [key, value];
        const name = value.slice(1);
        assert.ok(Object.hasOwn(guide.variables, name), `${topic}: undeclared ${name}`);
        assert.ok(Object.hasOwn(values, name));
        return [key, values[name]];
      }));
      for (const key of tool.inputSchema.required ?? []) assert.ok(Object.hasOwn(args, key), `${step.tool} missing ${key}`);
      for (const [key, value] of Object.entries(args)) {
        const schema = tool.inputSchema.properties[key]; assert.ok(schema, `${step.tool} unknown field ${key}`);
        assert.equal(Array.isArray(value) ? 'array' : typeof value, schema.type, `${step.tool}.${key}`);
        if (schema.enum) assert.ok(schema.enum.includes(value), `${step.tool}.${key} invalid enum`);
      }
    }
  }
});

test('the crypto format example is actually accepted and never claims target evidence', async () => {
  const example = analysisGuide('crypto').steps.find(s => s.arguments.action === 'analyze')!;
  const response = await rpc('tools/call', { name: example.tool, arguments: example.arguments });
  assert.notEqual(response.result.isError, true);
  const result = JSON.parse(response.result.content[0].text);
  assert.equal(result.counts.matched, 1);
  assert.equal(result.rows[0].role, 'intermediate');
  assert.match(JSON.stringify(example), /not target evidence/);
});

test('unknown topics fail explicitly and callers cannot mutate stored workflows', async () => {
  for (const topic of ['unknown', '__proto__', 'constructor', 1, null]) {
    const response = await rpc('tools/call', { name: 'analysis_guide', arguments: { topic } });
    assert.equal(response.result.isError, true);
    assert.match(response.result.content[0].text, /topic must be/);
  }
  const first = analysisGuide('writer'); first.steps.splice(0);
  assert.ok(analysisGuide('writer').steps.length > 0);
  assert.equal(analysisGuide().topic, 'start');
  assert.equal(MCP_TOOLS.filter(t => t.name === 'analysis_guide').length, 1);
});
