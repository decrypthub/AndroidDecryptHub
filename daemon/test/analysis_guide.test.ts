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

test('initialize tells the client that adb is a usable device channel and forbids guessing defenses', async () => {
  const init = await rpc('initialize');
  const text = init.result.instructions;
  // 设备可达性：不写这一条，模型会把「工具列表里没有点击能力」当成「点不到手机」。
  assert.match(text, /DEVICE ACCESS/);
  assert.match(text, /adb is the supported operator\/AI channel/);
  for (const capability of ['logcat', 'dumpsys activity activities', 'uiautomator dump', 'screencap', 'input tap'])
    assert.ok(text.includes(capability), 'missing adb capability: ' + capability);
  // 归因纪律：卡住不能直接等于反调试。
  assert.match(text, /ATTRIBUTION/);
  assert.match(text, /not by itself evidence of anti-debugging/);
  assert.match(text, /privacy consent/);
  assert.match(text, /Claim detection only with matching evidence/);
  // 需要用户介入时要停下来，而不是改注入或反复点同一处。
  assert.match(text, /say what is missing and stop/);
  assert.match(text, /never from screen size/);
});

test('the stuck guide offers adb device checks before any defense conclusion', () => {
  const guide = analysisGuide('stuck');
  assert.ok(guide.deviceChecks && guide.deviceChecks.length >= 3, 'stuck must start from device facts');
  const commands = guide.deviceChecks!.map(c => c.command).join('\n');
  for (const expected of ['dumpsys activity activities', 'uiautomator dump', 'screencap']) assert.ok(commands.includes(expected), expected);
  // 每个 check 都要说明「这属于普通原因」而不是检测。
  assert.ok(guide.deviceChecks!.some(c => /consent|login|permission/i.test(c.check)));
  // adb 不是 MCP 工具，不能混进模板步骤里被当作可调用工具校验。
  assert.equal(guide.steps.some(s => s.tool === 'adb'), false);
  assert.match(guide.limits.join(' '), /A non-progressing screen, a failed local command and a blocked request each have ordinary causes/);
  assert.match(guide.prerequisites.join(' '), /A stalled screen is a state, not a diagnosis/);
});

test('assessment output states that a stalled screen is not a diagnosis', async () => {
  const { assessAnalysis } = await import('../src/analysis_assist.ts');
  const report = await assessAnalysis({ topic: 'stuck', session: 'nope' }, {
    now: () => 1, sessions: new Map(), captures: [], stats: new Map(), storeLoss: () => null,
    readHookStatus: async () => { throw new Error('not used'); },
  } as any);
  assert.match(report.limits.join(' '), /A stalled screen or a hung command is a state, not a diagnosis/);
  assert.match(report.limits.join(' '), /adb \(dumpsys activity activities, uiautomator dump, screencap\)/);
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
