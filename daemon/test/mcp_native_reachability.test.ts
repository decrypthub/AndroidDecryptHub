import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const source = (path: string) => ts.createSourceFile(path, readFileSync(new URL(path, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const mcp = source('../src/mcp.ts');
function walk(node: ts.Node, visit: (node: ts.Node) => void) { visit(node); node.forEachChild(child => walk(child, visit)); }
function property(object: ts.ObjectLiteralExpression, name: string): ts.Expression {
  const p = object.properties.find(p => ts.isPropertyAssignment(p) && p.name.getText(mcp).replace(/['"]/g, '') === name);
  assert.ok(p && ts.isPropertyAssignment(p), `property ${name} absent`);
  return p.initializer;
}
function tool(name: string): ts.ObjectLiteralExpression {
  let result: ts.ObjectLiteralExpression | undefined;
  walk(mcp, node => {
    if (!ts.isObjectLiteralExpression(node)) return;
    const p = node.properties.find(p => ts.isPropertyAssignment(p) && p.name.getText(mcp) === 'name');
    if (p && ts.isPropertyAssignment(p) && ts.isStringLiteral(p.initializer) && p.initializer.text === name) result = node;
  });
  assert.ok(result, `MCP registry tool ${name} absent`); return result;
}
function callNamed(root: ts.Node, name: string) {
  const out: ts.CallExpression[] = [];
  walk(root, n => { if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name) out.push(n); });
  return out;
}

test('all three native MCP front doors expose and forward observation controls', () => {
  for (const name of ['native_hook', 'native_hook_all', 'native_look']) {
    const entry = tool(name), schema = property(entry, 'inputSchema');
    assert.ok(ts.isObjectLiteralExpression(schema));
    const props = property(schema, 'properties'); assert.ok(ts.isObjectLiteralExpression(props));
    const names = new Set(props.properties.map(p => p.name?.getText(mcp)));
    for (const field of ['maxEvents', 'sampleEvery', 'tid', 'returnAddress']) assert.ok(names.has(field), `${name} does not expose ${field}`);
    const handler = property(entry, 'handler'), text = handler.getText(mcp);
    if (/ensureNativeObservationSupport\(sid, a, sendCmd\)/.test(text)) continue;
    for (const field of ['maxEvents', 'sampleEvery', 'tid', 'returnAddress']) assert.match(text, new RegExp(`\\b${field}:\\s*a\\.${field}\\b`), `${name} drops ${field} before its host helper`);
  }
});

test('observation support is checked before installs in MCP, REST, look and batch entry points', () => {
  const handler = property(tool('native_hook'), 'handler');
  assert.equal(callNamed(handler, 'ensureNativeObservationSupport').length, 1);
  const text = handler.getText(mcp);
  assert.ok(text.indexOf('ensureNativeObservationSupport(') < text.indexOf("agentCmd(hookSid, 'native_hook'"));
  for (const [path, marker, install] of [
    ['../src/native_look.ts', 'export async function nativeLookArm', "deps.sendCmd(sid, 'native_hook'"],
    ['../src/native_hook_all.ts', 'export async function installSymbolHooks', "send(session, 'native_hook'"],
    ['../src/http/routes_runtime.ts', "path: '/api/native/hook'", "sendCmd(sid, 'native_hook'"]
  ]) {
    const source = readFileSync(new URL(path, import.meta.url), 'utf8'), part = source.slice(source.indexOf(marker));
    const check = part.indexOf('ensureNativeObservationSupport(');
    assert.ok(check >= 0 && check < part.indexOf(install), `${path} installs before capability validation`);
  }
  assert.match(readFileSync(new URL('../../agent/src/hook/native_hooks.cpp', import.meta.url), 'utf8'), /observationControlsVersion\\":1/);
});

test('trace_session record closure reaches qbdi_read through its actual imported helper', () => {
  const entry = tool('trace_session'), handler = property(entry, 'handler');
  const record = callNamed(handler, 'recordTrace'); assert.equal(record.length, 1);
  const importDecl = mcp.statements.find(s => ts.isImportDeclaration(s) && s.importClause?.namedBindings &&
    ts.isNamedImports(s.importClause.namedBindings) && s.importClause.namedBindings.elements.some(e => e.name.text === 'recordTrace'));
  assert.ok(importDecl && ts.isImportDeclaration(importDecl) && ts.isStringLiteral(importDecl.moduleSpecifier));
  assert.equal(importDecl.moduleSpecifier.text, './trace_store.ts');
  const closure = record[0].arguments[3];
  assert.ok(ts.isArrowFunction(closure) && closure.parameters[0].name.getText(mcp) === 'op');
  const forwarded = callNamed(closure, 'agentCmd'); assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].arguments[1].getText(mcp), 'op', 'closure must forward dynamic op, not a fixed operation');
  const storePath = new URL('../src/trace_store.ts', import.meta.url), store = ts.createSourceFile(fileURLToPath(storePath), readFileSync(storePath, 'utf8'), ts.ScriptTarget.Latest, true);
  const fn = store.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === 'recordTrace');
  assert.ok(fn && ts.isFunctionDeclaration(fn));
  assert.equal(fn.parameters[3].name.getText(store), 'cmd');
  const ops = callNamed(fn, 'cmd').map(c => c.arguments[0]).filter(ts.isStringLiteral).map(n => n.text);
  assert.ok(ops.includes('qbdi_trace')); assert.ok(ops.includes('qbdi_read'), 'paged reads must use the supplied closure');
  const agent = readFileSync(new URL('../../agent/src/bootstrap/agent_main.c', import.meta.url), 'utf8');
  assert.match(agent, /strcmp\(op,\s*"qbdi_read"\)/);
  const caps = /ADH_AGENT_OPS\[\]\s*=\s*\{([\s\S]*?)\};/.exec(agent)?.[1] ?? '';
  assert.match(caps, /"qbdi_read"/);
});
test('root_watch retains the selected agent generation across its MCP adapter',()=>{
  const handler=property(tool('root_watch'),'handler');
  const calls=callNamed(handler,'startRootWatch');assert.equal(calls.length,1);
  const target=calls[0].arguments[0];assert.ok(ts.isObjectLiteralExpression(target));
  const ticks=property(target,'starttimeTicks');
  assert.equal(ticks.getText(mcp),'s.starttimeTicks');
});
