import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { findDexdump, parseDexdump, disassembleDex } from '../src/dalvik.ts';

// dex_method_code used to answer with code_item bytes in hex — technically the bytecode, but in
// practice "now go install a baksmali and decode this yourself". The fix is a real Dalvik
// disassembly, and the decoder is the SDK's dexdump rather than a table kept by hand here: a wrong
// instruction width would desync everything after it while still printing plausible mnemonics.
//
// dexdump's text is the contract, so the parser is tested on a canned dump; the tool itself is
// exercised separately on the bridge dex this repo ships.

const DUMP = `Processing 'x.dex'...
Opened 'x.dex', DEX version '035'
Class #0            -
  Class descriptor  : 'Lcom/foo/Bar;'
  Access flags      : 0x0001 (PUBLIC)
  Static fields     -
    #0              : (in Lcom/foo/Bar;)
      name          : 'TAG'
      type          : 'Ljava/lang/String;'
      access        : 0x001a (PRIVATE STATIC FINAL)
      value         : "hi"
  Direct methods    -
    #0              : (in Lcom/foo/Bar;)
      name          : 'sign'
      type          : '(Ljava/lang/String;)Ljava/lang/String;'
      access        : 0x0009 (PUBLIC STATIC)
      code          -
      registers     : 3
      ins           : 1
      outs          : 1
      insns size    : 3 16-bit code units
0002a4:                                        |0000: const-string v0, "abc" // string@0001
0002a8: 6e10 0500 0000                         |0002: invoke-static {v0}, Lcom/foo/Bar;.hash:(Ljava/lang/String;)Ljava/lang/String; // method@0005
0002ae:                                        |0004: return-object v0
      catches       : (none)
      positions     :
        0x0000 line=12
      locals        :
        0x0003 - v0 Ljava/lang/String;
  Virtual methods   -
    #0              : (in Lcom/foo/Bar;)
      name          : 'nativeThing'
      type          : '()V'
      access        : 0x0101 (PUBLIC NATIVE)
Class #1            -
  Class descriptor  : 'Lcom/other/Baz;'
  Direct methods    -
    #0              : (in Lcom/other/Baz;)
      name          : 'sign'
      type          : '()V'
      access        : 0x0002 (PRIVATE)
      code          -
      registers     : 1
      ins           : 0
      outs          : 0
      insns size    : 1 16-bit code units
0003a0:                                        |0000: return-void
`;

test('field names are not mistaken for methods', () => {
  const r = parseDexdump(DUMP, { class: 'com.foo.Bar' });
  assert.equal(r.classes, 2);
  assert.deepEqual(r.methods.map((m) => m.name), ['sign', 'nativeThing']);
});

test('instructions keep their offset, code units and operands', () => {
  const r = parseDexdump(DUMP, { class: 'com.foo.Bar', method: 'sign' });
  assert.equal(r.methods.length, 1);
  const m = r.methods[0];
  assert.equal(m.kind, 'code');
  assert.equal(m.registers, 3);
  assert.equal(m.insnsSize, 3);
  assert.deepEqual(m.insns.map((i) => i.offset), ['0000', '0002', '0004']);
  assert.equal(m.insns[0].text, 'const-string v0, "abc" // string@0001');
  assert.equal(m.insns[1].hex, '6e10 0500 0000');
  assert.equal(m.insns[2].text, 'return-object v0');
});

test('a native method comes back as native with no instructions', () => {
  const r = parseDexdump(DUMP, { class: 'com/foo/Bar', method: 'native' });
  assert.equal(r.methods.length, 1);
  assert.equal(r.methods[0].kind, 'native');
  assert.deepEqual(r.methods[0].insns, []);
});

test('class matching accepts the dotted name, the descriptor and a bare suffix', () => {
  for (const pat of ['com.foo.Bar', 'com/foo/Bar', 'Bar']) {
    const r = parseDexdump(DUMP, { class: pat });
    assert.equal(r.methodMatches, 2, `pattern ${pat}`);
  }
  assert.equal(parseDexdump(DUMP, { class: 'Other.Baz' }).methodMatches, 1);
  assert.equal(parseDexdump(DUMP, { class: 'nope' }).methodMatches, 0);
});

test('methodMatches counts what was found even when the page is capped', () => {
  const r = parseDexdump(DUMP, { class: 'com.foo.Bar', maxMethods: 1 });
  assert.equal(r.methodMatches, 2);
  assert.equal(r.returned, 1);
  assert.equal(r.truncated, true);
});

test('maxInsns cuts one body and says so', () => {
  const r = parseDexdump(DUMP, { class: 'com.foo.Bar', method: 'sign', maxInsns: 2 });
  assert.equal(r.methods[0].insns.length, 2);
  assert.equal(r.methods[0].insnsTruncated, true);
});

test('the shipped bridge dex really disassembles through dexdump', async (t) => {
  if (!findDexdump()) { t.skip('dexdump is not installed on this host'); return; }
  const buf = readFileSync(new URL('../../agent/src/hook/adh_java_hook_bridge.dex', import.meta.url));
  const r = await disassembleDex(buf, { class: 'AdhJavaHookBridge', maxMethods: 3, maxInsns: 40 });
  assert.equal(r.available, true, r.error);
  assert.ok((r.methodMatches ?? 0) > 3, 'expected more matches than the page holds');
  assert.equal(r.methods.length, 3);
  assert.equal(r.truncated, true);
  for (const m of r.methods) {
    assert.ok(m.class.includes('AdhJavaHookBridge'));
    assert.ok(m.name.length > 0);
    assert.ok(m.insns.length <= 40);
  }
  assert.ok(r.methods.some((m) => m.insns.length > 0), 'at least one body should decode');
  // A missing class is an empty answer with a note, not an error.
  const none = await disassembleDex(buf, { class: 'NoSuchClassAnywhere' });
  assert.equal(none.methodMatches, 0);
  assert.equal(none.available, true);
  assert.ok(none.note);
});
