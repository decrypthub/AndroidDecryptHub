import test from 'node:test';
import assert from 'node:assert/strict';
import { disasmBytes } from '../src/capstone.ts';

// capstone-wasm throws when not one instruction decodes, and its message prints the success code:
// "Failed to disassemble, error: OK (CS_ERR_OK)". Measured on target memory: a zero page (padding
// between functions) produced exactly that, so a caller reading the error concluded the tool was
// broken. "Nothing decodes here" is an answer and has to come back as an empty list.

test('a page of zeros disassembles to an empty list instead of throwing', async () => {
  const out = await disasmBytes(new Uint8Array(64), 0x1000n, 16);
  assert.deepEqual(out, []);
});

test('bytes that are not AArch64 code report no instructions, not a crash', async () => {
  const ff = new Uint8Array(64).fill(0xff);
  const out = await disasmBytes(ff, 0x2000n, 16);
  assert.deepEqual(out, []);
});

test('real AArch64 bytes still decode, so the empty answer is not a blanket failure', async () => {
  // ldp x3, x4, [x29, #0x10] / ldr x9, [x29, #0x20] / add sp, sp, #0xc0 / blr x9
  const code = Uint8Array.from([
    0xa3, 0x13, 0x41, 0xa9,
    0xa9, 0x13, 0x40, 0xf9,
    0xff, 0x43, 0x03, 0x91,
    0x20, 0x01, 0x3f, 0xd6,
  ]);
  const out = await disasmBytes(code, 0x3000n, 4);
  assert.equal(out.length, 4);
  assert.equal(out[0].mnemonic, 'ldp');
  assert.equal(out[3].mnemonic, 'blr');
  assert.equal(out[0].addr, '0x3000');
});
