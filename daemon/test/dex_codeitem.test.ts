import test from 'node:test';
import assert from 'node:assert/strict';
import { readCodeItem, codeItemEnd, rebuildStandardDex } from '../src/dex.ts';

// Build a synthetic code_item: 16B header + insns + optional 4-byte padding + tries[] +
// encoded_catch_handler_list. Mirrors the shapes a real dex produces (tries>0 => the item
// extends past the insns, which the old extractor refused to walk).
function codeItem(opts: { tries?: number; insnsSize?: number; handlerList?: Buffer } = {}): Buffer {
  const tries = opts.tries ?? 0, insnsSize = opts.insnsSize ?? 2;
  const header = Buffer.alloc(16);
  header.writeUInt16LE(2, 0);              // registers_size
  header.writeUInt16LE(2, 2);              // ins_size
  header.writeUInt16LE(1, 4);              // outs_size
  header.writeUInt16LE(tries, 6);          // tries_size
  header.writeUInt32LE(0, 8);              // debug_info_off
  header.writeUInt32LE(insnsSize, 12);     // insns_size (code units)
  const parts: Buffer[] = [header, Buffer.alloc(insnsSize * 2)];
  if (tries > 0) {
    const padLen = (4 - ((16 + insnsSize * 2) % 4)) % 4;
    if (padLen) parts.push(Buffer.alloc(padLen));
    const t = Buffer.alloc(tries * 8);
    for (let i = 0; i < tries; i++) { t.writeUInt32LE(0, i * 8); t.writeUInt16LE(insnsSize, i * 8 + 4); t.writeUInt16LE(1, i * 8 + 6); }
    parts.push(t);
    parts.push(opts.handlerList ?? Buffer.from([0x01, 0x7f, 0x00, 0x04, 0x08]));
  }
  return Buffer.concat(parts);
}

test('a code_item with try/catch is walked to the end of its handler list', () => {
  const b = codeItem({ tries: 1 });
  const ci = readCodeItem(b, 0);
  assert.ok(ci);
  assert.equal(ci.size, b.length);                 // insns tail included, not truncated at the insns
  assert.equal(ci.tries, 1);
  assert.equal(ci.insnsSize, 2);
  assert.equal(ci.hex, b.toString('hex'));
});

test('tries[] alignment and multi-handler lists are accounted for', () => {
  const b = codeItem({ tries: 2, insnsSize: 3 });   // 16 + 6 = 22 -> 2 bytes of padding before tries[]
  const ci = readCodeItem(b, 0);
  assert.ok(ci);
  assert.equal(ci.size, b.length);
  assert.equal((16 + 3 * 2 + 2) % 4, 0);            // the padded tries[] offset really is 4-aligned
  assert.equal(ci.hex, b.toString('hex'));
});

test('a handler list with only a catch-all and one with two pairs both parse', () => {
  const catchAll = codeItem({ tries: 1, handlerList: Buffer.from([0x01, 0x00, 0x08]) });
  assert.equal(readCodeItem(catchAll, 0)?.size, catchAll.length);
  const twoPairs = codeItem({ tries: 1, handlerList: Buffer.from([0x01, 0x7e, 0x00, 0x01, 0x00, 0x02, 0x09]) });
  assert.equal(readCodeItem(twoPairs, 0)?.size, twoPairs.length);
});

test('a truncated or impossible item is refused instead of half-read', () => {
  const b = codeItem({ tries: 1 });
  assert.equal(readCodeItem(b.subarray(0, b.length - 1), 0), null);   // handler list cut short
  const lying = Buffer.from(b); lying.writeUInt16LE(3, 6);            // claims 3 tries, has 1
  assert.equal(readCodeItem(lying, 0), null);
  assert.equal(readCodeItem(b, b.length - 8), null);                  // header runs past the buffer
  const noTries = codeItem({ tries: 0 });
  assert.equal(readCodeItem(noTries, 0)?.size, 16 + 2 * 2);           // unchanged for tries==0
});

test('the rebuilder refuses a capture that is not a complete code_item', () => {
  const good = codeItem({ tries: 1 });
  assert.throws(() => rebuildStandardDex(Buffer.alloc(112), [{ midx: 7, codeItemHex: good.subarray(0, good.length - 1).toString('hex') }]),
    /capture for method #7 is not a complete code_item/);
  assert.throws(() => rebuildStandardDex(Buffer.alloc(112), [{ midx: 9, codeItemHex: '00' }]),
    /capture for method #9 is not a complete code_item/);
});

test('the size-only walk agrees with the hex walk and never reads past the buffer', () => {
  const b = codeItem({ tries: 1 });
  assert.equal(codeItemEnd(b, 0), b.length);
  assert.equal(codeItemEnd(b, 0), readCodeItem(b, 0)?.size);
  // A LEB whose last byte claims "more bytes follow" must stop at the end of the buffer instead of
  // reading buf[len] (undefined) and reporting a bogus length.
  const cut = Buffer.from(b.subarray(0, b.length - 2));
  cut[cut.length - 1] = 0x80;                       // continuation bit with nothing after it
  assert.equal(codeItemEnd(cut, 0), null);
  assert.equal(readCodeItem(cut, 0), null);
});
