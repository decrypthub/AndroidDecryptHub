import test from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {stdioEncoder,stdioDecoder} from '../src/transport/stdio_armor.ts';
import {DEVICE_FRAME_MAX} from '../src/device_protocol.ts';
function frame(size:number){const value=Buffer.alloc(size+4);value.writeUInt32BE(size);for(let n=0;n<size;n++)value[n+4]=n%256;return value;}
async function collect(stream:AsyncIterable<any>){const chunks:Buffer[]=[];for await(const chunk of stream)chunks.push(chunk);return Buffer.concat(chunks);}
test('stdio armor preserves control bytes and frame headers across arbitrary chunk and CRLF boundaries',async()=>{
  const raw=Buffer.concat(Array.from({length:256},(_,i)=>frame(i+1)));
  const encoded=await collect(Readable.from(Array.from(raw,n=>Buffer.from([n]))).pipe(stdioEncoder()));
  const windows=Buffer.from(encoded.toString('ascii').replaceAll('\n','\r\n'));
  assert.deepEqual(await collect(Readable.from(Array.from(windows,n=>Buffer.from([n]))).pipe(stdioDecoder())),raw);
});
test('stdio armor carries a maximum frame and refuses malformed, truncated, non-ASCII and oversized peers',async()=>{
  const raw=frame(DEVICE_FRAME_MAX),encoded=await collect(Readable.from([raw]).pipe(stdioEncoder()));assert.deepEqual(await collect(Readable.from([encoded]).pipe(stdioDecoder())),raw);
  for(const bytes of [Buffer.from('!!!!\n'),Buffer.from('AAAAAA==\n'),Buffer.from('AAAAAQ==\n'),Buffer.from('AAAAAQE='),Buffer.from('A'.repeat(1_400_000)+'\n'),Buffer.from([0xc1,0x41,0x41,0x41,10])])await assert.rejects(()=>collect(Readable.from([bytes]).pipe(stdioDecoder())));
  await assert.rejects(()=>collect(Readable.from([Buffer.from([0,16,0,1])]).pipe(stdioEncoder())));
  await assert.rejects(()=>collect(Readable.from([Buffer.from([0,0])]).pipe(stdioEncoder())));
});
