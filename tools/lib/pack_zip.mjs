#!/usr/bin/env node
// Dependency-free ZIP packer used for release bundles when `zip` is unavailable.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const [output, root] = process.argv.slice(2);
if (!output || !root) {
  console.error('usage: pack_zip.mjs <output.zip> <root-directory>');
  process.exit(2);
}

function crc32(buffer) {
  let value = ~0;
  for (const byte of buffer) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (0xedb88320 & -(value & 1));
  }
  return ~value >>> 0;
}

function walk(directory, prefix = '') {
  const entries = [];
  for (const name of fs.readdirSync(directory)) {
    const fullPath = path.join(directory, name);
    const relativePath = prefix ? `${prefix}/${name}` : name;
    if (fs.statSync(fullPath).isDirectory()) entries.push(...walk(fullPath, relativePath));
    else entries.push({ name: relativePath.replaceAll('\\', '/'), data: fs.readFileSync(fullPath) });
  }
  return entries;
}

const parts = [];
const central = [];
let offset = 0;
for (const entry of walk(root)) {
  const name = Buffer.from(entry.name);
  const compressed = zlib.deflateRawSync(entry.data);
  const useDeflate = compressed.length < entry.data.length;
  const payload = useDeflate ? compressed : entry.data;
  const method = useDeflate ? 8 : 0;
  const crc = crc32(entry.data);

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(method, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(payload.length, 18);
  local.writeUInt32LE(entry.data.length, 22);
  local.writeUInt16LE(name.length, 26);
  const localOffset = offset;
  parts.push(local, name, payload);
  offset += local.length + name.length + payload.length;

  const record = Buffer.alloc(46);
  record.writeUInt32LE(0x02014b50, 0);
  record.writeUInt16LE(20, 4);
  record.writeUInt16LE(20, 6);
  record.writeUInt16LE(method, 10);
  record.writeUInt32LE(crc, 16);
  record.writeUInt32LE(payload.length, 20);
  record.writeUInt32LE(entry.data.length, 24);
  record.writeUInt16LE(name.length, 28);
  record.writeUInt32LE(localOffset, 42);
  central.push(record, name);
}

const centralData = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(central.length / 2, 8);
end.writeUInt16LE(central.length / 2, 10);
end.writeUInt32LE(centralData.length, 12);
end.writeUInt32LE(offset, 16);
fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
fs.writeFileSync(output, Buffer.concat([...parts, centralData, end]));
console.log(`wrote ${output} (${fs.statSync(output).size} bytes)`);
