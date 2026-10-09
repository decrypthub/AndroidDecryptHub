// Host-side raw-byte disassembly through Capstone 5 (WebAssembly build). Keeping this in
// the daemon respects the ADH red line: the agent only reads bytes from target memory.
import { loadCapstone, Capstone, Const } from 'capstone-wasm';

export interface Insn {
  addr: string;
  bytes: string;
  mnemonic: string;
  opStr: string;
  text: string;
}

export const CAPSTONE_VERSION = `${Const.CS_API_MAJOR}.${Const.CS_API_MINOR}`;

let loaded: Promise<void> | null = null;

async function ensureCapstone(): Promise<void> {
  if (!loaded) loaded = loadCapstone();
  await loaded;
}

function normalizeAddress(value: bigint | number): string {
  return `0x${BigInt(value).toString(16)}`;
}

/**
 * Disassemble AArch64 bytes at an absolute runtime address.
 * The caller owns the bytes (usually an agent `read` reply decoded from base64).
 */
export async function disasmBytes(
  bytes: Uint8Array,
  address: bigint | number,
  count = 4096,
): Promise<Insn[]> {
  await ensureCapstone();
  const cs = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
  try {
    const limit = Math.max(1, Math.min(4096, Math.floor(count)));
    const decoded = cs.disasm(bytes, { address: BigInt(address), count: limit });
    return decoded.map((i: any) => {
      const opStr = String(i.opStr ?? '');
      const mnemonic = String(i.mnemonic ?? '');
      return {
        addr: normalizeAddress(typeof i.address === 'bigint' ? i.address : BigInt(Math.trunc(Number(i.address)))),
        bytes: Buffer.from(i.bytes ?? []).toString('hex'),
        mnemonic,
        opStr,
        text: opStr ? `${mnemonic} ${opStr}` : mnemonic,
      };
    });
  } finally {
    cs.close();
  }
}