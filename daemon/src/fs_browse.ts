// Device filesystem browsing for MCP (list_dir / read_file).
//
// The REST surface and the web FS browser could already walk the device filesystem; MCP could not,
// which meant an AI client had to ask for a base64 blob through another tool or give up. Both
// entry points share this module so the two surfaces cannot drift (the op-level audit flags any
// agent op that only one surface can reach).
//
// Reading a target file is an analysis capability, not a convenience: shared_prefs, keystores,
// certificates, config files and extraction scripts all live here. The agent caps a read at 1 MB
// and reports `truncated` honestly; the host never pretends a truncated read is complete.
import { sendCmd } from './service.ts';

export interface BrowseDeps { send: typeof sendCmd }
const defaultDeps: BrowseDeps = { send: sendCmd };

export interface DeviceEntry {
  name: string;
  /** d = directory, f = regular file, l = symlink, o = other/stat-failed. */
  type: 'd' | 'f' | 'l' | 'o';
  size: number;
  mode: number;
  mtime: number;
}

export interface DirListing {
  ok: true;
  path: string;
  count: number;
  truncated: boolean;
  entries: DeviceEntry[];
}

export async function listDeviceDir(session: string, path: string, deps: BrowseDeps = defaultDeps): Promise<DirListing> {
  const p = String(path ?? '');
  if (!p) throw new Error('need path');
  const r = await deps.send(session, 'list_dir', { path: p }, 20_000);
  if (!r?.ok) throw new Error(`list_dir ${p} failed: ${r?.error ?? 'unknown error'}`);
  const entries: DeviceEntry[] = Array.isArray(r.entries) ? r.entries : [];
  return {
    ok: true,
    path: String(r.path ?? p),
    count: Number(r.count ?? entries.length),
    truncated: r.truncated === true,
    entries,
  };
}

/** A bounded, printable view of a byte buffer - enough to judge what a file is. */
export function summarizeFile(buf: Buffer, previewBytes = 2048): { bytes: number; binary: boolean; textPreview: string; lineCount: number } {
  const bytes = buf.length;
  const binary = buf.includes(0);
  const slice = buf.subarray(0, Math.max(0, previewBytes));
  const textPreview = slice.toString('latin1').replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '.');
  const lineCount = buf.length ? buf.toString('latin1').split('\n').length : 0;
  return { bytes, binary, textPreview, lineCount };
}

/** Above this the full text is dropped: a 1 MB echo helps nobody and bloats the MCP reply. */
export const FILE_TEXT_LIMIT = 262_144;

export interface FileRead extends ReturnType<typeof summarizeFile> {
  ok: true;
  path: string;
  size: number;
  truncated: boolean;
  /** The whole file as UTF-8 text, when includeText was set and the file passed the guards. */
  text?: string;
  /** Why `text` is absent even though includeText was set (never a silent omission). */
  textOmitted?: string;
  /** Present only when includeBase64 is set: the raw bytes, for binary targets. */
  b64?: string;
}

export async function readDeviceFile(session: string, path: string, opts: { includeBase64?: boolean; includeText?: boolean; previewBytes?: number } = {}, deps: BrowseDeps = defaultDeps): Promise<FileRead> {
  const p = String(path ?? '');
  if (!p) throw new Error('need path');
  const r = await deps.send(session, 'read_file', { path: p }, 25_000);
  if (!r?.ok) throw new Error(`read_file ${p} failed: ${r?.error ?? 'unknown error'}`);
  if (typeof r.b64 !== 'string' || r.b64.length % 4 !== 0) throw new Error(`read_file ${p} returned a malformed base64 payload`);
  const buf = Buffer.from(r.b64, 'base64');
  const summary = summarizeFile(buf, opts.previewBytes ?? 2048);
  const base = {
    ok: true as const,
    path: String(r.path ?? p),
    size: Number(r.size ?? buf.length),
    truncated: r.truncated === true,
    ...summary,
    ...(opts.includeBase64 ? { b64: r.b64 } : {}),
  };
  if (!opts.includeText) return base;
  // Binary content and huge files are where a full text field would be actively misleading (or
  // enormous), so they are reported as omitted with a reason instead of pasted regardless.
  if (summary.binary) return { ...base, textOmitted: 'binary content (NUL byte present): use textPreview or includeBase64' };
  if (summary.bytes > FILE_TEXT_LIMIT) return { ...base, textOmitted: `file is ${summary.bytes} bytes (limit ${FILE_TEXT_LIMIT}): use includeBase64 or a smaller target` };
  return { ...base, text: buf.toString('utf8') };
}
