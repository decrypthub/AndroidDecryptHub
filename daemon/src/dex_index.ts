// Persistent DEX inverted index (WS-F). SQLite stays in the Host ADH Daemon layer; the
// injected agent only supplies bytes. Rows are keyed by dex SHA + parser version so stale
// indexes are rebuilt explicitly instead of returning plausible but mismatched results.
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR } from './state.ts';
import { analyzeDexCode, parseDex } from './dex.ts';

const PARSER_VERSION = 2;
export const DEX_INDEX_FILE = join(DATA_DIR, 'dex-index.sqlite');

// Journal mode. Default unchanged (WAL); this exists as an escape hatch, deliberately NOT as a
// changed default.
//
// SQLite's documentation says WAL does not work on a network filesystem — it needs the -shm
// shared-memory file, which network mounts do not provide coherently. Measured 2026-09-30: this
// index lived on a shared SMB tree and came back SQLITE_CORRUPT ("database disk image is
// malformed"), and on SMB the corrupt file could not be renamed from Linux (`mv` → "device or
// resource busy") because another host still held it — i.e. TWO machines had the same DB open.
//
// That second fact is why this default was left alone. Concurrent writers corrupt a SQLite file
// under any journal mode; I did not measure DELETE preventing anything, and this project does not
// change a default on a theory. The real fix is to stop sharing the database at all — set
// ADH_DATA_DIR (daemon/src/state.ts) to local disk, which was measured to take this same index from
// 3-of-4 dexes failing with SQLITE_CORRUPT to 4-of-4 classifying in ~1s.
// Set ADH_SQLITE_JOURNAL to DELETE/TRUNCATE/PERSIST/MEMORY only if you have measured a reason to.
const JOURNAL_MODES = ['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL'];
const JOURNAL_MODE = (() => {
  const want = (process.env.ADH_SQLITE_JOURNAL ?? 'WAL').toUpperCase();
  return JOURNAL_MODES.includes(want) ? want : 'WAL';
})();

const db = new DatabaseSync(DEX_INDEX_FILE);
db.exec(`
  PRAGMA journal_mode = ${JOURNAL_MODE};
  PRAGMA synchronous = NORMAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS dex_documents (
    sha TEXT PRIMARY KEY, size INTEGER NOT NULL, parser_version INTEGER NOT NULL,
    magic TEXT NOT NULL, string_count INTEGER NOT NULL, type_count INTEGER NOT NULL,
    proto_count INTEGER NOT NULL, field_count INTEGER NOT NULL, method_count INTEGER NOT NULL,
    class_count INTEGER NOT NULL, methods_with_code INTEGER NOT NULL, skipped_methods INTEGER NOT NULL,
    call_count INTEGER NOT NULL, string_use_count INTEGER NOT NULL, reflection_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS dex_strings (
    sha TEXT NOT NULL, string_idx INTEGER NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (sha, string_idx), FOREIGN KEY (sha) REFERENCES dex_documents(sha) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_strings_value ON dex_strings(sha, value COLLATE NOCASE);
  CREATE TABLE IF NOT EXISTS dex_classes (
    sha TEXT NOT NULL, class_idx INTEGER NOT NULL, name TEXT NOT NULL, super_name TEXT NOT NULL, access INTEGER NOT NULL,
    PRIMARY KEY (sha, class_idx), FOREIGN KEY (sha) REFERENCES dex_documents(sha) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_classes_name ON dex_classes(sha, name COLLATE NOCASE);
  CREATE TABLE IF NOT EXISTS dex_methods (
    sha TEXT NOT NULL, method_idx INTEGER NOT NULL, class_name TEXT NOT NULL, name TEXT NOT NULL,
    proto TEXT NOT NULL, return_type TEXT NOT NULL, params_json TEXT NOT NULL,
    PRIMARY KEY (sha, method_idx), FOREIGN KEY (sha) REFERENCES dex_documents(sha) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_methods_name ON dex_methods(sha, class_name COLLATE NOCASE, name COLLATE NOCASE);
  CREATE TABLE IF NOT EXISTS dex_fields (
    sha TEXT NOT NULL, field_idx INTEGER NOT NULL, class_name TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL,
    PRIMARY KEY (sha, field_idx), FOREIGN KEY (sha) REFERENCES dex_documents(sha) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_fields_name ON dex_fields(sha, class_name COLLATE NOCASE, name COLLATE NOCASE);
  CREATE TABLE IF NOT EXISTS dex_field_uses (
    sha TEXT NOT NULL, field_idx INTEGER NOT NULL, caller_idx INTEGER NOT NULL, access TEXT NOT NULL CHECK(access IN ('read','write')),
    PRIMARY KEY (sha, field_idx, caller_idx, access),
    FOREIGN KEY (sha, field_idx) REFERENCES dex_fields(sha, field_idx) ON DELETE CASCADE,
    FOREIGN KEY (sha, caller_idx) REFERENCES dex_methods(sha, method_idx) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_field_callers ON dex_field_uses(sha, field_idx, access);
  CREATE TABLE IF NOT EXISTS dex_string_uses (
    sha TEXT NOT NULL, string_idx INTEGER NOT NULL, caller_idx INTEGER NOT NULL,
    PRIMARY KEY (sha, string_idx, caller_idx),
    FOREIGN KEY (sha, string_idx) REFERENCES dex_strings(sha, string_idx) ON DELETE CASCADE,
    FOREIGN KEY (sha, caller_idx) REFERENCES dex_methods(sha, method_idx) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_string_callers ON dex_string_uses(sha, caller_idx);
  CREATE TABLE IF NOT EXISTS dex_calls (
    sha TEXT NOT NULL, caller_idx INTEGER NOT NULL, callee_idx INTEGER NOT NULL,
    PRIMARY KEY (sha, caller_idx, callee_idx),
    FOREIGN KEY (sha, caller_idx) REFERENCES dex_methods(sha, method_idx) ON DELETE CASCADE,
    FOREIGN KEY (sha, callee_idx) REFERENCES dex_methods(sha, method_idx) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_callers_by_callee ON dex_calls(sha, callee_idx);
  CREATE TABLE IF NOT EXISTS dex_reflections (
    sha TEXT NOT NULL, caller_idx INTEGER NOT NULL, api TEXT NOT NULL,
    target_class TEXT NOT NULL, target_descriptor TEXT NOT NULL,
    PRIMARY KEY (sha, caller_idx, api, target_class),
    FOREIGN KEY (sha, caller_idx) REFERENCES dex_methods(sha, method_idx) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS dex_reflection_target ON dex_reflections(sha, target_class COLLATE NOCASE);
`);

type DocumentRow = {
  sha: string; size: number; parser_version: number; magic: string;
  string_count: number; type_count: number; proto_count: number; field_count: number;
  method_count: number; class_count: number; methods_with_code: number; skipped_methods: number;
  call_count: number; string_use_count: number; reflection_count: number; created_at: number;
};

const getDocument = db.prepare('SELECT * FROM dex_documents WHERE sha = ?');

function publicDocument(row: DocumentRow, cached: boolean, elapsedMs: number, rebuildReason?: string) {
  return {
    sha: row.sha, size: row.size, parserVersion: row.parser_version, magic: row.magic,
    counts: {
      strings: row.string_count, types: row.type_count, protos: row.proto_count,
      fields: row.field_count, methods: row.method_count, classes: row.class_count,
      methodsWithCode: row.methods_with_code, skipped: row.skipped_methods,
      calls: row.call_count, stringUses: row.string_use_count, reflections: row.reflection_count,
    },
    cached, elapsedMs, indexFile: DEX_INDEX_FILE, ...(rebuildReason ? { rebuildReason } : {}),
  };
}

export function ensureDexIndex(buf: Buffer) {
  const started = performance.now();
  const sha = createHash('sha256').update(buf).digest('hex');
  const existing = getDocument.get(sha) as DocumentRow | undefined;
  if (existing && existing.size === buf.length && existing.parser_version === PARSER_VERSION)
    return publicDocument(existing, true, +(performance.now() - started).toFixed(2));

  const parsed = parseDex(buf);
  const analysis = analyzeDexCode(buf, parsed);
  const row: DocumentRow = {
    sha, size: buf.length, parser_version: PARSER_VERSION, magic: parsed.magic,
    string_count: parsed.counts.strings, type_count: parsed.counts.types,
    proto_count: parsed.counts.protos, field_count: parsed.counts.fields,
    method_count: parsed.counts.methods, class_count: parsed.counts.classes,
    methods_with_code: analysis.methodsWithCode, skipped_methods: analysis.skipped,
    call_count: analysis.calls.length, string_use_count: analysis.stringUses.length,
    reflection_count: analysis.reflections.length, created_at: Date.now(),
  };
  const insertDoc = db.prepare(`INSERT INTO dex_documents VALUES (${Array(16).fill('?').join(',')})`);
  const insertString = db.prepare('INSERT INTO dex_strings VALUES (?, ?, ?)');
  const insertClass = db.prepare('INSERT INTO dex_classes VALUES (?, ?, ?, ?, ?)');
  const insertMethod = db.prepare('INSERT INTO dex_methods VALUES (?, ?, ?, ?, ?, ?, ?)');
  const insertField = db.prepare('INSERT INTO dex_fields VALUES (?, ?, ?, ?, ?)');
  const insertFieldUse = db.prepare('INSERT OR IGNORE INTO dex_field_uses VALUES (?, ?, ?, ?)');
  const insertStringUse = db.prepare('INSERT OR IGNORE INTO dex_string_uses VALUES (?, ?, ?)');
  const insertCall = db.prepare('INSERT OR IGNORE INTO dex_calls VALUES (?, ?, ?)');
  const insertReflection = db.prepare('INSERT OR IGNORE INTO dex_reflections VALUES (?, ?, ?, ?, ?)');
  db.exec('BEGIN IMMEDIATE');
  try {
    if (existing) db.prepare('DELETE FROM dex_documents WHERE sha = ?').run(sha);
    insertDoc.run(
      row.sha, row.size, row.parser_version, row.magic, row.string_count, row.type_count,
      row.proto_count, row.field_count, row.method_count, row.class_count, row.methods_with_code,
      row.skipped_methods, row.call_count, row.string_use_count, row.reflection_count, row.created_at,
    );
    parsed.strings.forEach((value, idx) => insertString.run(sha, idx, value));
    parsed.classes.forEach((c, idx) => insertClass.run(sha, idx, c.name, c.superName, c.access));
    parsed.methods.forEach((m, idx) => insertMethod.run(sha, idx, m.cls, m.name, m.proto, m.returnType, JSON.stringify(m.params)));
    parsed.fields.forEach((f, idx) => insertField.run(sha, idx, f.cls, f.name, f.type));
    analysis.fieldAccesses.forEach(x => insertFieldUse.run(sha, x.fieldIdx, x.callerIdx, x.access));
    analysis.stringUses.forEach(x => insertStringUse.run(sha, x.stringIdx, x.callerIdx));
    analysis.calls.forEach(x => insertCall.run(sha, x.callerIdx, x.calleeIdx));
    analysis.reflections.forEach(x => insertReflection.run(sha, x.callerIdx, x.api, x.targetClass, x.targetDescriptor));
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  const rebuildReason = !existing ? 'new' : existing.size !== buf.length ? 'size-mismatch' : 'parser-version-mismatch';
  return publicDocument(row, false, +(performance.now() - started).toFixed(2), rebuildReason);
}

// Drop a document and everything derived from it (the child tables cascade). Used by artifact
// retention: once the dex file is deleted, an index row for it would answer `dex_index_search`
// with hits whose bytes no longer exist — a stale answer is worse than no answer.
export function deleteDexDocument(sha: string): boolean {
  const info = db.prepare('DELETE FROM dex_documents WHERE sha = ?').run(sha);
  return Number(info.changes) > 0;
}

export function searchDexIndex(sha: string, query: string, limit = 200) {
  const started = performance.now();
  const document = getDocument.get(sha) as DocumentRow | undefined;
  if (!document) throw Object.assign(new Error('dex index not found'), { status: 404 });
  const cap = Math.max(1, Math.min(1000, Number(limit) || 200));
  const like = `%${query}%`;
  const strings = db.prepare('SELECT string_idx AS idx, value FROM dex_strings WHERE sha = ? AND value LIKE ? COLLATE NOCASE LIMIT ?').all(sha, like, cap);
  const classes = db.prepare('SELECT class_idx AS idx, name, super_name AS superName, access FROM dex_classes WHERE sha = ? AND name LIKE ? COLLATE NOCASE LIMIT ?').all(sha, like, cap);
  const methods = db.prepare(`SELECT method_idx AS idx, class_name AS cls, name, proto, return_type AS returnType, params_json AS paramsJson
    FROM dex_methods WHERE sha = ? AND (class_name LIKE ? COLLATE NOCASE OR name LIKE ? COLLATE NOCASE OR proto LIKE ? COLLATE NOCASE) LIMIT ?`).all(sha, like, like, like, cap)
    .map((m: any) => ({ ...m, params: JSON.parse(m.paramsJson), paramsJson: undefined }));
  const fields = db.prepare(`SELECT f.field_idx AS idx, f.class_name AS cls, f.name, f.type,
      u.access, m.method_idx AS callerIdx, m.class_name AS callerClass, m.name AS callerName, m.proto AS callerProto
    FROM dex_fields f LEFT JOIN dex_field_uses u ON u.sha=f.sha AND u.field_idx=f.field_idx
    LEFT JOIN dex_methods m ON m.sha=u.sha AND m.method_idx=u.caller_idx
    WHERE f.sha=? AND (f.class_name LIKE ? COLLATE NOCASE OR f.name LIKE ? COLLATE NOCASE OR f.type LIKE ? COLLATE NOCASE) LIMIT ?`).all(sha, like, like, like, cap);
  const callers = db.prepare(`SELECT callee.method_idx AS calleeIdx, callee.class_name AS calleeClass,
      callee.name AS calleeName, callee.proto AS calleeProto, caller.method_idx AS callerIdx,
      caller.class_name AS callerClass, caller.name AS callerName, caller.proto AS callerProto
    FROM dex_calls c JOIN dex_methods callee ON callee.sha=c.sha AND callee.method_idx=c.callee_idx
    JOIN dex_methods caller ON caller.sha=c.sha AND caller.method_idx=c.caller_idx
    WHERE c.sha=? AND (callee.class_name LIKE ? COLLATE NOCASE OR callee.name LIKE ? COLLATE NOCASE OR callee.proto LIKE ? COLLATE NOCASE) LIMIT ?`).all(sha, like, like, like, cap);
  const stringCallers = db.prepare(`SELECT s.string_idx AS stringIdx, s.value, m.method_idx AS callerIdx,
      m.class_name AS cls, m.name, m.proto
    FROM dex_strings s JOIN dex_string_uses u ON u.sha=s.sha AND u.string_idx=s.string_idx
    JOIN dex_methods m ON m.sha=u.sha AND m.method_idx=u.caller_idx
    WHERE s.sha=? AND s.value LIKE ? COLLATE NOCASE LIMIT ?`).all(sha, like, cap);
  const reflections = db.prepare(`SELECT r.target_class AS targetClass, r.target_descriptor AS targetDescriptor,
      r.api, m.method_idx AS callerIdx, m.class_name AS cls, m.name, m.proto
    FROM dex_reflections r JOIN dex_methods m ON m.sha=r.sha AND m.method_idx=r.caller_idx
    WHERE r.sha=? AND (r.target_class LIKE ? COLLATE NOCASE OR r.target_descriptor LIKE ? COLLATE NOCASE) LIMIT ?`).all(sha, like, like, cap);
  return {
    sha, query, strings, classes, methods, fields, callers, stringCallers, reflections,
    counts: { strings: strings.length, classes: classes.length, methods: methods.length, fields: fields.length, callers: callers.length, stringCallers: stringCallers.length, reflections: reflections.length },
    elapsedMs: +(performance.now() - started).toFixed(2),
  };
}

export function listDexReflections(sha: string, limit = 500) {
  const document = getDocument.get(sha) as DocumentRow | undefined;
  if (!document) throw Object.assign(new Error('dex index not found'), { status: 404 });
  return db.prepare(`SELECT r.target_class AS targetClass, r.target_descriptor AS targetDescriptor,
      r.api, m.method_idx AS callerIdx, m.class_name AS cls, m.name, m.proto
    FROM dex_reflections r JOIN dex_methods m ON m.sha=r.sha AND m.method_idx=r.caller_idx
    WHERE r.sha=? ORDER BY r.target_class, m.class_name, m.name LIMIT ?`).all(sha, Math.max(1, Math.min(5000, Number(limit) || 500)));
}
