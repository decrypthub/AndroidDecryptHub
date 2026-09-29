import { createHash } from 'node:crypto';
import { createReadStream, existsSync, unlinkSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { analyzeSo, cryptoConstScan, disasmSo, OBJDUMP, svcScan } from '../analysis.ts';
import { scanCryptoVariants } from '../crypto_variants.ts';
import {
  analyzeCoverage, cryptoScan, extractMethodCode, invokeXref, parseDex,
  rebuildStandardDex, recoverFromSnapshots, searchDex, stripMethodCode,
} from '../dex.ts';
import { ensureDexIndex, listDexReflections, searchDexIndex } from '../dex_index.ts';
import {dumpBuf, dumpBufPath, modulesFromMaps, persistArtifact, pickSid, reconstructSo,
  repairDexHeader, sendCmd,} from '../service.ts';
import { resolveModule, ModuleAmbiguousError } from '../memory.ts';
import { broadcast, CAPTURES, dumps, readBody, sessions } from '../state.ts';
import type { DumpMeta } from '../state.ts';
import type { Route, RouteContext, SendResponse } from './types.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));

export async function serveDashboard(send: SendResponse) {
  try {
    const html = await readFile(join(__dirname, '..', '..', 'public', 'index.html'), 'utf8');
    return send(200, html, 'text/html; charset=utf-8');
  } catch { return send(500, { error: 'dashboard missing' }); }
}

export function analysisRoutes({ req, res, url, send }: RouteContext): Route[] {
  const routes: Route[] = [
    { method: 'POST', path: '/api/native/syscall_scan', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const r = svcScan(buf);
      return send(200, { execSegs: r.execSegs, scannedBytes: r.scanned, svcCount: r.hits.length, hits: r.hits.slice(0, 200) });
    } },
    { method: 'POST', path: '/api/native/crypto_const', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const hits = cryptoConstScan(buf);
      const byName: Record<string, number> = {};
      for (const h of hits) byName[h.name] = (byName[h.name] ?? 0) + 1;
      return send(200, { size: buf.length, hits, byName, algorithms: Object.keys(byName) });
    } },
    // Structural counterpart to crypto_const: the standard-constant scan above is blind to an app
    // that implements the algorithm itself and perturbs it. This one identifies by structure and
    // reports the mutation, plus where a static scan cannot see at all.
    { method: 'POST', path: '/api/native/crypto_variants', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      return send(200, { size: buf.length, ...scanCryptoVariants(buf) });
    } },
    { method: 'POST', path: '/api/native/analyze', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, q } = JSON.parse(body || '{}');
      let path: string, tmp: string | null;
      try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try {
        const a = await analyzeSo(path);
        if (q) { const rx = new RegExp(String(q), 'i');
          a.exports = a.exports.filter((s: string) => rx.test(s)); a.imports = a.imports.filter((s: string) => rx.test(s));
          a.strings = a.strings.filter((s: string) => rx.test(s)); }
        const CAP_SYM = 20000, CAP_STR = 1000;
        a.truncated = { exports: a.exports.length > CAP_SYM, imports: a.imports.length > CAP_SYM, strings: a.strings.length > CAP_STR };
        a.exports = a.exports.slice(0, CAP_SYM); a.imports = a.imports.slice(0, CAP_SYM); a.strings = a.strings.slice(0, CAP_STR);
        return send(200, a);
      } catch (e) { return send(502, { error: (e as Error).message }); }
      finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
    } },
    { method: 'POST', path: '/api/native/disasm', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, symbol, start, stop } = JSON.parse(body || '{}');
      let path: string, tmp: string | null;
      try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try {
        const insns = await disasmSo(path, { symbol, start, stop });
        return send(200, { symbol: symbol ?? null, count: insns.length, instructions: insns.slice(0, 2000) });
      } catch (e) { return send(502, { error: (e as Error).message, objdump: OBJDUMP }); }
      finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
    } },
    { path: '/api/modules', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await sendCmd(sid, 'maps');
        if (!r.ok) return send(502, r);
        return send(200, modulesFromMaps(r.regions ?? []));
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/module/dump', handler: async () => {
      const body = await readBody(req);
      const { session, name } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !name) return send(400, { error: 'need session, name' });
      try {
        const maps = await sendCmd(sid, 'maps');
        // Shared strict resolution (exact -> unique suffix -> unique substring): `libc` used to
        // silently pick between libc.so / libc++.so / libcutils.so.
        let mod: any;
        try {
          mod = resolveModule(modulesFromMaps(maps.regions ?? []), String(name));
        } catch (e) {
          if (e instanceof ModuleAmbiguousError) return send(409, { error: e.message, candidates: e.candidates });
          throw e;
        }
        if (!mod) return send(404, { error: `module not found: ${name}` });
        const buf = await reconstructSo(sid, mod.base);
        const sha = createHash('sha256').update(buf).digest('hex');
        const existing = dumps.get(sha);
        // v4.99: a dedup hit must describe THIS request, not the call that happened to store the
        // bytes first. The sha proves the content is identical; everything that says "what this
        // response is" (source/complete/session/tag/addr) is recomputed here, the same rule
        // dumpRegion has followed since v4.96. Without this, a module dump whose bytes first came
        // from a region dump came back as source:'region' with that session's tag and package.
        if (existing) return send(200, { ...existing, dedup: true, module: mod.name, segments: mod.segs,
          source: 'so-reassembly', note: 'reassembled from memory: offsets == vaddrs, section headers dropped, not byte-exact',
          size: buf.length, requestedSize: buf.length, complete: true, addr: mod.base, tag: mod.name,
          sessionId: sid, package: sessions.get(sid)?.package ?? existing.package ?? '?' });
        const s = sessions.get(sid);
        const path = join(CAPTURES, `${sha.slice(0, 16)}.so`);
        if (!existsSync(path)) await writeFile(path, buf);
        const meta: DumpMeta = { sha256: sha, size: buf.length, requestedSize: buf.length, complete: true, source: 'so-reassembly', note: 'reassembled from memory: offsets == vaddrs, section headers dropped, not byte-exact', addr: mod.base, tag: mod.name, sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind: 'so' };
        dumps.set(sha, meta);
        broadcast('dump.new', meta);
        return send(200, { ...meta, dedup: false, module: mod.name, segments: mod.segs });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/dex/method_code', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, class: cls, method, limit } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!cls) return send(400, { error: 'need class' });
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const codes = extractMethodCode(buf, parsed, String(cls), method ? String(method) : undefined);
      // recovered + empty + unresolvable === count: an item we cannot walk is neither "recovered"
      // nor "empty" (it used to be counted as recovered because its header had been read anyway).
      const recovered = codes.filter(c => c.codeItemHex).length;
      const unresolvable = codes.filter(c => c.unresolvable).length;
      // How many method records to return (default 200, capped) - callers that need to find a
      // specific shape (e.g. a method with try/catch) ask for a bigger window explicitly.
      const lim = Math.min(Math.max(Math.trunc(Number(limit)) || 200, 1), 5000);
      return send(200, { class: cls, method: method ?? null, count: codes.length, recovered,
        empty: codes.length - recovered - unresolvable, unresolvable, methods: codes.slice(0, lim) });
    } },
    { method: 'POST', path: '/api/dex/index', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf(body); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try { return send(200, ensureDexIndex(buf)); }
      catch (e) { return send(422, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/dex/index/search', handler: async () => {
      const { sha, query, limit } = JSON.parse((await readBody(req)) || '{}');
      if (!sha || query === undefined) return send(400, { error: 'need indexed dex sha and query' });
      try { return send(200, searchDexIndex(String(sha), String(query), limit)); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
    } },
    { method: 'POST', path: '/api/dex/index/reflections', handler: async () => {
      const { sha, limit } = JSON.parse((await readBody(req)) || '{}');
      if (!sha) return send(400, { error: 'need indexed dex sha' });
      try { return send(200, { sha, reflections: listDexReflections(String(sha), limit) }); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
    } },
    { method: 'POST', path: '/api/dex/xref', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, method } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!method) return send(400, { error: 'need method (substring of callee cls->name)' });
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const { xref, methodsWithCode, skipped } = invokeXref(buf, parsed);
      const q = String(method).toLowerCase();
      const results: Record<string, string[]> = {};
      for (const [callee, callers] of xref) if (callee.toLowerCase().includes(q)) results[callee] = callers.slice(0, 200);
      return send(200, { method, methodsWithCode, skipped, matches: Object.keys(results).length, callers: results });
    } },
    { method: 'POST', path: '/api/dex/coverage', handler: async () => {
      const { b64, sha, limitMissing } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const cov = analyzeCoverage(buf, parsed);
      const lm = Number(limitMissing ?? 100);
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...cov,
        recoveryPct: +(cov.recoveryRate * 100).toFixed(2), missing: cov.missing.slice(0, lm), missingTotal: cov.missingTotal });
    } },
    { method: 'POST', path: '/api/dex/recover', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      const load = (b64?: string, sha?: string) => (b64 || (sha && dumps.get(sha))) ? dumpBuf({ b64, sha }) : Promise.resolve(null);
      let base: Buffer | null, restored: Buffer | null;
      try { base = await load(body.baseB64, body.baseSha); restored = await load(body.restoredB64, body.restoredSha); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
      if (!base || !restored) return send(400, { error: 'need base + restored (b64 or known sha)' });
      let parsed; try { parsed = parseDex(base); } catch (e) { return send(422, { error: (e as Error).message }); }
      const { captures, report } = recoverFromSnapshots(base, restored, parsed);
      // The rebuild fails loud on a base whose still-referenced items cannot be walked; that is a
      // statement about the input, so it maps to 422 like /api/dex/rebuild, not to a 500.
      let rb; try { rb = rebuildStandardDex(base, captures); } catch (e) { return send(422, { error: (e as Error).message }); }
      let parseOk = true; try { parseDex(rb.dex); } catch { parseOk = false; }
      const outSha = createHash('sha256').update(rb.dex).digest('hex');
      const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
      if (!existsSync(path)) await writeFile(path, rb.dex);
      const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
      dumps.set(outSha, meta); broadcast('dump.new', meta);
      return send(200, { ok: true, ...report, injected: rb.injected, classesRewritten: rb.classesRewritten, parseOk, sha256: outSha, size: rb.dex.length,
        mapRebuilt: rb.mapRebuilt, mapEntries: rb.mapEntries, relocatedCodeItems: rb.relocatedCodeItems, relocatedClassData: rb.relocatedClassData,
        unmatchedCaptures: rb.unmatchedCaptures, skippedCaptures: rb.skippedCaptures, duplicateCaptures: rb.duplicateCaptures, layout: rb.layout });
    } },
    { method: 'POST', path: '/api/dex/strip', handler: async () => {
      const { b64, sha, midx } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const stripped = stripMethodCode(buf, Number(midx));
      return send(200, { ok: true, midx: Number(midx), b64: stripped.toString('base64') });
    } },
    { method: 'POST', path: '/api/dex/rebuild', handler: async () => {
      const { b64, sha, captures } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!Array.isArray(captures)) return send(400, { error: 'need captures[]' });
      let res; try { res = rebuildStandardDex(buf, captures); } catch (e) { return send(422, { error: (e as Error).message }); }
      let parseOk = true, methods = 0;
      try { const pd = parseDex(res.dex); methods = pd.counts.methods; } catch { parseOk = false; }
      const outSha = createHash('sha256').update(res.dex).digest('hex');
      const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
      if (!existsSync(path)) await writeFile(path, res.dex);
      const meta: DumpMeta = { sha256: outSha, size: res.dex.length, source: 'dex-rebuild', addr: '0', tag: 'rebuilt', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
      dumps.set(outSha, meta); broadcast('dump.new', meta);
      return send(200, { ok: true, injected: res.injected, classesRewritten: res.classesRewritten, parseOk, methods, sha256: outSha, size: res.dex.length,
        mapRebuilt: res.mapRebuilt, mapEntries: res.mapEntries, relocatedCodeItems: res.relocatedCodeItems, relocatedClassData: res.relocatedClassData,
        unmatchedCaptures: res.unmatchedCaptures, skippedCaptures: res.skippedCaptures, duplicateCaptures: res.duplicateCaptures, layout: res.layout });
    } },
    // Combined: /api/dex/parse | /api/dex/crypto_scan | /api/dex/search — one body, branches on path.
    { method: 'POST', path: '/api/dex/parse', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/crypto_scan', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/search', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/repair', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const info = repairDexHeader(buf);
      // Stored, not echoed: see persistArtifact. The repaired dex is fetched by the returned sha.
      const { meta, dedup } = await persistArtifact(buf, { source: 'dex-repair', addr: '', tag: 'dex_repair', sessionId: '', package: '' });
      return send(200, { ...info, sha256: meta.sha256, size: meta.size, kind: meta.kind, path: meta.path, dedup });
    } },
    { path: '/api/dumps', handler: () => send(200, [...dumps.values()]) },
    { path: '/api/dumps/download', handler: () => {
      const sha = url.searchParams.get('sha') ?? '';
      const m = dumps.get(sha);
      if (!m) return send(404, { error: 'no such dump' });
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': `attachment; filename="${sha.slice(0, 16)}.${m.kind}.bin"` });
      return createReadStream(m.path).pipe(res);
    } },
    { path: '/', handler: () => serveDashboard(send) },
    { path: '/index.html', handler: () => serveDashboard(send) },
  ];

  async function dexParseScanSearch() {
    const body = await readBody(req);
    const { b64, sha, full } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    let parsed;
    try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    if (url.pathname === '/api/dex/crypto_scan') {
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...cryptoScan(parsed) });
    }
    if (url.pathname === '/api/dex/search') {
      const { query, kinds } = JSON.parse(body || '{}');
      if (!query) return send(400, { error: 'need query' });
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...searchDex(parsed, String(query), kinds) });
    }
    // parse: counts + samples (or full arrays when full=true)
    const cap = full ? Infinity : 200;
    return send(200, {
      magic: parsed.magic, counts: parsed.counts,
      classes: parsed.classes.slice(0, cap).map(c => c.name),
      methods: parsed.methods.slice(0, cap),
      strings: parsed.strings.slice(0, cap),
    });
  }
  return routes;
}
