export type Mode = 'read' | 'analysis' | 'write';
export interface OperationSpec { name: string; mode: Mode; session?: string; global?: boolean }
const readTools = new Set([
  'analysis_guide','process_list','backends','capabilities','dumps_list','runtime_diagnostics','agent_ping',
  'memory_maps','maps_query','memory_read','memory_disasm','memory_search','memory_scan_magic','got_enum',
  'java_enum','java_call_result','art_dexfiles','object_inspect','live_captures','capture_detail','http_exchanges','file_probe',
  'flow_correlate','crypto_identify','detect_summary','detect_modules','scope_list','fs_list','fs_read',
]);
const analysisTools = new Set([
  'native_symbols','native_xref','native_disasm','native_analyze','native_crypto_const','crypto_variant_scan','native_syscall_scan',
  'dex_search','dex_index','dex_index_search','dex_reflections','dex_xref','dex_crypto_scan','dex_method_code','dex_repair',
  'dex_coverage','dex_recover','memory_dump','dump_all_dex',
]);
// Read intent is tool-specific: oracle diff/stability actively invoke the target;
// native_hook_all and syscall_watch ignore arbitrary action fields and install hooks.
const readActions: Record<string, readonly string[]> = {
  jni_onload:['list','status'],jni_hook:['status'],jni_env_hook:['status'],java_hook:['status'],
  native_hook:['status'],hw_watch:['status'],native_look:['read'],java_trace:['digest'],syscall_trace:['digest'],
  module_watch:['status','list'],root_watch:['status','read'],trace_session:['query','stats','slice','list'],
  oracle:['list'],stealth:['status'],
};
export function describeTool(name: string, args: Record<string, any> = {}): OperationSpec {
  let mode: Mode = readTools.has(name) ? 'read' : analysisTools.has(name) ? 'analysis' : 'write';
  if (Object.hasOwn(readActions,name) && readActions[name].includes(args.action)) mode = 'read';
  if (name === 'settings') mode = args.action === 'get' || args.action === 'maintenance' && args.dryRun !== false ? 'read' : 'write';
  if (name === 'recipe' && (!args.action || args.action === 'list') && !args.name) mode = 'read';
  if (name === 'detect_java' && args.confirm !== true) mode = 'read';
  if (name === 'mem_backend' && (!args.backend || args.backend === 'status')) mode = 'read';
  if (name === 'memory_restore' && !args.addr) mode = 'read';
  if (name === 'oracle' && args.action==='drop') mode = 'analysis';
  if (name === 'crypto_evidence') mode = ['save','drop'].includes(args.action) ? 'analysis' : 'read';
  return { name, mode, session: args.session,
    global: ['settings','scope_set','analyze_app','unpack_package'].includes(name) || name === 'trace_session' && args.action==='drop' || name === 'root_watch' && ['prepare','stop'].includes(args.action) && !args.session };
}
const routeTools: Record<string, string> = {
  '/api/scope':'scope_set','/api/analyze-app':'analyze_app','/api/config':'settings','/api/settings/import':'settings',
  '/api/java/call':'java_call','/api/native/hook':'native_hook','/api/native/call':'native_call','/api/native/stealth':'stealth',
  '/api/native/hook_all':'native_hook_all','/api/java/trace':'java_trace','/api/jni/onload':'jni_onload',
  '/api/jni/hook':'jni_hook','/api/jni/env_hook':'jni_env_hook','/api/java/hook':'java_hook','/api/object/set':'object_set',
  '/api/object/invoke':'object_invoke','/api/trace/qbdi':'qbdi_trace','/api/unpack/trigger':'trigger',
  '/api/memory/write':'memory_write','/api/memory/restore':'memory_restore','/api/module/watch':'module_watch',
  '/api/recipes/run':'recipe','/api/agent/load_so':'load_library','/api/unpack/run':'unpack_package',
  '/api/native/syscall_watch':'syscall_watch','/api/syscall/trace':'syscall_trace',
};
const readPaths = new Set(['/api/fs/read','/api/memory/read','/api/memory/disasm','/api/memory/search',
  '/api/native/got_enum','/api/java/enum','/api/object/inspect','/api/jni/field_digest','/api/syscall/digest',
  '/api/trace/digest','/api/native/backtrace','/api/dex/index/search','/api/dex/index/reflections','/api/dex/xref',
  '/api/dex/coverage','/api/dex/parse','/api/dex/method_code','/api/dex/search','/api/dex/crypto_scan']);
const analysisPaths = new Set(['/api/native/syscall_scan','/api/native/crypto_const','/api/native/crypto_variants',
  '/api/native/analyze','/api/native/disasm','/api/module/dump','/api/dex/index','/api/dex/recover',
  '/api/dex/strip','/api/dex/rebuild','/api/dex/repair','/api/art/dump','/api/memory/dump',
  '/api/unpack/dump-one','/api/unpack/dump-so-one','/api/unpack/pull-so','/api/unpack/dump-all','/api/unpack/dump-so']);
export function describeHttp(path: string, method: string, args: Record<string, any> = {}): OperationSpec {
  const alias = routeTools[path];
  if (path === '/api/config') return describeTool('settings', { ...args, action: method === 'POST' ? 'patch' : 'get' });
  if (path === '/api/scope') return describeTool(method === 'POST' ? 'scope_set' : 'scope_list', args);
  if (path === '/api/settings/import') return describeTool('settings', { ...args, action: 'patch' });
  if (path === '/api/maintenance') return describeTool('settings', { ...args, action: 'maintenance' });
  if (alias) return describeTool(alias, args);
  if (readPaths.has(path)) return { name: `http:${path}`, mode: 'read', session: args.session };
  if (method === 'GET' && !['/api/hook/selftest','/api/java/probe','/api/compat/probe','/api/debug/frame_echo'].includes(path)) {
    return { name: `http:${path}`, mode: 'read', session: args.session };
  }
  if (analysisPaths.has(path)) {
    return { name: `http:${path}`, mode: 'analysis', session: args.session };
  }
  // Unclassified POST/actions are guarded writes, never silently considered read-only.
  return { name: `http:${path}`, mode: 'write', session: args.session, global: !args.session };
}
