#!/usr/bin/env bash
# v0.20 file I/O GOT-hook capture. Hooks libjavacore.so's open/close (plain libc
# symbols) plus __read_chk/__write_chk (bionic FORTIFY_SOURCE wrappers — the real
# path behind java.io.FileInputStream/FileOutputStream on this ART version; plain
# read/write/writev/syscall are imported by libjavacore.so too but never fire for
# this call path — confirmed empirically), triggers a real file write+read+verify
# (via JNI reflection into FileIO.run()), and asserts the agent captured the real
# file path at open and the real marker bytes at both write and read.
# Exit 0 = PASS. Prereq: adhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
MARKER="ADH_FILE_MARKER_v1"; FNAME="adh_file_test.txt"

set +e
OUT="$(node - "$HTTP" "$MARKER" "$FNAME" <<'EOF'
const [http, marker, fname]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/file/hook_test?session=${a.sessionId}&module=libjavacore.so`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`hooked=${JSON.stringify(r.hooked)} triggered=${r.triggered} result=${r.result} captures=${r.count}`);
(r.captures||[]).forEach(c=>console.log(`  [${c.func} inl=${c.inl}] ${(c.ascii||'').slice(0,80)}`));
const opened=(r.captures||[]).find(c=>c.func==='open' && c.ascii.includes(fname));
const wrote =(r.captures||[]).find(c=>c.func==='write' && c.ascii.includes(marker));
const read  =(r.captures||[]).find(c=>c.func==='read'  && c.ascii.includes(marker));
const pass = r.ok && r.hooked.open>=1 && r.hooked.readChk>=1 && r.hooked.writeChk>=1 && r.triggered
  && /校验OK/.test(r.result||'') && !!opened && !!wrote && !!read;
console.log(`open path captured: ${!!opened}; write marker captured: ${!!wrote}; read marker captured: ${!!read}`);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.20 file I/O GOT-hook capture (open path + write/read marker bytes, real java.io.File round-trip)" 1 && exit 0 || exit 1
