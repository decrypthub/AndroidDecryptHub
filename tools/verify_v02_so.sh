#!/usr/bin/env bash
# v0.2 SO-reassembly acceptance: reconstruct a loaded .so from target memory and
# confirm the rebuilt ELF is valid + analyzable (llvm-readelf reads it; exported
# symbols survive). Target = libidh_agent.so itself (guaranteed loaded, known exports).
# Exit 0 = PASS. Prereq: idhd running, device attached, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
NDK="${ANDROID_NDK_HOME:-$HOME/AppData/Local/Android/Sdk/ndk/28.2.13676358}"
READELF="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe"

set +e
OUT="$(node - "$HTTP" "$ROOT" <<'EOF'
const [http, root] = process.argv.slice(2);
const base=`http://127.0.0.1:${http}`;
const P=(o)=>fetch(`${base}${o.path}`,o.body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o.body)}:{}).then(r=>r.json());
const agents=await P({path:'/api/agents'});
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).pop();
if(!a){console.log('NO_AGENT');process.exit(0);}
const mods=await P({path:`/api/modules?session=${a.sessionId}`});
const mine=mods.find(m=>m.name==='libidh_agent.so');
console.log('modules total='+mods.length+' target='+(mine?`${mine.name} base=${mine.base} segs=${mine.segs} size=${mine.size}`:'MISSING'));
if(!mine){console.log('NO_MODULE');process.exit(0);}
const d=await P({path:'/api/module/dump',body:{session:a.sessionId,name:'libidh_agent.so'}});
if(d.error){console.log('DUMP_ERR '+d.error);process.exit(0);}
console.log(`reassembled: kind=${d.kind} size=${d.size} sha=${(d.sha256||'').slice(0,16)}… path=${d.path}`);
console.log('DUMP_PATH='+d.path);
EOF
)"
echo "$OUT"
echo "$OUT" | grep -q 'RESULT' # noop
DUMP_PATH="$(echo "$OUT" | sed -n 's/^DUMP_PATH=//p')"
if [ -z "$DUMP_PATH" ] || [ ! -f "$DUMP_PATH" ]; then echo "❌ no reassembled file"; echo "RESULT:FAIL"; exit 1; fi

# A memory image has no section headers; analyzability comes from PT_DYNAMIC.
# Assert the reassembled ELF is valid AND its dynamic table + dynstr are intact.
echo "=== llvm-readelf on reassembled ELF ==="
HDR="$("$READELF" -h "$DUMP_PATH" 2>&1)"
echo "$HDR" | grep -E "Class|Machine|Type" | sed 's/^/  /'
PHDR="$("$READELF" -l "$DUMP_PATH" 2>&1)"
DYN="$("$READELF" --dynamic "$DUMP_PATH" 2>&1)"

IS_ELF64=$(echo "$HDR" | grep -c "ELF64")
IS_AARCH64=$(echo "$HDR" | grep -c "AArch64")
IS_DYN=$(echo "$HDR" | grep -Ec "Type:.*DYN")
HAS_LOAD=$(echo "$PHDR" | grep -c "LOAD")
HAS_DYNAMIC=$(echo "$PHDR" | grep -c "DYNAMIC")
HAS_SONAME=$(echo "$DYN" | grep -c "libidh_agent.so")
HAS_SYMTAB=$(echo "$DYN" | grep -c "SYMTAB")
HAS_STRTAB=$(echo "$DYN" | grep -c "STRTAB")
STR_START=$(grep -c "adh_agent_start" "$DUMP_PATH" 2>/dev/null)
STR_JNI=$(grep -c "JNI_OnLoad" "$DUMP_PATH" 2>/dev/null)
echo "  elf64=$IS_ELF64 aarch64=$IS_AARCH64 dyn=$IS_DYN LOAD=$HAS_LOAD DYNAMIC=$HAS_DYNAMIC"
echo "  dyn: soname=$HAS_SONAME symtab=$HAS_SYMTAB strtab=$HAS_STRTAB ; dynstr has adh_agent_start=$STR_START JNI_OnLoad=$STR_JNI"

if [ "$IS_ELF64" -ge 1 ] && [ "$IS_AARCH64" -ge 1 ] && [ "$IS_DYN" -ge 1 ] \
   && [ "$HAS_LOAD" -ge 1 ] && [ "$HAS_DYNAMIC" -ge 1 ] \
   && [ "$HAS_SONAME" -ge 1 ] && [ "$HAS_SYMTAB" -ge 1 ] && [ "$HAS_STRTAB" -ge 1 ] \
   && [ "$STR_START" -ge 1 ] && [ "$STR_JNI" -ge 1 ]; then
  echo "✅ v0.2 SO-reassembly PASS (valid ELF from memory; PT_DYNAMIC + dynstr intact & analyzable)"
  echo "RESULT:PASS"; exit 0
else
  echo "❌ v0.2 SO-reassembly FAIL"; echo "RESULT:FAIL"; exit 1
fi
