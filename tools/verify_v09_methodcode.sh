#!/usr/bin/env bash
# v0.9 Method Body Recovery (L.7, HOST-ONLY). Extracts a method's runtime code_item
# bytecode from a captured dex. Probe.hello -> const-string + return-object (insnsSize 3,
# starts 0x1a, ends 1100); all probe methods have code (0 empty). App: JavaCrypto.run
# has non-empty code. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "❌ APK missing"; echo "RESULT:FAIL"; exit 1; }
PROBE_B64="ZGV4CjAzOAAldROcj4AnW/EXyPvKv8zYfcWhEh6enuXYAgAAcAAAAHhWNBIAAAAAAAAAAFACAAAKAAAAcAAAAAQAAACYAAAAAgAAAKgAAAAAAAAAAAAAAAMAAADAAAAAAQAAANgAAADgAQAA+AAAADABAAA4AQAARgEAAEkBAABgAQAAdAEAAIgBAACUAQAAlwEAAJ4BAAADAAAABAAAAAUAAAAHAAAAAgAAAAIAAAAAAAAABwAAAAMAAAAAAAAAAAABAAAAAAAAAAAACAAAAAEAAQAAAAAAAAAAAAEAAAABAAAAAAAAAAYAAAAAAAAAQAIAAAAAAAABAAAAAAAAACgBAAADAAAAGgABABEAAAABAAEAAQAAACwBAAAEAAAAcBACAAAADgADAA4AAgAOAAY8aW5pdD4ADElESF9QUk9CRV9PSwABTAAVTGNvbS9pZGgvcHJvYmUvUHJvYmU7ABJMamF2YS9sYW5nL09iamVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwAKUHJvYmUuamF2YQABVgAFaGVsbG8AnwF+fkQ4eyJiYWNrZW5kIjoiZGV4IiwiY29tcGlsYXRpb24tbW9kZSI6InJlbGVhc2UiLCJoYXMtY2hlY2tzdW1zIjpmYWxzZSwibWluLWFwaSI6MjYsInNoYS0xIjoiYTdhZDE4YTcwNDYwYjc5OWQwNDgyZTQ5N2MxMDlhNzViZjdmOTFkZSIsInZlcnNpb24iOiI4LjEwLjktZGV2In0AAAACAACBgASQAgEJ+AEAAAsAAAAAAAAAAQAAAAAAAAABAAAACgAAAHAAAAACAAAABAAAAJgAAAADAAAAAgAAAKgAAAAFAAAAAwAAAMAAAAAGAAAAAQAAANgAAAABIAAAAgAAAPgAAAADIAAAAgAAACgBAAACIAAACgAAADABAAAAIAAAAQAAAEACAAAAEAAAAQAAAFACAAA="

DEXDIR="$ROOT/_dexes"; rm -rf "$DEXDIR"; mkdir -p "$DEXDIR"
for d in $(unzip -l "$APK" | awk '/classes[0-9]*\.dex/{print $4}'); do unzip -p "$APK" "$d" > "$DEXDIR/$d" 2>/dev/null; done

set +e
OUT="$(node - "$HTTP" "$DEXDIR" "$PROBE_B64" <<'EOF'
import fs from 'node:fs';
const [http, dexDir, probeB64]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const POST=(p,b)=>fetch(`${base}${p}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());

const p=await POST('/api/dex/method_code',{b64:probeB64,class:'Probe'});
console.log(`probe: count=${p.count} recovered=${p.recovered} empty=${p.empty}`);
(p.methods||[]).forEach(m=>console.log(`  ${m.method} regs=${m.registers} insnsSize=${m.insnsSize} hex=${m.insnsHex}`));
const hello=(p.methods||[]).find(m=>/->hello$/.test(m.method));
const probePass = p.empty===0 && hello && hello.insnsSize===3 && /^1a/.test(hello.insnsHex) && /1100$/.test(hello.insnsHex);

// app dex: JavaCrypto.run has non-empty code
let appHit=false;
for(const f of fs.readdirSync(dexDir).filter(x=>x.endsWith('.dex'))){
  const b64=fs.readFileSync(`${dexDir}/${f}`).toString('base64');
  const r=await POST('/api/dex/method_code',{b64,class:'com/adh/sandbox/JavaCrypto',method:'run'});
  const run=(r.methods||[]).find(m=>/->run$/.test(m.method));
  if(run && run.insnsSize>0){ appHit=true; console.log(`  app JavaCrypto.run insnsSize=${run.insnsSize} regs=${run.registers}`); }
}
const pass = probePass && appHit;
console.log(`probe hello ok=${!!probePass} app JavaCrypto.run recovered=${appHit}`);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -rf "$DEXDIR"
verify_gate "v0.9 method body recovery (probe hello bytecode + app JavaCrypto.run)" 0 && exit 0 || exit 1
