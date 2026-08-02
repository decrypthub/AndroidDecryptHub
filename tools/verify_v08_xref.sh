#!/usr/bin/env bash
# v0.8 dex invoke-xref (HOST-ONLY). Parses dex bytecode into a call-graph and finds
# callers of a method. Verifies: probe dex Probe.<init> calls Object.<init>; app dex
# JavaCrypto calls Cipher.doFinal. Also asserts low desync (width-table correctness).
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

// probe dex: Probe.<init> should call Object.<init>
const p=await POST('/api/dex/xref',{b64:probeB64,method:'Ljava/lang/Object;-><init>'});
console.log(`probe: methodsWithCode=${p.methodsWithCode} skipped=${p.skipped} matches=${p.matches}`);
const probeCallers=Object.values(p.callers||{}).flat();
console.log('  callers of Object.<init>:', probeCallers);
const probePass = p.skipped===0 && probeCallers.some(c=>/Lcom\/idh\/probe\/Probe;-><init>/.test(c));

// app dex: who calls Cipher.doFinal -> should include JavaCrypto
let appHit=false, totalCode=0, totalSkip=0;
for(const f of fs.readdirSync(dexDir).filter(x=>x.endsWith('.dex'))){
  const b64=fs.readFileSync(`${dexDir}/${f}`).toString('base64');
  const r=await POST('/api/dex/xref',{b64,method:'Ljavax/crypto/Cipher;->doFinal'});
  totalCode+=r.methodsWithCode||0; totalSkip+=r.skipped||0;
  const callers=Object.values(r.callers||{}).flat();
  if(callers.some(c=>/JavaCrypto/.test(c))) { appHit=true; console.log('  Cipher.doFinal called by (JavaCrypto):', callers.filter(c=>/JavaCrypto/.test(c))); }
}
const desyncRate = totalCode? totalSkip/totalCode : 1;
console.log(`app: methodsWithCode=${totalCode} skipped=${totalSkip} desyncRate=${(desyncRate*100).toFixed(2)}%`);
const pass = probePass && appHit && desyncRate < 0.02;   // width table must be near-perfect
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -rf "$DEXDIR"
verify_gate "v0.8 dex invoke-xref (call-graph + callers + low desync)" 0 && exit 0 || exit 1
