#!/usr/bin/env bash
# v0.8 dex search index (HOST-ONLY). Searches the probe dex and the app's dex for
# strings/classes/methods and asserts known hits. Exit 0 = PASS. Prereq: adhd + APK.
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

// probe dex: search class/method/string
const s1=await POST('/api/dex/search',{b64:probeB64,query:'Probe',kinds:['class']});
const s2=await POST('/api/dex/search',{b64:probeB64,query:'hello',kinds:['method']});
const s3=await POST('/api/dex/search',{b64:probeB64,query:'IDH_PROBE_OK',kinds:['string']}); // hash-bound legacy probe marker
console.log(`probe: class(Probe)=${s1.counts.classes} method(hello)=${s2.counts.methods} string=${s3.counts.strings}`);
const probePass = (s1.classes||[]).some(c=>/Probe/.test(c)) && (s2.methods||[]).some(m=>m.name==='hello') && (s3.strings||[]).includes('IDH_PROBE_OK');

// app dex (multidex): search for our own class + a crypto algorithm string
let foundClass=false, foundAlgo=false;
for(const f of fs.readdirSync(dexDir).filter(x=>x.endsWith('.dex'))){
  const b64=fs.readFileSync(`${dexDir}/${f}`).toString('base64');
  const r=await POST('/api/dex/search',{b64,query:'JavaCrypto',kinds:['class']});
  if((r.classes||[]).some(c=>/JavaCrypto/.test(c))) foundClass=true;
  const a=await POST('/api/dex/search',{b64,query:'AES/CBC/PKCS5Padding',kinds:['string']});
  if((a.strings||[]).includes('AES/CBC/PKCS5Padding')) foundAlgo=true;
}
console.log(`app: JavaCrypto class=${foundClass} "AES/CBC/PKCS5Padding" string=${foundAlgo}`);
const pass = probePass && foundClass && foundAlgo;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -rf "$DEXDIR"
verify_gate "v0.8 dex search (class/method/string hits in probe + app dex)" 0 && exit 0 || exit 1
