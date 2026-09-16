#!/usr/bin/env bash
# v0.4 dex parse + crypto static scan (HOST-ONLY — no device needed).
#   1) parse the 728B probe dex (b64) -> finds type Lcom/idh/probe/Probe;, method hello, string IDH_PROBE_OK
#      (hash-bound legacy probe fixture; do not rename without regenerating the fixed dex hash)
#   2) crypto_scan the app's classes.dex -> finds javax/crypto method refs + algorithm strings
#      (AES/CBC/PKCS5Padding, HmacSHA256) proving the static crypto channel works
# Exit 0 = PASS. Prereq: adhd running; sandbox APK built.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "❌ APK missing"; echo "RESULT:FAIL"; exit 1; }
PROBE_B64="ZGV4CjAzOAAldROcj4AnW/EXyPvKv8zYfcWhEh6enuXYAgAAcAAAAHhWNBIAAAAAAAAAAFACAAAKAAAAcAAAAAQAAACYAAAAAgAAAKgAAAAAAAAAAAAAAAMAAADAAAAAAQAAANgAAADgAQAA+AAAADABAAA4AQAARgEAAEkBAABgAQAAdAEAAIgBAACUAQAAlwEAAJ4BAAADAAAABAAAAAUAAAAHAAAAAgAAAAIAAAAAAAAABwAAAAMAAAAAAAAAAAABAAAAAAAAAAAACAAAAAEAAQAAAAAAAAAAAAEAAAABAAAAAAAAAAYAAAAAAAAAQAIAAAAAAAABAAAAAAAAACgBAAADAAAAGgABABEAAAABAAEAAQAAACwBAAAEAAAAcBACAAAADgADAA4AAgAOAAY8aW5pdD4ADElESF9QUk9CRV9PSwABTAAVTGNvbS9pZGgvcHJvYmUvUHJvYmU7ABJMamF2YS9sYW5nL09iamVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwAKUHJvYmUuamF2YQABVgAFaGVsbG8AnwF+fkQ4eyJiYWNrZW5kIjoiZGV4IiwiY29tcGlsYXRpb24tbW9kZSI6InJlbGVhc2UiLCJoYXMtY2hlY2tzdW1zIjpmYWxzZSwibWluLWFwaSI6MjYsInNoYS0xIjoiYTdhZDE4YTcwNDYwYjc5OWQwNDgyZTQ5N2MxMDlhNzViZjdmOTFkZSIsInZlcnNpb24iOiI4LjEwLjktZGV2In0AAAACAACBgASQAgEJ+AEAAAsAAAAAAAAAAQAAAAAAAAABAAAACgAAAHAAAAACAAAABAAAAJgAAAADAAAAAgAAAKgAAAAFAAAAAwAAAMAAAAAGAAAAAQAAANgAAAABIAAAAgAAAPgAAAADIAAAAgAAACgBAAACIAAACgAAADABAAAAIAAAAQAAAEACAAAAEAAAAQAAAFACAAA="

# extract ALL dex (multidex): classes.dex, classes2.dex, ...
DEXDIR="$ROOT/_dexes"; rm -rf "$DEXDIR"; mkdir -p "$DEXDIR"
for d in $(unzip -l "$APK" | awk '/classes[0-9]*\.dex/{print $4}'); do
  unzip -p "$APK" "$d" > "$DEXDIR/$d" 2>/dev/null
done
ls "$DEXDIR"/*.dex >/dev/null 2>&1 || { echo "❌ extract dex failed"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$DEXDIR" "$PROBE_B64" <<'EOF'
import fs from 'node:fs';
const [http, dexDir, probeB64] = process.argv.slice(2);
const base=`http://127.0.0.1:${http}`;
const POST=(path,body)=>fetch(`${base}${path}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json());

// 1) parse probe dex
const p=await POST('/api/dex/parse',{b64:probeB64, full:true});
console.log(`probe: magic=${p.magic} classes=${p.counts.classes} methods=${p.counts.methods} strings=${p.counts.strings}`);
const hasProbeType = (p.classes||[]).includes('Lcom/idh/probe/Probe;');
const hasHello = (p.methods||[]).some(m=>m.name==='hello' && m.cls==='Lcom/idh/probe/Probe;');
const hasStr = (p.strings||[]).includes('IDH_PROBE_OK');
console.log(`  Probe type=${hasProbeType} hello()=${hasHello} "IDH_PROBE_OK"=${hasStr}`);
const parsePass = p.magic.startsWith('dex\n') && hasProbeType && hasHello && hasStr;

// 2) crypto scan ALL app dexes (multidex) and aggregate
const files=fs.readdirSync(dexDir).filter(f=>f.endsWith('.dex'));
const apiSet=new Set(); const algoSet=new Set(); let totalClasses=0, totalApis=0;
for(const f of files){
  const appDex=fs.readFileSync(`${dexDir}/${f}`).toString('base64');
  const c=await POST('/api/dex/crypto_scan',{b64:appDex});
  if(c.error){console.log(`  ${f}: ${c.error}`);continue;}
  totalClasses+=c.counts.classes; totalApis+=c.cryptoApis.length;
  c.cryptoApis.forEach(m=>apiSet.add(m.cls+'->'+m.name));
  c.algoStrings.forEach(s=>algoSet.add(s));
}
const c={cryptoApis:[...apiSet],algoStrings:[...algoSet]};
console.log(`app crypto (${files.length} dex): classes=${totalClasses} cryptoApiRefs=${totalApis} algoStrings=${algoSet.size}`);
const hasCipherDoFinal = [...apiSet].some(x=>/Cipher;->doFinal/.test(x));
const hasMac = [...apiSet].some(x=>/Mac;->(doFinal|init|getInstance)/.test(x));
const hasAes = c.algoStrings.includes('AES/CBC/PKCS5Padding');
const hasHmac = c.algoStrings.includes('HmacSHA256');
console.log(`  Cipher.doFinal=${hasCipherDoFinal} Mac=${hasMac} "AES/CBC/PKCS5Padding"=${hasAes} "HmacSHA256"=${hasHmac}`);
const cryptoPass = hasCipherDoFinal && hasMac && hasAes && hasHmac;

const pass = parsePass && cryptoPass;
console.log(pass?'✅ v0.4 dex-parse + crypto static scan PASS':'❌ v0.4 FAIL');
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -rf "$DEXDIR"
verify_gate "v0.4 dex-parse + crypto static scan" 0 && exit 0 || exit 1
