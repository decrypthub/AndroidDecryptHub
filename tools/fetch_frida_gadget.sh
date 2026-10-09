#!/usr/bin/env bash
# Fetch official Frida Gadget builds for ADH.
#
# Usage:
#   tools/fetch_frida_gadget.sh [version|latest] [--abi arm64|arm|x86_64|x86]
#   tools/fetch_frida_gadget.sh --list [--abi arm64] [--remote]
#   tools/fetch_frida_gadget.sh --print-url <version|latest> [--abi arm64]
#
# Defaults: version=latest, abi=arm64, cache=$ROOT/agent/third_party/frida/<version>/<abi>/
# Official source: https://github.com/frida/frida/releases
# Known versions are pinned in tools/frida_gadget_versions.json. Unknown versions
# are resolved through the GitHub Releases API (set GITHUB_TOKEN to raise limits).
# Downloaded gadgets are gitignored and never committed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
VERSION="${ADH_FRIDA_VERSION:-latest}"
ABI="${ADH_FRIDA_ABI:-arm64}"
CACHE_DIR="${ADH_FRIDA_DIR:-$ROOT/agent/third_party/frida}"
MANIFEST="${ADH_FRIDA_MANIFEST:-$ROOT/tools/frida_gadget_versions.json}"
API="https://api.github.com/repos/frida/frida/releases"
MODE="fetch"; REMOTE=0; FORCE=0; RELEASE_JSON=""
usage() { sed -n '2,15p' "$0"; cat <<'EOF'

Env:
  ADH_FRIDA_VERSION   default version (latest)
  ADH_FRIDA_ABI       default ABI (arm64)
  ADH_FRIDA_DIR       cache root (default agent/third_party/frida)
  ADH_FRIDA_MANIFEST  pinned-version manifest
  GITHUB_TOKEN        optional GitHub token for API requests
  FRIDA_GADGET_URL    override official asset URL (requires FRIDA_GADGET_SHA256)
  FRIDA_GADGET_SHA256 expected sha256 when digest is absent/overridden
EOF
}
die() { echo "!! $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE="list"; shift ;;
    --remote) REMOTE=1; shift ;;
    --print-url) MODE="print"; shift ;;
    --force) FORCE=1; shift ;;
    --abi) ABI="${2:?--abi needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --release-json) RELEASE_JSON="${2:?--release-json needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) die "unknown option: $1" ;;
    arm64|arm|x86_64|x86) ABI="$1"; shift ;;
    *) VERSION="$1"; shift ;;
  esac
done
case "$ABI" in arm64|arm|x86_64|x86) ;; *) die "unsupported ABI: $ABI" ;; esac
need node
need sha256sum
manifest_lookup() {
  [ -f "$MANIFEST" ] || return 1
  node - "$MANIFEST" "$VERSION" "$ABI" <<'NODE'
const fs=require('fs'); const [file,version,abi]=process.argv.slice(2);
const m=JSON.parse(fs.readFileSync(file,'utf8')); const v=version==='latest'?m.default:version;
const e=m.versions&&m.versions[v]&&m.versions[v][abi];
if(!e||!e.asset||!e.url||!e.sha256) process.exit(3);
process.stdout.write([v,e.asset,e.url,e.sha256].join('|')+'\n');
NODE
}
manifest_list() {
  [ -f "$MANIFEST" ] || return 1
  node - "$MANIFEST" "$ABI" <<'NODE'
const fs=require('fs'); const [file,abi]=process.argv.slice(2); const m=JSON.parse(fs.readFileSync(file,'utf8'));
for(const [v,byAbi] of Object.entries(m.versions||{})){ const e=byAbi&&byAbi[abi]; if(e&&e.asset&&e.url&&e.sha256) console.log([v,e.asset,e.url,e.sha256].join('|')); }
NODE
}
fetch_to_file() {
  local url="$1" out="$2" token="${GITHUB_TOKEN:-}"
  node - "$url" "$out" "$token" <<'NODE'
(async () => {
  const fs=require('fs'); const [url,out,token]=process.argv.slice(2);
  const headers={'User-Agent':'ADH-Frida-Gadget-Fetch','Accept':'application/vnd.github+json'};
  if(token) headers.Authorization=`Bearer ${token}`;
  const r=await fetch(url,{headers,redirect:'follow'});
  if(!r.ok){ console.error(`HTTP ${r.status} for ${url}`); process.exit(1); }
  const {Readable}=await import('node:stream'); const {pipeline}=await import('node:stream/promises');
  await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(out));
})();
NODE
}
api_parse_file() {
  node - "$1" "$2" "$3" "$4" <<'NODE'
const fs=require('fs'); const [file,mode,version,abi]=process.argv.slice(2); const json=JSON.parse(fs.readFileSync(file,'utf8'));
const abiToken={arm64:'android-arm64',arm:'android-arm',x86_64:'android-x86_64',x86:'android-x86'}[abi];
if(!abiToken) process.exit(2); const releases=Array.isArray(json)?json:[json]; const rows=[];
for(const rel of releases){ const tag=rel.tag_name||rel.name||version; const assetName=`frida-gadget-${tag}-${abiToken}.so.xz`;
  for(const a of (rel.assets||[])){
    if(mode==='list'&&a.name&&a.name.includes('frida-gadget-')&&a.name.endsWith(`-${abiToken}.so.xz`)) rows.push([tag,a.name,a.browser_download_url,(a.digest||'').replace(/^sha256:/,'')].join('|'));
    else if(mode!=='list'&&a.name===assetName) rows.push([tag,a.name,a.browser_download_url,(a.digest||'').replace(/^sha256:/,'')].join('|'));
  }
}
if(!rows.length){ console.error(mode==='list'?`no ${abiToken} frida-gadget assets found`:`asset not found: frida-gadget-${version}-${abiToken}.so.xz`); process.exit(3); }
process.stdout.write(rows.join('\n')+'\n');
NODE
}
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT; JSON="$TMP/release.json"
if [ "$MODE" = "list" ]; then
  if [ -n "$RELEASE_JSON" ] || [ "$REMOTE" -eq 1 ]; then
    if [ -n "$RELEASE_JSON" ]; then cp "$RELEASE_JSON" "$JSON"; else fetch_to_file "$API?per_page=20" "$JSON"; fi
    api_parse_file "$JSON" list "$VERSION" "$ABI"
  else
    manifest_list || die "manifest missing and --remote not requested: $MANIFEST"
  fi
  exit 0
fi
META=""
if [ -z "${FRIDA_GADGET_URL:-}" ]; then
  if [ -z "$RELEASE_JSON" ]; then META="$(manifest_lookup || true)"; fi
  if [ -z "$META" ]; then
    if [ -n "$RELEASE_JSON" ]; then cp "$RELEASE_JSON" "$JSON"; elif [ "$VERSION" = "latest" ]; then fetch_to_file "$API/latest" "$JSON"; else fetch_to_file "$API/tags/$VERSION" "$JSON"; fi
    META="$(api_parse_file "$JSON" "$MODE" "$VERSION" "$ABI")"
  fi
fi
if [ -n "${FRIDA_GADGET_URL:-}" ]; then
  URL="$FRIDA_GADGET_URL"; SHA="${FRIDA_GADGET_SHA256:-}"; [ -n "$SHA" ] || die "FRIDA_GADGET_URL override requires FRIDA_GADGET_SHA256"; TAG="$VERSION"; ASSET="$(basename "$URL")"
else
  TAG="${META%%|*}"; REST="${META#*|}"; ASSET="${REST%%|*}"; REST="${REST#*|}"; URL="${REST%%|*}"; SHA="${REST#*|}"
fi
SHA="${SHA#sha256:}"; [ -n "$URL" ] || die "empty download URL"; [ -n "$SHA" ] || die "missing sha256 for $ASSET"
if [ "$MODE" = "print" ]; then printf '%s|%s|%s|sha256:%s\n' "$TAG" "$ASSET" "$URL" "$SHA"; exit 0; fi
OUTDIR="$CACHE_DIR/$TAG/$ABI"; OUT="$OUTDIR/libfrida-gadget.so"; MANIFEST_OUT="$OUTDIR/manifest.json"
if [ -f "$OUT" ] && [ -f "$MANIFEST_OUT" ] && [ "$FORCE" -ne 1 ]; then echo "$OUT"; exit 0; fi
XZ="$TMP/$ASSET"; echo ">> downloading $ASSET" >&2; fetch_to_file "$URL" "$XZ"
ACTUAL="$(sha256sum "$XZ" | awk '{print $1}')"; [ "$ACTUAL" = "$SHA" ] || die "sha256 mismatch for $ASSET: expected $SHA got $ACTUAL"
mkdir -p "$OUTDIR"
if command -v xz >/dev/null 2>&1; then xz -dc "$XZ" > "$OUT"; elif command -v python3 >/dev/null 2>&1; then python3 -c 'import lzma,sys,shutil; shutil.copyfileobj(lzma.open(sys.argv[1],"rb"), open(sys.argv[2],"wb"))' "$XZ" "$OUT"; else die "need xz or python3"; fi
chmod 0644 "$OUT" 2>/dev/null || true; DECOMP="$(sha256sum "$OUT" | awk '{print $1}')"
node - "$MANIFEST_OUT" "$TAG" "$ABI" "$ASSET" "$URL" "$SHA" "$DECOMP" "$OUT" <<'NODE'
const fs=require('fs'); const [file,version,abi,asset,url,sha256,decompressed_sha256,path]=process.argv.slice(2);
fs.writeFileSync(file, JSON.stringify({version,abi,asset,url,sha256,decompressed_sha256,file:path,source:'official-frida-release'},null,2)+'\n');
NODE
echo "$OUT"
