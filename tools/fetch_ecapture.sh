#!/usr/bin/env bash
# Fetch the official eCapture binary for ADH (optional, root + eBPF capture backend).
#
# Usage:
#   tools/fetch_ecapture.sh [version|latest] [--abi arm64]
#   tools/fetch_ecapture.sh --list [--abi arm64]
#   tools/fetch_ecapture.sh --print-url [version|latest] [--abi arm64]
#
# Defaults: version=latest (pinned default), abi=arm64, cache=$ROOT/agent/third_party/ecapture/<version>/<abi>/
# Official source: https://github.com/gojue/ecapture/releases — versions/digests are pinned in
# tools/ecapture_versions.json (digests come from the release's own checksum file).
# The binary is gitignored and never committed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
VERSION="${ADH_ECAPTURE_VERSION:-latest}"
ABI="${ADH_ECAPTURE_ABI:-arm64}"
CACHE_DIR="${ADH_ECAPTURE_DIR:-$ROOT/agent/third_party/ecapture}"
MANIFEST="${ADH_ECAPTURE_MANIFEST:-$ROOT/tools/ecapture_versions.json}"
MODE="fetch"; FORCE=0
usage() { sed -n '2,14p' "$0"; cat <<'EOF'

Env:
  ADH_ECAPTURE_VERSION   default version (latest = manifest default)
  ADH_ECAPTURE_ABI       default ABI (arm64)
  ADH_ECAPTURE_DIR       cache root (default agent/third_party/ecapture)
  ADH_ECAPTURE_MANIFEST  pinned-version manifest
  ECAPTURE_URL           override asset URL (requires ECAPTURE_SHA256)
  ECAPTURE_SHA256        expected sha256 when overriding the URL
EOF
}
die() { echo "!! $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE="list"; shift ;;
    --print-url) MODE="print"; shift ;;
    --force) FORCE=1; shift ;;
    --abi) ABI="${2:?--abi needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) die "unknown option: $1" ;;
    arm64|x86_64) ABI="$1"; shift ;;
    *) VERSION="$1"; shift ;;
  esac
done
[ "$ABI" = "arm64" ] || die "unsupported ABI: $ABI (eCapture Android builds: arm64)"
need node
need sha256sum
[ -f "$MANIFEST" ] || die "manifest missing: $MANIFEST"

meta() { # meta <mode> -> prints "version|asset|url|sha256|binary"
  node - "$MANIFEST" "$VERSION" "$ABI" "$1" <<'NODE'
const fs = require('fs');
const [file, version, abi, mode] = process.argv.slice(2);
const m = JSON.parse(fs.readFileSync(file, 'utf8'));
const v = version === 'latest' ? (m.default || Object.keys(m.versions || {}).sort().pop()) : version;
const e = m.versions && m.versions[v] && m.versions[v][abi];
if (mode === 'list') {
  for (const [ver, byAbi] of Object.entries(m.versions || {})) {
    const x = byAbi[abi];
    if (x) console.log(`${ver}${ver === m.default ? ' (default)' : ''}\t${x.asset}\t${x.url}`);
  }
  process.exit(0);
}
if (!e || !e.url || !e.sha256) process.exit(3);
process.stdout.write([v, e.asset, e.url, e.sha256, e.binary || 'ecapture'].join('|'));
NODE
}
if [ "$MODE" = "list" ]; then meta list; exit 0; fi

URL="${ECAPTURE_URL:-}"; SHA="${ECAPTURE_SHA256:-}"; TAG="$VERSION"; ASSET=""; BIN="ecapture"
if [ -n "$URL" ]; then
  [ -n "$SHA" ] || die "ECAPTURE_URL override requires ECAPTURE_SHA256"
  [ "$VERSION" = "latest" ] && TAG="custom"
  ASSET="$(basename "$URL")"
else
  LINE="$(meta fetch || true)"
  [ -n "$LINE" ] || die "version '$VERSION' is not pinned for $ABI in $MANIFEST (add it, or use ECAPTURE_URL+ECAPTURE_SHA256)"
  TAG="$(printf '%s' "$LINE" | cut -d'|' -f1)"
  ASSET="$(printf '%s' "$LINE" | cut -d'|' -f2)"
  URL="$(printf '%s' "$LINE" | cut -d'|' -f3)"
  SHA="$(printf '%s' "$LINE" | cut -d'|' -f4)"
  BIN="$(printf '%s' "$LINE" | cut -d'|' -f5)"
  SHA="${SHA#sha256:}"
fi
if [ "$MODE" = "print" ]; then printf '%s|%s|%s|sha256:%s\n' "$TAG" "$ASSET" "$URL" "$SHA"; exit 0; fi

OUTDIR="$CACHE_DIR/$TAG/$ABI"
OUT="$OUTDIR/$BIN"
META_OUT="$OUTDIR/manifest.json"
if [ -f "$OUT" ] && [ -f "$META_OUT" ] && [ "$FORCE" -ne 1 ]; then echo "$OUT"; exit 0; fi
mkdir -p "$OUTDIR"

TMP_ARCHIVE="$OUTDIR/$ASSET"
echo ">> downloading $ASSET" >&2
node - "$URL" "$TMP_ARCHIVE" <<'NODE'
(async () => {
  const fs = require('fs');
  const [url, out] = process.argv.slice(2);
  const res = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'ADH-ecapture-fetch' } });
  if (!res.ok) { console.error(`!! download failed: HTTP ${res.status}`); process.exit(1); }
  fs.writeFileSync(out, Buffer.from(await res.arrayBuffer()));
})().catch((e) => { console.error('!! download error: ' + e.message); process.exit(1); });
NODE
ACTUAL="$(sha256sum "$TMP_ARCHIVE" | awk '{print $1}')"
[ "$ACTUAL" = "$SHA" ] || die "sha256 mismatch for $ASSET: expected $SHA got $ACTUAL"
# Extract with the archive as a RELATIVE name (Git Bash's tar reads "X:/..." as a remote host).
case "$ASSET" in
  *.tar.gz|*.tgz) ( cd "$OUTDIR" && tar -xzf "$ASSET" ) ;;   # archive contains ./ecapture
  *.xz) ( cd "$OUTDIR" && xz -dc "$ASSET" > "$BIN" ) ;;
  *) cp "$TMP_ARCHIVE" "$OUT" ;;
esac
# eCapture tarballs extract as ./ecapture; normalise the layout.
if [ ! -f "$OUT" ]; then
  FOUND="$(find "$OUTDIR" -maxdepth 2 -type f -name "$BIN" | head -1)"
  [ -n "$FOUND" ] || die "archive did not contain $BIN"
  [ "$FOUND" = "$OUT" ] || mv "$FOUND" "$OUT"
fi
chmod 0755 "$OUT" 2>/dev/null || true
DECOMP="$(sha256sum "$OUT" | awk '{print $1}')"
node - "$META_OUT" "$TAG" "$ABI" "$ASSET" "$URL" "$SHA" "$DECOMP" "$OUT" <<'NODE'
const fs = require('fs');
const [file, version, abi, asset, url, sha256, binarySha256, path] = process.argv.slice(2);
fs.writeFileSync(file, JSON.stringify({ version, abi, asset, url, sha256, binarySha256, path, fetchedAt: new Date().toISOString() }, null, 2) + '\n');
NODE
rm -f "$TMP_ARCHIVE"
echo ">> eCapture $TAG/$ABI -> $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes, binary sha256 ${DECOMP:0:16}…)" >&2
echo "$OUT"