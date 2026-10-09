#!/usr/bin/env bash
# Bundle a Frida hook so Frida Gadget 17+ can run it.
#
# As of Frida 17.0.0 the language bridges (Java.perform()/ObjC/Swift) are no longer
# bundled inside the Gadget runtime: a hook that uses them must be bundled together
# with the bridge package (https://frida.re/docs/gadget/ -> "Using the language bridges").
#
# Usage:
#   tools/compile_frida_script.sh <hook.js> [-o <out.bundle.js>]
#                                 [--bridge auto|java|none] [--minify] [--offline]
#
# Behavior:
#   * classic-style hooks (bare `Java.perform(...)`) get a shim that imports
#     frida-java-bridge and publishes it as the global `Java`
#   * hooks that already `import Java from 'frida-java-bridge'` are bundled as-is
#   * already-bundled input (carries the adh-frida-bundle tag) is copied through
#   * default output: <hook>.bundle.js next to the input
#
# The LAST line on stdout is the bundle path (machine-readable); progress goes to stderr.
# Deps live in tools/frida/node_modules (gitignored, installed on first use with
# --ignore-scripts: esbuild ships a prebuilt binary, and the native `frida` binding that
# frida-compile needs is deliberately NOT part of this toolchain).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
NPM_DIR="$ROOT/tools/frida"

usage() { sed -n '2,26p' "$0"; }
die() { echo "!! $*" >&2; exit 1; }

[ $# -ge 1 ] || { usage >&2; exit 1; }
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

INPUT="$1"; shift
OUT=""; BRIDGE="auto"; MINIFY=0; OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) OUT="${2:?--output needs a value}"; shift 2 ;;
    --bridge) BRIDGE="${2:?--bridge needs a value}"; shift 2 ;;
    --minify) MINIFY=1; shift ;;
    --offline) OFFLINE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -f "$INPUT" ] || die "script not found: $INPUT"
case "$BRIDGE" in auto|java|none) ;; *) die "--bridge must be auto|java|none (got $BRIDGE)" ;; esac
command -v node >/dev/null 2>&1 || die "node not found (needed to run the bundler)"

need_deps() {
  [ -f "$NPM_DIR/node_modules/esbuild/package.json" ] &&
  [ -f "$NPM_DIR/node_modules/frida-java-bridge/package.json" ] &&
  # ...and esbuild's binary must be the one for THIS host. node_modules lives in a shared tree, so a
  # cache installed on the other OS is present-but-unusable: esbuild refuses at bundle time with
  # "You installed esbuild for another platform", which surfaced as verify_v30 failing at bundling.
  # Treating that as "deps missing" makes both machines self-heal on first use, which is what this
  # install-on-demand contract already promised.
  [ -d "$NPM_DIR/node_modules/$(host_esbuild_pkg)" ]
}

# @esbuild/<os>-<arch> for the running host, e.g. @esbuild/linux-x64.
host_esbuild_pkg() {
  node -e 'const o={linux:"linux",darwin:"darwin",win32:"win32"}[process.platform]||process.platform;
const a={x64:"x64",arm64:"arm64",arm:"arm",ia32:"ia32"}[process.arch]||process.arch;
process.stdout.write(`@esbuild/${o}-${a}`)'
}
# esbuild's launcher must EXEC its platform binary. This tree is typically on a CIFS mount with
# nounix,file_mode=0664 — the server stores no Unix mode, so the client forces 0664 on every file and
# NOTHING on the share can ever be executable. `chmod +x` looks like it works and `ls` still shows
# -rw-rw-r--; esbuild then dies with EACCES on its own binary. So when the resolved binary is not
# executable, stage a copy on local disk and point esbuild at it (ESBUILD_BINARY_PATH is esbuild's
# supported override). Nothing is hidden: the reason is printed.
ensure_esbuild_runnable() {
  case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) return 0 ;; esac   # NTFS keeps the mode
  local pkg bin cache ver
  pkg="$(host_esbuild_pkg)"
  bin="$NPM_DIR/node_modules/$pkg/bin/esbuild"
  [ -f "$bin" ] || return 0
  [ -x "$bin" ] && return 0
  ver="$(node -e 'process.stdout.write(String(require(process.argv[1]).version))' "$NPM_DIR/node_modules/esbuild" 2>/dev/null || echo unknown)"
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/adh/esbuild-$ver-${pkg//\//-}"
  mkdir -p "$(dirname "$cache")" || die "cannot create cache dir for esbuild"
  if [ ! -x "$cache" ] || [ "$bin" -nt "$cache" ]; then
    cp -f "$bin" "$cache" && chmod +x "$cache" || die "cannot stage a runnable esbuild copy at $cache"
  fi
  export ESBUILD_BINARY_PATH="$cache"
  echo ">> $pkg/bin/esbuild is not executable on this filesystem (no exec bit on the share); staged a runnable copy at $cache" >&2
}

if ! need_deps; then
  if [ "$OFFLINE" = "1" ]; then
    die "bundler deps missing under tools/frida (offline): cd tools/frida && npm install --ignore-scripts"
  fi
  command -v npm >/dev/null 2>&1 || die "npm not found (needed once to install tools/frida deps)"
  echo ">> installing bundler deps (one-time, gitignored) in tools/frida" >&2
  ( cd "$NPM_DIR" && npm install --no-audit --no-fund --ignore-scripts --loglevel=error ) >&2 ||
    die "npm install failed in $NPM_DIR"
fi
ensure_esbuild_runnable

# node is a Windows binary under Git Bash: hand it Windows-style paths.
NODE_INPUT="$INPUT"; NODE_OUT="$OUT"
if command -v cygpath >/dev/null 2>&1; then
  NODE_INPUT="$(cygpath -w "$INPUT")"
  [ -n "$OUT" ] && NODE_OUT="$(cygpath -w "$OUT")"
fi

ARGS=(--input "$NODE_INPUT" --bridge "$BRIDGE")
if [ -n "$NODE_OUT" ]; then ARGS+=(--output "$NODE_OUT"); fi
if [ "$MINIFY" = "1" ]; then ARGS+=(--minify); fi

OUTPUT="$(node "$NPM_DIR/build.mjs" "${ARGS[@]}")" || die "bundling failed"
[ -n "$OUTPUT" ] || die "bundler returned an empty path"
[ -f "$OUTPUT" ] || die "bundler did not produce: $OUTPUT"
printf '%s\n' "$OUTPUT"