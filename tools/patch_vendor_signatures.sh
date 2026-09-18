#!/usr/bin/env bash
# Rewrite the identifying strings inside the FETCHED third-party sources.
#
# Why: the agent links LSPlant (and Dobby) statically, so THEIR strings are in our shipped .rodata -
# and the LSPlant one even reaches the target in a place that matters more than a log line: the
# generated dex carries "lsplant" as its source name, which a detector can read straight out of ART.
# The vendored trees are gitignored and recreated by tools/fetch_*.sh, so the rewrite has to live in
# the fetch path - editing the checkout by hand would be undone by the next fetch.
#
# Idempotent: run it as often as you like. `--check` exits non-zero when a string is still there, so
# the acceptance script can assert the fetch step really did its job.
#
# Usage: bash tools/patch_vendor_signatures.sh [--check]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="${ADH_THIRDPARTY_DIR:-$ROOT/agent/third_party}"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

LSP="$TP/lsplant/lsplant/src/main/jni"
[ -d "$LSP" ] || { echo ">> LSPlant sources absent (run tools/fetch_lsplant.sh) - nothing to patch"; exit 0; }

patch_one() {  # patch_one <file> <old> <new> <label>
  local file="$1" old="$2" new="$3" label="$4"
  [ -f "$file" ] || { echo "!! missing $file"; exit 1; }
  if grep -qF "$old" "$file"; then
    if [ "$CHECK" = "1" ]; then echo "!! $label still present in $file"; exit 1; fi
    OLD="$old" NEW="$new" perl -0777 -pi -e 's/\Q$ENV{OLD}\E/$ENV{NEW}/g' "$file"
    echo ">> $label -> $new"
  else
    echo ">> $label already clean"
  fi
}

# 1) the ART suspend reason (shows up in the artifact as "LSPlant Hook" x2)
patch_one "$LSP/lsplant.cc" '"LSPlant Hook"' '"art hook"' 'suspend reason'
# 2) LSPlant own log tag
patch_one "$LSP/logging.hpp" '#define LOG_TAG "LSPlant"' '#define LOG_TAG "rt.java"' 'log tag'
# 3) THE IMPORTANT ONE: the source name of the hook stub dex LSPlant generates at runtime. A target
#    can enumerate loaded dex files, so the tool name must not sit in there.
patch_one "$LSP/lsplant.cc" 'generated_source_name.empty() ? "lsplant" :' 'generated_source_name.empty() ? "generated" :' 'generated dex source name'

echo ">> vendor signature patch done"
