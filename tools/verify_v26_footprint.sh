#!/usr/bin/env bash
# v2.6 WS-J static injection-footprint guard. Host-only, no device needed:
#   - shipped libadh_agent.so is stripped (no .symtab/.debug_*)
#   - .dynsym exposes exactly JNI_OnLoad + adh_agent_set_package + adh_agent_start
#   - the ELF itself has no RWX LOAD segment
# This does not hide anything; it prevents the release build from regressing into
# a symbol-heavy or RWX artifact. Anonymous exec pages created by Dobby/QBDI are
# measured separately by compat_probe on the device.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
verify_host_begin

SO="$ROOT/agent/build/libadh_agent.so"
if [ ! -f "$SO" ]; then
  echo "FAIL  agent .so missing: $SO (run tools/build_agent.sh)"
  exit 1
fi

SECTIONS="$("$READELF" -SW "$SO")"
DYNSYM="$("$READELF" --dyn-syms --wide "$SO")"
PROGRAM="$("$READELF" -l "$SO")"
DEFINED="$(awk '$1 ~ /^[0-9]+:$/ && $7 != "UND" {print $8}' <<<"$DYNSYM" | sort -u | tr '\n' ' ')"
EXPECTED="JNI_OnLoad adh_agent_set_package adh_agent_start "
BYTES="$(wc -c < "$SO" | tr -d '[:space:]')"
DEBUG_SO="$ROOT/agent/build/libadh_agent.so.debug"

echo "agent=${BYTES}B defined-exports=${DEFINED:-none}"
verify_chk "release .so has no .symtab/.debug sections" '! grep -qE "\\.(symtab|debug_)" <<<"$SECTIONS"'
verify_chk "release .dynsym defined set is exactly the three bootstrap entries" '[ "$DEFINED" = "$EXPECTED" ]'
verify_chk "release ELF has no RWX LOAD segment" '! grep -qE "LOAD.*(RWE|RWX)" <<<"$PROGRAM"'
verify_chk "release .so is smaller than the local debug copy" '[ -f "$DEBUG_SO" ] && [ "$BYTES" -lt "$(wc -c < "$DEBUG_SO" | tr -d "[:space:]")" ]'
verify_host_finish "v2.6 WS-J static injection footprint (strip + 3-entry whitelist + no RWX)"
