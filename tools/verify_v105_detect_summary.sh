#!/usr/bin/env bash
# v10.5 detection checklist (HOST-ONLY).
#
# The system GOT hooks record ptrace / access / faccessat / property reads. The host turns those
# lines into the module V checklist. This script runs that classifier, the app-library selector,
# and the confirm gate on the Java plan. It does not need a device or a daemon.
#
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

cd "$ROOT/daemon"
if ! verify_unit_pass "detection checklist" detect_summary.test.ts 12; then
  echo "RESULT:FAIL (detect_summary unit tests did not all pass)"
  exit 1
fi
echo "RESULT:PASS"
exit 0
