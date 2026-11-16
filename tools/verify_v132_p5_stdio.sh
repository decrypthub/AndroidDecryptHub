#!/usr/bin/env bash
# Host-only regression. Real Android acceptance is the separate explicit-serial TypeScript tool.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f device/daemon/build/device-rpc-fixture-classpath.json ]; then
  echo 'RESULT:SKIP offline Kotlin classpath unavailable; no device fallback'
  exit 0
fi
(cd daemon && node test/run.mjs test/device_stdio.test.ts)
echo 'RESULT:PASS P5 USB stdio protocol/auth/large frames/unsupported'
