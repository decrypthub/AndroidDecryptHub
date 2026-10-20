#!/usr/bin/env bash
# Daily / CI host-only gate. Same scripts as verify_all.sh marked :host — no device, no sandbox.
# Full device gate: tools/verify_all.sh (or ADH_VERIFY_MODE=full).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ADH_VERIFY_MODE=host
exec bash tools/verify_all.sh
