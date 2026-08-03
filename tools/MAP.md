# tools/ — MAP

Navigation index for the build + verify scripts. **Read this before adding a verify
script or touching `verify_all.sh`.**

## Shared libraries (source these, don't execute)

### `lib/verify_common.sh` — verify-script helpers
Dedups the boilerplate hand-copied across ~26 `verify_vXX_*.sh` scripts. Source it:
```bash
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
```
API:
| Function | Use |
|---|---|
| `verify_resolve_env` | Sets `ROOT`/`HTTP`/`SERIAL`/`BASE` (honors `IDH_HTTP_PORT`/`IDH_SERIAL`). For device scripts that gate on liveness OR set SERIAL. |
| `verify_resolve_env_host` | Sets `ROOT`/`HTTP`/`BASE` only (no SERIAL, no `adb` call). For host-only scripts. |
| `verify_sandbox_alive` | Sets `ALIVE` (sandbox pid or empty) + prints the alive line. Call before `verify_gate … 1`. |
| `verify_gate "<label>" <0\|1>` | Reads `$OUT` for `RESULT:PASS`. Returns 0 on pass; if arg2=1, also requires non-empty `$ALIVE`. Prints the ✅/❌ line. Uses here-string grep (SIGPIPE-safe — the `echo\|grep -q` pattern false-fails on >64KB payloads under `pipefail`). |
| `verify_grep_q <haystack> <pattern>` | SIGPIPE-safe `grep -q` for host scripts grepping large HTML. |
| `verify_host_begin` / `verify_chk "<label>" '<expr>'` / `verify_host_finish "<label>"` | The chk-accumulator idiom for host scripts with many assertions (replaces the inline `fail=0; chk(){…}` redefinition). |

**Contract preserved**: each verify script still exits 0 on PASS / 1 on FAIL, and the
node heredoc payload (the unique per-test code) stays byte-for-byte verbatim in the
script — the lib only factors the shell boilerplate around it.

### `lib/env.sh` — build-path env
SDK/NDK/CMake/Ninja/toolchain/READELF/ROOT/ABI resolution, sourced by `build_agent.sh`
and `build_detect.sh` (was inlined verbatim in both). Pure var assignment — does NOT
touch shell options; the caller's `set -e/-u/-o pipefail` stands. WSL builds use
`wsl_env.sh` instead (different SDK discovery + path translation — kept separate).

## Script shapes (three coexist by design)

1. **Device node-heredoc + ALIVE gate** — `verify_resolve_env` + `set +e; OUT="$(node …)"` + `verify_sandbox_alive` + `verify_gate "label" 1`. e.g. `verify_v04_crypto.sh`, `verify_v22_capture.sh`, `verify_v26_cryptocoverage.sh`.
2. **Device/host node-heredoc, no ALIVE** — `verify_resolve_env[_host]` + heredoc + `verify_gate "label" 0`. e.g. `verify_v18_loadso.sh`, `verify_v10_mcp.sh`, `verify_v08_*`.
3. **Host chk-accumulator** — `verify_resolve_env_host` + `verify_host_begin` + `verify_chk`×N + `verify_host_finish "label"`. e.g. `verify_v10_webui.sh`, `verify_v19_settings.sh`.

`verify_v01.sh` is the bootstrap outlier (full build+deploy+maps-verbatim chain, `process.exit(code)+exit $RC` idiom) — left hand-rolled, do not force into the common mold.
`verify_v02_so.sh` / `verify_v10_qbdi.sh` / `verify_v10_events.sh` have custom footers (readelf pipeline / 3-way SKIP gate / curl+`node -e`) — header-only conversion, custom gate kept verbatim.

## Adding a new verify script (recipe)

1. Copy `verify_v04_crypto.sh` as the closest template (device) or `verify_v10_webui.sh` (host-chk).
2. Source `lib/verify_common.sh`, call `verify_resolve_env` (device) or `verify_resolve_env_host` (host).
3. Write the unique test as a `node - "$HTTP" [args] <<'EOF' … EOF` heredoc that prints exactly one `RESULT:PASS` or `RESULT:FAIL` line (use `process.exit(0)` on the fail path so `set +e` isn't needed... but keep `set +e` before the `OUT=$(…)` capture anyway — node may throw).
4. `echo "$OUT"` for diagnostics, then `verify_gate "<descriptive label>" <0|1> && exit 0 || exit 1`.
5. `bash -n tools/verify_vXX.sh` (syntax), then run it standalone against a live idhd+device+sandbox to confirm green.
6. **Add it to `verify_all.sh`'s `SCRIPTS` array** as `"verify_vXX.sh:device"` or `:host"`, in version order. Without this it never runs in regression.

## `verify_all.sh` — the regression runner

- Runs `dev_up.sh` first, then each script in `SCRIPTS` (sequential; `:device` scripts force-stop + relaunch `com.idh.sandbox/.MainActivity` + sleep 4 first).
- `:device` scripts SKIP (not FAIL) when no device attached.
- Exit 0 iff all RUN scripts pass. Prints `pass=N fail=N skip=N [failed:…]`.
- **`verify_v23_javahook.sh` is deliberately EXCLUDED** — LSPlant WS-A is blocked on this ROM (libart stripped). See the comment in the SCRIPTS array. Re-add only on a stock/AOSP device.

## Build scripts

- `build_agent.sh` — `libidh_agent.so` (arm64-v8a, NDK+SDK cmake), stages into `sandbox-app/…/jniLibs/$ABI`, prints `idh_agent_start`+`JNI_OnLoad` exports (fail-loud on compile error — do NOT hide build output).
- `build_detect.sh` — `libidhdetect.so` (sandbox's mock detection target), same cmake pattern.
- `fetch_qbdi.sh` / `fetch_lsplant.sh` — one-time third-party fetch (gitignored under `agent/third_party/`).
- `build_zygisk.sh` — Magisk Zygisk 模块 zip（依赖 `build_agent.sh`）→ `injector/zygisk/dist/adh-zygisk.zip`
- `dev_up.sh` — idempotent: start ADH Daemon (if down) + `adb reverse` for 8760/8761.
- `load_frida_gadget.sh` — manual real-injection helper (module W, deferred).

## Known flakes (pre-existing, not introduced by the lib refactor)

- **`verify_v08_disasm.sh` / `verify_v08_analyze.sh`** intermittently report `exports=0` on the memory-reconstructed `.so`. Root cause is in `daemon reconstructSo` (index.ts:686) — `readMem` breaks early on a short first chunk (line 663), which can truncate a PT_LOAD and drop the dynamic segment. Both pass on re-run. Tracked for the daemon `dump.ts` extraction (Phase 2).
