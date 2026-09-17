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
| `verify_resolve_env` | Sets `ROOT`/`HTTP`/`SERIAL`/`BASE` (`ADH_HTTP_PORT`/`ADH_SERIAL`). For device scripts that gate on liveness OR set SERIAL. |
| `verify_resolve_env_host` | Sets `ROOT`/`HTTP`/`BASE` only (no SERIAL, no `adb` call). For host-only scripts. |
| `verify_sandbox_alive` | Sets `ALIVE` (sandbox pid or empty) + prints the alive line. Call before `verify_gate … 1`. |
| `verify_gate "<label>" <0\|1>` | Reads `$OUT` for `RESULT:PASS`. Returns 0 on pass; if arg2=1, also requires non-empty `$ALIVE`. Prints the ✅/❌ line. Uses here-string grep (SIGPIPE-safe — the `echo\|grep -q` pattern false-fails on >64KB payloads under `pipefail`). |
| `verify_grep_q <haystack> <pattern>` | SIGPIPE-safe `grep -q` for host scripts grepping large HTML. |
| `verify_host_begin` / `verify_chk "<label>" '<expr>'` / `verify_host_finish "<label>"` | The chk-accumulator idiom for host scripts with many assertions (replaces the inline `fail=0; chk(){…}` redefinition). |
| `install_apk_root <apk> [remote] [serial]` | Root `push` + `pm install -r -t` (from `env.sh`). Never `adb install` — ColorOS waits on USB confirm. |

**Contract preserved**: each verify script still exits 0 on PASS / 1 on FAIL, and the
node heredoc payload (the unique per-test code) stays byte-for-byte verbatim in the
script — the lib only factors the shell boilerplate around it.

### `lib/env.sh` — build-path env
SDK/NDK/CMake/Ninja/toolchain/READELF/ROOT/ABI resolution, sourced by `build_agent.sh`
and `build_detect.sh` (was inlined verbatim in both). Pure var assignment — does NOT
touch shell options; the caller's `set -e/-u/-o pipefail` stands. Git Bash `pwd` is
`/x/Project/...`; `ROOT` is converted with `cygpath -m` so Windows `apksigner`/NDK
see `X:/...`. WSL builds use `wsl_env.sh` instead (different SDK discovery + path
translation — kept separate).

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
5. `bash -n tools/verify_vXX.sh` (syntax), then run it standalone against a live adhd+device+sandbox to confirm green.
6. **Add it to `verify_all.sh`'s `SCRIPTS` array** as `"verify_vXX.sh:device"` or `:host"`, in version order. Without this it never runs in regression.

## `verify_all.sh` — the regression runner

- Runs `dev_up.sh` first, then each script in `SCRIPTS` (sequential; `:device` scripts force-stop + relaunch `com.adh.sandbox/.MainActivity` + sleep 4 first).
- `:device` scripts SKIP (not FAIL) when no device attached.
- Exit 0 iff all RUN scripts pass. Prints `pass=N fail=N skip=N [failed:…]`.
- `verify_v26_footprint.sh` — host-only static guard: stripped agent `.so`, exactly three dynamic exports, no RWX `LOAD`; runs in `verify_all.sh` without a device.

## Build scripts

- `build_agent.sh` — `libadh_agent.so` (arm64-v8a, NDK+SDK cmake), stages into `sandbox-app/…/jniLibs/$ABI`, prints `adh_agent_set_package` + `adh_agent_start` + `JNI_OnLoad` exports (fail-loud on compile error — do NOT hide build output).
- `build_detect.sh` — `libadhdetect.so` (sandbox's mock detection target), same cmake pattern.
- `build_java_hook_bridge.sh` — regenerate the fixed `AdhJavaHookBridge` DEX + C array header from Java source (requires `javac` + Android `d8`; generated artifacts are committed).
- `fetch_qbdi.sh` / `fetch_dobby.sh` / `fetch_lsplant.sh` — one-time third-party fetch (gitignored under `agent/third_party/`). Dobby is the verified native inline backend; LSPlant v6.4 is the optional ART Java-method hook backend and is statically linked into the agent when present.
- `build_zygisk.sh` — 构建 Manager 证书固定的 Root Device Daemon + Zygisk 模块 → `injector/zygisk/dist/adh-zygisk.zip`
- `build_bundle.sh` — Magisk/KernelSU 可直接安装的版本化组合包（Zygisk + Device Daemon + Manager）→ `injector/zygisk/dist/adh-bundle-vX.Y.Z.zip`
- `flash_device.sh` — 把组合包推到当前手机并刷入（自动识别 KernelSU `ksud` / Magisk）。`--no-build` 跳过重建；`--reboot` 刷完重启让 Zygisk + Device Daemon 加载。多设备时必须设 `ANDROID_SERIAL`。
- Device surface: `cd device && ./gradlew :core:test :daemon:testDebugUnitTest :daemon:assembleDebug :manager:testDebugUnitTest :manager:assembleDebug`
- `dev_up.sh` — idempotent: start Host ADH Daemon (if down) + `adb reverse` for 8088/8761.
- `load_frida_gadget.sh` — manual Frida Gadget loader (module W **optional** backend, off by default): official Gadget (version/ABI selectable, sha256-pinned) → bundle the hook if it needs a language bridge → stage into `<pkg>/code_cache` (app uid + selinux ctx) → `POST /api/agent/load_so` dlopen (constructor-driven: **no entry symbol**) → wait for `frida-gadget` threads in `/proc/<pid>/task` → optional `--marker` end-to-end assert. `--watch` writes `on_change: reload` (edit the staged hook → hot reload).
- `compile_frida_script.sh` — bundle a hook with the Frida language bridges via esbuild (`tools/frida/`, gitignored deps). Needed because **Frida 17+ no longer ships Java/ObjC bridges inside the Gadget runtime**; `frida-compile` is NOT used (its CLI needs the native `frida` binding → MSVC on Windows).
- `verify_v30_fridagadget.sh` — v3.0 Gadget acceptance (device): official gadget → dlopen → bundled Java hook writes a marker; prints RESULT:SKIP when the gadget asset or bundler deps are missing (both are gitignored caches).
- `build_xposed.sh` — 构建可选 LSPosed/Xposed 薄模块（`injector/xposed/`）：把 `libadh_agent.so` 打进模块 APK（未压缩），产出 `injector/xposed/dist/adh-xposed.apk`。
- `install_xposed.sh` — root 安装 + 用 `/data/adb/lspd/cli`（LSPosed/Vector）启用模块并设 scope；`--disable` 先逐条 `scope rm` 再关模块（空参数 `scope set` 会 NPE）。
- `verify_v31_xposed.sh` — v3.1 可选 Xposed 后端验收（device）：框架 → 薄模块 → 框架注入 `com.adh.manager` → agent 上线并被 Host 驱动；结束恢复测试前状态；无框架/构建不了时 SKIP。
- `verify_v32_backend_control.sh` — v3.2 可选后端**控制面**验收（device）：构建并推送 Device Daemon → 用它的 root-only 一次性 CLI 设/清框架 scope、开关模块，每步都与框架 CLI 交叉核对，最后恢复原状态；无框架/无模块时 SKIP。## Known flakes (pre-existing, not introduced by the lib refactor)
- `verify_v33_backends.sh` — v3.3 注入后端矩阵（host）：`GET /api/backends` 形状 + **缓存条目与磁盘逐字节一致** + 控制台「注入后端」页标记 + 内联脚本 `node --check`；无设备依赖。
- `fetch_ecapture.sh` — 官方 eCapture 发布包（`tools/ecapture_versions.json` 固定版本 + 官方 checksum 里的 sha256），缓存到 gitignore 的 `agent/third_party/ecapture/<ver>/<abi>/`。
- `ecapture_capture.sh` — 可选 eCapture 运行器（root + eBPF）：`--preflight-only` 打印 root/内核/BPF/BTF 能力并给出 supported/unsupported 判定；运行后按输出里的 `probe started successfully` 给结论，失败时打印首条错误；产出落到 `captures/ecapture/`。
- `verify_v34_ecapture.sh` — v3.4 eCapture 验收（device）：官方二进制 → 预检 → 对 sandbox 起 TLS probe → 用 MCP `net_capture` 驱动一次真实 HTTPS → 断言 eCapture 抓到 `ADH_NET_MARKER_v1`/`ADH_NET_RESPONSE_v1`；内核不支持时 SKIP。- **`verify_v08_disasm.sh` / `verify_v08_analyze.sh`** intermittently report `exports=0` on the memory-reconstructed `.so`. Root cause is in `daemon reconstructSo` (index.ts:686) — `readMem` breaks early on a short first chunk (line 663), which can truncate a PT_LOAD and drop the dynamic segment. Both pass on re-run. Tracked for the daemon `dump.ts` extraction (Phase 2).
- `verify_v35_sessions.sh` — v3.5 会话清理（host）：`pruneSessions` 单测（保留上限 / 过期丢弃 / 不动在线会话）+ 会话选择器标记与下拉配色 + daemon 可达时校验实际离线会话上限。
- `verify_v42_lsplant.sh` — LSPlant probe + `java_hook status`（deploy new agent；旧 payload 明确 SKIP）。
- `verify_v43_javahook.sh` — 沙盒确定性 `HookProbe.ping` install → broadcast 触发 → 原返回值 → `JAVA_HOOK` capture 事件 → `unhook` 验收（deploy new sandbox/agent；未部署时 SKIP）。
- `verify_v44_java_enum.sh` — 沙盒 `HookProbe` 类/字段/两个 `ping` 重载枚举验收（deploy new agent/sandbox；未部署时 SKIP）。
- `verify_v45_java_call.sh` — 沙盒 `HookProbe.ping` 两个重载的反射主动调用与返回值验收（deploy new agent/sandbox；未部署时 SKIP）。
