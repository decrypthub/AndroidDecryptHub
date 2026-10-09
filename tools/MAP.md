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
| `verify_restart_sandbox` | Force-stops and relaunches the sandbox, then waits for startup. Use before scans of mutable syscall/native code sites or broad JNI hook probes so earlier checks cannot leave live patches behind. |
| `verify_gate "<label>" <0\|1>` | Reads `$OUT` for `RESULT:PASS`. Returns 0 on pass; if arg2=1, also requires non-empty `$ALIVE`. Prints the ✅/❌ line. Uses here-string grep (SIGPIPE-safe — the `echo\|grep -q` pattern false-fails on >64KB payloads under `pipefail`). |
| `verify_grep_q <haystack> <pattern>` | SIGPIPE-safe `grep -q` for host scripts grepping large HTML. |
| `verify_unit_pass "<label>" <test-file> [min_pass]` | Runs `node --test test/<test-file>` from `daemon/`; returns 0 only if the run exits clean **and** its summary reports zero failures, **and** the passing count meets `min_pass`. Use this for every script that gates on `node --test` — it parses **both** reporters node emits (`ℹ fail 0` spec / `# fail 0` TAP) and strips ANSI. Don't hand-roll the grep: the old `grep -qE '^ℹ fail 0$'` pattern was copied into three scripts and **could never match**, because capturing output with `UNIT="$(…)"` is a pipe, i.e. always TAP. `min_pass` also closes the silent-vacuous-pass hole (a test file that stops loading still exits 0). |
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

## Script shapes (four coexist by design)

1. **Device node-heredoc + ALIVE gate** — `verify_resolve_env` + `set +e; OUT="$(node …)"` + `verify_sandbox_alive` + `verify_gate "label" 1`. e.g. `verify_v04_crypto.sh`, `verify_v22_capture.sh`, `verify_v26_cryptocoverage.sh`.
2. **Device/host node-heredoc, no ALIVE** — `verify_resolve_env[_host]` + heredoc + `verify_gate "label" 0`. e.g. `verify_v18_loadso.sh`, `verify_v10_mcp.sh`, `verify_v08_*`.
3. **Host chk-accumulator** — `verify_resolve_env_host` + `verify_host_begin` + `verify_chk`×N + `verify_host_finish "label"`. e.g. `verify_v10_webui.sh`, `verify_v19_settings.sh`.
4. **`node --test` unit gate** — `verify_unit_pass "<label>" <test-file> <min_pass>`, usually as step 1 before the capability half. e.g. `verify_v101_crypto_variants.sh`, `verify_v99_artifact_store.sh`, `verify_v15_dumpall.sh`. **Always use the helper** — see the `verify_unit_pass` row above for why a hand-rolled grep here is a trap. If the check lives inside a JS heredoc instead (like `verify_v100_adh_cli.sh`), mirror the helper's logic: accept `#`/`ℹ`, strip ANSI, require `rc===0`, and floor the passing count.

`verify_v01.sh` is the bootstrap outlier (full build+deploy+maps-verbatim chain, `process.exit(code)+exit $RC` idiom) — left hand-rolled, do not force into the common mold.
`verify_v02_so.sh` / `verify_v10_qbdi.sh` / `verify_v10_events.sh` have custom footers (readelf pipeline / 3-way SKIP gate / curl+`node -e`) — header-only conversion, custom gate kept verbatim.

## Adding a new verify script (recipe)

1. Copy `verify_v04_crypto.sh` as the closest template (device) or `verify_v10_webui.sh` (host-chk).
2. Source `lib/verify_common.sh`, call `verify_resolve_env` (device) or `verify_resolve_env_host` (host).
3. Write the unique test as a `node - "$HTTP" [args] <<'EOF' … EOF` heredoc that prints exactly one `RESULT:PASS` or `RESULT:FAIL` line (use `process.exit(0)` on the fail path so `set +e` isn't needed... but keep `set +e` before the `OUT=$(…)` capture anyway — node may throw).
   If the subject has pure unit tests, gate them **first** with `verify_unit_pass` (shape 4) and `exit 1` on failure — a script that prints `RESULT:FAIL` for its unit gate and then keeps going will have that failure overwritten by the later `RESULT:PASS`. (`verify_v99` and `verify_v15_dumpall` both shipped that bug; both are fixed.)
4. `echo "$OUT"` for diagnostics, then `verify_gate "<descriptive label>" <0|1> && exit 0 || exit 1`.
   **Missing preconditions are SKIPs, not passes**: print `SKIP <script> (<reason>)` and `exit 0`
   *without* the `RESULT:PASS` sentinel (and return before `verify_gate`). `verify_all.sh` counts a
   script that exits 0 with a top-level `SKIP` line as a skip, so a capability that never ran is
   never reported as an acceptance (`verify_v75_zygisk_memfd.sh` is the reference).
5. `bash -n tools/verify_vXX.sh` (syntax), then run it standalone against a live adhd+device+sandbox to confirm green.
6. **Add it to `verify_all.sh`'s `SCRIPTS` array** as `"verify_vXX.sh:device"` or `:host"`, in version order. Without this it never runs in regression.
7. **Resolving the target agent: use the CLI, do not hand-roll it.** The block
   ```bash
   SID="$(cd "$ROOT/daemon" && node src/cli.ts target --package com.adh.sandbox --quiet)" || exit 0   # exit 3 = no agent
   ```
   is the same one `adh target` uses (one implementation, `daemon/src/cli.ts`); the older pattern —
   fetch `/api/agents`, filter by package, sort by `connectedAt`, take `[0]` — had been copied into 76
   scripts. `--quiet` prints the session id alone; `--json` gives the whole dossier; exit 3 means
   "no agent online" (the gate's SKIP), 1 means "that package is not there". Prefer `--package` over
   picking the newest session: a test that resolves a different process than it names is worse than
   one that fails.

## `verify_all.sh` — the regression runner

- Runs `dev_up.sh` first, then each script in `SCRIPTS` (sequential; `:device` scripts force-stop + relaunch `com.adh.sandbox/.MainActivity` + sleep 4 first).
- `:device` scripts SKIP (not FAIL) when no device attached; a script that exits 0 after a top-level
  `SKIP ...` line is counted (and printed) as a skip, not a pass — the sentinel is `RESULT:PASS`.
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
- `verify_v34_ecapture.sh` — v3.4 eCapture 验收（device）：官方二进制 → 预检 → 对 sandbox 起 TLS probe → 用 MCP `capture_start` + `java_call` 驱动一次真实 HTTPS → 断言 eCapture 抓到 `ADH_NET_MARKER_v1`/`ADH_NET_RESPONSE_v1`；内核不支持时 SKIP。**2026-10-01 起不在 `verify_all.sh` 门禁内**（eCapture 降级为实验脚本），手动跑仍然可用。- **`verify_v08_disasm.sh` / `verify_v08_analyze.sh`** intermittently report `exports=0` on the memory-reconstructed `.so`. Root cause is in `daemon reconstructSo` (index.ts:686) — `readMem` breaks early on a short first chunk (line 663), which can truncate a PT_LOAD and drop the dynamic segment. Both pass on re-run. Tracked for the daemon `dump.ts` extraction (Phase 2).
- `verify_v35_sessions.sh` — v3.5 会话清理（host）：`pruneSessions` 单测（保留上限 / 过期丢弃 / 不动在线会话）+ 会话选择器标记与下拉配色 + daemon 可达时校验实际离线会话上限。
- `verify_v42_lsplant.sh` — LSPlant probe + `java_hook status`（deploy new agent；旧 payload 明确 SKIP）。
- `verify_v43_javahook.sh` — 沙盒确定性静态 `HookProbe.ping` + 实例 `instancePing`（`INSTANCE` receiver）install → broadcast 触发 → 原返回值 → `JAVA_HOOK` capture 事件 → `unhook` 验收（deploy new sandbox/agent；未部署时 SKIP）。
- `verify_v44_java_enum.sh` — 沙盒 `HookProbe` 类/字段/两个 `ping` 重载枚举验收（deploy new agent/sandbox；未部署时 SKIP）。
- `verify_v45_java_call.sh` — 沙盒 `HookProbe.ping` 两个重载的反射主动调用与返回值验收（deploy new agent/sandbox；未部署时 SKIP）。
- `verify_v46_native_hook.sh` — 沙盒 `libadhdetect.so:adh_trace_target` inline hook → JNI 触发 → 真实 hookId 的寄存器 capture 事件 → unhook 验收（deploy new agent/sandbox；未部署时 SKIP）。
- `verify_v68_native_fp_args.sh` — native **FP/SIMD 参数与 FP 返回**：`native_call f:2.5,d:4,1` → `fpResult 0x4026000000000000` / `fpResultDouble 11`（double 返回）、`adh_fp_target_f` → `fpResultFloat 11` / 低位 `0x41300000`（float 返回）、`adh_fp_order_fd` 与 `adh_fp_order_df` 两种类型顺序都 → `0x4072300000000000 / 291`（钉住"第一个 FP 参数进第一个 FP 寄存器"）、`adh_fp_mix` 的 `f:0.1` → `102.00000149011612`（钉住 `f:` 真按 float32 取整）、`adh_fp_nan` → `fpResultDouble:null`（非有限值不产出非法 JSON）、整数路径 `20,22 -> 84` 不回归；六条 fail-loud（未知类型 / 空参数 `1,,2` / 整数越界 / 浮点越界 / 第 9 个整型 / 第 9 个浮点）；同一函数 inline hook 的 `NATIVE_HOOK` 事件必须同时含 `"x0":"0x1"`（整数 bank）与 `"s0":"2.5"` / `"d1":"4"`（FP bank），且 soft unhook 后调用恢复 11 而**事件数不再增长**。
- `verify_v69_stealth_pool.sh` — **去特征 / 反注入痕迹**：重启沙盒取干净进程 → 目标自己的 `Detection.antiHookProbe` 审计基线（`anonExec=0`、序言完整、入口不外跳）→ 装 inline hook（stealth 关）→ 审计看得见（`anonExec=2`、`prologueDiffers`、`entryBranchesOutside`，trampoline 在匿名页）→ hard unhook 后序言/入口恢复 → 重开进程 + `stealth on` → 同一 hook 下 **`anonExec=0`**、trampoline 落在 `/memfd:jit-cache (deleted)`、hook 仍返回 84 → `stealth off` 还原 mmap GOT 槽。
- `verify_v70_site_hooks.sh` — **call-site hooking（入口零改写）**：重启沙盒取干净进程 → 装 `mode=sites`（断言 `siteCount>=1`、site 的 `now != orig`、thunk 页在 `/memfd:jit-cache`）→ 调 `Detection.siteProbe` 返回 84 且 `hits>=1`，同时目标自己的 `antiHookProbe` 仍报 `prologueDiffers=false / entryBranchesOutside=false` → hard unhook 后逐位读回调用点 == `orig`、status 清空、调用仍 84 → 重开进程再装一次成功（证明无 Dobby 式陈旧状态）。
- `verify_v71_mcp_registry.sh` — **MCP 注册表 host 自检**（<1s、不需设备）：直接 import `daemon/src/mcp.ts` 并逐个校验 name/description/inputSchema/handler，专门拦"描述里一个撇号把整个模块搞挂、而 `node --check` 看不出来"这类事故（本轮真的踩到过：daemon 起不来、所有静态检查全绿）。
- `verify_v72_site_hooks_cross.sh` — **跨模块 call-site hooking**：加载插件库（跨模块调用 adh_add_target）→ `scope=all` 断言 3 站点/2 模块（`b`+`bl`）、三个探针都 84 且 `hits>=3`、目标审计 `prologueDiffers/entryBranchesOutside=false`、`anonExec=0`、三张 thunk 页都在 `/memfd:jit-cache` → hard unhook 后逐位读回 == `orig` 且三页全部 munmap → `scope=<plugin>` 只选中该模块。
- `verify_v73_vtable_hook.sh` — **指针槽（vtable）hook**：`mode=vtable` 后断言 `slotCount>=1`、vtable 槽 `kind=data`、模块 PLT 槽 `kind=got`、**直接读函数地址的 24 字节安装前后逐位相同**、相邻槽未被改、`slotProbe()` 仍 84 且 `hits>=1`（间接调用被拦）、thunk 页在 `/memfd:jit-cache`、hard unhook 后 16 字节槽位区逐位还原 + 页 munmap；同时把"审计因 GOT 槽被换而报 prologueDiffers"这个副作用原样打印。
- `verify_v74_slot_object_callback.sh` — **对象虚调用 + 可写函数指针**：对象侧断言只改对象表那一个槽（`kind=data`/`r--`/`orig`==函数地址）、**只调对象探针**时 `hits>=1`、函数 24 字节前后逐位相同、unhook 后槽位读回 == 原值且 thunk 页消失；可写侧断言默认 **fail-loud**（"writable slots were skipped"）、`slotsWritable:true` 后命中 `rw-` 槽且探针命中，unhook 后还原。
- `verify_v47_got_enum.sh` — 枚举 `libadhdetect.so` 的 GOT/relocation，断言导入符号可见（deploy new agent；未部署时 SKIP）。
- `verify_v48_memory_disasm.sh` — 真机地址 → agent 读内存 → Host Capstone 5 WASM 反汇编；覆盖绝对地址与 module+offset 两条路径（deploy new daemon/agent；未部署时 SKIP）。
- `verify_v49_native_call.sh` — `adh_add_target` 按 module+symbol 和绝对地址主动调用，断言返回值与 confirm 门禁（deploy new agent/daemon；未部署时 SKIP）。
- `verify_v50_syscall_watch.sh` — Host dump+静态扫描 `svc #0` → native inline hook → 调 `adh_direct_gettid`，断言 x8=0xb2 的事件与 unhook（deploy new daemon/agent；未部署时 SKIP）。
- `verify_v51_qbdi_args.sh` — QBDI 带 2 个整数参数 trace `adh_add_target(20,22)`，断言 retval=84 与指令流非空；旧 agent 忽略 args 时 SKIP（deploy new agent/daemon）。
- `verify_v52_java_override.sh` — LSPlant Java hook `skipOriginal + returnValue`：调 `recordPing`/`lastPingResult` 证明调用方实际拿到替换值，再 unhook（deploy new agent/sandbox）。
- `verify_v53_java_arg_rewrite.sh` — Java hook 参数改写：`argIndex/argValue` 后原方法仍执行，调用方返回 `REAL_HOOK:ADH_REWRITTEN`（deploy new agent/sandbox）。
- `verify_v54_jni_register_hook.sh` — JNIEnv->RegisterNatives hook：触发 `Detection.jniRegisterProbe()`，断言 JNI_NATIVE 事件和新注册方法 `0xAD11`，再 uninstall（deploy new agent/sandbox）。
- `verify_v55_native_rewrite.sh` — native hook 参数改写 `1,2 -> 18`，skip original + returnValue `0x54 -> 84`，status 字段与 unhook（deploy new agent/daemon）。
- `verify_v56_hook_stress.sh` — 同一 native/Java 目标各 24 次 install/unhook，断言软卸载复用、最终行为恢复、agent 存活（deploy new agent/daemon）。
- `verify_v57_jni_onload.sh` — JNI_OnLoad list → hook → 手动 call（返回 JNI_VERSION_1_6）→ JNI_ONLOAD 事件 → 软 unhook → 再次 call 不新增 hit（已加载模块路径，非 load-time 拦截）。
- `verify_v58_jni_env_hook.sh` — JNIEnv 函数表逐项 hook：FindClass / GetMethodID / GetStaticMethodID / NewStringUTF / GetStringUTFChars 各装一次，触发 `Detection.jniEnvProbe()` 后断言 5 条精确 JNI_ENV 事件与 hits，再 uninstall 证明表项已还原（hits 冻结、探针返回值不变）。
- `verify_v59_jni_env_arrays.sh` — JNIEnv 字段/数组表项 hook：GetFieldID / GetStaticFieldID / SetByteArrayRegion / GetByteArrayElements 各装一次，触发 `Detection.jniEnvArrayProbe()` 后断言 4 条精确 JNI_ENV 事件（含 `start=0 len=8 hex=414448…` 与 `len=8 hex=…`），再 uninstall 证明表项还原（hits 冻结、返回值不变、RELRO 仍为 r--）。
- `verify_v60_jni_env_preserve.sh` — JNIEnv hook 行为不变性：安装 GetMethodID / GetStaticMethodID / GetFieldID / GetStaticFieldID 后 `Detection.jniEnvExceptionProbe()` 的返回值必须与未安装时一致（失败查找仍留下 NoSuchMethodError / NoSuchFieldError，且失败查找本身也有 JNI_ENV 事件），uninstall 后再次一致。
- `verify_v61_got_by_name.sh` — 按名 GOT hook（`native_hook mode=got`）：安装 `libadhdetect.so:adh_trace_target` 的 GOT 槽 → 触发 `Detection.nativeHookProbe()` → 断言 NATIVE_HOOK 事件与 hits → 软 unhook 后行为不变、不再新增事件（回归守卫：`module_base_of` 曾把整条按名路径悄悄打成 0 命中）。
- `verify_v62_jni_call_hooks.sh` — JNIEnv Call*Method / NewObject hook：装 NewObjectA / CallObjectMethodA / CallIntMethodA / CallVoidMethod(varargs) / CallStaticObjectMethod(varargs)，触发 `Detection.jniCallProbe()`，断言事件里已解析出 `class#method(sig) args(...)`（含字符串与整数实参）与探针位掩码，再 uninstall 证明表项还原（hits 冻结、返回不变、RELRO r--）。
- `verify_v63_jni_array_writeback.sh` — byte[] 原地回写：Set/GetByteArrayRegion、Get/ReleaseByteArrayElements(mode 0)、Get/ReleasePrimitiveArrayCritical，触发 `Detection.jniArrayWriteProbe()` 写入 0xA0../0xB0.. 再读回，断言事件里出现 `writeback hex=a0a1…`、`writeback hex=b0b1…` 与探针位掩码，再 uninstall 验还原。（补上评审指出的 in-place 解密回写盲区。）
- `verify_v64_jni_call_types.sh` — Call* 全族覆盖 + 通配安装：`function:"*"` 一次装 76 个槽位（断言 `applied=76 failed=0`，每个槽位过 ABI 偏移守卫），触发 `Detection.jniCallTypesProbe()` 断言 Boolean/Byte/Char/Short/Long/Float/Double（实例 A 形态 + 静态 varargs 形态）每族命中且 `status.last` 里能看到解析后的 `class#method(sig)`，再全量卸载证明还原。
- `verify_v65_java_ctor_inherited.sh` — java_hook 完整性：hook 构造器 `JniCtorTarget.<init>(int)`（断言回调看到实参 21、对象仍被正确构造 total=42、`skipOriginal/returnValue` 被 fail-loud 拒绝）+ hook 继承成员 `JniDerived.baseValue`（解析到声明类 `JniBase.baseValue()`），再逐个 unhook 并复查行为不变。
- `verify_v66_native_hard_unhook.sh` — native **hard unhook**：inline hook → 命中/调用正常 → `hard:true` 卸载（回写保存的原始序言、释放槽位、不动 Dobby 池）→ 行为恢复、status `count/patched=0`、无 RWX、anon 足迹稳定不泄漏、同地址再 hook 被明确拒绝（Dobby 状态已陈旧，需重启目标）。
- `verify_v67_jni_onload_watch.sh` — **load-time JNI_OnLoad 拦截**：`jni_onload watch` 装 dlopen 钩子 → 两个运行时才加载的插件库各走一遍：A 观察（事件 `phase:"load"`、插件 JNI_OnLoad 真的跑过 count=1）；unhook（真还原字节）后 watch B 用 `skipOriginal+returnValue` **替换** load-time 调用（事件 `skipped:true`、插件计数 0、`System.loadLibrary` 仍成功）。
- `verify_v47_got_enum.sh` — 枚举 `libadhdetect.so` 的 GOT/relocation，断言导入符号可见（deploy new agent；未部署时 SKIP）。
- `verify_v97_memread_direct.sh` — **内存读取后端**（device）：重启沙盒取干净进程 → 以只读代码映射为锚点，`memory_read` 的自动路径与 `via:"direct"` 路径返回**逐字节相同**的数据且回复各自点明 `via` → 对一个 `---p` 区间直读必须**干净失败**且目标仍活（`agent_ping`）→ `compat_probe` 报出 `memBackend`/`memOpenErrno`/`libartJniGetVms`（能力不再静默降级）→ 命令结束后目标进程 `/proc/<pid>/fd` 里**没有**遗留的 `/proc/self/mem`。信号守卫本身（拷贝途中映射消失）无法在此确定性触发，脚本不声称覆盖它。
- `verify_v98_injected_java_surface.sh` — **注入路径的 Java 面**（device）：照 `verify_v75` 的做法把 `com.android.settings`（可用 `ADH_JAVA_TARGET` 换）写进 Zygisk scope 并冷启动，拿到 `entry=start` 的 memfd 注入会话后断言 agent **仍然够得着 Java**——`compat_probe.backends.jniReflect` / `artDexCapture` 为 true、`libartJniGetVms` 为 true、`art_dexfiles` `ok:true`、`java_enum(java.lang.String)` 走通反射（返回含 classLoader 与成员表）。
  **这是 JavaVM 缺陷的回归守卫**：memfd 加载的 agent 没有 `JNI_OnLoad`，而 linker 拒绝它 `dlopen("libart.so")`，所以修复前这里全是 `no JavaVM`，而门禁其余 79 项因为跑在自加载沙盒上照样全绿。
  注意断言的是**能力**不是计数：系统应用（如 Settings）在线程上下文类加载器里可能没有应用级 dex，`art_dexfiles count=0` 是合理的，判别信号是 `ok`（修复前为 `ok:false error:"no JavaVM"`）。结束恢复 Zygisk scope。缺前置条件时打印 `SKIP` 且**不带** `RESULT:PASS` 哨兵。
- `verify_v99_artifact_store.sh` — **工件存储**（host）：先跑 `daemon/test/artifact_store.test.ts`（纯策略单测 8 项：文件名映射、超龄、超量、最旧优先、`protectSha`、mtime 未知不猜老），再**重启 daemon**（PowerShell 杀进程 + 等端口停 + 重起，同 v37）后断言：磁盘上每个工件都重新出现在 `/api/dumps` 里、条目 `source=disk-reload`（不编造来源）、没有指向不存在文件的悬空条目、`settings.artifacts` 暴露预算。**注册在最后**，因为它自己会重启 daemon。
- `verify_v15_dumpall.sh`（v9.11 扩）——除原有的枚举/dump/去重/下载外，先跑 `daemon/test/dex_artifact_shape.test.ts`（4 项，用学习通实测数字钉死 carrier 判定），再断言逐 dex 都被分类、`realDexCount+carrierCount==dexCount`、沙盒上 `carrierCount===0`、`index.built>=1`。
- `verify_v100_adh_cli.sh` — **`adh` 命令行**（device；daemon 那半不需要设备也能跑）：先跑 `daemon/test/cli_args.test.ts`（10 项：声明即消费、未知/错位 flag 报用法错、歧义目标必须报错不许静默选、AGENT_VER 与 module.prop 必须同步），再断言 `doctor` 给出守护进程信息与**刷入的 agent 版本 vs 源码版本**配对、`target` 解析出唯一 agent 并报活体事实（ping/能力/dex 数）、`unpack` 逐 dex 分类且 `--out` 落盘数量等于 `realDexCount`；结构性守卫一条：`cli.ts` 只许 import `config.ts`（客户端，不可能与 daemon 真值漂移）。
  **每个 flag 都必须有可观测效果**，这是本条的重点：`--port`/`--host` 由错误信息里的 base URL 证、`--timeout` 由"2 秒预算真的在 ~2s 内结束"证（`req.setTimeout` 只约束 socket 空闲、不约束 connect，早先版本会在 5.1s 才报"超时 2 秒"——这条断言就是防它回退）、`--json` 由输出形状证、`--package`/`--session` 由它拒绝解析的目标证、`--out`/`--include-carriers` 由落盘文件数证。理由见 `daemon/src/cli.ts` 顶部：**接受但忽略的 flag 比没有这个 flag 更糟**（`xls-probe` 的 `--proxy` 只在 `signcode` 上生效，`face --proxy` 静默忽略，而那条路正是"换出口"实验本身）。目标侧断言需要在线 agent，没有时打印 `SKIP` 且不带 `RESULT:PASS` 哨兵。
- `build_crypto_variants.sh` — 构建变异算法检测的**靶子库**（`fixtures/crypto-variants/{std,variant}.c` → `fixtures/crypto-variants/build/libadhcrypto_{std,variant}.so`，NDK clang `--target=aarch64-linux-android26 -O0`）。两个库构成 A/B：`std` 是教科书常量（负对照），`variant` 携带参考仓库真实出货的那几种变异（MD5 init 被改写、SHA1 轮常量被改写、base64 码表被置换，另加运行时生成的码表与多项式）。**必须是编译产物**：检测器的全部主张就是"能从二进制真正含有的字节里认出变异"，拿测试自己拼的 Buffer 去测只能证明测试会拼常量。`-O0` 是刻意的——优化会把表折进立即数，靶子就不再含有自己的常量了。
- `verify_v101_crypto_variants.sh` — **变异算法识别**（host）：先跑 `daemon/test/crypto_variants.test.ts`（13 项，向量取自参考仓库的真实变异字节），再编译靶子并**经 daemon 的 REST 面**扫这两个库：负对照（教科书库必须一条 variant 判定都没有）→ MD5 变异（由未被改动的 K 表锚定、缺席的 init 作为证据、报告的 `12/16` 说明"标准 init 被原位改写"）→ SHA1 变异（从**另一端**锚定：IV 未动、轮常量被改）→ 置换码表按**形状**找到且漂移量计数为 54 → CRC-32C 被如实报成"另一套标准"而非变异 → `limits` 三条（运行时生成的表、连锚点一起改的变异）**必须存在**（扫描器要说得出自己在哪瞎）。
  最关键的一条断言是**度量出来的缺口**：旧的标准常量扫描对两个库返回**完全相同的算法名**（`status` 一样），而且在变异库上仍然报 `MD5-init`——那是 SHA1 init 的前 8 字节撞上的**假阳性**。即旧工具不是安静地瞎，是会主动误导；这条断言把"新层加了什么"钉成了可复跑的事实。
