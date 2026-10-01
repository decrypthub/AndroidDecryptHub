# AGENTS.md

Guidance for Codex working in this repo. Keep this file short. Only rules that are **not inferable from the code**.

## What this is

**ADH (Android DecryptHub)** — a general-purpose **Android runtime reverse-analysis** tool. **IDH** is the iOS counterpart ([ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper)); do not use IDH as this project's product name. Injects a native agent into a target app, observes/dumps/hooks/traces at runtime, controlled from a browser + MCP. Targets are frequently **evasive** (anti-debug, root/signature detection, code obfuscation, encrypted traffic) — the design assumes hostile runtimes. Scope is **authorized reverse investigation**, not legal forensics and not evasion tooling for malicious use.

## Source of truth (read before changing scope)

- `docs/HANDOVER.md` — **接手本项目的 Agent 从这里开始**：环境真相（连着的手机**没有 root 且是用户日常机，不要碰**）、
  其它文档里没有的坑、以及在"无设备 / 无 root"前提下能交付什么。它不定义 scope，只定义**怎么在这里干活**。
- `docs/REQUIREMENTS.md` — the single authoritative spec of **what** we build (modules A–W; module X is retired).
- `docs/DEVELOPMENT_PLAN.md` — **how / architecture / roadmap**.
- `docs/PROGRESS.md` — **where we are right now**; update it every session. This is how work survives across sessions.
- `docs/FEATURE_STATUS.md` — **发布范围与功能状态**（测过 / 没测 / 没通过 / 半成品四类）；发版或对外承诺前先看这里。
- `docs/CASE_STUDIES.md` — **真实目标实战记录**：拿到了什么 + ADH 作为工具暴露了什么（脱敏，不含目标数据）。
- `docs/archive/` — non-authoritative historical snapshots; never restore stale TODOs from them.
- `docs/REFERENCE_IOS.md` + `.ref/ios-decrypt-helper/` — the iOS project we inherit ideas from.

There is one plan. If something contradicts these docs, fix the docs in the same change — do not leave a divergent second plan.

## Naming

| 名称 | 含义 |
|------|------|
| **ADH** | 本产品（Android DecryptHub） |
| **Host ADH Daemon** / `adhd` | 本机守护进程（`daemon/`，HTTP/WS/MCP/分析）；对外统一此称 |
| **Device Daemon** | 手机侧作用域服务（`device/:daemon`，AIDL）；**不是** Host 分析进程 |
| **ADH Manager** | 手机侧 Compose UI（`device/:manager`）；注入作用域与目标进程启停 |
| **ADH Sandbox** / `com.adh.sandbox` | 模拟注入与确定性验收宿主；不是产品目标包 |
| **IDH** | iOS 参考项目（IOSDecryptHub / ios-decrypt-helper），仅作对照 |
| `libadh_agent.so` | 本产品 agent `.so`（唯一交付名，随 Zygisk 模块与沙盒打包；Xposed 薄模块只作社区/实验） |
- 新代码/新文案使用 `ADH` / `Host ADH Daemon` / `adhd` / `adh_*`。不保留 IDH 名称兼容层：不再产出或接受 `libidh_agent.so`，不导出 `idh_agent_start`，不读取 `IDH_*` 环境变量，不兼容 `idhd-data/` 或 `libidhdetect.so`；IDH 仅指 iOS 参考项目。`com.idh.probe` / `IDH_PROBE_OK` 是 hash 绑定的固定 probe dex 例外。

## Architecture red line (do not cross)

Never merge these layers.

- `libadh_agent.so` (in target process) — **collect / execute only**: hook, trace, dump, maps scan, light RPC. Keep it minimal, low-memory, non-blocking.
- **Host ADH Daemon** (`daemon/`, npm `adhd`) — HTTP / WebSocket / MCP / DB / index / disasm cache / analysis.
- **Device** (`device/`: `:core` + `:daemon` + `:manager`) — injection scope + module status + target process stop/restart. No analysis.
- Web UI (browser) — observe / search / visualize (frozen as a READ-ONLY viewer, 2026-10-01).

**Never** put HTTP, MCP, a database, the dex indexer, or Capstone/QBDI heavy analysis inside the agent `.so` or the Device Daemon/Manager. That causes target OOM/ANR and is easy to detect.

## How to work here (long-running, cross-session)

Loop: **Explore → Plan → Implement → Verify**, then iterate on the result.

1. Explore the relevant code/docs first; state a short plan before writing code.
2. Implement one roadmap slice at a time (see the version roadmap in DEVELOPMENT_PLAN).
3. **Verify against a pass/fail signal** — never call something done on "looks right".
4. Update `docs/PROGRESS.md` and `git commit` at each meaningful milestone.
5. For independent parallel work use worktrees / subagents; keep the agent `.so` changes isolated from ADH Daemon / web when possible.

## Scope priority (current)

Build **`libadh_agent.so` functionality** and self-test via 模拟注入 (sandbox `dlopen`). **Module W**: Zygisk (`injector/zygisk`) + device multi-module (`device/` Compose Manager + root Device Daemon). Module X (Android UI automation) is retired and removed: do not restore the Manager AccessibilityService, notification reader, phone_* MCP tools, or device input/power/volume/clipboard bridge. When an AI agent needs to interact with the attached phone, use `adb` directly. Keep the Device surface limited to injection scope, module status, and target app process control. Frida Gadget remains a dev/debug backend (out of the release artifact, 2026-10-01; off by default) (`tools/load_frida_gadget.sh`, verified by `tools/verify_v30_fridagadget.sh`; Frida 17+ hooks using `Java.perform()` must be bundled with `tools/compile_frida_script.sh`). A community/experimental LSPosed/Xposed thin module is also available (Zygisk is the only official path, 2026-10-01) (`injector/xposed/`, built by `tools/build_xposed.sh`, verified by `tools/verify_v31_xposed.sh`) — it only loads the agent, never analysis code. Do not block feature verification on real injection — CI stays on 模拟注入.

## Verification (give yourself a real signal)

- Primary loop uses **`sandbox-test-app` with 模拟注入** (the app `dlopen`s the agent itself) — no root needed, deterministic, CI-friendly. Iterate here first.
- Real-target integration uses the attached device (see below) via Zygisk / gadget injection.
- Every module must have a deterministic **input → expected-output** check (sandbox activity + acceptance script). Prefer running the check and reading its output over eyeballing.

## Commands

Bash (Git Bash / WSL) — the `tools/*.sh` scripts assume it. `node 24` runs `.ts` directly (no build/transpile step). Agent build needs `ANDROID_SDK_ROOT` + NDK `28.2.13676358` + SDK `cmake/3.22.1` (scripts default `ANDROID_SDK_ROOT=$HOME/AppData/Local/Android/Sdk`).

```bash
# --- agent .so (C/NDK, arm64-v8a) — fails loud on compile error, stages into sandbox jniLibs
bash tools/build_agent.sh          # -> agent/build/libadh_agent.so
bash tools/build_detect.sh         # sandbox mock native lib libadhdetect.so
# bash tools/build_java_hook_bridge.sh  # regenerate embedded Java hook bridge dex/header after editing its Java source
bash tools/fetch_qbdi.sh           # one-time: QBDI headers/.so (instruction trace); gitignored
bash tools/fetch_dobby.sh          # one-time: Dobby (verified native inline-hook backend)
# bash tools/fetch_lsplant.sh       # optional: LSPlant v6.4 + patched ART fallback (Java method hook; statically linked when present)

# --- ADH Daemon (daemon/, npm adhd) — from daemon/
node src/index.ts                  # start (HTTP/WS 8088, agent TCP 8761); or: npm start
node --watch src/index.ts          # dev; or: npm run dev
node test/smoke.ts                 # smoke; or: npm run smoke
node src/cli.ts --help             # `adh` CLI (npm run adh): doctor | target | unpack — the client of adhd,
                                   # and the one implementation of "resolve the target agent" (see docs/PROGRESS.md)

# --- sandbox app (Kotlin, AGP 8.7.3 / Gradle 8.9 / compileSdk 36) — from sandbox-app/
./gradlew :app:assembleDebug       # build APK; install with install_apk_root (su + pm, not adb install)

# --- Zygisk + Device surface (module W)
bash tools/build_zygisk.sh         # -> injector/zygisk/dist/adh-zygisk.zip
bash tools/build_bundle.sh         # -> injector/zygisk/dist/adh-bundle-vX.Y.Z.zip
bash tools/flash_device.sh --reboot # 推到当前手机并刷入（KernelSU/Magisk）；后续代码更新重复这一条
cd device && ./gradlew :core:test :daemon:assembleDebug :manager:assembleDebug

# --- run + verify (this is the real pass/fail signal)
bash tools/dev_up.sh               # idempotent: start Host ADH Daemon + set adb reverse (run first each loop)
bash tools/verify_all.sh           # full regression; device checks auto-SKIP (not FAIL) if offline
bash tools/verify_v04_crypto.sh    # a single acceptance check (exit 0 = PASS). one per capability slice

```

Ports: Host ADH Daemon HTTP/WS `8088` (LAN, same as iOS `idh`), agent TCP `8761`. Override via `ADH_HTTP_PORT` / `ADH_AGENT_PORT`. Prefer `http://<LAN>:8088/<package>` to pin an app; do not default to `127.0.0.1`. The agent dials the host through `adb reverse`; AI phone interaction uses `adb` directly. `dev_up.sh` sets the HTTP and agent tunnels. New-machine repro order: `fetch_qbdi` → `fetch_dobby` → optional `fetch_lsplant` → `build_agent` → `build_detect` → `dev_up` → `verify_all`.

There is no separate lint step. `CLAUDE.md` (for Claude) is kept in sync with this file apart from the header line — mirror any change into both.

## Module layout (navigation)

Each layer has a `MAP.md` — read it before editing that layer:

- `tools/MAP.md` — `tools/lib/verify_common.sh` + `tools/lib/env.sh`. **Add a verify script = source the lib + one node heredoc**.
- `daemon/src/MAP.md` — Host ADH Daemon: `state.ts` ← `service.ts` ← `mcp.ts` / `index.ts`.
- `device/MAP.md` — device multi-module: `:core` (scope contract) + `:daemon` (AIDL) + `:manager` (Compose).
- `injector/` — Zygisk Magisk zip (`injector/zygisk/`); community/experimental LSPosed/Xposed thin loader (`injector/xposed/`).
- `agent/src/MAP.md` — Agent source ownership and Phase 3 extraction rules; read it before moving capabilities out of bootstrap.



## Test device (which phone you have decides everything)

- **The handover machine gets a rooted, flashable phone from the user.** With it the normal path is open:
  `tools/flash_device.sh` (KernelSU/Magisk), `install_apk_root` (`su` + `pm install`), and the full
  `tools/verify_all.sh` (117 = 36 host + 81 device). **Record the device facts** (model / API level / ABI /
  root method / serial) in `docs/HANDOVER.md` §1.3 — the ART structure resolver is validated on **SDK 35
  (primary) / 36 (secondary)**, so a different API level means "extend the resolver" is your first task,
  not "the tool is broken".
- **On the original Windows workstation there is NO rooted device.** The unit there (`a22fecdd`, PGP110 /
  Android 15 / SDK 35 / arm64-v8a) is the user's **daily driver and deliberately unrooted** (verified
  2026-09-29: `id` → `uid=2000(shell)`, no `su`, `/data/adb` permission denied). Do not flash it, install
  anything on it, or start/stop apps on it; `tools/dev_up.sh` also runs `adb reverse` against whatever is
  attached, so skip it for host-only work. The sandbox app is not installed there, so all 81 device scripts
  fail or hang waiting for an agent — **do not run the full `verify_all.sh` on that machine**; the host-subset
  recipe (36/36 on 2026-09-29) is in `docs/HANDOVER.md` §2.2.
- **`docs/HANDOVER.md` is the onboarding doc** — environment truth by machine profile, the pitfalls not
  written anywhere else, and the todo list with acceptance signals. Read it before planning work.
- Unchanged and still true: primary agent ABI is `arm64-v8a` **only** (ratified product boundary, 2026-10-01); keep **per-API-level ART resolvers**; this
  ColorOS ROM ships a **heavily stripped `libart.so`**; the verified native inline-hook backend is Dobby
  (`tools/fetch_dobby.sh`), with LSPlant v6.4 an optional Java-hook backend linked in only when
  `tools/fetch_lsplant.sh` has prepared its pinned sources.

## Boundaries

- Authorized targets only. Anti-anti-debug "resilience" (module S) is diagnostic + survival for authorized analysis; default off, no self-hiding by default, dangerous ops need confirmation.
- Never commit captured target data (keys, plaintext, dumps). `.gitignore` excludes `captures/`, `dumps/`, `adhd-data/`.
