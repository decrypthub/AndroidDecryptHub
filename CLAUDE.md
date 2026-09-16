# CLAUDE.md

Guidance for Claude working in this repo. Keep this file short. Only rules that are **not inferable from the code**.

## What this is

**ADH (Android DecryptHub)** — a general-purpose **Android runtime reverse-analysis** tool. **IDH** is the iOS counterpart ([ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper)); do not use IDH as this project's product name. Injects a native agent into a target app, observes/dumps/hooks/traces at runtime, controlled from a browser + MCP. Targets are frequently **evasive** (anti-debug, root/signature detection, code obfuscation, encrypted traffic) — the design assumes hostile runtimes. Scope is **authorized reverse investigation**, not legal forensics and not evasion tooling for malicious use.

## Source of truth (read before changing scope)

- `docs/REQUIREMENTS.md` — the single authoritative spec of **what** we build (modules A–W).
- `docs/DEVELOPMENT_PLAN.md` — **how / architecture / roadmap**.
- `docs/PROGRESS.md` — **where we are right now**; update it every session. This is how work survives across sessions.
- `docs/FEATURE_STATUS.md` — **发布范围与功能状态**（测过 / 没测 / 没通过 / 半成品四类）；发版或对外承诺前先看这里。
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
| `libadh_agent.so` | 本产品 agent `.so`（交付物名，随 Zygisk/Xposed 模块与沙盒打包）；`libidh_agent.so` 仅作为**已刷入旧模块的回退名**被 loader/companion 接受 |
- 新代码/新文案使用 `ADH` / `Host ADH Daemon` / `adhd` / `adh_*`。**不再产出** `libidh_agent.so`（仅 loader 兼容回退）；`idh_agent_start` 旧符号、`IDH_*` 环境变量、`idhd` npm 别名与 `idh_*` 内部符号同样只作 legacy 兼容层，不得作为新产品名、新接口名或新日志 tag；IDH 仅指 iOS 参考项目。`com.idh.probe` / `IDH_PROBE_OK` 是 hash 绑定的固定 probe dex 例外。

## Architecture red line (do not cross)

Never merge these layers.

- `libadh_agent.so` (in target process) — **collect / execute only**: hook, trace, dump, maps scan, light RPC. Keep it minimal, low-memory, non-blocking.
- **Host ADH Daemon** (`daemon/`, npm `adhd`) — HTTP / WebSocket / MCP / DB / index / disasm cache / analysis.
- **Device** (`device/`: `:core` + `:daemon` + `:manager`) — injection scope + module status + target process stop/restart. No analysis.
- Web UI (browser) — observe / search / configure.

**Never** put HTTP, MCP, a database, the dex indexer, or Capstone/QBDI heavy analysis inside the agent `.so` or the Device Daemon/Manager. That causes target OOM/ANR and is easy to detect.

## How to work here (long-running, cross-session)

Loop: **Explore → Plan → Implement → Verify**, then iterate on the result.

1. Explore the relevant code/docs first; state a short plan before writing code.
2. Implement one roadmap slice at a time (see the version roadmap in DEVELOPMENT_PLAN).
3. **Verify against a pass/fail signal** — never call something done on "looks right".
4. Update `docs/PROGRESS.md` and `git commit` at each meaningful milestone.
5. For independent parallel work use worktrees / subagents; keep the agent `.so` changes isolated from ADH Daemon / web when possible.

## Scope priority (current)

Build **`libadh_agent.so` functionality** and self-test via 模拟注入 (sandbox `dlopen`). **Module W**: Zygisk (`injector/zygisk`) + device multi-module (`device/` Compose Manager + root Device Daemon). Frida Gadget is available as an **optional, off-by-default** backend (`tools/load_frida_gadget.sh`, verified by `tools/verify_v30_fridagadget.sh`; Frida 17+ hooks using `Java.perform()` must be bundled with `tools/compile_frida_script.sh`); repackage (`injector/gadget-pack`) remains deferred. An optional LSPosed/Xposed thin module is also available (`injector/xposed/`, built by `tools/build_xposed.sh`, verified by `tools/verify_v31_xposed.sh`) — it only loads the agent, never analysis code. Do not block feature verification on real injection — CI stays on 模拟注入.

## Verification (give yourself a real signal)

- Primary loop uses **`sandbox-test-app` with 模拟注入** (the app `dlopen`s the agent itself) — no root needed, deterministic, CI-friendly. Iterate here first.
- Real-target integration uses the attached device (see below) via Zygisk / gadget injection.
- Every module must have a deterministic **input → expected-output** check (sandbox activity + acceptance script). Prefer running the check and reading its output over eyeballing.

## Commands

Bash (Git Bash / WSL) — the `tools/*.sh` scripts assume it. `node 24` runs `.ts` directly (no build/transpile step). Agent build needs `ANDROID_SDK_ROOT` + NDK `28.2.13676358` + SDK `cmake/3.22.1` (scripts default `ANDROID_SDK_ROOT=$HOME/AppData/Local/Android/Sdk`).

```bash
# --- agent .so (C/NDK, arm64-v8a) — fails loud on compile error, stages into sandbox jniLibs
bash tools/build_agent.sh          # -> agent/build/libadh_agent.so
bash tools/build_detect.sh         # sandbox mock native lib libidhdetect.so
bash tools/fetch_qbdi.sh           # one-time: QBDI headers/.so (instruction trace); gitignored
bash tools/fetch_dobby.sh          # one-time: Dobby (native inline hook; the only hook backend in v1)

# --- ADH Daemon (daemon/, npm adhd) — from daemon/
node src/index.ts                  # start (HTTP/WS 8088, agent TCP 8761); or: npm start
node --watch src/index.ts          # dev; or: npm run dev
node test/smoke.ts                 # smoke; or: npm run smoke

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

# --- python gateway (PyPI android-decrypt-hub, 脚本 adh)
cd python && PYTHONPATH=src python -m unittest
```

Ports: Host ADH Daemon HTTP/WS `8088` (LAN, same as iOS `idh`), agent TCP `8761` (override via `ADH_HTTP_PORT` / `ADH_AGENT_PORT`; legacy `IDH_*` aliases work). Prefer `http://<LAN>:8088/<package>` to pin an app; do not default to `127.0.0.1`. Agent dials host through `adb reverse`; `dev_up.sh` sets both tunnels. New-machine repro order: `fetch_qbdi` → `build_agent` → `build_detect` → `dev_up` → `verify_all`.

There is no separate lint step. `AGENTS.md` (for Codex) is kept in sync with this file apart from the header line — mirror any change into both.

## Module layout (navigation)

Each layer has a `MAP.md` — read it before editing that layer:

- `tools/MAP.md` — `tools/lib/verify_common.sh` + `tools/lib/env.sh`. **Add a verify script = source the lib + one node heredoc**. 
- `daemon/src/MAP.md` — Host ADH Daemon: `state.ts` ← `service.ts` ← `mcp.ts` / `index.ts`.
- `device/MAP.md` — device multi-module: `:core` (scope contract) + `:daemon` (AIDL) + `:manager` (Compose).
- `injector/` — Zygisk Magisk zip (`injector/zygisk/`); optional LSPosed/Xposed thin loader (`injector/xposed/`).
- `agent/src/MAP.md` — Agent source ownership and Phase 3 extraction rules; read it before moving capabilities out of bootstrap.
- `python/` — PyPI `android-decrypt-hub`（脚本 `adh`）：连接 Host ADH Daemon 并把 `POST /mcp` 桥到 stdio。



## Test device (available now)

- `adb` serial `13f54a46` — OnePlus PGP110, **Android 15 / SDK 35**, `arm64-v8a`, **rooted** (`su` → uid=0), `ro.debuggable=0`.
- **Multiple identical PGP110 units are attached** (`13f54a46` + others). adb commands without `-s` fail with "more than one device" — `export ANDROID_SERIAL=13f54a46` so every adb call (incl. the `tools/*.sh` scripts) targets the right unit.
- Keep **per-API-level ART resolvers**; the ART-structure dex resolver (L.6) must handle **SDK 35** (this device). SDK 36 (Pixel 6 Pro) is a secondary target, not attached now.
- Primary agent ABI is `arm64-v8a`.
- This OnePlus/ColorOS ROM ships a **heavily stripped `libart.so`**. Java-method hooking (LSPlant) was **removed from the v1 scope** for this reason — it cannot initialise here, so it was neither verifiable nor shippable; the native inline-hook backend (Dobby, `tools/fetch_dobby.sh`) is unaffected and verified.

## Boundaries

- Authorized targets only. Anti-anti-debug "resilience" (module S) is diagnostic + survival for authorized analysis; default off, no self-hiding by default, dangerous ops need confirmation.
- Never commit captured target data (keys, plaintext, dumps). `.gitignore` excludes `captures/`, `dumps/`, `idhd-data/`, `adhd-data/`.
