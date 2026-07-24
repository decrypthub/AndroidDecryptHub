# AGENTS.md

Guidance for Codex working in this repo. Keep this file short. Only rules that are **not inferable from the code**.

## What this is

**ADH (Android DecryptHub)** — a general-purpose **Android runtime reverse-analysis** tool. **IDH** is the iOS counterpart ([ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper)); do not use IDH as this project's product name. Injects a native agent into a target app, observes/dumps/hooks/traces at runtime, controlled from a browser + MCP. Targets are frequently **evasive** (anti-debug, root/signature detection, code obfuscation, encrypted traffic) — the design assumes hostile runtimes. Scope is **authorized reverse investigation**, not legal forensics and not evasion tooling for malicious use.

## Source of truth (read before changing scope)

- `docs/REQUIREMENTS.md` — the single authoritative spec of **what** we build (modules A–W).
- `docs/DEVELOPMENT_PLAN.md` — **how / architecture / roadmap**.
- `docs/PROGRESS.md` — **where we are right now**; update it every session. This is how work survives across sessions.
- `docs/REFERENCE_IOS.md` + `.ref/ios-decrypt-helper/` — the iOS project we inherit ideas from.

There is one plan. If something contradicts these docs, fix the docs in the same change — do not leave a divergent second plan.

## Naming

| 名称 | 含义 |
|------|------|
| **ADH** | 本产品（Android DecryptHub） |
| **IDH** | iOS 参考项目（IOSDecryptHub / ios-decrypt-helper），仅作对照 |
| `libidh_agent.so` / `idhd` / `idh_*` | 早期脚手架遗留的内部标识符；产品对外统一称 ADH |

## Architecture red line (do not cross)

Three layers. Never merge them.

- `libidh_agent.so` (in target process) — **collect / execute only**: hook, trace, dump, maps scan, light RPC. Keep it minimal, low-memory, non-blocking.
- `idhd` (host daemon) — HTTP / WebSocket / MCP / DB / index / disasm cache / analysis.
- Web UI (browser) — observe / search / configure.

**Never** put HTTP, MCP, a database, the dex indexer, or Capstone/QBDI heavy analysis inside the agent `.so`. That causes target OOM/ANR and is easy to detect.

## How to work here (long-running, cross-session)

Loop: **Explore → Plan → Implement → Verify**, then iterate on the result.

1. Explore the relevant code/docs first; state a short plan before writing code.
2. Implement one roadmap slice at a time (see the version roadmap in DEVELOPMENT_PLAN).
3. **Verify against a pass/fail signal** — never call something done on "looks right".
4. Update `docs/PROGRESS.md` and `git commit` at each meaningful milestone.
5. For independent parallel work use worktrees / subagents; keep the agent `.so` changes isolated from `idhd`/web when possible.

## Scope priority (current)

Build **all `libidh_agent.so` functionality first** and self-test it via 模拟注入 (sandbox `dlopen`) — that exercises the same agent code paths, so no real injection is needed to verify features. **Defer the Zygisk/gadget/repackage injectors (module W)** entirely; the user tests real injection manually. Do not block feature verification on real injection.

## Verification (give yourself a real signal)

- Primary loop uses **`sandbox-test-app` with 模拟注入** (the app `dlopen`s the agent itself) — no root needed, deterministic, CI-friendly. Iterate here first.
- Real-target integration uses the attached device (see below) via Zygisk / gadget injection.
- Every module must have a deterministic **input → expected-output** check (sandbox activity + acceptance script). Prefer running the check and reading its output over eyeballing.

## Commands

Bash (Git Bash / WSL) — the `tools/*.sh` scripts assume it. `node 24` runs `.ts` directly (no build/transpile step). Agent build needs `ANDROID_SDK_ROOT` + NDK `28.2.13676358` + SDK `cmake/3.22.1` (scripts default `ANDROID_SDK_ROOT=$HOME/AppData/Local/Android/Sdk`).

```bash
# --- agent .so (C/NDK, arm64-v8a) — fails loud on compile error, stages into sandbox jniLibs
bash tools/build_agent.sh          # -> agent/build/libidh_agent.so
bash tools/build_detect.sh         # sandbox mock native lib libidhdetect.so
bash tools/fetch_qbdi.sh           # one-time: QBDI headers/.so (instruction trace); gitignored
bash tools/fetch_lsplant.sh        # one-time: LSPlant + Dobby (Java-method hook, WS-A)

# --- daemon (idhd) — from daemon/
node src/index.ts                  # start (HTTP/WS 8760, agent TCP 8761); or: npm start
node --watch src/index.ts          # dev; or: npm run dev
node test/smoke.ts                 # smoke; or: npm run smoke

# --- sandbox app (Kotlin, AGP 8.7.3 / Gradle 8.9 / compileSdk 36) — from sandbox-app/
./gradlew :app:assembleDebug       # build APK; install with adb install

# --- run + verify (this is the real pass/fail signal)
bash tools/dev_up.sh               # idempotent: start idhd + set adb reverse (run first each loop)
bash tools/verify_all.sh           # full regression; device checks auto-SKIP (not FAIL) if offline
bash tools/verify_v04_crypto.sh    # a single acceptance check (exit 0 = PASS). one per capability slice
```

Ports: idhd HTTP/WS `8760`, agent TCP `8761` (override via `IDH_HTTP_PORT` / `IDH_AGENT_PORT`). Agent dials host through `adb reverse`; `dev_up.sh` sets both tunnels. New-machine repro order: `fetch_qbdi` → `build_agent` → `build_detect` → `dev_up` → `verify_all`.

There is no separate lint step. `AGENTS.md` (for Codex) is kept in sync with this file apart from the header line — mirror any change into both.

## Test device (available now)

- `adb` serial `13f54a46` — OnePlus PGP110, **Android 15 / SDK 35**, `arm64-v8a`, **rooted** (`su` → uid=0), `ro.debuggable=0`.
- **Multiple identical PGP110 units are attached** (`13f54a46` + others). adb commands without `-s` fail with "more than one device" — `export ANDROID_SERIAL=13f54a46` so every adb call (incl. the `tools/*.sh` scripts) targets the right unit.
- Keep **per-API-level ART resolvers**; the ART-structure dex resolver (L.6) must handle **SDK 35** (this device). SDK 36 (Pixel 6 Pro) is a secondary target, not attached now.
- Primary agent ABI is `arm64-v8a`.
- This OnePlus/ColorOS ROM ships a **heavily stripped `libart.so`** (~68% of LSPlant's required ART symbols removed) — **LSPlant Java-method hooking (WS-A) is blocked on this device**; verify it on a stock/AOSP device (Pixel) instead. Non-LSPlant capabilities are unaffected.

## Boundaries

- Authorized targets only. Anti-anti-debug "resilience" (module S) is diagnostic + survival for authorized analysis; default off, no self-hiding by default, dangerous ops need confirmation.
- Never commit captured target data (keys, plaintext, dumps). `.gitignore` excludes `captures/`, `dumps/`, `idhd-data/`.
