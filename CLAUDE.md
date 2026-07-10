# CLAUDE.md

Guidance for Claude working in this repo. Keep this file short. Only rules that are **not inferable from the code**.

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
- Build / test / lint commands: _TBD — fill in here once the build exists (e.g. `cmake`, `gradlew`, `npm`, verify scripts under `tests/`)._

## Test device (available now)

- `adb` serial `1A281FDEE003ZV` — Pixel 6 Pro, **Android 16 / SDK 36**, `arm64-v8a`, **rooted** (`su` present), `ro.debuggable=0`.
- This is a recent ART version — the ART-structure dex resolver (L.6) must target SDK 36; keep per-API-level resolvers.
- Primary agent ABI is `arm64-v8a`.

## Boundaries

- Authorized targets only. Anti-anti-debug "resilience" (module S) is diagnostic + survival for authorized analysis; default off, no self-hiding by default, dangerous ops need confirmation.
- Never commit captured target data (keys, plaintext, dumps). `.gitignore` excludes `captures/`, `dumps/`, `idhd-data/`.
