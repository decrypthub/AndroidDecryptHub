# ADH (Android DecryptHub) — As-Built Architecture

> This documents what is **implemented and verified** (see `tools/verify_all.sh`),
> not the aspirational spec. Spec: `REQUIREMENTS.md`. Progress: `PROGRESS.md`.

## Layers (red line honored)

```
Target app process            libidh_agent.so     collect / execute only
  (device, arm64)             ── framed TCP ──►   hook · trace · dump · maps · JNI reflect
                              (via adb reverse)
Device (phone)                device/             scope Manager (Compose) + Device Daemon (AIDL)
                              injector/zygisk     Magisk early-inject by allowlist
Host daemon                   ADH Daemon (adhd)   analysis · storage · HTTP · WS · MCP
Browser / AI client           Web console / MCP   observe · search · drive
```

- **Agent** (`agent/`, C + NDK): loaded via `System.loadLibrary` (模拟注入) or Zygisk injector.
  Dual entry `JNI_OnLoad` / `adh_agent_start` (`idh_agent_start` legacy alias). Connects to **Host** ADH Daemon over TCP `127.0.0.1:8761`
  (reachable from device via `adb reverse`). Executes commands, streams results. No HTTP/DB.
- **Host ADH Daemon** (`daemon/`, npm `adhd`, Node 24 + TypeScript, no build step; legacy name `idhd`):
  agent registry, HTTP+WS `8760`, REST API, MCP server, dex parser/indexer, ELF analysis, dump storage.
- **Device surface** (`device/` multi-module, Gradle 8.9 / AGP 8.7.3 / Compose):
  - `:core` — `AdhPaths` / `ScopeConfig` / `ScopeJson` + shared `IAdhScopeService` contract
  - `:daemon` — module-launched root `app_process` APK; scope/module-state Binder only (**not** Host analysis)
  - `:manager` — ordinary Compose APK; receives the daemon Binder through a root-only provider handshake and never invokes `su`
- **Web/MCP**: `daemon/public/index.html` console; `POST /mcp` for AI clients.
- **Injector** (`injector/zygisk/`): Magisk module zip; starts Device Daemon at boot and packages its APK; path constants must stay in sync with `device/:core`.

Do **not** confuse **Host ADH Daemon** (`daemon/` on PC) with **Device Daemon** (`device/:daemon` on phone).
## Wire protocol (agent ↔ idhd), NDJSON

- agent→idhd: `hello` (identity), `maps` (sample), `cmdResult` (per command).
- idhd→agent: `ack`, `cmd {id, op, ...}`. idhd `sendCmd()` awaits the matching `cmdResult`.
- Large payloads (dumps) are chunked via `read` and assembled + hashed in idhd.

## Agent commands (collect/execute)

`maps · read · search · scan_magic · art_dexfiles · jni_probe · gothook_selftest ·
crypto_probe · crypto_hook_test · net_hook_test · flow_watch · detect_watch ·
compat_probe · trace_run · object_inspect · object_invoke`

Core primitives reused across commands: `got_replace()` (GOT/PLT hook engine, single RELRO
slot + trampoline), `resolve_sym()` (in-memory dynsym, namespace-independent),
`load_app_class()` (app classloader reflection), `capture`/`trace` buffers (mutex, tid+ts),
tagged-pointer untagging for `pread(/proc/self/mem)`.

## idhd analysis (heavy work)

- **Dump engine**: maps, memory read/search/scan_magic, region dump + sha256 dedup,
  SO reassembly (SoFixer-lite), dex header repair.
- **Dex**: parser (string/type/method/class), search, invoke-xref (Dalvik width table,
  0% desync over 21820 methods), crypto static scan, method code_item extraction.
- **Native**: llvm-objdump disasm, llvm-readelf analyze, crypto-constant scan, svc scan.
- **Correlation**: crypto captures ↔ network captures by thread + time window.

## Verified capability map (module → verify script)

| Capability | Verify |
|---|---|
| skeleton + 模拟注入 + maps == kernel | verify_v01 |
| dump: read/scan/search/dump+dedup/so-reassembly/dex-repair | verify_v02* |
| ART structural dex capture (byte-exact) | verify_v03 |
| crypto static + **plaintext-boundary AES capture** | verify_v04_* |
| GOT hook engine (intercept+trampoline) | verify_v04_gothook |
| anti-analysis observation + compat diagnostic | verify_v05_detect |
| Runtime Object Inspector (field read + invoke) | verify_v06 |
| **TLS plaintext capture** + **network↔crypto correlation** | verify_v07* |
| dex search / xref / native disasm / analyze | verify_v08_* |
| native crypto-const / direct-syscall / method-body recovery | verify_v09_* |
| MCP server / Web console / function trace / export | verify_v10_* |

## Build & verify

```
tools/build_agent.sh     # NDK cmake -> libidh_agent.so (fails loudly on error)
tools/build_detect.sh    # sandbox native mock lib
tools/dev_up.sh          # ensure idhd + adb reverse
tools/verify_all.sh      # run every acceptance (device checks auto-skip if offline)
```

Device: Pixel 6 Pro, Android 16 / SDK 36, arm64-v8a, rooted.
