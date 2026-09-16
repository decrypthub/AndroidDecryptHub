# ADH Daemon (daemon/src/) — MAP

ADH Daemon / `adhd` (Node 24 + TypeScript, runs `.ts` directly, no build step). HTTP/WS `8088`, agent TCP `8761`, automation TCP `8763` (loopback + adb reverse). App pin: `GET /<package>` and `POST /<package>/mcp`.

## Module layout (post-split)

| File | Role | Imports |
|---|---|---|
| `config.ts` | **Process configuration.** ADH port env vars plus Host LAN/local Web UI URL discovery. | node only |
| `state.ts` | **Shared state + leaf helpers.** All registries (`sessions`/`dumps`/`agentSockets`/`pending`), `events`+`recordEvent`, `settings`+`mergeSettings`/`saveSettings`/`configStats`, capture store (`captures`/`captureTimers`/`capStats`/`captureHealth`), classification (`hexToPreview`/`categoryOf`/`classify`/`cryptoIdentify`), `SANDBOX`/`captureModules`, infra (`wss`/`broadcast`/`log`/`readBody`), framing (`frameJson`/`FRAME_JSON`/`FRAME_MAX`). **Imports nothing from service/mcp/index** (no cycles). | node + ws only |
| `service.ts` | **Service layer.** Agent-command transport (`sendCmd`/`agentCmd`/`pickSid`), dump engine (`readMem`/`reconstructSo`/`repairDexHeader`/`dumpRegion`/`dumpBuf`/`dumpBufPath`/`modulesFromMaps`), capture ops (`withCaptureSuspended`/`startCaptureLoop`/`dumpAllDex`/`autoDumpDex`/`applyCaptureEnabled`). `capSeq` is service-local (`++`'d in `startCaptureLoop` — can't reassign an imported binding in ESM). | `state.ts`, `dex.ts`, node |
| `mcp.ts` | **MCP Server (JSON-RPC).** `MCP_TOOLS` registry (single array — **add a tool = add one entry**) + `handleMcp`. Handlers delegate to `service.ts` primitives + `state.ts` reads + DEX/index/analysis layers. | `state.ts`, `service.ts`, `dex.ts`, `dex_index.ts`, `analysis.ts` |
| `automation.ts` | **Optional phone automation transport.** Loopback-only NDJSON bridge for the user-enabled Manager AccessibilityService; exposes observe/act/status commands to MCP. No device-side HTTP/MCP/analysis. | — |
| `http/router.ts` | **REST composition and first-match dispatch.** Creates request context, concatenates route domains in stable order, then `/<package>` dashboard + `POST /<package>/mcp` pin, then 404. | `http/routes_*.ts`, `mcp.ts` |
| `http/routes_system.ts` | Health, MCP, captures/events, settings, destructive data lifecycle, diagnostics, agent registry, `/wechat-follow.png`, `/raven.svg`/`/raven.png`/`/favicon.ico`, and `/api/mcp/config` (direct HTTP MCP endpoint metadata) | `config.ts`, `state.ts`, `service.ts`, `mcp.ts` | — also serves `GET /api/backends` (injection-backend matrix: sessions by entry + host-side Frida Gadget cache; read-only, the daemon has no adb).
| `http/routes_runtime.ts` | Live agent execution routes: maps, object/JNI/ART, hook/trace, filesystem, memory, trigger, and unpack commands. | `state.ts`, `service.ts` |
| `http/routes_analysis.ts` | Host native/DEX analysis, module reconstruction, dump download, and dashboard routes. | `state.ts`, `service.ts`, `dex.ts`, `dex_index.ts`, `analysis.ts` |
| `index.ts` | **Boot + agent-TCP frame decode only.** Owns `agentServer`/`httpServer`/WS upgrade/listen/SIGINT and delegates HTTP requests to `http/router.ts`. | `config.ts`, `state.ts`, `service.ts`, `http/router.ts` |
| `dex.ts` | Pure DEX parser/rebuilder plus proto/field/code analysis (`parseDex`/`analyzeDexCode`/`searchDex`/`extractMethodCode`/`invokeXref`/`cryptoScan`/`analyzeCoverage`/`rebuildStandardDex`/`recoverFromSnapshots`/`stripMethodCode`). No daemon state. | — |
| `dex_index.ts` | WS-F persistent SQLite index keyed by DEX SHA/size/parser version: strings and callers, fields and read/write sites, methods, call edges, and `Class.forName` targets. | `state.ts`, `dex.ts`, node:sqlite |
| `analysis.ts` | Host-side ELF analysis shelling out to NDK llvm tools (`analyzeSo`/`cryptoConstScan`/`svcScan`/`disasmSo`/`OBJDUMP`). | — |

**Import graph is one-directional**: `state ← service ← mcp/http/index`; `dex_index` depends only on `state` + pure `dex`; `analysis` stays pure. No circular refs.

## Why the split (was: one 1585-line `index.ts`)

Adding a crypto hook once meant reading the whole file; the REST surface was inline `if(pathname===)` blocks. State, service, MCP, and the three HTTP route domains are now separate, while `router.ts` preserves one ordered table and one matching implementation.

## Adding a new capability

- **MCP tool**: add one `{ name, description, inputSchema, handler }` to `MCP_TOOLS` in `mcp.ts`; optional groups can filter `tools/list` (see automation tools). Handler calls `agentCmd`/`dumpBuf`/`dumpRegion`/… from `service.ts`. Done — `tools/list` + `tools/call` pick it up automatically.
- **REST route**: add one table entry to the owning `http/routes_*.ts` domain. Preserve domain composition order in `http/router.ts` when paths overlap.
- **Agent command op**: handled in the agent C `command_loop` (Phase 3 — table-driven after refactor).

## Known flake (pre-existing, in `service.ts` reconstructSo path)

`verify_v08_disasm`/`verify_v08_analyze` intermittently report `exports=0` on the memory-reconstructed `.so`: `readMem` breaks early on a short first chunk (`service.ts` `readMem`), truncating a PT_LOAD and dropping the dynamic segment. Passes on re-run. Fix candidate: read each PT_LOAD segment boundary precisely rather than assuming contiguous.

### backends.ts (module W)

Shared injection-backend matrix: ackendMatrix() (sessions by entry, host-side Frida Gadget cache, device-side backend pointers) and classifySession() (which paths are really loaded in one target, from the agent's own maps). Used by REST GET /api/backends AND the MCP tool ackends — one implementation, two surfaces.
