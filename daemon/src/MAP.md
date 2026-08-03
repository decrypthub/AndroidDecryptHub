# ADH Daemon (daemon/src/) — MAP

ADH Daemon / `adhd` (Node 24 + TypeScript, runs `.ts` directly, no build step). Legacy internal name: `idhd`. HTTP/WS `8760`, agent TCP `8761`.

## Module layout (post-split)

| File | Role | Imports |
|---|---|---|
| `state.ts` | **Shared state + leaf helpers.** All registries (`sessions`/`dumps`/`agentSockets`/`pending`), `events`+`recordEvent`, `settings`+`mergeSettings`/`saveSettings`/`configStats`, capture store (`captures`/`captureTimers`/`capStats`/`captureHealth`), classification (`hexToPreview`/`categoryOf`/`classify`/`cryptoIdentify`), `SANDBOX`/`captureModules`, infra (`wss`/`broadcast`/`log`/`readBody`), framing (`frameJson`/`FRAME_JSON`/`FRAME_MAX`). **Imports nothing from service/mcp/index** (no cycles). | node + ws only |
| `service.ts` | **Service layer.** Agent-command transport (`sendCmd`/`agentCmd`/`pickSid`), dump engine (`readMem`/`reconstructSo`/`repairDexHeader`/`dumpRegion`/`dumpBuf`/`dumpBufPath`/`modulesFromMaps`), capture ops (`withCaptureSuspended`/`startCaptureLoop`/`autoDumpDex`/`runUnpackSession`/`applyCaptureEnabled`). `capSeq` is service-local (`++`'d in `startCaptureLoop` — can't reassign an imported binding in ESM). | `state.ts`, `dex.ts`, node |
| `mcp.ts` | **MCP Server (JSON-RPC).** `MCP_TOOLS` registry (single array — **add a tool = add one entry**) + `handleMcp`. Handlers delegate to `service.ts` primitives + `state.ts` reads + `dex.ts`/`analysis.ts` pure layer. | `state.ts`, `service.ts`, `dex.ts`, `analysis.ts` |
| `index.ts` | **Boot + agent-TCP frame decode + REST routing (table-driven `handleHttp`).** `lanIPv4s`/`webUrls`, `httpServer`/`agentServer`/`ws upgrade`/`SIGINT`. `ROUTES` table: `{method?, path, handler, prefix?}` + first-match loop + 404 fallback. **Add a REST route = add one table entry.** | `state.ts`, `service.ts`, `mcp.ts`, `dex.ts`, `analysis.ts` |
| `dex.ts` | Pure DEX parser/rebuilder (`parseDex`/`searchDex`/`extractMethodCode`/`invokeXref`/`cryptoScan`/`analyzeCoverage`/`rebuildStandardDex`/`recoverFromSnapshots`/`stripMethodCode`). No daemon state. | — |
| `analysis.ts` | Host-side ELF analysis shelling out to NDK llvm tools (`analyzeSo`/`cryptoConstScan`/`svcScan`/`disasmSo`/`OBJDUMP`). | — |

**Import graph is one-directional**: `state ← service ← mcp/index`, plus `dex`/`analysis` as pure leaves. No circular refs.

## Why the split (was: one 1585-line `index.ts`)

Adding a crypto hook meant reading the whole file; the REST surface was inline `if(pathname===)` blocks (no route table). The split moves state + service + MCP out so an edit to one concern stays in one file. The route-table conversion of `handleHttp` is the remaining step (tracked in PROGRESS).

## Adding a new capability

- **MCP tool**: add one `{ name, description, inputSchema, handler }` to `MCP_TOOLS` in `mcp.ts`. Handler calls `agentCmd`/`dumpBuf`/`dumpRegion`/… from `service.ts`. Done — `tools/list` + `tools/call` pick it up automatically.
- **REST route**: currently add an `if (url.pathname === …)` block in `handleHttp` (`index.ts`). (Route-table conversion pending.)
- **Agent command op**: handled in the agent C `command_loop` (Phase 3 — table-driven after refactor).

## Known flake (pre-existing, in `service.ts` reconstructSo path)

`verify_v08_disasm`/`verify_v08_analyze` intermittently report `exports=0` on the memory-reconstructed `.so`: `readMem` breaks early on a short first chunk (`service.ts` `readMem`), truncating a PT_LOAD and dropping the dynamic segment. Passes on re-run. Fix candidate: read each PT_LOAD segment boundary precisely rather than assuming contiguous.
