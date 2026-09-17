# Agent source map

`libadh_agent.so` stays collect/execute-only. HTTP, MCP, storage, indexing, and heavy analysis belong to the Host ADH Daemon.

## Layout

| Path | Responsibility |
|---|---|
| `bootstrap/agent_main.c` | Dual entry, first-loaded-copy owner guard, late reporter binding, hello/report, command dispatch, and lifecycle |
| `bootstrap/agent_internal.h` | Shared bootstrap utility, transport, memory, and filesystem declarations |
| `bootstrap/util.c` | JSON, base64, property, process, and time helpers |
| `bootstrap/io.c` | Host connection and length-framed transport |
| `bootstrap/mem.c` | Maps, memory read, magic scan, and byte search commands |
| `bootstrap/fs.c` | Directory listing and file-read commands |
| `capture/capture.c` | Crypto/TLS/file/system wrappers, bounded capture buffers, Java reporter, and capture/probe commands |
| `hook/got.c` | ELF relocation parsing, GOT slot replacement, in-memory symbol lookup, and GOT self-test |
| `hook/native_inline_dobby.cpp` | Dobby native inline-hook backend |
| `hook/native_hooks.cpp` | Unified native hook registry: GOT/inline/address install, arm64 register-capture stubs, and NATIVE_HOOK events |
| hook/java_lsplant.cpp | LSPlant v6.4 ART Java-method hook shim; optional static link over the same Dobby backend |
| `runtime/actions.c` | Safety-gated Java trigger and explicit in-process `.so` loading commands |
| `runtime/art.c` | ClassLoader-cookie enumeration and per-API ART DexFile structural resolution |
| `runtime/inspection.c` | Live-object reflection, JNI/runtime compatibility probes, and the bootstrap/current injection-footprint counters |
| `runtime/java_enum.cpp` | Live-class reflection: enumerate class metadata/constructors/overloaded methods/fields and actively invoke static or field-backed instance methods |
| `runtime/jni.c` | JavaVM discovery, native-thread attach/detach, and app ClassLoader access |
| `trace/commands.c` | Function-call trace state, GOT trace orchestration, and QBDI command response handling |
| `trace/qbdi_trace.c` | Optional runtime-loaded QBDI instruction trace |

## Naming

`libadh_agent.so` is the single shipped agent name; the exported entry point is `adh_agent_start`. New code, commands, logs, and UI copy use `ADH` / `adh_*`. The fixed `com.idh.probe` / `IDH_PROBE_OK` fixture is intentionally hash-bound.

## Phase 3 extraction rule

Move one capability domain at a time and preserve command names and response schemas. A new module exposes a narrow header, is added to `agent/CMakeLists.txt`, and must pass `tools/build_agent.sh` plus its focused acceptance script before the next domain moves.

Phase 3 domain extraction is complete. Further bootstrap work should focus on table-driven RPC dispatch, not moving isolated helper functions solely to reduce line count.

## Release footprint

- `tools/build_agent.sh` keeps `libadh_agent.so.debug` locally and stages only a stripped `.so`.
- `exports.map` restricts `.dynsym` to `JNI_OnLoad`, `adh_agent_set_package`, and `adh_agent_start`.
- `compat_probe` reports bootstrap vs current exec/anon-exec/RWX counters; base injection and GOT hooks must not add true anonymous executable pages.
