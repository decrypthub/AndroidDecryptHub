# Agent source map

`libidh_agent.so` stays collect/execute-only. HTTP, MCP, storage, indexing, and heavy analysis belong to the Host ADH Daemon.

## Layout

| Path | Responsibility |
|---|---|
| `bootstrap/agent_main.c` | Dual entry, lifecycle, JNI attachment, command dispatch, and capabilities not yet extracted |
| `bootstrap/agent_internal.h` | Shared bootstrap utility, transport, memory, and filesystem declarations |
| `bootstrap/util.c` | JSON, base64, property, process, and time helpers |
| `bootstrap/io.c` | Host connection and length-framed transport |
| `bootstrap/mem.c` | Maps, memory read, magic scan, and byte search commands |
| `bootstrap/fs.c` | Directory listing and file-read commands |
| `hook/got.c` | ELF relocation parsing, GOT slot replacement, in-memory symbol lookup, and GOT self-test |
| `hook/native_inline_dobby.cpp` | Dobby native inline-hook backend |
| `hook/java_lsplant.cpp` | Optional LSPlant Java-method hook backend |
| `trace/qbdi_trace.c` | Optional runtime-loaded QBDI instruction trace |

## Phase 3 extraction rule

Move one capability domain at a time and preserve command names and response schemas. A new module exposes a narrow header, is added to `agent/CMakeLists.txt`, and must pass `tools/build_agent.sh` plus its focused acceptance script before the next domain moves.

Remaining large domains in `bootstrap/agent_main.c`: capture and wrappers, JNI/object/ART commands, trigger/trace commands, and RPC dispatch/lifecycle.
