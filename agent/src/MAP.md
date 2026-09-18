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
| `hook/got.c` (self-identity) | `adh_self_module_name()` derives our own module name from `dladdr` instead of hardcoding `libadh_agent.so` (GOT self-test / stealth pool own-GOT lookup / footprint counter keep working when the agent is loaded from a memfd). `adh_self_image_bounds()` + `adh_image_span_of()` give our image's address range and PT_LOAD span: our own mappings are recognised by *address*, because a memfd agent's name (`jit-cache`) is also ART's JIT-cache name |
| `hook/got.c` | ELF relocation parsing, GOT slot replacement, in-memory symbol lookup, and GOT self-test |
| `hook/slot_hooks.c` | Pointer-slot ("vtable") backend (covers object vcalls: vptr -> RELRO table -> `ldr/ldr/blr`, and writable callback pointers with `slotsWritable`): rewrites 8-byte DATA slots that hold the target address (virtual dispatch tables, callback tables, GOT entries) so indirect calls are intercepted with zero code changes; scans readable non-exec ranges by scope, labels each slot `got` (GLOB_DAT/JUMP_SLOT relocation) or `data`, reuses the verified thunk emitter (no BL-range limit for a pointer call) and the RELRO-safe pointer swap, and restores every slot bit-exactly on unhook |
| `hook/site_hooks.c` | Call-site ("sites") backend: rewrites the `B`/`BL` call sites that reach a function (own module by default, other modules with `scope`; one level of PLT/tail-call resolution) to hand-encoded arm64 thunks on per-site memfd pages within ±128 MB, so the target entry stays byte-identical. Matching the original instruction form (`b` vs `bl`) is required, every emitted thunk is self-checked before installation, and the patch is fully reversible (own patcher, no Dobby state) |
| `hook/stealth_pool.c` | Opt-in trampoline-pool camouflage for authorized anti-detection work: swaps this module's own RELRO GOT slot for `mmap`, so Dobby's arenas land in a `memfd:jit-cache` mapping instead of an anonymous executable page (thread-local redirect window around the Dobby calls, always falls back to the real `mmap`, reports its errno honestly) |
| `hook/native_inline_dobby.cpp` | Dobby native inline-hook backend |
| `hook/native_hooks.cpp` | Unified native hook registry: GOT/inline/address install (prologue snapshot + patch verification), arm64 register-capture stubs, NATIVE_HOOK events, soft unhook by default and opt-in hard unhook (writes the saved original bytes back, frees the slot, leaves the Dobby pool untouched) |
| hook/java_lsplant.cpp | LSPlant v6.4 ART hook shim (optional static link over the same Dobby backend): methods incl. inherited ones (superclass-chain resolution, declaring class reported) and constructors (`method: "<init>"`, ctor-argument observation, skip/override rejected) |
| `runtime/actions.c` | Safety-gated Java trigger, explicit in-process `.so` loading, and the typed `native_call` active-call command (integer/pointer args in x0-x7, `f:`/`d:` args in s0-s7/d0-d7) |
| `runtime/fp_call.S` | AAPCS64 trampoline for `native_call`: loads x0-x7 from the integer bank and d0-d7 from the FP bank, calls the target and writes the d0 return through the caller's out-pointer (a per-call slot, not a global, so concurrent calls cannot cross). Must stay assembly: a naked C version loses the argument registers under -O3, and x3 has to be parked because it is caller-saved |
| `runtime/art.c` | ClassLoader-cookie enumeration and per-API ART DexFile structural resolution |
| `runtime/inspection.c` | Live-object reflection, JNI/runtime compatibility probes, and the bootstrap/current injection-footprint counters |
| `runtime/java_enum.cpp` | Live-class reflection: enumerate class metadata/constructors/overloaded methods/fields and actively invoke static or field-backed instance methods |
| `runtime/jni.c` | JavaVM discovery, native-thread attach/detach, and app ClassLoader access |
| `runtime/jni_hooks.c` | Global JNIEnv->RegisterNatives hook and bounded JNI_NATIVE registration events |
| `runtime/jni_env_hooks.c` | JNIEnv function-table per-entry hooks: the thirteen fixed entries (member IDs, byte-array read + in-place writeback, primitive-array critical pair) plus every Call*Method / NewObject family and all three JNI forms (varargs / V / A) — 76 slots total — with resolved member labels, rendered arguments, wildcard install ("*" / prefix*), ABI-guarded slot offsets, bounded JNI_ENV events and a per-slot `last` snapshot with bounded JNI_ENV events, reactivation and clean slot restore |
| `runtime/jni_method_names.c` | jmethodID -> "<class>#<name><signature>" resolution for the Call* hooks (reflection over the receiver chain, mid-keyed cache, capped scans) |
| `runtime/jni_onload.c` | JNI_OnLoad work: already-loaded module discovery, inline hook with prologue snapshot, manual invocation, real unhook (restores the bytes), plus the load-time watch state consumed by `runtime/dlopen_watch.c` (skip/return replacement of a load-time call) |
| `runtime/dlopen_watch.c` | Lazily-installed dlopen/`android_dlopen_ext` hook that offers every freshly mapped module to the JNI_OnLoad watch, so the patch is in place before the VM calls it |
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
