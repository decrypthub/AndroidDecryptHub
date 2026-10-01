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
| `bootstrap/mem_read.c` | The one memory-read backend. `/proc/self/mem` when the target allows it, otherwise a bounds-checked direct copy inside a short signal guard (a target that makes itself non-dumpable makes `open("/proc/self/mem")` fail with EACCES even for itself, which used to kill read/search/scan/dump/art_dexfiles together). Owns the fd — released at the end of each command so no standing `/proc/self/mem` descriptor is left in the target — and reports which route answered (`adh_mem_backend_name`). A target that refuses the fd cannot be produced on demand, so `mem_backend` can FORCE the direct route session-wide: `adh_mem_fd()` then answers -1 and every call site (read / search / scan_magic / art.c / trace) takes the direct branch with no per-site change, which is how the fallback gets covered for commands other than `read`. Nothing else in the agent may open `/proc/self/mem` |
| `bootstrap/fs.c` | Directory listing and file-read commands |
| `capture/capture.c` | Crypto/TLS/file/system wrappers, bounded capture buffers, Java reporter, and the capture command family (`capture_start`/`capture_stop`/`capture_drain`) + `file_probe`/`got_enum` recon. The one-shot probe commands that hardcoded a target trigger (`crypto_hook_test`, `net_hook_test`, `file_hook_test`, `flow_watch`, `detect_watch`, `inline_crypto_test`, `crypto_probe`) were deleted on 2026-10-01 — the persistent capture set + the caller-side trigger replaced them |
| `hook/got.c` (self-identity) | `adh_self_module_name()` derives our own module name from `dladdr` instead of hardcoding `libadh_agent.so` (GOT self-test / stealth pool own-GOT lookup / footprint counter keep working when the agent is loaded from a memfd). `adh_self_image_bounds()`/`adh_image_bounds_of()` give our image's address range (min/max PT_LOAD): our own mappings are recognised by *address*, because a memfd agent's name (`jit-cache`) is also ART's JIT-cache name. `adh_self_build_id()`/`adh_build_id_of()`/`adh_build_id_from_phdr()` read the GNU build ID out of PT_NOTE in memory - the exact identity for "another copy of this same .so", used by the single-instance guard so a coincidental span match on an unrelated module can no longer suppress the agent (span stays as the no-build-ID fallback) |
| `hook/got.c` | ELF relocation parsing, GOT slot replacement, in-memory symbol lookup, and GOT self-test |
| `hook/slot_hooks.c` | Pointer-slot ("vtable") backend (covers object vcalls: vptr -> RELRO table -> `ldr/ldr/blr`, and writable callback pointers with `slotsWritable`): rewrites 8-byte DATA slots that hold the target address (virtual dispatch tables, callback tables, GOT entries) so indirect calls are intercepted with zero code changes; scans readable non-exec ranges by scope, labels each slot `got` (GLOB_DAT/JUMP_SLOT relocation) or `data`, reuses the verified thunk emitter (no BL-range limit for a pointer call) and the RELRO-safe pointer swap, and restores every slot bit-exactly on unhook |
| `hook/site_hooks.c` | Call-site ("sites") backend: rewrites the `B`/`BL` call sites that reach a function (own module by default, other modules with `scope`; one level of PLT/tail-call resolution) to hand-encoded arm64 thunks on per-site memfd pages within ±128 MB, so the target entry stays byte-identical. Matching the original instruction form (`b` vs `bl`) is required, every emitted thunk is self-checked before installation, and the patch is fully reversible (own patcher, no Dobby state) |
| `hook/stealth_pool.c` | Opt-in trampoline-pool camouflage for authorized anti-detection work: swaps this module's own RELRO GOT slot for `mmap`, so Dobby's arenas land in a `memfd:jit-cache` mapping instead of an anonymous executable page (thread-local redirect window around the Dobby calls, always falls back to the real `mmap`, reports its errno honestly) |
| `hook/native_inline_dobby.cpp` | Dobby native inline-hook backend |
| `hook/native_hooks.cpp` | Unified native hook registry (status carries MECHANISM, not just counters: for `mode=got` it reports `slot`/`slotsPatched`/`slotCurrent`/`pageProtRestored`+`pagePermsBefore/Now`/`installedAtMs`/`firstHitMs` and a `verdict` of `fired` vs `installed-never-fired`, because address/target/original are all the same pre-patch slot VALUE and `hits:0` used to be ambiguous between "never fired" and "no traffic"): GOT/inline/address install (prologue snapshot + patch verification), arm64 register-capture stubs, NATIVE_HOOK events (x0-x8/x18 + x29/x30, and with `backtrace:true` the caller chain captured AT THE HIT by walking the thread x29 chain inside its own stack bounds), soft unhook by default and opt-in hard unhook (writes the saved original bytes back, frees the slot, leaves the Dobby pool untouched) |
| hook/java_lsplant.cpp (hook_all) | `action=hook_all` installs every method of a class in one call (optional name/params filters, "*" = any): it collects declared + inherited members (keyed on name AND params, so foo(int)/bar(int) both land), installs each through the ordinary single-hook path, and returns hookIds plus the matched count so a slot-limited batch is visible |
| hook/java_lsplant.cpp | LSPlant v6.4 ART hook shim (optional static link over the same Dobby backend): methods incl. inherited ones (superclass-chain resolution, declaring class reported) and constructors (`method: "<init>"`, ctor-argument observation, skip/override rejected). `stack:true` makes `AdhJavaHookBridge` capture a bounded caller chain at the hit (app frames only, plumbing filtered) that every JAVA_HOOK event and the per-hook status report |
| `runtime/actions.c` | Safety-gated Java trigger, explicit in-process `.so` loading, and the typed `native_call` active-call command (integer/pointer args in x0-x7, `f:`/`d:` args in s0-s7/d0-d7) |
| `runtime/fp_call.S` | AAPCS64 trampoline for `native_call`: loads x0-x7 from the integer bank and d0-d7 from the FP bank, calls the target and writes the d0 return through the caller's out-pointer (a per-call slot, not a global, so concurrent calls cannot cross). Must stay assembly: a naked C version loses the argument registers under -O3, and x3 has to be parked because it is caller-saved |
| `runtime/art.c` | ClassLoader-cookie enumeration and per-API ART DexFile structural resolution |
| `runtime/inspection.c` | Live-object reflection, JNI/runtime compatibility probes, and the bootstrap/current injection-footprint counters |
| `runtime/java_enum.cpp` | Live-class reflection: enumerate class metadata/constructors/overloaded methods/fields and actively invoke static or field-backed instance methods |
| `runtime/jni.c` | JavaVM discovery, native-thread attach/detach, and app ClassLoader access. The VM is normally handed over by `JNI_OnLoad`; when it is not (a real injected target, where the agent is mapped from a memfd and the linker refuses `dlopen("libart.so")` for namespace `"(default)"`), `JNI_GetCreatedJavaVMs` is taken out of the already-loaded libart.so by in-memory symbol lookup, with dlopen only as a last resort |
| `runtime/jni_hooks.c` | Global JNIEnv->RegisterNatives hook and bounded JNI_NATIVE registration events |
| `runtime/jni_env_hooks.c` | JNIEnv function-table per-entry hooks: the thirteen fixed entries (member IDs, byte-array read + in-place writeback, primitive-array critical pair) plus every Call*Method / NewObject family and all three JNI forms (varargs / V / A) — 76 slots total — with resolved member labels, rendered arguments, wildcard install ("*" / prefix*), ABI-guarded slot offsets, bounded JNI_ENV events and a per-slot `last` snapshot with bounded JNI_ENV events, reactivation and clean slot restore |
| `runtime/jni_method_names.c` | jmethodID -> "<class>#<name><signature>" resolution for the Call* hooks (reflection over the receiver chain, mid-keyed cache, capped scans) |
| `runtime/jni_onload.c` | JNI_OnLoad work: already-loaded module discovery, inline hook with prologue snapshot, manual invocation, real unhook (restores the bytes), plus the load-time watch state consumed by `runtime/dlopen_watch.c` (skip/return replacement of a load-time call) |
| `runtime/dlopen_watch.c` | Lazily-installed dlopen/`android_dlopen_ext` hook that offers every freshly mapped module to the JNI_OnLoad watch, so the patch is in place before the VM calls it |
| `trace/commands.c` | QBDI command response handling (`qbdi_trace`). The one-shot function tracer (`trace_run`) was deleted on 2026-10-01: `native_hook mode=got` + `java_call` + `native_backtrace`/`trace_digest` cover it without hardcoding a target trigger |
| `trace/qbdi_trace.c` | Optional runtime-loaded QBDI instruction trace |

## Naming

`libadh_agent.so` is the single shipped agent name; the exported entry point is `adh_agent_start`. New code, commands, logs, and UI copy use `ADH` / `adh_*`. The fixed `com.idh.probe` / `IDH_PROBE_OK` fixture is intentionally hash-bound.

## Phase 3 extraction rule

Move one capability domain at a time and preserve command names and response schemas. A new module exposes a narrow header, is added to `agent/CMakeLists.txt`, and must pass `tools/build_agent.sh` plus its focused acceptance script before the next domain moves.

Phase 3 domain extraction is complete. Further bootstrap work should focus on table-driven RPC dispatch, not moving isolated helper functions solely to reduce line count.

## Versioning

`AGENT_VER` in `bootstrap/agent_internal.h` must equal `version` in `injector/zygisk/module/module.prop`:
the module ships this `.so`, so "which agent is flashed" and "which module is flashed" cannot have two
different answers. It is reported by `compat_probe` (and in the hello) so a session can be checked against
the build you think you flashed. Both the module zip and the agent must be rebuilt/reflashed together.

## Release footprint

- `tools/build_agent.sh` keeps `libadh_agent.so.debug` locally and stages only a stripped `.so`.
- `exports.map` restricts `.dynsym` to `JNI_OnLoad`, `adh_agent_set_package`, and `adh_agent_start`.
- `compat_probe` reports bootstrap vs current exec/anon-exec/RWX counters; base injection and GOT hooks must not add true anonymous executable pages.
