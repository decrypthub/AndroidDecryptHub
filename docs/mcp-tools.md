# ADH MCP Tools

Generated from the live ADH Daemon registry (47 tools). Endpoint: `POST /mcp` (JSON-RPC 2.0).

| Tool | Description | Args |
|---|---|---|
| `process_list` | List connected target agent sessions | — |
| `backends` | Injection-backend matrix: sessions by entry, host-side Frida Gadget cache + loader command, device-side backend pointers. Pass session to classify which injection paths are really loaded in that process (zygisk / xposed_module / frida_gadget / self_load). | session |
| `dumps_list` | List captured dump artifacts (dex/so/region) | — |
| `compat_probe` | Self-assess agent env + injection footprint: tracer/seccomp/backends/exec/anon/rwx | session |
| `memory_maps` | On-demand full /proc/self/maps of the target | session |
| `memory_read` | Read target memory at hex addr for size bytes (base64 out) | session, addr, size |
| `memory_search` | Search target memory for hex or text pattern | session, hex, text, limit |
| `memory_scan_magic` | Scan target memory for dex/elf/oat/vdex/zip magics | session |
| `art_dexfiles` | Enumerate loaded DexFiles via ART ClassLoader structures (no magic scan) | session |
| `crypto_capture` | Hook EVP_CipherUpdate + trigger the target’s crypto workload class; return captured plaintext | session, class |
| `net_capture` | Hook SSL_write/SSL_read + trigger HTTPS; return captured TLS plaintext | session, class |
| `file_probe` | Recon which loaded module’s GOT holds open/openat/read/write/close pointers (guides file_capture’s module arg) | session |
| `file_capture` | Hook open/openat/read/write/close + trigger the target’s file I/O; return captured paths + read/write bytes | session, module, class |
| `detect_watch` | Observe the target’s own anti-analysis checks (debug/root/prop) | session, module, class |
| `object_inspect` | Read a live Java object’s fields via reflection (static field path) | session, className, field |
| `dex_search` | Search a dex (b64|sha) for strings/classes/methods | b64, sha, query, kinds |
| `dex_index` | Build or reuse the persistent SQLite index for a dex (b64|known dump sha) | b64, sha |
| `dex_index_search` | Search an indexed dex for strings, string callers, classes, fields, methods and reflection targets | sha, query, limit |
| `dex_reflections` | List statically resolved Class.forName targets and their callers from an indexed dex | sha, limit |
| `dex_xref` | Find callers of a method in a dex (b64|sha) | b64, sha, method |
| `dex_crypto_scan` | Static crypto scan of a dex (API refs + algorithm strings) | b64, sha |
| `native_disasm` | Disassemble an ELF .so (b64|sha) by symbol | b64, sha, symbol |
| `native_analyze` | Exports/imports/NEEDED/strings of an ELF .so (b64|sha) | b64, sha |
| `native_crypto_const` | Locate crypto by constant signatures in a stripped .so (b64|sha) | b64, sha |
| `native_syscall_scan` | Find direct svc #0 syscalls in a .so (b64|sha) | b64, sha |
| `memory_dump` | Dump target memory [addr,addr+size) to a capture artifact (sha256 dedup) | session, addr, size |
| `flow_correlate` | Hook EVP+SSL_write, trigger encrypt-then-send, capture plaintext+request (tid/ts) | session |
| `object_invoke` | Call a no-arg method on a live object (via static field path) | session, className, field, method |
| `trace_function` | Trace calls to a native symbol (args+tid+ts) while the target’s detection workload runs | session, symLib, symbol, hookModule, class |
| `dex_method_code` | Extract a method’s runtime code_item bytecode from a dex (b64|sha) | b64, sha, class, method |
| `dex_repair` | Repair a dumped dex header (file_size/checksum/signature) | b64, sha |
| `crypto_identify` | 一眼看清目标 App 用了哪些加密算法/密钥/IV — summarize all captured crypto (algorithm, key, iv, plaintext) into a plain-language report for non-experts | — |
| `live_captures` | List the live captures streamed by the persistent hooks — crypto / net(TLS) / file / system, filterable by category (algorithm+op+preview, newest last) | limit, category |
| `capture_detail` | Full detail of one capture by id: algorithm, key(hex), iv(hex), plaintext(utf8+hex), ciphertext(hex) | id |
| `dex_coverage` | 方法恢复率报告 — per-method state (native/abstract/present/extracted) + recovery rate over a dumped dex | b64, sha |
| `dump_all_dex` | 一键 dump 当前目标进程所有已加载 DEX：ART DexFile 枚举 + 逐个 dump + SHA-256 去重 | session |
| `dex_recover` | Recover extracted CodeItems from a restored snapshot into a base dex + rebuild (baseSha/baseB64 + restoredSha/restoredB64) | baseB64, baseSha, restoredB64, restoredSha |
| `trigger` | Actively load a class (level 1) and invoke a safe static no-arg method (level 3) to force code paths — a trigger source for unpacking | session, class, method, level |
| `qbdi_trace` | QBDI instruction-level dynamic trace of a native function (per-instruction disassembly + return value) | session, symLib, symbol |
| `net_correlate` | Network↔crypto correlation: pair plaintext with the TLS request carrying its ciphertext (same thread + time window) | session |
| `load_library` | 把任意 .so 加载进目标进程（如 frida-gadget，随后 gadget 会按 script 模式自动跑你的 frida 脚本）。可选 symbol 探测。dlopen from inside the target. | session, path, symbol |
| `automation_status` | Read-only phone automation status: user toggle, bridge connection, connected device capabilities and package allowlist. This tool never enables automation. | — |
| `phone_observe` | Observe the active phone screen. Prefer the AccessibilityService node tree; when it is empty or non-semantic, fall back to a screenshot that the AI can inspect. Returns snapshotId plus nodes or an image. | mode, includeScreenshot, maxNodes, maxDepth, interactiveOnly, package |
| `phone_find` | Find compact, actionable nodes without transferring the whole tree. Supports text/resourceId/contentDescription and interaction flags; returns refs valid for snapshotId. | text, textContains, resourceId, contentDescription, contentDescriptionContains, clickable, editable, scrollable, index, limit, maxNodes, interactiveOnly, package |
| `phone_wait` | Wait for a selector to appear or disappear, optionally scrolling a virtualized list until it appears. | text, textContains, resourceId, contentDescription, contentDescriptionContains, clickable, editable, scrollable, index, gone, timeoutMs, intervalMs, scroll, direction, maxScrolls, maxNodes, interactiveOnly, package |
| `phone_act` | Act on the active phone screen. Prefer a selector or snapshotId+ref from phone_observe; use normalized coordinates only as the visual fallback. Supports tap, long_press, swipe, scroll, set_text and global back/home/recents. | text, textContains, resourceId, contentDescription, contentDescriptionContains, clickable, editable, scrollable, index, snapshotId, action, ref, x, y, x2, y2, coordinateSpace, key, direction, durationMs, observeAfter, package |
| `phone_app` | Open, stop or restart an allowlisted app by package name. Open uses the launch intent; stop/restart delegate to the authenticated root Device Daemon. | action, package |
