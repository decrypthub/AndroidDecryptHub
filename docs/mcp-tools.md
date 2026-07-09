# IDH MCP Tools

Generated from the live idhd registry (25 tools). Endpoint: `POST /mcp` (JSON-RPC 2.0).

| Tool | Description | Args |
|---|---|---|
| `process_list` | List connected target agent sessions | — |
| `dumps_list` | List captured dump artifacts (dex/so/region) | — |
| `compat_probe` | Self-assess agent env: tracer/seccomp/hook-backend availability | session |
| `memory_maps` | On-demand full /proc/self/maps of the target | session |
| `memory_read` | Read target memory at hex addr for size bytes (base64 out) | session, addr, size |
| `memory_search` | Search target memory for hex or text pattern | session, hex, text, limit |
| `memory_scan_magic` | Scan target memory for dex/elf/oat/vdex/zip magics | session |
| `art_dexfiles` | Enumerate loaded DexFiles via ART ClassLoader structures (no magic scan) | session |
| `crypto_capture` | Hook EVP_CipherUpdate + trigger sandbox AES; return captured plaintext | session |
| `net_capture` | Hook SSL_write/SSL_read + trigger HTTPS; return captured TLS plaintext | session |
| `detect_watch` | Observe the target’s own anti-analysis checks (debug/root/prop) | session |
| `object_inspect` | Read a live Java object’s fields via reflection (static field path) | session, className, field |
| `dex_search` | Search a dex (b64|sha) for strings/classes/methods | b64, sha, query, kinds |
| `dex_xref` | Find callers of a method in a dex (b64|sha) | b64, sha, method |
| `dex_crypto_scan` | Static crypto scan of a dex (API refs + algorithm strings) | b64, sha |
| `native_disasm` | Disassemble an ELF .so (b64|sha) by symbol | b64, sha, symbol |
| `native_analyze` | Exports/imports/NEEDED/strings of an ELF .so (b64|sha) | b64, sha |
| `native_crypto_const` | Locate crypto by constant signatures in a stripped .so (b64|sha) | b64, sha |
| `native_syscall_scan` | Find direct svc #0 syscalls in a .so (b64|sha) | b64, sha |
| `memory_dump` | Dump target memory [addr,addr+size) to a capture artifact (sha256 dedup) | session, addr, size |
| `flow_correlate` | Hook EVP+SSL_write, trigger encrypt-then-send, capture plaintext+request (tid/ts) | session |
| `object_invoke` | Call a no-arg method on a live object (via static field path) | session, className, field, method |
| `trace_function` | Trace calls to a native symbol (args+tid+ts) during Detection.run() | session, symLib, symbol, hookModule |
| `dex_method_code` | Extract a method’s runtime code_item bytecode from a dex (b64|sha) | b64, sha, class, method |
| `dex_repair` | Repair a dumped dex header (file_size/checksum/signature) | b64, sha |
