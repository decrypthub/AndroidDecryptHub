# AndroidDecryptHub

[中文](README.md) | English

AndroidDecryptHub (**ADH**) is an open-source workbench for **authorized Android runtime reverse analysis**. A small agent inside the target process handles hooks, capture, tracing, and dumps. The Host ADH Daemon (`adhd`) handles storage, DEX indexing, disassembly, the Web viewer, and MCP. Its iOS counterpart is [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub).

This repository is a **source snapshot**, with no installable Release attached. Zygisk is the official injection path. Frida Gadget, Xposed, and eCapture are development or experimental backends. The shipped architecture is `arm64-v8a` only. ART structure resolution has mainly been validated on Android SDK 35, with secondary validation on SDK 36. Results depend on the target's ROM, protections, and actual call paths.

## Capabilities

- Java, JNI, and native hooks, including GOT, inline, call-site, and pointer-slot backends.
- Persistent crypto, TLS plaintext, file, and system-behavior capture, with explicit loss and truncation reporting.
- Memory search and dump, ART DEX enumeration, SO reconstruction, DEX repair, and method-body recovery.
- Persistent DEX index, search, xrefs, reflection clues, Capstone disassembly, and algorithm signatures.
- Read-only Web viewer, REST/MCP, and the `adh doctor`, `adh target`, and `adh unpack` commands.

The current crypto-to-TLS join uses **same-thread and time-window co-occurrence**. It does not prove that two records contain the same data; deterministic content correlation remains to be implemented. QBDI is optional. See [the MCP tool list](docs/mcp-tools.md).

## Architecture

```text
Target app    libadh_agent.so       hook / capture / trace / dump
Device        Zygisk + ADH Manager  injection scope, module status, process control
Host          adhd                  HTTP / WebSocket / MCP / DB / analysis
Browser       Web viewer            observe, search, export
```

The agent does not run HTTP, a database, or heavy analysis. The wire contract is in [proto/PROTOCOL.md](proto/PROTOCOL.md).

## Build and run

You need Android SDK (compileSdk 36), NDK `28.2.13676358`, CMake, JDK 17, Node.js 24, and a **dedicated rooted arm64 test device** for device acceptance. The scripts support Windows/Git Bash and Linux. Set `ANDROID_SDK_ROOT` and `ANDROID_NDK_HOME`, then follow the [build guide](docs/BUILDING.md).

```bash
bash tools/fetch_dobby.sh
bash tools/fetch_lsplant.sh   # optional Java method-hook backend
bash tools/build_agent.sh
bash tools/build_bundle.sh
```

Start the Host ADH Daemon:

```bash
cd daemon
npm ci
npm start
```

The default HTTP/WebSocket/MCP port is `8088`; agent TCP uses `8761`. From `daemon/`, run `node src/cli.ts doctor` or use `target --help` and `unpack --help`. Host unit tests run with `node --test test/*.test.ts`. `tools/verify_all.sh` controls the connected device, so run it only with an explicitly selected, dedicated test device.

## Safety and license

Use ADH only on apps you own or are authorized to examine. It does not provide legal chain-of-custody guarantees. Keep captured keys, plaintext, and dumps private; `captures/`, `dumps/`, and `adhd-data/` are Git-ignored.

**Host HTTP `8088` and agent TCP `8761` currently listen on all interfaces without authentication.** Run them only on a trusted or isolated network; do not expose them to the public internet. See [security boundaries](docs/SECURITY.md).

The original project source is [MIT-licensed](LICENSE). Fetched third-party dependencies retain their own licenses, including LSPlant's LGPL-3.0; see [NOTICE](NOTICE).
