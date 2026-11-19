# AndroidDecryptHub

[中文](README.md) | English

AndroidDecryptHub (**ADH**) is an open-source workbench for **authorized Android runtime reverse analysis**. A small agent inside the target process handles hooks, capture, tracing, and dumps. The Host ADH Daemon (`adhd`) handles storage, DEX indexing, disassembly, the Web viewer, and MCP. Its iOS counterpart is [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub).

A flashable Zygisk bundle is available in the [v0.6.0 Release](https://github.com/decrypthub/AndroidDecryptHub/releases/tag/v0.6.0) as `adh-bundle-v0.6.0.zip`. Zygisk is the official injection path. Frida Gadget and eCapture are development or experimental backends. The shipped architecture is `arm64-v8a` only. ART structure resolution has mainly been validated on Android SDK 35, with secondary validation on SDK 36. Results depend on the target's ROM, protections, and actual call paths.

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

On a dedicated rooted device with Zygisk enabled, select the Release ZIP in Magisk → Modules → Install from storage, then reboot. The installer tries to install the bundled Manager APK. If that fails, use the module Action or extract and install `manager.apk`. Start the Host ADH Daemon on your computer and configure the target package scope in Manager. The prerelease APK uses this build's debug signing key; a future APK signed with a different key cannot update it in place. See the [build guide](docs/BUILDING.md).

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

The default HTTP/WebSocket/MCP port is `8088` and agent TCP uses `8761`. From `daemon/`, run `node src/cli.ts doctor` to check the Host and `npm test` for Host unit tests. `tools/verify_all.sh` controls the connected device, so run it only with an explicitly selected, dedicated test device.

## Upgrade and first result

1. Back up the existing Host data directory and `/data/adb/adh/` on the device, then upgrade in place with matching Host, module, and Manager versions. Use a Manager signed with the same certificate and reuse the original `ADH_DATA_DIR`. Verify the app scope in ADH Manager and the Host settings at `/workbench?view=quick-start` → **查看 Host 配置**.
2. Establish a verified [device connection](README.md#2-确认设备连接) with the companion `adh` CLI. Click **检查设备连接** and select a connection if more than one is online.
3. Click **读取诊断结果** to see the device ID, connection ID, model, and state revision. Diagnostic reads are available in observation mode. Sandbox receipts are labeled **隔离沙盒**.

To rehearse from 0.6.0-format state, build `:daemon:writeDeviceRpcFixtureClasspath` in `device/` and run `node test/fixtures/upgrade_quick_start.ts` from `daemon/`. Pass `--serve` to follow the same steps from the printed workbench URL. The rehearsal uses temporary files and a loopback JVM device. On-device package deployment and upgrade have separate acceptance checks. See the [Chinese quick start](README.md#快速开始) for commands and storage details.

## Safety and license

Use ADH only on apps you own or are authorized to examine. It does not provide legal chain-of-custody guarantees. Keep captured keys, plaintext, and dumps private; `captures/`, `dumps/`, and `adhd-data/` are Git-ignored.

**Host HTTP `8088` and agent TCP `8761` currently listen on all interfaces without authentication.** Run them only on a trusted or isolated network; do not expose them to the public internet. See [security boundaries](docs/SECURITY.md).

The original project source is [MIT-licensed](LICENSE). Fetched third-party dependencies retain their own licenses, including LSPlant's LGPL-3.0; see [NOTICE](NOTICE).
