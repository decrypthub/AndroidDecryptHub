# Building ADH from source

This repository does not ship a prebuilt agent, APK, module ZIP, or captured target data.

## Prerequisites

- Android SDK with compileSdk 36 and build tools; set `ANDROID_SDK_ROOT`.
- Android NDK `28.2.13676358` (or a compatible host NDK for the agent); set `ANDROID_NDK_HOME`.
- CMake, Ninja, JDK 17, Bash, Node.js 24, npm, and `adb`.
- A dedicated rooted `arm64-v8a` device for Zygisk and device acceptance. ART structural resolution is principally validated on SDK 35 and secondarily on SDK 36.

The Gradle wrappers are included under `device/`, `sandbox-app/`, and `injector/xposed/`. The build scripts resolve a Windows SDK layout by default and support Linux NDK tools when `ANDROID_NDK_HOME` points to them.

## Native agent and test fixture

```bash
bash tools/fetch_dobby.sh
bash tools/fetch_lsplant.sh   # optional; enables the LSPlant Java hook backend
bash tools/fetch_qbdi.sh      # optional; instruction tracing backend
bash tools/build_agent.sh
bash tools/build_detect.sh
```

`build_agent.sh` stages the stripped `libadh_agent.so` into the sandbox app's `jniLibs`. It keeps debug symbols locally and does not commit them.

## Device bundle

```bash
bash tools/build_bundle.sh
```

The bundle builder compiles the Zygisk companion, ADH Manager, and root Device Daemon. It requires a working Gradle environment and Android SDK build tools including `apksigner`, and uses local debug APK signing. Inspect and validate the ZIP before installation. There is currently no certified release artifact for this source snapshot.

## Host daemon

```bash
cd daemon
npm ci
npm start
```

The Web viewer and MCP endpoint use port `8088`; the agent connects to TCP `8761`, normally via `adb reverse`. Use `ADH_HTTP_PORT`, `ADH_AGENT_PORT`, and `ADH_DATA_DIR` to override host defaults. Keep `ADH_DATA_DIR` on a local filesystem: concurrent SQLite writers on a shared network drive can corrupt the index.

## Verification

```bash
cd daemon
node --test test/*.test.ts
```

The full acceptance runner is `bash tools/verify_all.sh`. It calls `tools/dev_up.sh`, establishes `adb reverse`, and many device scripts install or restart the sandbox. Set `ANDROID_SERIAL` to a **dedicated rooted test device** before running it. Do not run the device suite on a personal daily-use phone.
