# device/ — ADH 设备侧多模块工程（对标 Vector 形态，不做 Xposed）

学形态不学产品：Manager Compose UI + Device Daemon（AIDL/作用域）+ shared core。
采集/hook 仍在仓库顶层 `agent/`；Host 分析仍在顶层 `daemon/`（ADH Daemon / npm `adhd`）。
Magisk 打包仍在 `injector/zygisk/`。

## Modules

| Gradle | Package | Role |
|---|---|---|
| `:core` | `com.adh.core` | Scope 契约单一真相：路径常量、JSON 编解码、`IAdhScopeService` AIDL、已安装应用目录 JSON、进程控制允许清单 |
| `:daemon` | `com.adh.daemon` | 模块以 root `app_process` 启动的 APK；读写 `scope.json`、模块状态、枚举已安装应用，并以 uid=0 终止/重启目标应用 |
| `:manager` | `com.adh.manager` | 普通 Compose APK；经受认证 Binder 读/写 scope、应用目录与进程启停，并直接探测 Host Web UI 地址；不调用 `su`、不自己 `getInstalledApplications` |

## Optional backend control (Xposed/LSPosed)

`device/daemon/src/main/java/com/adh/daemon/XposedBackend.kt` is the only place that talks to the
framework. It shells out to `/data/adb/lspd/cli` (the framework's own surface — no sqlite poking):

| Surface | Purpose |
|---|---|
| `IAdhScopeService.getXposedStatus/setXposedEnabled/setXposedScope` (protocol **v5+**; current protocol **v13**) | Manager UI: card in the Scope screen; the ADH allowlist is mirrored into the framework scope whenever it is saved while the backend is enabled |
| `app_process … com.adh.daemon.AdhDeviceDaemon --xposed-status\|--xposed-enable\|--xposed-disable\|--xposed-scope <pkgs>` | root-only one-shot CLI (same code paths as AIDL) for operators and `tools/verify_v32_backend_control.sh` |

Framework quirks encoded here: `scope set <module>` with **no** apps throws (so clearing removes
entries one by one), and `scope set` implicitly enables the module — callers that care about the
enabled flag must set it explicitly.

## Boundaries (red line)

```text
Target App  →  agent/libadh_agent.so     collect only
Zygisk      →  injector/zygisk           early inject by scope
Device      →  device/:daemon+:manager   scope + module status + target process control + Host console link
Host PC     →  daemon/ (ADH Daemon)      HTTP/WS/MCP/analysis
```

Never host HTTP/MCP services, a dex indexer, or heavy analysis in the Device Daemon
or Manager. AI agents interact with the handset through adb when needed.
The Manager may still act as a bounded HTTP client for Host `/health`
so it can display and open the Web UI address; that request never passes through
the privileged Device Daemon.

Installed-app enumeration is privileged: the Device Daemon uses
`ActivityThread.systemMain()` + `getSystemContext()` (uid 0) and returns a compact
JSON catalog over AIDL (`listApplications`, protocol v2). Icons are **not** in that
JSON (Binder size). Protocol v3 adds `getApplicationIconPng(package)` — Manager
loads visible rows lazily. Protocol v4 adds `controlPackage(package, stop|restart)`
so the Manager can force-stop or relaunch a target after changing injection scope;
the daemon refuses Manager / Device Daemon / `system_server` / System UI / `android`.
Injection scope remains `/data/adb/adh/scope.json`.

## Scope contract (shared)

Path: `/data/adb/adh/scope.json`

```json
{"version":1,"mode":"allowlist","packages":["com.example.target"]}
```

Constants live only in `:core` (`AdhPaths`, `ScopeConfig`). Zygisk C++ mirrors the same path string (documented; keep in sync by hand until a codegen step exists).

## Build

```bash
cd device
./gradlew :core:test :daemon:assembleDebug :manager:assembleDebug
```

Toolchain locked to Gradle 8.9 + AGP 8.7.3 + Kotlin 2.0.21 + Compose BOM (same class as sandbox). AGP 9 / Kotlin 2.4 are a later upgrade, not this foundation.

## vs Vector

| Vector | ADH |
|--------|-----|
| manager Compose | `:manager` Compose |
| on-device daemon | `:daemon` AIDL skeleton |
| zygisk loader | `injector/zygisk` (Magisk zip) |
| native collect agent | `agent/` collect agent (not an Xposed framework) |
| xposed/LSPosed framework | **not ours** — user-installed (LSPosed/Vector). ADH ships an optional thin loader module (injector/xposed/) and drives its enabled/scope state from the Device Daemon ([XposedBackend] below). |

ADH adopts Vector's versioned module packaging, bundled Manager checksum, Magisk
Action entry, and privileged-daemon boundary. It does not adopt Vector's parasitic
`com.android.shell` Manager or system_server hooks: ADH keeps a standalone Manager,
and the root daemon publishes its narrow AIDL Binder through a UID-0-only provider
handshake. Every daemon transaction verifies caller UID, package ownership, and the
Manager signing certificate pinned during the build.

The Manager also adopts Vector's compact status-first information hierarchy while
remaining a standalone ADH app. Default resources are Simplified Chinese, `values-en`
follows English system locales, and Material You/light-dark colors follow the system.
User-facing text is limited to module status, the Host Web UI address, scope actions,
target process stop/restart, errors, and versions.
Module status distinguishes an unavailable Device Daemon from an absent or unloaded
module. Both Home and Scope re-check when returning to the foreground.
