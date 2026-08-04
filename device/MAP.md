# device/ — ADH 设备侧多模块工程（对标 Vector 形态，不做 Xposed）

学形态不学产品：Manager Compose UI + Device Daemon（AIDL/作用域）+ shared core。
采集/hook 仍在仓库顶层 `agent/`；Host 分析仍在顶层 `daemon/`（ADH Daemon / npm `adhd`）。
Magisk 打包仍在 `injector/zygisk/`。

## Modules

| Gradle | Package | Role |
|---|---|---|
| `:core` | `com.adh.core` | Scope 契约单一真相：路径常量、JSON 编解码、`IAdhScopeService` AIDL |
| `:daemon` | `com.adh.daemon` | 模块以 root `app_process` 启动的 APK；只读写 scope/模块状态 |
| `:manager` | `com.adh.manager` | 普通 Compose APK；经受认证 Binder 读/写 scope，并直接探测 Host Web UI 地址；不调用 `su` |

## Boundaries (red line)

```text
Target App  →  agent/libidh_agent.so     collect only
Zygisk      →  injector/zygisk           early inject by scope
Device      →  device/:daemon+:manager   scope + module status + Host console link
Host PC     →  daemon/ (ADH Daemon)      HTTP/WS/MCP/analysis
```

Never host HTTP/MCP services, a dex indexer, or heavy analysis in the Device Daemon
or Manager. The Manager may only act as a bounded HTTP client for Host `/health`
so it can display and open the Web UI address; that request never passes through
the privileged Device Daemon.

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
| native / LSPlant framework | `agent/` collect agent (not an Xposed framework) |
| xposed API | not in scope |

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
errors, and versions.
Module status distinguishes an unavailable Device Daemon from an absent or unloaded
module. Both Home and Scope re-check when returning to the foreground.
