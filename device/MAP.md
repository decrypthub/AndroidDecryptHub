# device/ — ADH 设备侧多模块工程（对标 Vector 形态）

学形态不学产品：Manager Compose UI + Device Daemon（AIDL/作用域）+ shared core。
采集/hook 仍在仓库顶层 `agent/`；Host 分析仍在顶层 `daemon/`（ADH Daemon / npm `adhd`）。
Magisk 打包仍在 `injector/zygisk/`。

## Modules

| Gradle | Package | Role |
|---|---|---|
| `:core` | `com.adh.core` | Scope 契约单一真相：路径常量、JSON 编解码、逐包 Hook 策略（`CaptureFamilies`）、`IAdhScopeService` AIDL、已安装应用目录 JSON、进程控制允许清单 |
| `:daemon` | `com.adh.daemon` | 模块以 root `app_process` 启动的 APK；读写 `scope.json`、模块状态、枚举已安装应用，并以 uid=0 终止/重启目标应用 |
| `:manager` | `com.adh.manager` | 普通 Compose APK；经受认证 Binder 读/写 scope（含逐包策略）、应用目录与进程启停，并直接探测 Host Web UI 地址；不调用 `su`、不自己 `getInstalledApplications` |

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
{
  "version": 2,
  "mode": "allowlist",
  "packages": ["com.example.target"],
  "policy": {
    "com.example.target": { "c": { "d": true, "h": false, "s": true, "a": false, "t": true, "e": false } }
  }
}
```

`policy` is the **per-package hook policy** (`CaptureFamilies`): which crypto hook families the agent
**installs** for that package — an unchecked family means those GOT hooks are never installed in that
process, not that its records are filtered afterwards. Short keys are deliberate (same reason as
`InstalledAppsJson`: the blob crosses Binder): `c` = capture section, `d/h/s/a/t/e` =
digest / hmac / symmetric / asymmetric / tls / aead. The agent *holds* the policy but never arms
itself — a GOT patch needs a module name and the agent carries none (WS-B red line), so the policy
is applied by the next caller-issued install and its verdict comes back in that install's reply.

**Defaults are all-on, and absence means all-on.** A missing `policy` section, a missing package entry,
or a missing family key all decode to `true`, so an old scope file, an old Manager and an old daemon
stay correct by simply not writing the section — and `encode` drops entries that are default or whose
package left the scope, so the section only ever holds non-defaults. Writers must gate on
`AdhProtocol.MIN_POLICY_VERSION`: `RootScopeBinder.setScopeJson` decodes and re-encodes, so a daemon
older than that would silently drop `policy` and still report success.

Constants live only in `:core` (`AdhPaths`, `ScopeConfig`, `CaptureFamilies`). Zygisk C++ mirrors the same path string (documented; keep in sync by hand until a codegen step exists).

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
| native collect agent | `agent/` collect agent（不是框架） |

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
