# device/ — ADH 设备侧多模块工程（对标 Vector 形态）

学形态不学产品：Manager Compose UI + Device Daemon（AIDL/作用域）+ shared core。
采集/hook 仍在仓库顶层 `agent/`；Host 分析仍在顶层 `daemon/`（ADH Daemon / npm `adhd`）。
Magisk 打包仍在 `injector/zygisk/`。

## Modules

## P5 additions (2026-11-16)

`core/EarlyPlanWire.kt` encodes the bounded early-plan/1 wire. `daemon/device/HookPlanCache.kt` owns validated, expiring app/Agent-bound cache and exact legacy backups through DeviceOperations. `AndroidHookBinding.kt` validates installed identity/ABI; `EarlyPlanBroker.kt` serves root companions only. Manager Binder v20 adds package-only CAS and Hook cache read/revoke; the fixed family editor is now a read-only legacy snapshot. Authoritative programmable editing stays on Host. No automatic app restart. See [P5_HOOK_PLANS.md](../docs/P5_HOOK_PLANS.md).

## Modules reference

| Gradle | Package | Role |
|---|---|---|
| `:core` | `com.adh.core` | Scope 契约单一真相：路径常量、JSON 编解码、逐包 Hook 策略（`CaptureFamilies`）、`IAdhScopeService` AIDL、已安装应用目录 JSON、进程控制允许清单 |
| `:daemon` | `com.adh.daemon` | 模块以 root `app_process` 启动的 APK；读写 `scope.json`、模块状态、枚举已安装应用，并以 uid=0 终止/重启目标应用 |
| `:manager` | `com.adh.manager` | 普通 Compose APK；经受认证 Binder 读/写 scope（含逐包策略）、应用目录与进程启停，并直接探测 Host Web UI 地址；不调用 `su`、不自己 `getInstalledApplications` |

## Boundaries (red line)

```text
Target App  →  agent/libadh_agent.so     collect only
Zygisk      →  injector/zygisk           early inject by scope
Device      →  device/:daemon+:manager   scope + module status + system CA certs + target process control + Host console link
Host PC     →  daemon/ (ADH Daemon)      HTTP/WS/MCP/analysis
```

Never host HTTP/MCP services, a dex indexer, or heavy analysis in the Device Daemon
or Manager. AI agents interact with the handset through adb when needed.
The Manager may still act as a bounded HTTP client for Host `/health`
so it can display and open the Web UI address; that request never passes through
the privileged Device Daemon. Protocol v17: once the Manager has learned a LAN
address, it asks the daemon to store `ipv4:port` at `/data/adb/adh/host.endpoint`.
The daemon does not scan the network. Zygisk reads that line and hands it to the
agent, which dials `127.0.0.1:8761` first and the remembered address second.
Protocol v18: the Manager imports a PEM or DER file and the daemon stores CA
certificates at `/data/adb/adh/cacerts/<subject_hash_old>.N`. `post-fs-data.sh`
copies those into a tmpfs and bind-mounts it over the Conscrypt and `/system`
trust stores in init's mount namespace before zygote starts. No imported
certificate means the script does not mount anything. A reboot, confirmed in
the Manager and performed by the daemon, is what makes a new certificate visible.

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

`policy` is the **per-package hook policy** (`CaptureFamilies`): which crypto / system hook families
the agent **installs** for that package — an unchecked family means those GOT hooks are never
installed in that process, not that its records are filtered afterwards. Short keys are deliberate
(same reason as `InstalledAppsJson`: the blob crosses Binder): `c` = capture section, `d/h/s/a/t/e/y` =
digest / hmac / symmetric / asymmetric / tls / aead / system-detection. The agent *holds* the policy
but never arms itself — a GOT patch needs a module name and the agent carries none (WS-B red line),
so the policy is applied by the next caller-issued install and its verdict comes back in that
install's reply.

A leftover `b` object in an old scope file is ignored on read and dropped on the next write. The
Java SSL-bypass switch that used it was removed: on this ROM it crashed the target inside ART class
initialization, and TLS plaintext stays the native capture family `t`.

Policy entries are keyed by whatever the injector matched, and that is the **package**: Zygisk hands
the module a process name (`com.example.app:core`), so the injector tries the exact process name and
then the package prefix, asking the companion with each. A per-app policy therefore reaches every
process of the app, which is what the UI promises (REQUIREMENTS §30.4).

**Crypto defaults on; system detection (`y`) defaults off.** A missing `policy` section, a missing
package entry, or a missing crypto family key decode to crypto ON; missing `y` means system OFF. An
old scope file therefore stays on the historical "sysModule empty" path. `encode` drops entries that
are default or whose package left the scope. Writers must gate on `AdhProtocol.MIN_POLICY_VERSION`:
`RootScopeBinder.setScopeJson` decodes and re-encodes, so a daemon older than that would silently drop
`policy` and still report success.

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
system CA import, target process stop/restart, errors, and versions. The Manager shell is three
bottom tabs: Home (running status, module/app version, device model, Android release, ABI, and
whether `update.json` is newer), Apps (injection scope), and Certificates. Per-app hook policy is
its own screen, opened from an app row. Home compares `BuildConfig.VERSION_CODE` with the published
manifest at the same URL as `module.prop` `updateJson`.
Module status distinguishes an unavailable Device Daemon from an absent or unloaded
module. Both Home and Scope re-check when returning to the foreground.

## P3 device domain (2026-11-16)

`core/DeviceRpc.kt` pins adh.device/1, bounded framing and the method-effect contract. AIDL v19 appends info/capabilities/scope CAS without renumbering previous transactions. `daemon/AndroidDeviceBackend.kt` owns Android business operations; `RootScopeBinder` enforces the existing caller verifier then delegates to the same `device/DeviceOperations` as USB RPC. That package owns installation identity, atomic files, the bounded revision/operation journal, process generations, scope preservation and a stream dispatcher. `LocalDeviceRpcServer` adds only an authenticated abstract UDS; no phone HTTP/MCP/TCP/analysis server. DeviceDaemon holds a process lock for identity/journal ownership.

JVM `DeviceDomainTest` tests recovery/CAS/storage errors; `DeviceRpcFixture` exposes the production identity/domain/codec over an OS-temp loopback socket with a synthetic backend. `:daemon:writeDeviceRpcFixtureClasspath` explicitly builds its ignored classpath manifest for Host interoperability tests; it never starts a real Android service. See docs/P3_DEVICE_DOMAIN.md for limits and the separate unverified Android/SELinux boundary.

## P4 authenticated LAN (2026-11-16)

`DeviceTls` builds a self-signed installation certificate using public JCA/JSSE, independent of imported system CAs. `DeviceNetwork` restores only explicitly enabled TLS configuration; its default is disabled. `DevicePairings` persists bounded public grants and revocations, closes revoked streams and fails closed on storage errors. The same DeviceRpcSession negotiates USB-token or LAN client-signature authentication, then dispatches through DeviceOperations with a per-request authorization guard inside the domain lock. Capabilities are filtered by grant; no TCP plaintext, remote root shell, HTTP/MCP, database or analysis is introduced. Existing Binder numbering stays v19; its API was not changed this slice. See docs/P4_LAN_AUTH.md for USB-first enrollment, permissions, recovery and unsupported legacy capabilities. Real Android TLS/SELinux and device effects remain a separate hardware gate.
