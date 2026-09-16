# injector/ — Module W (Zygisk + Manager)

| Path | Role |
|---|---|
| `zygisk/` | Magisk Zygisk module source + packager |
| `zygisk/jni/` | Companion `.so` (`main.cpp`) — reads `/data/adb/adh/scope.json`, opens the agent from the module-dir fd, loads it with `android_dlopen_ext`, passes the real package, then calls `adh_agent_start` |
| `zygisk/module/` | Magisk module skeleton (`module.prop`, installer/action scripts, boot status scripts, META-INF) |
| `zygisk/dist/adh-zygisk.zip` | Build output (`bash tools/build_zygisk.sh`) |
| `zygisk/dist/adh-bundle-vX.Y.Z.zip` | Versioned module + verified `manager.apk` + root Device Daemon APK |
| `manager/` | **DEPRECATED stub** — Manager APK moved to `device/manager` (Jetpack Compose). See `manager/README.md`. |

## Scope contract

Scope JSON path and constants live in **`device/core`** (`AdhPaths` / `ScopeConfig` / `ScopeJson`). Zygisk path strings in `zygisk/jni/` **must stay in sync** with `device/core` `AdhPaths`.

```json
{"version":1,"mode":"allowlist","packages":["com.example.target"]}
```

- Empty / missing file → inject nothing (fail-loud empty allowlist).
- Hard excludes: `zygote`, `zygote64`, `system_server`, `com.adh.manager`.
- After changing scope, cold-start the target app.
- `post-fs-data.sh` resets runtime markers; `service.sh` starts `daemon.apk` with root `app_process`, while the root companion recreates `zygisk_loaded` after a real Zygisk load.
- `build_zygisk.sh` rejects missing Zygisk C exports, pins the built Manager certificate into Device Daemon, and packages `daemon.apk` plus its launcher.
- Agent load is fail-loud: `preAppSpecialize` opens `libadh_agent.so` via `getModuleDir()` + `openat`; `postAppSpecialize` only calls `android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` (never `getModuleDir()` in post — Zygisk Next deadlocks).
- Companion calls `adh_agent_set_package` before `adh_agent_start`; early injection must not report `zygote64` as the target package.
- Companion sets `DLCLOSE_MODULE_LIBRARY`, so the Zygisk module `.so` is unloaded after post-specialize; the agent `.so` stays loaded for the session.
- KernelSU scope-read SELinux rules are re-applied by `post-fs-data.sh`; Magisk still uses module-root `sepolicy.rule`.

## Build

```bash
bash tools/build_agent.sh      # prerequisite
bash tools/build_zygisk.sh     # -> injector/zygisk/dist/adh-zygisk.zip
bash tools/build_bundle.sh     # -> injector/zygisk/dist/adh-bundle-vX.Y.Z.zip
bash tools/flash_device.sh --reboot  # KernelSU ksud / Magisk install + reboot
```
