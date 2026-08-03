# injector/ — Module W (Zygisk + Manager)

| Path | Role |
|---|---|
| `zygisk/` | Magisk Zygisk module source + packager |
| `zygisk/jni/` | Companion `.so` (`main.cpp`) — reads `/data/adb/adh/scope.json`, `dlopen`s `libidh_agent.so`, calls `idh_agent_start` |
| `zygisk/module/` | Magisk module skeleton (`module.prop`, `customize.sh`, META-INF) |
| `zygisk/dist/adh-zygisk.zip` | Build output (`bash tools/build_zygisk.sh`) |
| `manager/` | ADH Manager APK — LSPosed-style app list / allowlist UI |

## Scope contract

```json
{"version":1,"mode":"allowlist","packages":["com.example.target"]}
```

- Empty / missing file → inject nothing (fail-loud empty allowlist).
- Hard excludes: `zygote`, `zygote64`, `system_server`, `com.adh.manager`.
- After changing scope, cold-start the target app.

## Build

```bash
bash tools/build_agent.sh      # prerequisite
bash tools/build_zygisk.sh     # -> injector/zygisk/dist/adh-zygisk.zip
cd injector/manager && ./gradlew :app:assembleDebug
```
