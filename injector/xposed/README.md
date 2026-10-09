# injector/xposed — 可选 LSPosed/Xposed 后端（薄模块）

模块 W 的**可选**注入后端之一：在用户已有 Xposed 框架（LSPosed / Vector / EdXposed）的前提下，
把 ADH agent 送进被作用域（scope）的目标进程。**默认关闭**，只有显式安装 + 启用 + 配 scope 才生效。

## 它做什么 / 不做什么

- **做**：在框架已加载进目标进程后（`handleLoadPackage`），把本 APK 里自带的 `libadh_agent.so`
  加载进该进程（`System.loadLibrary("adh_agent")`）。加载失败即视为该后端不可用，不再做
  第二套路径扫描兜底。之后 agent 像其他注入路径一样自己连 Host ADH Daemon（`adb reverse` → 8761）。
- **不做**：不实现任何分析能力。hook/trace/dump/索引/HTTP/MCP/DB 全部仍在 Host ADH Daemon —— 架构红线不变。
- **不 vendor 上游代码**：`api-stub/` 只是我们自己写的 compile-only ABI 声明（`IXposedHookLoadPackage` /
  `XC_LoadPackage.LoadPackageParam` / `XposedBridge.log`），运行时由框架提供真类；APK 里不含这些类。

## 策略（slice 1）

| 规则 | 原因 |
|------|------|
| 只进 scope 内应用的**主进程** | 一个进程一个 agent 会话；多进程留待后续显式开启 |
| 永不进 `android` / `com.android.*` / `com.google.android.gms` | 框架进程、系统 UI 等不属于 ADH 目标，配置错了也不能碰 |
| 永不进 `com.adh.xposed` 自身 | 防止自注入递归 |
| 只对 ADH 自己的测试宿主写 marker（`com.adh.sandbox` / `com.adh.manager`） | 验收需要端到端信号，但**绝不**在第三方目标里留文件 |

作用域由框架（LSPosed/Vector 的 scope）决定；ADH Manager/Device Daemon 侧去驱动这套 scope 属于后续切片。

## 构建 / 安装 / 验收

```bash
bash tools/build_xposed.sh                 # 产出 injector/xposed/dist/adh-xposed.apk（自动带上 agent .so）
bash tools/install_xposed.sh               # root 安装 + vector-cli 启用模块 + 设 scope（默认 com.adh.manager）
bash tools/install_xposed.sh --disable     # 收尾：禁用模块并清 scope（默认关闭）
bash tools/verify_v31_xposed.sh            # 真机验收（安装→启用→启动目标→断言 marker + agent 会话→自动收尾）
```

厂商无关的启用方式：任意 Xposed 管理器里勾选 “ADH Xposed Bridge”，并把目标 App 加入其作用域。

## 目录

```
injector/xposed/
├── api-stub/     # compile-only Xposed ABI 声明（不进 APK）
└── module/       # 薄加载器 APK（assets/xposed_init → com.adh.xposed.AdhXposedEntry）
    └── src/main/jniLibs/arm64-v8a/libadh_agent.so   # 由 tools/build_xposed.sh 临时投放（gitignore）
```