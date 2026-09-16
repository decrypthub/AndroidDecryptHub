# ADH 功能状态（发布前梳理，2026-09-16）

> 这份文件回答一个问题：**第一版里到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh` 的 pass/fail（当前 **52/52 全绿**，设备 + host），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。

## 0. 第一版发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，322,032 B，release 剥离） | `tools/build_agent.sh` | ✅ 已验收 |
| Zygisk 模块 zip + ADH Manager APK + 组合包 | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ 已验收（v27）+ 真机刷入 |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭 |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭 |
| 开发用（不随发布物交付） | `sandbox-app/`（测试宿主）、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布：什么在 .so、什么在主机、什么在设备侧

> 一句话：**`libadh_agent.so` 是"运行时唯一入口"（目标进程里的眼睛和手），但不是全部能力的载体。**
> 分析/索引/存储/编排/呈现都在主机；"给谁注入、何时注入"在设备侧；可选后端是另一种进入/观测方式。

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **29 个命令**：GOT/inline hook、函数与 QBDI trace、dex/so/内存 dump、maps 与内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、轻量 RPC —— 只**采集/执行** | 13 个 C 文件（≈190 KB 源码）→ 产物 322,032 B |
| **Host ADH Daemon**（主机） | `daemon/` | **63 个 HTTP 路由 + 42 个 MCP 工具**：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编、原生常量与 syscall 扫描、脱壳编排与重建、捕获与工件存储、Web UI、MCP server | TypeScript |
| **Device**（手机侧） | `device/`（`:core` AIDL + `:daemon` root + `:manager` Compose） | **12 个 AIDL 方法**：作用域读写、模块状态、应用目录/图标、目标进程启停、可选后端（Xposed）状态/开关/作用域 —— **不做分析** | Kotlin |
| **注入器** | `injector/zygisk`、`injector/xposed` | 唯一职责：把 `.so` 送进目标进程 + 传真实包名 | C++ / Java |
| **可选后端** | `tools/`（Gadget/eCapture）+ `injector/xposed` | 另一种"进入/观测"方式，默认关闭 | 脚本 / 薄 APK |

### 依赖关系（发布视角）

- **必须注入 `.so`**：42 个 MCP 工具里的 **21 个** —— 明文捕获（加解密/TLS/文件/反检测）、hook、trace、dump、活体对象自省、主动触发（runtime 面）。
- **不需要 `.so`**：另外 **21 个**（静态/工件面）—— `dex_search`/`dex_index`/`dex_xref`/`dex_repair`/`dex_recover`、`native_disasm`/`native_analyze`/`native_crypto_const`/`native_syscall_scan`、`crypto_identify`、`live_captures`/`capture_detail` 等；其中静态分析可以直接喂 `b64`/`sha` 工件（`dumpBuf` 支持），**完全不注入也能用**。
- **完全不看 `.so`**：eCapture（eBPF 在设备侧读 `SSL_write/SSL_read` 明文）；Frida Gadget 的 JS hook 也不依赖我们的 `.so`（我们只是用它当载体/用 `load_library` 触发）。

### ADH Manager 到底管什么

12 个 AIDL 方法里 **10 个与"注入/后端/作用域"相关**（作用域读写 2、应用目录与图标 2、模块状态 3、Xposed 状态/开关/作用域 3），另 1 个目标进程启停、1 个协议版本。
它**从不接触 `.so`**：不 `dlopen`、不做分析 —— "注入动作"由 Zygisk / Xposed / 沙盒完成，"决定给谁注入、后端开不开、目标进程要不要重启"才归 Manager。
## 1. v1 范围收敛

第一版只保留下方“测过的功能”。未验收、半成品或没有真实触发源的能力，已从代码、Web UI、MCP/工具入口、Manager 和发布文档中移除；历史记录只保留在 `docs/archive/`，不作为产品入口或发布说明。

当前 `verify_all` 没有任何“跑不过却还留着”的检查：fail=0。

## 2. 测过的功能（52/52 全绿）

| 能力 | 覆盖脚本 | 验收要点 |
|---|---|---|
| 命令通道 / 协议分帧 | v02, v21_frame | 1MB 命令帧 + 16MB dump 跨帧字节一致（无 8192 上限） |
| 内存与 dump | v02_dump, v02_so, v22_capture | 搜索/落盘/ sha256 对照 / 去重；高频突发下 `emitted+backlog+dropped==seq` 如实记账 |
| dex 静态分析 | v03, v04_dexparse, v08_dexsearch, v08_xref, v09_methodcode | ART 结构枚举、crypto 常量扫描、调用图 xref、方法字节码恢复 |
| dex 修复/重建/恢复 | v02_dexrepair, v12_rebuild, v13_recover, v29_dexindex | 头部修复字节一致、CodeItem 注入重建可解析、持久索引 + 反射边 |
| 原生反汇编/常量/syscall | v08_disasm, v08_analyze, v09_cryptoconst, v09_syscall | 内存镜像反汇编、导入导出、AES S-box、`svc #0` 直连点 |
| 加解密动态捕获（Java 层） | v04_crypto, v11_capture, v24_javacap | EVP 边界明文、富采集（算法+Key+IV+明文+密文） |
| 加解密动态捕获（原生 GOT） | v26_cryptocoverage | ECDSA_sign/verify + `EVP_AEAD_CTX_seal/open` 命中（含 APS2 packed reloc 扫描） |
| TLS 明文 | v07, v07_flow | `SSL_write/SSL_read` 边界明文 + 明文↔密文同线程关联 |
| 文件 I/O | v20_file, v25_fsbrowser | libc `open/read/write` 捕获；`list_dir`/`read_file` + 坏路径 fail-loud |
| 反检测观测 | v05_detect | 目标自身 `ptrace/access/__system_property_get` 被观测（含 lazy-binding 修复） |
| 活体对象 / 主动触发 | v06, v14_trigger, v16_identify | 字段反射 + 方法调用、安全触发器、算法识别 |
| 函数/指令 trace | v10_trace, v10_qbdi | 参数/tid/时间戳；QBDI 指令级 trace（用后 `dlclose`） |
| 一键 dump 所有 DEX | v15_dumpall, v17_dumpall_mcp | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载；REST + MCP 双入口 |
| 进程内 dlopen | v18_loadso | 目标进程内加载任意 `.so` 并解析符号（Gadget 依赖此能力） |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, verify_v32_backend_control | scope 往返；Device Daemon 驱动框架状态/作用域并**恢复测试前状态** |
| 可选后端（Gadget/Xposed/eCapture） | v30, v31, v32, v34 | 官方二进制 + sha256 固定；Java bridge hook 真跑通；eCapture 抓到请求+响应明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions | MCP 51 工具可调（自动化关闭时隐藏 phone_*）、Web UI 可用、后端矩阵、会话清理与选择器修复 |
| 可选手机自动化（模块 X） | v36_automation | 默认关闭；控件树/截图兜底（受保护窗口 fail-loud）、find/wait/selector/ref/坐标/scroll/app/global 动作、进程内信号等待（事件/捕获 + 游标 + UTF-8 明文）、agent 断线自愈重连、设备侧命令硬超时（卡死不再拖垮通道）、set_text 真输入并提交、通知读取（opt-in listener）、命名配方（phone_skill）、双层包名 allowlist；协议 v7 一键启停 + opt-in 自动修复；协议 v8 屏幕状态/唤醒/非安全解锁；随新模块部署 |
| 注入足迹 | v26_footprint | release agent 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |
| 注入单实例收敛 | 真机混态手工验证（Zygisk + self-load） | `dl_iterate_phdr` 首载 copy 独占 bootstrap；同 PID 不再出现第二个 `jni_onload` 会话；winner copy 迟绑定 reporter，v24 rich Java 仍 PASS |

## 3. 发布结论

- 可以发布：`libadh_agent.so` + Zygisk 包/Manager + 三个可选后端（Gadget/Xposed/eCapture，均默认关闭）。
- 当前验收入口：`tools/verify_all.sh`，52/52 全绿。
- 发布口径只认本文件 §2 和 `verify_all`；不再宣传或暴露未验收/半成品能力。
