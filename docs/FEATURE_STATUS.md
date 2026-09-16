# ADH 功能状态（发布前梳理，2026-09-16）

> 这份文件回答一个问题：**第一版里到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh` 的 pass/fail（当前 **51/51 全绿**，设备 + host），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。

## 0. 第一版发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，323,424 B，release 剥离） | `tools/build_agent.sh` | ✅ 已验收 |
| Zygisk 模块 zip + ADH Manager APK + 组合包 | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ 已验收（v27）+ 真机刷入 |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭 |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭 |
| 开发用（不随发布物交付） | `sandbox-app/`（测试宿主）、`tools/`、`docs/`、`daemon/` | — |

## 1. 没通过测试的功能（不要了）

| 功能 | 证据 | 处置 |
|---|---|---|
| **LSPlant Java 方法 hook** | 测试机 ColorOS/A15 的 `libart.so` 被裁剪（LSPlant 需要的 44 个 ART 符号缺 30 个），`idh_javahook_init` 无法初始化；`verify_v23_javahook` 从未通过，长期被排除在 `verify_all` 之外 | **已删除**（commit `3753791`）：agent shim / 命令 / daemon 路由 / 沙盒回调脚手架 / fetch 脚本 / 验收脚本 / CMake 分支。agent `.so` 591,752 → 323,424 B |
| ShadowHook inline 后端 | 同 ROM 上 `shadowhook_init` 失败（INIT_LINKER/errno12）；它只是文档里的历史尝试 | 代码从未入库；inline hook 改用 **Dobby**（已验证 v28） |

> 当前 `verify_all` 里**没有**任何"跑不过却还留着"的检查：fail=0。

## 2. 测过的功能（51/51 全绿）

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
| 活体对象 / 主动触发 | v06, v14_trigger, v16_identify, v17_deepunpack | 字段反射 + 方法调用、安全触发器、算法识别、按包名全类主动加载 |
| 函数/指令 trace | v10_trace, v10_qbdi | 参数/tid/时间戳；QBDI 指令级 trace（用后 `dlclose`） |
| 脱壳会话 | v15_session | T0→触发→T1→恢复 五阶段贯通 + 覆盖率 |
| 进程内 dlopen | v18_loadso | 目标进程内加载任意 `.so` 并解析符号（Gadget 依赖此能力） |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, verify_v32_backend_control | scope 往返；Device Daemon 驱动框架状态/作用域并**恢复测试前状态** |
| 可选后端（Gadget/Xposed/eCapture） | v30, v31, v32, v34 | 官方二进制 + sha256 固定；Java bridge hook 真跑通；eCapture 抓到请求+响应明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions | MCP 40+ 工具可调、Web UI 可用、后端矩阵、会话清理与选择器修复 |
| 注入足迹 | v26_footprint | release agent 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |

## 3. 没测的功能（存在，但没有通过验收）

| 项 | 现状 | 说明 |
|---|---|---|
| KDF 原生一次性捕获（PBKDF2/HKDF/scrypt） | hook 已安装，**测不出来** | Android JCA 的 KDF 是纯 Java 迭代，不走原生一次性 API；对"原生直接调用"的目标仍可能命中。文档一直标 PENDING，前端 `kdf` 家族在自测中永远为空 |
| eCapture 的 `pcap` / `keylog` 模式 | 只验证了 `text` | 其余模式代码路径未跑过 |
| eCapture 在非本机内核上的表现 | 只在本机（5.10 / 无 BTF）验证 | 其它内核/ROM 的兼容性未知（预检会给出可加载判定） |
| Frida Gadget `--watch`（改脚本热重载） | 手工验证过，未进 CI | CI 只跑一次 Java bridge 探针 |
| Xposed 多进程目标 | 未做 | 目前只注入 scope 内**主进程**（策略写在模块里） |
| 国密 SM2/SM3/SM4、隐私分析面板 | 无代码 | 只有规格条目；依赖已删除的 Java hook 路线 |
| 重打包注入（`injector/gadget-pack`）、ptrace 注入器 | 无代码 | 架构图里标注"延后" |
| `python/` PyPI 网关（`android-decrypt-hub`） | 代码完整、有单测、本地已构建 0.1.1 wheel，但**完全未入库**（git 未跟踪） | 要发布需先决定是否纳入仓库与 CI |
| ADH Manager 的真机 UI 交互 | 只有 Binder/repository 单测 | 真机 UI 操作未自动化验证 |

## 4. 开发到一半的功能

| 项 | 到什么程度 | 缺什么 |
|---|---|---|
| KDF 原生一次性捕获 | agent 侧 hook 与还原代码已写完（44 行），分类/筛选项也在 | 缺**可触发的目标**：没有真实调用源 → 无法验证，也无从判断是否真的能抓 |
| `python/` 网关 | CLI + 配置 + MCP 桥接 + 单测 + 打包脚本都在本地 | 未入库、未进 `verify_all`、未发版 |
| 多进程作用域 | Zygisk 作用域按包生效；Xposed 模块只处理主进程 | 需要"按进程选择"的产品决策与实现 |
| 可选后端的"一键下发" | Web 控制台只给命令模板 + 逐会话后端检测 | daemon 没有 adb 通道；需要设备侧中转或受控 adb 桥 |

## 5. 结论

- **可以发布**：`libadh_agent.so` + Zygisk 包/Manager + 三个可选后端（Gadget/Xposed/eCapture），全部有独立验收入口（`tools/verify_all.sh` 51/51）。
- **不要宣传**：Java 方法 hook（已删除）、KDF 原生捕获、国密、隐私面板、重打包、ptrace 注入。
- **发版前若还想再砍一刀**：把 KDF 家族从设置/前端摘掉（让 UI 不再出现永远填不满的分类），并把 `python/` 明确为"未发布"。