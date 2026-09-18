# ADH 功能状态（发布前梳理，2026-09-19 更新）

> 这份文件回答一个问题：**现在到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh`（**98 个脚本 = 23 host + 75 device**），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。
> 最近一次**全绿**门禁：`6319d5d`（设备在位，**92 PASS / 0 FAIL / 2 SKIP**）。
> 最近一次 host-only 门禁（手机不在位）：**23 PASS / 0 FAIL / 75 SKIP** —— 设备脚本如实记 SKIP，不再冒充通过。

## 0. 发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，release 剥离，834,408 B） | `tools/build_agent.sh` | ✅ 已验收（v01–v79 系列） |
| Zygisk 模块 zip + ADH Manager APK + 组合包（**v0.3.10**） | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ 已验收（v27）+ 真机刷入（memfd 注入 v4.37） |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭；官方二进制（未魔改） |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭；需内核 eBPF |
| 开发用（不随发布物交付） | `sandbox-app/`、`sandbox-native/`、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **40 个命令分支**：GOT/inline/addr/sites/vtable hook、Java(LSPlant) hook（单方法 + `hookAll` 批量 + 参数改写/返回值替换/skip/调用链）、JNI_OnLoad（含加载时 watch）/RegisterNatives/JNIEnv 76 槽、函数与 QBDI trace、dex/so/内存 dump、maps/内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、`native_call`（整数+浮点）、`native_backtrace`、`syscall_watch`、轻量 RPC —— **只采集/执行，不做分析** | C/C++，产物 834 KB |
| **Host ADH Daemon**（主机） | `daemon/` | **70 个 MCP 工具 + 50 条 HTTP 路由**：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编与 syscall 归因/参数解码、trace 摘要、syscall 摘要、脱壳编排与重建、工件存储、Web UI、MCP server | TypeScript（含 5 个单测文件、44+ 条用例） |
| **Device**（手机侧） | `device/` | AIDL 作用域读写、模块状态、目标进程启停、可选后端开关 —— **不做分析** | Kotlin |
| **注入器** | `injector/zygisk`、`injector/xposed` | 把 `.so` 送进目标进程（Zygisk 走 **memfd**，目标 maps 不出现模块路径）+ 传真实包名 | C++/Java |
| **可选后端** | `tools/`（Gadget/eCapture） | 另一种进入/观测方式，默认关闭 | 脚本/薄 APK |

## 1. 测过的功能（按 verify_all 的脚本分组）

| 能力 | 覆盖脚本 | 验收要点 |
|---|---|---|
| 命令通道 / 协议分帧 | v02, v21_frame | 1MB 命令帧 + 16MB dump 跨帧字节一致 |
| 内存与 dump | v02_dump, v02_so, v22_capture | 搜索/落盘/sha256 对照/去重；突发下 `emitted+backlog+dropped==seq` 如实记账 |
| dex 静态分析 / 修复 / 索引 | v03, v04_dexparse, v08_*, v09_methodcode, v12_rebuild, v13_recover, v29_dexindex | ART 结构枚举、常量扫描、xref、字节码恢复、重建与持久索引 |
| 原生反汇编 / 常量 / syscall 扫描 | v08_disasm, v08_analyze, v09_cryptoconst, v09_syscall | 内存镜像反汇编、导入导出、AES S-box、`svc #0` 直连点 |
| 加解密动态捕获 | v04_crypto, v11_capture, v24_javacap, v26_cryptocoverage | EVP 边界明文、富采集、ECDSA/AEAD 覆盖（含 APS2 packed reloc） |
| TLS / 文件 I/O | v07, v07_flow, v20_file, v25_fsbrowser | SSL_write/read 明文与关联；libc open/read/write 捕获 |
| 反检测观测与去特征 | v05_detect, v69(stealth), v70/v72(sites), v73/v74(vtable) | 目标自审（anon r-x、序言比对）；stealth 后 anonExec 2→0；sites 保持入口字节不变 |
| Java hook（LSPlant） | v42/v43/v52/v53/v65, **v79(stack)**, **v82(hookAll)**, **v83(java_trace digest)** | 单方法/构造器/继承、参数改写、返回值替换、skip original；`stack:true` 给出 App 帧调用链；`hookAll` 一次装全类（截断可见） |
| native hook | v46, v49, v55, v56, v66, v68, **v84(native_hook_all selection)** | inline/addr、软/硬卸载、寄存器事件、浮点参数、千次压测 |
| JNI 面 | v54, v57, v58, v59, v60, v62, v63, v64, v67 | RegisterNatives、JNI_OnLoad（含加载时替换）、JNIEnv 76 槽、Call* 三类入口、数组写回、异常保持 |
| 主动调用 | v45(java_call), v49(native_call), v51(qbdi args) | 反射调用 Java 方法/字段；按符号或地址调 native（整数+浮点） |
| trace | v10_trace, v10_qbdi, **v78(backtrace)** | 函数参数/线程/时间戳；QBDI 指令级（用后 dlclose）；hook 命中当刻的 x29 调用链 + 符号化 |
| 内存反汇编（MCP） | v48 | Capstone 5 WASM，绝对地址或 module+offset |
| 系统调用监听 | v50(direct), **v76(归因)**, **v77(libc+过滤)**, **v81(摘要+参数)** | 直接 `svc #0` 捕获；静态归因（223/224 libc 站点）；按名/号过滤只装命中站点；`syscall_digest` 给调用方/次数/`paths` 直方图，并比对运行期 x8 与归因号 |
| 一键 dump 所有 DEX | v15, v17 | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载（REST+MCP） |
| 进程内 dlopen | v18 | 目标进程内加载任意 `.so` 并解析符号 |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, v32_backend_control, **v75(memfd)** | scope 往返；后端状态/作用域可控并恢复；**agent 从 memfd 加载**（目标 maps 无模块路径，目标内自证 + ELF 头） |
| 可选后端 | v30, v31, v34 | 官方二进制 + sha256 固定；Xposed Java bridge；eCapture 抓明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions, **v71(registry)**, **v80(trace digest)**, **v83(java trace)**, **v84(native batch)** | MCP 70 工具可调；注册表形状自检；Web UI；会话清理 |
| 手机自动化（模块 X） | v36, v38, v39, v40, v41 | 树/截图/选择器/手势/输入/wait/通知/技能；硬超时、桥接自愈、root 输入、屏幕状态；**重启后的 OEM 弹窗按 BACK 有界重试** |
| 注入足迹 | v26_footprint, v01 | release 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |
| 单元测试（host） | v76, v80, v81, v83, v84 | syscall 归因/参数解码、trace 摘要、backtrace dynsym、Java trace（含三阶段装配与 drain 守卫）、native 批量选择：**75 条** `node --test` 用例（另有 automation 30 条；v81/v83 按文件最小数断言） |

## 2. 待真机验证（代码 + host 验收已完成，手机不在位）

| 项 | 内容 | 脚本 |
|---|---|---|
| syscall 归因比率/数字过滤 | `attributedCount ≥ 90% svcCount`、`syscalls:['178']` | v77 |
| hook 回溯健壮性 | `btTruncated` → `frame-cap-reached`、`bt[]` 帧 `-4` 修正、槽位复用不复用旧开关 | v78 |
| Java 调用链 | `stack:true` 链里两个 fixture 帧 + 不带 stack 时无链 | v79 |
| trace 摘要 | 对 `libadhdetect.so:adh_add_target` 实跑 `trace_digest` | v80（设备半） |
| syscall 摘要 | libc `uname` 站点 → 调用方必须是 `adh_libc_uname_probe`、observed 全 160、无 mismatch | v81（设备半） |
| Java 批量挂钩 | 两个 `ping` 重载各自出事件；类级 `limit=3` 显示 `installed=3 < matched` | v82 |
| Java 类级 trace | start 挂 HookProbe → java_call stackOuter → digest 给出两个重载各自次数与调用方 → stop 后进程存活 | v83（设备半） |
| native 批量挂钩 | 对 libadhdetect.so 用 prefix:adh_ 装一批 → 触发 → unhook 全部 → 进程存活 | v84（设备半） |
| 门禁抖动定性 | gate11 的 v11/v16/v20 单独复跑（评审判定为设备状态级联，非回归） | — |
| 采集链路回归 | `service.ts` 的 drain 重构（共享 `drainSession`，java_trace/syscall_digest 不再裸发 `capture_drain`）需要设备复跑采集家族：v04_crypto / v11 / v16 / v20 / v22 / v26 | — |
| 全量门禁 | 手机接回后跑到全绿，把数字写回本文件与 `PROGRESS.md` | — |

## 3. 发布结论

- 可以发布：`libadh_agent.so` + Zygisk 包/Manager（v0.3.10）+ 三个可选后端（Gadget/Xposed/eCapture，均默认关闭）。
- 发布口径只认 `verify_all.sh` 的 pass/fail 与本文 §1；§2 的项在真机复验前不算通过。
- 已知边界（不隐瞒）：arm64-v8a only；Java/native 各 16 个并发 hook 槽；`-fomit-frame-pointer` 的第三方库只能拿到 1 帧调用链；高频 syscall 事件受 agent 事件环上限约束（有 `dropped` 记账）；全量 syscall 拦截（seccomp/PTRACE_SYSEMU）仍属 L3 未实现；Frida Gadget 后端用官方二进制（未魔改去特征）。