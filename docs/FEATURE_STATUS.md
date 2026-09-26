# ADH 功能状态（发布前梳理，2026-09-23 更新）

> 这份文件回答一个问题：**现在到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh`（**113 个脚本 = 34 host + 79 device**），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。
> 最近一次带真机全量门禁（2026-09-23，aa165071 / Android 15 / PGP110）：**113 PASS / 0 FAIL / 0 SKIP**。
> 手机不在位时，当前 34 个 host 脚本运行、79 个 device 脚本按规则记 SKIP；本轮未执行 host-only 门禁。
> **发布范围收口提案**（不做/降级的 10 项，含证据与"什么条件下重新考虑"）见 `DEVELOPMENT_PLAN.md §6.9.5`；需求口径修订建议（去特征对抗面、SKIP 分层、信任模型等 7 条）见 `REQUIREMENTS.md` 顶部"口径修订建议"——两者都是**待确认**，确认后合并进正文。

## 0. 发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，release 剥离，836,432 B） | `tools/build_agent.sh` | ✅ 已验收（v01–v79 系列） |
| 最近一次 Zygisk 模块 zip + ADH Manager APK + 组合包（**v0.3.10**） | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | 旧包曾验收并刷入；早于本轮模块 X 退役和 Device AIDL v13，当前源码需要重建 release bundle 后再发布/刷机 |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭；官方二进制（未魔改） |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭；需内核 eBPF |
| 开发用（不随发布物交付） | `sandbox-app/`、`sandbox-native/`、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **40 个命令分支**：GOT/inline/addr/sites/vtable hook、Java(LSPlant) hook（单方法 + `hookAll` 批量 + 参数改写/返回值替换/skip/调用链）、JNI_OnLoad（含加载时 watch）/RegisterNatives/JNIEnv 76 槽、函数与 QBDI trace、dex/so/内存 dump、maps/内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、`native_call`（整数+浮点）、`native_backtrace`、`syscall_watch`、轻量 RPC —— **只采集/执行，不做分析** | C/C++，产物 817 KB |
| **Host ADH Daemon**（主机） | `daemon/` | **67 个 MCP 工具 + 93 条 HTTP 路由**：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编与 syscall 归因/参数解码、trace 摘要、syscall 摘要、脱壳编排与重建、工件存储、Web UI、MCP server | TypeScript（含 13 个单测文件、121 条用例） |
| **Device**（手机侧） | `device/` | AIDL 作用域读写、模块状态、目标进程启停、可选后端开关 —— **不做分析** | Kotlin |
| **注入器** | `injector/zygisk`、`injector/xposed` | 把 `.so` 送进目标进程（Zygisk 走 **memfd**，目标 maps 不出现模块路径）+ 传真实包名 | C++/Java |
| **可选后端** | `tools/`（Gadget/eCapture） | 另一种进入/观测方式，默认关闭 | 脚本/薄 APK |

## 1. 测过的功能（按 verify_all 的脚本分组）

| 能力 | 覆盖脚本 | 验收要点 |
|---|---|---|
| 命令通道 / 协议分帧 | v02, v21_frame | 1MB 命令帧 + 16MB dump 跨帧字节一致 |
| 内存与 dump | v02_dump, v02_so, v22_capture | 搜索/落盘/sha256 对照/去重；突发下 `emitted+backlog+dropped==seq` 如实记账 |
| dex 静态分析 / 修复 / 索引 | v03, v04_dexparse, v08_*, v09_methodcode, v12_rebuild, v13_recover, **v95(try/catch code_item)**, **v96(map_list 重建 + 布局自检)**, v29_dexindex | ART 结构枚举、常量扫描、xref、字节码恢复、重建与持久索引；**带 try/catch 的方法读全 `code_item`（header+insns+tries[]+handler 列表）并字节级重建一致**，解不动的 item 显式报 `unresolvable` 而不是算作已恢复；**重建把 code_item/class_data 重定位到文件末尾并重建 map_list**（map 现在描述文件本身，代价是旧副本作为 slack 保留、文件变大） |
| 原生反汇编 / 常量 / syscall 扫描 | v08_disasm, v08_analyze, v09_cryptoconst, v09_syscall | 内存镜像反汇编、导入导出、AES S-box、`svc #0` 直连点 |
| 加解密动态捕获 | v04_crypto, v11_capture, v24_javacap, v26_cryptocoverage | EVP 边界明文、富采集、ECDSA/AEAD 覆盖（含 APS2 packed reloc） |
| TLS / 文件 I/O | v07, v07_flow, v20_file, v25_fsbrowser | SSL_write/read 明文与关联；libc open/read/write 捕获 |
| 反检测观测与去特征 | v05_detect, v69(stealth), v70/v72(sites), v73/v74(vtable) | 目标自审（anon r-x、序言比对）；stealth 后 anonExec 2→0；sites 保持入口字节不变 |
| Java hook（LSPlant） | v42/v43/v52/v53/v65, **v79(stack)**, **v82(hookAll)**, **v83(java_trace digest)** | 单方法/构造器/继承、参数改写、返回值替换、skip original；`stack:true` 给出 App 帧调用链；`hookAll` 一次装全类（截断可见） |
| native hook | v46, v49, v55, v56, v66, v68, **v84(native_hook_all selection + 槽位预算)**, **v86(native throttle)** | inline/addr、软/硬卸载、寄存器事件、浮点参数、千次压测；限流只压事件、不改返回值替换；v86 真机 `forcedReturn=20/20` |
| JNI 面 | v54, v57, v58, v59, v60, v62, v63, v64, v67, **v90(表索引 ABI 机检)**, **v91(字段访问器 + 可改写 + 字段摘要 + 通配)**, **v92(字段摘要单测/接线)**, **v93(字符串+直接缓冲表项, host)**, **v90/v91(数组两族 + 创建/对象数组 + CallNonvirtual + 字符串/反射桥 + 覆盖 228/229, host)** | RegisterNatives、JNI_OnLoad（含加载时替换）、JNIEnv **228/229 表项（唯一余项 `RegisterNatives` 由 v4.14 的入口 inline hook 覆盖）**（99 固定 + 36 字段访问器 + 31 族 ×3：ID 查询 / Call* 三类入口 / 字符串与直接缓冲 / **数组 region 读写全族** / **数组元素 pin 与写回全族** / **数组创建 + 长度 + 对象数组元素 + AllocObject** / **CallNonvirtual 三形态全族（事件带 `via=<class>`）** / **字符串全族（含 critical 对）** / **反射桥 `From/ToReflected*`** / `FatalError` / `ExceptionCheck` / 引用生命周期 / 异常流 / 类型自省 / monitor 与弱引用，索引逐条与 NDK `jni.h` 对照，见 v90；wrapper 签名由 `_Static_assert` 编译期钉死；`action:status` 支持用 `function` 过滤（含 `installed` 关键字）并自报 `total/matched/emitted/truncated`，整表 228 项的回复不再静默截断；固定槽位由**单一列表**同时驱动枚举值与名字表（v4.82），并有**运行期布局自检**——枚举与表任何错位都会拒绝 patch 并点名位置，而不是挂到隔壁函数）、Call* 三类入口、数组写回、异常保持 |
| 主动调用 / 活体对象 | v45(java_call), v49(native_call), v51(qbdi args), v06(对象读/调用), **v89(字段写入)** | 反射调用 Java 方法/字段；按符号或地址调 native；活体对象字段**读+写**（写入带 before/after；**严格解析**：typo/越界/int 超范围一律拒绝，不再静默写 0；final 字段 fail-loud；参数超长拒绝而不是截断；**字段查找与枚举走父类链**，继承字段不再报 not found） |
| trace | v10_trace, v10_qbdi, **v78(backtrace)** | 函数参数/线程/时间戳；QBDI 指令级（用后 dlclose）；hook 命中当刻的 x29 调用链 + 符号化 |
| 内存反汇编（MCP） | v48 | Capstone 5 WASM，绝对地址或 module+offset |
| 系统调用监听 | v50(direct), **v76(归因)**, **v77(libc+过滤)**, **v81(摘要+参数)**, **v85(syscall_trace 装配)**, **v86(native throttle)** | 直接 `svc #0` 捕获；静态归因（223/224 libc 站点）；按名/号过滤只装命中站点；`syscall_digest` 给调用方/次数/`paths` 直方图，并比对运行期 x8 与归因号 |
| 一键 dump 所有 DEX | v15, v17 | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载（REST+MCP） |
| 进程内 dlopen | v18 | 目标进程内加载任意 `.so` 并解析符号 |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, v32_backend_control, **v75(memfd)** | scope 往返；后端状态/作用域可控并恢复；**agent 从 memfd 加载**（目标 maps 无模块路径，目标内自证 + ELF 头） |
| 可选后端 | v30, v31, v34 | 官方二进制 + sha256 固定；Xposed Java bridge；eCapture 抓明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions, **v71(registry)**, **v80(trace digest)**, **v83(java trace)**, **v84(native batch)**, **v85(一站式 syscall)**, **v86(throttle)**, **v87(MCP 可操作性)** | MCP 67 个工具可调；注册表形状自检；Web UI；会话清理 |
| 手机自动化（模块 X） | 已退役，不纳入验收范围 | AI Agent 直接使用 adb 操作手机；ADH 不再提供 AccessibilityService、通知读取、phone_* MCP 工具或设备输入控制桥 |
| 注入足迹 | v26_footprint, v01 | release 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |
| 字符串去特征 | **v88**, scan_agent_signatures, patch_vendor_signatures | 自己的 tag/文案/自名/fixture 默认值全部清零（含 DT_SONAME）；vendored LSPlant 的三处（含运行时 dex source name）由 fetch 期补丁清掉并机检；剩余 Dobby/导出/Java bridge 等按只许降预算记账；门禁带**负对照**（植入 token 必须被抓到） |
| MCP 可操作性 / 设备文件系统 | **v87**, v25_fsbrowser, **v89(object_set)** | 每个 agent op 必须能从 MCP 导入图到达（否则在 `INTERNAL_OPS` 写明理由）：`fs_list`/`fs_read` 与 REST 共用实现；存活/引擎/通道三个探针的判定显式（引擎 `ok` = fired && protRestored） |
| 单元测试（host） | v76, v80, v81, v83, v84, v85, **v86**, **v87** | syscall 归因/参数解码/一站式装配、trace 摘要、backtrace dynsym、Java trace（含三阶段装配与 drain 守卫）、native 批量选择、native 限流（默认/夹紧/拒绝垃圾值 + 安装回路真实 payload）、探针判定与设备文件读取（二进制/超大/截断/坏 base64）：**121 条** `node --test` 用例 |

## 2. 真机验收结果与当前遗留项（2026-09-23）

> `tools/verify_all.sh` 在 aa165071（OnePlus PGP110 / Android 15）上实际执行：**113 PASS / 0 FAIL / 0 SKIP**。PASS 表示当前验收脚本通过，不代表所有路线图项都已实现。

### 本轮修复并验收

- QBDI `qbdi_addCodeCB()` 以 `QBDI_INVALID_EVENTID` 作为失败哨兵；事件 ID `0` 是有效值。修复后带参/无参 QBDI trace 与 trace digest 均通过。
- Native hook 限流只抑制事件记录，不再覆盖 `skipOriginal` / `returnValue` 的行为；真机 v86 为 `hits=20, throttled=18, emitted=2, forcedReturn=20/20`。
- Syscall/trace 验收在扫描可变代码站点前重启沙盒，v50 探针调用后立即卸钩；v77 attribution、v80 trace digest、v81 syscall digest、v85 syscall trace 均通过。
- v91 JNI 验收缩小摘要时间窗，并在每个同步探针返回后立即卸钩；字段改写摘要、字符串、数组 region/element 与 JNI 家族探针均通过。
- 移除手机自动化模块 X 后，当前验收脚本清单为 **34 host + 79 device = 113**；手机自动化相关的旧 FAIL/SKIP 不再属于产品范围或门禁。

### 仍未完成或需决策

- **（2026-09-26 真机脱壳实战发现）"内存与 dump / dex 静态分析"与"JNI 面 / Java hook"两组的门禁结论
  只覆盖了沙盒自加载路径。** 在真机 Zygisk 注入路径下：①目标若 `prctl(PR_SET_DUMPABLE,0)`
  （SecNeo/梆梆系默认行为），`/proc/self/mem` 对自身返回 EACCES，`memory_read`/`memory_search`/
  `memory_dump`/`scan_magic`/`art_dexfiles` 全部失效；②agent 由 memfd 加载，`dlopen("libart.so")` 被
  linker namespace 拒绝（`not accessible for the namespace "(default)"`），拿不到 JavaVM，`art_dexfiles`/
  `java_hook`/`trigger`/`object_*` 全部返回 `no JavaVM`。两者都有明确修法（直接解引用读取回退；
  Zygisk 模块把 `env->GetJavaVM()` 传给 agent），**修完前不应把这两组算作真机可用**。
  详见 `PROGRESS.md` 2026-09-26 节。
- v84 native hook batch 目前只有 host 侧验收，尚未加入设备侧批量选择/行为验收。
- cdex/041 仍需真实样本；DEX 重建追加式布局保留旧副本作为 slack，文件会变大。
- Agent TCP `8761` 仍监听 `0.0.0.0` 且没有鉴权，LAN 信任边界待产品决策；完整 syscall 拦截（seccomp/PTRACE_SYSEMU）仍属 L3 未实现。
- `DEVELOPMENT_PLAN.md §6.9.5` 里除模块 X 以外的发布范围收口项仍需逐项确认。

## 3. 发布结论

- 当前代码范围为 `libadh_agent.so` + Zygisk/Manager + 三个可选后端（Gadget/Xposed/eCapture，默认关闭）；模块 X 已退役，AI 使用 adb 操作手机。
- 本轮源码门禁为 **113 PASS / 0 FAIL / 0 SKIP**，Device `:core:test :daemon:assembleDebug :manager:assembleDebug` 成功。协议 v13 对应的 release bundle 尚未重建/刷入，因此这些结果验证的是当前源码与 debug 构建，不代表已发布包升级完成。
- 已知边界：arm64-v8a only；Java/native 各 16 个并发 hook 槽；`-fomit-frame-pointer` 第三方库可能只能解析 1 帧；JNIEnv 表覆盖 228/229（唯一余项 `RegisterNatives` 由入口 inline hook 覆盖）；`FatalError` 事件为 best effort；高频事件可能受 capture ring 限流/丢弃；native_call 超时后目标调用无法取消；dex 重建会增大文件与内存峰值；Agent TCP `8761` 暂无鉴权；Gadget 使用官方二进制且默认关闭。
