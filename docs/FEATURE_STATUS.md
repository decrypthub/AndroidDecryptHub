# ADH 功能状态（发布前梳理，2026-09-19 更新）

> 这份文件回答一个问题：**现在到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh`（**115 个脚本 = 31 host + 84 device**），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。
> 最近一次**全绿**门禁：`6319d5d`（设备在位，**92 PASS / 0 FAIL / 2 SKIP**）。
> 最近一次 host-only 门禁（手机不在位）：**31 PASS / 0 FAIL / 84 SKIP** —— 设备脚本如实记 SKIP，不再冒充通过。

## 0. 发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，release 剥离，836,432 B） | `tools/build_agent.sh` | ✅ 已验收（v01–v79 系列） |
| Zygisk 模块 zip + ADH Manager APK + 组合包（**v0.3.10**） | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ 已验收（v27）+ 真机刷入（memfd 注入 v4.37） |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭；官方二进制（未魔改） |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭；需内核 eBPF |
| 开发用（不随发布物交付） | `sandbox-app/`、`sandbox-native/`、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **40 个命令分支**：GOT/inline/addr/sites/vtable hook、Java(LSPlant) hook（单方法 + `hookAll` 批量 + 参数改写/返回值替换/skip/调用链）、JNI_OnLoad（含加载时 watch）/RegisterNatives/JNIEnv 76 槽、函数与 QBDI trace、dex/so/内存 dump、maps/内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、`native_call`（整数+浮点）、`native_backtrace`、`syscall_watch`、轻量 RPC —— **只采集/执行，不做分析** | C/C++，产物 817 KB |
| **Host ADH Daemon**（主机） | `daemon/` | **78 个 MCP 工具 + 88 条 HTTP 路由**：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编与 syscall 归因/参数解码、trace 摘要、syscall 摘要、脱壳编排与重建、工件存储、Web UI、MCP server | TypeScript（含 13 个单测文件、151 条用例） |
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
| native hook | v46, v49, v55, v56, v66, v68, **v84(native_hook_all selection + 槽位预算)**, **v86(限流装配，仅 host)** | inline/addr、软/硬卸载、寄存器事件、浮点参数、千次压测；限流窗口/计数只做了**装配**验收（host），运行时恒等式 `hits = 已发 + throttled` 待真机（§2） |
| JNI 面 | v54, v57, v58, v59, v60, v62, v63, v64, v67, **v90(表索引 ABI 机检)**, **v91(字段访问器 + 可改写 + 字段摘要 + 通配)**, **v92(字段摘要单测/接线)**, **v93(字符串+直接缓冲表项, host)**, **v90/v91(数组两族 + 创建/对象数组 + CallNonvirtual + 覆盖 215/229, host)** | RegisterNatives、JNI_OnLoad（含加载时替换）、JNIEnv **215/229 表项 = 94%**（86 固定 + 36 字段访问器 + 31 族 ×3：ID 查询 / Call* 三类入口 / 字符串与直接缓冲 / **数组 region 读写全族** / **数组元素 pin 与写回全族** / **数组创建 + 长度 + 对象数组元素 + AllocObject** / **CallNonvirtual 三形态全族（事件带 `via=<class>`）** / 引用生命周期 / 异常流 / 类型自省 / monitor 与弱引用，索引逐条与 NDK `jni.h` 对照，见 v90；wrapper 签名由 `_Static_assert` 编译期钉死）、Call* 三类入口、数组写回、异常保持 |
| 主动调用 / 活体对象 | v45(java_call), v49(native_call), v51(qbdi args), v06(对象读/调用), **v89(字段写入)** | 反射调用 Java 方法/字段；按符号或地址调 native；活体对象字段**读+写**（写入带 before/after；**严格解析**：typo/越界/int 超范围一律拒绝，不再静默写 0；final 字段 fail-loud；参数超长拒绝而不是截断；**字段查找与枚举走父类链**，继承字段不再报 not found） |
| trace | v10_trace, v10_qbdi, **v78(backtrace)** | 函数参数/线程/时间戳；QBDI 指令级（用后 dlclose）；hook 命中当刻的 x29 调用链 + 符号化 |
| 内存反汇编（MCP） | v48 | Capstone 5 WASM，绝对地址或 module+offset |
| 系统调用监听 | v50(direct), **v76(归因)**, **v77(libc+过滤)**, **v81(摘要+参数)**, **v85(syscall_trace 装配)**, **v86(限流装配，仅 host)** | 直接 `svc #0` 捕获；静态归因（223/224 libc 站点）；按名/号过滤只装命中站点；`syscall_digest` 给调用方/次数/`paths` 直方图，并比对运行期 x8 与归因号 |
| 一键 dump 所有 DEX | v15, v17 | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载（REST+MCP） |
| 进程内 dlopen | v18 | 目标进程内加载任意 `.so` 并解析符号 |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, v32_backend_control, **v75(memfd)** | scope 往返；后端状态/作用域可控并恢复；**agent 从 memfd 加载**（目标 maps 无模块路径，目标内自证 + ELF 头） |
| 可选后端 | v30, v31, v34 | 官方二进制 + sha256 固定；Xposed Java bridge；eCapture 抓明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions, **v71(registry)**, **v80(trace digest)**, **v83(java trace)**, **v84(native batch)**, **v85(一站式 syscall)**, **v86(throttle)**, **v87(MCP 可操作性)** | MCP 76 工具可调；注册表形状自检；Web UI；会话清理 |
| 手机自动化（模块 X） | v36, v38, v39, v40, v41 | 树/截图/选择器/手势/输入/wait/通知/技能；硬超时、桥接自愈、root 输入、屏幕状态；**重启后的 OEM 弹窗按 BACK 有界重试** |
| 注入足迹 | v26_footprint, v01 | release 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |
| 字符串去特征 | **v88**, scan_agent_signatures, patch_vendor_signatures | 自己的 tag/文案/自名/fixture 默认值全部清零（含 DT_SONAME）；vendored LSPlant 的三处（含运行时 dex source name）由 fetch 期补丁清掉并机检；剩余 Dobby/导出/Java bridge 等按只许降预算记账；门禁带**负对照**（植入 token 必须被抓到） |
| MCP 可操作性 / 设备文件系统 | **v87**, v25_fsbrowser, **v89(object_set)** | 每个 agent op 必须能从 MCP 导入图到达（否则在 `INTERNAL_OPS` 写明理由）：`fs_list`/`fs_read` 与 REST 共用实现；存活/引擎/通道三个探针的判定显式（引擎 `ok` = fired && protRestored） |
| 单元测试（host） | v76, v80, v81, v83, v84, v85, **v86**, **v87** | syscall 归因/参数解码/一站式装配、trace 摘要、backtrace dynsym、Java trace（含三阶段装配与 drain 守卫）、native 批量选择、native 限流（默认/夹紧/拒绝垃圾值 + 安装回路真实 payload）、探针判定与设备文件读取（二进制/超大/截断/坏 base64）：**121 条** `node --test` 用例（合计含 automation 30 条 = 151；v81/v83/v86/v87 按文件最小数断言） |

## 2. 待真机验证（代码 + host 验收已完成，手机不在位）

| 项 | 内容 | 脚本 |
|---|---|---|
| syscall 归因比率/数字过滤 | `attributedCount ≥ 90% svcCount`、`syscalls:['178']` | v77 |
| hook 回溯健壮性 | `btTruncated` → `frame-cap-reached`、`bt[]` 帧 `-4` 修正、槽位复用不复用旧开关 | v78 |
| Java 调用链 | `stack:true` 链里两个 fixture 帧 + 不带 stack 时无链 | v79 |
| trace 摘要 | 对 `libadhdetect.so:adh_add_target` 实跑 `trace_digest`（**脚本已就绪**） | v80_device |
| syscall 摘要 | libc `uname` 站点 → 调用方必须是 `adh_libc_uname_probe`、observed 全 160、无 mismatch（**脚本已就绪**） | v81_device |
| Java 批量挂钩 | 两个 `ping` 重载各自出事件；类级 `limit=3` 显示 `installed=3 < matched` | v82 |
| Java 类级 trace | start 挂 HookProbe → java_call stackOuter → digest 给出两个重载各自次数与调用方 → stop 后进程存活（**脚本已就绪**） | v83_device |
| 一站式 syscall 跟踪 | libc uname 站点 start → 触发 adh_libc_uname_probe → digest 调用方是该 fixture、observed 全 160、无 mismatch → stop 后存活（**脚本已就绪**） | v85_device |
| native 批量挂钩 | 对 libadhdetect.so 用 prefix:adh_ 装一批 → 触发 → unhook 全部 → 进程存活 | v84（设备半） |
| 签名去特征（运行期，**脚本已就绪**） | 目标进程内用 agent 自己的 search 扫已加载镜像（带正对照 `native_hook`，扫不到正对照则 FAIL）；`qbdi_trace`/`trace_digest` 现在 **symLib 必填**（MCP schema + REST 400），v10_qbdi 已改显式传参 | v88_device/v51/v10_qbdi/v02_so |
| JNIEnv 字段访问器 + 写入改写（严格解析+范围检查+status `override`）+ 摘要（区分改写）+ 字符串/直接缓冲表项 | hook `Get/Set<Type>Field`（instance+static）→ 触发沙盒 native 探针 → 事件必须带 `field=0x.. value=..`、**字段摘要能把访问还原成 `Class#name:sig`**（靠 GetFieldID 事件带出的 id）且**被 setValue 改写的写入单列**（rewrittenSamples/lastRequested vs lastValue）、**`setValue` 覆盖 `SetIntField` 后目标里的值真的变成覆盖值**、**摘要报出 `rewrittenSamples/lastRequested`**、**字符串拷贝事件带文本预览与直接缓冲的 address/capacity**、**数组区域 14 个表项逐条 `start/len/first=[…]` 断言**（夹具 `jniArrayRegionProbe` 七种类型往返，返回 `0xAD707F` 才算全过）、**数组元素 14 个表项逐条形状 + 预览断言**（Get 带 `isCopy`、Release 带 `mode`；copyback 必须落值、`JNI_ABORT` 必须丢弃，夹具 `jniArrayElementsProbe` 返回 `0xAD80FF`）、RELRO 还原、进程存活（沙盒夹具 `jniFieldProbe`/`jniStringProbe`/`jniArrayRegionProbe`/`jniArrayElementsProbe` 已在 host 构建通过；**失败/跳过路径也统一卸载**，不会把改过的表留给下一个脚本） | v91（**脚本已就绪**） |
| 活体对象字段写入 | `object_set` 在沙盒上把 `HeapProbe.sConfig` 的 `flag/counter/label` 改掉 → 后续读取必须看到新值 → **继承字段 `inherited`（声明在父类）写入后复读为 9 且声明类正确** → `note`（Kotlin val/final）必须 ok:false → typo/越界值必须被拒 → 还原后进程存活 | v89（**脚本已就绪**） |
| MCP 探针与文件系统（**脚本已就绪**） | `agent_ping` 往返延迟、`engine_selftest` 在沙盒上 `fired && protRestored`、`protocol_selftest` 1MB 帧完整、`fs_list`/`fs_read` 走 `/data/data/com.adh.sandbox` 与 `/proc/self/cmdline`（v25 老断言必须继续过） | v87_device |
| native 事件限流（**脚本已就绪**） | libc 热站点（`read`/`write`）用 `throttleMs:200`：事件间隔 ≥ 窗口、`hits = 已发事件 + throttled`、`throttled` 单调递增；带 `returnValue`/`skipOriginal` 的钩子每一次命中都生效 | v86_device |
| 门禁抖动定性 | gate11 的 v11/v16/v20 单独复跑（评审判定为设备状态级联，非回归） | — |
| 采集链路回归 | `service.ts` 的 drain 重构（共享 `drainSession`，java_trace/syscall_digest 不再裸发 `capture_drain`）需要设备复跑采集家族：v04_crypto / v11 / v16 / v20 / v22 / v26 | — |
| 全量门禁 | 手机接回后跑到全绿，把数字写回本文件与 `PROGRESS.md` | — |

## 3. 发布结论

- 可以发布：`libadh_agent.so` + Zygisk 包/Manager（v0.3.10）+ 三个可选后端（Gadget/Xposed/eCapture，均默认关闭）。
- 发布口径只认 `verify_all.sh` 的 pass/fail 与本文 §1；§2 的项在真机复验前不算通过。
- 已知边界（不隐瞒）：arm64-v8a only；**v4.76 修掉一个从 v4.55 潜伏至今的错位**——`ENV_SLOT_CallStaticVoidMethod_end` 这个算术锚点吞掉了一个枚举值，导致 36 个字段访问器的枚举值比表位置大 1、安装时被 `table entry unavailable` 拒绝（字段钩子/`setValue` 改写/字段摘要因此从未真正挂上）；现已改为不吞槽位的别名锚点，并加两条编译期不变式（表长 == `ENV_HOOK_MAX`、末字段 == `ENV_HOOK_MAX-1`）钉死枚举与表的对应关系；Java/native 各 16 个并发 hook 槽（`status` 报告 `slots{max,used,active,free,byMode}` 与 `maxHooks`：**`used` = 已占用槽位**，软卸载的 inline 钩子仍占、失败装不再占；批量安装按 `free` 截断并在 0 空闲时 fail-loud）；`-fomit-frame-pointer` 的第三方库只能拿到 1 帧调用链；JNIEnv 面覆盖「ID 查询 + Call*/NewObject 三形态 + 字符串/直接缓冲 + **数组 region 读写全族** + **Get/Release<Type>ArrayElements 指针族** + 36 个字段访问器 + 引用生命周期 + 异常流 + 类型自省与 monitor/弱引用」；覆盖率现在是**可测的数字**：`tools/verify_v90_jni_table_abi.sh` 输出 `coverage: 215/229 function-table entries hooked (94%)` 与**未覆盖名单**（`NewString`/`GetStringLength`/`GetStringUTFLength`/`ReleaseStringUTFChars`/`Get+ReleaseStringCritical`、`FromReflected*`/`ToReflected*`、`FatalError`/`UnregisterNatives`/`ExceptionCheck`…），门禁下限 215；下一步补哪些槽位由这份名单决定，而不是手感。高频事件用 `throttleMs` 限流（实现 + host 验收完成，真机验证待做），事件环另有 `dropped` 记账；全量 syscall 拦截（seccomp/PTRACE_SYSEMU）仍属 L3 未实现；Frida Gadget 后端用官方二进制（未魔改去特征）。