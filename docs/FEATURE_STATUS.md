# ADH 功能状态（发布前梳理，2026-09-29 更新）

> 这份文件回答一个问题：**现在到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh`（**118 个脚本 = 36 host + 82 device**），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。
> 最近一次带真机全量门禁（2026-09-23，aa165071 / Android 15 / PGP110）：**113 PASS / 0 FAIL / 0 SKIP**。
> **2026-09-29 复跑为 host-only：36 PASS / 0 FAIL。** device 半段**未验证**，原因不是代码：当前设备
> `a22fecdd` 已授权（`adb devices` 报 `device`）但**沙盒 App 根本没装**（`pm list packages` 里没有任何
> adh 包，`am start` 报 Activity 不存在），所以 82 个 device 脚本既起不了沙盒也连不上 agent。
> 要恢复 device 半段：`cd sandbox-app && ./gradlew :app:assembleDebug` + `install_apk_root`。
>
> ### ⚠️ 2026-09-29（二）Linux 接管机上的真实数字：**103 PASS / 11 FAIL / 4 SKIP**
>
> 分档：**host 36 条 = 29 PASS / 5 FAIL / 2 SKIP**；**device 82 条 = 74 PASS / 6 FAIL / 2 SKIP**。
> 设备换回参考机 `aa165071`（SDK 35 / arm64 / SukiSU root），刷入的模块与 HEAD 逐字节一致
> （见 §0 交付物表），**未重刷即跑**。上面那个 "36/36 host" 不成立，原因见下。
>
> **11 条 FAIL 逐条查完，没有一条能归到产品代码**，分三类：
>
> | 类别 | 脚本 | 根因 |
> |---|---|---|
> | **环境（缺 Windows 工具链 / 依赖是 Windows 装的）** 7 条 | `v01` · `v02_so` · `v08_disasm` · `v08_analyze` · `v26_footprint` · `v29_dexindex` · `v30_fridagadget` | `cmake.exe` / `llvm-readelf.exe` / `llvm-objdump.exe` 写死在 Windows NDK 路径（`env.sh:17`、`analysis.ts:12`）；`v29` 是 2.1 GB WAL 模式 SQLite 放在 SMB 上的结构性超时（实测 466ms，预算 250ms；58k 方法的 dex 索引后首次查询 **49 秒**）；`v30` 是 `tools/frida/node_modules/esbuild` 装的是 **`@esbuild/win32-x64`**，Linux 上打不了包 |
> | **门禁自身缺陷** 2 条 | `v100_adh_cli` · `v101_crypto_variants` | 断言 `grep -qE '^ℹ fail 0$'` 匹配 node **spec reporter**，而命令替换永远是管道 → node 走 **TAP** 打 `# fail 0`，**断言永远不成立**。`v101` 的单元测试实际 **13/13 全过**。同类写法还在 `v99`/`v15_dumpall` 里。**✅ 这 4 处已于同日修掉**（收成 `verify_unit_pass`，附 5 项齿检）；`v100` 转 **22 checks/0 problems**、`v15_dumpall` device 段全绿、`v101` 由假红变如实 SKIP、`v99` 不再把 `RESULT:FAIL` 洗成假绿——详见 `PROGRESS.md` 同日第 9 条 |
> | **文档已登记的偶发/未定因** 2 条 | `v72_site_hooks_cross` · `v22_capture` | `v72` 的失败形态与 §2 记录的**逐字相同**（`scopeAll.siteCount:0` / `hits:3` / `target already hooked by id 1`）；`v22` 是记账不变量的已知抖动 |
>
> **4 条 SKIP 也全是环境**：`v37_agent_reconnect`（`netstat -ano \| grep LISTENING` 是 Windows-only）、
> `v90_jni_table_abi`（缺 NDK 的 `jni.h`——**JNIEnv 228/229 的机检在这台机器上被静默跳过**）、
> `v32_backend_control`（`gradle unavailable`）、`v99_artifact_store`（重启逻辑 Windows-only）。
>
> **方法学订正**：`HANDOVER §2.2` 那条 A 组 recipe 用 `bash tools/$s && echo PASS`，**把 SKIP 算成 PASS**
> （SKIP 一般 `exit 0`）——这就是 "36/36" 的来源。（`tools/verify_all.sh` 自身分得清，是文档里的 recipe 不对。）
> 逐条证据见 `PROGRESS.md` 2026-09-29（二）。
>
> ### 🔴 2026-09-30：根因是 **dex 索引库损坏**，不是"环境噪声"
>
> 上面那些"intermittent device 失败"的真根因只有**一个**：`adhd-data/dex-index.sqlite` 在 **SMB 共享树**上
> 被**两台机器同时写**，库损坏（`SQLITE_CORRUPT` / "database disk image is malformed"），
> 4 个 dex 里 3 个分类失败——而**四层静默吸收**让它看起来像无关的零散 flake：
> `realDexCount` 把没分类的算成真代码、`reportSummary` 丢掉 `classifyError`、
> `v15_dumpall` 的恒等式因同源推导而永真、`v08_xref` 把错误响应算成"这个 dex 0 个方法"。
> **四处都已修**（含新增 `ADH_DATA_DIR` 让索引脱离网络盘）。
> **实测效果**：`unpack` 1/4 → **4/4**（1 秒）；`v29` `queryMs` 466ms → **1.72ms 且 PASS**；
> `v15_dumpall` `shaped=1/4` → **`4/4` PASS**。详见 `PROGRESS.md` 2026-09-30（第 8–11 条）。
>
> **当前真实数字**（gate5，`ADH_DATA_DIR` 指向本地盘，103 PASS / 10 FAIL / 5 SKIP）。
> 其中 `v08_xref` 与 `v19_settings` 的失败**已在同一轮之后修掉并单独复验通过**，故实际遗留 **8 条**：
> 6 条环境（`v01` 缺 `cmake.exe`；`v02_so`/`v08_disasm`/`v08_analyze`/`v26_footprint` 缺 Windows 路径下的
> LLVM 工具，`v90` 因此 SKIP；`v30` 的 `frida/node_modules` 是 Windows 装的 esbuild）、
> 1 条文档已登记的偶发（`v22_capture` 记账抖动）、
> 1 条**未解决**（`v100` 在全量门禁里必红、单独跑必绿——已排除 5 条路并加了诊断，见 `PROGRESS.md` 第 12 条）。
> **下一步**：`HANDOVER §5` 第 1b 条**还剩 ①④**——① 工具链路径 host-aware + 本机装 `llvm`
> （救 `v02_so`/`v08_disasm`/`v08_analyze`/`v26_footprint`，并让 `v90` 从 SKIP 转真跑）、
> ④ `frida` 依赖分平台（救 `v30`）。（③ 索引脱离网络盘**已由本轮的 `ADH_DATA_DIR` 完成**。）
> **发布范围收口提案**（不做/降级的 10 项，含证据与"什么条件下重新考虑"）见 `DEVELOPMENT_PLAN.md §6.9.5`；需求口径修订建议（去特征对抗面、SKIP 分层、信任模型等 7 条）见 `REQUIREMENTS.md` 顶部"口径修订建议"——两者都是**待确认**，确认后合并进正文。

## 0. 发布物

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，release 剥离，836,432 B） | `tools/build_agent.sh` | ✅ 已验收（v01–v79 系列） |
| 最近一次 Zygisk 模块 zip + ADH Manager APK + 组合包（**v0.3.12**） | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ **设备上正在跑的模块已逐字节等于 HEAD**（2026-09-29 复核，HEAD `c273ef4`/`aa165071`）：`libadh_agent.so` `82e0cfb5…`、`manager.apk` `e0b2a83d…`、`daemon.apk` `87c2df98…`、`zygisk/arm64-v8a.so` `e565bfdc…` 四项与 `agent/build/`、`device/*/build/`、`injector/zygisk/.stage/` 完全一致；`com.adh.sandbox` 与本仓 `sandbox-app/…/app-debug.apk` 同一次构建。**因此不需要重刷即可跑全量门禁。**（旧结论"早于模块 X 退役和 Device AIDL v13、需重建 bundle 后再刷机"已作废——它描述的是更早的一次刷机。） |
| 可选后端：Xposed 薄模块 APK | `injector/xposed/` + `tools/build_xposed.sh` | ✅ 已验收（v31/v32），默认关闭 |
| 可选后端：Frida Gadget | `tools/fetch_frida_gadget.sh` + `load_frida_gadget.sh` | ✅ 已验收（v30），默认关闭；官方二进制（未魔改） |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ✅ 已验收（v34），默认关闭；需内核 eBPF |
| 开发用（不随发布物交付） | `sandbox-app/`、`sandbox-native/`、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **40 个命令分支**：GOT/inline/addr/sites/vtable hook、Java(LSPlant) hook（单方法 + `hookAll` 批量 + 参数改写/返回值替换/skip/调用链）、JNI_OnLoad（含加载时 watch）/RegisterNatives/JNIEnv 76 槽、函数与 QBDI trace、dex/so/内存 dump、maps/内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、`native_call`（整数+浮点）、`native_backtrace`、`syscall_watch`、轻量 RPC —— **只采集/执行，不做分析** | C/C++，产物 817 KB |
| **Host ADH Daemon**（主机） | `daemon/` | **67 个 MCP 工具 + 93 条 HTTP 路由**：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编与 syscall 归因/参数解码、trace 摘要、syscall 摘要、脱壳编排与重建、工件存储、Web UI、MCP server | TypeScript（含 19 个单测文件、169 条用例（2026-09-29 实测 `node --test test/*.test.ts` = 169 pass / 0 fail，旧记的 121 已过时）） |
| **Device**（手机侧） | `device/` | AIDL 作用域读写、模块状态、目标进程启停、可选后端开关 —— **不做分析** | Kotlin |
| **注入器** | `injector/zygisk`、`injector/xposed` | 把 `.so` 送进目标进程（Zygisk 走 **memfd**，目标 maps 不出现模块路径）+ 传真实包名 | C++/Java |
| **可选后端** | `tools/`（Gadget/eCapture） | 另一种进入/观测方式，默认关闭 | 脚本/薄 APK |

## 1. 测过的功能（按 verify_all 的脚本分组）

| 能力 | 覆盖脚本 | 验收要点 |
|---|---|---|
| 命令通道 / 协议分帧 | v02, v21_frame | 1MB 命令帧 + 16MB dump 跨帧字节一致 |
| 内存与 dump | v02_dump, v02_so, v22_capture, **v97(读取后端 + 强制直读覆盖全部读命令)** | 搜索/落盘/sha256 对照/去重；突发下 `emitted+backlog+dropped==seq` 如实记账 |
| dex 静态分析 / 修复 / 索引 | v03, v04_dexparse, v08_*, v09_methodcode, v12_rebuild, v13_recover, **v95(try/catch code_item)**, **v96(map_list 重建 + 布局自检)**, v29_dexindex | ART 结构枚举、常量扫描、xref、字节码恢复、重建与持久索引；**带 try/catch 的方法读全 `code_item`（header+insns+tries[]+handler 列表）并字节级重建一致**，解不动的 item 显式报 `unresolvable` 而不是算作已恢复；**重建把 code_item/class_data 重定位到文件末尾并重建 map_list**（map 现在描述文件本身，代价是旧副本作为 slack 保留、文件变大） |
| 原生反汇编 / 常量 / syscall 扫描 | v08_disasm, v08_analyze, v09_cryptoconst, v09_syscall | 内存镜像反汇编、导入导出、AES S-box、`svc #0` 直连点 |
| **变异（魔改）算法识别** | **v101** | 按**结构**识别而不是按标准常量：MD5 由未被改动的 K 表锚定、缺席的 init 作为变异证据（并报"标准 init 被原位改写 12/16"）；SHA1 **从另一端**锚定（IV 在位、轮常量被改）；置换码表按**形状**找到并数出漂移量（54）。变异判定**必须带证据**，且 `limits` 必须自述盲区（运行时生成的表、连锚点一起改的变异）。**并同时断言旧的标准常量扫描对教科书库与变异库返回同一组算法名、且在变异库上误报 `MD5-init`**（假阳性）——即这条能力补的是"两层同时瞎"的整类漏检。靶子是**编译产物**（`fixtures/crypto-variants/` + `build_crypto_variants.sh`），不是测试自己拼的 buffer |
| 加解密动态捕获 | v04_crypto, v11_capture, v24_javacap, v26_cryptocoverage | EVP 边界明文、富采集、ECDSA/AEAD 覆盖（含 APS2 packed reloc） |
| TLS / 文件 I/O | v07, v07_flow, v20_file, v25_fsbrowser | SSL_write/read 明文与关联；libc open/read/write 捕获 |
| 反检测观测与去特征 | v05_detect, v69(stealth), v70/v72(sites), v73/v74(vtable) | 目标自审（anon r-x、序言比对）；stealth 后 anonExec 2→0；sites 保持入口字节不变 |
| Java hook（LSPlant） | v42/v43/v52/v53/v65, **v79(stack)**, **v82(hookAll)**, **v83(java_trace digest)** | 单方法/构造器/继承、参数改写、返回值替换、skip original；`stack:true` 给出 App 帧调用链；`hookAll` 一次装全类（截断可见） |
| native hook | v46, v49, v55, v56, v66, v68, **v84(native_hook_all selection + 槽位预算)**, **v86(native throttle)** | inline/addr、软/硬卸载、寄存器事件、浮点参数、千次压测；限流只压事件、不改返回值替换；v86 真机 `forcedReturn=20/20` |
| JNI 面 | v54, v57, v58, v59, v60, v62, v63, v64, v67, **v90(表索引 ABI 机检)**, **v91(字段访问器 + 可改写 + 字段摘要 + 通配)**, **v92(字段摘要单测/接线)**, **v93(字符串+直接缓冲表项, host)**, **v90/v91(数组两族 + 创建/对象数组 + CallNonvirtual + 字符串/反射桥 + 覆盖 228/229, host)** | RegisterNatives、JNI_OnLoad（含加载时替换）、JNIEnv **228/229 表项（唯一余项 `RegisterNatives` 由 v4.14 的入口 inline hook 覆盖）**（99 固定 + 36 字段访问器 + 31 族 ×3：ID 查询 / Call* 三类入口 / 字符串与直接缓冲 / **数组 region 读写全族** / **数组元素 pin 与写回全族** / **数组创建 + 长度 + 对象数组元素 + AllocObject** / **CallNonvirtual 三形态全族（事件带 `via=<class>`）** / **字符串全族（含 critical 对）** / **反射桥 `From/ToReflected*`** / `FatalError` / `ExceptionCheck` / 引用生命周期 / 异常流 / 类型自省 / monitor 与弱引用，索引逐条与 NDK `jni.h` 对照，见 v90；wrapper 签名由 `_Static_assert` 编译期钉死；`action:status` 支持用 `function` 过滤（含 `installed` 关键字）并自报 `total/matched/emitted/truncated`，整表 228 项的回复不再静默截断；固定槽位由**单一列表**同时驱动枚举值与名字表（v4.82），并有**运行期布局自检**——枚举与表任何错位都会拒绝 patch 并点名位置，而不是挂到隔壁函数）、Call* 三类入口、数组写回、异常保持 |
| 主动调用 / 活体对象 | v45(java_call), v49(native_call), v51(qbdi args), v06(对象读/调用), **v89(字段写入)** | 反射调用 Java 方法/字段；按符号或地址调 native；活体对象字段**读+写**（写入带 before/after；**严格解析**：typo/越界/int 超范围一律拒绝，不再静默写 0；final 字段 fail-loud；参数超长拒绝而不是截断；**字段查找与枚举走父类链**，继承字段不再报 not found） |
| trace | v10_trace, v10_qbdi, **v78(backtrace)** | 函数参数/线程/时间戳；QBDI 指令级（用后 dlclose）；hook 命中当刻的 x29 调用链 + 符号化 |
| 内存反汇编（MCP） | v48 | Capstone 5 WASM，绝对地址或 module+offset |
| 内存扫描瞄准 | **v15/v97 家族**（`memory_search`/`memory_scan_magic` 的 `minAddr`/`maxAddr`） | 窗口外区域**跳过**而非裁掉，回复回显生效窗口（`all` / `lo-hi`）并报 `regionClipped`/`truncated`——部分扫描不会读起来像全扫描 |
| 系统调用监听 | v50(direct), **v76(归因)**, **v77(libc+过滤)**, **v81(摘要+参数)**, **v85(syscall_trace 装配)**, **v86(native throttle)** | 直接 `svc #0` 捕获；静态归因（223/224 libc 站点）；按名/号过滤只装命中站点；`syscall_digest` 给调用方/次数/`paths` 直方图，并比对运行期 x8 与归因号 |
| 一键 dump 所有 DEX | v15, v17, **v15(逐 dex 分类 carrier/real + 同 pass 建索引)** | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载（REST+MCP）；**每个 dex 带 `classes`/`methods`/`carrier` 判定**（诱饵壳 vs 真代码），并复用 `ensureDexIndex` 在同一次 pass 建索引 |
| 进程内 dlopen | v18 | 目标进程内加载任意 `.so` 并解析符号 |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, v32_backend_control, **v75(memfd)**, **v98(注入路径的 Java 面)** | scope 往返；后端状态/作用域可控并恢复；**agent 从 memfd 加载**（目标 maps 无模块路径，目标内自证 + ELF 头） |
| 可选后端 | v30, v31, v34 | 官方二进制 + sha256 固定；Xposed Java bridge；eCapture 抓明文 |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions, **v71(registry)**, **v80(trace digest)**, **v83(java trace)**, **v84(native batch)**, **v85(一站式 syscall)**, **v86(throttle)**, **v87(MCP 可操作性)** | MCP 67 个工具可调；注册表形状自检；Web UI；会话清理 |
| **`adh` 命令行** | **v100** | `doctor`（daemon 健康 + **刷入的 agent 版本 vs 本仓源码版本**配对 + 后端矩阵）· `target`（解析**唯一** agent——歧义时报错而不是静默换进程——并报活体事实）· `unpack`（一键 `dump_all_dex` + 逐 dex 分类 + `--out` 落盘）；纯客户端（只 import `config.ts`，可打远程 daemon）。**每个 flag 都由效果证**：`--port`/`--host` 由错误里的 base URL、`--timeout` 由"2 秒预算真的在 ~2s 内结束"、`--json` 由输出形状、`--package`/`--session` 由它拒绝解析的目标、`--out`/`--include-carriers` 由落盘文件数。它是"找在线 agent 取 session"这段逻辑的**唯一实现**（此前 76 个 verify 脚本各抄一份）。**`target`/`unpack` 的真机端到端已于 2026-09-29（二）验证**：`v100` 真机 **22 checks / 0 problems**，含 `target` 报出唯一 agent + 活体事实、`unpack` 逐 dex 分类、`--out` 每个真 dex 落盘且字节数与报告一致。（页首 2026-09-28 那条"尚未验证"已作废。） |
| 手机自动化（模块 X） | 已退役，不纳入验收范围 | AI Agent 直接使用 adb 操作手机；ADH 不再提供 AccessibilityService、通知读取、phone_* MCP 工具或设备输入控制桥 |
| 注入足迹 | v26_footprint, v01 | release 剥离 + 仅 3 个动态导出 + 无 RWX LOAD |
| 字符串去特征 | **v88**, scan_agent_signatures, patch_vendor_signatures | 自己的 tag/文案/自名/fixture 默认值全部清零（含 DT_SONAME）；vendored LSPlant 的三处（含运行时 dex source name）由 fetch 期补丁清掉并机检；剩余 Dobby/导出/Java bridge 等按只许降预算记账；门禁带**负对照**（植入 token 必须被抓到） |
| MCP 可操作性 / 设备文件系统 | **v87**, v25_fsbrowser, **v89(object_set)** | 每个 agent op 必须能从 MCP 导入图到达（否则在 `INTERNAL_OPS` 写明理由）：`fs_list`/`fs_read` 与 REST 共用实现；存活/引擎/通道三个探针的判定显式（引擎 `ok` = fired && protRestored） |
| 单元测试（host） | v76, v80, v81, v83, v84, v85, **v86**, **v87** | syscall 归因/参数解码/一站式装配、trace 摘要、backtrace dynsym、Java trace（含三阶段装配与 drain 守卫）、native 批量选择、native 限流（默认/夹紧/拒绝垃圾值 + 安装回路真实 payload）、探针判定与设备文件读取（二进制/超大/截断/坏 base64）：**169 条** `node --test` 用例（2026-09-29 实测；旧记 121 已过时） |

## 2. 真机验收结果与当前遗留项（2026-09-23）

> `tools/verify_all.sh` 在 aa165071（OnePlus PGP110 / Android 15）上实际执行：**113 PASS / 0 FAIL / 0 SKIP**。PASS 表示当前验收脚本通过，不代表所有路线图项都已实现。

### 本轮修复并验收

- QBDI `qbdi_addCodeCB()` 以 `QBDI_INVALID_EVENTID` 作为失败哨兵；事件 ID `0` 是有效值。修复后带参/无参 QBDI trace 与 trace digest 均通过。
- Native hook 限流只抑制事件记录，不再覆盖 `skipOriginal` / `returnValue` 的行为；真机 v86 为 `hits=20, throttled=18, emitted=2, forcedReturn=20/20`。
- Syscall/trace 验收在扫描可变代码站点前重启沙盒，v50 探针调用后立即卸钩；v77 attribution、v80 trace digest、v81 syscall digest、v85 syscall trace 均通过。
- v91 JNI 验收缩小摘要时间窗，并在每个同步探针返回后立即卸钩；字段改写摘要、字符串、数组 region/element 与 JNI 家族探针均通过。
- 移除手机自动化模块 X 后，当前验收脚本清单为 **34 host + 79 device = 113**；手机自动化相关的旧 FAIL/SKIP 不再属于产品范围或门禁。

### 仍未完成或需决策

- **（2026-09-26 真机脱壳实战：已修）"内存与 dump / dex 静态分析"与"JNI 面 / Java hook"两组原先只在
  沙盒自加载路径下过门禁，在真机 Zygisk 注入路径下有两条静默失效路径，现已在 agent 内修掉并真机验证：**
  ①目标 `prctl(PR_SET_DUMPABLE,0)`（SecNeo/梆梆系默认行为）会让 `open("/proc/self/mem")` 对自身返回
  EACCES，`memory_read`/`memory_search`/`memory_dump`/`scan_magic`/`art_dexfiles` 一起失效 —— 现在
  由 `bootstrap/mem_read.c` 的**边界检查直读**兜底（SIGSEGV/SIGBUS 短守卫），fd 按命令释放，
  每回复点名实际路线；②agent 由 memfd 加载时 `dlopen("libart.so")` 被 linker namespace 拒绝，
  拿不到 JavaVM —— 现在从已加载的 libart.so **按内存镜像查 `JNI_GetCreatedJavaVMs`**，Gadget/Xposed
  后端同样受益。真机复验：学习通无需任何绕法即可 `memory_search` / `art_dexfiles`（14 个 DexFile）/
  一键 `dump_all_dex`，且 13 个真 dex 与手工提取结果 sha256 逐字节相同。验收脚本
  `tools/verify_v97_memread_direct.sh` 已入门禁。详见 `PROGRESS.md` 2026-09-26（续）节。
  同一轮还做了两项加固：内存扫描的预算不再被框架 OAT 吃光（截断如实上报 `truncated`/`regionClipped`），
  以及 `dex_repair` 不再把整份修复后的 dex 内联回吐（120MB → 160MB base64），改为落成可按 sha 取回的工件。
- **（2026-09-26 发现，未归属）`verify_v72_site_hooks_cross.sh` 偶发 FAIL**（`scope=all` 的站点扫描报
  `siteCount:0`，但钩子确实装上且命中 3 次；随后按名 scope 的调用被拒 `target already hooked by id 1`）。
  · **与本次改动无关**：`git stash` 摘掉全部改动重建 agent 后失败形态**逐字相同**。
  · 但它是**间歇**的（随后又 PASS 过整轮，`FAIL` 时也能复现）——"稳定失败"这个说法是当时的初判，不成立。
  · **2026-09-26 追到线索**：缺口是**恒定**的（`seq - accountedFor` 两次都是 22），不是竞态。
    `g_cap_seq` **只在 native `capture()` 里自增**（Java 富采集路径不推它），所以不是 Java 那条；
    而 invariant 里的 `emitted` 是 **daemon 把"它自己观察到的** drain 回复里的 `ncaps` 累加**出来的——
    凡是被**别的消费者** drain 掉、而那条路径没有把计数记进 `capStats` 的，就会让 `accountedFor < seq`。
    → 下一次查这条时从"谁还会 drain（`withCaptureSuspended` / 一次性探针 / 其它读 `/api/captures` 的路径）"
    入手，而不是从环形缓冲本身。
  · 第 3 项（`native_hook` 机制自证）已落地并单独跑过 v72：**仍需复看**——本轮它在 9 项 native hook
    家族里 PASS 过、整轮门禁里也 PASS 过，所以第 3 项**没有**解决它，也**没有**证据说它与之相关。
    症状（`hAll = status.hooks[0]` 取到的不是刚装的那个）更像调用方按数组下标取钩子，
    而 status 的 hooks 顺序在并发安装下不保证；把它归到"偶发、未定因"，不要当成已修。
- **（2026-09-26 加固，第 2 项）工件生命周期**：`dumps` 只在内存 → 重启 daemon 后磁盘工件全部不可见
  （`dumps_list`/按 sha 下载/`dex_index` 一律答"没有"）；`captures/` 无任何回收（实测一轮约 1.27GB）。
  现在启动时从磁盘**重新哈希采纳**（来源标 `disk-reload`，不编造 provenance），并按新增的
  `settings.artifacts{maxBytes,maxAgeDays}` 回收——删工件的同时删 dex 索引行（陈旧索引比没有更糟）。
  策略抽在纯模块 `daemon/src/artifacts.ts` 里并有 8 项单测；验收 `tools/verify_v99_artifact_store.sh`
  会**真的重启 daemon**，断言 281 个工件全部回流。
- **（2026-09-26 发现）`verify_v22_capture.sh` 的记账不变量 `emitted+backlog+dropped==seq` 偶发不成立，
  缺额约 5.5k 且形态稳定，与本次内存读取改动无关**——用 `git stash` 摘掉全部改动重建基线 agent 后同样不成立，
  同一天的后续整轮回归里它又 PASS。属未定因的抖动，建议单独排查（capture ring 在超高 burst 下的记账）。
- v84 native hook batch 目前只有 host 侧验收，尚未加入设备侧批量选择/行为验收。
- cdex/041 仍需真实样本；DEX 重建追加式布局保留旧副本作为 slack，文件会变大。
- **Agent TCP `8761` 监听 `0.0.0.0` 且无鉴权 —— 待产品决策（2026-09-26 复核后仍未改）。**
  三条路各有权衡：**加 token 校验**（要改协议握手，需同步 Device Daemon 与验收）、
  **只绑 `127.0.0.1`**（最小改动，依赖 adb reverse，但会去掉「手机浏览器直连局域网」那条路）、
  **维持现状**（信任 LAN）。这是信任模型选择而非技术债，且**改动面跨 Device Daemon / Manager /
  adb reverse 三处**，所以没有在本轮加固里顺手改。
  完整 syscall 拦截（seccomp/PTRACE_SYSEMU）仍属 L3 未实现（`DEVELOPMENT_PLAN §6.9.5` 建议不做）。
- `DEVELOPMENT_PLAN.md §6.9.5` 里除模块 X 以外的发布范围收口项仍需逐项确认。

## 3. 发布结论

- 当前代码范围为 `libadh_agent.so` + Zygisk/Manager + 三个可选后端（Gadget/Xposed/eCapture，默认关闭）；模块 X 已退役，AI 使用 adb 操作手机。
- 本轮源码门禁为 **113 PASS / 0 FAIL / 0 SKIP**，Device `:core:test :daemon:assembleDebug :manager:assembleDebug` 成功。协议 v13 对应的 release bundle 尚未重建/刷入，因此这些结果验证的是当前源码与 debug 构建，不代表已发布包升级完成。
- 已知边界：arm64-v8a only；Java/native 各 16 个并发 hook 槽；`-fomit-frame-pointer` 第三方库可能只能解析 1 帧；JNIEnv 表覆盖 228/229（唯一余项 `RegisterNatives` 由入口 inline hook 覆盖）；`FatalError` 事件为 best effort；高频事件可能受 capture ring 限流/丢弃；native_call 超时后目标调用无法取消；dex 重建会增大文件与内存峰值；Agent TCP `8761` 暂无鉴权；Gadget 使用官方二进制且默认关闭。
