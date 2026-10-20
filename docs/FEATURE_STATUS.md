# ADH 功能状态（2026-10-13 新增：SSL 绕过开关 + 多进程作用域修复；2026-10-12 新增：逐包 Hook 策略；2026-10-11 范围变更：可选注入后端收窄；全量设备验收仍以 2026-10-01 为准）

> 这份文件回答一个问题：**现在到底有什么、什么是验证过的、什么是没验证的、什么还没做完。**
> 判定只认 `tools/verify_all.sh`（**118 个脚本 = 36 host + 82 device**），不认"看起来能跑"。
> 规格见 `REQUIREMENTS.md`，架构与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。
>
> ### ✅ 2026-10-01 本轮：范围收口 + 沙盒耦合清零
>
> 1. **两份"待确认"提案已并入正文**：`DEVELOPMENT_PLAN §6.9.5` 的 10 项收口与 `REQUIREMENTS`
>    的 7 条口径修订全部确认，结论写进 §6.9.1/§6.9.2/§6.10/§9/§22.3/§20.1 等对应章节，
>    **两块提案原文已删除**（不再有第二份计划）。唯一仍未决的是 agent TCP `8761` 的信任模型（§20.1）。
> 2. **9 条沙盒耦合命令真删**（§6.9.5 原列 8 条 + 同形态的 `file_hook_test`）：
>    `crypto_hook_test` `net_hook_test` `file_hook_test` `flow_watch` `detect_watch` `trace_run`
>    `inline_crypto_test` `crypto_probe` `jni_probe`。它们的真耦合不是类名（类名本来就从命令来），
>    而是**把触发契约写死成目标的 `run()`**（其中 3 条还写死 `libjavacrypto.so`）——
>    grep 门禁看不见的那一半。
> 3. **能力不丢，改由真实原语提供**：持续捕获 `capture_start`/`capture_stop`（**新做成 MCP 工具**，
>    回报 `installed/attempted/notInstalled` 裁决，且**先归零再装**所以计数权威）+ `java_call`
>    （class/method/args 全部来自命令）+ `native_hook`(got/inline/sites/vtable) + `got_enum`/`compat_probe`；
>    网络↔加密关联搬到 daemon 的纯模块 `daemon/src/flow.ts`（10 条单测，含跨线程负例与窗口边界）。
> 4. **计数变化**（每一条都可现场复算）：agent 命令分支 42 → **33**；MCP 工具 69 → **65**；
>    HTTP 路由 93 → **84**；`INTERNAL_OPS` 6 → **1**；门禁 118 → **117**（eCapture 降级为实验脚本、移出闸门）。
> 5. **新增红线门禁**（`verify_v87_mcp_operability` 内，**两侧都查**）：`agent/src` 与 `daemon/src` 的
>    `com.adh.sandbox` 常量 = 0、agent 内无硬编码目标模块名、9 条禁令 op 不得回归、
>    `capture_start/stop` 必须走共享实现 `setCapture`。
> 6. **daemon 变成真正的 target-agnostic**：`state.ts` 里的 `SANDBOX`（9 个沙盒类名）已删除。
>
> ### 门禁数字
>
> | 轮次 | 结果 | 说明 |
> |---|---|---|
> | 本轮**改动前**基线（2026-10-01，本机全量） | **109 PASS / 5 FAIL / 4 SKIP** | 5 条 FAIL 里 3 条不是产品问题：`v87`/`v94` 在编辑中途被抓到（agent 已删、路由未删的中间态）、`v08_xref` 是 SMB 写回抖动（复跑 PASS）。排掉后 = **112 / 2 / 4**，与 2026-09-30 记录一致 |
> | 本轮**改动后**（2026-10-01，全量） | **114 PASS / 1 FAIL / 2 SKIP** | 同一台设备 `aa165071`，设备上 agent sha `7ec9834b…`（`tools/build_agent.sh --deploy` 构建并部署；`install_apk_root` 也会自动回刷）。唯一 FAIL 是本机缺 gradle 的 `v01`，`v31`/`v32` 同样因缺 gradle 重建模块 APK 而 SKIP |
>
> 排除在外的既有噪声（两次都一样）：`v01`（本机缺 Windows 路径下的完整构建链）、`v22_capture`（已登记的记账抖动）、
> `v31`/`v32`（缺 gradle 重建模块 APK）—— **`v37`/`v99` 已不再是 SKIP**（跨平台进程控制 + 冷启动预算，见 `tools/lib/verify_common.sh`）。逐条历史见 `PROGRESS.md`。

## 0. 发布物

> **2026-10-09 补记**：公开仓库已发布 [v0.3.12 可刷入预发布包](https://github.com/decrypthub/AndroidDecryptHub/releases/tag/v0.3.12)，包含 Zygisk 模块、Agent、Root Device Daemon 和 Manager；ZIP SHA-256 为 `8c09b1ace579b6a4d84bea06523151729f547f12b88eee685cb0a6e351c73695`。本次只通过构建、ZIP/签名/架构主机检查，**未刷入专用 root 设备，未跑新一轮设备门禁**。下表的旧设备 hash 与设备验收结果仍是 2026-10-01 的历史状态。

| 交付物 | 来源 | 状态 |
|---|---|---|
| `libadh_agent.so`（arm64-v8a，release 剥离，**1,019,520 B**，sha `b8dc7137…`） | `tools/build_agent.sh`（**2026-10-01 起也可在本机用 NDK r29 + cmake 构建，见 `HANDOVER §1.5`**） | ✅ 已验收（v01–v79 系列 + **v102**；2026-10-12 逐包 Hook 策略加入后重建，`v26_footprint` 断言动态导出恰好 4 个）。**2026-10-13 晚当前产物（1,021,856 B，sha `587bff9f…`）**：删掉 Java SSL 绕过 profile、`TrustAllManager`、`bypassKind`。已写入 `aa165071` 的模块目录（沙盒与模块路径同一 hash）。签名扫描 PASS。`v75` / `v42` / `v102` 没有在这份 so 上复跑。`v104` 随该功能删除 |
| 2026-10-01 设备上的旧 Zygisk 模块 zip + ADH Manager APK（**v0.3.12**；与 2026-10-09 新发布包区分） | `tools/build_zygisk.sh` / `build_bundle.sh` / `flash_device.sh` | ✅ 模块 zip 与 APK 是 2026-09-29 那次刷机的产物（`manager.apk` `e0b2a83d…`、`daemon.apk` `87c2df98…`、`zygisk/arm64-v8a.so` `e565bfdc…`）。**agent 已于 2026-10-01 更新为 `78d9d20f…`**（本机 NDK r29 构建），同时写进设备的两条路径：沙盒 `…/lib/arm64/libadh_agent.so`（模拟注入）与 `/data/adb/modules/adh/libadh_agent.so`（Zygisk 注入）。这段记录只描述旧设备状态，不代表新 Release 已刷入。 |
| ~~可选后端：Frida Gadget~~ | 历史脚本仍在 `tools/` | ❌ **已退出产品面**（2026-10-20）：Web/MCP 不展示；`verify_all` 不再跑 v30 |
| 可选后端：eCapture | `tools/fetch_ecapture.sh` + `ecapture_capture.sh` | ⚠️ **实验脚本，不在门禁内**（`verify_v34` 仅手动）；需内核 eBPF |
| Host 捕获落盘 | `daemon/src/capture_persist.ts` | ✅ 按包 jsonl；重启可回放；按包清空/导出（2026-10-20 v0.4.0） |
| HTTP 整请求重组 | `http_exchange.ts` / MCP `http_exchanges` | ✅ 已接线 + 单测；**未进 verify_all / FEATURE 门禁表旧行** — 以 REST/MCP 手工验 |
| 开发用（不随发布物交付） | `sandbox-app/`、`sandbox-native/`、`tools/`、`docs/`、`daemon/` | — |

## 0.5 能力分布

| 层 | 位置 | 承担什么 | 规模 |
|---|---|---|---|
| **Agent**（目标进程内） | `agent/` → `libadh_agent.so` | **33 个命令分支**（2026-10-01 删掉 9 条一次性触发命令后）：GOT/inline/addr/sites/vtable hook、Java(LSPlant) hook（单方法 + `hookAll` 批量 + 参数改写/返回值替换/skip/调用链）、JNI_OnLoad（含加载时 watch）/RegisterNatives/**JNIEnv 228/229 槽**、持续捕获 `capture_start/stop/drain`、函数与 QBDI trace、dex/so/内存 dump、maps/内存读写搜、ART 结构枚举、活体对象自省、主动触发、`load_so`、`native_call`（整数+浮点）、`native_backtrace`、`syscall_watch`、轻量 RPC —— **只采集/执行，不做分析** | C/C++，产物 1.0 MB |
| **Host ADH Daemon**（主机） | `daemon/` | **65 个 MCP 工具 + 84 条 HTTP 路由**（2026-10-01 计数，`grep -c` 可复算）：dex 解析/索引(SQLite)/搜索/xref、Capstone 反汇编与 syscall 归因/参数解码、trace 摘要、syscall 摘要、脱壳编排与重建、工件存储、Web UI、MCP server | TypeScript（含 20 个单测文件、**180 条用例**（2026-10-12 实测 `node --test` = 180 pass / 0 fail）） |
| **Device**（手机侧） | `device/` | AIDL 作用域读写、模块状态、目标进程启停 —— **不做分析** | Kotlin |
| **注入器** | `injector/zygisk` | 把 `.so` 送进目标进程（Zygisk 走 **memfd**，目标 maps 不出现模块路径）+ 传真实包名 | C++/Java |
| **可选后端** | `tools/`（eCapture 等） | 实验/调试；**Frida Gadget 已退出产品面**（2026-10-20）；不进发布物 | 脚本 |

## 1. 测过的功能（按 verify_all 的脚本分组）

| 能力 | 覆盖脚本 | 验收要点 |
|---|---|---|
| 命令通道 / 协议分帧 | v02, v21_frame | 1MB 命令帧 + 16MB dump 跨帧字节一致 |
| 内存与 dump | v02_dump, v02_so, v22_capture, **v97(读取后端 + 强制直读覆盖全部读命令)** | 搜索/落盘/sha256 对照/去重；突发下 `emitted+backlog+dropped==seq` 如实记账 |
| dex 静态分析 / 修复 / 索引 | v03, v04_dexparse, v08_*, v09_methodcode, v12_rebuild, v13_recover, **v95(try/catch code_item)**, **v96(map_list 重建 + 布局自检)**, v29_dexindex | ART 结构枚举、常量扫描、xref、字节码恢复、重建与持久索引；**带 try/catch 的方法读全 `code_item`（header+insns+tries[]+handler 列表）并字节级重建一致**，解不动的 item 显式报 `unresolvable` 而不是算作已恢复；**重建把 code_item/class_data 重定位到文件末尾并重建 map_list**（map 现在描述文件本身，代价是旧副本作为 slack 保留、文件变大） |
| 原生反汇编 / 常量 / syscall 扫描 | v08_disasm, v08_analyze, v09_cryptoconst, v09_syscall | 内存镜像反汇编、导入导出、AES S-box、`svc #0` 直连点 |
| **变异（魔改）算法识别** | **v101** | 按**结构**识别而不是按标准常量：MD5 由未被改动的 K 表锚定、缺席的 init 作为变异证据（并报"标准 init 被原位改写 12/16"）；SHA1 **从另一端**锚定（IV 在位、轮常量被改）；置换码表按**形状**找到并数出漂移量（54）。变异判定**必须带证据**，且 `limits` 必须自述盲区（运行时生成的表、连锚点一起改的变异）。**并同时断言旧的标准常量扫描对教科书库与变异库返回同一组算法名、且在变异库上误报 `MD5-init`**（假阳性）——即这条能力补的是"两层同时瞎"的整类漏检。靶子是**编译产物**（`fixtures/crypto-variants/` + `build_crypto_variants.sh`），不是测试自己拼的 buffer |
| 加解密动态捕获 | v04_crypto, v11_capture, v24_javacap, v26_cryptocoverage |（v04 自 2026-10-01 起走真实路径：`capture_start` → `java_call` → `live_captures`） EVP 边界明文、富采集、ECDSA/AEAD 覆盖（含 APS2 packed reloc） |
| TLS / 文件 I/O | v07, v07_flow, v20_file, v25_fsbrowser |（v07 断言 SSL_write/read 两侧明文标记；v07_flow 断言 daemon 侧 tid+200ms 关联；v20 断言 open 路径 + 读写标记，均走持续捕获） SSL_write/read 明文与关联；libc open/read/write 捕获 |
| 反检测观测与去特征 | v05_detect, v69(stealth), v70/v72(sites), v73/v74(vtable) |（v05 自 2026-10-01 起从**持续捕获的 system 类**读 debug/root/prop；**TRACEME 中和目前没有控制面**——原 `detect_watch` 是唯一开关，已随命令删除，见 `DEVELOPMENT_PLAN §6.9.1` WS-J） 目标自审（anon r-x、序言比对）；stealth 后 anonExec 2→0；sites 保持入口字节不变 |
| Java hook（LSPlant） | v42/v43/v52/v53/v65, **v79(stack)**, **v82(hookAll)**, **v83(java_trace digest)** | 单方法/构造器/继承、参数改写、返回值替换、skip original；`stack:true` 给出 App 帧调用链；`hookAll` 一次装全类（截断可见） |
| **Java SSL 绕过** | 真机 `aa165071` 2026-10-16 的自动安装记录已过时；2026-10-19 起改为命令安装，这轮没有单独复测绕过是否生效 | `java_hook` `action:bypass` 才装 `TrustManagerImpl` / `Platform` 的握手校验、`SSLContext.init`、`TrustManagerFactory.getTrustManagers`、OkHttp `CertificatePinner.check`、HostnameVerifier。注入时不装。Android 12+ 不钩 `SetStatus` 和 `ClassLinker::RegisterNative`。 |
| **Java 算法采集** | **v104**（`aa165071` 2026-10-19 通过） | `java_hook` `action:crypto` 才钩 `Cipher` / `Mac` / `MessageDigest` / `Signature` 的 init、doFinal、digest、sign、verify，只观察，原方法照常跑，记录进 `jcaptures`。注入时不装，同一时刻只有一个安装者。关掉的算法族不装。沙盒 `JavaCrypto.javaHookProbe` 走平台 Provider（跳过本应用的 `ADH-Intercept`）。门禁要求 java 通道抓到 AES-CBC 明文与密钥、解密、AES-GCM、HMAC、SHA-256、RSA 明文，以及 `SHA256withRSA` 的 sign（带签名输出）和 verify（带签名输入），并且探针返回值以 `ok ` 开头。 |
| **多进程作用域（按包名覆盖该包所有进程）** | 真机判定（2026-10-13），无独立门禁脚本 | Zygisk `nice_name` 是进程名，作用域/策略/界面按包名；修复后"先进程名、后包名"两问，hard-exclude 两 key 都判，`hello.package`/`hello.process` 分开上报。真机验证：只写包名 → 主进程 + `:core` + `:player` 三个进程全部注入且拿到同一份策略；只写 `:core` → 仍只覆盖 `:core` |
| native hook | v46, v49, v55, v56, v66, v68, **v84(native_hook_all selection + 槽位预算)**, **v86(native throttle)**, **v28(inline 入口 hook)** | inline/addr、软/硬卸载、寄存器事件、浮点参数、千次压测；限流只压事件、不改返回值替换；v86 真机 `forcedReturn=20/20` |
| JNI 面 | v54, v57, v58, v59, v60, v62, v63, v64, v67, **v90(表索引 ABI 机检)**, **v91(字段访问器 + 可改写 + 字段摘要 + 通配)**, **v92(字段摘要单测/接线)**, **v93(字符串+直接缓冲表项, host)**, **v90/v91(数组两族 + 创建/对象数组 + CallNonvirtual + 字符串/反射桥 + 覆盖 228/229, host)** | RegisterNatives、JNI_OnLoad（含加载时替换）、JNIEnv **228/229 表项（唯一余项 `RegisterNatives` 由 v4.14 的入口 inline hook 覆盖）**（99 固定 + 36 字段访问器 + 31 族 ×3：ID 查询 / Call* 三类入口 / 字符串与直接缓冲 / **数组 region 读写全族** / **数组元素 pin 与写回全族** / **数组创建 + 长度 + 对象数组元素 + AllocObject** / **CallNonvirtual 三形态全族（事件带 `via=<class>`）** / **字符串全族（含 critical 对）** / **反射桥 `From/ToReflected*`** / `FatalError` / `ExceptionCheck` / 引用生命周期 / 异常流 / 类型自省 / monitor 与弱引用，索引逐条与 NDK `jni.h` 对照，见 v90；wrapper 签名由 `_Static_assert` 编译期钉死；`action:status` 支持用 `function` 过滤（含 `installed` 关键字）并自报 `total/matched/emitted/truncated`，整表 228 项的回复不再静默截断；固定槽位由**单一列表**同时驱动枚举值与名字表（v4.82），并有**运行期布局自检**——枚举与表任何错位都会拒绝 patch 并点名位置，而不是挂到隔壁函数）、Call* 三类入口、数组写回、异常保持 |
| 主动调用 / 活体对象 | v45(java_call), v49(native_call), v51(qbdi args), v06(对象读/调用), **v89(字段写入)** | 反射调用 Java 方法/字段；按符号或地址调 native；活体对象字段**读+写**（写入带 before/after；**严格解析**：typo/越界/int 超范围一律拒绝，不再静默写 0；final 字段 fail-loud；参数超长拒绝而不是截断；**字段查找与枚举走父类链**，继承字段不再报 not found） |
| trace | v10_trace, v10_qbdi, **v78(backtrace)** |（v10_trace 自 2026-10-01 起 = `native_hook mode=got` + `java_call` + 在事件 x0 处 `memory_read` 读回参数字符串） 函数参数/线程/时间戳；QBDI 指令级（用后 dlclose）；hook 命中当刻的 x29 调用链 + 符号化 |
| 内存反汇编（MCP） | v48 | Capstone 5 WASM，绝对地址或 module+offset |
| 内存扫描瞄准 | **v15/v97 家族**（`memory_search`/`memory_scan_magic` 的 `minAddr`/`maxAddr`） | 窗口外区域**跳过**而非裁掉，回复回显生效窗口（`all` / `lo-hi`）并报 `regionClipped`/`truncated`——部分扫描不会读起来像全扫描 |
| 系统调用监听 | v50(direct), **v76(归因)**, **v77(libc+过滤)**, **v81(摘要+参数)**, **v85(syscall_trace 装配)**, **v86(native throttle)** | 直接 `svc #0` 捕获；静态归因（223/224 libc 站点）；按名/号过滤只装命中站点；`syscall_digest` 给调用方/次数/`paths` 直方图，并比对运行期 x8 与归因号 |
| 一键 dump 所有 DEX | v15, v17, **v15(逐 dex 分类 carrier/real + 同 pass 建索引)** | ART DexFile 枚举 → 逐 dex dump → SHA-256 去重 → 下载（REST+MCP）；**每个 dex 带 `classes`/`methods`/`carrier` 判定**（诱饵壳 vs 真代码），并复用 `ensureDexIndex` 在同一次 pass 建索引 |
| 进程内 dlopen | v18 | 目标进程内加载任意 `.so` 并解析符号 |
| 设备侧后端（Zygisk/Manager） | v27_zygisk, v32_backend_control, **v75(memfd)**, **v98(注入路径的 Java 面)** | scope 往返；后端状态/作用域可控并恢复；**agent 从 memfd 加载**（目标 maps 无模块路径，目标内自证 + ELF 头） |
| **逐包 Hook 策略**（按 App 选算法族） | **v102** | `scope.json` 的 `policy` 段给每个勾选的 App 一份 `CaptureFamilies`（摘要 / HMAC / 对称 / 非对称 / TLS / AEAD）。**勾掉的族在目标进程里根本不装钩子**（安装期策略，不是记录过滤）；缺段 / 缺包 / 缺键一律按"开"，所以老 scope 文件与老 daemon 不写该段即保持正确。策略经 companion 的 `policy <pkg>` 一行标志送达 agent，agent **只持有、不自己装**（模块名归调用方，WS-B 红线），由下一次安装应用，回执里 `skipped` 与各族 `-1` 即为证据。真机 `aa165071` 两轮冷启动验收：关 hmac+AEAD → 恰好只跳过这两族；全开 → 无跳过 |
| 可选后端 | v30（v34 已移出闸门） | 官方二进制 + sha256 固定；eCapture 抓明文。均为**实验/调试用**，只有 Zygisk 是官方路径（2026-10-01） |
| 控制面 / MCP / Web | v10_mcp, v10_webui, v10_export, v10_events, v19_settings, v33_backends, v35_sessions, **v71(registry)**, **v80(trace digest)**, **v83(java trace)**, **v84(native batch)**, **v85(一站式 syscall)**, **v86(throttle)**, **v87(MCP 可操作性)** | MCP 67 个工具可调；注册表形状自检；Web UI；会话清理 |
| **`adh` 命令行** | **v100** | `doctor`（daemon 健康 + **刷入的 agent 版本 vs 本仓源码版本**配对 + 后端矩阵）· `target`（解析**唯一** agent——歧义时报错而不是静默换进程——并报活体事实）· `unpack`（一键 `dump_all_dex` + 逐 dex 分类 + `--out` 落盘）；纯客户端（只 import `config.ts`，可打远程 daemon）。**每个 flag 都由效果证**：`--port`/`--host` 由错误里的 base URL、`--timeout` 由"2 秒预算真的在 ~2s 内结束"、`--json` 由输出形状、`--package`/`--session` 由它拒绝解析的目标、`--out`/`--include-carriers` 由落盘文件数。它是"找在线 agent 取 session"这段逻辑的**唯一实现**（此前 76 个 verify 脚本各抄一份）。**`target`/`unpack` 的真机端到端已于 2026-09-29（二）验证**：`v100` 真机 **22 checks / 0 problems**，含 `target` 报出唯一 agent + 活体事实、`unpack` 逐 dex 分类、`--out` 每个真 dex 落盘且字节数与报告一致。（页首 2026-09-28 那条"尚未验证"已作废。） |
| 手机自动化（模块 X） | 已退役，不纳入验收范围 | AI Agent 直接使用 adb 操作手机；ADH 不再提供 AccessibilityService、通知读取、phone_* MCP 工具或设备输入控制桥 |
| 注入足迹 | v26_footprint, v01 | release 剥离 + 仅 4 个动态导出 + 无 RWX LOAD |
| 字符串去特征 | **v88**, scan_agent_signatures, patch_vendor_signatures | 自己的 tag/文案/自名/fixture 默认值全部清零（含 DT_SONAME）；vendored LSPlant 的三处（含运行时 dex source name）由 fetch 期补丁清掉并机检；剩余 Dobby/导出/Java bridge 等按只许降预算记账；门禁带**负对照**（植入 token 必须被抓到） |
| MCP 可操作性 / 设备文件系统 | **v87**, v25_fsbrowser, **v89(object_set)** | 每个 agent op 必须能从 MCP 导入图到达（否则在 `INTERNAL_OPS` 写明理由）：`fs_list`/`fs_read` 与 REST 共用实现；存活/引擎/通道三个探针的判定显式（引擎 `ok` = fired && protRestored） |
| 单元测试（host） | v76, v80, v81, v83, v84, v85, **v86**, **v87** | syscall 归因/参数解码/一站式装配、trace 摘要、backtrace dynsym、Java trace（含三阶段装配与 drain 守卫）、native 批量选择、native 限流（默认/夹紧/拒绝垃圾值 + 安装回路真实 payload）、探针判定与设备文件读取（二进制/超大/截断/坏 base64）：**169 条** `node --test` 用例（2026-09-29 实测；旧记 121 已过时） |

## 2. 真机验收结果与当前遗留项

### 2.1 本轮（2026-10-01）改动后的全量门禁

> 设备 `aa165071`（OnePlus PGP110 / Android 15 / arm64-v8a / KernelSU），设备上 agent 为 `40024e15…`
> （本机 NDK r29 构建），daemon 为本轮源码：**114 PASS / 1 FAIL / 2 SKIP**（117 条）。
>
> | | 结果 | 说明 |
> |---|---|---|
> | **本轮改动后** | **114 PASS / 1 FAIL / 2 SKIP** | 门禁 117 条（`v34` 已移出）；唯一 FAIL 是本机环境（缺 gradle），2 条 SKIP 同理。**比本轮开始时（112/2/4）多了两条真检查**：`v37`/`v99` 从「Windows-only 进程控制导致静默 SKIP」修成跨平台实现并真跑通过 |
> | 改动前同机基线 | 112 PASS / 2 FAIL / 4 SKIP（118 条） | 109/5/4 的原始输出里 3 条非产品问题（`v87`/`v94` 编辑中途、`v08_xref` SMB 抖动） |
>
> **唯一的 FAIL（不是本轮的改动）**：
> - `v01`：需要完整构建链——它自己会跑 `build_agent.sh` 与 `gradlew`，本机没有 gradle（agent 部分本机已可构建，见 `HANDOVER §1.5`）。
> - ~~`v22_capture`~~ ✅ **本轮定位并修复（两层根因）**：恒等式此前**恒差 3455**（多次复现、数值稳定）。① **口径不一致**——`seq/dropped` 是 agent **整个进程**的累计值，`emitted` 只统计**本 daemon 会话**，任何一次重启都留下永久偏移；② 更隐蔽的一层是**跨会话聚合**：`capture()` 先在锁外 `seq++` 再 trylock，采样若落在"已计数、结果未定"的窗口里，这一条就既不在 ring 也不在 dropped——活会话下次采样自愈，但**会话恰好结束在那一刻就永久冻结**，门禁每个脚本重启 App 攒下几十个死会话，累加成了几千，读起来正像静默丢记录（其实一条没丢）。修法：health 按**会话基线**汇报、**只聚合在线会话**（历史残渣单列 `staleSessions`/`staleResidual`）、残差拆成 `agentResidual`/`agentLost`/`daemonLost` 三类各自命名、agent 新增累计 `drained`、记账先于处理、`/api/captures` 顶层字段改 spread（此前手抄子集漏掉了新字段，脚本会"断言一个看不到的字段而通过"）。修复后连跑 5 次精确成立（含"只重启 daemon、agent 累计不变"这个原本必挂的条件）。
>
> **2 条 SKIP（全是环境）**：`v31`/`v32`（缺 gradle 重建 Xposed 模块 APK）。
>
> 对照：改动前 `v08_xref` 抖红过一次，本轮 **PASS**（SMB 上 `_dexes/` 的写回竞态，与本改动无关；值得记进 `HANDOVER §3` 同类坑）。

### 2.2 历史：2026-09-23 那一轮（保留作对照）

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
  拿不到 JavaVM —— 现在从已加载的 libart.so **按内存镜像查 `JNI_GetCreatedJavaVMs`**，Gadget
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
    ✔ **2026-10-01 已定位并修复**（见 §2.1）：不是"谁还会 drain"，而是 **agent 累计 vs 会话累计的口径差**；`withCaptureSuspended` 与一次性探针命令也已随之删除。
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
- cdex/041：**已决议不进排期**（2026-10-01，无真实样本）；DEX 重建追加式布局保留旧副本作为 slack，文件会变大。
- **Agent TCP `8761` 监听 `0.0.0.0` 且无鉴权 —— 待产品决策（2026-09-26 复核后仍未改）。**
  三条路各有权衡：**加 token 校验**（要改协议握手，需同步 Device Daemon 与验收）、
  **只绑 `127.0.0.1`**（最小改动，依赖 adb reverse，但会去掉「手机浏览器直连局域网」那条路）、
  **维持现状**（信任 LAN）。这是信任模型选择而非技术债，且**改动面跨 Device Daemon / Manager /
  adb reverse 三处**，所以没有在本轮加固里顺手改。**仍未决策**（2026-10-01 复核未变，见 `REQUIREMENTS §20.1`）。
- 完整 syscall 拦截（seccomp/PTRACE_SYSEMU）**已决议不做**（2026-10-01，见 `DEVELOPMENT_PLAN §9.1` 与 `REQUIREMENTS` 的 L3 行）：ptrace/seccomp 本身就是强指纹。

## 3. 发布结论

- 当前代码范围为 `libadh_agent.so` + Zygisk/Manager；**官方注入路径只有 Zygisk**（CI 走模拟注入）。
  **Frida Gadget 已退出产品面**（2026-10-20）：Web/MCP/CLI 不展示；历史脚本仅在 `tools/`。
  eCapture 仍为实验/调试，不进发布物。模块 X 已退役，AI 使用 adb 操作手机。
- **产品边界 = `arm64-v8a` only**（2026-10-01 决议）；Web UI 冻结为只读查看器；
  全量 syscall 拦截不做；cdex/041 需真实样本、不进排期。
- 2026-10-01 设备门禁结果见 §2.1。2026-10-09 已在本机补齐 Android SDK 36 和 Gradle 8.9 wrapper 缓存，并从公开快照成功运行 Device `:core:test :daemon:assembleDebug :manager:assembleDebug`、重建协议 v13 对应的 v0.3.12 bundle、发布到 GitHub；**这个新 bundle 尚未刷入或验收**（见 `HANDOVER §1.5`）。
- 已知边界：arm64-v8a only（产品边界）；**单目标最多 16 个并发 hook 槽**（Java/native 各计，超出 fail-loud 并给释放建议，见 `REQUIREMENTS §21.2`）；`-fomit-frame-pointer` 第三方库可能只能解析 1 帧；JNIEnv 表覆盖 228/229（唯一余项 `RegisterNatives` 由入口 inline hook 覆盖）；`FatalError` 事件为 best effort；高频事件可能受 capture ring 限流/丢弃；native_call 超时后目标调用无法取消；dex 重建会增大文件与内存峰值；Agent TCP `8761` 暂无鉴权；一键脱壳会抑制本包自动布防直至进程重启；`capture_start` 的**先归零再装**语义意味着它会短暂卸下再装回钩子（这段时间目标的事件不会被捕获）。
