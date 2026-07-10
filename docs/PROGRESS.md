# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 当前阶段 —— ✅ 项目完成

**v0.2 – v1.0 全部实现并逐项验证：`tools/verify_all.sh` = 26/26 PASS（真机 Pixel 6 Pro / host）。无 Blocked。循环已停（cron 已删）。**

完整取证流水线（模块 A–V + idhd 分析 + MCP + Web），全部真机/host 验证：
模拟注入 → maps/内存 dump（so 重组、dex 修复）→ **ART 结构级真实 dex 捕获** →
**明文边界 AES 捕获 + TLS 明文捕获 + 网络↔crypto 关联** → 反分析观测(+中和) + 抗干扰诊断 →
活体对象自省 → dex 搜索/xref/方法体恢复 → 原生反汇编/分析/常量扫描/svc 扫描 →
**函数级 trace + QBDI 指令级动态 trace** → 25 MCP tool（AI 可编程操控）+ Web 控制台（含 Events）+
会话录制/回放 + 诊断导出 + 文档（architecture/threat-model/mcp-tools）。

**QBDI 已解除并完成**：GitHub API 被墙但 release 直链可下；`tools/fetch_qbdi.sh` 拉 v0.12.1
arm64 预编译，agent 运行时 dlopen libQBDI.so，指令级 trace idh_trace_target 得 retval=30 + 64 条指令。

### 交付物（可复现）

- `libidh_agent.so`（C/NDK，双入口，纯采集）、`idhd`（Node/TS，REST+WS+MCP+分析）、
  Web 控制台、`sandbox-app`（模拟注入 + 各 mock 目标）、26 个验收脚本、`fetch_qbdi.sh`。
- QBDI 依赖非 git（third_party/qbdi + libQBDI.so 已 gitignore）；`bash tools/fetch_qbdi.sh` 重新拉取。
- 新机复现：fetch_qbdi → build_agent → build_detect → dev_up → verify_all。

## 技术栈（已定）

- idhd = **Node.js + TypeScript**（node 24 直接跑 .ts，无构建步骤）；deps: `ws`
- agent = **C + NDK 28.2 + SDK cmake 3.22.1 + ninja**，ABI arm64-v8a
- sandbox = **AGP 8.7.3 / Gradle 8.9 / Kotlin 2.0.21 / compileSdk 36**，Java 21(jbr)
- 通信 v0：NDJSON over TCP，agent 经 `adb reverse tcp:8761` 连 host idhd
- 端口：idhd HTTP/WS `8760`，agent TCP `8761`

## 已完成

- [x] 需求定稿（模块 A–W）折叠进 REQUIREMENTS/DEVELOPMENT_PLAN；一份方案
- [x] git、`.gitignore`、`CLAUDE.md`、`PROGRESS.md`；设备就绪
- [x] **v0.1 端到端验证**（3 commits）：idhd(HTTP/WS/TCP registry+dashboard)、
      agent .so 双入口(JNI_OnLoad+idh_agent_start)、sandbox 模拟注入、
      agent 注册 + maps 采样全部与内核 `/proc/<pid>/maps` verbatim 一致
- [x] 可复现验收脚本 `tools/build_agent.sh` + `tools/verify_v01.sh`（exit 0 = PASS）

## 范围指令（最高优先级，循环每轮必读）

- **目标：先把 `libidh_agent.so` 的全部功能实现并自测通过**（模块 A–V 的 agent 侧能力）。
- **验证一律走模拟注入**（sandbox `dlopen` 加载 agent）—— 它执行的就是 agent 的同一套代码路径，`.so` 全功能都能在此自测，无需真实注入。
- **Zygisk / gadget / 重打包注入器（模块 W）整体延后**，由用户自己手动测试注入；循环**不要**在注入器上花时间，也不要因为"没有真实注入"而阻塞任何功能验证。
- 因此 v0.1 已建立的 sandbox 模拟注入回路 = 后续所有版本的验证台。缺哪个测试 Activity 就往 sandbox-app 里加。

## 自动续跑循环（已启用）

- 已启用 durable cron `4b2458ac`（每 ~10 分钟空闲时唤醒），指令：读本文件 → `bash tools/dev_up.sh` → 做下一个可验证增量 → 构建 → 验证 → 仅验证通过才 commit → 更新本文件。
- 每次迭代先跑 `tools/dev_up.sh`（幂等拉起 idhd + adb reverse + 检测设备）。
- 设备离线时只做 host 侧工作（idhd/web/dex 解析/协议/sandbox 代码），设备验证标 PENDING，不伪造验证。
- 停止：删除该 cron（CronDelete 4b2458ac）或在本文件写明 v0.2–v1.0 全部完成。

## 进行中

- [ ] v1.0 — **MCP Server + Web 控制台已完成并验证**；仅剩 QBDI 指令级 trace（高风险，最后）
- [x] v0.9 — 完成并验证：native 常量扫描 + direct syscall + **Method Body Recovery(L.7)**
- [ ] v0.8 Dex 索引 + Native Browser — **完成并验证**（搜索+xref+disasm+analyze）
- [ ] v0.3 ART 结构级捕获 — **核心已完成并验证**，剩恢复状态标记/多 resolver 为后续

### v0.9 完成补充：direct syscall

- [x] **Direct syscall 扫描**（E.9 L1）：解析 ELF program header，扫 PF_X 段找 `svc #0`(0xd4000001) 热点。`POST /api/native/syscall_scan`。sandbox-native 加内联 svc 直连 gettid

### v1.0 进展

- [x] **MCP Server**（Streamable HTTP / JSON-RPC）：`POST /mcp` — initialize/tools/list/tools/call，**19 个 tool** 包装 Service 层（进程/内存/ART/crypto/net/detect/object/dex/native 全套）。AI 客户端可编程操控。host 验证

### v1.0 已完成并验证（verify_all.sh 22/22 PASS）

- [x] **MCP Server**（19 tools，JSON-RPC，AI 可编程操控）
- [x] **Web 控制台**（daemon/public/index.html）：Dashboard/Capture/Dumps/Dex/Native/MCP 多面板，
      WS 实时 agent + session 选择器，一键跑各捕获/分析，调现成 REST/MCP API
- [x] Method Body Recovery(L.7 被动)：`POST /api/dex/method_code` 提取方法运行时 code_item

### v1.0 Trace 层已完成并验证

- [x] **函数级 trace（I.2）第一公民**：`GET /api/trace/run` — 通用 4 参 wrapper hook 任意原生符号，
      记录 args+tid+ts，**并把指针参数解析成字符串预览**（如 access("/system/xbin/su")）。suite 覆盖
- [x] 静态反汇编（llvm-objdump）+ 二进制分析（v0.8）作为静态指令视图

## Blocked

- （无）—— QBDI 已解除并完成（见「当前阶段」）。

### v0.8 完成补充：invoke-xref

- [x] **Dex invoke-xref**（K.2）：Dalvik 指令宽度表 + payload 处理 + 一致性校验（walk 必须精确落在 insns_size）。
      21820 个真实方法 0.00% desync。`POST /api/dex/xref`——查"谁调用了某加密 API"（Cipher.doFinal ← JavaCrypto.run）

### v0.9 进展

- [x] **native crypto 常量扫描**（H.4）：AES S-box/inv、Base64 表、SHA-256 init+K、MD5/SHA-1 init、TEA delta 字节签名。
      `POST /api/native/crypto_const`。对付静态链接+strip 符号的原生加密（EVP 符号 hook 落空时用常量定位）

### v0.9 待做

- [ ] Method Body Recovery（L.7）：被动恢复（执行前后 code_item 对比）+ 受控触发；需 ART 抽取壳 mock
- [ ] Direct syscall coverage（E.9）：扫可执行段 svc 指令热点 + DBI 观测

### v0.7 完成并全部验证（网络监控 + 关联）

- [x] TLS 明文捕获（SSL_write/SSL_read GOT hook，绕过 TLS/pinning）
- [x] **网络↔crypto 关联（取证闭环）**：capture 加 tid+ts_ns；flow_watch 同时 hook EVP+SSL_write，
      触发"加密→发送"流；idhd 按同线程+时间窗关联，输出"明文 IDH_CORRELATE_v1 → 承载其密文的请求"。
      `GET /api/flow/watch`，Δ~33ms 命中

### v0.8 已完成并验证（verify_all.sh 16/16 PASS）

- [x] **Dex 搜索索引**（K.2/K.3）：searchDex() 搜 string/class/method；`POST /api/dex/search`
- [x] **原生反汇编**：llvm-objdump -d（NDK 自带，无额外依赖）按符号/地址范围反汇编 ELF .so → 结构化 {addr,bytes,mnemonic,text}；`POST /api/native/disasm`
- [x] **原生二进制分析**：llvm-readelf dyn-syms(exports/imports)+NEEDED + 字符串提取；`POST /api/native/analyze {q?}`
- 说明：llvm-mc 未随 NDK；无 section 的内存镜像 raw-binary 反汇编留作增强（objdump -d 需 section/symbol，对拉取的文件型 .so 完美工作）

### v0.8 待做

- [ ] invoke-xref：解析 code_item 字节码（需 Dalvik 指令宽度表 + payload 处理），method→callers
- [ ] Web Native Browser / Dex Browser UI（并入 v1.0 Web 收尾）

### v0.7 已完成并验证（verify_all.sh 12/12 PASS）

- [x] **网络 TLS 明文捕获**：GOT-hook Conscrypt(libjavacrypto) 的 SSL_write/SSL_read，
      在 TLS 边界读明文——请求(含 X-Idh-Marker)在 SSL_write、响应(IDH_NET_RESPONSE_v1)在 SSL_read。
      **绕过 TLS 与 pinning**。`GET /api/net/hook_test`
- [x] 自包含测试栈：`daemon/tls_test_server.mjs`（本地 HTTPS 自签名，经 adb reverse，无需外网）+ sandbox Network.kt（全信任客户端）
- [x] **修复严重构建隐患**：build_agent.sh 曾用 >/dev/null 吞掉编译错误 → 本轮多次跑的是**旧 .so**。
      现已 forward-declare load_app_class + build_agent 编译失败即报错退出

### v0.7 待做 —— 网络↔crypto 关联（取证闭环第二半）

- [ ] 给捕获事件加 thread id + 时间戳，把网络明文与 crypto 明文按线程/时间窗关联（correlate_request）
- [ ] 当前 capture buffer 是 pull 式；关联需要统一事件流（可先在 idhd 侧按序聚合 net+crypto 捕获）

### v0.6 完成并全部验证（verify_all.sh 11/11 PASS）

- [x] **T 活体对象字段读取**：反射经静态字段到达对象，枚举其声明字段（name + String.valueOf）。
      `POST /api/object/inspect {className,field}` — 验证读到 HeapProbe.sConfig 的 token/count/note
- [x] **T 低风险方法调用**：无参 getter/toString 反射调用。`POST /api/object/invoke {className,field,method}`
      — getToken() → IDH_TOKEN_abc123
- [x] sandbox 增 HeapProbe（已知字段值的 Config 对象）

### v0.6 后续增强（推迟，非阻塞）

- [ ] **完整堆实例枚举（Java.choose）**：需 JVMTI（jvmti.h 不在 NDK，要 vendor 头或声明结构）或 ART 堆遍历（art::gc::Heap::VisitObjects，偏移相关）。当前经静态字段/hook 引用到达对象。
- [ ] byte[]/数组/集合字段的 hex/摘要展示；堆内 String/byte[] 搜索；与 hook 事件联动展开参数对象

### v0.5 完成并全部验证（verify_all.sh 10/10 PASS）

- [x] **V 反分析行为观测**：GOT-hook 目标原生检测调用（libidhdetect：ptrace/access/__system_property_get），
      观测到目标"用了哪些检测"——debug(ptrace TRACEME) + root(su 路径) + prop(ro.debuggable)，
      并**中和 PTRACE_TRACEME**（观测 V + 抗调试 S 附赠）。`GET /api/detect/watch`
- [x] **S 抗干扰诊断**：`compat_probe` 自评——TracerPid、seccomp、后端可用性(gotHook/jniReflect/artDexCapture/memRead)、
      maps/module 计数、dlopen 受限标记。`GET /api/compat/probe`
- [x] sandbox 增 libidhdetect.so（原生检测 mock）+ Detection.kt；tools/build_detect.sh

### v0.5 后续增强（推迟）

- [ ] 更多检测类别：签名检测(PackageManager，需 Java hook)、模拟器检测、frida/xposed 痕迹扫描
- [ ] 行为分叉标注（检测命中后目标是否改走分支）；Anti-Analysis Radar Web 页

### v0.4 完成并全部验证（verify_all.sh 9/9 PASS）

- [x] 静态通道：DEX 解析器 + crypto 静态扫描
- [x] **GOT/PLT hook 引擎**（E.8.1）：intercept + trampoline，单槽 RELRO 定位
- [x] **动态通道 = #1 卖点**：原生 EVP GOT hook 在**明文边界**抓到 AES 明文 `IDH_CRYPTO_PLAINTEXT_v1`（加密前），trampoline 不崩
  - `resolve_sym()`：解析已加载模块内存 dynsym（绕过 dlopen namespace 限制）
  - `crypto_probe`：定位 EVP 指针在哪个模块 GOT（实测 libjavacrypto.so=Conscrypt JCE 路径）
  - `crypto_hook_test`：装 hook → JNI 反射触发 JavaCrypto.run() → 返回捕获明文
  - **经验**：Conscrypt 经 GOT 调系统 libcrypto EVP（可 hook）；系统 libcrypto 不可 dlopen（namespace）→ 内存 dynsym 解析；"libcrypto.so" 子串会误配 cronet 版 → 精确 basename

### v0.4 后续增强（推迟，非阻塞）

- [ ] HMAC/Digest 捕获（EVP_DigestUpdate/HMAC_Update，GOT 已确认可 hook）；key/iv 捕获（hook EVP_CipherInit）
- [ ] 明文事件异步流到 idhd（当前是 pull 式 capture buffer）→ Algorithm Session 视图（H.1）
- [ ] 纯 Java 自实现加密（不走 BoringSSL）需 Java 层 hook（LSPlant，留待引擎稳定）

### v0.4 已完成并验证（verify_all.sh 7/7 PASS）

- [x] **DEX 解析器** `daemon/src/dex.ts`（header/string_ids/type_ids/method_ids/class_defs、uleb128、MUTF-8）——同时是 v0.5 基础
- [x] **crypto 静态扫描（H.2）** `POST /api/dex/parse` + `/api/dex/crypto_scan`：找 javax/crypto 方法引用 + 算法字符串
- [x] sandbox JavaCrypto（AES/CBC + HmacSHA256，已知 key/iv/明文）——静态引用 + 未来动态 hook 目标
- [x] verify_v04_dexparse（host-only，多 dex 聚合）：probe dex 解析正确；app 中命中 Cipher.doFinal/Mac/AES-CBC/HmacSHA256

### v0.4 动态通道进展

- [x] **GOT/PLT hook 引擎（E.8.1）已完成并验证**（verify_v04_gothook，suite 8/8）：`got_replace()` 扫描模块非 exec 段（含 RELRO）找已解析函数指针→mprotect→换 wrapper→trampoline 调原函数。self-test hook agent 自己的 close() 命中且不崩。
  - **关键经验（写死在代码注释）**：① 必须扫到 RELRO(r--) 段——真正的 .got.plt 槽在那；只扫 writable 会命中 .data 副本导致 wrapper 不触发。② 只能 hook **第一个（真实）槽**；把重复副本也改掉会破坏原函数自身调用路径→trampoline 时死锁。
- [ ] **下一步 v0.4(dyn-2)：用 GOT 引擎 hook BoringSSL EVP，抓明文**
  - 目标：`libcrypto.so` 的 `EVP_EncryptUpdate/EVP_DecryptUpdate/EVP_CipherUpdate`（Android JCE 默认 Conscrypt→BoringSSL）。
  - 定位调用方模块：Conscrypt native（libjavacrypto.so 或 boot image）——先用 `got_replace` 在哪个模块能命中 EVP 指针需实测；或对所有已加载模块尝试。
  - wrapper 签名 `int EVP_CipherUpdate(ctx, out, *outl, in, inl)`：记录 in/inl（明文/密文）→ 发事件给 idhd → 调原函数。
  - 验证：sandbox JavaCrypto.run() 跑 AES，断言捕获的明文含 "IDH_CRYPTO_PLAINTEXT_v1"。
  - 备选：若 Conscrypt 不经 GOT 调 EVP（静态内联），改 hook 导出符号地址的 inline hook，或 Java 层 LSPlant。

**（历史决策）为什么先不做 LSPlant**：Java method hook 需内联 hook 后端 + backup method 重建（版本相关、易崩）；改走更安全的原生 EVP GOT hook，引擎已就绪。

**更安全的计划（下一个增量）——原生 BoringSSL EVP 的 PLT/GOT hook（E.8.1）**：
- Android JCE 默认走 Conscrypt → BoringSSL `libcrypto.so` 的 `EVP_CipherUpdate/EVP_EncryptUpdate/EVP_DecryptUpdate` 等。
- GOT hook = 只改函数指针（安全，可 trampoline 调原函数），无需内联/指令重定位/backup method。
- agent：枚举已加载模块，解析各自 .dynamic→DT_JMPREL/DT_SYMTAB/DT_STRTAB，匹配 EVP_* 符号的 GOT 槽，mprotect 可写→换指针→我方 wrapper 记录 in/inlen（明文）后调原函数。
- 先在**受控目标**验证 GOT hook 机制（hook agent 自己对某 libc 函数的调用，断言 wrapper 命中），再上 EVP。
- 验证：sandbox JavaCrypto.run() 跑 AES，hook 抓到的明文 == "IDH_CRYPTO_PLAINTEXT_v1"。
- 备选/补充：Java 层 hook（LSPlant）留待引擎稳定后，用于纯 Java 自实现加密（不走 BoringSSL）的场景。

### v0.3 已完成并验证（verify_all.sh 6/6 PASS）

- [x] agent JNI 反射基础（cache JavaVM + attach 原生线程 + Build.VERSION 读取）`GET /api/jni/probe`
- [x] **ART 结构级 dex 枚举** `GET /api/art/dexfiles`：ClassLoader→pathList→dexElements→dexFile→mCookie(long[])→art::DexFile*→scavenge begin_（指向 dex/cdex magic 的成员）→自描述 header 读 size。**不做 magic 扫描、不硬编码 ART 偏移**。关键：Android tagged pointer（top-byte TBI）需 untag 后再 pread。
- [x] **结构级 dump** `POST /api/art/dump`：对 InMemoryDexClassLoader 的已知 728B dex，sha256 与 d8 原始输出**字节级一致**；正确归属 ClassLoader 类型
- [x] sandbox 增 DynamicDex（InMemoryDexClassLoader 加载已知 dex + 设为 context loader）

### v0.3 剩余（推迟，非阻塞）

- [ ] 恢复状态标记（已恢复/仍为空）、多 Android API level resolver 兜底、与 magic scan 交叉校验、失败时结构探测报告
- [ ] 抽取壳场景（方法体运行时解密）——属 v0.9 Method Body Recovery

### v0.2 Dump Engine — 完成并全部验证（tools/verify_all.sh 5/5 PASS）

- [x] idhd↔agent 命令通道（`cmd`/`cmdResult`，pending-promise + 超时；每 session socket）
- [x] 按需全量 maps `GET /api/process/maps`（前 40 与内核 verbatim 一致）
- [x] `memory.read` `POST /api/memory/read`（/proc/self/mem pread + base64；读到真实 ELF 头）
- [x] dex/ELF magic 扫描 `GET /api/memory/scan_magic`（dex/cdex/elf/zip/oat/vdex 全命中）
- [x] `memory.search` `POST /api/memory/search`（hex/text）
- [x] region dump + sha256 去重 `POST /api/memory/dump` + `/api/dumps[/download]`（mock dex 字节级 sha256 校验）
- [x] **so 重组** `GET /api/modules` + `POST /api/module/dump`（SoFixer-lite：PT_LOAD 按 vaddr 重排，保留 PT_DYNAMIC；重建 libidh_agent.so 有效可分析）
- [x] **dex header 修复** `POST /api/dex/repair`（file_size/checksum/signature；对真实 5MB dex 字节级还原）
- [x] 主回归脚本 `tools/verify_all.sh`（设备缺席时 device 脚本 SKIP 不 FAIL）

### v0.2 未做（推迟，非阻塞）

- [ ] Web：Memory Explorer / Dump Center 页面（并入 v1.0 Web 收尾，或 v0.3 后穿插）

## v1.0 打磨已完成（本轮）

- [x] **MCP 工具补齐到 25**（+memory_dump/flow_correlate/object_invoke/trace_function/dex_method_code/dex_repair）——每个能力都可被 AI 调用
- [x] **诊断导出** `GET /api/export/report`（仅元数据，无 key/明文）+ `GET /api/mcp/doc`
- [x] **文档**：docs/architecture.md（as-built）、docs/threat-model.md、docs/mcp-tools.md（自动生成）

## 下一步

**无。项目按路线图完成（v0.2–v1.0 全绿，26/26）。自动续跑循环已停（durable cron 已删除）。**
后续若要扩展：模块 U 非标运行时识别（Flutter/Unity/RN）、真实 Zygisk/gadget 注入器（模块 W，用户手测）、
更多 sandbox 对抗场景。均为增强，非路线图必需。

## 下一步（v0.2 Dump Engine）

1. 协议扩展：idhd→agent 命令通道（cmd/cmdResult），大 payload 走 base64/后续 shm
2. agent：按需返回**完整 maps**、`memory.read(start,size)`、region dump、dex magic scan
3. idhd：`/api/process/maps`、`/api/memory/read`、`/api/memory/dump`、`/api/memory/scan_magic`；dump 落盘 + sha256 去重（DexIdentity）
4. Web：Memory Explorer 最小页
5. 验收：AntiDumpMock/DynamicDex（sandbox 需补这些 Activity）dump hash 对照；`tools/verify_v02.sh`

## 验收信号（每个版本必须可 pass/fail）

- v0.1：agent 连上 idhd；maps 条目数与 `adb shell cat /proc/<pid>/maps` 一致；Dashboard 显示在线
- 后续版本验收标准见 `DEVELOPMENT_PLAN.md` §11 测试策略

## 未决 / 待办提醒

- 构建工具链选型（NDK/CMake for agent；idhd 语言：C++/Rust/Go 待定）在 v0.1 敲定后回填 `CLAUDE.md` 的 build 命令
- ART 结构 resolver 需覆盖 SDK 36（设备版本）优先

## 会话日志（倒序，简短）

- 2026-07-10 (P1 第二代恢复闭环)：按评审 P1 做"被动恢复"——**从恢复镜像捕获 CodeItem，不假设执行回填原 DEX**。
  ① `codeItemOf/recoverFromSnapshots`（dex.ts）：对 base 的 BASE_EMPTY 方法，从 restored 快照提取 code_item 生成 captures，再 `rebuildStandardDex`。
  ② `stripMethodCode`：同长度冗余-uleb 把 code_off 置 0，模拟抽取（不移位）。
  ③ `/api/dex/recover {baseSha,restoredSha}`（+ `/api/dex/strip` 测试工具）：真实设备流程=对同一 dex 先后 dump 两次(T0 抽取态/T1 运行后)做差异恢复，**无需新 agent 代码**（快照就是 art dump）。
  ④ 面板「脱壳」加"快照恢复"入口（base/restored sha → 恢复重建 + 下载）。
  ⑤ `verify_v13_recover`（host）：真实 classes.dex 抽取一个方法→从恢复镜像捕获→重建→**字节码字节级一致**。**verify_all 29/29。**
  覆盖范围诚实：处理"回填型"抽取壳；分离缓冲/执行后擦除型需 backend C(壳恢复函数 hook)/D(ArtMethod)，属下一档。P2=主动分级触发（类加载/初始化/安全调用）。
- 2026-07-10 (脱壳架构轮·采纳评审设计)：按评审给的正确设计做**脱壳地基**（先 CodeItem 捕获器+方法索引+重建器，不做 invoke-all）。
  纠正两个判断：① 第二代核心是"在壳恢复方法体的瞬间抓完整 CodeItem"，不能假设执行会回填原 DEX；② `begin+file_size` 对 DEX 041 container/cdex 会截断。
  ① **agent resolver 升级**（修 SDK36 截断 bug）：识别 035–041 + cdex，DEX 041 按 `container_size` 取全物理容器（begin=container_begin），严格校验 endian/header_size/越界，返回富视图 format/version/logical/dataBegin/dataSize/confidence。
  ② **方法索引 + 恢复率报告**（`analyzeCoverage`，`/api/dex/coverage`）：per-method 状态（native/abstract/BASE_PRESENT/BASE_EMPTY），恢复率只按具体 Java 方法算。真机 app dex：total=22586 concreteJava=21740 present=21740 recovery=100%（未加固→100%，诚实）。
  ③ **结构化标准 DEX 重建器**（`rebuildStandardDex`，`/api/dex/rebuild`）：按 method_idx 追加 CodeItem + 重写受影响类的 class_data + patch class_data_off（不做 uleb 原位改写）+ 修 file_size/data_size/SHA-1/Adler32。
  ④ 面板「脱壳」页加覆盖率报告（恢复率进度条 + 缺失方法清单）。
  ⑤ `verify_v12_rebuild`（host）：真实 classes.dex → 覆盖率 → 注入一个 code_item 重建 → **重建 dex 可解析 + 该方法字节码字节级一致（26B MATCH）**。**verify_all 28/28。**
  下一轮（P1）：运行时 CodeItem 捕获后端（解释器/自然执行捕获点）+ 抽取壳模拟场景做硬信号；再 P2 主动分级触发。
- 2026-07-10 (Java 层 hook 轮·参考 iOS 数据模型)：把加解密从"只有类别"升级到 iOS 级富审计。
  参考 iOS log_store 记录模型（algorithm/operation/key/iv/input/output/callstack/分类），做 **Android 自己的方案**：
  ① **Java 层拦截 Provider `IdhSecurity`**：插到最高优先级的 JCE Provider，包住 Cipher/Mac/MessageDigest 的 SPI，
     委托真实 AndroidOpenSSL 计算、在 Java API 边界采集 **算法全名 + Key + IV + 明文 + 密文**，覆盖纯 Java 加密。
  ② **agent JNI 富采集**：`Java_com_idh_sandbox_IdhReport_nReport`（JNI 名字绑定，无需 RegisterNatives）→ g_jcaps 富缓冲；
     capture_drain 增 `jcaptures`（algo/op/key/iv/in/out）。native EVP 层保留作显式指定 provider 绕过时的兜底。
  ③ **idhd 去重**：Java 富记录为准，按输入明文丢弃 native 回声（同明文 2s 窗）；`/api/captures` 带 source+key/iv/out。
  ④ **面板主从详情**：来源(Java/Native) + 算法 + 操作 + 🔑Key + IV + 明文(UTF-8) + 🔒密文。
  硬信号：`DESede/CBC/PKCS5Padding encrypt key=24B iv=8B ct=48B 明文=IDH_LIVE_..订单金额=191.00元`；10 个精确算法名全覆盖。
  **verify_v11 升级为富字段断言（算法+Key+IV+明文+密文），verify_all 27/27。**
  （下一步：把 IdhSecurity 从 sandbox 挪到 agent 注入的 dex，做到任意目标；或上 LSPlant 做不可绕过的方法级 hook。）
- 2026-07-10 (加密面铺开轮)：只抓 AES 太单薄——按 IDH 覆盖完整加密面。
  ① **agent 常驻 hook 扩到全套**：EVP_CipherUpdate(对称) + EVP_DigestUpdate(摘要) + HMAC_Update/EVP_DigestSignUpdate(HMAC) + SSL_read/write(TLS)；capture_stop 对称还原。
  ② **demo 跑全套算法**（每 2s 轮转）：AES-CBC/CTR/GCM、DESede、MD5/SHA-1/SHA-256/SHA-512、HmacSHA256/HmacSHA1。
  ③ **面板分类**：对称/摘要/HMAC/TLS 四类 pill；明文 UTF-8 解码（中文可读）。
  ④ 新验收 `verify_v11_capture.sh`（对称+摘要+HMAC 三类都自动捕获 + 明文含 IDH_LIVE_ + DEX 可下载）。
  硬信号：`cats=对称加解密|摘要 Digest|HMAC`，明文 `IDH_LIVE_0009_HmacSHA1_订单金额=163.00元`。**verify_all 27/27**。
- 2026-07-10 (面板产品化轮·参考 iOS 数据流)：把 Web 从"接口调试器"改成**可操作观测面板**。
  参考 `.ref/ios-decrypt-helper`（hook 常驻→log store→Web 轮询主从列表；dump 面板直接下载）。
  ① **agent 常驻采集**：`capture_start`（常驻装 EVP+SSL hook，不还原）/`capture_drain`（返回并清空累积）/`capture_stop`（还原）。
  ② **idhd 自动流水线**：agent 连上即 `capture_start` + 每 1.5s `capture_drain` 入库/广播；自动 `art_dexfiles`→逐个 dump（可下载）。
  新端点 `/api/captures`(列表)/`/api/captures/:id`(明文 UTF-8 解码，中文可读)。
  ③ **sandbox App 加实时加解密驱动**（每 2.5s 滚动明文"订单金额=…元"），面板打开即自动填充。
  ④ **Web 重写为中文面板**：默认「加解密」主从实时列表（自动填充、点开看明文/密文/线程/时间）、「脱壳(DEX)」一键 Dump+下载、进程信息栏、其余功能中文化；调试台保留。
  ⑤ **冲突修复**：常驻 hook/drain 与一次性 probe 端点(crypto/net/flow)争用同一 GOT 槽+缓冲 → idhd `withCaptureSuspended` 在这三端点期间挂起常驻采集（暂停 drain+capture_stop→跑→capture_start）。
  硬信号：`/api/captures total>0 on=true`，明文 `IDH_LIVE_0003_订单金额=121.00元`；`/api/dumps` 4 个 dex-auto。**verify_all 26/26**。
- 2026-07-10 (可用性闭环轮·参考 iOS)：把"怎么打开观测控制台"按产品做闭环，参考 `.ref/ios-decrypt-helper`
  （其 `http_server.m` getifaddrs 取局域网 IP、fail-loud 明示"仅本地可访问"、悬浮窗 URL 点击复制）。
  ① **idhd 探测宿主机局域网 IP**（`os.networkInterfaces`，过滤 vEthernet/WSL/docker 等虚拟网卡，优先 192.168./10./172.16-31.），
  `/health` 增 `web:{port,local,lan[]}`，启动横幅打印 local/LAN（无 LAN 则 fail-loud）。实测 `http://192.168.100.11:8760`。
  ② **Web 顶栏显示访问地址**（LAN 优先，点击复制）。
  ③ **`dev_up.sh` 增 `adb reverse tcp:8760`**——手机浏览器与电脑用同一个 `127.0.0.1:8760`（经隧道）。
  ④ **sandbox App 主界面重做**：显示可复制的局域网地址 + 本机地址 + "在手机浏览器打开"按钮 + **活体在线指示**
  （轮询 idhd `/health`：绿=控制台在线并显示 agents 数，红=提示去电脑 `dev_up.sh`）。
  ⑤ **Web 控制台加 Debug 面板**：monkeypatch fetch 统一记录每个 REST/MCP 请求 + WS 事件（方法/状态/耗时）。
  闭环硬信号：设备侧 App 经反向隧道读到 `health: ok=true agents=2 lan='http://192.168.100.11:8760'`。**verify_all 仍 26/26。**
- 2026-07-10 (评审硬化轮)：应大佬评审，修 agent 侧 3 处正确性/隐蔽性缺陷并各自加验证——
  ① **`got_replace` hook 后恢复原页保护 + 写屏障**：RELRO(r--) 槽改写后 `__atomic_thread_fence` 发布再 `mprotect` 回 r--，不再残留 rw-（削弱 RELRO / 完整性自检诱饵）。selftest 实测 `origPerms=r--p slotPerms=r--p protRestored=true`，验证脚本纳入通过条件。
  ② **`resolve_sym` 用 DT_HASH(nchain)/DT_GNU_HASH 求 dynsym 数**，节区相邻反推降为兜底——不再依赖 `.dynstr` 紧邻 `.dynsym` 的非标准布局。
  ③ **`got_replace` 泛化为跨全部 caller 模块**（每模块仍只改第一个真实 RELRO 槽，避免 trampoline 死锁），单 caller 场景行为不变。**verify_all 仍 26/26**，1 次提交。
- 2026-07-10 (loop#18)：**QBDI 指令级动态 trace 完成——项目收官**。release 直链绕过 API 封锁拉到 v0.12.1 arm64 预编译；agent dlopen libQBDI.so，trace idh_trace_target 得 retval=30 + 64 条指令。**verify_all 26/26，v0.2–v1.0 全部完成。循环停止（删 cron）。** 2 次提交。
- 2026-07-10 (loop#17)：v1.0 会话录制/回放（事件持久化到 idhd-data/events.jsonl，重启 idhd 后回放验证）+ Web Events tab。suite 25/25，3 次提交。**功能完成，仅剩 QBDI(Blocked)；无实质自动化待办。**
- 2026-07-10 (loop#16)：v1.0 打磨——MCP 补齐到 25 tools + 诊断导出(/api/export/report, 仅元数据) + 生成 docs（architecture/threat-model/mcp-tools）。suite 24/24，3 次提交。除 QBDI(Blocked) 外功能全部完成并验证。
- 2026-07-10 (loop#15)：v1.0 函数级 trace 第一公民（通用 trace_run，任意原生符号，args+tid+ts+指针→字符串预览，access("/system/xbin/su")）。suite 23/23，4 次提交。**QBDI 指令级 trace 记为 Blocked**（网络受限拉不到预编译 + 重集成风险）；剩 v1.0 打磨项（导出/回放/文档/MCP 补齐）。
- 2026-07-10 (loop#14)：v0.9 完成——Method Body Recovery(L.7 被动，提取方法 code_item)。v1.0——**Web 控制台**（多面板，调全套 API）。suite 22/22，4 次提交。**功能核心全部完成，仅剩 QBDI 指令级 trace**（高风险，最后做）。
- 2026-07-10 (loop#13)：v0.9 收尾——direct syscall 扫描(E.9，svc #0 热点)。v1.0 大件——**MCP Server（19 tools，JSON-RPC，AI 可编程操控）**。suite 20/20，3 次提交。剩 Web UI + Method Body Recovery + QBDI。
- 2026-07-10 (loop#12)：v0.8 收尾——dex invoke-xref（指令宽度表，21820 方法 0% desync，Cipher.doFinal←JavaCrypto.run）。v0.9 起步——native crypto 常量扫描(H.4：AES S-box/Base64/SHA/MD5/TEA)。suite 18/18，2 次提交。
- 2026-07-10 (loop#11)：v0.8 核心完成——原生反汇编(llvm-objdump)+ 原生二进制分析(llvm-readelf: exports/imports/NEEDED/strings)。NDK 自带工具，无额外依赖。suite 16/16，2 次提交。invoke-xref + Web UI 待做。
- 2026-07-10 (loop#10)：v0.7 完成——网络↔crypto 关联（取证闭环：明文 IDH_CORRELATE_v1 关联到承载其密文的 TLS 请求，同线程 Δ~33ms）。v0.8 起步——dex 搜索索引(string/class/method)。suite 14/14，2 次提交。
- 2026-07-10 (loop#9)：v0.7 网络 TLS 明文捕获完成——GOT-hook Conscrypt SSL_write/SSL_read，抓到请求(X-Idh-Marker)+响应明文，绕过 TLS。自建本地 HTTPS 测试栈(selfsigned v5 async cert 坑)。**修复 build_agent 吞编译错误导致跑旧 .so 的严重隐患**。suite 12/12，1 次提交。关联(network↔crypto)待做。
- 2026-07-10 (loop#8)：v0.6 完成——Runtime Object Inspector（反射读活体对象字段 + 无参方法调用）。经静态字段到达对象，读到 token/count/note，getToken() 调用成功。完整 Java.choose 堆枚举推迟（需 JVMTI/ART 堆遍历）。suite 11/11，2 次提交。
- 2026-07-10 (loop#7)：v0.5 完成——V 反分析行为观测（GOT-hook 目标原生 ptrace/access/prop 检测，抓到防御地图 + 中和 TRACEME）+ S 抗干扰诊断（compat_probe）。sandbox 加 libidhdetect.so。suite 10/10，3 次提交。
- 2026-07-10 (loop#6)：**v0.4 完成——#1 卖点明文边界 crypto 捕获验证通过**。原生 EVP GOT hook 在 libjavacrypto(Conscrypt) 抓到 AES 明文 "IDH_CRYPTO_PLAINTEXT_v1"（加密前）。含 resolve_sym 内存 dynsym 解析、crypto_probe 定位、JNI 反射触发。suite 9/9。2 次提交。
- 2026-07-10 (loop#5)：v0.4 动态通道地基——原生 GOT/PLT hook 引擎(E.8.1)完成并真机验证（hook agent 自身 close，intercept+trampoline 不崩）。深挖两个 bug：RELRO 槽定位、单槽 hook（多槽 trampoline 死锁）。suite 8/8，1 次提交。下一步用引擎 hook EVP 抓明文。
- 2026-07-10 (loop#4)：v0.4 静态 crypto 通道——DEX 解析器(dex.ts) + crypto 静态扫描，host 验证（probe dex 解析 + 多 dex 命中 Cipher/Mac/AES/HmacSHA256）。sandbox 加 JavaCrypto。动态 hook 通道有意推迟到专门回合（改走更安全的原生 EVP GOT hook，计划已记录）。suite 7/7。1 次提交。
- 2026-07-10 (loop#3)：v0.3 ART 结构级 dex 捕获完成——JNI 反射基础 + ClassLoader cookie→art::DexFile*→begin_ 枚举（untag tagged pointer）+ 结构级 dump 对已知 InMemoryDex 字节级 sha256 校验。现场 root-cause 两个 bug（tagged pointer pread EFAULT、响应缓冲截断丢 newline）。2 次提交，suite 6/6。
- 2026-07-10 (loop#2)：v0.2 完成——so 重组（SoFixer-lite，重建 libidh_agent.so 有效）+ dex header 修复（真实 5MB dex 字节级还原）+ 主回归 verify_all.sh 5/5。3 次提交。
- 2026-07-10 (loop#1)：v0.2 Dump Engine 核心完成——命令通道 + maps/read/scan_magic/search/dump+dedup，全部真机验证（dump 对 mock dex 字节级 sha256 校验）。3 次提交。
- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。v0.1 端到端验证。
