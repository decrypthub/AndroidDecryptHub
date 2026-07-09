# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 当前阶段

**v0.1 完成并在真机验证。** 下一步 v0.2 Dump Engine。

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

### v1.0 唯一剩余

- [ ] **QBDI 指令级 trace**（模块 I.3，高级 DBI）：agent 集成 QBDI 库（arm64 Android，git submodule + CMake，重）。
      风险最高、依赖最大——留到最后。**函数级 trace 已由 GOT hook 引擎覆盖**（crypto/net/detect 都是 hook-then-log）；
      QBDI 独有价值是逐指令 trace。若集成受阻记 Blocked，用 GOT/inline hook + llvm-objdump 静态反汇编作为替代覆盖。

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

## 下一步（收官 v1.0）

功能核心（模块 A–V 的 agent 侧能力 + idhd 分析）已基本完成并逐项真机/host 验证（suite 20/20）。剩下三块：
1. **Web UI 页面**（低风险、纯展示层）：Dashboard 已有；加 Dex/Native/Crypto/Network Browser，调现成 REST API。可先做，稳。
2. **Method Body Recovery（L.7）**（中）：sandbox PackerMock（运行时填 code_item）；agent hook 执行点，前后 dump code_item 对比。
3. **QBDI trace**（高风险、最后做）：agent 集成 QBDI 库（git submodule + CMake），指定函数/范围指令级 trace。若集成受阻，记 Blocked，用 llvm-objdump 静态反汇编 + GOT/inline hook 观测作为替代覆盖。
- 全部完成后：在 PROGRESS 标注 v0.2–v1.0 完成，可考虑停循环。

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
