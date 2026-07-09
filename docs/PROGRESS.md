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

- [ ] v0.4 Java Hook + Crypto — **静态通道已完成并验证**；动态通道（method hook 抓运行时 key/iv/明文）待做
- [ ] v0.3 ART 结构级捕获 — **核心已完成并验证**（tools/verify_v03.sh），剩恢复状态标记/多 resolver 为后续

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

## 下一步

→ **v0.4(dyn-2)：用已验证的 GOT 引擎 hook BoringSSL EVP 抓明文**（详见上「v0.4 动态通道进展」）
1. 实测哪个已加载模块的 GOT 有 EVP_*Update 指针（Conscrypt native）；got_replace 命中。
2. wrapper 记录 in/inl（明文）→ 发 CRYPTO 事件给 idhd → 调原函数。
3. sandbox JavaCrypto 跑 AES，断言捕获明文含 "IDH_CRYPTO_PLAINTEXT_v1"。
- GOT 引擎（v0.4(dyn-1)）+ JNI 反射（v0.3(1)）已就绪可复用。

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

- 2026-07-10 (loop#5)：v0.4 动态通道地基——原生 GOT/PLT hook 引擎(E.8.1)完成并真机验证（hook agent 自身 close，intercept+trampoline 不崩）。深挖两个 bug：RELRO 槽定位、单槽 hook（多槽 trampoline 死锁）。suite 8/8，1 次提交。下一步用引擎 hook EVP 抓明文。
- 2026-07-10 (loop#4)：v0.4 静态 crypto 通道——DEX 解析器(dex.ts) + crypto 静态扫描，host 验证（probe dex 解析 + 多 dex 命中 Cipher/Mac/AES/HmacSHA256）。sandbox 加 JavaCrypto。动态 hook 通道有意推迟到专门回合（改走更安全的原生 EVP GOT hook，计划已记录）。suite 7/7。1 次提交。
- 2026-07-10 (loop#3)：v0.3 ART 结构级 dex 捕获完成——JNI 反射基础 + ClassLoader cookie→art::DexFile*→begin_ 枚举（untag tagged pointer）+ 结构级 dump 对已知 InMemoryDex 字节级 sha256 校验。现场 root-cause 两个 bug（tagged pointer pread EFAULT、响应缓冲截断丢 newline）。2 次提交，suite 6/6。
- 2026-07-10 (loop#2)：v0.2 完成——so 重组（SoFixer-lite，重建 libidh_agent.so 有效）+ dex header 修复（真实 5MB dex 字节级还原）+ 主回归 verify_all.sh 5/5。3 次提交。
- 2026-07-10 (loop#1)：v0.2 Dump Engine 核心完成——命令通道 + maps/read/scan_magic/search/dump+dedup，全部真机验证（dump 对 mock dex 字节级 sha256 校验）。3 次提交。
- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。v0.1 端到端验证。
