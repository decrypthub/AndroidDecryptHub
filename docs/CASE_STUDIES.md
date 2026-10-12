# 实战案例集

> 这里记录 **ADH 在真实目标上跑出来的结果**——不是路线图，也不是验收清单。
> 每一篇回答两个问题：① 这次到底拿到了什么；② **ADH 作为工具暴露了什么**。
> 目标名保留（都是公开 App），但**不含任何账号、ID、消息内容、密钥或抓包原文**——
> 那些只在 gitignored 的 `dumps/` 下，不进仓库。

---

## 案例 1 — 学习通（`com.chaoxing.mobile` 7.0.4 / SecNeo 梆梆加固）

设备 OnePlus PGP110 `aa165071` / Android 15，模块 `adh` v0.3.10 起。日期 2026-09-26。

### 拿到了什么

**脱壳：13 个 dex / 143,312,364 B / 98,135 类 / 748,297 方法**，
每个 dex 的 `dex_coverage.recoveryRate=1`、`unresolvable=0`，checksum 与 signature 全部有效
（**没有方法抽取**）。一键 `dump_all_dex` 产出的 13 个真 dex 与早期手工挖出的结果 **sha256 逐字节相同**。

**协议：环信（Easemob/Hyphenate）IM —— MSYNC。** 见下"目标情报"。

### 这次暴露的 ADH 缺陷（两条已修，见 §改进记录）

| # | 症状 | 根因 |
|---|---|---|
| A | `memory_read`/`search`/`scan_magic`/`dump`/`art_dexfiles` **整组失效** | 目标 `prctl(PR_SET_DUMPABLE,0)` → `open("/proc/self/mem")` 对自身也返回 EACCES，而 agent 所有读内存路径都只走这条 fd |
| B | `art_dexfiles`/`java_hook`/`trigger`/`object_*` 全部 `no JavaVM` | agent 由 Zygisk 经 **memfd** 加载，linker 拒绝 `dlopen("libart.so")`（`not accessible for the namespace "(default)"`），裸名也不在 app 的搜索路径里 |
| C | `memory_scan_magic` 扫不到 app 堆 | 额度（256 命中 / 512MB / 每区域 64MB）被框架 OAT 的 dex magic 吃光，且被裁的区域不报 |
| D | `dex_repair` 把 120MB 的 dex 以 base64 内联回吐（160MB 回复） | 回复里 `repairedB64` 原样带回整份文件，而调用方本来就有这些字节 |

**关键点：A 和 B 都不是设计错误，是"没人测过那条路"。** 79 个 device 验收全部跑在沙盒
`System.loadLibrary` 自加载路径上——那条路径结构上不可能产生 memfd 加载的 agent，
也不会遇到不可 dump 的进程。**门禁恰好绕开了这个工具存在的理由。**（见案例结论第 1 条）

### 目标情报（可复用的加固形态）

**SecNeo / 梆梆（`libDexHelper.so` + `com.secneo.apkwrapper.*`）的诱饵结构：**

- ART 会把它命名成 `[anon:dalvik-classes.dex extracted in memory from …/base.apk]`，
  而且 **`file_size` 被吹到 120MB** —— 看起来就是"我要找的那个大 dex"。
- 但它的 `class_defs_size` **只有 17**，内容是 `com.secneo.apkwrapper.*` + ARouter 路由表。
  **这是外壳，不是代码。**
- **真 dex 在 `[anon:libc_malloc]` 区域里**（本次是 160MB 区域里 13 个等距排布的槽位），
  **ART 没有给它任何命名**。
- 所以：**只靠 `art_dexfiles`（ART DexFile 枚举）会完全错过真载荷**，
  必须走内存扫描 / 区域 dump。（本次两条路都跑了：修好 B 之后 `art_dexfiles` 报 14 个 DexFile，
  恰好是 1 个外壳 + 13 个真 dex；而单靠 magic 扫描当时还扫不到。）

**判断"诱饵 dex"的启发式**：`file_size` 与实际 `class_defs_size`/`data_size` 严重不成比例
（本次 120MB vs 17 类 / data_size 19,480 字节）。

### 目标情报：环信 IM（MSYNC）

- 协议**不在 dex 里**，在 `libhyphenate.so`（8.9MB）。dex 只有 JNI 适配层
  `com/hyphenate/chat/adapter`（95 类）；顶层 SDK 类名未混淆，`com.hyphenate.chat.core` 混淆。
- 协议名 **MSYNC**，protobuf，包 `easemob.pb`；信封
  `{verison(原文拼错), command, payload, trace_id, compress_algorimth, encrypt_type}`。
- **载荷不加密**（`encrypt_type:[0]`、`compress_algorimth:0`），安全只在 TLS。
- IM 通道是 **WebSocket over TLS**（`:443`），另有 REST 与独立上报通道。
- **最有价值的方法论发现：SDK 自己把协议明文打进 logcat**（tag `ONE SDK`），
  一行一条解码后的 MSYNC。**可重复、零侵入、不用解 TLS。**

**仍未解决**：MSYNC 在 WebSocket 帧里的**二进制字段号**。protobuf 描述符表被剥离，
字段号只存在于生成的序列化代码里；而按 libc 符号（`send`/`recv`/`sendmsg`/`recvmsg`/`readv`/`connect`）
挂 GOT 钩子，在心跳每 30s 的情况下 **5 分钟 0 命中** —— 说明这条 I/O 路径**不走这些符号**。
→ **这是 ADH 的一个未解问题，见案例结论第 2 条。**

### 案例结论（喂给工具改进）

1. **验证盲区是本项目最重要的问题**（✅ 已办，路线图新增 WS-L）。门禁全绿 ≠ 真机可用。
   · ~~原提的补法：沙盒加"只经 Zygisk 注入"变体 + "启动即 `prctl(PR_SET_DUMPABLE,0)`"变体。~~
   · **实测修正**：`prctl(4,0)` 在本 ROM **不阻断**自读 `/proc/self/mem`，那个变体建了也**不会失败**，
     属于装饰 → 不建（这不影响 A 的结论：拒绝该 fd 的目标确实存在，只是不能靠 prctl 制造）。
   · **实际修法**：① 在**既有**的注入路径验收上断言 **Java/ART 能力**——`verify_v75` 早就创建了
     "memfd 注入、无 `JNI_OnLoad`"这个条件，只是从不断言 Java 能力（新增 `verify_v98`）；
     ② 加**强制直读**开关，让读内存回退覆盖**全部**读命令（扩 `verify_v97`）。
     mutation 对照已证明 v98 有牙齿：禁用 JavaVM 查找后它 FAIL，且症状与真实缺陷一字不差。
2. **`native_hook` 的 `ok:true` + `hits:0` 无法自证**（✅ 已办）：装成功时 `original`/`replacement` 看着全对，
   但钩子是否落在真实调用路径上无从判断——本次只能靠"心跳周期 vs 0 命中"这种**外部推理**下结论。
   → status 现在给出机制事实：`slot`/`slotsPatched`（改了哪个槽）、`slotCurrent`（补丁还在不在）、
   `pageProtRestored`（RELRO 有没有被留成可写）、`firstHitMs` 与派生 `verdict`
   （`fired` vs `installed-never-fired`）。
3. **大目标上瞄不准**（✅ 已办）：内存扫描没有区间参数、没有分页；`dump_all_dex` 只报数量不报性质
   （14 个里哪个是诱饵壳，要人自己看）。
   → 扫描加 `minAddr`/`maxAddr`（窗口外区域跳过、回复回显窗口、补 `regionClipped`）；
   `dump_all_dex` 逐 dex 判定 carrier 并**在同一 pass 建索引**。学习通复验：
   `realDexCount 13 / carrierCount 1`、`realBytes 143MB` vs `totalBytes 263MB`。
4. **工件生命周期**（✅ 已办）：`dumps` map 只在内存里（daemon 重启后磁盘工件"消失"）；
   磁盘上的 `captures/*.bin` 没有任何回收，本轮就留了约 1.1GB。
   → daemon 启动时从 `captures/` **重新采纳**（重新哈希，自愈，不依赖旁路索引），并新增
   `settings.artifacts{maxBytes,maxAgeDays}` 回收（删文件同时删 dex 索引行）。验收 `verify_v99`：
   真重启后 281 个工件全部回来、标 `disk-reload`、无悬空路径。
5. **缺一键编排**（✅ 部分已办）：零件齐了（scope → 冷启动 → probe → `art_dexfiles` → `dump_all_dex`
   → index → coverage），但没串起来，本次约 20 次工具调用做考古。
   → `dump_all_dex` 现在自带判定 + 建索引，"dump 完看报告"一步到位；**冷启动/probe 那两段仍要人工**，
   且**没有**恢复被有意删掉的 T0/T1 恢复会话。

---

## 案例 2 — 漫播 / 克拉克拉（`com.uxin.kilaaudio` 1.6.18，**无壳**）

设备 OnePlus PGP110 `aa165071` / Android 15，模块 `adh` v0.3.12。日期 2026-10-12。
（完整现场记录含密钥与明文，在 gitignored 的 `dumps/kilaaudio/ANALYSIS.md`。）

### 拿到了什么

**脱壳**：`unpack` 一把出 **10 个真 dex / 65.6 MiB / 0 个诱饵壳**，直接建索引——目标没加壳，
学习通那种"先脱壳再谈分析"的戏份这次没有。

**登录手机号加密 —— 算法 + 密钥 + 证明**。一次 UI 驱动（adb 点选 + 输入）触发"发送验证码"，
`EVP_CipherUpdate` 抓到 **11 字节明文（手机号）**，agent 的 ctx→key 连接同时给出 **16 字节 key 与 IV**；
用这两个值在本地复算，输出与 App 真正放进请求参数的 `cellPhone` 字段**逐字节相同**。
算法是 **AES-128-CBC / PKCS7**，IV 是源码里的字符串常量，key 不是（见下）。

**同一把工具盘出的全景**：App 自带的 AES/RSA 工具类、证书固定配置的解密路径（AES-CBC + RSA，
密钥由服务端以 `ENCRYPTED_AES_KEY` 形式下发）、播放器的 AES-CBC/NoPadding、IM 的 HMAC-SHA1/MD5、
**埋点通道的 AEAD（GCM 类）**，以及若干第三方 SDK 各自的 AES。分类靠
`dex_index_search` 的 `stringCallers`（"哪段代码引用了这个算法名"）+ `callers`（"谁调了 JCE"），
一条命令一类，比逐个函数啃字节码快得多。

### 这次暴露的 ADH 缺陷 / 环境事实

| # | 症状 | 说明 |
|---|---|---|
| A | **业务请求没发出去**，抓包里只有埋点域名 | App 自己的 `PublicKeyManager` 报 `server public key check fail`，业务调用 `Failed to get response after 3 retries`；把已知的手机号密文在 500 条记录里搜也是 0 命中 → 请求在客户端就被拦。摘掉我们的钩子重试**看不出区别**，所以至少不是我们的 GOT 钩子导致的，但也没证明摘掉就能成。**待办** |
| B | `am start -n <pkg>/main.MainActivity` 被 `SecurityException: not exported` 拒 | 冷启动必须走 launcher 入口（`cmd package resolve-activity` 拿到的 SplashActivity）或 `monkey -p`。`verify_v102_policy.sh` 早就这么做，但手写脚本时踩了一次 |
| C | 带 LSPlant/GOT 钩子的进程被 `force-stop` 会留 `SIGSEGV code 0 (SI_USER)` tombstone | 栈在 ART `MarkCompact::UpdateLivenessInfo`——**进程正被拉倒时倒在 GC 线程里**。上一轮把它读成"目标完整性自检自杀"属于**过度解读**，本案例更正 |
| D | `dex_crypto_scan` 的 `cryptoApis` 对 App 自己的 dex 恒为空 | 它只匹配**声明**在 `javax/crypto`、`java/security` 前缀类里的方法，App 不会去声明这些类。有用的是同一次返回的 `algoStrings` + 索引的 `stringCallers`。**待办**：要么把 `cryptoApis` 改成"引用了这些类的 App 方法"，要么在文档里说清它是什么 |
| E | `java_hook` 的 `lastArg` 对 `byte[]` 参数是 `[B@…` | 所以"hook 住加密函数看 key"这条路走不通；这次能拿到 key，靠的是 **agent 自己在 native 层做的 ctx→key 连接**，不是 Java 钩子 |

### 目标情报（可复用的形态）

- **加密工具类被混淆成单字母**：`<pkg>.base.utils.encrypt.a`（AESUtil），方法 `b/c/g/h/i/t/u/v/w/x/y`；
  静态布尔字段是"初始化过没有"，未初始化时调用抛异常——**这本身就是定位线索**：谁还需要初始化，
  谁就没被这条流用到。
- **固定 IV + 服务端下发 key**：AES 的 IV 写死在 `certpin.c` 里当字符串常量，key 走配置下发。
  所以"搜 dex 找 key"注定失败，"搜 dex 找 IV / 找算法名"通常能成。
- **同一 App 里多套密钥并存**：登录一套、证书配置一套、播放一套、埋点一套、第三方 SDK 各自一套，
  而且**至少两套的 key 与 IV 相同**（`key == iv`）。看到一条 11 字节明文别急着当手机号，
  先用它的 key/IV 把候选明文都算一遍对一下。
