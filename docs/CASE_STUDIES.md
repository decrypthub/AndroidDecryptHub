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

**业务登录协议整条还原 + 签名破译**（同日晚）：`POST /api/v549/user/login/password` 的
表单四字段（手机号密文 / 密码密文 / source / 签名）全部还原，本地复算出的**整个请求体与真机逐字节相同**，
服务端接受（随机号码回"用户不存在"而非"签名校验失败"）。算法细节见下面"追加：签名算法"。

### 这次暴露的 ADH 缺陷 / 环境事实

| # | 症状 | 说明 |
|---|---|---|
| A | **业务请求没发出去**，抓包里只有埋点域名 | App 自己的 `PublicKeyManager` 报 `server public key check fail`，业务调用 `Failed to get response after 3 retries`；把已知的手机号密文在 500 条记录里搜也是 0 命中 → 请求在客户端就被拦。摘掉我们的钩子重试**看不出区别**，所以至少不是我们的 GOT 钩子导致的，但也没证明摘掉就能成。**待办** |
| B | `am start -n <pkg>/main.MainActivity` 被 `SecurityException: not exported` 拒 | 冷启动必须走 launcher 入口（`cmd package resolve-activity` 拿到的 SplashActivity）或 `monkey -p`。`verify_v102_policy.sh` 早就这么做，但手写脚本时踩了一次 |
| C | 带 LSPlant/GOT 钩子的进程被 `force-stop` 会留 `SIGSEGV code 0 (SI_USER)` tombstone | 栈在 ART `MarkCompact::UpdateLivenessInfo`——**进程正被拉倒时倒在 GC 线程里**。上一轮把它读成"目标完整性自检自杀"属于**过度解读**，本案例更正 |
| D | `dex_crypto_scan` 的 `cryptoApis` 对 App 自己的 dex 恒为空 | 它只匹配**声明**在 `javax/crypto`、`java/security` 前缀类里的方法，App 不会去声明这些类。有用的是同一次返回的 `algoStrings` + 索引的 `stringCallers`。**待办**：要么把 `cryptoApis` 改成"引用了这些类的 App 方法"，要么在文档里说清它是什么 |
| E | `java_hook` 的 `lastArg` 对 `byte[]` 参数是 `[B@…` | 所以"hook 住加密函数看 key"这条路走不通；这次能拿到 key，靠的是 **agent 自己在 native 层做的 ctx→key 连接**，不是 Java 钩子 |
| F | **装 LSPlant Java 钩子会把目标打崩** | 冷启动后只装一处 `okio.RealBufferedSink#writeUtf8`，约 6 s 内进程在 `ClassLinker::SetupClass` 里 `SIGSEGV`，`pc` 落在 `<unknown>` 映射（不属于任何已加载 so）——像被替换过的 ART 里的代码。**native（GOT）钩子同一条时间线上全程稳定**。**2026-10-13 已定性**（见下）：崩因是"**钩了桥自己依赖的类**"，不是"热"，也不是"类没加载"；后者的 `pc` 落点查清了——夹在两个 Dalvik GC 匿名区**之间**、不落在任何映射里。 |
| G | `CAnonymous::PrintLog` 的日志是死代码 | 目标 native 层有 `"input string was:"` / `"version:N,actual salt was:"` 这类日志，但只在外部 logger 指针非空时才发，而 App 从不注册 → `logcat` 里永远看不到。**别把"日志里没有"当成"这条路径没走"。** |

### 追加：Java 钩子崩溃的定性（2026-10-13）

把 `Init` 和 `Hook` 分开测（`javahook_probe` 只做 `adh_javahook_init`，明确不装钩），再用频次阶梯：

| 变体（都是冷启动后装一处钩） | 结果 |
|---|---|
| `javahook_probe`（只 Init，不装钩） | ✅ 存活 75 s |
| `okio.RealBufferedSink#writeUtf8`（约 42 次/秒） | ✅ 存活 240 s，命中 1 万+ |
| `java.util.HashMap#get(Object)`（77 次/秒，boot classpath） | ✅ 存活 90 s，命中 6897 |
| `java.lang.String#length()` | ❌ **3.1 s 死**（复现两次，都是 3.1 s） |

**结论：不是"热"，不是"类还没加载"，是"钩了钩子桥自己依赖的类"。** 桥在渲染实参/返回值/事件
JSON 时用的是 `java.lang.String`，钩上 `String` 就等于让桥递归进自己。可用的规则是
**别钩 `java.lang.String`（以及桥自身依赖的类）**，其余类没问题 —— 这条把 Java 钩子从
"不能不用"变成"有明确禁区、可以用"。

两条崩溃签名不同，都是这一族的下游表现：
* 热点/自引用：`SIGSEGV` 在 **JIT 线程池**，`art::LiveInterval::AddUse` ← `SsaLivenessAnalysis` ← `ComputeLiveness`；
* 另一条：`ClassLinker::SetupClass+348` 调出去，`pc` 夹在两个 Dalvik GC 匿名区**之间**（不落在任何映射里）。

**顺带修掉一个真缺陷**：`tools/fetch_lsplant.sh` 的 patch 3 让 `JitCodeCache::Init` 失败时"继续跑"，
于是 `JitCodeCache::Available()` 为假、`RecordJitMovement()` 永不执行 —— JIT 代码移动跟踪**根本没起来**。
根因不是"符号被 strip"而是**被改名**：`GarbageCollectCache` 在 dynsym 和 symtab 里都不存在，
而 `JitCodeCache::DoCollection(Thread*)` 存在且在导出表里、参数形状相同。`HookSyms()` 本就支持多候选，
所以 patch 5 只加了一个候选（正常 ROM 行为不变），patch 6 把 `jitTracking` 报进探针回执。
两处独立证据：`javahook_probe` 从 `jitTracking:false` 变成 `true`。

### 追加：签名算法（同日晚）

业务接口的 `sign` 是**必须项**——不带它服务端直接回"签名校验失败"，而它由 native 算，
Java 层只看到一次转发调用。破解路径值得记下来，因为**它不需要任何 Java 钩子**：

1. **载荷从 SSL 明文拿，不从 Java 钩子拿**。`capture_start` 之后 agent 的 native SSL 钩子
   已经在给 TLS 明文，`live_captures` 按 `category:'net'` 读，一次就拿到完整请求体。
   这条路同时避开了缺陷 F。
2. **别拿 hook 出来的签名反推算法**——签名是"参数的函数"，hook 到的如果是另一条请求
   （不同端点/不同字段集），反推的方程就是错的。必须先钉住**载荷**，再谈算法。
3. **目标 so 没 strip 就直接读符号**。`llvm-nm -D` 一把列出 `EncryptSalt` / `mapToQuery` /
   `CAnonymous::Encrypt` / `EncodeTool1` / `EncodeTool2`；顺着 JNI 入口反汇编 40 行就看清主流程，
   比在 Java 层猜拦截器快一个数量级。**"名字唬人的自定义摘要"要实测**：这里的 `EncodeTool1`
   IV 和 K 表就是标准 MD5，`EncodeTool2` 才是 SHA-256 —— 名字不可信，常量表可信。
4. **编译期常量直接读文件**：盐是 `.bss` 里的 `std::string`，由 `_GLOBAL__sub_I_*.cpp` 用
   `.rodata` 里的字面量初始化 —— 反汇编那三个 `__cxx_global_var_init*` 就能拿到地址，
   再去文件里读字符串，不需要跑起来也不需要 dump 内存。
5. 服务端成了最终裁判：修好之后随机号码回的是 **"用户不存在"**（业务判定），
   而不是之前的 **"签名校验失败"**（协议判定）——**错误码的变化就是 pass/fail 信号**。

### 目标情报（可复用的形态）


- **加密工具类被混淆成单字母**：`<pkg>.base.utils.encrypt.a`（AESUtil），方法 `b/c/g/h/i/t/u/v/w/x/y`；
  静态布尔字段是"初始化过没有"，未初始化时调用抛异常——**这本身就是定位线索**：谁还需要初始化，
  谁就没被这条流用到。
- **固定 IV + 服务端下发 key**：AES 的 IV 写死在 `certpin.c` 里当字符串常量，key 走配置下发。
  所以"搜 dex 找 key"注定失败，"搜 dex 找 IV / 找算法名"通常能成。
- **同一 App 里多套密钥并存**：登录一套、证书配置一套、播放一套、埋点一套、第三方 SDK 各自一套，
  而且**至少两套的 key 与 IV 相同**（`key == iv`）。看到一条 11 字节明文别急着当手机号，
  先用它的 key/IV 把候选明文都算一遍对一下。

### 追加：抓包路线的两条真实边界（2026-10-13）

- **多进程**：这个目标跑主进程 + `:core` + `:player`。真机判定过——ADH 的作用域原先按
  **进程名**字面匹配，所以"勾了包名"只覆盖主进程，次要进程根本没有 agent。**如果一个 App 的网络栈
  在次要进程里，那么无论旁路做得多好，那个进程里什么都没有**。已修（按包名覆盖该包全部进程），
  但这条经验是通用的：怀疑"抓不到"时，先确认**发请求的那个进程**里到底有没有采集面。
- **代理本身**：真机复现中，即使旁路已经在三个进程里装好（`on 12/13`）、系统代理也设成了本机端口，
  目标这一轮的 socket 仍然**直连 443**（`/proc/net/tcp`，按 uid 过滤），代理侧 0 个连接——即这一轮它
  不走系统代理；而同一台机器、同一套代理在更早的一轮里确实把登录请求解出来了。**结论要分开讲**：
  旁路有没有生效是 ADH 能负责的（真机可证），代理能不能看到明文还取决于目标愿不愿意用系统代理，
  后者不在 ADH 的控制范围内。**2026-10-13 晚：这张 13 条 Java 旁路已从产品里删掉。** 静默回调之后同一地址仍在
  `MarkVisiblyInitialized` 里把进程打死（uptime 约一小时）。TLS 明文继续走 native 的 `SSL_read`/`SSL_write`。

---

## 案例 3 — 中国移动（`com.greenpoint.android.mc10086.activity`）

设备 OnePlus PGP110 `aa165071` / Android 15。日期 2026-10-21。主进程已登录；`:tools` 进程在线，但没有拼出 HTTP。

### 拿到了什么

登录之后的业务接口有两个签名头。用进程里 `EVP_DigestUpdate` 的原文重算，和头里的值比较：带这两个头的 **16 条全部对上，0 条对不上**。其中一条的输入形状也逐条对过（URL + `_` + JSON + 固定后缀）。另一条接口的 body 用捕获到的 AES-128-CBC 密钥解出 JSON，并且把那条明文重新加密后与 body **逐字节相同**（3 条）。

短信登录请求不在这批交换里。业务接口的大 body 用已看到的密钥解不开（21 条）。响应 body 用这些密钥也解不开（26 条有 body，0 条解开）。

采集环 `complete:false`，`dropped` 远大于窗口里还留着的条数。上面的数字只覆盖还留在交换列表里的 37 条，不覆盖进程一生发出的全部请求。

### 这次暴露的 ADH 缺陷

| # | 症状 | 根因 |
|---|---|---|
| A | 对签名要手写脚本，把摘要明文和某一条 HTTP 配在一起 | 没有「这条摘要命中了哪个头、对上几条」的结果 |
| B | 解密方向只看到密文；部分 `EVP_CipherUpdate` 没有 key/iv | 钩子在入口抄输入。密钥来自更早的 Init，对不上就空着 |
| C | 列表预览里经常没有 path | 预览截断在摘要前面的长字段上，必须逐条打开详情 |
| D | `llvm-nm -D` / `readelf --dyn-syms` 对 dump 出来的 so 是空的 | 重建文件没有 section header，动态符号还在，只是工具不认 |
| E | 结论容易说成「协议就是这些」 | 环溢出只在 health 里，分析结论不会自己带上「窗口不完整」 |

## 案例 4 — 京东（`com.jingdong.app.mall` 16.1.50）：`jdgs` 这个头

设备 OnePlus PGP110 `aa165071` / Android 15 / SDK 35，Zygisk 注入。日期 2026-10-22。目标没有壳，但签名库 `libjdg.so` 只导出 `JNI_OnLoad`，内部是自定义 VM。

### 拿到了什么

`jdgs` 是请求头里的一个 JSON：`b1` 设备 UUID、`b2` JDGuard 版本、`b3` 协议版本、`b4` Base64 载荷、`b5`/`b6` 两个 SHA-256、`b7` 时间戳。生成点是 `JDGuardHelper$1#genSign(URI, byte[], String, String, boolean)`，返回 `Map` 且只有 `jdgs` 一个键；调用链 `HttpSettingTool#doSignUsingJdGuard → ParamBuilderFor*#setupParams`。它给**每个**签名请求生成，不只是登录 SDK。

`b4` 的输入拿到了：在 `libjdg.so` 的 GOT 上钩 zlib `compress`，命中的 `x2/x3` 就是压缩前的整段明文（371 B，`x3=0x173` 对得上），内容是 `{"e1":<eid>,"e2":"<版本>§§0§§<包名>|<32hex>|<客户端版本>§§-…","e3":<毫秒>,"e5":<33 B>,"e4":<uuid>}`——`e4` 每次不同（nonce），其余是设备/包/版本指纹。本地用同一份明文压缩得到 293 B，而 `b4` 解出来 296 B。

**没还原的部分**：那 296 B 的二次变换。`native_crypto_const` 在库里只找到 SHA-256 / MD5 / SHA-1 / Base64，`crypto_variant_scan` 没有 AES 结构；`e5` 也不是标准 Base64。它是 libjdg 自己 VM 里的实现，不是 OpenSSL/JCA 边界上的调用，所以 `capture_start` 的 crypto 钩子（EVP/JCA）完全看不到它。

### 这次暴露的 ADH 缺陷

状态列：**已修** = 有代码 + 验收；**撤回** = 证明不安全后移除；**未修** = 已知、还没做（附可行的下一步）。

| # | 症状 | 根因 | 状态 |
|---|---|---|---|
| A | Java hook 事件里参数是 `java.net.URI@30d92b0`、返回值是 `java.util.HashMap@20b20ae` | 桥只渲染 `args[0]`，对象一律降级成 `类名@hash`；协议分析等于没有参数 | **已修**（第一轮）：全参数 + `byte[]` hex、URI/Map/JSON `toString`；`MAX_ARG_BYTES` 64 → 2048 |
| B | 想钩 `libjdg` 的 native，只能看到一个 `JNI_OnLoad` 导出 | 方法全是 `RegisterNatives` 动态注册；事后装 `jni_hook` 看不到已发生的注册 | **未修**。枚举这半边够用了（`java_enum` 会标 `native`，实测 `Bridge` 只有 `main` 是 native）；拿 fnPtr 要么读 `ArtMethod.data_`（按 API 解析 ART 布局），要么把 `JNI_OnLoad → RegisterNatives → ADRP/ADD 表地址` 这条静态链自动化。手动配方见 C 行 |
| C | 试过在 hello 预装 `jni_hook`，App 5 分钟内 **SIGILL**，另一次 **ART GC 空指针** | 对 `libart.so` 的 `RegisterNatives` 做 inline patch；包装函数本身正常（晚装 40 s 稳定） | **撤回**：该能力已从启动策略移除。安全解法是静态读注册表：`native_disasm JNI_OnLoad` → 唯一 `RegisterNatives` 调用 → `memory_read` 方法表 → `{main, (I[Ljava/lang/Object;)[Ljava/lang/Object;, fnPtr}` |
| D | `native_hook` 只能抓**调用前**内存，拿不到 `compress` 的输出 | 没有 `memAfter`；当时只能靠"下次命中前读 x0"，实测拿到的是全 0 | **已修**（第五轮）：`memAfter` 调用后窗口（1..512 B，`phase:"after"` + `ret`），真机把 `78 9c…` inflate 回 371 B 原文 |
| E | `memory_disasm module+offset` 直接失败，报 `Failed to disassemble, error: OK (CS_ERR_OK)` | capstone-wasm 在**零条指令**时抛异常，错误分支把成功码当错误打印 | **已修**：返回 `count:0` + `undecodedBytes` + `note`，3 条单测 |
| F | `native_analyze` 对 1.6 MB 的 so 回吐约 19 MB strings | 没有分页/长度截断，一次就把上下文打满 | **已修**（第七轮）：`maxStrings`/`stringsOffset` 分页 + 单条 `maxStringChars` 截断 + `nextOffset`/`longStrings`/`scanCapped` 说明漏了什么；顺带修了"EOF 结尾那条字符串被丢" |
| G | 多目标时 `live_captures` 里沙盒自检数据和目标混在一条流 | 该工具没有 `session`/`package` 过滤（`http_exchanges` 有） | **已修**（第七轮）：同一套过滤语义（记录先按自己的 package 戳） |
| H | 静态读 Java 逻辑仍要人肉 | `dex_method_code` 只回 bytecode 十六进制，没有 Dalvik 反汇编 | **已修**（第七轮）：`disasm:true` 走 SDK `dexdump -d`，流式解析、只留命中方法、每方法 `maxInsns` 上限；工具缺失/头校验过期时明说并保留原始 bytecode |

### 第二轮：门面、opcode 与 oracle

`Bridge`（`com.jd.security.jdguard.core.Bridge`）是 JDGuard 的 Java 门面，只暴露一个 `static native Object[] main(int, Object[])` 和一层 `entry(int, Object[])`。`getAppKey()` 返回的就是 `b1`（所以 `b1` 不是设备 UUID，是 JDGuard 给这个 App 的 key），`getJDGVN()` 给了 `b2` 的主干，`androidId()` 是请求里出现的那个 16 hex。

hook `entry` 得到一个完整样本：`opcode=101`，参数是 `[byte[1727] "POST /client.action <md5(body)>…", <设备占位串>, <eid>, "1.0", <e5>, <nonce>, null]`，返回 `[jdgs JSON]`。**b4 的输入因此确定：请求行 + body 摘要 + 设备字段 + e5 + nonce**；上一轮抓到的压缩前明文就是 native 用这些字段拼出来的 JSON。

想把它变成可反复查询的 oracle，先给 `java_call` 补了数组编组。第一次把第一个元素传成 `String`，目标在 `GetArrayLength` 上直接 abort（`not an array: java.lang.String`）——这反过来证明调用真的进了 `main`；改成 `byte[]` 后再调，**命令超时、进程随后被杀**。`entry` 依赖真实调用上下文，从 agent 的命令线程异地调用会挂死，而 `java_call` 没有隔离：一个阻塞的目标方法会把整条命令通道一起拖死。**oracle 这条路要先解决"在目标自己的线程上调用 + 超时后能放弃"**，不是加个参数就能通的。

### 第三轮：`b4` 的结构

把同一签名操作内的两次事件按 **tid** 配对（按时间戳会错：同一个毫秒里有 2 个并发签名），各自独立恢复出一条密钥流，两条在 **291/294 字节上一致（99%）**；换成其它任意两次调用只有 0–1.4%。由此定死：

```
b4 = base64( zlib(JSON) ⊕ keystream )
```

**第五轮用 `memAfter` 拿到目标自己的压缩输出后修正**：密文与压缩流**长度完全相等**（295/295、294/294、294/294、293/293），所以没有前缀，是**等长异或**；第三轮看到的"1 字节头"是本地 zlib 与目标 zlib 差一个字节造成的假象。排除项不变：同一操作内明文只差 4 字节（时间戳）时密文只差 6 字节且位置保持——**没有雪崩，不是 AES-CBC/ECB**；逐字节比对也不是纯 deflate；换成精确的压缩流后，任意两次调用的密钥流彼此 0–0.7% 一致。

**密钥流带每次调用的盐**：同一个请求（同 `t=`、同 functionId）在同一次操作里的两次调用，`b4` **完全不同**——所以 K 不是只由请求决定，还混入了每次调用的量（最可能是 `e3` 时间戳）。

顺带纠正：`e4`/`e5` 是装机常量（90 秒内 6 次调用全同），不是 nonce。剩下未知的是密钥流的派生——它对 `e3/e4/e5/e1/e2` 的 SHA256/MD5 与计数器模式都不匹配，属于 libjdg 自定义 VM 里的 PRG。

### 第四轮：密钥流按请求派生

把 `byte[]` 渲染上限提到 2048 后，hook `Bridge.entry` 直接看到签名输入本体（255 字节 ASCII）：`POST /client.action <40 hex digest>&area=…&build=…&client=android&clientVersion=…&ef=1&eid=…`。签名覆盖**请求行 + body 摘要 + 选定 query 参数**，这解释了 `b4` 逐请求变化。

密钥流按请求派生：同一请求的两次调用，恢复出的 K 前缀一致；不同请求 0–1.4%。排除项：`rand`/`random`/`srand` 虽然被导入但签名路径 0 次调用；库里没有任何教科书 PRNG 常数；对请求做 `SHA256/SHA1/MD5/HMAC-SHA256`（分别拼 `e5`/`e4`/`eid`/`appKey`/`e2`，加 counter0，前后缀都试）共 53 种构造全部不匹配。剩下的是 VM 内的自定义 PRG。

### 第六轮：把标准密码学排除干净

有了同一次调用的精确 D 与 C，可以干净地试标准构造：`AES-128/256-CTR` 与 `ChaCha20`（12 种种子 × 5 种 IV，共 112 组）、`RC4`（12 种种子 × 5 种 drop，共 60 组）、以及 32 字节块之间的哈希链，**全部不中**。`e4` 修正为"每次会话"的标识（同进程稳定、重启即变）。

顺带看到 jdguard 在用 `access()` 探测模拟器痕迹（`vboxguest.ko`/`vboxsf`/`qemu_pipe`/`goldfish`/`bluestacks`/`androVM`…）——这类行为本该由 `detect_summary` 的 sys 钩子汇总，本次是从 `access` 的 GOT 上顺带看见的；采样窗口里没有 `/dev/urandom` 读取。

**这一例的教训**：目标把密码学搬进自己的 VM 之后，"在标准库边界上抓"和"扫标准常量"会同时失效；这时能救场的不是再猜算法，而是**输入侧**（压缩前明文已经拿到）和**输出侧**（`b4` 的字节结构）能不能对齐。ADH 的输入侧这次够用，输出侧缺 `memAfter`。

### 第十二轮：打通——20 字节 key，b4 可完整还原

```
b4 = base64( RC4_key( zlib_compress(fingerprint JSON) ) )
```
key = 传给 `libjdg+0x89480`（KSA）的 **20 字节**。验证方式：用抓到的 key 跑 KSA+PRGA 作用于同一次调用的 b4 → 得到 `78 9c …` → **inflate 出 `{"e1":…,"e2":…,"e3":…,"e5":…,"e4":…}`**。

关键节点：
- 状态是**每线程缓存**（首次签名后状态地址不变、不再被写）→ KSA 只在**新线程第一次签名**时跑；因此必须"重启 App → 立刻抓"。
- 无 `mem` 的 `0x89480` hook 命中 1 次且**不崩**；`mem:"x1:32"` 在调用当刻拷 key 才有效（事后读该指针已是复用垃圾）。
- key 20 字节呈"固定盐 + 变动字节"结构（第 3–7、10–15、19 字节两次抓取相同，0–2/8–9/16–18 不同），像指针/时间戳字节拼进固定盐。
- **禁用硬件观察点**：在京东上挂 perf 断点后目标第三次 SIGSEGV（JDGuard 反篡改会检测硬件断点）。后续一律用 hook/静态。

**这一例的教训（更新）**：连续三次把混淆代码误判成算法（xor 比较、字符状态机、宽度存储表）之后，真正破局的是**数据流**：`memAfter` 拿压缩输出 → 观察点指出"谁碰它" → 找到 RC4 → 再顺着 `(state,key,len)` 的入参抓 key。不是读懂了 542 KB 的混淆体，而是让目标自己把关键数据交出来。

### 第十一轮：b4 是 RC4（逐字节证明），只剩 key

结论：`b4 = base64( RC4_{key}( zlib(fingerprint JSON) ) )`。不是自定义 VM 的 PRG，就是 RC4。

怎么找到的（前面三次都猜错，这一条是靠观察点命中的）：

| 位置 | 我曾以为是 | 实际是 |
|---|---|---|
| `0x97b78` `eor lsl #5/#29/#28` | xorshift PRG | 混淆比较 `cmp (a^(a<<5)),(b^(b<<5))` |
| `0xf6474` `eor w9,w9,w23` | 密钥流循环 | 逐字符状态机（16 位值跳表） |
| `0x1020a4` 11 项跳转表 | 字节码 VM | 按宽度存储的辅助（`strb/strh/str/w`） |
| **`0x89608`** `ldrb w9,[x20,x22]` | — | **RC4 PRGA 读明文的那条指令** |

证据链（都在一次调用内自洽）：
1. GOT hook `compress` + `memAfter:"x0:512"` → 目标自己的压缩输出 D。
2. 在 compress 返回瞬间用 `hw_watch action:"after"` 挂 rw 观察点（x0）→ 第一条访问 D 的指令 = `libjdg+0x89608`，其函数入口 `0x89574`，交换助手 `0x89560`。
3. 在该入口挂 `mem:"x0:192,x0+192:66"` + `memAfter:"x2:192"` → 抓到 258 字节状态（`S[256]+i+j`，**是合法置换**，`i=j=0`）与同一次调用的输出前 192 字节。
4. 用该状态跑 PRGA 覆盖 D → 与那 192 字节**逐字节相等**，且等于 `base64decode(b4)` 的前 192 字节。**RC4 + 状态都对上了。**

key 未知，但候选被精确排除（KSA 确定性：比 256 位全等）：`e5`、`eid`、每次调用的 uuid、完整请求、`e5+eid`/`eid+e5`、它们的 `sha256`/`md5`、`sha256(JSON)`、`sha256(D)`、`md5(D)`、`appKey` —— 最好成绩 3/256（随机≈1）。

下一步（已定）：状态缓冲的首字节地址从 `NATIVE_HOOK` 事件的 `x0` 取，挂观察点 → 下次调用命中 **KSA 的 `S[0]=0`** 那条写指令 → 反汇编 → key 指针/长度 → 抓 key。

工具侧：`hw_watch` 是本轮新增（`perf_event_open` 断点 + 采样环 + 自动撤防，支持“hook 返回时按寄存器挂”）；两个坑写进 `PROGRESS.md`：必须显式 `IOC_ENABLE`，以及 SELinux 下 app 域 EACCES（`perf_event_paranoid=-1` 也不够）。**代价**：在 `0x89574` 装 `mem+memAfter` 的 inline hook 后目标 SIGSEGV 崩了一次（证据已先抓到）。

### 第七轮：回头把这张表的 F/G/H 和 `java_call` 补掉

分析收尾后按上表逐条改，改动与验收见 `PROGRESS.md` 的同日第七轮记录。这一轮新学到的两条目标知识：

- **`java_call` 不再是"会把通道拖死"的调用**：agent 侧加了独立 attach 线程，`java_call {detach:true}` 立即回 `callId`，`java_call_result` 查状态。真机用 `Thread.sleep(15000)` 验证：启动 87 ms 返回，睡眠期间 `agent_ping` 3.17 ms，最终 `done elapsedMs=15007`。**这就是第二轮"`entry` oracle"卡住的那一半**——现在阻塞的方法只会占一条线程，不会占掉整个会话；剩下的一半是目标侧（`entry` 需要精确的 7 元素参数数组），属于目标工作，不是工具缺口。
- **JDGuard 的状态是"按进程"的**：`Bridge.getAppKey()` 在主进程返回 36 字符的 appKey（与 jdgs 的 `b1` 一致），但在 `:jdpush` 进程里**返回 null**（`getJDGVN()` 两边都正常）。所以"注入到哪个进程"会直接改变 oracle 的答案——多进程目标（京东、微信这类）先 `process_list` 挑主进程，不要用 `capabilities` 的默认选择。

顺带：`docs/mcp-tools.md` 一直是按 `/api/mcp/doc` 生成的，但文件头写着 65 tools 而实际早已 77——文档漂移了一个数量级没人发现。已重新生成（78 tools），`adhd-data/regen-mcp-doc.mjs` 就是生成器。

### 第八轮：native 入口、opcode 分派与"可回放的签名"

**静态钉死入口**（`libjdg.so` 1,631,472 B，sha `47dac66f…`，直接从 APK 的 `lib/arm64/` 拉）
- `JNI_OnLoad`(0xa1770) 先拼出 `com/jd/security/jdguard/core/Bridge`（32 字节常量 + 栈上补 `idge`），再 `ldr x8,[x8,#0x6b8]`（JNIEnv idx 215 = RegisterNatives），`x2=0x159118`、`w3=1`：**只注册一个 native**。
- 表在文件里全 0，必须读 `.rela.dyn` 的 addend：`name@0x5bda2="main"`、`sig@0x5bda7="(I[Ljava/lang/Object;)[Ljava/lang/Object;"`、**`fnPtr@0xa236c`**。这条把缺陷 B 对这类 so 闭合了——不用 hook，也不需要在加载时抢。
- 同一个 `JNI_OnLoad` 还读一个**运行期解密的属性名**（0x1593cc 是密文，经 0xa2044 解），`atoi >= 28` 才走 API-28 分支。`strings` 捞不到它。

**`main` 是 opcode 分派器**：`sub w8,w8,#0x65; cmp w8,#8; ldrh w11,[0x63e48+w8*2]; br x10`（表基址 0xa3858），**101..109** 走这里，`>998` 走 0xb3580。`entry` 是通用 RPC：101 签名 / 102 环境查询 / 104 / 106 摘要（`(int,"<32hex>&<e5>",long)` → 32 hex）。

**完整的 101 向量**（之前只看到 524 字符，实际 3,318）：

```
[ byte[1530] "POST /client.action <40hex>&…&eid=…&ep=<urlenc JSON>&ext=<urlenc JSON>&…",
  "-§§-§§-§§-§§-§§-§§-§§-", <eid>, "1.0", <e5>, <uuid>, null ]
```

元素 0 里带两个 URL 编码的 JSON（设备指纹 `ep`、扩展 `ext`），和 jdguard 自己的 `e2` 是两套；元素 5 是**每次调用一个 uuid**。

**oracle（本轮的关键能力）**：用 `java_call {detach:true}` 原样回放这份向量，**3 ms** 拿回完整 jdgs。于是签名从"等目标自己发"变成可重复实验：
- 同输入连调 3 次：`b4` 每次不同，`b5` **三次一致**，`b6` 每次都变。
- 只改元素 5（uuid）：`b5` 不变，`b4` 变且**长度 408→396**——nonce 进了被压缩的明文，不只是密钥流。
- `b5` ≠ `sha256(请求字节/请求 hex/40 hex 摘要/"/client.action")`；`b6` ≠ `sha256(base64decode(b4))`、≠ `sha256(b4 ascii)`。

**native 链**（`compress` 命中当刻的 backtrace）：
`main(0xa236c) → 0x97144 → 0x97828 → 0xf65f8 → 0x102108 → 0x102d40 → 0x103288(六参转发) → 0x104000(variadic thunk, blr x9) → zlib compress`，GOT hook 命中 1 次。注意 `0x9a240` 那组 `deflateInit_/deflate/deflateEnd` **不在** 101 路径上（inline hook 命中 0）——同一个 so 里有两套压缩代码，别串。

**这轮暴露并修掉的工具缺陷**（每条都是被下一步卡住才发现的）
| 症状 | 根因 | 状态 |
|---|---|---|
| dispatcher 的参数只看到第一个元素（524 字符） | `bounded(Object[])` 按**单值**上限 512 截整个数组 | 已修：数组用 `MAX_ARG_CHARS`，并 1600 → 4608；`byte[]` 的 hex 不再被 512 截 |
| 回放报 `unterminated JSON string` | agent `jargs[2048]` 截断 3 KB args | 已修：16 KiB |
| `Object[]` 里放不了 `byte[]` | JSON 数组没有类型 | 已修：`{"$bytes":…}` / `{"$bytesHex":…}` |
| 返回 `[Ljava.lang.String;@ec1a0e7` | 返回值走 `String.valueOf(Object)` | 已修：数组逐元素渲染（上限 64 槽） |
| hook 命中（hits=1）但 `native_backtrace` 说没有事件 | backtrace 只查 daemon 捕获库，库要靠 `capture_start` 的 drain 才有数据 | 未修（应在找不到时按需 drain 一次） |
| 重启后按 `process_list` 选会话会打到刚死的进程 | 旧会话有几十秒 `online` 窗口 | 未修（脚本先 `agent_ping` 再选；工具层应自己保证） |
| `qbdi_trace` 只能按导出符号，够不到 `main` | 命令层强制 `symLib+symbol`（agent 内部本来就是按函数指针工作） | 已修：`addr` 绝对地址入口，`trace_digest` 同步支持；真机把 `libQBDI.so` 推进 App 私有目录 + `load_library` 后，`qbdi_trace {addr: libjdg+0xf6430}` 返回 3 条指令、`retval` 正确 |
| `memory_search` 会"命中"自己 | 它把请求里的 pattern 解码到**自己命令线程的栈**，然后又扫描这段栈 | 已修：扫描跳过当前线程栈。证据：从未发送过的随机 16 字节 pattern 也命中同一个固定地址 `74430168f0`；修后 0 命中 |
| `hw_watch`（硬件写观察点）没有 | 无法回答"谁写了这块缓冲"（写者是未导出 VM handler；指令级 trace 又淹没在扁平化代码里） | 已加：`perf_event_open(PERF_TYPE_BREAKPOINT)` + 采样环，命中即报 `ip`+内核调用链并自动撤防。**平台约束**：SELinux Enforcing 下 app 域 `EACCES`（哪怕 `perf_event_paranoid=-1`）；`setenforce 0` 后可 arm |

### 第九轮：b6 定案（`md5(明文 JSON)`），以及"工具读不到那块缓冲"

第八轮把 `b5`/`b6` 当 SHA-256 试了 24 种 body 形状、19 种入参组合、HMAC/加盐/常串全否。这一轮换路子：**不猜输入，直接钩哈希本体**，并且先把"看不到整条输入"这个工具上限拆掉。

**先修工具（这是能出结果的前提）**

- `mem` 上限原本是 **192 B × 4 窗口 / 总计 512 B**，而这条签名链的 preimage 是 **1530–1636 字节**——也就是说"唯一值得看的那块缓冲"恰好是工具读不到的。提到 **1024 × 4 / 4096**，`NATIVE_HOOK_MEM` 的记录缓冲改成按上限推导，daemon 侧常量和单测一起改（单测原来把 192/512 写死）。
- 事件里的 `fp`（8 个 vector 寄存器）约 600 B/条，128 条就是 75 KB 噪声，直接把一次采集顶满；改成 **q0–q7 全零就不发**。

**定位**：常量扫描确认包里确有 SHA-256 的 IV/K 表（`+0x156284` / `+0x1562a4`），唯一引用 K 表的是 `+0x8c1f8` 这个函数；它只有一个调用者 `+0x98998`，而 `+0x98998` 只分配 **33 字节**（32 hex + NUL）——所以这条链是"16 字节摘要的 hex"，不是 SHA-256。

**实测**：`+0x8c1f8` 上装 inline hook，`mem:"x0:1024,x0+1024:1024"` + `memAfter:"x2:32"`，一次拿全「输入 + 目标自己算的输出」。**52/52 次命中全是 MD5**，逐字节等于目标写出的 16 字节。每个请求两次调用：

| preimage | 长度 | 内容 |
|---|---|---|
| A | ~1530–1636 | `POST /client.action <query/body>` |
| B | ~564–568 | `{"b1":…,"b2":…,"b3":…,"b4":…,"b5":"<64 hex>","b7":…}`（**没有 b6**） |

于是 `b6 = md5_hex(A 之后那条 B)`，而 `b5` 在 B 里**已经填好**、长度 64 hex = 32 字节。B 的键序固定 `b1,b2,b3,b4,b5,b7`。

**`b5` 还没定**，但排除面已经很大：模块里**只有一个 hex 格式化器**（33 字节分配），**没有 65 字节分配**——libjdg 内部不存在"把 32 字节 hex 成 64 字符"的代码，所以 b5 要么是两个 32-hex 串拼接，要么由别的模块/Java 层产生。已否：`sha256(整条 args)`、`sha256(args 去掉方法和路径)`、`sha256(path+args)`、9 种 `md5(a)‖md5(b)` 组合、`sha256/md5(b4)`、`sha256(b4+b7)`、`sha256/md5(JSON 去掉 b5)`（两级签名假设）；b5 的任何 ≥8 字符子串都**不出现**在 args 字符串里。下一步指向 **HMAC-SHA256**（模块确实带 SHA-256 表，只是这条链不走；而 b5 正好 32 字节）——要先重启 App 抓 KSA 那 20 字节 key。

**这一轮最该记住的教训：分析脚本自己也会"沉默地骗人"。**

| 症状 | 根因 |
|---|---|
| ADRP 扫描报「0 个引用」，差一点据此写下"这些常量表没有代码引用" | JS 里 `w & 0x9f000000` 是**有符号**的负值，跟 `0x90000000` 永远不相等。修正后同一文件立刻有 **12342** 条 ADRP |
| "找 65 字节分配 → 0 处" | `Number.parseInt('0x41', 16)` 与直觉不符，实际在找 101。改成 `Number()` 后立刻命中 |

结论已写进 `PROGRESS.md`：**凡"0 命中"必须同时打印"到底扫了多少条指令/字节"**，否则 0 只是一个沉默的谎。

### 第十轮：trace 第一次真的用上——它先打死了目标，根因是我们自己的补丁

到这一轮为止，`jdgs` 的分析全靠 hook + 静态 ELF 反查，**`qbdi_trace` / `trace_digest` 一次没用过**。补做时：

| 调用 | 结果 |
|---|---|
| `trace_digest {symLib:"libc.so", symbol:"malloc"}` @ 沙盒 | ✅ 143 条指令，`retval` 正常 |
| `trace_digest {addr: libjdg+0x8c1f8}` @ 京东 | ❌ 超时 → **SIGBUS（pc=0x2a, BUS_ADRALN）**，进程被杀（`tombstone_10`） |

第一版归因是错的（"QBDI 的返回模型被目标的扁平化控制流带偏"）。修完再测才发现真相：**那个地址上刚被 soft unhook 的 `native_hook` 补丁还在**。soft unhook 的语义就是"补丁留在原地、只把开关关掉"（为了免 Dobby 重新激活），所以函数入口仍是 `b <trampoline>`；QBDI 忠实地跟着这条跳转进了 trampoline，**再也回不到模拟器**，最后落到 `pc=lr=0x2a`。在**同一个地址、不加钩子**的对照实验里：1327 条指令、1.2 s、`completed` —— libjdg 的 trace 本身没问题。

两个修复（都已真机验收，`tools/verify_v110_trace_guard.sh`）：

1. **拒绝**带我们自己补丁的地址，错误里点名 hook id 与状态（`active` / `soft-unhooked`）。判断用 `used && patched && target`，**不能用 `active`**——要抓的恰恰是 `active==0` 的 soft 状态。
2. **纵深防御**：每条被插桩指令的地址都要落在"可执行映射快照"里（否则 `QBDI_STOP` + `stopReason:"ran-away"` + `stopPc`），外加 20 万条指令的执行预算（此前只有采集上限，执行没有上限，所以能跑到宿主超时）。宿主把 `stopReason` / `stopPc` / `retvalValid` 摆到结果顶层，被止损的 run **不再把 x0 冒充返回值**。

**这一轮最该记住的**：崩溃归因必须先做**对照组**（同地址、无补丁）。否则会把自己工具留下的状态写成"目标的特性"，然后基于错误结论去设计防护——第一版方案（"拒绝这类加固模块"）就是错的，真正的规则是"**别 trace 自己插过桩的地址**"。





