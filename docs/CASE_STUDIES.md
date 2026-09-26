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

1. **验证盲区是本项目最重要的问题。** 学通通案例证明：门禁全绿 ≠ 真机可用。
   补法：沙盒加一个**只经 Zygisk 注入**的变体 + 一个启动即 `prctl(PR_SET_DUMPABLE,0)` 的变体。
2. **`native_hook` 的 `ok:true` + `hits:0` 无法自证。** 装成功时 `original`/`replacement` 看着全对，
   但钩子是否落在真实调用路径上无从判断——本次只能靠"心跳周期 vs 0 命中"这种**外部推理**下结论。
   status 应给出机制性证据，而不是只给计数。
3. **大目标上瞄不准**：内存扫描没有区间参数、没有分页；`dump_all_dex` 只报数量不报性质
   （14 个里哪个是诱饵壳，要人自己看）。
4. **工件生命周期**：`dumps` map 只在内存里（daemon 重启后磁盘工件"消失"）；
   磁盘上的 `captures/*.bin` 没有任何回收，本轮就留了约 1.1GB。
5. **缺一键编排**：零件齐了（scope → 冷启动 → probe → `art_dexfiles` → `dump_all_dex` → index → coverage），
   但没串起来，本次约 20 次工具调用做考古。
