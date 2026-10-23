# ADH (Android DecryptHub) — 功能需求说明

> **产品定位**：**通用 Android 运行时逆向分析工具** — 不是 demo，也不是「手机版 jadx」。
> 适用于任意 App 的运行时观测/dump/hook/trace，并**对高对抗目标（反调试、root/签名检测、代码混淆、加密传输）具备实战能力**。
> **参考项目**：[taisuii/ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper)（IOSDecryptHub）
> **本文档范围**：本文档是**唯一权威功能规格**（模块 A–W；模块 X 手机 UI 自动化已于 2026-09-23 按产品范围决议退役）。开发步骤与排期见 `DEVELOPMENT_PLAN.md`。

---

> **⚠️ v2.0+ 加固重构（当前工作面）**：模块 A–W 的能力在 v0.1–v1.0 已全部"跑通一遍"；原可选手机自动化模块 X 已退役，AI 需要操作连接手机时直接使用 adb。
> 当前轮（v2.0+）不是加新模块，而是**把既有每条路径做到不骗人**——真实 hook 覆盖面（Java/inline）、
> 去 sandbox 耦合、环形缓冲如实上报、length-framed 协议、持久索引、脱壳二代、确定性关联等。
> 权威工作流与排期见 `DEVELOPMENT_PLAN.md §6.9`（WS-A…WS-K / v2.0–v2.6）。三条门禁：不为过测而耦合、
> 不胡乱兜底(fail-loud)、红线不动。本文档的模块规格仍是"要什么"的权威，§6.9 是"当前怎么把它做扎实"。

---

## 0. 与 iOS 参考项目的关系

[ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper) 是一个注入目标 App 的 dylib + 内嵌 Web 面板的 iOS 行为监控平台。它的能力边界受 iOS 平台限制，但产品形态和工程思路值得继承。

### 0.1 iOS 参考项目已具备的能力（我们要继承并超越）

| 能力域 | iOS 参考项目做了什么 |
|--------|---------------------|
| 加解密审计 | hook CommonCrypto / Security / OpenSSL EVP，记录算法、Key、IV、明文、密文、调用栈；流式分片拼回完整数据 |
| 文件监控 | hook open/write/unlink/rename，记录沙盒文件操作 |
| 系统监控 | hook dlopen/dlsym，记录动态库加载与符号解析；dlsym 重定向使函数指针调用也能被捕获 |
| 网络监控 | NSURLSession 请求/响应配对；SSL_read/SSL_write 明文捕获 |
| 二进制 dump | FairPlay 脱壳：导出解密 Mach-O |
| 反汇编 | Capstone：按字节/地址/函数反汇编 |
| Web 面板 | 多 tab、master-detail、实时列表、搜索、过滤、暂停、导出 |
| MCP Server | Streamable HTTP，30+ tools（disassemble、query_events、correlate_request 等） |
| 健康监控 | fail-loud：hook 失败、服务异常、落盘失败三处可见 |
| 测试宿主 | 交互式测试 App + URL scheme 自动化触发 |
| 悬浮窗 | 进程内毛玻璃浮窗 + 全屏日志查看器 |

### 0.2 iOS 参考项目的局限（Android 不受此限）

| iOS 局限 | Android 可充分发挥的空间 |
|----------|--------------------------|
| 无 DEX / ART 运行时结构暴露 | 完整 Dex 捕获、索引、smali、xref、按需反编译 |
| Mach-O 脱壳仅限已加载且 cryptid=1 的镜像 | dex/so/内存/oat/vdex 多源 dump + 脱壳辅助 + 方法体恢复 |
| fishhook 仅覆盖 import slot | PLT/GOT + inline hook + QBDI DBI |
| 扩展进程（appex）无法在主进程砸壳 | 多 ClassLoader、InMemoryDex、动态加载全链路可观测 |
| 沙盒文件路径受限 | /proc/self/maps 全内存枚举、任意 region dump、magic 扫描 |
| 难以做指令级 trace | QBDI 指定函数/地址范围 instruction trace |
| HTTP/MCP/分析全在目标进程 | **三层架构**：Agent 轻量采集，adhd 守护进程承担重活 |

### 0.3 架构升级（相对 iOS 参考项目的核心差异）

iOS 参考项目把 HTTP、MCP、Capstone、日志存储全部放在注入的 dylib 里。Android 项目采用三层分离：

```text
目标 App 进程          libadh_agent.so     hook / trace / dump / 采集 / 轻量 RPC
独立守护进程           ADH Daemon (adhd)   HTTP / WebSocket / MCP / DB / 索引 / 缓存 / 调度
浏览器                 Web UI              观测台、搜索、配置、可视化、导出
```

**记住这条红线**：目标进程内只做采集、拦截、定位；分析、索引、反编译、展示、持久化全部在 ADH Daemon。

---

## 1. 产品定义

### 1.1 一句话

一个运行在 Android 目标进程内的高能力 native agent，配合本机守护进程（ADH Daemon）、Web UI 和 MCP Server，实现：

- 运行时 dex/so/memory dump
- Java / native hook 与算法观测
- 函数级与指令级 trace
- Capstone 反汇编与二进制分析
- Dex 搜索、xref、smali / 伪 Java
- 脱壳辅助与算法逆向工作流

### 1.2 核心卖点（用户真正关心的）

```text
当前进程实际加载了什么 dex？
哪个 ClassLoader 加载的？
哪个方法用了这个字符串？
哪个方法调用了这个加密 API？
运行时 key/iv 的真实值是什么？          ← 明文边界观测，天然绕过加密与 pinning
这个 dex 是文件加载还是内存加载？
native 函数在 libxxx.so 的哪个偏移？
能否一键生成 Hook 点？
网络请求与加密调用能否关联？             ← 把密文对应到明文与调用方
这个 App 用了哪些反调试 / root / 签名 / 模拟器检测？   ← 反分析行为观测（模块 V）
检测到分析环境后它的行为如何分叉？
堆里当前活着的 token / key / 配置对象是什么？          ← 活体对象自省（模块 T）
```

> **第一卖点**：在**明文边界** hook（`Cipher.doFinal` / `Mac` / `SSL_write` / `EVP_*`），
> 无论目标用什么加密、是否加固、是否 pinning，都在数据变成密文之前拿到明文，
> 并回答「这段密文里装的是什么、key 是什么、谁发的」。

### 1.3 不是什么

- 不是全量 jadx 替代品
- 不是「万能脱壳器」
- 不是全进程无差别 instruction trace 工具
- 不是把重分析引擎塞进目标 App 的单体 so
- **不做 Frida 的功能表对齐（2026-10-01）**：能力按**分析问题**组织——native 算法还原 / Java 状态与风控 / TLS 与协议 / 加固脱壳，每类给一条端到端可验收路径；"Frida 有而我们没有"本身不构成需求

---

## 2. 系统组成

程序由四个可交付物组成：

| 组件 | 名称 | 职责 |
|------|------|------|
| Agent | `libadh_agent.so` | 注入目标进程，执行 hook/trace/dump/采集 |
| Daemon | `adhd` | 守护进程，HTTP/MCP/存储/索引/调度 |
| Web UI | 嵌入式前端 | 浏览器访问的实时观测台 |
| Sandbox | `sandbox-test-app` | 覆盖全模块的自动化验证宿主 |

辅助交付物：注入脚本、配置工具、proto 协议、文档。

---

## 3. 功能需求总览

```text
ADH (Android DecryptHub)
│
├── A. 进程接入与会话管理
├── B. Runtime Dex 管理
├── C. Dump Engine（dex / so / memory）
├── D. Java Hook Engine
├── E. Native Hook / libc / linker 监控
├── F. 文件与系统 API 监控
├── G. 网络监控
├── H. 加密算法观测与分析
├── I. Trace Engine（Java / JNI / Native）
├── J. 反汇编与二进制分析
├── K. Dex 索引、搜索与反汇编
├── L. 脱壳辅助（含 ART 结构级捕获、方法体恢复）
├── M. 事件中心与关联分析
├── N. Web 观测台
├── O. MCP Server
├── P. 自观测与审查日志
├── Q. 安全与访问控制
├── R. 数据存储与导出
├── S. 目标兼容性与抗干扰采集（诊断 + 韧性）
├── T. Runtime Object Inspector（活体对象自省）
├── U. 非标准运行时识别与扩展点（Flutter / Unity / RN）
├── V. 反分析行为观测（调试 / root / 签名 / 模拟器 / 完整性检测）
└── W. 注入后端（Zygisk + Gadget 直载 + 模拟注入）
```

以下逐模块描述「做什么」「看到什么」「边界在哪」。

---

## 4. A — 进程接入与会话管理

### 4.1 Agent 注入

**功能**：将 `libadh_agent.so` 加载到目标 App 进程。详细的后端与打包见**模块 W**。

**注入方式**（覆盖 root 与非 root 两条路径，用户按环境选择）：

- **Root 路径 — Zygisk 插件**（主线，early inject）：随 Zygisk 模块在 zygote fork 后早期加载，抢在目标反调试布防之前。
- **模拟注入**（开发/CI 主路径）：`sandbox-test-app` 自身 `dlopen` 加载 agent，无需真机对抗即可验证全部模块。
- ~~Frida Gadget 直载~~：**已退出产品面**（不再作为官方注入后端；Web/MCP 不展示加载入口）。

Agent 必须支持两种 bootstrap 入口且行为一致：被注入器加载（`JNI_OnLoad`/构造函数）与被宿主主动加载（导出唯一入口 `adh_agent_start()`）。

**功能要求**：

- 注入后自动连接 `adhd` 守护进程
- 上报进程身份：`pid`、`uid`、`packageName`、`processName`、`ABI`、`Android 版本`、`启动时间`
- 支持多进程 App：每个进程独立 session，adhd 统一管理
- 支持 attach / detach：用户从 Web UI 选择目标进程
- Agent 崩溃不影响 adhd；Agent 重启后自动重连并恢复 session 元数据

### 4.2 会话（Session）

**功能**：一次「观测任务」的完整上下文。

**Session 包含**：

- 目标进程信息
- 已捕获的 dex 列表
- 已加载 module 列表
- 活跃 hook 规则
- trace 任务状态
- 事件流游标
- dump 产物索引

**功能要求**：

- 支持 session 录制与回放（事件时间线可离线查看）
- 支持多 session 并行（多 App / 多进程）
- session 数据持久化在 adhd，Agent 断开不丢已采集数据

---

## 5. B — Runtime Dex 管理

**功能**：回答「当前进程实际加载了哪些 dex、从哪来、谁加载的」。

### 5.1 Dex 来源类型

| 来源 | 说明 |
|------|------|
| `BASE_APK` | 安装包内 classes.dex / classesN.dex |
| `SPLIT` | split APK 中的 dex |
| `DEX_CLASS_LOADER` | `DexClassLoader` / `PathClassLoader` 加载的外部 dex/jar/apk |
| `IN_MEMORY` | `InMemoryDexClassLoader` 从 `ByteBuffer` 加载 |
| `MEMORY_SCAN` | `/proc/self/maps` 或堆扫描发现的 dex magic |
| `ART_DEXFILE` | 通过 ART 内部结构关联定位（进阶） |

### 5.2 ClassLoader 追踪

**功能**：

- 记录完整 ClassLoader 树（parent 链、创建时机、关联 dex）
- 每个 dex 绑定 `class_loader_id`
- 类加载事件：`loadClass` 命中时记录 class 名、ClassLoader、dex 来源
- Web UI 展示 ClassLoader 拓扑图

### 5.3 Dex 身份与去重

**功能**：

- 每个 dex 计算 `sha256` 作为唯一身份
- 相同内容不同来源的 dex 合并展示，保留多来源标注
- 记录：`size`、`captured_at`、`load_path`（若有）、`source` 类型

### 5.4 Dex 列表展示

Web UI「Dex Browser」需展示：

- dex 名称 / hash / 大小 / 来源 / ClassLoader / 捕获时间
- 含多少个 class / method / string
- 索引状态（未索引 / 索引中 / 已索引）
- 操作：查看 / dump 下载 / 建立索引 / 搜索

---

## 6. C — Dump Engine

**功能**：从运行时获取真实二进制内容，不限于磁盘文件。

### 6.1 内存 Maps 管理

**功能**：统一抽象 `/proc/self/maps`。

```text
MemoryRegion {
  start, end, perms, offset, dev, inode, pathname
  type: heap | stack | anon | dalvik | dex | oat | vdex | cdex | so | apk | ashmem
  tags: []
}
```

**能力**：

- 枚举全部内存段
- 按权限过滤：r-- / rw- / r-x / rwx
- 按类型过滤：heap / so / dex / anon 等
- 按路径关键词搜索
- 读取指定地址范围（带权限检查）
- 导出 maps 快照

### 6.2 Magic 扫描

**功能**：在指定 region 或全进程扫描特征 magic。

| Magic | 识别对象 |
|-------|----------|
| `dex\n035` ~ `dex\n039` | DEX |
| `cdex` | Compact DEX |
| `ELF` | 可执行 / 共享库 |
| `PK\x03\x04` | ZIP / APK / JAR |
| `oat\n` | OAT |
| `vdex` | VDEX |

**输出**：命中地址列表、所属 region、上下文预览（前后 N 字节）

### 6.3 Dex Dump

**触发方式**：

- 手动：用户在 Web UI 指定 dex 或地址 dump
- 自动：`DexClassLoader` / `InMemoryDexClassLoader` 加载时
- 事件：命中加密 API / 目标方法时联动 dump
- 扫描：magic 扫描命中后一键 dump

**Dump 后处理**（在 adhd 执行）：

- sha256 去重
- dex header 修复（`file_size` / `checksum` / `signature`）
- 有效性检查（`code_item` 是否可读）
- 自动进入索引队列

### 6.4 SO Dump

**类型**：

| 类型 | 策略 |
|------|------|
| 文件型 | maps 有 pathname → 直接复制源文件 |
| 内存型 | 按 ELF program header 重组 segment |
| 修复型 | 多段拼接 r-x / r-- / rw-，修复 ELF header |

**元数据输出**：

- module name / base address / load bias
- segments 列表
- dynamic symbols / imports / exports
- strings 段提取
- 可执行段 hash

### 6.5 通用内存 Dump

**功能**：

- 指定 `start + size` dump 任意 region
- 按字符串附近 dump（命中地址 ± N 字节）
- 按对象地址附近 dump（Java 对象 / native 指针）
- 调用栈命中时自动 dump 当前线程栈附近内存
- heap / anon region 关键词搜索后 dump

### 6.6 Dump 产物管理

**功能**：

- 产物列表：类型（dex/so/region/maps）、大小、hash、时间、触发原因
- 下载 / 删除 / 重新索引
- 与 session 关联
- 批量导出 zip

---

## 7. D — 已移除

此模块不在 v1 产品面；历史设计只保留在 `docs/archive/`，不提供代码、Web UI、MCP 或工具入口。

---

## 8. E — Native Hook / libc / linker 监控

**功能**：观测 native 层行为，并明确标注事件来源与覆盖边界。

### 8.1 Hook Backend 抽象

```text
HookBackend
├── PLT/GOT hook          — 导入表调用
├── inline hook           — 任意地址
├── linker monitor        — dlopen/android_dlopen_ext
├── dlsym monitor         — 符号解析（含重定向）
├── syscall trace         — 系统调用级（可选）
└── QBDI instrumentation  — DBI 级
```

**UI 必须标注来源**：`Java API` / `libc` / `syscall` / `DBI` / `可能漏检 direct syscall`

> 实现状态（v4.6 / v4.9 / v4.15 / v4.31，真机 `aa165071` 验收）：inline hook 与主动调用都已覆盖 **两套寄存器 bank**。hook 事件给 `x0-x8/x18` 加 `fp:{d0-d7, s0-s7, q0hi-q7hi}`（float 参数只填低 32 位；事件把 double/float 两种读法都给出，**不做猜测** —— 哪种是调用方用的必须由目标签名判定）。参数改写目前只支持 x0-x7 整数槽，FP 参数只读。`native_call` 的实参是类型化的 `f:<float>` / `d:<double>`（同一条 FP 寄存器序列：第 i 个 FP 参数进 d_i，float 只填低 32 位即 s_i）与整数/指针 token（x0-x7），两个 bank 各限 8 个（第 9 个直接报错，v68 已验）。**用了 FP 参数时**才返回 `fpResult`(d0 原始 64 位) / `fpResultDouble`(%.17g，double 精确往返) / `fpResultFloat`(%.9g) + `returnBank:"d0"` + `x0MayBeStale:true`：double 返回填 d0，float 返回只填 d0 的低 32 位（s0），而 `result`/`resultDecimal` 是整数 bank 的 x0，只有目标确实返回整数时才是答案。128-bit / vector / 结构体返回值与栈上传参不在支持范围，**当前既不检测也不提示**（不解析，调用方按签名自判）。

### 8.2 libc / bionic 监控

| 函数 | 记录内容 |
|------|----------|
| `open` / `openat` | path、flags、fd、返回值 |
| `read` / `write` | fd、长度、数据摘要 |
| `pread` / `pwrite` | fd、offset、长度 |
| `close` | fd |
| `fopen` / `fread` / `fwrite` / `fclose` | 路径、模式 |
| `access` / `stat` / `lstat` / `fstat` | 路径 / fd |
| `mmap` / `munmap` / `mprotect` | 地址、大小、权限 |
| `connect` / `send` / `recv` / `sendto` / `recvfrom` | fd、地址、数据摘要 |

### 8.3 linker 监控

| 函数 | 记录内容 |
|------|----------|
| `dlopen` / `android_dlopen_ext` | path、flags、handle |
| `dlsym` | handle、symbol、resolved address |
| `dlclose` | handle |

**dlsym 重定向**（继承 iOS 思路）：

- 对已 hook 的 native 符号，`dlsym` 返回 wrapper 地址
- 使通过函数指针的间接调用也能被捕获
- 边界：目标在 Agent 注入前已缓存函数指针则无法重定向

### 8.4 Native 加密库监控

**OpenSSL / BoringSSL**（若目标链接）：

```text
EVP_EncryptInit_ex / EVP_DecryptInit_ex / EVP_CipherInit_ex
EVP_EncryptUpdate / EVP_DecryptUpdate / EVP_CipherUpdate
EVP_EncryptFinal_ex / EVP_DecryptFinal_ex / EVP_CipherFinal_ex
EVP_CIPHER_CTX_ctrl
EVP_DigestInit/Update/Final
HMAC_Init/Update/Final
```

**Java JCA**（注入进程内，与上面的 native EVP 同时采集）：

```text
javax.crypto.Cipher            init / doFinal
javax.crypto.Mac               init / doFinal
java.security.MessageDigest    digest
java.security.Signature        initSign / initVerify / sign / verify
```

记录算法名、操作（encrypt/decrypt/mac/digest/sign/verify）、key、iv、输入、输出，进同一条 `jcaptures`。原方法照常执行。作用域策略关掉的族不装钩子。

**其他**：

```text
AES_encrypt / AES_decrypt
MD5_Update / SHA1_Update / SHA256_Update
RSA_public_encrypt / RSA_private_decrypt
```

### 8.5 JNI 监控

| 监控点 | 记录内容 |
|--------|----------|
| `RegisterNatives` | class、methods 表（name/signature/fnPtr） |
| `Call*Method` 系列 | class、method、参数 |
| `NewStringUTF` / `GetStringUTFChars` | 字符串内容 |
| `GetByteArrayElements` / `SetByteArrayRegion` / `GetByteArrayRegion` / `ReleaseByteArrayElements` / `Get|ReleasePrimitiveArrayCritical` | 数组数据摘要（含 in-place 回写后的最终内容） |
| `FindClass` | class 名 |
| `GetFieldID` / `GetStaticFieldID` | 字段所属类、name、签名 |

> 实现状态（v4.18 / v4.19，真机 `aa165071` 验收）：JNI 监控通过 **JNIEnv 函数表槽位 hook**（替换表项指针，非函数体 patch）实现 —— 已实现 `RegisterNatives`（v4.14）、`FindClass` / `GetMethodID` / `GetStaticMethodID` / `NewStringUTF` / `GetStringUTFChars`（v4.18）、`GetFieldID` / `GetStaticFieldID` / `GetByteArrayElements` / `SetByteArrayRegion`（v4.19）。成员 ID 事件带所属类（`<class>#<name><sig>`），数组事件带长度 + 有界 hex 摘要（前 24 字节）。
> `Call*Method` / `NewObject` 系列（v4.24–v4.27）已按三种入口 + 全部返回类型接入：**varargs / V / A**，共 76 个槽位，可用 `function:"*"` 或前缀通配（`"CallIntMethod*"`）一次装/卸；状态里每槽位除 `installed/active/hits/dropped/slotValue/original` 外还给出 `last`（最近一次事件文本），目标流量冲掉捕获环时仍可核对。这一点必须三种都装：NDK 的 C++ `JNIEnv_` 内联包装其实是把参数塞进 `va_list` 后调 `...V` 入口，C 代码调 varargs 入口，生成的代码常调 `...A` 入口——只 hook 一种会漏掉整类调用者。事件里给出 `class#name(sig)` 与实参渲染（字符串/整数/长整型/浮点/对象指针，最多 6 个参数），成员名通过反射反查 `jmethodID`（`runtime/jni_method_names.c`，带 mid 缓存与扫描上限）。
> load-time `JNI_OnLoad`（v4.30）：`jni_onload watch module=...` 会挂 dlopen/`android_dlopen_ext` 钩子，在模块刚映射、VM 还没调用 `JNI_OnLoad` 时完成 patch；`skipOriginal+returnValue` 可以**替换**这次 load-time 调用（真机验证：插件自身 JNI_OnLoad 计数保持 0，而 `System.loadLibrary` 仍成功）。
> 边界：只观察**经过 JNIEnv 表**的调用（native 库的正常用法），ART 内部 C++ 直调不经过该表；`CallNonvirtual*` / `CallByte|Char|Short|Float|Double*` 等其余族可按同一机制继续加。每个槽位有 256 条事件上限，超过后只累加 `dropped`，入 ring 走既有 try-lock。
> 真机实测（`aa165071`）：debuggable 应用启用 **CheckJNI**，此时被替换的表项是 CheckJNI 包装（original 仍带检查）；wrapper 必须先 park 掉调用方的 pending exception 再做自己的反射调用，否则会吞掉目标的 `NoSuchMethodError` / `NoSuchFieldError`（装/不装/卸后同值的 A/B 验收见 `tools/verify_v60_jni_env_preserve.sh`）。反过来，在 pending exception 下调用 `GetMethodID` 这类非法用法会被 CheckJNI 直接 abort 进程，不在支持范围。

### 8.6 Direct Syscall 覆盖（分级）

灰产/加固常用直接 `svc` 指令绕过 libc/PLT hook。不承诺完全拦截，按级别收口：

| 级别 | 能力 | 边界 |
|------|------|------|
| L0 声明 | libc/PLT/inline hook 可能漏 direct syscall；UI 明确标注事件来源 | 默认 |
| L1 检测 | 扫描可执行段中 `svc #0` 指令热点，识别高频 syscall wrapper，输出疑似绕过 libc 的函数列表 | 静态，安全 |
| L2 观测 | 对指定函数/地址范围用 DBI 记录 syscall 前后寄存器，与文件/网络事件弱关联 | 需指定范围 |

| L3 高风险实验 | SVC patch / seccomp-unotify / PTRACE_SYSEMU | **已决议不做（2026-10-01）**：ptrace/seccomp 本身是强指纹，与低可检测性目标冲突；归因需求由 L1/L2 的 svc-site hook 覆盖。出现"必须看到全部 syscall 且不在乎被检测"的授权场景再重新评估 |

> 实现状态（v4.117，**实现 + host 单测 + 真机门禁完成**）：**钩子内联的指令 trace `traceInsns` / `traceFrom`**。要解决的问题是"输入的产地"看不全：目标的关键状态常常是**请求作用域**的（解释器帧、描述符、参数向量），先抓参数、事后再 trace，等 trace 跑起来那块内存已经被释放（京东该案例上这条路线死了三次）。所以 trace 必须跑在**命中当刻、目标线程上**。语义：`traceInsns: N`（0 = 关，默认）时，该钩子**每条已发事件**多一个 `trace` 子对象——**同一条记录**，不另发（另发就要靠 seq 配对，而 memAfter 的教训是"多一条记录就多一种配错"）；`traceInsns: 0` 时事件里**连键都没有**（"没开"与"开了没看到"必须可分）。`traceFrom: x0..x9 | x29 | x30` 用该寄存器里的**代码地址**当起点（缺省用被钩入口）；与 `skipOriginal`/`returnSet` **互斥**（trace 会执行原件，而那两项存在的意义就是不让它跑）。`trace = {insns, seen, stopReason, start, stopPc, capped, error?, mnemonics[{mnemonic,count}], first["0x…: insn"]}`，`stopReason ∈ completed | instruction-budget | time-budget | ran-away | left-range | did-not-run | reentrant`。实现约束（红线）：**per-thread VM**（`pthread_getspecific`，**绝不引入全局锁**——钩子会并发命中，全局锁等于给目标装隐形瓶颈）；三条守卫一个都不能省（指令预算 / 墙钟 300 ms / exec-range），exec-range 快照改为**不可变发布 + 原子换指针**（并发 run 会同时读它）；inline 钩的入口是我们自己的分支，所以从 Dobby trampoline 起跑并把函数所在模块一起加进插桩范围（否则 `did-not-run`）；`pc == lr` 在 PREINST 里先停，都不匹配时报 `left-range` 而不是谎称 `completed`；线程内重入以 `reentrant` 拒绝。代价写在 `agent/src/trace/qbdi_trace.h`：被 trace 的函数会被**执行**（每次命中跑两遍）、栈参数与浮点参数不保证、VM 每线程常驻。Host：`normalizeTraceInsns`/`normalizeTraceFrom`/`nativeTracePayload`（默认 payload **不带**这两个键，有单测）、`native_look read` 把 trace 并成一行、`nativeHookIdentity` 的头部窗口 4096→16384 hex（带 trace 的事件 ~3 KB，`seq` 会掉出旧窗口）。验收：`daemon/test/native_hook_trace.test.ts` 6 条 + identity/native_look 各补 1/2 条（330→**339** 通过，`tsc` 0）；`tools/verify_v117_inhook_trace.sh`（device）断言 sites 钩 `traceInsns:32` 的事件 `first[0]` 地址 **== 被钩入口**、inline 钩从 trampoline 起跑且能跳回函数体、`traceInsns` 缺省**无** `trace` 键、`traceInsns+skipOriginal` 被拒、返回值两次不变、目标存活；回归 `v110/v115/v10_qbdi/v113/v107/v114` 全 PASS。

> 实现状态（v4.120，**实现 + host 单测 + 真机门禁完成**）：**可控回放 + 差分** `oracle`（MCP tool）。这是"未知参数"变成"小搜索空间"的那件原语，也是这一轮验证过"必须有"的东西——每做一次真实协议分析都要手写一遍（拼参数数组、回放、比两份捕获），而且很容易写错（改错字段、模板被污染、调用把会话拖死）。语义：`record` 用 **detached java_call** 调一次目标自己的门面并把**当次参数**存成模板（阻塞的方法只占一条线程，不占会话），`extract` 指定回复里要观察的值路径（默认 `result`，路径行走时**遇到像 JSON 的字符串会先解析**，所以 `result[0].b5` 对"返回 JSON 字符串的门面"照样成立）；`replay` 把补丁打到**记录下来的参数**上再跑（字节载荷仍是 `{"$bytesHex":…}`，所以 `[1][0].$bytesHex` 就是普通路径），回 `value`/`changed`；`diff` 每个 variant 跑一次并给出**依赖矩阵**：`sensitive` = 单字段改动**会**移动观察值的字段（即 preimage 的一部分），`insensitive` = 改了也不动的字段——多字段 variant 不参与归因（无法分辨是谁起的作用）。`list`/`drop` 管理模板。全部纯函数（`getPath`/`setPath`/`summarizeDiff`）有单测，agent 只负责执行。验收：`daemon/test/oracle.test.ts` 6 条（路径/不可变写/矩阵归因/模板不被污染/未知 id 报错/目标异常透传），**349 通过**、`tsc` 0；`tools/verify_v120_oracle_diff.sh`（device）用沙盒静态门面 `JniCallStatics.staticCombine(label,count)`（返回 `S:<label>:<count>`）证明 record→replay→diff 的每一步：baseline `S:ADH:7`、`[1]=8 → S:ADH:8`、两个 variant 都进 `sensitive`、无变化的补丁进 `insensitive`——PASS。

> 实现状态（v4.119，**实现 + host 单测 + 真机门禁完成**）：**命中点内的写观察点** `native_hook { traceWatch: "x0:32" }`（与 `mem` 同一套窗口文法：寄存器 + 有符号偏移 + 可选一层解引用）。存在理由很硬：硬件观察点要靠 `perf_event_open(PERF_TYPE_BREAKPOINT)`，而 app 域在这台设备上被拒（**errno 13**），于是"到底哪条 store 写了这块内存"此前**没有任何答案**——指令 trace 只知道跑了哪些代码，不知道哪次写落在哪。现在它是事实：trace 期间对 `[lo,hi)` 挂 QBDI 的 `qbdi_addMemRangeCB(QBDI_MEMORY_WRITE)`，回执 `traceWatch {lo, hi, count, truncated, hits:[{pc, insn, addr, size, value}], error?}`；范围在**命中当刻**由寄存器算出（所以调用方给寄存器，而不是会过期的绝对地址），**只在该次 run 内生效**（per-thread VM 会跨命中复用，因此 run 结束立刻 `qbdi_deleteInstrumentation`，否则下一次命中会替上一次的范围付钱）。三条守卫与 `traceInsns` 共用；`traceWatch` 必须配 `traceInsns`，否则拒绝（"装了钩却从不观察"是最坏的一种谎）。Host：`normalizeTraceWatch`（**恰好一个窗口**、canonical、非法即抛），默认 payload 不带该键；`native_hook` 的 status 回显 `traceWatch`。验收：`daemon/test/native_hook_trace.test.ts` 新增 3 条（默认无键 / 规范化与有符号偏移 / 拒多窗口与缺 traceInsns），**343 通过**、`tsc` 0；`tools/verify_v119_trace_watch.sh`（device）用一个通用夹具（读 8 字节并把 `buf[0]^=0xff`）断言事件里 `hit.addr == buf`、`size == 1`、`value == 0xbe`、`insn` 是 `strb`、`lo` 是解析后的范围起点；再把同一钩子**不带** `traceWatch` 重新激活，断言事件**没有**该键且 `trace` 仍在——PASS。回归 `v117/v118/v114` 全绿。

> 实现状态（v4.118，**实现 + host 单测 + 真机门禁完成**）：**命中点窗口可以往回读** `x<reg>-<off>:<len>`（`x3-40:40`）。理由不是"方便"：模板解释器把指令记录放在**一整片连续数组**里，所以"产出这个值的那条指令"在 `pc-10`，**在处理函数拿到的指针之前**——只往前看的文法永远回答不了"上一条是什么"。实现：agent 的 `parse_window` 接受 `-`（`@#<n>` 的偏移仍是无符号的字节下标，负值是另一个问题，直接拒），命中时按有符号算地址，借位到 0 以下报 `underflow` 而不是变成巨大地址；canonical 拼写保留负号（`x0-8:16`），status 回显它。Host：`parseMemWindows` 同一文法、`±65535` 上限（错误文案写 `±`）、canonical 去零。验收：`daemon/test/native_hook_mem.test.ts` 新增 1 条（正负偏移、`-0` 归一、`@x1-8`、上限、`@#1-8` 被拒）+ 既有 1 条文案更新（340 通过、`tsc` 0）；`tools/verify_v118_negative_window.sh`（device）在已知 16 字节图案后调一个**冷**夹具（`buf+8`），要求记录里 `offset:-8`、`hex` 恰好是那 16 字节、status 回显 `x0-8:16`、目标存活——PASS。

> 实现状态（v4.43，**实现 + host 验收完成，真机验收待做**）：**系统调用监听从"发生了什么"推进到"是谁发的、发了多少次、挂对了没有"**。`syscall_digest`（MCP + `POST /api/syscall/digest`）读取本次会话的 `NATIVE_HOOK` 事件（`syscall_watch` 现在装钩时带 `backtrace:true`，事件里带命中当刻的调用链），按 **(syscall 号, 调用方帧)** 分组给出次数/首末时间/线程，并**优先取 libc 之外的第一帧**作为"发起者"（指纹采集排查要的就是这个）；同时把**运行期 x8 与静态归因号逐事件比对**，不一致时列出 `mismatches {hookId, attributed, observed, count}`——这正好补上"归因可能错但没人比对"的缺口。**参数解码**：`syscall_args.ts` 把寄存器翻译成路径/结构体/标志位（`openat` 路径 + flags 访问模式、`uname` 的 utsname、`connect` 的 IPv4/IPv6、`memfd_create` 名字、`ioctl/socket/read/write/getrandom/kill/prctl` 标量），指针由 Host 经 agent 有界读取（`decodeLimit` 默认 40，`decode:false` 可关），读不到写 `(unreadable)`；摘要额外给出 **`paths` 直方图**与每组 `example`。纯函数 `digestSyscallSamples` 有 10 条、`syscall_args` 有 9 条单测（libc 帧跳过、分组/时间窗/线程去重、号码未知不丢、名字表、错配检测、空输入说明、无符号按 offset、plan/路径/flags/uname/双栈 sockaddr/ioctl/不可读/垃圾串）；`tools/verify_v81_syscall_digest.sh`（host）跑全部 **44** 条 daemon 单测 + 合成命中断言 + 参数解码断言 + MCP schema，**PASS**。真机验收（对 `libc.so` 的 uname 站点跑 watch → 触发沙盒探针 → digest 必须给出 `adh_libc_uname_probe` 作为调用方且 `observed` 全为 160）待手机可用时补。

> 实现状态（v4.41，**实现 + host 验收完成，真机验收待做**）：**trace 日志的 AI 友好摘要**。`qbdi_trace` 一次最多回 8192 条原始指令——精确但没法看。新增 `daemon/src/trace_digest.ts`（纯函数 `digestTrace`）：把指令流聚合成 **循环**（回边目标 + 体大小 + 迭代次数）、**调用目标**（次数；能取到模块 dump 时给出符号）、**内存访问形态**（`ldr/str [base+off]` 计数）、**立即数常量**（已知 crypto magic 自动标注，如 TEA 黄金比、MD5/SHA1/SHA256 初值）、**分支形态**（条件/无条件/间接 + 目标计数）、**热点指令**；并给诚实注释（命中 8192 上限、`blr` 目标未解析、无循环时说明可能是直线代码）。MCP `trace_digest`（+ `POST /api/trace/digest`）一次调用完成"跑 trace + 摘要 + 给调用点/热点符号化"。**已验收**：`tools/verify_v80_trace_digest.sh`（host，18 条单元测试 + 合成 trace 断言 + MCP schema）；**真机验收（对 `libadhdetect.so` 的 `adh_add_target` 跑一次并断言摘要内容）待手机空闲后补**——期间 `backtrace.ts` 的模块/符号解析抽到了 `module_symbols.ts`（供 digest 复用），`verify_v77/v78` 需要在真机上复跑确认无回归。

> 实现状态（v4.48，**实现 + host 验收完成，真机验收待做**）：**native 事件限流 `throttleMs`** —— 热站点（`read`/`write`/`futex`）一秒能打出上万条 `NATIVE_HOOK`，事件环一满，摘要读起来就像"目标没动静"，所以限流解决的是**诚实性**问题而不是流量。每个钩子一个窗口：窗口内**最多发一条事件**，被压掉的命中**照样计数**——下一条事件带 `throttled`（这条事件代表多少次命中），`status` 带累计 `throttled`，于是恒等式 **`hits = 已发事件 + throttled`** 始终成立。窗口 0 = 每条都发（默认，行为与告警都不变），>0 夹紧到 **0..60000 ms** 且 status 回显生效值；槽位复用与软卸载后重新激活都会清零窗口与计数。**限流只压事件、不改行为**：`argIndex` 参数改写、`returnValue` 返回值替换、`skipOriginal` 在窗口内的命中上照常生效（`record_site` 照常回答"不要调原函数"）——限流永远不会把改行为的钩子变成"偶尔放行"；实现无锁（命中线程上一条 relaxed 时间戳读，窗口用 `CLOCK_MONOTONIC`，被压增量用 `exchange` 取，两个并发 emitter 不会重复报同一批命中），失败模式是"多发一条"，绝不阻塞目标线程。Host 侧新增纯函数 `daemon/src/native_hook_args.ts`（`normalizeThrottleMs`：缺省/≤0 = 0，>60000 夹紧，非数字**拒绝**而不是当 0；`nativeHookInstallPayload` 统一装配），`native_hook_all` 与 `syscall_watch` 都改走它——"throttleMs 真的上线了"从此是可单测的事实；`native_hook` / `native_hook_all` / `syscall_watch` / `syscall_trace`（MCP + REST）全部暴露 `throttleMs`，REST 对非法值回 **400**（参数错不是设备错）。验收：`daemon/test/native_hook_throttle.test.ts` 12 条单测（默认关闭/夹紧/截断/拒绝垃圾值/装配/不悄悄限流，外加**安装回路**：注入式 sender 断言两个 host 工具真实发出的 payload 带 `throttleMs`，中途失败必须把已装 hook 交回调用方）+ `tools/verify_v86_native_throttle.sh`（host：跑单测 + 断言 agent"先改写后限流、被压命中计数并照常回答 skipOriginal、status 带窗口与累计" + 断言 host 工具确实带上该字段 + MCP 四工具 schema），**PASS**；agent 零告警重建通过。

> 实现状态（v4.47，**实现 + host 验收完成，真机验收待做**）：**一站式系统调用跟踪** `syscall_trace` —— `start` 调 `syscall_watch` 并把它响应里的归因**自动串成 `expected {hookId: nr}`**（错位会以 mismatch 暴露，而不是被手工抄错），`digest` 走共享 `drainSession` + `syscall_digest`（调用方/次数/`paths` 直方图/mismatch），`stop` 只卸传入 id（显式拒绝空列表与 0）。装不上任何钩时 fail-loud。MCP 工具数 → 71；纯装配单测 8 条 + `tools/verify_v85_syscall_trace.sh`（host，PASS）。

> 实现状态（v4.46，**实现 + host 验收完成，真机验收待做**）：**native 批量挂钩** `native_hook_all` —— 给 `module` + `prefix/contains/exact` 过滤，Host 从模块 dump 解析导出表、只挑 **STT_FUNC**（可 `exclude` 去噪），按地址序取前 `limit`（≤16）个逐个装 inline hook，返回 `hookIds` + `matched` vs `installedCount` + 每符号失败明细；`action:unhook` 只卸传入 id；`confirm:true` 必填。MCP 工具数 → 70，纯函数 7 条单测 + `tools/verify_v84_native_hook_all.sh`（host，PASS）。

> 实现状态（v4.45，**实现 + host 验收完成，真机验收待做**）：**Java 类级 trace 摘要** `java_trace` —— 三阶段 `start / digest / stop`。`start` 用 v4.44 的 `hook_all` 挂整个类（或指定方法的所有重载）并**保留**钩子；`digest` 先显式 `capture_drain`，再把这些 hookId 的 `JAVA_HOOK` 事件聚合成每方法次数/首末时间/线程/最后参数与返回值/错误计数、**时间线**（保留最新窗口）与**调用方直方图**（`stack:true` 时取 Java 调用链最内层 App 帧）；`stop` 只卸传入 id。MCP `java_trace` + `POST /api/java/trace`；纯函数 7 条单测 + `tools/verify_v83_java_trace.sh`（host，PASS）。

> 实现状态（v4.44，**实现 + 构建完成，真机验收待做**）：**Java 侧批量挂钩 `action=hookAll`**（对标 Frida 的 `overloads.forEach(hook)`）。一次调用收集该类的全部匹配方法（**声明 + 继承链**，可选 `method` 与 `params` 过滤，`"*"` 即任意），逐个走**既有的单方法安装路径**（构造器限制、槽位上限、部分失败回滚等规则完全一致），返回 `hookIds[]` 与 **`matched`**（匹配到多少个）——被 `limit` 截断时一眼可见。去重键是 **(方法名, 参数列表)**：只按参数去重会把 `foo(int)` 与 `bar(int)` 里的一个悄悄丢掉（实现时自查出来的）。MCP `java_hook action:hookAll`（+ `limit`）与 HTTP 路由同名参数；agent 构建零告警。真机验收脚本 `tools/verify_v82_java_hook_all.sh` 已写好（两个 `ping` 重载各自产生事件；`limit=3` 的类级批次必须 `installed=3 < matched`；`unhook 0` 后进程存活），等手机接回执行。

> 实现状态（v4.40，真机 `aa165071` 验收）：**Java hook 命中时带调用链**（native 版的姊妹能力，v4.39）。`java_hook stack:true` 时 `AdhJavaHookBridge` 在回调里采一条有界调用链（`Class#method:line`，最内层在前，最多 12 帧/512 字符），并**过滤掉采集自身与 hook 管线**（`java.lang.Thread`、`dalvik.system.VMStack`、`java.lang.reflect.Method`、`AdhJavaHookBridge`、LSPlant 的 `NativeBridge_` 合成类），因此事件里的 `stack` 就是"谁调用了目标方法"；per-hook status 同步给出 `stackCapture` 与 `lastStack`，status 顶层带 `stackCapture:true` 能力位。默认关闭（每次命中一次栈遍历）。真机验收 `tools/verify_v79_java_stack.sh`：hook `HookProbe.ping(String)`（stack:true）后经 `stackOuter → stackMiddle → ping` 调用，事件 `stack` 恰好是 `com.adh.sandbox.HookProbe#stackMiddle:33 <- com.adh.sandbox.HookProbe#stackOuter:36`（顺序正确、无管线帧），status.lastStack 一致；同一方法再以**不带 stack** 的方式 hook 时事件里**没有** stack 字段而功能不变，两次 unhook 后进程存活。

> 实现状态（v4.39，真机 `aa165071` 验收）：**native hook 命中时带调用链**（对标 Frida `Thread.backtrace()`）。关键设计教训：**链必须在命中当刻采集**——第一版让 Host 事后去读目标栈，读到的是已经被进程复用/清零的内存（真机现象：`[fp]`/`[fp+8]` 全 0，只有 `lr` 可信）。现在 `native_hook backtrace:true` 让 agent 在命中线程上直接走 x29 链：先用 `pthread_attr_getstack` 拿到本线程栈边界（thread-local 缓存一次），再在边界内逐帧读 `[fp]`/`[fp+8]`，最多 8 帧，写进事件的 `bt`（`bt[0]` 就是 `x30` 立即调用者）。Host 侧 `native_backtrace`（MCP + `POST /api/native/backtrace`）把每帧按**包含它的 maps 区域**定位模块（原先 min/max 匹配会把沙盒帧错认成 `base.apk`），并用 PT_DYNAMIC 解析 `.dynsym` 给出"模块+偏移+最近符号（尺寸覆盖时标 exact）"，因此在**内存重建镜像（没有节头表）**上同样可用；来源是 APK 内映射的库如实报 `symbolSource=archive-mapped`。诚实的失败面：未映射的返回地址（`return-address-not-mapped`，列表到此为止）、栈不可读、fp 不在可写映射内、链不递增或成环——各自写进 `stopReason`，不编造帧。真机验收 `tools/verify_v78_hook_backtrace.sh`：`adh_bt_outer → adh_bt_mid1 → adh_bt_mid2 → adh_bt_target`（该沙盒库用 `-fno-omit-frame-pointer` 构建）三帧全部 `exact`，第 4/5 帧落到 `libadh_agent.so`（native_call 蹦床的调用方）；再用 `fp=0x1` 显式路径验证"停在第 1 帧 + 说明原因"。

> 实现状态（v4.38，真机 `aa165071` 验收）：**L1 升级为"可归因 + 可按名筛选"，并把覆盖面从"目标自己的 direct svc"扩到 libc 封装**——普通 App 不自己发 `svc`，它调的是 bionic 包装函数，桩在 `libc.so` 里。Host 侧新增静态归因：对每个 `svc #0` 站点向前解码"把号写进 x8 的 MOV"(MOVZ x8/w8，#imm / MOVZ x8，#imm，lsl #16)，遇到控制流指令即停止（绝不借用邻桩的号）；解不出来就如实报 `unknown`，不猜。`syscall_watch` 因此支持 `syscalls: ["uname","openat",117]` 过滤（名字/十进制/十六进制都行），命中为 0 时 **fail-loud**；`native_syscall_scan` 同样返回每站点的号 + 名字。真机数据：bionic `libc.so` 224 个 `svc` 站点，223 个成功归因（`openat/getrandom/uname/getuid...`，1 个解不出）；`syscall_watch module=libc.so syscalls=["uname"]` 只挂那 1 个站点，沙盒探针走 libc `uname()` 后 `NATIVE_HOOK` 事件 `x8=0xa0` 命中，卸钩后进程存活（`tools/verify_v77_syscall_watch_libc.sh`）。归因解码器有真机无关的单元测试（`daemon/test/syscall_watch.test.ts`，7 条）——第一版就抓到一个致命 bug：JS 位与是**有符号 int32**，`0xd2800008 & mask` 落在负数域，等于正向字面量永不成立，归因**全空**而所有静态检查全绿。

---

## 9. F — 文件与系统 API 监控

本节是 **Java 层**文件/系统监控的独立视图（与 D.7.3、D.7.4 配合），侧重 Web UI 展示。

### 9.1 事件记录格式

```text
FileEvent {
  event_type: READ | WRITE | DELETE | RENAME | MKDIR | ...
  timestamp, thread_id
  path, fd
  size, data_preview
  source: JAVA | LIBC | SYSCALL
  stacktrace
  class_name, method_name  (若来自 Java)
}
```

### 9.2 噪点过滤

继承 iOS 噪点过滤思路：

- 系统路径白名单/黑名单
- 高频无用路径自动降噪
- 「查看噪声」模式：展示被过滤的事件
- 用户可标记「非噪声」反馈给规则

### 9.3 文件浏览（可选进阶）

- 列出 App 可访问目录（data/data/包名/...）
- 读取 / 下载沙盒内文件（需权限声明与二次确认）
- 与文件事件联动：点击路径查看相关事件

---

## 10. G — 网络监控

**功能**：捕获网络请求与响应，并与加密事件关联。

### 10.1 Java 层网络

| 框架 | 监控方式 |
|------|----------|
| `HttpURLConnection` | hook 输入/输出流 |
| `OkHttp` | hook `RealCall.execute/enqueue`、`Request/Response` |
| `Retrofit` | hook ServiceMethod 层 |
| `WebView` | hook `loadUrl`、`shouldInterceptRequest` |
| `SSLSocket` | 握手与读写 |
| `HttpsURLConnection` | 同 HttpURLConnection |

**记录内容**：

- URL、method、request headers、request body
- response status、response headers、response body
- 耗时、线程、调用栈
- 请求与响应**配对**为一条记录（继承 iOS 配对思路）

### 10.2 Native 层网络

| 函数 | 记录内容 |
|------|----------|
| `SSL_write` / `SSL_read` | 明文数据（App 自带 TLS 栈时） |
| `connect` | 目标地址 |
| Cronet / 自研协议 | 按 module 定制 hook |

**边界**：系统 TLS 若不经 App import slot，可能不命中，UI 需说明。

### 10.3 关联分析

**功能**（继承 iOS `correlate_request`）：

- 给定一条网络事件，在时间窗 + 线程维度查找相关的加密事件
- 输出：该请求前/后发生了哪些 Cipher/MessageDigest/Mac 调用
- 可视化：时间线上网络请求与加密调用的叠图

---

## 11. H — 加密算法观测与分析

### 11.1 动态通道（主力）

汇总 D.7.2 与 E.8.4 的 hook 输出，提供统一「算法观测台」：

- 实时事件流
- 按算法分类：Digest / HMAC / Symmetric / Asymmetric / Base64
- 按操作分类：Init / Update / Final / Encrypt / Decrypt / Sign / Verify
- 详情：Key / IV / 明文 / 密文 / Hex / HexDump / 调用栈
- 流式拼包：多次 update 合并为完整输入输出

### 11.2 静态通道

**DEX 扫描**（在 adhd 对已索引 dex 执行）：

- 引用 `javax.crypto.Cipher`、`java.security.MessageDigest` 等类的方法
- `const-string` 中的算法名字符串（AES、RSA、MD5、HmacSHA256 等）
- `invoke` 链：从入口方法到加密 API 的调用路径

**Native 扫描**（对已 dump 的 so）：

- 导入符号：EVP_*、AES_*、MD5_*、SHA*_*
- 字符串：算法名、密钥相关常量
- 输出「疑似算法函数」列表

### 11.3 静态 + 动态联立

```text
静态定位疑似 sign() 方法
    ↓
动态 hook 该方法 + Cipher.init
    ↓
一次登录流程后输出完整算法链路
    ↓
点击跳转 smali / native disasm
```

### 11.4 Stripped Native Crypto 常量签名扫描

灰产常把加密放 native、静态链接 + strip 符号，`EVP_*`/`AES_*` 符号 hook 落空。对 dump 出的 so 扫描**算法特征常量**定位疑似算法函数，再 inline hook 定点：

| 特征常量 | 识别对象 |
|----------|----------|
| AES S-box / 逆 S-box、Rcon | AES |
| `0x6a09e667…`（8 个初值） | SHA-256 |
| MD5 init `0x67452301…`、T 表 | MD5 |
| SHA-1 init `0x67452301…0xC3D2E1F0` | SHA-1 |
| Base64 字母表 `ABC…/+` | Base64 |
| TEA/XTEA delta `0x9E3779B9` | TEA 系 |
| CRC32 多项式表 | CRC |

**输出**：疑似算法函数候选列表（module + offset + 命中常量），可一键 inline hook。

### 11.5 字符串解密例程观测

混淆器把常量字符串加密、运行时解密。能力：

- 识别/hook 字符串解密函数（Java 静态方法或 native），记录输入密文 → 输出明文。
- 或对解密后内存 dump，重建**明文字符串表**。
- 与 dex 索引联动：把解密后的明文回填到方法上下文，抵消字符串混淆。

---

## 12. I — Trace Engine

**功能**：观测真实执行路径。分三种，不混用。

### 12.1 Java 方法级 Trace（主线）

**记录**：

- 方法进入 / 退出
- 参数 / 返回值 / 异常
- 线程、调用栈、耗时

**过滤**（必须支持，默认开启过滤）：

- 按包名 / 类名 / 方法名
- 按关键词命中
- 按 API 类型：加密 / 网络 / 文件 / 设备信息
- 按线程
- 按时间窗口（只 trace N 秒）
- 按命中次数上限

**输出**：

- 调用树
- 线程时间线
- 与 smali 对照跳转

### 12.2 DEX 指令级 Trace（调试模式）

**边界**：ART 可能 JIT/AOT，不一定逐条执行 dex opcode。

**定位**：小范围、指定方法、调试模式。

**能力**：

- 指定 method_idx 的 opcode 级执行记录
- 必要时强制解释执行 / 插桩
- 与 smali 行号对照

**禁止作为默认功能**：不做全进程 DEX 指令 trace。

### 12.3 Native Trace（QBDI）

**过滤维度**：

```text
scope: module | address range | function | thread | duration | hit count | condition
event: call | ret | basic block | instruction | mem read | mem write | register snapshot
```

**模式**：

| 模式 | 用途 |
|------|------|
| 函数级 trace | 默认，看调用关系 |
| 基本块 trace | 分支分析 |
| 指令级 trace | 算法逆向，指定地址范围 |

**输出 — TraceEvent**：

```text
timestamp, pid, tid, module, pc, symbol, event_type
asm, regs, mem_access, call_depth, correlation_id
```

**Web UI**：

- 函数调用树
- 线程时间线
- 基本块图
- 指令列表 + 反汇编
- 寄存器变化
- 内存读写热点

---

## 13. J — 反汇编与二进制分析

**功能**：基于 Capstone，在 adhd 中做主要分析，Agent 仅提供轻量即时反汇编。

### 13.1 地址模型

```text
Runtime Address = module_base + offset
File Offset     = ELF segment mapping
Display         = libcrypto.so + 0x345678
```

Web UI 优先显示 `module + offset` 或 `symbol + offset`，不仅显示裸绝对地址。

### 13.2 反汇编能力

- 按地址反汇编 N 条指令
- 按字节 hex 反汇编
- 按函数范围反汇编（已知起止地址）
- 按 module 枚举可执行段并反汇编
- 架构：ARM32 / ARM64（主线），可扩展 x86

### 13.3 二进制分析

```text
BinaryAnalyzer
├── module 列表
├── 可执行段枚举
├── 符号表 / 动态符号
├── imports / exports
├── strings 提取
├── 函数候选（entry / prologue 识别）
├── branch targets / call targets
├── xref（谁调用了谁）
└── 搜索索引
```

### 13.4 搜索能力

- 字符串搜索
- 符号名搜索
- 地址搜索
- 汇编助记符搜索
- 立即数搜索
- call / jump 目标搜索
- 函数交叉引用

### 13.5 与 Trace 联动

- trace 命中 PC → 一键反汇编该地址
- 反汇编 call 指令 → 跳转目标函数
- 函数级 trace 树节点 → 展开为指令列表

---

## 14. K — Dex 索引、搜索与反汇编

**功能**：按需反编译，不是全量 jadx。

### 14.1 Dex 解析

解析标准 dex 结构：

```text
string_ids / type_ids / proto_ids / field_ids / method_ids / class_defs / code_item
```

支持：标准 dex、多 dex、修复后的内存 dex。

### 14.2 索引

| 索引 | 内容 |
|------|------|
| string index | 全部字符串 |
| class index | 类名、父类、接口、access flags |
| method index | 类名、方法名、descriptor、access |
| field index | 类名、字段名、类型 |
| invoke xref | method → callers / callees |
| string xref | string → used_by_methods |
| field xref | field → readers / writers |

### 14.3 搜索（优先级高于全量反编译）

| 搜索类型 | DEX 指令特征 |
|----------|-------------|
| 字符串 | `const-string`, `const-string-jumbo` |
| API 调用 | `invoke-virtual/static/direct/interface` |
| 字段 | `iget/iput/sget/sput` |
| 类引用 | `new-instance`, `check-cast`, `instance-of`, `const-class` |
| 加密特征 | Cipher, MessageDigest, Mac, SecretKeySpec, Base64 |
| 网络特征 | OkHttp, Retrofit, WebView, HttpURLConnection |

**典型工作流**：

```text
搜 "/api/login"
  → 哪些方法用了这个字符串
  → 这些方法调用了谁 / 谁调用了它们
  → 一键看 smali
  → 一键生成 Hook 模板
  → 一键启动 crypto trace
```

### 14.4 反汇编输出

- **smali**：`dex_sha256 + method_idx → smali`（按需生成，缓存）
- **伪 Java**：按需 method 级生成，非全量 decompile
- **CFG**：基本块 + 分支可视化（进阶）

### 14.5 缓存策略

```text
dex_sha256 + method_idx  -> smali
dex_sha256 + method_idx  -> pseudo_java
dex_sha256 + string_idx  -> used_by_methods[]
dex_sha256 + method_idx  -> callers[] / callees[]
```

不缓存全量反编译结果，避免内存爆炸。

---

## 15. L — 脱壳辅助

**功能定位**：运行时 dex 捕获 / dump / 修复辅助，不是「万能脱壳」。

### 15.1 一代整体加固

壳把真实 dex 解密后加载。

**工具能力**：

- hook `DexClassLoader` path → 复制 dex
- maps 扫描 dex magic → dump
- classloader 监控 → 自动捕获
- dex header 修复
- 自动建索引

### 15.2 二代抽取壳

方法体运行时才解密。

**工具能力**：

- 类加载后 dump
- 方法首次执行后 dump
- 执行前后 `code_item` 对比
- 指定 class/method 定点 dump
- 有效性检查：哪些方法已恢复、哪些仍为空

### 15.3 内存 dex 型

`InMemoryDexClassLoader` + `ByteBuffer`。

**工具能力**：

- hook 构造 → dump ByteBuffer 全内容
- 修 header → 索引 → 搜索

### 15.4 VMP 虚拟化壳

**工具能力**（辅助，不承诺还原 Java）：

- trace VM dispatch
- 识别 opcode handler
- dump vm bytecode
- 记录输入输出
- 定位关键 API 调用

### 15.5 产品描述边界

```text
支持：运行时 dex 捕获、内存 dex dump、方法体恢复辅助、抽取壳分析辅助
不支持承诺：所有壳还原成可读的 Java 源码、VMP 完整语义还原
```

**口径（2026-10-01 确认）**：**覆盖所有场景类型都有对应工具与流程，不保证每个壳 100% 还原；
恢复率如实上报**（分子/分母都来自真实解析，解不动的显式 `unresolvable` 并计入分母）。
即：产品承诺的是"给你一套能对任何一类壳展开作业的方法与可验证的进度",
不是"任何壳都能出可读源码"。**无真实样本的壳类型不进排期**（见 §22.3）。

### 15.6 ART 结构级 Dex 捕获（主力，优先级高）

不依赖 dex magic、不依赖磁盘路径、不依赖 ClassLoader 构造参数，直接从 ART 运行时结构关联真实 DexFile。混淆/加固改不了已加载的字节码，这是最鲁棒的捕获路径。

**能力**：

- 遍历 `ClassLinker` / `DexCache` / `ClassLoader`，枚举已加载 Class ↔ DexFile 关系
- 记录映射：`ClassLoader → DexFile → begin/size`
- 从 ART DexFile 内存地址 dump（支持 CompactDex → 展开为标准 dex）
- 与 maps magic scan 结果**交叉校验**
- 按 Android API level 维护 resolver（ART 内部结构随版本变动；**优先覆盖测试设备 SDK 36**）
- 失败时输出**结构探测报告**，不静默失败

**输出**：`DexIdentity.source = ART_DEXFILE`、`art_location`、`class_loader_id`、`begin`、`size`、`api_level`

### 15.7 Method Body Recovery 辅助

针对二代抽取壳（方法体运行时才解密）。分两模式，**不做无脑全量主动 invoke**（避免触发风控/网络/删数据/自毁）：

**模式一 · 被动恢复**：

- 方法真实执行前后对比 `code_item`
- 命中 hook/trace 时自动 snapshot code_item
- 标记每个方法的 body 恢复状态（已恢复 / 仍为空 / 未触发）

**模式二 · 受控触发**：

- 仅对 sandbox 或用户**显式选择**的方法启用
- 默认跳过：构造函数、native 方法、同步方法、调用链含危险 API 的方法
- 支持 dry-run 风险分析、one-shot、超时、线程隔离、异常捕获
- 触发前后记录 `code_item` 差异

**边界**：不承诺无副作用；不默认全量 invoke；不对未知业务方法自动执行。

---

## 16. M — 事件中心与关联分析

**功能**：所有模块产生的数据统一进入事件中心。

### 16.1 事件类型

```text
CRYPTO      — 加密 API 调用
FILE        — 文件读写
NETWORK     — 网络请求/响应
SYSTEM      — dlopen/dlsym/mmap 等
JAVA_HOOK   — 自定义 Java hook 命中
JNI         — JNI 调用
NATIVE      — native hook 命中
DEX         — dex 加载/捕获
DUMP        — dump 完成
TRACE       — trace 事件
CLASS_LOAD  — 类加载
DETECTION   — 目标的反分析检测（调试/root/签名/模拟器/完整性）
AUDIT       — 工具自审计（hook 安装/RPC/错误，独立于目标事件流）
```

### 16.2 事件记录格式

```text
Event {
  seq: u64                    — 全局递增序号
  type, category, timestamp_ns
  pid, tid
  source: JAVA | LIBC | SYSCALL | DBI
  summary: string             — 列表展示用
  detail: object              — 详情页完整数据
  stacktrace: string[]
  correlation_id: optional     — 关联组
  related_dex: optional
  related_method: optional
  noise: bool                  — 是否被噪点过滤
}
```

### 16.3 事件浏览

- 实时事件流（WebSocket 推送）
- 按类型 / 时间 / 关键词 / 大小过滤
- 暂停 / 恢复采集
- 清空（内存 + 可选文件）
- 单条详情展开
- 批量导出

### 16.4 关联分析

- 网络请求 ↔ 加密调用（时间窗 + 线程）
- dex 加载 ↔ 类加载 ↔ 方法 hook 命中
- native dlopen ↔ 符号调用 ↔ crypto
- 用户自定义：事件 A 后 N 秒内的事件 B

---

## 17. N — Web 观测台

**功能**：浏览器访问的实时控制台，不是简单文件下载页。

### 17.1 页面结构

| 页面 | 功能 |
|------|------|
| **Dashboard** | 当前 session、进程信息、dex/so/hook/trace/dump 计数、健康状态 |
| **Dex Browser** | dex 列表、class/method/string/API 搜索、xref、smali/伪 Java |
| **Native Browser** | module 列表、symbols、imports/exports、strings、disasm、xref |
| **Hook Center** | 安装/管理 Java/native hook、模板库、自定义规则 |
| **Crypto Lab** | 算法观测台、Algorithm Session 详情、静态扫描报告 |
| **Network** | 请求/响应列表、详情、与 crypto 关联 |
| **File Monitor** | 文件事件流、路径搜索、噪点模式 |
| **Trace Viewer** | 调用树、时间线、指令列表、寄存器、过滤配置 |
| **Dump Center** | dump 任务、产物列表、下载、索引状态 |
| **Memory Explorer** | maps 浏览、region 读取、magic 扫描、dump |
| **Object Inspector** | 活体实例枚举、字段读取、堆内 String/byte[] 搜索、低风险 getter 调用（模块 T） |
| **Anti-Analysis Radar** | 目标的调试/root/签名/模拟器/完整性检测事件、检测手段清单、行为分叉标注（模块 V） |
| **Injection Center** | 注入后端选择、Zygisk/Gadget/模拟注入、agent 加载状态（模块 W） |
| **Compatibility & Health** | 抗干扰诊断报告、hook 后端可用性、自审计日志、诊断包导出（模块 S + P） |
| **MCP Center** | tool 列表、schema、调用历史、token 管理 |
| **Settings** | 访问控制、过滤规则、导出、诊断 |

### 17.2 通用 UI 能力

- 多 tab 架构
- 左右分栏 master-detail（列表 + 详情）
- 实时刷新 + 「N 条新事件」提示
- 关键字搜索、分类过滤、大小过滤
- 详情：Hex / HexDump / 调用栈 / 关联跳转
- 暂停 / 清空 / 导出
- 进程信息栏：包名、PID、UID、Android 版本、设备型号、内存
- 健康状态横幅（红色 = 有 hook 失败或服务异常）
- 离线断连提示

### 17.3 进程内浮层（可选）

继承 iOS 悬浮窗思路，Android 可选实现：

- 系统 overlay 浮窗 / 通知栏常驻
- 显示各分类事件计数
- 显示 adhd 连接状态与服务地址
- 点击跳转 Web 或展开简化日志

### 17.4 诊断与反馈

继承 iOS「审查日志」思路：

- 一键生成诊断报告：版本、目标 App、hook 健康、事件统计
- 复制 / 导出报告
- 不含业务敏感数据（key/明文）的默认报告
- 可选附带最近 N 条非敏感事件摘要

---

## 18. O — MCP Server

**功能**：供 AI 客户端（Cursor、Claude 等）程序化操控工作台。
**部署位置**：只在 `adhd`，不在目标进程。

### 18.1 传输

- MCP Streamable HTTP（POST/GET + SSE 流式）
- 与 HTTP API 共享 Service Layer
- Token 认证

### 18.2 Tool 列表

**进程管理**：

```text
process.list / attach / detach / info
```

**内存**：

```text
memory.maps / read / search / dump / scan_magic
```

**Dex**：

```text
dex.list / dump / search_string / search_method / search_api
dex.disassemble_method / xref / class_info
```

**Java Hook**：

```text
java.hook / unhook / list_hooks
java.trace_method / crypto_watch
```

**Native**：

```text
native.modules / symbols / disasm / disasm_function
native.trace_function / trace_range / trace_stop
```

**文件与系统**：

```text
file.watch_enable / events
syscall.watch_enable / events
```

**Dump**：

```text
dump.list / download / status
```

**Trace**：

```text
trace.start / stop / query / export
```

**事件**：

```text
events.query / get / correlate
stats.get / health.get
```

**反汇编**：

```text
disassemble.bytes / address / function
binary.search_string / search_symbol / imports / exports
```

**活体对象自省（T）**：

```text
object.find_instances / read_fields / search_heap / invoke_getter / get
```

**反分析行为观测（V）**：

```text
detect.watch_enable / events / summary
```

**抗干扰与注入（S / W）**：

```text
compat.probe / report
inject.backends / attach_zygisk / pack_gadget / status
```

> 实现状态（v4.49，**实现 + host 验收完成，真机验收待做**）：**"MCP 完全可操作"从口号变成可机检的不变式**。此前没人检查"MCP 能不能做到 agent 能做的每一件事"，审计（40 个 agent 命令分支 × MCP 导入图可达性）抓到两类真问题：`ping` 自 v0.2 起就是**死代码**（agent 实现了，Host 侧从没发过，于是判断 agent 存活只能靠一条真命令等超时）；另有三个能力只有 REST/验收脚本能到——设备文件浏览（`list_dir`/`read_file`）、hook 引擎自检（`gothook_selftest`）、通道完整性自检（`frame_echo`）。本轮把它们做成工具：`agent_ping`（5s 存活 + 往返延迟）、`engine_selftest`（`ok` = **判定**：GOT hook 必须 `fired` 且 RELRO 页保护 `protRestored`，否则报"这个构建可被检测"）、`protocol_selftest`（超大帧 + 越过 8192 老上限的尾部标记）、`fs_list` / `fs_read`（设备文件系统，1MB 上限、`truncated` 如实、二进制/超大文件用 `textOmitted` 说明原因、base64 需显式开启）。实现只写一份：`daemon/src/agent_probe.ts` 与 `daemon/src/fs_browse.ts` 同时服务 MCP 与 REST（`/api/agent/ping` 新增；`/api/hook/selftest` 状态码跟随判定；`/api/fs/*` 保留 v25 依赖的 `text` 与 `ok:false`）。不变式由 `tools/verify_v87_mcp_operability.sh` 机检：**每个 agent op 必须能从 MCP 导入图到达，除非在 `INTERNAL_OPS` 里写明理由**（当前 3 个只剩验收脚本使用：`crypto_probe`/`jni_probe`/`inline_crypto_test`；**2026-10-01 更新：这三条命令连同 `capture_start`/`capture_stop` 一起重排 —— 前者已删除，后者做成了正式 MCP 工具，`INTERNAL_OPS` 只剩 `capture_drain`**），同时反向检查"daemon 发过 agent 不认识的 op"与五个工具的 schema。16 条单测（延迟/时钟注入、三种引擎判定 + 命令失败不冤枉引擎、尾部丢失/截断/padLen 回显、kb 夹紧、空路径不发送、二进制/超大 omission、坏 base64 拒绝）+ 全量 host 门禁 28 PASS / 0 FAIL / 75 SKIP。

### 18.3 与 iOS 参考项目 MCP 的对照

iOS 已有：disassemble、analyze_function、list_imports、get_macho_info、query_events、correlate_request、get_event、get_stats、get_diag、dump_status 等。

Android 在此基础上增加：全套 dex 操作、Java hook、native trace、memory maps、classloader 信息等。

---

## 19. P — 自观测与审查日志

**功能**：fail-loud，失效必须可见（继承 iOS 思路）；工具能长期自维护、可复现、可反馈。

### 19.0 两条独立事件流（关键）

- **目标事件流**：采集到的目标 App 行为（crypto/network/file/dex/detection…）。
- **工具自审计流（AUDIT）**：Agent/adhd 自己干了什么。两套 ring buffer、两个视图、互不淹没。

**自审计内容**：每个 hook 安装成功/失败/跳过（原因，形成 hook 台账）、每次 dump 触发源与结果、每条 RPC、每次 Agent↔adhd 重连、ring buffer 溢出、流式 crypto 上下文丢失、trace 异常退出。

**一键诊断包**：版本 + 目标 App 指纹 + hook 健康台账 + 最近 N 条自审计（默认脱敏，不含 key/明文），用于维护、复盘、issue 复现。

### 19.1 监控项

- 每个 hook 模块安装结果：成功 / 失败 / 跳过（及原因）
- Agent ↔ adhd 连接状态
- ring buffer 溢出次数
- 事件落盘失败
- trace 任务异常退出
- adhd HTTP/MCP 服务状态
- 流式加密上下文丢失（update 无对应 init）

### 19.2 展示位置

- Web Dashboard 健康横幅
- 进程内浮层（若启用）
- Agent 日志 `[ADH/ERR]`
- `GET /api/health` / MCP `health.get`

### 19.3 行为原则

- 失效可见，但**不崩溃宿主 App**
- 废弃/不可用的 hook 目标（如已移除的 API）单独标记，不淹没真正告警
- 递归保护：hook 回调内不再触发同类 hook

---

## 20. Q — 安全与访问控制

**功能**：工具能 dump 内存、读文件、hook 任意 API，必须防止未授权访问。

### 20.1 网络监听

- 默认只监听 `127.0.0.1`
- 用户手动开启 LAN 访问
- 开启 LAN 后**必须**设置 token
- 可选：一次性访问码、IP 白名单
- **agent 命令口（TCP `8761`）的信任模型 —— 仍待决策**（2026-10-01 复核未变）：当前监听 `0.0.0.0` 且无鉴权。
  三条路各有代价：**加共享 token**（要改协议握手，Device Daemon 与验收同步改）、
  **只绑 `127.0.0.1`**（最小改动，依赖 `adb reverse`，但去掉"手机浏览器直连局域网"那条路）、
  **维持现状**（信任 LAN）。改动面跨 Device Daemon / Manager / adb reverse 三处，属产品决策，不是技术债。

### 20.2 危险操作

以下操作需二次确认：

- dump 全进程内存
- 开启 instruction 级 trace
- 读取其他 App 数据目录
- 导出含 key/明文的事件日志
- 关闭访问认证

### 20.3 敏感数据

- 事件详情含 key/明文时，Web UI 默认遮罩，点击才显示
- 导出可选脱敏模式
- MCP 默认不返回完整明文，需显式参数

---

## 21. R — 数据存储与导出

### 21.1 存储（adhd）

| 数据 | 存储方式 |
|------|----------|
| 事件流 | SQLite + 滚动文件归档 |
| dex 产物 | 文件系统 + sha256 索引 |
| so 产物 | 文件系统 + module 索引 |
| 索引 | SQLite / RocksDB |
| smali/伪Java 缓存 | 文件 + LRU |
| Capstone 反汇编缓存 | 文件 + LRU |
| trace 数据 | 分段文件 + 索引 |
| session 元数据 | SQLite |

### 21.2 Agent 内存策略

- ring buffer 保留最近 N 条事件
- 单条 blob 上限（如 64KB），防 OOM
- 大 payload 走共享内存 fd 直传 adhd，不在 Agent 堆积
- **钩子槽位写成产品语义（2026-10-01）**：单目标最多 **16 个并发 hook**（Java / native 各自独立计数）。
  这是**产品语义而不是裸数字**：超出时 **fail-loud** 拒绝安装并给出具体原因（`too many native hooks (max 16)`），
  **不静默排队、不静默丢弃老钩子**。当前占用由 `native_hook action:status` 给出（`slots.max/used/active/free/byMode`
  + 每个钩子的 `id`/module/symbol），要腾槽就是照这份清单选一个 `unhook`——
  **agent 目前不主动"建议卸哪个"**，能给的是这份可直接执行的清单。
  `native_hook_all` 的批量安装按剩余槽位截断并回报 `limitReason`/`effectiveLimit`/`slotLimited`；
  0 个空槽时整批失败而不是逐个失败。

### 21.3 导出

- 事件日志：JSON / JSONL / CSV
- 审查/诊断报告：文本 / JSON
- dump 产物：单文件 / zip 批量
- trace：JSON / 自定义格式
- dex 索引：可导出为独立数据库

---

## 22. 沙盒测试 App 需求

**功能**：不是 Hello World，而是覆盖全部模块的确定性测试宿主。

### 22.1 Activity 划分

| Activity | 覆盖模块 |
|----------|----------|
| `JavaCryptoActivity` | MD5, SHA-256, HMAC-SHA256, AES/CBC, AES/GCM, RSA sign/verify |
| `FileIOActivity` | FileInputStream, FileOutputStream, RandomAccessFile, SharedPreferences, SQLite |
| `DynamicDexActivity` | DexClassLoader, PathClassLoader, InMemoryDexClassLoader |
| `NativeActivity` | dlopen, dlsym, native AES mock, native file R/W, call chain |
| `NetworkActivity` | HttpURLConnection, OkHttp, HTTPS 请求 |
| `DeviceInfoActivity` | TelephonyManager, Settings, Build 字段读取 |
| `AntiDumpMockActivity` | mmap dex-like buffer, fake header, runtime restore mock |
| `TraceActivity` | hot loop, branch, nested calls, memory R/W |
| `AntiDebugMockActivity` | ptrace 自附加、/proc/self/status TracerPid、maps 自扫描、hook 序言校验 — 验证模块 S 存活 + 模块 V 观测 |
| `PackerMockActivity` | 一/二代抽取壳、InMemoryDex、字符串解密 — 验证 L.6/L.7 |
| `NativeCryptoStrippedActivity` | strip 符号的 native AES — 验证 H.4 常量扫描 + inline hook |
| `ObfuscatedFlowActivity` | 混淆 + 加密 + 网络全链路 — 端到端验收 H+G+M |
| `HeapObjectActivity` | 已知字段值的活体对象 — 验证 T 实例枚举与字段读取 |
| `DetectionActivity` | 显式执行 root/签名/模拟器/完整性检测 — 验证 V 检测清单命中 |

### 22.2 自动化触发

- ADB intent 触发各 Activity 的指定操作
- 每个操作有**预期输出**（如 AES key、密文 hash）
- CI device test 可自动断言 hook 命中与数据正确性

### 22.3 验证标准

```text
每个 hook 模板        → 可自动验证命中
每个 dump 类型        → hash 可对照
每个 trace 模式       → 可回放调用树
每个搜索类型          → 可命中已知样本
每个 MCP tool         → 有对应测试用例
```

**三条口径（2026-10-01 生效）**：

- **SKIP 语义分层**：**可选依赖**缺失（QBDI 库在但 VM 起不来、Gadget 资产没 fetch、grep 不到的 gradle/工具链）
  = `SKIP:optional-dependency`；**产品路径**缺失（agent 连不上、能力装不上、断言不成立）= `FAIL`。
  判据是"换一台达标的机器/环境它会不会必然通过"——会，就是前置缺失；不会，就是产品问题。
  理由：QBDI 在本机 ROM 上起不来曾被算成红，读起来像产品坏了。
- **验证必须写清"扫谁"**：任何扫描类断言都要写明作用域（哪一段映射、哪个模块、哪个 tag）。
  沙盒夹具自带 log tag 与模块名，扫"整个进程"必然把夹具自己的痕迹算进结果——v88 已收窄到
  agent 自己的 `r--p`/`r-xp` 段，同类断言照此办理。
- **无样本的功能不进排期**：cdex/041 这类必须以真实样本为前提的能力，没有样本就不立项、不排期、
  不用合成样本"证明"实现（2026-10-01 决议）。

---

## 23. 能力边界总表

### 23.1 能稳定做到

- 枚举 `/proc/self/maps`
- dex / so / memory dump
- 加密 API 运行时观测（Java + OpenSSL）
- 文件读写观测（Java + libc，带来源标注）
- 网络请求/响应捕获（主流框架）
- 指定范围 native trace（QBDI）
- Capstone 反汇编与二进制搜索
- dex 索引、字符串/API 搜索、smali、xref
- Web + MCP 远程控制
- 运行时 dex 捕获与脱壳辅助
- ART 结构级 dex 捕获（不依赖 magic/路径）
- 活体 Java 对象枚举与字段读取（模块 T）
- 目标反分析检测的观测（调试/root/签名/模拟器，模块 V）
- Zygisk + Gadget + 模拟注入（模块 W）
- 明文边界加密观测（绕过加密与 pinning）

### 23.2 不能承诺 100%

- 所有加固壳还原成 Java 源码
- 所有 native 函数都能 hook（direct syscall、静态链接、内联封装）
- 全进程 instruction trace 不影响性能
- stripped so 的函数边界全部准确
- VMP 壳语义还原
- 所有 Android 版本 ART 内部结构一致
- 所有 HTTPS 明文（系统 TLS 栈不一定命中）
- 目标在 Agent 注入前已缓存的函数指针

- 对抗所有商用加固的注入存活（S 尽力而为，先诊断后韧性，不赌全胜）

### 23.3 推荐产品描述

```text
通用 Android 运行时逆向分析工具：运行时观测、按需 trace、
dex/so/memory dump、ART 结构级脱壳辅助、活体对象自省、
明文边界加密观测、反分析行为观测、Java/native 分析工作流；
Zygisk / Gadget 多注入路径。
```

---

## 24. 功能原则复述

```text
按需反编译  →  看懂代码（搜什么看什么）
trace       →  看真实执行（过滤后观测）
dump        →  拿运行时真实内容
脱壳辅助    →  把隐藏代码变成可索引 dex
关联分析    →  把网络/加密/加载串成链路
```

```text
libadh_agent.so  →  采集与执行，越轻越好
adhd             →  分析与服务，越强越好
Web UI           →  观测与交互，实时可见
MCP              →  AI 可编程操控，与 HTTP 同源
```

---

## 25. 参考项目速查

| 项目 | 地址 | 关系 |
|------|------|------|
| ios-decrypt-helper | https://github.com/taisuii/ios-decrypt-helper | 产品形态与工程思路参考；Android 版全面扩展 |
| Capstone | https://github.com/capstone-engine/capstone | 反汇编引擎 |
| QBDI | https://github.com/QBDI/QBDI | Native DBI trace |
| MCP | https://modelcontextprotocol.io | AI 操控协议 |
| Frida Gadget | https://frida.re | 非 root 注入 so |
| Zygisk (Magisk) | https://github.com/topjohnwu/Magisk | root early-inject 后端 |

---

## 26. S — 目标兼容性与抗干扰采集

**目标**：授权取证环境中，提高 Agent 在主动反调试/反注入运行时下的**存活能力、采集稳定性与故障定位能力**。

> 实现状态（v4.56，**实现 + host 验收完成，真机验收待做**）：**字段事件可归因 + JNIEnv 字段摘要**。v4.55 的访问事件只有 `field=0x..`，读不出字段名；现在 `GetFieldID`/`GetStaticFieldID` 的事件会带上它们交出去的 id（`Class#name:sig -> 0x..`），新增的 `jniFieldDigest`（MCP `jni_field_digest` + `POST /api/jni/field_digest`）用 id→名字表把访问按 (accessor, field) 聚合成"哪个字段被读写了几次、最后值是什么、哪些线程"，未解析的 id 保持原始指针并单独计数（不猜），空窗口明确提示需要先 hook 字段槽位；drain 走共享 `drainSession`。

> 实现状态（v4.70，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 数组区域读写全族入表**。`Get<Type>ArrayRegion`（Java 数组 → native 缓冲）与 `Set<Type>ArrayRegion`（native → Java 数组）是批量数据通道，脱壳/校验/协议解析都经过它们，写回事件还是"目标改了数组内容"的直接证据。新增 14 槽（`Boolean/Char/Short/Int/Long/Float/Double` 各一对；ABI 里没有 `SetObjectArrayRegion`，`Byte` 那一对在 v4.19 就已覆盖），事件统一为 `array=0x.. start=N len=N first=[…]`（最多 4 个元素的有界预览）。失败即不采信：调用后仍有挂起异常时**不读缓冲区**，事件写 `<call failed>` 且 `ok=false`。签名由 14 条 `_Static_assert` 编译期钉死（`Set*` 的 `const <T> *` 形参由此暴露）、索引 199–214 由 `tools/verify_v90_jni_table_abi.sh` 对 NDK `jni.h` 机检；该脚本的覆盖口径同时补齐为「59 固定 + 36 字段访问器 + 21 族 ×3 = 158 表项」，与 spec 索引数一致，覆盖率 **158/229 = 69%**，门禁下限 158（只升不降）。同机制在 v4.67–v4.69 已补入异常流 + `GetJavaVM`、引用生命周期、类型自省/monitor/弱引用/`GetVersion`（覆盖率 115 → 125 → 133 → 144 → 158）。

> 实现状态（v4.71，**实现 + host 构建通过，真机验收待做**）：数组区域族的**设备证据路径**（v4.63→v4.64 的老规矩）。沙盒 native 夹具 `Detection.jniArrayRegionProbe` 让七种类型各"写回读"一遍固定内容，全部往返成功才返回 `0xAD707F`；`tools/verify_v91_jni_env_fields.sh` 的 `(3g)` 段逐个安装 14 个表项、触发夹具、要求**每个表项自己的事件**里 `start=0 len=4 first=[…]` 与夹具内容精确匹配（Get/Set 两侧都要）、再逐个卸载，`pass` 表达式纳入 `arrayProbeOk`。夹具与声明已在 host 构建通过（`build_detect.sh` + `:app:assembleDebug`；`.so` 导出符号与 `Detection.class` 声明均已核对），真机跑 v91 即出证据。

> 实现状态（v4.72，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 数组元素族（指针式 pin/写回）入表**。`Get<Type>ArrayElements` 把元素指针（真指针或副本，`isCopy` 标明）交给 native，`Release<Type>ArrayElements` 是写入落地处，`mode` 决定落地方式（0 copyback / 1 commit / 2 abort）。新增 14 槽（`Boolean/Char/Short/Int/Long/Float/Double` 各一对；`Byte` 那对 v4.19 已有），事件 `array=.. len=.. elements=.. isCopy=.. first=[…]`，Release 事件额外带 `mode=<n>(copyback|commit|abort)`。两条硬约束：长度只用 `GetArrayLength` 且**仅在不处于挂起异常时**取（有挂起异常再调 JNI 非法，CheckJNI 会 abort），预览按取回长度截断到 4 个元素；Release 预览在调用原函数**之前**读，`abort` 事件显示的正是被丢弃的值。`Byte` 那对保持 v4.19 的 `hex=` 文案（v59/v63 设备断言钉死），新类型用 `first=[…]`，差异是刻意的。签名由 14 条 `_Static_assert` 钉死、索引 183–198 由 v90 机检，覆盖率 **172/229 = 75%**，门禁下限 172。

> 实现状态（v4.73，**实现 + host 验收完成**）：v4.70/v4.71 的**评审收口**（1×P1 + 5×P2，全部落在"验证脚本不许骗人"这一侧）。① v91 的 `fail()`/`skip()` 出口现在统一卸载（`installedSlots` + `installSlot`/`uninstallSlot`），失败时不再把改写的 JNIEnv 表槽位留给后续脚本；② 数组 region wrapper 对 `(arr, 0, 0, NULL)` 这类零长度无缓冲调用不再误报 `ok=false`；③ 数组区域段补能力前置检查——旧 agent（status 里没有这些槽位）或旧 APK（夹具方法不存在）走 SKIP，只有"夹具跑通但返回码不对"才 FAIL；④ 该段事件窗口加印 capture health（dropped/backlog/complete），缺事件时能直接区分"环被冲掉"；⑤ 夹具 `jniArrayRegionProbe` 每段分配失败立即清挂起异常并返回，不再带着异常继续调 JNI；⑥ v90 的字段访问器清单门禁从"非空"改为"恰好 36 条"。MCP `jni_env_hook` 描述同步补齐到当前能力面与通配写法。

> 实现状态（v4.74，**实现 + host 构建通过，真机验收待做**）：数组元素族的**设备证据路径**。沙盒夹具 `Detection.jniArrayElementsProbe` 对七种类型各跑一遍「Set 种子 → `Get<Type>ArrayElements` → 改第 0 个元素 → `Release(...,0)` → `Get<Type>ArrayRegion` 回读」，回读用 `memcmp` 与"应该变成的值"逐字节比对（不是"不等于旧值就算过"）；另加一轮 `int[]` + `JNI_ABORT`，回读必须仍是旧值——**hook 不得把 abort 变成 commit**。全过返回 `0xAD80FF`。v91 新增 `(3h)` 段：能力前置（旧 agent → SKIP）、夹具缺失（旧 APK → SKIP）、逐条安装 14 个表项、断言每个表项自己的事件形状（`len`/`elements`/`isCopy` 或 `mode`/`first`）、copyback 预览逐类型精确匹配、abort 轮必须出现 `mode=2(abort)` 且预览带着被丢弃的值、逐条卸载；夹具与声明已 host 构建通过（`.so` 导出符号与 `Detection.class` 均已核对）。

> 实现状态（v4.75，**实现 + host 验收完成，真机验收待做**）：**数组创建 / 长度 / 对象数组 / `AllocObject` 入表**。新增 13 槽：`NewBooleanArray`…`NewDoubleArray`（8 个，事件 `len=N -> 0x..`）、`NewObjectArray`（带元素类名 `elem=Class`）、`GetArrayLength`（`array=.. len=N`）、`GetObjectArrayElement`（`array=.. index=N -> 0x..`，**NULL 元素合法**故 `ok` 跟异常状态走、文案区分 `(null element)` 与 `<call failed>`）、`SetObjectArrayElement`（`array=.. index=N value=0x..`，`ArrayStoreException` 记为失败）、`AllocObject`（`class=Class -> 0x..`，不开构造器的分配）。`New*Array`/`AllocObject` 的 `ok` 取 `!failed && result != NULL`，不把"没造出来"记成成功。签名由 13 条 `_Static_assert` 钉死、索引 27/171–182 由 v90 机检，覆盖率 **185/229 = 81%**，门禁下限 185；剩余盲区（`CallNonvirtual*` 30、字符串 6、反射桥 4、`FatalError`/`UnregisterNatives`/`ExceptionCheck`）由 v90 的未覆盖名单跟踪。

> 实现状态（v4.76，**实现 + host 验收完成，真机验收待做**）：**`CallNonvirtual*` 三形态全族 + 表/枚举一致性硬约束**。新增 30 槽（`CallNonvirtual{Object,Boolean,Byte,Char,Short,Int,Long,Float,Double}Method` + `CallNonvirtualVoidMethod`，各 varargs/V/A），事件在成员标签后追加 `via=<class>`（调用方指定的实现类——非虚调用的关键信息）。同时修掉两个真实缺陷：① **潜伏 bug**：`ENV_SLOT_CallStaticVoidMethod_end` 作为"算术锚点"仍会占用一个枚举值，使 36 个字段访问器的枚举值自 v4.55 起比其在 `g_env_hooks[]` 中的位置大 1；安装路径"按名字取表位置 → 按枚举值 switch 取表项"因此错位：**第一个字段槽 `GetObjectField` 落 `default` 被以 `table entry unavailable` 拒绝，其余 35 个静默绑定到"上一个字段"的表项与 wrapper**（请求 `GetIntField` 实际挂的是 `GetShortField` 的槽位与 wrapper），事件名却写成请求的字段——被点名字段的真实表项未被动过、其调用不会产生事件，即字段钩子、`setValue` 改写与字段摘要从未真正生效。v4.81 改为把最后家族的 V/A 写成真枚举，字段块落回 179–214 与表一一对应，并新增组基址断言（见 v4.81）；② Call* 族 varargs 形态缺 `g_env_hook_in_ours` 检查（V/A 有），agent 自身解析类名时的内部 `CallObjectMethod` 会被记成目标事件。安全网：`g_env_hooks[]` 改为不定长数组并新增两条编译期不变式（表长 == `ENV_HOOK_MAX`；最后一个字段槽 == `ENV_HOOK_MAX-1`），把枚举/表漂移从静默截断变成一行编译错误。索引 64–93 由 v90 机检，覆盖率 **215/229 = 94%**，门禁下限 215；剩余 14 项见 v90 未覆盖名单。

> 实现状态（v4.77–v4.79，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 表收尾**。v4.77 补字符串族 6 槽（`NewString` 带 `len/text` 预览、`GetStringLength`/`GetStringUTFLength`、`ReleaseStringUTFChars`、`GetStringCritical`/`ReleaseStringCritical`——critical 对**不在 critical 区内调用任何 JNI 函数**，用"NULL 即失败"代替 `ExceptionCheck`）；v4.78 补反射桥与注销侧 5 槽（`FromReflectedMethod`/`FromReflectedField` 输出 `mid`/`fid` 供 host 与 ID 查询事件连接、`ToReflectedMethod`/`ToReflectedField` 带类名与 static 标志、`UnregisterNatives`）；v4.79 补最后 2 槽：`FatalError`（事件先写、原函数永不返回，属 best effort）与 `ExceptionCheck`（目标自己的检查记 `pending=true/false`；**agent 自身所有异常检查改走 `adh_jni_exception_check()` 直调已保存的 original**（不仅本文件：另外 8 个模块共 52 处调用一并切换，声明在 `jni_env_hooks.h`），既不进表也不误记）。v90 的覆盖率口径随之封口：**228/229 表项可挂**，唯一未挂的 `RegisterNatives` 由 `jni_hooks.c` 的入口 inline hook 覆盖，脚本显式列它为 `COVERED_ELSEWHERE` 并对"未挂且未分类"的表项报 FAIL；索引逐条机检（`checked 228 indices`），下限 228。

> 实现状态（v4.81，**实现 + host 验收完成**）：**评审更正 + 让"整体平移"编译期失败**。① 事实更正（subagent 独立复算）：字段错位的症状不是"全部被拒"——只有首个字段落 `default` 被拒，其余 35 个静默绑定到上一个字段的表项与 wrapper（事件名却是请求的名字）；把这一句写对，比把 bug 说轻更重要。② 归因更正：总数断言抓不住整体平移（定长数组下恒真；错位下末字段断言也成立），真正报错的是中间态的 `-Warray-bounds`。③ 新增组基址断言（`CallObjectMethod == ENV_FIXED_SLOTS`、`CallNonvirtualObjectMethod == CallStaticVoidMethod + 3`、`GetObjectField == CallNonvirtualVoidMethod + 3`、`SetStaticDoubleField == GetObjectField + 35`），整体平移在此编译失败。④ 最后家族的 V/A 改为真枚举（删除算术别名）。⑤ 补齐 Call*/CallNonvirtual 家族的签名证明：31 家族 × 3 形态 = 93 条 `_Static_assert`（此前为 0，wrapper 是强转 `void*` 装表的，签名错误只会在目标调用时炸）。
> 实现状态（v4.82，**实现 + host 验收完成，真机待做**）：**固定槽位单一来源 + 运行期布局自检**。① 固定槽位的枚举值与可安装名字表此前是两份手写清单（v90 只查"名字↔spec index"，查不出顺序差异），现改为一份 `ADH_FIXED_SLOT_LIST` 同时展开枚举、名字表与 `env_slot_name()` 期望名；**同时修掉 v4.75 引入的错位**：那 13 个新槽位在枚举与列表里的插入位置不同，导致 `GetArrayLength`/`NewObjectArray`/`GetObjectArrayElement`/`SetObjectArrayElement`/`AllocObject` **五个**槽位会命中隔壁 case（与字段族同类的静默错位）。② 新增运行期自检 `env_hook_layout_ok()`：逐位比较"枚举名 vs 表内名"，不一致即**拒绝 install/uninstall**（status 仍放行并在回复里报 `layout`/`layoutError`）并报出第 N 位与两个名字（结果缓存）。③ v90 改为解析新列表并断言固定槽位恰为 99 条。

> 实现状态（v4.83，**实现 + host 构建通过，真机验收待做**）：**v4.75–v4.79 那 56 个槽位的设备证据路径**。沙盒夹具 `Detection.jniFamilyProbe` 用确定性取值走一遍：八种 `New<Type>Array` + `GetArrayLength`、`NewObjectArray` + 对象数组元素读写（含 NULL 元素合法）、`AllocObject`、`CallNonvirtualObjectMethod` 三种形态（新增 `JniNonvirtualBase/Child`，非虚调用必须返回父类实现 `base:t`——hook 若破坏派发立即暴露）、反射桥（`FromReflected*` 的 id 必须等于 `GetMethodID`/`GetFieldID` 的结果，`ToReflected*` 回来的名字必须正确）、字符串族（`NewString`/`GetStringLength`/`GetStringUTFLength`/`GetStringCritical`/`ReleaseStringCritical`/`ReleaseStringUTFChars`）与 `ExceptionCheck`；全过返回 `0xAD91FF`。`tools/verify_v91_jni_env_fields.sh` 的 `(3j)` 段安装 29 个槽位、触发夹具、逐条断言事件内容（`via=`、`(null element)`、`static=0 -> 0x`、`text="ADH42"`、`pending=false` 等）、再逐个卸载；`FatalError`/`UnregisterNatives` 只验证装卸（不能对活进程触发）。边界如实记录：CallNonvirtual 只触发 Object 形态，其余 27 个返回类型靠同一套宏生成 + 93 条签名断言覆盖。

> 实现状态（v4.84，**实现 + host 验收完成**）：**v90 的接线与发事件门禁**。① 接线：每个固定槽位必须在 `env_hook_slot()` 与 `env_hook_wrapper()` 两个 switch 里各有 case，字段访问器与全部 Call 家族要求相应宏展开存在——名字在列表里却没有 case 的错（真机才 fail-loud）从此在 host 门禁就失败（负对照：删掉 `FatalError` 的 slot case → `FAIL fixed slots with no dispatch case`）。② 发事件：每个 wrapper 生成宏与手写 wrapper 必须含 `env_note(`/`call_emit(`，防止"装了但从不发事件"的空壳槽位（当前 0 个）。

> 实现状态（v4.85，**实现 + host 验收完成，真机待做**）：**归因卫生**。`adh_jni_ours_enter()/adh_jni_ours_leave()`（可嵌套，保存/恢复）内建到 `jni.c` 三个 helper（`adh_jni_app_class_loader`/`adh_jni_class_name`/`adh_jni_load_app_class`）内部，使其**无论被谁调用**（wrapper、RegisterNatives 钩子回调、`java_call`/`object_inspect`/`java_trace` 等命令路径）产生的 JNI 查找都不再被记成目标事件——挂了 `FindClass`/`GetMethodID`/`CallObjectMethod` 等槽位后，仪表自身的类名解析原本会污染事件流。同时修掉 `adh_jni_load_app_class` 把 `FindClass` 结果未判空就交给 `GetMethodID` 的崩溃隐患（失败返回 NULL）。边界如实记录：agent 主动触发的那一次调用本身仍作为普通事件出现、暂无 origin 标记。

> 实现状态（v4.86，**实现 + host 验收完成，真机待做**）：**第四轮评审收口**。① **P1**：`adh_jni_exception_check()` 未覆盖两个 C++ 模块（`java_lsplant.cpp` 17 处、`java_enum.cpp` 11 处，且未 include 头文件；抑制标志是 C 侧 file-static）——现两文件均 include `jni_env_hooks.h` 并全部改走 helper；同时新增 `adh_jni_exception_clear()`（`ExceptionClear` 同为可挂槽位）并切换 C++ 侧 16+8 处，ADH 自身异常流量才真正不进事件流。② **P2**：`GetStringChars`/`GetStringCritical` 预览不再依赖"NUL 终止"假设——先取 `GetStringLength`（critical 区之外、带守卫）再按真实长度截断；固定槽的 dispatch case 改为列表驱动（消除"case 与 wrapper 配错但签名相同"的静默错位），v90 wiring 门禁改为校验宏体的名字↔字段/wrapper 配对（带负对照）；文档口径更正：家族 31 个/签名断言 93 条、布局自检拒绝 install/uninstall（status 放行并报 `layout`）、v4.75 受影响槽位 5 个（含 `AllocObject`）。

> 实现状态（v4.87，**实现 + host 验收完成**）：**设备脚本的 HTTP 路由门禁**（`tools/verify_v94_device_script_routes.sh`，已接入 `verify_all.sh`）。daemon 声明 88 条 `/api/` 路由、验收脚本引用 82 条，逐条比对"脚本引用的每个 `/api/...` 都必须有路由服务"（前缀路由按前缀匹配；`/` 这种静态兜底路由被排除，否则任何路径都会"有服务"）；注释里的路径先剔除，避免把散文当端点。负对照：注入一条不存在的路由引用即 FAIL。同时报告"没有任何验收脚本引用的 api 路由"（当前 5 条：`/api/native/stealth`、`/api/native/hook_all`、`/api/native/backtrace`、`/api/file/probe`、`/api/skills`），只作信息提示。门禁规模变为 **116 脚本 = 32 host + 84 device**。
> 实现状态（v4.88，**实现 + host 验收完成**）：**"wrapper 只能谈自己的槽位"门禁**。手写 wrapper 体内出现的每个 `ENV_SLOT_X` 必须与其自身名字一致，宏生成的 wrapper 体内不得出现字面量 `ENV_SLOT_<名字>`（槽位只能来自参数）——这堵住了"签名/接线/布局全对、但函数体写错槽位常量"的最后一类静默错误（此前只有真机证据段能发现）。负对照：把 `GetVersion_wrapper` 的 `env_note` 指向 `ENV_SLOT_FindClass` 即 FAIL。
> 实现状态（v4.89，**实现 + host 验收完成，真机待做**）：**第五轮评审收口**。① `ExceptionClear` 的 C 侧归因缺口：60 处直接走表的调用（8 个 C 模块 52 处 + 本文件 7 处，helper 内部 1 处回退保留）改走 `adh_jni_exception_clear()`；vendored LSPlant 的两处（`art_method.hpp`/`jni_helper.hpp`）由 `tools/fetch_lsplant.sh` 新增的第 4 号补丁处理（注入声明 + 替换调用 + 未生效即退出），vendor 树 gitignored、补丁随 fetch 重放。② 家门禁两处假阴性：家族 base 形态配对正则改为分号锚定（原 `\b` 会匹配 `name##V`）并补 `&name##_wrapper;` 检查；安装路径新增 wrapper 指针判空（`adh_swap_pointer_in_ro_page` 接受 NULL，缺 case 时会把 NULL 写进 ART 表）。③ 预览长度预查询加 `env_budget_left()` 门；重新激活校验表项仍指向本 wrapper；v91 `(3i)` 断言 `layout == "ok"`。④ 口径更正：最后一处 "84 条" → 93，旧名 `env_exception_pending` → `adh_jni_exception_check`。
> 实现状态（v4.90，**实现 + host 语法/门禁通过，真机验收待做**）：**`file_probe` 的设备证据路径**（v4.87 路由审计发现 5 条无人引用的 api 路由，其中 4 条的能力由 MCP 面覆盖，`file_probe` 是唯一真正没有验收路径的）。`verify_v87_device_probe_fs.sh` 新增第 5 段：断言五个符号都解析出非零地址、`modules` 非空且均为 `.so`、至少一个模块持有其中之一（按符号打印命中数；不断言具体模块，因为 import 结构随 ROM 变化）。
> 实现状态（v4.91，**实现 + host 验收完成，真机待做**）：**能力面的"如实上报"收口**（第七轮评审的 3 条 P1）。① 内存链路：agent `read` 带 `requested/short`；daemon `readMemEx` 提供 `complete/requested/read`，`reconstructSo` 逐 PT_LOAD 校验整段读取（短读抛错），`dumpRegion` 校验 size 并在 meta 里带 `requestedSize/complete`，三个出口原样上报；`/api/module/dump` 的模块名匹配"精确 → 唯一宽松 → 歧义 409"。② syscall digest 的 `counters {hits, throttled, emitted, source}`：以 agent `native_hook` status 为权威，status 不可用时退回事件增量并标注来源。③ QBDI trace 的 `seen/cap/truncated`（`count` 恒等于携带条数）+ 生命周期调用全检查；daemon `traceCompleteness()` 把截断写成 digest note。

> 实现状态（v4.92，**实现 + host 验收完成，真机待做**）：**第七轮评审剩余 P2 收口**。① `native_call`：地址字符串严格要求整串被消费（`0x1234zz` 不再被当成 `0x1234`），调用后检查挂起 Java 异常并回 `ok:false, pendingException:true`（值仍回传但标明不可信）。② 模块名解析统一到 `resolveModule()`（精确 → 唯一后缀 → 唯一包含 → 歧义抛错），`liveDisasm`/`syscall_watch`/`/api/module/dump` 共用（后者歧义回 409 + candidates）；`liveDisasm` 拒绝非正/NaN size 与越界 offset。③ automation 要求设备回包 `ok === true`（省略 `ok` 的半截帧不再按成功 resolve）。④ `phone_task`/`phone_skill run` 新增总时限 `timeoutMs`（默认 120s，夹紧 5s–10min），每步/每次重试按剩余预算夹紧，耗尽返回 `timedOut:true` 与停在哪一步。⑤ `/api/module/dump` 的 meta 标注"内存重组、非磁盘复刻"。边界（未修，如实记录）：原始地址路径的 `native_call` 不做存活性校验且无调用超时。

> 实现状态（v4.93，**实现 + host 验收完成**）：**daemon 侧事件环淘汰入 digest 口径**。`state.ts` 新增 `captureStoreStats()`（累计 pushed / evicted、当前 retained / retain、最老保留记录时间戳），`syscall_digest` 在 note 中把"agent 环丢包"与"daemon 存储淘汰"分开报告，并且只在请求窗口确实受影响时提示（无窗口时=全部保留记录；`sinceMs` 早于最老保留记录时点名）。新单测 `capture_store.test.ts` 覆盖淘汰计数与还原。

> 实现状态（v4.94，**实现 + host 验收完成，真机待做**）：**`native_call` 原始地址的活体校验**。新增纯函数 `classifyAddress()`（mapped/executable/path，end 不包含、非法输入不映射），`native_call` 处理原始 `addr` 时先取 maps：未映射或不可执行一律 `ok:false` 并说明原因（此前会直接跳进去崩在目标里）；`module+symbol` 路径本就每次重解析 maps。仍未做：调用本身没有超时（daemon 放弃等待但 agent 会阻塞在被调函数里，需 agent 侧看门狗）。

> 实现状态（v4.95，**实现 + host 构建/门禁通过，真机验收待做**）：**`native_call` 看门狗**。目标调用改在独立线程执行，命令线程以 15s（早于 host 的 20s）`pthread_cond_timedwait` 等待；超时回 `ok:false, timedOut:true, watchdogSeconds:15`（调用仍在目标里跑、结果不可用、会话保持可用），成功回带 `timedOut:false`。挂起 Java 异常的检查移入 worker（异常是 per-thread 的）；超时路径刻意让 job 泄漏以避免 use-after-free。沙盒夹具 `adh_slow_leaf()` + `verify_v49` 新段断言 `timedOut` 与"随后的 ping 仍然成功"。worker 无法被取消（等目标函数自己返回）——本版保证的是会话可用与如实上报。**代价（v5.00 补齐口径）**：超时后再发起一次 `native_call`，目标里可能同时有两个调用在跑；未回收的 worker 每个占一个线程栈，v5.00 起 agent 用 `ADH_NATIVE_CALL_MAX_OUTSTANDING=4` 计数，超过就拒绝新调用（fail-loud），而不是把目标慢慢塞满线程。

> 实现状态（v4.96，**实现 + host 验收完成**）：**第八轮评审收口**。① dump 的 dedup 按**本次**请求重算 `size/requestedSize/complete`（此前命中旧工件会借旧 meta，把短读又变成"完整"）。② `phone_task`/`phone_skill` 的超时与重试解析全部改走 NaN-safe 的 `finiteNumber()`（`Number('abc')` 曾让 deadline 失效并让 wait 无限轮询；MCP 层不做 schema 校验）。③ syscall `counters` 增加 `basis`（自安装累计 / 窗口下界）并写进 note；`qbdi_trace` 补回复缓冲过小的早退；`phone_task` 在预算耗尽时回报 `timedOut:true` 而不是普通步骤失败；`captureStoreStats(session)` 支持按 session 统计，淘汰说明抽成 `storeLossNote()` 供 syscall/java/field 三个 digest 共用。

> 实现状态（v4.97，**实现 + host 验收完成**）：**`native_call` 地址守卫单一来源**。v4.94 只给 MCP handler 加了活体校验，REST 路由（设备脚本走的路径）仍是透传；现抽出共享 `assertCallableAddress(sid, addr)`（空地址放行给 module+symbol；否则取 maps 判"未映射/不可执行"）供 MCP 与 REST 共用，两端不再分叉。

> 口径修订（**已于 2026-10-01 确认并并入正文**，不再留第二份计划）：① 去特征对手面 → §26.3；
> ② 问题对齐（不做 Frida 功能表对齐）→ §1.3；③ SKIP 语义分层 + ⑤ 验证写清"扫谁" + ④ 无样本不进排期 → §22.3；
> ⑥ 钩子槽位写成产品语义 → §21.2；⑦ agent 命令口信任模型 → §20.1（**仍待决策**，是本节唯一未决项）。
>
> 实现状态（v5.03，**实现 + host 验收完成，真机待做**）：**第十一轮评审收口（1 条 P1 + 7 条 P2）**。① 原始 `map_list` 读不全时**抛错**（此前会带着读到的条目继续重建并报 `mapRebuilt:true`，新 map 静默缺类型）；② `verifyDexLayout` 增加 `file_size` 与 `data_off+data_size` 一致性，并要求 header 中非零的固定区（string/type/proto/field/method/class_def + string_data）以及所有被引用的 class_data/code_item 区都出现在 map 里；③ 重复 midx 的 capture 回报 `duplicateCaptures`；④ `/api/dex/rebuild`、`/api/dex/recover` 与 MCP `dex_recover` 的回复补齐 `mapRebuilt/mapEntries/relocated*/unmatchedCaptures/skippedCaptures/duplicateCaptures/layout`；⑤ 5 个内联 class_data 循环加 `p > buf.length` 边界（恶意 `dm/vm` 曾可让请求线程空转约 60s/类）；⑥ REST 的 `native_call`/`native_hook` 也把原始 addr 交给守卫（`addr:0` 的回退此前只在 MCP 生效）；⑦ `num.ts:cursorNumber()` 统一 cursor 语义（null/''/[] 与非有限值都视为未给，避免 `Number(null)===0` 把时间窗变成全量）。
>
> 实现状态（v5.02，**实现 + host 验收完成，真机待做**）：**第十轮评审收口（1 条 P1 + 9 条 P2）**。① `/api/dex/method_code` 的 `recovered` 只数真正走得通的 item，`empty = count - recovered - unresolvable`（三者之和恒等于 `count`）；② `extractMethodCode` 先校验 item 再读 header——越界 `code_off` 不再把"每条方法各自如实报告"变成 500；③ 新增 `codeItemEnd()`（只走不拷贝 hex）供覆盖率与布局自检使用；④ LEB 解码补 `p < buf.length` 边界与 EOF 哨兵；⑤ `missingTotal` 与封顶 5000 的 `missing` 列表分离，`stillMissing` 用它计算；⑥ rebuild 返回 `skippedCaptures`（空 capture 不再静默丢弃）；⑦ agent 侧 `native_call` 的 outstanding 计数改为先计数后创建（create 失败回退）；⑧ phone 面最后两处 NaN 走 `finiteNumber`，`phone_wait` 的 cursor 非数字视为未给；⑨ `addr:0` 视为未给地址，回退 module+symbol；⑩ `/api/dex/recover` 的 rebuild 抛错映射 422。
>
> 实现状态（v5.01，**实现 + host 验收完成，真机待做**）：**WS-E 第二片：重建 dex 的 map_list**。重建从"追加到旧 map 之后"改为：把**每个被引用**的 code_item（4 字节对齐）与 class_data item 写到文件末尾，追加一份新的 map_list 列出这两个区域，并把每个 `class_def.class_data_off`、每个方法 `code_off` 指到新副本（旧副本成为不再被 map 列出的 slack，文件随之变大：9,604,000 → 13,215,556 B）。新增 `readClassDataItem()` 与 `verifyDexLayout()`：map 唯一且有序、两个区域逐条走得通、class_def 与 code_off 都落在被列出的条目上、checksum/signature 与字节一致；重建回复带 `layout{ok,errors,mapEntries,classDataItems,codeItems}` 与 `mapRebuilt/mapEntries/relocatedCodeItems/relocatedClassData/unmatchedCaptures`。验收：`verify_v96_dex_map.sh`（含截断/篡改两个负对照）+ v12/v13/v95。WS-E 只剩 cdex/041（需样本 → PENDING）。
>
> 实现状态（v5.00，**实现 + host 验收完成，真机待做**）：**第九轮评审收口（1 条 P1 + 9 条 P2）**。**P1**：宿主守卫与 agent 解析地址的规则不同（守卫 `parseAddress()` 裸数字串=十进制，agent `strtoull(...,0)` 前导 0=八进制），`"010000000000"` 会被校验成 `0x2540be400` 而调用到 `0x40000000`——`assertCallableAddress()` 现在返回**归一化后的 `0x…`**（`normalizeAddressForAgent()`），MCP/REST 都改发这个串，空白串 trim 后走 module+symbol；agent 的 `native_call` addr 分支同时补 `adh_addr_is_executable()`（agent 端口可直连，不能只靠宿主守卫）。**P2**：守卫覆盖 sites/vtable 裸 addr、只在 `action=hook` 生效、守卫与下发同 session；agent 侧未回收 worker 计数上限 4（对永不返回的函数重试不再堆积线程）；看门狗窗口只覆盖调用本身——worker 先发布 `call_done`+结果再跑 JNI 探测，探测未在窗口内完成时回 `exceptionProbe:"unavailable"` + 调用结果（不再把已返回的调用报成"还在跑"），attach 失败也不再静默当"无异常"；`/api/module/dump` 的 dedup 命中按本次请求重算 source/complete/session/tag/addr；phone 面剩余 NaN（intervalMs/lookbackMs/stableMs/maxScrolls/maxNodes/maxTextLength）统一走 `num.ts: finiteNumber()`；修正"未映射地址装 inline hook 会崩"的旧文案（agent 自 `88e8e75` 起先拒绝，宿主守卫的价值是更早更一致地报错）。
>
> 实现状态（v4.99，**实现 + host 验收完成，真机待做**）：**WS-E 第一片：try/catch 的 code_item**。`readCodeItem()` 按规范走完 header + insns + 4 字节对齐的 `tries[]` + `encoded_catch_handler_list`（sleb128 handler size、type/addr 对、catch-all）；`tries!=0` 的方法不再被静默跳过（沙盒 dex 1166/46228）。解不动的 item 走**显式 `unresolvable`**：覆盖率里不计入 present、列进 `missing` 并带理由（上限 200 条），恢复报告同样列出失败理由；`rebuildStandardDex` 注入前校验 capture 是完整 code_item（半截件 → 422），不再把半截字节追加进新 dex。`/api/dex/method_code` 支持 `limit`（默认 200、上限 5000）。验收：`verify_v95_dex_trycatch.sh`（host，含负对照）+ `daemon/test/dex_codeitem.test.ts`。仍未做：rebuild 的 map_list 重建、cdex/041（需样本，PENDING）。
>
> 实现状态（v4.98，**实现 + host 验收完成**）：**同一守卫覆盖 `native_hook mode=inline addr`**。MCP 与 REST 两条路径都先调用共享的 `assertCallableAddress()`，守卫文案改为中性以服务"调用或挂钩"两种动作；`jni_onload action=call` 只接受 module（内部解析符号）故不需要该守卫。（v5.00 更正：agent 自 `88e8e75` 起在任何 patch 之前就用 `adh_addr_is_executable()` 拒绝未映射/不可执行的 inline 目标，"会崩在目标里"不是事实——宿主守卫的价值是**更早、更一致**地报错；`mode=sites|vtable` 同样接受裸 addr，v5.00 起也过守卫。）

> 实现状态（v4.80，**实现 + host 验收完成，真机验收待做**）：**JNIEnv status 可过滤、并自报完整性**。表项涨到 228 后，整表回复超出旧的 32 KB 缓冲会被**静默截断**（只回一部分槽位且不说明——验证者会把"缺条目"读成"未安装"）。现在 `action:status` 用 `function` 当过滤器（与安装同语法：精确名 / 前缀 / `*后缀` / `*包含*` / `all`·`*`），另支持关键字 `installed`(仅已挂槽位)；解析与匹配和安装路径共用同一实现，回复带 `total`/`matched`/`emitted`/`truncated`，缓冲 128 KB（协议长度分帧、上限 64 MB）足够整表一次带回。安装/卸载对 `installed` 关键字显式报错（它是 status 过滤器，不是槽位名）。MCP 描述同步；v91 新增 `(3i)` 设备段断言三种视角的自洽性。

> 实现状态（v4.66，**实现 + host 验收完成**）：**JNIEnv 覆盖率成为数字** + 两条评审 P1 收口。① 事件可信度：字符串拷贝/ pin 的 wrapper 在调用抛异常时**不再读缓冲区**（越界时 ART 不写 buf，读了就是拿未初始化内存当证据），失败事件写明 `<copy failed, buffer untouched>` 且 `ok=false`；`capacity=0` 显式标注歧义。② v91 对三个字符串读取器**逐个**断言（独立代码路径必须各自证明），并去掉魔数。③ `verify_v90_jni_table_abi.sh` 输出 `coverage: N/229` 与未覆盖名单（当时 119/229 = 52%，下限 115），"JNIEnv 全表可挂"从此有可跟踪的数字与待办清单。

> 实现状态（v4.65，**实现 + host 验收完成，真机验收待做**）：**pin 住 Java 字符串的一对**。`GetStringChars`（事件带 `string=.. isCopy=.. text="…"`，有界预览最多 24 字符且遇字符串自带终止符即停）与 `ReleaseStringChars`（事件带 `string=/chars=`）补齐"直接拿内部指针"这条读字符串路径；JNIEnv 表 117 → **119 槽**，索引 165/166 由 `verify_v90_jni_table_abi.sh` 对 NDK `jni.h` 机检、签名由 `_Static_assert` 编译期钉死。沙盒探针与 v91 的 `(3f)` 同步扩展。

> 实现状态（v4.64，**实现 + host 验收完成，真机验收待做**）：v4.63 那 5 个表项的设备验证路径补齐——沙盒 native 探针 `Detection.jniStringProbe`（`GetStringRegion`/`GetStringUTFRegion` 各拷一次 + `NewDirectByteBuffer`/`GetDirectBufferAddress`/`GetDirectBufferCapacity` 各一次）与 Kotlin 声明已在 host 构建通过（`build_detect.sh` + `:app:assembleDebug`）；v91 的 `(3f)` 段逐个安装/触发/断言事件内容（`text="…"`、`address=`、`capacity=64`）/卸载，并纳入 pass。

> 实现状态（v4.63，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 再补 5 个表项**——`GetStringRegion`/`GetStringUTFRegion`（native 把 Java 字符串拷进自己的缓冲区；事件带 `string=0x.. start/len` 与有界文本预览，UTF-16 24 字符 / UTF-8 48 字节、不可打印转 `.`）与直接缓冲三件套 `NewDirectByteBuffer`/`GetDirectBufferAddress`/`GetDirectBufferCapacity`（事件带 `address/capacity`）。槽位 112 → **117**（18 固定 + 21 族 ×3）；签名由 `_Static_assert` 编译期钉死、索引由 `verify_v90_jni_table_abi.sh` 对 NDK `jni.h` 机检（`checked 117 indices`）。其余表项（`GetStringChars`/`ReleaseStringChars`、`GetJavaVM`、`NewWeakGlobalRef`、`ExceptionOccurred` 等）仍是盲区，同机制可加。

> 实现状态（v4.61，**实现 + host 验收完成**）：**字段摘要区分"被改写的写入"**。`jni_field_digest` 现在解析 `value=<应用值> requested=<原值>`：顶层给出 `rewrittenSamples`，每组给出 `rewritten` 与 `lastRequested`，`lastValue` 固定为**目标最终存下的值**，并在 notes 里点名"有 N 次写入被激活的 setValue 覆盖改写"——"目标想写 7、被我们写成 42"本身就是这类分析的结论，不能再混进普通写入里。单测 5 → 7 条；MCP 描述同步。

> 实现状态（v4.60，**实现 + host 验收完成**）：**覆盖功能的收口**。REST `/api/jni/env_hook` 补上 `setValue` 转发（v4.58 只接了 MCP，设备脚本走 REST 因此永远不可能通过），并在 host 侧加了通用参数面检查——MCP schema 的每个属性名必须在对应 REST handler 里出现（v92 现在会打印 `forwards all N MCP parameters`）。`setValue` 改为严格解析（整串必须是数字，只有浮点可解析时同步到整数槽），并按目标字段类型做范围检查（Boolean 0/1、Byte/Char/Short/Int 各自区间、Float/Double 必须有限），越界 fail-loud 而不是静默取模；`override_active` 改为 release/acquire 发布，status 读覆盖时持同一把锁。

> 实现状态（v4.58，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 字段写入可改写**。`jni_env_hook` 新增 `setValue`（数字，单槽）：`Set<Type>Field` wrapper 在调用原函数前替换写入值，事件给出 `value=<应用值> requested=<原值>`，覆盖状态随卸载清除；只支持 boolean/byte/char/short/int/long/float/double（对象字段需要 agent 不持有的引用，直接拒绝），`setValue` + 通配模式亦拒绝。覆盖值安装时解析成整数与浮点各一份，热路径零解析。同时收口评审 P2：ID 查询在"无异常但返回 NULL"时不再报 ok:1、预算耗尽不再把成功的调用标成 ok:false、两个 ID wrapper 补 `_Static_assert` 签名检查。

> 实现状态（v4.57，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 钩子选择器补齐后缀/包含匹配**。此前只有前缀通配（`CallIntMethod*`），36 个字段访问器没有一次装上的写法。现在 `"*"`/`all` = 全部、`Call*` = 前缀、**`*Field` = 后缀**（一次挂上整个字段族）、**`*Field*` = 包含**（同时命中 `GetFieldID`/`GetStaticFieldID` 与访问器——字段摘要解析名字所需的组合）；匹配用有界比较（不依赖子串 NUL 终止），命中/失败数与首个失败原因照旧上报，MCP 描述里写明四种模式。设备脚本 v91 增加断言：`*Field` 一次安装后 status 中名字以 `Field` 结尾且 `installed` 的槽位 ≥ 36，再用同一模式整体卸载。

> 实现状态（v4.55，**实现 + host 验收完成，真机验收待做**）：**JNIEnv 字段访问器 36 槽**。native 代码通过 `env->Get/Set<Type>Field`（instance + static，9 种类型）读写字段的路径此前不可见——`object_set` 只覆盖反射路径。槽位从 76 扩到 **112**：一份列表宏同时驱动枚举、名字表、结构体字段 case 与 wrapper 派发；每个 wrapper 转发原函数并记录 `field=0x.. value=..` 事件，保留重入守卫 / 事件预算 / RELRO 还原。安全性三层：`_Static_assert` 把 wrapper 签名钉死在编译期、`tools/verify_v90_jni_table_abi.sh` 把索引钉死在 SDK `jni.h`、安装期偏移不符即拒绝 patch。沙盒新增 `HeapProbe.sCounter` 与 native 探针 `Detection.jniFieldProbe`，设备脚本 `tools/verify_v91_jni_env_fields.sh` 验证事件内容、表页只读与卸载还原。

> 实现状态（v4.54，**实现 + host 验收完成**）：**JNIEnv 槽位表的 ABI 机检**。索引写错会打到相邻 JNI 函数（影响目标里每一次 JNI 调用），所以在扩展槽位前先把索引正确性变成可机检的证据：`tools/verify_v90_jni_table_abi.sh` 解析 NDK `jni.h` 的 `JNINativeInterface` 字段序（233 槽），与 agent 的 `env_hook_spec_index()`（含两套调用族宏展开）逐条对照，并检查每个要安装的槽位都有索引；同时把下一步要用的 36 个字段访问器索引也钉住，防止实现或文档手抄出错。

> 实现状态（v4.53，**实现 + host 验收完成，真机验收待做**）：**活体对象从"能读、能调"补到"能写"**。`object_set{className, field, targetField, value}`（MCP + `POST /api/object/set`）沿用 inspect/invoke 的静态持有者约定，按字段声明类型**严格解析**（boolean 只认 true/false/1/0/yes/no；int/long/float/double 走全量解析 + 范围与 `isfinite` 检查——typo、越界、部分解析一律拒绝，不会静默写 0），返回 before/after 并回读验证；final 字段（Kotlin `val`）先经 `Modifier.isFinal` 判定后明确报错，参数超长也 fail-loud 而不是写入被截断的值。设备脚本 `tools/verify_v89_object_set.sh` 在 `HeapProbe.sConfig` 上翻转三个可变字段并复读，另要求 final 字段 fail-loud。字段查找与 `object_inspect` 的枚举都**沿父类链**（`getSuperclass()` 上溯），每条记录带声明类；边界：只覆盖反射可见字段，直接 `iget/iput` 与 JNIEnv `Get/Set*Field` 仍未纳入观察面（后者是 v4.54+ 的 JNIEnv 槽位候选）。

> 实现状态（v4.52，**实现 + host 验收完成，真机验收待做**）：**hook 槽位预算从"藏在失败里"变成可见、可被工具遵守**。agent 的 `native_hook status` 新增 `slots{max,used,active,free,byMode{got,inline,sites,vtable}}`，其中 **`used` = 已消耗槽位**（软卸载的 inline 钩子保留 stub、槽位直到硬卸载才释放），`free = max - used` 才是真实余量、`java_hook status` 新增 `maxHooks`；host 的 `native_hook_all` 先读一次 status，用纯函数 `effectiveBatchLimit(requested, freeSlots)` 决定这一批装几个——`free < requested` 时截断并由 `limitReason` 说明，**`free == 0` 直接 fail-loud**（"unhook something first"）而不是逐符号失败，老 payload 不上报预算时回退到请求值并注明，负数预算按"agent 报告损坏"拒绝（不再伪装成 0 空闲），响应带 `effectiveLimit`/`requestedLimit`。**安装失败不再烧槽位**：预留位（`active==2`，从未发布）在失败路径归还 `used`，否则 16 次失败就能吃光整个预算。单测 7 → 9 条（截断/阻断/回退/夹紧/损坏预算），`tools/verify_v84_native_hook_all.sh` 增加"agent 必须上报 slots、daemon 必须走 status 取预算、响应必须带 limitReason"的断言。

> 实现状态（v4.51，**实现 + host 验收完成**）：**vendored LSPlant 的字符串也清掉了**——`tools/patch_vendor_signatures.sh`（幂等 + `--check`，由 `tools/fetch_lsplant.sh` 调用）把 `ScopedSuspendAll("LSPlant Hook")`、LSPlant 的 log tag、以及**运行时生成 dex 的 source name `"lsplant"`** 改成中性；扫描器把 `LSPlant`/`lsplant` 提为 MUST_BE_ABSENT，门禁额外跑 vendor check（重新 fetch 忘打补丁会现形）。Dobby（预编译 AAR）与导出/Java bridge 仍在预算内。

> 实现状态（v4.50，**实现 + host 验收完成，真机验收待做**）：**字符串层去特征 + 签名门禁**。agent 跑在目标进程里，`.rodata` 就是目标能自己读的内存，所以「还残留哪些串」必须是**可测**的：`tools/scan_agent_signatures.sh` 分两类——MUST_BE_ABSENT（我们自己的身份串，必须为 0）与 BUDGETED（还动不了的，带只许降的上限 + stage 2 修法）。stage 1 已清零：7 个 `ADH_*` 日志 tag → 中性 `rt.*`；自己文案里的 Host ADH Daemon / ADH wrapper / `lsplant::` / `Dobby*` / `fetch_*_dobby|lsplant.sh` → 中性；fixture 默认值在**整条链路上**删除：agent 的 `qbdi_trace` 缺 symLib/symbol 直接 fail-loud，MCP 的 `qbdi_trace`/`trace_digest` schema 也把 symLib 改成必填、REST 路由缺参回 400（此前默认值只是搬到了 daemon，真实目标上表现为 "symbol not found"）；`verify_v02_so.sh` 的 soname 断言随之翻成「必须没有」；`got.c` 自名 fallback 改 XOR 混淆（volatile 表+key 防常量折叠）；CMake 关掉 DT_SONAME（我们从不用 soname 加载）。门禁 `tools/verify_v88_agent_signatures.sh` 带**负对照**：往 .so 副本植入一个 token，扫描器必须报 FAIL。仍预算中的（`adh_agent_start`/`adh_agent_set_package` 导出、Java bridge 类名与 dex 文件名、`adh.reporter.class`、预编译 Dobby/LSPlant 符号、`libQBDI.so`、`libzygisk.so`）各自写明 stage 2 修法，数字只许降。

### 26.1 诊断层

- 检测目标是否存在：hook 冲突、maps 自扫描、ptrace 占用、seccomp 限制、linker namespace 限制、inline-hook 序言校验、Zygisk/框架痕迹检测
- 对每个 hook 后端给出可用性检测结果
- 发现目标行为分叉（注入后闪退/走不同分支）时生成诊断事件
- 生成**兼容性报告**：哪些能力可用、哪些被限制、哪些可能触发崩溃

### 26.2 韧性层（授权环境，默认关闭）

- **early-inject**：抢在目标反调试布防之前完成加载与关键 hook（配合 W 的 Zygisk 后端）
- **与目标 ptrace 自附加共存**：目标 `PTRACE_TRACEME` 占位时的采集策略。
  ⚠️ **现状**：**观测**由持续捕获的 `system` 类提供。Manager Hook 配置的「系统检测」（policy `y`，默认关）
  打开后，`capture_start` 才装这些钩子；`sysModule`（逗号分隔，最多 8 个）为空时 Host 对该包跑
  `detect_modules` 自动选库，按名改 `ptrace` / `access` / `faccessat` / `__system_property_get` /
  `__system_property_read_callback` 的 GOT。事件带返回值、路径或属性值、以及调用点的 `lr`。
  Host 的 `detect_summary` 把它们收成反调试 / root / 签名 / 模拟器 / 完整性清单（Web 用白话展示）；
  `open`/`openat` 只有打到 `/proc/self/status|maps` 或 su 路径才计入。`detect_java` 在 `confirm:true`
  时按调用方点名的 family 安装 Java 钩子（`File.exists` 不在默认 family 里）。**中和**（伪造 TRACEME
  返回值）仍然没有控制面。
- **最小侵入模式**：只启用 maps/dex/classloader/crypto 等低痕迹模块，关闭高痕迹 hook
- **hook 自校验对抗**：应对目标周期性校验函数序言字节、检测 GOT 改写

> 实现状态（v4.37，真机 `aa165071` 验收）：**Zygisk 注入的 agent 不再以文件路径出现在目标 maps** —— 伴生进程把 agent 复制进 `memfd:jit-cache`，并在 **post-specialize（App 域）** 由 linker 从该 fd 加载（pre-specialize 创建的 memfd 因域切换会被 linker 拒绝，真机实测），失败则回退模块路径并记录；scope 判定改由 **root 伴生进程**代读 `/data/adb/adh/scope.json`（`scope <pkg>` 协议）；注入决策写 `/data/adb/adh/zygisk_inject.log`（实例在 App 域时经伴生转发）。真机 `com.android.settings`：maps 中 `libadh_agent.so` 计数为 0、agent 以三个小 `/memfd:jit-cache (deleted)` 映射出现、daemon 侧在线 `entry=start`；验收脚本 `tools/verify_v75_zygisk_memfd.sh` 额外要求"决策日志有注入决策 + 会话必须是本次冷启动新建（pid 全新、`entry=start`、同 pid 唯一）+ 目标内自证（agent 自己的 maps 里是私有 r-xp 的 `/memfd:jit-cache (deleted)`、inode 与 ART 自己的 jit-cache 不同、offset 0 处头 4 字节为 `7f 45 4c 46`、`compat_probe.agentExecMappings>=1`）"，避免"没注入"也能满足"maps 里没有 libadh_agent"；缺前置条件时脚本只打印 `SKIP`（不打 `RESULT:PASS`），`verify_all.sh` 记为 skip。单实例身份用 **GNU build ID**（PT_NOTE 内存读取）判定"同一个文件的另一个副本"，PT_LOAD span 仅作回退。

> 实现状态（v4.36，真机 `aa165071` 验收）：指针槽后端覆盖到**真实对象虚调用**（对象持 vptr、表在 RELRO、`ldr vptr/ldr slot/blr`）与**可写函数指针**（回调变量）：默认只改只读槽，可写槽需 `slotsWritable:true`（默认安装会明确报"writable slots were skipped"，成功路径也会回传 `skippedWritable`）；revert 只还原"仍等于我们 thunk"的槽，目标自己改写过的槽保留并回传 `slotChangedByTarget`；验收断言对象虚调用的命中归因（只调该探针时 hits 增长）、被改槽确是函数地址、函数 24 字节前后逐位相同、槽位逐位还原与 thunk 页消失。

> 实现状态（v4.35，真机 `aa165071` 验收）：**指针槽（vtable/回调表/GOT）hook**——`native_hook mode=vtable` 扫描可读非可执行 data 段里等于目标地址的 8 字节槽，改槽不改码：函数入口、调用点、指令缓存都不动，间接调用（函数指针表，内存形态与 C++ vtable 相同；真实对象分派未单独验收）因此也能拦。逐槽回传 `kind`（只有 GLOB_DAT/JUMP_SLOT 算 `got`，vtable 里的 RELATIVE 指针算 `data`）与所在模块/映射权限；真机断言"直接读函数地址的 24 字节安装前后逐位相同" + "间接调用命中" + "相邻槽未被改" + "hard unhook 逐位还原且 thunk 页 munmap"。**已知副作用（验收里如实断言）**：改模块自己的 GOT 槽会改变该模块内 `&symbol` 的解析结果，目标自查可因此发现重定向（代码本身没有变）。默认只改只读映射里的槽，`slotsWritable:true` 才改可写槽；回滚失败时保留 thunk 页并把 `pageKept` 报到 status。

> 实现状态（v4.34，真机 `aa165071` 验收）：**跨模块调用点拦截**：`scope` 选择扫描范围（`module` 默认 / `all` 所有文件映射可执行段 / 单个模块名），每个调用点各自分配 near thunk 页（跨模块调用点常超出单页的 BL 范围）；扫描按"目标模块 → /data 应用自有模块 → 系统库"排序，128 MB 预算，`scanned`/`truncated` 如实回传。沙盒新增跨模块 fixture（插件库调用目标库），真机断言 3 站点/2 模块全部命中、目标入口审计仍然干净、hard unhook 后逐位还原且所有 thunk 页 munmap。生成 thunk 后先自检（pc 相对分支与字面量）才允许安装。

> 实现状态（v4.33，真机 `aa165071` 验收）：**"序言不变也能拦"** 已落地：`native_hook mode=sites` 不改目标函数，只改同模块内调用它的 `B`/`BL`（含一层 PLT/尾调用解析）到自家 near thunk（memfd 页、±128 MB 内解析、按原指令形态写回 `b`/`bl`），因此目标自校验序言时看到的是**原始字节**。验收断言"拦截真的发生"（两种形态 b/bl 各命中、hits≥1、返回值正确）、"入口审计干净"（目标自己的 24 字节序言比对 + 入口首指令不外跳 + 无匿名可执行页），并在 hard unhook 后独立读回两个调用点的字节 == agent 记录的原值、确认 thunk 页已 munmap、同进程重装仍可用。边界：只覆盖同模块直接调用（含一层 PLT/尾调用 stub）；调用点自身字节可被检查；最多 8 个调用点/hook；sites 模式**不支持** skipOriginal/returnSet（返回值 bank 依目标而定，直接 fail-loud）。

> 实现状态（v4.32，真机 `aa165071` 验收）：**hook 自校验对抗**落地一半，且是可测量的。开启 `stealth` 后，inline hook 后端不再留下"无路径的可执行页"：Dobby 的 trampoline arena 被重定向到 ART 风格的 `/memfd:jit-cache` 映射（Dobby 的 mmap 走本模块 GOT；重定向窗口线程本地；任何失败回退真 mmap 并如实报 errno）。沙盒 `Detection.antiHookProbe`（目标自己扫 maps + 自校验序言）在开启前后给出可对账的数字：`anonExec 2 → 0`。但**入口序言被改写无法隐藏**（同一审计在 stealth 下仍报 `prologueDiffers/entryBranchesOutside=true`，v69 已断言这一点）——要"序言也不变"必须改用 GOT/表项 hook 或 ART 层 Java hook（LSPlant 不改 .text）。默认关闭，开启需 Host `confirm:true`。

### 26.3 边界

- **对手面已写死（2026-10-01）**：只针对「**目标进程内**的字符串扫描 + `anon r-x` 扫描 + 线程名 + 已加载模块名」。
  文件系统上的模块名、Zygisk 目录名、包名痕迹**明确不在范围**——不定义对手面这就是无界任务。
- 不承诺绕过所有反调试/反注入
- 默认不自我隐藏
- 韧性能力默认关闭，需在会话中显式开启并二次确认
- 验证：sandbox `AntiDebugMockActivity` 作为工具自身稳定性回归

---

## 27. T — Runtime Object Inspector（活体对象自省）

**目标**：对当前 ART 堆中的活体 Java 对象做授权范围内的运行时自省。回答 Hook 无法回答的「当前活着的对象里有什么」。

### 27.1 能力

- 按 class name 枚举存活实例（`Java.choose` 式）
- 读取对象字段：基本类型 / String / 数组 / `byte[]` / 集合摘要
- 为对象生成 `object_id`，支持后续继续查看、跨事件引用
- 堆内搜索：String / `byte[]` / Map key-value 命中（如「含 token 的 String」）
- 对选中对象调用低风险方法（getter/toString/size/length）
- 展示对象所属 ClassLoader / Dex / 创建线程线索
- 与 Hook 事件联动：命中事件里的参数对象可一键展开字段

### 27.2 安全边界

- 默认只读；方法调用必须显式确认，默认仅允许无副作用调用
- 禁止默认递归全堆深扫
- 上限：对象数量、字段深度、字符串长度、超时

**取证价值**：加密混淆目标里 key/token/配置常以活体对象存在于堆中，Hook 抓不到静止状态，Object Inspector 直接捞出。

---

## 28. U — 非标准运行时识别与扩展点

**目标**：识别非 Java 主线运行时，先给观测入口，不承诺语义还原。

### 28.1 第一阶段（仅识别）

- Flutter：`libflutter.so`、Dart snapshot、资源布局；BoringSSL 静态链接边界
- Unity：`libil2cpp.so`、`global-metadata.dat`、mono runtime
- React Native / Hermes：Hermes bytecode、JS bundle、SoLoader
- Cronet / 自研 TLS 栈识别

### 28.2 第二阶段（观测入口）

- 记录模块加载、关键符号、字符串、网络/crypto 边界
- 允许用户对识别出的 runtime 下发专用 hook/trace 模板

### 28.3 边界

- 不承诺还原 Dart/IL2CPP/Hermes 高级语义；第一版不做成 Flutter/Unity 逆向平台
- **不进 MVP**

---

## 30. W — 注入后端与打包

**目标**：把「能否注入真实目标」这个高风险变量，与「每个功能模块是否正确」解耦，覆盖 root 与非 root，并保证 CI 可持续验证。

### 30.1 注入后端

| 后端 | 环境 | 说明 |
|------|------|------|
| **Zygisk 插件** | root（Magisk） | 主线，zygote fork 后 early-inject，配合 S 韧性；配套 **ADH Manager** 管理作用域白名单（`/data/adb/adh/scope.json`） |
| **模拟注入** | 无需 root | sandbox 自身 `dlopen` 加载 agent（开发/CI 主路径） |
| ~~Frida Gadget~~ | — | **已退出产品面**（2026-10-20）；仓库可残留历史脚本，不进 UI / 门禁 / 发布物 |

### 30.2 打包交付物

- `libadh_agent.so`（arm64-v8a 主线，设备 ABI）
- Zygisk 模块包（root 版）+ ADH Manager APK（作用域：选哪些 App 注入）；另提供 Magisk 可直接安装、自动安装 Manager 的组合包
- 双 bootstrap 入口：`JNI_OnLoad`/构造函数（被加载）与 `adh_agent_start()`（被宿主主动调用，唯一对外入口），行为一致

### 30.3 模拟注入回路（CI 主路径）

```text
sandbox-app 启动 → System.loadLibrary("adh_agent") → JNI_OnLoad；注入器 → adh_agent_start()
  → 连 ADH Daemon → 跑通全部模块断言 → 再打真实目标
```

无需 root、确定性、可回归。真机注入只在联调/实战启用。

### 30.4 Zygisk + Manager（设备侧作用域）

```text
ADH Manager（普通 APK、无 Root）→ 受认证 AIDL Binder
Root Device Daemon（模块随 boot 启动）→ 读写 /data/adb/adh/scope.json（allowlist）
Zygisk 模块 (id=adh) → preAppSpecialize 读 scope/open agent fd/set package → postAppSpecialize android_dlopen_ext → DLCLOSE companion
Agent → TCP 8761 → ADH Daemon（host，经 adb reverse）
```

交付物：`injector/zygisk/dist/adh-zygisk.zip`、`device/manager` APK，以及二者合一且可由 Magisk 直接安装的版本化 `injector/zygisk/dist/adh-bundle-vX.Y.Z.zip`。Gadget 直载路径已落地（见 §30.5）。

- Zygisk `.so` 必须导出未改名且默认可见的 C 符号 `zygisk_module_entry`；有 root companion 时同样要求 `zygisk_companion_entry`，打包阶段必须自动验证。
- Agent 必须在 `preAppSpecialize` 内用 `getModuleDir()` + `openat` 打开 `libadh_agent.so`；`postAppSpecialize` 只用 `android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` 加载，禁止在 post 阶段调 `getModuleDir()`（Zygisk Next 会死锁）。
- Companion 必须在 `adh_agent_start()` 前调用 `adh_agent_set_package()` 传真实包名；early inject 不得把 `zygote64` 当目标包名上报。
- scope 读取失败必须 fail-loud/no-inject；KernelSU 由 `post-fs-data.sh` 应用 `allow zygote adb_data_file` 的最小规则，Magisk 使用模块根 `sepolicy.rule`。
- **逐包 Hook 策略**：`scope.json` 的可选 `policy` 段给每个已勾选包一份 `CaptureFamilies`（摘要 / HMAC / 对称 / 非对称 / TLS / AEAD 六个开关）。它是**安装期策略而非记录过滤器**——关掉的族在该进程里**根本不装钩子**（动机：2026-10-11 实测某个轻度混淆目标在钩子生效期间以 `SIGSEGV (SI_USER)` 自杀，改动面越小越好）。缺段 / 缺包 / 缺键一律按"开"处理，所以老 scope 文件与老 Daemon 不写该段即保持正确；`encode` 丢弃默认值与已出作用域的条目，该段只承载非默认项。策略经 companion 的 `policy <pkg>` 动词以单行紧凑标志（`d=1,h=0,…`）取回，在 `preAppSpecialize` 连同包名交给 `adh_agent_set_policy()`。**agent 只持有策略，不自己装钩子**：GOT 补丁需要一个模块名，而 agent 不携带任何模块名（WS-B 红线，`tools/verify_v87_mcp_operability.sh`），所以它把策略应用到**下一次由调用方发起的安装**上；安装回执里 `skipped` 列出被策略关掉的族、各族计数 `-1` 即"策略跳过"（区别于 `0`＝模块没导入该符号），daemon 侧由 `captureHooks` 观测。**诚实边界**：策略**决定**不需要主机（它存在手机上，经 companion → agent 送达），但**安装与观测仍然需要主机**（记录由 agent 的 ring 缓冲，主机不在时既没有人安装、填满即丢）。写入方必须按 `AdhProtocol.MIN_POLICY_VERSION`（= v15）门禁：Device Daemon 的 `setScopeJson` 是 decode→re-encode，低于该版本会**静默丢掉 `policy` 却照样回保存成功**。AI agent 读改同一份文件（`adb shell su -c 'cat …'` / 整份写回），与 Manager 界面**同源不分叉**。
- **SSL 绕过默认开**：应用被注入（已在作用域里）之后，agent 放行 Java 侧证书校验，让外部代理能看到 HTTPS。装钩前先 `Class.forName(name, true, loader)`。Android 12 及以上不钩 `Class::SetStatus`，也不钩 `ClassLinker::RegisterNative`（这台 Android 15 上钩了它，目标会在 `JNI_OnLoad` / `RegisterNatives` 里被 SIGSEGV）。每次握手走 `TrustManagerImpl.checkServerTrusted` / `getTrustedChainForServer` / `Platform.checkServerTrusted`（返回链的重载把对端证书当可信链返回，void 的直接跳过），另外改 `SSLContext.init`、`TrustManagerFactory.getTrustManagers`、OkHttp `CertificatePinner.check` 和 HostnameVerifier。类不存在就跳过。采集族 `t` 的 native `SSL_read` / `SSL_write` 照旧，和这次放行是两件事。
- Companion 应设置 `DLCLOSE_MODULE_LIBRARY`，post-specialize 后卸载自身映射；agent `.so` 保持加载服务会话。
- **作用域按包名匹配，覆盖该包的每一个进程**。Zygisk 交给模块的是**进程名**（`nice_name`），次要进程形如 `com.example.app:core`；模块必须把它拆出包名，再按"先进程名、后包名"向 companion 问 `scope` / `policy`（窄的优先，于是"只想盯某一个进程"仍然可用），hard-exclude 对两个 key 都要判。agent 上报的 `hello.package` 是包名、`hello.process` 是进程名，因此多进程 App 在 daemon/面板里归到一个包下、每个 session 仍能溯源到进程。**这条不是可选的**：按字面匹配进程名时，勾一个包只能覆盖它的主进程，而目标的网络栈可能在 `:core` 之类的次要进程里——抓包成不成功由"你碰巧写的是哪个名字"决定（2026-10-13 真机判定，见下）。
- 模块作者固定为 `decrypthub.com`；root 管理器中的模块描述只显示“等待重启 / 运行中 / 未加载”这类简洁工作状态，不展示内部路径、架构说明或开发备注。
- ADH Manager 的设备控制能力只限注入作用域、模块状态、系统证书，以及经 Device Daemon 终止/重启目标应用进程；界面默认中文，已有系统语言资源时跟随系统语言，并跟随系统深浅色主题。首页保留运行状态、Web UI 访问地址、作用域入口和版本信息。Manager 可直接探测 Host ADH Daemon `/health` 来显示并打开局域网优先的 Web UI 地址，但不得把该请求转交 Device Daemon，也不得在设备侧承载 HTTP 服务或分析逻辑。目标进程启停/打开必须走受认证 AIDL（`controlPackage`），当前 Device Daemon AIDL 为 v18（v15 增加逐包 Hook 策略、v16 曾增加 `b` 旁路段，都走同一个 scope JSON；v17 新增 `setHostEndpoint`，把 Manager 已经从 `/health` 得到的 `ipv4:port` 写到 `/data/adb/adh/host.endpoint`，Device Daemon 自己不扫描网络；v18 让 Manager 导入 PEM/DER，Daemon 只把带 CA 标记的证书写到 `/data/adb/adh/cacerts/<subject_hash_old>.N`，`post-fs-data.sh` 在 zygote 起来前并入系统信任库，未导入时不挂载。重启须经用户确认后由 Daemon 执行）。旧版 v7-v12 的 AccessibilityService、设备电源状态与受限 UI 输入方法已从当前协议删除。Manager 不得自己调用 `am`/`su`。不得对 Manager、Device Daemon、`system_server`、System UI 或 `android` 执行终止/重启。
- “运行中”必须来自本次启动中 Zygisk 实际加载模块的标记，不能仅以模块目录存在作为成功依据；标记由 root companion 写入，启动时先清除旧状态。
- Manager 不得直接调用 `su` 或访问 `/data/adb`。模块以 root `app_process` 启动 Device Daemon，Manager 仅通过 AIDL Binder 读取状态和作用域；daemon 必须校验调用 UID、`com.adh.manager` 包归属和构建时固定的 APK 签名证书。
- Binder 交接入口只接受 UID 0 发布，并核对 AIDL descriptor；Manager 必须区分 Device Daemon 未连接、模块未安装、模块已安装但未加载、运行中四种状态。服务未连接时不得用空配置冒充真实作用域，也不得显示“模块未安装”。

### 30.5 可选注入后端（Gadget / eCapture）— 实验性，不进发布物

> **范围收口（2026-10-01 决议）**：**官方注入路径只有 Zygisk**（CI 走模拟注入）。
> Frida Gadget = **开发/调试用**（移出发布物）；
> eCapture = **实验脚本**，且已**移出 `verify_all.sh` 门禁**。判定细则见 `DEVELOPMENT_PLAN.md §6.10`。

两个可选后端（Gadget / eCapture）都**不是默认路径**，必须显式调用；默认注入仍是 Zygisk（root）与模拟注入（CI）。两者都是开源生态里现成的机制，ADH 只借它把 agent/JS hook 或明文观测送进目标，不把分析与存储搬进目标进程（架构红线不变）。

**Frida Gadget（已落地并真机验证，2026-09-15）**

- 只走官方 release：`tools/fetch_frida_gadget.sh <version|latest> [--abi arm64] [--list] [--print-url]`，缓存到 gitignore 的 `agent/third_party/frida/<version>/<abi>/`；压缩包 sha256 固定在 `tools/frida_gadget_versions.json`（离线可复现，切换版本只换参数）。
- **Frida 17 起语言桥不再内置在 Gadget runtime**：`Java.perform()` 这类 hook 必须先打包。`tools/compile_frida_script.sh` 用 esbuild 把 hook 与 `frida-java-bridge` 打成单文件（经典写法自动注入 `globalThis.Java`；已是 module 写法则原样打包；已打包文件幂等直通）。**不用 `frida-compile`**：其 CLI 依赖原生 `frida` 绑定，Windows 上要 MSVC。
- `tools/load_frida_gadget.sh <hook.js> [...]`：官方 so → 按需打包 → 落进 `<pkg>/code_cache`（app uid + selinux ctx；配置名必须是 `<soname>.config.so`，否则 Gadget 静默回退默认 listen）→ `POST /api/agent/load_so` dlopen。**Gadget 由构造函数自启动，没有入口符号可调**，`symbolFound` 仅信息性；随后轮询 `/proc/<pid>/task` 等 `frida-gadget` 线程，可选 `--marker` 断言脚本真的跑到（只有"线程起来"不等于脚本跑通）。
- `--watch` 写 `on_change: reload`：改 `code_cache/adh_hook.js` 即热重载，无需重启目标进程。
- 验收：`tools/verify_v30_fridagadget.sh`（真机：官方 gadget → dlopen → 打包后的 Java hook 写 marker；gadget 或打包依赖缺失时 SKIP，因为两者都在 gitignore 缓存里）。实测开销：so 25,220,848 B、目标进程 +9 行 maps、+2 个线程。

**eCapture（可选，root + eBPF，2026-09-16 真机验证）**

- 用途：eBPF uprobe 在 `SSL_write/SSL_read` 边界读明文，**不需要证书/代理**，与 agent 的 GOT hook 互补（同一次请求里 agent GOT hook 可能 0 命中，eCapture 仍抓到请求+响应明文）。
- 只走官方发布：`tools/fetch_ecapture.sh`（版本固定在 `tools/ecapture_versions.json`，sha256 取自发布自带的 `checksum-<ver>.txt`），缓存于 gitignore 的 `agent/third_party/ecapture/<ver>/<abi>/`。
- 运行：`tools/ecapture_capture.sh --package <pkg> | --pid N [--seconds N]`；固定使用已验证的 text 模式。`--preflight-only` 输出 root/内核/`CONFIG_BPF_SYSCALL`/`CONFIG_UPROBES`/BTF 能力并给判定，运行后按输出里的 `probe started successfully` 给结论（失败打印首条错误）。
- 门槛：root + aarch64 内核 ≥ 5.5 + eBPF；**内核 BTF 不是必需**（本机 5.10 / `CONFIG_DEBUG_INFO_BTF=n` 实测 OpenSSL probe 正常启动），因此 BTF 只作为提示，真正的能力信号是 probe 是否启动。
- 验收：`tools/verify_v34_ecapture.sh`（真机：官方二进制 → 预检 → 对 sandbox 起 probe → **用 MCP `net_capture` 驱动一次真实 HTTPS** → 断言抓到 `ADH_NET_MARKER_v1` 请求明文与 `ADH_NET_RESPONSE_v1` 响应明文）；内核不支持时 SKIP 并给出原因。

**控制面（注入中心）**
- 注入中心（已落地，2026-09-15）：主机侧 `GET /api/backends` + Web 控制台"注入后端"页给出会话分类、Gadget 缓存/命令与设备侧后端入口（每个会话可一键判定 Zygisk/Gadget/自加载）；验收 `tools/verify_v33_backends.sh`。
- MCP 面（2026-09-16）：`backends` 工具与 REST *同源*（`daemon/src/backends.ts`）；带 `session` 参数按 agent 自身 maps 判定该进程真实存在的注入路径（`zygisk`/`frida_gadget`/`self_load`）—— AI 客户端与控制台看到的是同一份真相；验收并入 `tools/verify_v33_backends.sh`。
- Gadget 在控制台里只做"命令模板 + 检测"，一键下发仍走主机工具（daemon 无 adb）。
---


## 31. X — 手机 UI 自动化（已退役）

2026-09-23 产品范围决议：移除 ADH 自带的手机 UI 自动化能力。Host 不再提供 AccessibilityService 桥接、phone_* MCP 工具、通知读取、手机电源/音量/剪贴板控制或自动化配方；Manager 不再声明或管理 AccessibilityService / NotificationListenerService。AI Agent 需要操作连接手机时直接调用 adb。

保留范围：ADH Manager / Device Daemon 继续管理注入作用域、模块状态和目标 App 进程启停；adb 仍是 AI 与测试脚本操作手机的通道。不得因移除 UI 自动化而把 HTTP/MCP/分析搬入设备端。

---

*本文档是唯一权威功能规格（模块 A–X）。开发步骤与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。*
