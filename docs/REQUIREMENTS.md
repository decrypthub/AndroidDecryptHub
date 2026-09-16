# ADH (Android DecryptHub) — 功能需求说明

> **产品定位**：**通用 Android 运行时逆向分析工具** — 不是 demo，也不是「手机版 jadx」。
> 适用于任意 App 的运行时观测/dump/hook/trace，并**对高对抗目标（反调试、root/签名检测、代码混淆、加密传输）具备实战能力**。
> **使用范围**：授权范围内的逆向调查与运行时分析；非法律取证，亦非面向未授权目标的规避工具。
> **参考项目**：[taisuii/ios-decrypt-helper](https://github.com/taisuii/ios-decrypt-helper)（IOSDecryptHub）
> **本文档范围**：本文档是**唯一权威功能规格**（模块 A–X）。开发步骤与排期见 `DEVELOPMENT_PLAN.md`。

---

> **⚠️ v2.0+ 加固重构（当前工作面）**：模块 A–W 的能力在 v0.1–v1.0 已全部"跑通一遍"，X 为新增的可选手机自动化面。
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
└── W. 注入后端（Zygisk + Gadget 直载 + Xposed 桥接 + 模拟注入）
```

以下逐模块描述「做什么」「看到什么」「边界在哪」。

---

## 4. A — 进程接入与会话管理

### 4.1 Agent 注入

**功能**：将 `libadh_agent.so` 加载到目标 App 进程。详细的后端与打包见**模块 W**。

**注入方式**（覆盖 root 与非 root 两条路径，用户按环境选择）：

- **Root 路径 — Zygisk 插件**（主线，early inject）：随 Zygisk 模块在 zygote fork 后早期加载，抢在目标反调试布防之前。
- **Frida Gadget 直载**：通过目标进程内的 `load_library` 加载官方 Gadget，运行 Frida JS hook，无需改写目标 APK。
- LSPosed / Xposed 桥接加载（有框架时）。
- **模拟注入**（开发/CI 主路径）：`sandbox-test-app` 自身 `dlopen` 加载 agent，无需真机对抗即可验证全部模块。

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
| `GetByteArrayElements` / `SetByteArrayRegion` | 数组数据摘要 |
| `FindClass` | class 名 |

### 8.6 Direct Syscall 覆盖（分级）

灰产/加固常用直接 `svc` 指令绕过 libc/PLT hook。不承诺完全拦截，按级别收口：

| 级别 | 能力 | 边界 |
|------|------|------|
| L0 声明 | libc/PLT/inline hook 可能漏 direct syscall；UI 明确标注事件来源 | 默认 |
| L1 检测 | 扫描可执行段中 `svc #0` 指令热点，识别高频 syscall wrapper，输出疑似绕过 libc 的函数列表 | 静态，安全 |
| L2 观测 | 对指定函数/地址范围用 DBI 记录 syscall 前后寄存器，与文件/网络事件弱关联 | 需指定范围 |
| L3 高风险实验 | SVC patch / seccomp-unotify / PTRACE_SYSEMU | 仅 sandbox/授权环境，非默认产品能力 |

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
| **Injection Center** | 注入后端选择、Zygisk/Gadget/Xposed/模拟注入、agent 加载状态（模块 W） |
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

### 20.4 授权声明

- 仅限授权安全测试与自有 App
- 脱壳/分发受版权保护的应用可能违法
- 文档与 UI 中明确提示

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
- Zygisk + Gadget + Xposed + 模拟注入（模块 W）
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
Zygisk / Gadget / Xposed 多注入路径。
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

### 26.1 诊断层

- 检测目标是否存在：hook 冲突、maps 自扫描、ptrace 占用、seccomp 限制、linker namespace 限制、inline-hook 序言校验、Zygisk/框架痕迹检测
- 对每个 hook 后端给出可用性检测结果
- 发现目标行为分叉（注入后闪退/走不同分支）时生成诊断事件
- 生成**兼容性报告**：哪些能力可用、哪些被限制、哪些可能触发崩溃

### 26.2 韧性层（授权环境，默认关闭）

- **early-inject**：抢在目标反调试布防之前完成加载与关键 hook（配合 W 的 Zygisk 后端）
- **与目标 ptrace 自附加共存**：目标 `PTRACE_TRACEME` 占位时的采集策略
- **最小侵入模式**：只启用 maps/dex/classloader/crypto 等低痕迹模块，关闭高痕迹 hook
- **hook 自校验对抗**：应对目标周期性校验函数序言字节、检测 GOT 改写

### 26.3 边界

- 不承诺绕过所有反调试/反注入
- 默认不自我隐藏
- 不提供面向未授权目标的通用规避能力
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

## 29. V — 反分析行为观测

**目标**：观测**目标 App 自身**为检测分析环境所做的行为（与模块 S 互为镜像：S 让我们活下来，V 让我们看清对方的防御）。

### 29.1 检测类别与观测点

| 类别 | 目标常用手段（hook / 观测点） |
|------|------------------------------|
| 调试检测 | `ptrace(PTRACE_TRACEME)`、`/proc/self/status` TracerPid、`Debug.isDebuggerConnected`、JDWP 检查、fork+ptrace、时间差检测 |
| Root 检测 | `su` 路径 `access/stat`、Magisk 痕迹、`Build.TAGS` test-keys、RootBeer、PackageManager 查已知 root 包、`getprop ro.debuggable/ro.secure` |
| 签名检测 | `PackageManager.getPackageInfo(GET_SIGNATURES / GET_SIGNING_CERTIFICATES)`、`checkSignatures`、签名哈希比对 |
| 模拟器检测 | `Build.*` 字段、`/proc/cpuinfo`、传感器、telephony、`qemu` 属性 |
| 完整性/注入检测 | 读自身 maps、扫 frida/xposed、`.so` 哈希校验、GOT/序言校验 |

### 29.2 输出

- `DETECTION` 事件：类别、手段、目标读到的值/结果、调用方、调用栈
- **检测手段清单**：该 App 一共用了哪些检测、各触发几次、在什么时机（启动/登录/关键操作）
- **行为分叉标注**：检测命中后目标是否改走分支（配合 S 的分叉诊断）

### 29.3 价值

给调查员一张对方防御地图：「这个 App 启动时用 3 种方式查 root、登录前查签名」，据此决定用哪种注入路径与最小侵入配置。

---

## 30. W — 注入后端与打包

**目标**：把「能否注入真实目标」这个高风险变量，与「每个功能模块是否正确」解耦，覆盖 root 与非 root，并保证 CI 可持续验证。

### 30.1 注入后端

| 后端 | 环境 | 说明 |
|------|------|------|
| **Zygisk 插件** | root（Magisk） | 主线，zygote fork 后 early-inject，配合 S 韧性；配套 **ADH Manager** 管理作用域白名单（`/data/adb/adh/scope.json`） |
| **Frida Gadget**（可选，默认关） | 非 root / root | 官方 Gadget so 由 agent `dlopen` 进目标进程，运行 Frida JS hook；按版本/ABI 下载 + sha256 固定；高开销（~25 MB so、额外 maps 与线程），只有显式调用才启用 |
| LSPosed/Xposed 桥接（可选，默认关） | 有框架（Vector/LSPosed） | 薄 Xposed 模块复用框架加载，不 vendor GPL 代码 |
| **模拟注入** | 无需 root | sandbox 自身 `dlopen` 加载 agent（开发/CI 主路径） |

### 30.2 打包交付物

- `libadh_agent.so`（arm64-v8a 主线，设备 ABI）
- Zygisk 模块包（root 版）+ ADH Manager APK（作用域：选哪些 App 注入）；另提供 Magisk 可直接安装、自动安装 Manager 的组合包
- Gadget 工具链：`tools/fetch_frida_gadget.sh`（官方 release，按版本/ABI + sha256，`--list`/`--print-url`）、`tools/compile_frida_script.sh`（Frida 17 起语言桥移出 runtime，用 esbuild + `frida-java-bridge` 打包）、`tools/load_frida_gadget.sh`（落盘 → `load_so` dlopen → 等 `frida-gadget` 线程 → 可选 `--marker` 断言脚本真的跑通）
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
- Companion 应设置 `DLCLOSE_MODULE_LIBRARY`，post-specialize 后卸载自身映射；agent `.so` 保持加载服务会话。
- 模块作者固定为 `decrypthub.com`；root 管理器中的模块描述只显示“等待重启 / 运行中 / 未加载”这类简洁工作状态，不展示内部路径、架构说明或开发备注。
- ADH Manager 的设备控制能力只限注入作用域、模块状态，以及经 Device Daemon 终止/重启目标应用进程；界面默认中文，已有系统语言资源时跟随系统语言，并跟随系统深浅色主题。首页保留运行状态、Web UI 访问地址、作用域入口和版本信息。Manager 可直接探测 Host ADH Daemon `/health` 来显示并打开局域网优先的 Web UI 地址，但不得把该请求转交 Device Daemon，也不得在设备侧承载 HTTP 服务或分析逻辑。目标进程启停/打开必须走受认证 AIDL（`controlPackage`），协议 v6 增加 `open`；协议 v7 增加自动化 AccessibilityService 的读取/显式启停，Manager 提供用户开关；用户开启后写入 `/data/adb/adh/automation.enabled`，Device Daemon 在服务被系统清理时自动修复。协议 v8 增加 root 屏幕状态/唤醒/非安全锁屏解除。Manager 不得自己调用 `am`/`su`。不得对 Manager、Device Daemon、`system_server`、System UI 或 `android` 执行终止/重启。
- “运行中”必须来自本次启动中 Zygisk 实际加载模块的标记，不能仅以模块目录存在作为成功依据；标记由 root companion 写入，启动时先清除旧状态。
- Manager 不得直接调用 `su` 或访问 `/data/adb`。模块以 root `app_process` 启动 Device Daemon，Manager 仅通过 AIDL Binder 读取状态和作用域；daemon 必须校验调用 UID、`com.adh.manager` 包归属和构建时固定的 APK 签名证书。
- Binder 交接入口只接受 UID 0 发布，并核对 AIDL descriptor；Manager 必须区分 Device Daemon 未连接、模块未安装、模块已安装但未加载、运行中四种状态。服务未连接时不得用空配置冒充真实作用域，也不得显示“模块未安装”。

### 30.5 可选注入后端（Gadget / LSPosed）— 默认关闭

两个后端都**不是默认路径**，必须显式调用；默认注入仍是 Zygisk（root）与模拟注入（CI）。两者都是开源生态里现成的加载机制，ADH 只借它把 agent/JS hook 送进目标，不把分析与存储搬进目标进程（架构红线不变）。

**Frida Gadget（已落地并真机验证，2026-09-15）**

- 只走官方 release：`tools/fetch_frida_gadget.sh <version|latest> [--abi arm64] [--list] [--print-url]`，缓存到 gitignore 的 `agent/third_party/frida/<version>/<abi>/`；压缩包 sha256 固定在 `tools/frida_gadget_versions.json`（离线可复现，切换版本只换参数）。
- **Frida 17 起语言桥不再内置在 Gadget runtime**：`Java.perform()` 这类 hook 必须先打包。`tools/compile_frida_script.sh` 用 esbuild 把 hook 与 `frida-java-bridge` 打成单文件（经典写法自动注入 `globalThis.Java`；已是 module 写法则原样打包；已打包文件幂等直通）。**不用 `frida-compile`**：其 CLI 依赖原生 `frida` 绑定，Windows 上要 MSVC。
- `tools/load_frida_gadget.sh <hook.js> [...]`：官方 so → 按需打包 → 落进 `<pkg>/code_cache`（app uid + selinux ctx；配置名必须是 `<soname>.config.so`，否则 Gadget 静默回退默认 listen）→ `POST /api/agent/load_so` dlopen。**Gadget 由构造函数自启动，没有入口符号可调**，`symbolFound` 仅信息性；随后轮询 `/proc/<pid>/task` 等 `frida-gadget` 线程，可选 `--marker` 断言脚本真的跑到（只有"线程起来"不等于脚本跑通）。
- `--watch` 写 `on_change: reload`：改 `code_cache/adh_hook.js` 即热重载，无需重启目标进程。
- 验收：`tools/verify_v30_fridagadget.sh`（真机：官方 gadget → dlopen → 打包后的 Java hook 写 marker；gadget 或打包依赖缺失时 SKIP，因为两者都在 gitignore 缓存里）。实测开销：so 25,220,848 B、目标进程 +9 行 maps、+2 个线程。

**LSPosed/Xposed 模块（slice 1 已落地并真机验证，2026-09-15）**

- 形态：`injector/xposed/` 薄加载器 APK（`com.adh.xposed`）。职责只有"框架已加载的前提下把 agent 送进目标进程"，**不含任何分析能力**；hook/trace/dump/索引/HTTP/MCP/DB 仍在 Host ADH Daemon。
- **不 vendor 上游代码**：`injector/xposed/api-stub/` 是自己写的 compile-only ABI 声明（`IXposedHookLoadPackage` / `XC_LoadPackage.LoadPackageParam` / `XposedBridge.log`），`compileOnly` 依赖，运行时由框架提供真类。静态验证过产物 dex 里**只有** `Lcom/adh/xposed/AdhXposedEntry;` 一个类定义。
- 载入方式：`System.loadLibrary("adh_agent")`；加载失败即报错，不再做第二套路径扫描兜底。之后 agent 自己连 Host ADH Daemon（`adb reverse` → 8761）。
- 关键设备事实（决定打包布局）：Vector 给模块的 `nativeLibraryDirectories` 是 **`base.apk!/lib/arm64-v8a`**，所以 agent `.so` 必须以**未压缩**形式留在 APK 里（`useLegacyPackaging=false` + `extractNativeLibs=false`）；"安装时解压"的旧布局下 `System.loadLibrary` 必然 `UnsatisfiedLinkError`（真机日志已确认）。模块 dex 由 `InMemoryDexFile` 载入、APK 不进 maps，所以 `maps` 兜底只对解压式布局有意义。
- 策略（slice 1）：只进 scope 内应用的**主进程**；永不进 `android` / `com.android.*` / `com.google.android.gms` / 模块自身；**只对 ADH 自己的测试宿主**（sandbox / Manager）写验收 marker，绝不在第三方目标里留文件。
- 工具链：`tools/build_xposed.sh`（把 agent `.so` 打进模块 → `injector/xposed/dist/adh-xposed.apk`）、`tools/install_xposed.sh`（root 安装 + `vector-cli modules enable` + `scope set`；`--disable` 逐条 `scope rm` 再关模块 —— 空参数的 `scope set` 在 Vector 2.2 会抛 NPE 且不清空）、`tools/verify_v31_xposed.sh`（真机验收，并**恢复测试前状态**，默认回到关闭）。
- 真机证据（靶子 `com.adh.manager`，不是会自加载 agent 的 sandbox）：marker `ADH_XPOSED_OK pkg=com.adh.manager ... agent=1`；框架日志 `Loading legacy module com.adh.xposed` → `Loading class com.adh.xposed.AdhXposedEntry`；Host daemon 侧出现 `entry=jni_onload` 在线会话且能真的执行命令（模块枚举 533 条）。
**eCapture（可选，root + eBPF，2026-09-16 真机验证）**

- 用途：eBPF uprobe 在 `SSL_write/SSL_read` 边界读明文，**不需要证书/代理**，与 agent 的 GOT hook 互补（同一次请求里 agent GOT hook 可能 0 命中，eCapture 仍抓到请求+响应明文）。
- 只走官方发布：`tools/fetch_ecapture.sh`（版本固定在 `tools/ecapture_versions.json`，sha256 取自发布自带的 `checksum-<ver>.txt`），缓存于 gitignore 的 `agent/third_party/ecapture/<ver>/<abi>/`。
- 运行：`tools/ecapture_capture.sh --package <pkg> | --pid N [--seconds N]`；固定使用已验证的 text 模式。`--preflight-only` 输出 root/内核/`CONFIG_BPF_SYSCALL`/`CONFIG_UPROBES`/BTF 能力并给判定，运行后按输出里的 `probe started successfully` 给结论（失败打印首条错误）。
- 门槛：root + aarch64 内核 ≥ 5.5 + eBPF；**内核 BTF 不是必需**（本机 5.10 / `CONFIG_DEBUG_INFO_BTF=n` 实测 OpenSSL probe 正常启动），因此 BTF 只作为提示，真正的能力信号是 probe 是否启动。
- 验收：`tools/verify_v34_ecapture.sh`（真机：官方二进制 → 预检 → 对 sandbox 起 probe → **用 MCP `net_capture` 驱动一次真实 HTTPS** → 断言抓到 `ADH_NET_MARKER_v1` 请求明文与 `ADH_NET_RESPONSE_v1` 响应明文）；内核不支持时 SKIP 并给出原因。

**控制面（ADH Manager/Device Daemon 驱动 Xposed）**
  AIDL 协议 v5 新增 `getXposedStatus` / `setXposedEnabled` / `setXposedScope`，Manager 的 Scope 页有对应卡片；ADH 允许名单在保存时镜像进框架 scope（启用状态下），所以"哪些应用"仍然只在 Manager 一处配置。
  同一个代码路径还导出了 root-only 一次性 CLI（`--xposed-status|--xposed-enable|--xposed-disable|--xposed-scope`），供运维与 `tools/verify_v32_backend_control.sh` 使用（无需 Manager UI、无需重启）。
  两个框架怪癖已写进实现：`scope set <module>` 不带应用会抛 NPE（清 scope 必须逐条 `scope rm`）；`scope set` 会**隐式启用**模块，所以调用方若要保持"关闭"必须显式再关一次。
- 注入中心（已落地，2026-09-15）：主机侧 `GET /api/backends` + Web 控制台"注入后端"页给出会话分类、Gadget 缓存/命令与设备侧后端入口（每个会话可一键判定 Zygisk/Xposed/Gadget/自加载）；验收 `tools/verify_v33_backends.sh`。
- MCP 面（2026-09-16）：`backends` 工具与 REST *同源*（`daemon/src/backends.ts`）；带 `session` 参数按 agent 自身 maps 判定该进程真实存在的注入路径（`zygisk`/`xposed_module`/`frida_gadget`/`self_load`）—— AI 客户端与控制台看到的是同一份真相；验收并入 `tools/verify_v33_backends.sh`。
- Gadget 在控制台里只做"命令模板 + 检测"，一键下发仍走主机工具（daemon 无 adb）。
---


## 31. X — 可选手机自动化（UI 观测与执行）

**目标**：在用户明确开启后，让 Host ADH Daemon / MCP 能观察并操作授权 App 的界面，为 AI 手机控制提供稳定、可审计的执行面。默认关闭。

### 31.1 分层

```text
Host ADH Daemon / MCP  →  自动化 TCP 8763（loopback + adb reverse）  →  Manager AccessibilityService
                                                                    ├─ 控件树
                                                                    └─ 截图 + 归一化坐标动作
```

- 设备侧只允许 `:manager` 中用户启用的 `AdhAutomationAccessibilityService` 作为客户端拨入 Host，不监听端口、不承载 HTTP/MCP/索引/分析。
- agent `.so` 不参与 UI 自动化；它以事件/单步方式补充目标进程内部状态，匹配与等待逻辑在 Host 侧完成（见 §31.3 规则 5）。

### 31.2 MCP 面

| 工具 | 说明 |
|---|---|
| `automation_status` | 只读状态：Host 开关、桥接连接、设备能力、允许包名；不能开启自动化 |
| `phone_observe` | 优先返回控件树；树为空或非语义时返回压缩截图；支持 `maxDepth`、`interactiveOnly`、truncation 标记；`mode=text` 把同一棵树渲染成紧凑纯文本（含 `snapshotId` 与 ref，可直接用于 `phone_act`），用于节省 AI 上下文 |
| `phone_find` | 按 text/resourceId/contentDescription/交互标志返回紧凑节点列表，不传整棵树 |
| `phone_wait` | 等待三类条件竞速命中：控件/状态、agent 事件、进程内捕获；可对虚拟列表执行 scroll-until-found（`scrollMode=gesture` 用真滑动代替 `ACTION_SCROLL`，用于翻页器/自绘列表，`axis` 选纵向或横向）；`afterCaptureId`/`afterEventSeq` 游标或 `lookbackMs` 消除两次调用间的信号丢失 |
| `phone_act` | `tap` / `long_press` / `swipe` / `scroll` / `set_text` / `global back/home/recents`；优先 selector 或 `snapshotId+ref`，兜底归一化坐标；`set_text` 的 `text` 是输入内容而非目标过滤条件 |
| `phone_app` | 通过包名 `open` / `stop` / `restart` 授权应用；新 daemon 走 root Device Daemon，旧 daemon 保留 Accessibility fallback。`open`/`restart` 必须**验证前台**：未到达时返回 `verified:false` + 实际前台包 + 处理提示（OEM 确认框吞掉启动时必须点名该包） |
| `phone_device` | `status` / `wake` / `unlock` / `lock`；安全锁屏凭据不绕过 |
| `phone_task` | 单次 MCP 调用内执行有界步骤序列（≤30 步），步骤间可用 `{{id.path}}` 引用前序步骤的结果（如把 `find` 得到的 `snapshotId`/`ref` 直接喂给 `act`）；每步支持 `retries` 与结构化失败输出 |
| `phone_skill` | 保存 / 列出 / 运行 / 删除命名手机配方（skills）：步骤受校验（仅 observe/find/wait/act/app/device，≤30 步）、不可嵌套、无 shell；配方可声明 `params`（≤10）并由步骤以 `{{input.<name>}}` 引用，运行时用 `inputs` 传值、`defaults` 兜底，缺参数 fail-loud；运行复用 `phone_task` 的执行器、allowlist 与重试语义 |

### 31.3 兜底规则

1. 控件树包含文本、contentDescription、resourceId、bounds、可执行动作和 snapshot-bound ref。
2. 控件树为空、不可操作或目标页面为自绘内容时，截图作为第二感知层返回（JPEG，默认最长边 1280；MCP 通过 image content 返回，不持久化原图）。
3. 视觉动作只能使用归一化坐标或显式像素坐标；ref 只能用于对应 snapshotId，动作完成后 ref 失效。
4. `FLAG_SECURE` 等受保护窗口截图失败必须 fail-loud 返回 `screenshot_failed` / `screenshot_unsupported`，不得伪造画面。
5. 进程内信号等待与控件条件竞速，命中即返回；同一类过滤为 AND。事件用 `agentEvent`（精确 type）/ `agentEventContains`（JSON 子串），捕获用 `captureCategory`（crypto/net/file/system）/ `captureContains`（在解码后的 UTF-8 文本 + 元数据上做子串匹配）。`phone_observe`/`phone_find`/`phone_act` 返回 `cursor`（`phone_act` 另有动作派发前的 `cursorBefore`）；把游标传给 `afterCaptureId`/`afterEventSeq` 只匹配更新的记录（不看时间戳），避免信号在两次 MCP 调用之间到达而丢失。agent 与 Host 的连接由 agent 自己维持：Host 重启（每次升级都会发生）后 agent 必须自行重连，目标进程不得失联；纯信号等待不依赖无障碍服务。信号等待超时时必须带回窗口内的实际信号摘要（`saw.captures`/`saw.events` + `totals`）与当时的 `cursor`，让 AI 能改写过滤条件而不是盲猜。
6. 同一个 JSON 字段既可能是目标也可能是负载：`set_text` 的 `text` 是"要写入的值"，不得当作选择器（否则要求控件当前文本已等于待写入值，永远选不中）——隐式选择器按动作剔除该键，显式 `selector:{text:...}` 仍然有效。选择器解析允许有界重试（≤3 次 / ~500ms），以吸收动画与列表滚动造成的瞬时抖动。

7. `phone_task`/`phone_skill` 的步骤可引用**前序步骤**的结果：`{{stepId}}` 取整份结果，`{{stepId.path.to.0}}` 取深层值（数组用数字下标）；整串是模板时保留原类型，字符串内嵌则转字符串。只能引用带 `id` 且已完成的前序步骤——未知名与缺失路径必须 fail-loud（`template_unknown_step` / `template_path_missing`），不允许静默替换成空值。它让"find 得到 ref → 立刻 act"在一次调用内完成，避免 ref 在两次调用之间过期。保留命名空间 `input`：`phone_skill` 的配方用 `params` 声明参数，运行时 `inputs` 传值（`defaults` 可兜底），缺失时返回 `skill_missing_input` 且不执行任何步骤。

8. 动作失败必须**自带现场**：`phone_act` 的选择器解析失败、ref 过期、手势被窗口拒绝等错误都要附上当前屏幕的紧凑文本视图（`--- current screen ---`）与前台包；若现场本身读不到（例如前台是不在 allowlist 的系统弹窗），则附上"读不到的原因"，不得掩盖原始错误。等待类失败另有 `saw` 摘要（见规则 5）。

### 31.4 开关与安全

- Host `settings.automation.enabled` 默认 `false`；关闭时 MCP `tools/list` 不返回 `phone_*`。
- 自动化必须同时满足：用户在 Android 无障碍设置中启用服务、Host 开关打开、当前前台包在独立 allowlist 内。
- 不复用注入 scope；不提供任意 shell；系统弹窗/权限页/支付页默认不自动授权。
- skills 只是主机侧保存的配方：不新增权限、不能嵌套 skills、不能携带 shell，写入 `adhd-data/skills.json`（不进版本库）；文件被篡改或损坏时丢弃条目而不是执行。
- 截图可单独关闭；设备侧再次校验 allowlist，不能靠 MCP 参数绕过。

### 31.5 验收

`tools/verify_v36_automation.sh`：MCP 工具可见性、控件树、`phone_find`、selector/ref 点击、`phone_wait`、agent 信号等待（游标 + 明文解码 + fail-loud 超时）、视觉截图兜底、归一化坐标点击、滑动、系统通知栏读取、`set_text` 真输入并读回（后两项仅在设备装了对应启动器/搜索组件时执行，否则 SKIP）、`phone_skill` 存/列/跑/删与非法步骤拒绝、`phone_observe mode=text` 紧凑视图及其 ref 可直接驱动动作、`phone_app restart` 前台验证、agent 在 Host 重启后自行重连（`tools/verify_v37_agent_reconnect.sh`，同 pid 新会话 + 命令可达）、`phone_task` 步骤链式引用（`{{id.path}}` 命中与未知名 fail-loud）、`phone_wait` 手势滚动（启动器翻页实测生效）；桥接未启用（或没有在线 agent 会话）时对应段落 SKIP。注意 `verify_v31_xposed.sh` 为让框架重新注入会 `force-stop com.adh.manager`，而 force-stop 会连带给 Manager 的无障碍服务摘牌 —— 该脚本必须记录并在收尾时还原它，否则回归本身会关掉手机自动化。真机证据见 `docs/PROGRESS.md`。

---

*本文档是唯一权威功能规格（模块 A–X）。开发步骤与排期见 `DEVELOPMENT_PLAN.md`，跨会话进度见 `PROGRESS.md`。*
