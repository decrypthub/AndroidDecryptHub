# 参考项目：ios-decrypt-helper

> 本地克隆路径：`.ref/ios-decrypt-helper`  
> 上游仓库：https://github.com/taisuii/ios-decrypt-helper

## 是什么

IOSDecryptHub — 基于 fishhook 注入目标 iOS App 的**行为监控平台**。

- 注入物：`decrypt_helper.dylib`
- 内置 HTTP 服务（默认 `:8088`）+ 嵌入式 Web 面板
- 可选：进程内悬浮窗、MCP Server（Streamable HTTP）

## 能力清单（Android 项目需继承并扩展）

| 模块 | 文件/目录 | 能力 |
|------|-----------|------|
| 加解密 hook | `src/hooks/crypto/` | digest / hmac / symmetric / asymmetric / kdf / evp |
| 文件 hook | `src/hooks/behavior/hook_file.m` | open / write / unlink / rename |
| 系统 hook | `src/hooks/behavior/hook_system.m` | dlopen / dlsym + dlsym 重定向 |
| 网络 hook | `src/hooks/behavior/hook_network.m` | NSURLSession 配对 + SSL_read/write |
| 改机 hook | `src/hooks/behavior/hook_spoof_objc.m` | UIDevice 等（仅本进程） |
| 脱壳 | `src/core/macho_dump.m` `dump_manager.m` | FairPlay Mach-O dump / IPA 重打包 |
| 反汇编 | Capstone（内嵌） | 按 bytes / 地址 / 函数反汇编 |
| HTTP | `src/server/http_server.m` | REST API + 内嵌前端 |
| MCP | `src/server/mcp_server.m` | 30+ tools |
| 日志 | `src/core/log_store.m` | 环形缓冲 + 异步落盘 + 分类计数 |
| 健康 | `src/core/dh_health.c` | fail-loud 自检 |
| 噪点过滤 | `src/core/dh_noise.m` | 系统路径降噪 |
| UI | `src/ui/` + `web/index.html` | 悬浮窗 + 全屏日志 |
| 测试 | `sim_uitest/` `tests/` | 交互式宿主 + MCP 测试脚本 |

## iOS 局限 → Android 扩展映射

| iOS 有 | Android 额外要做 |
|--------|------------------|
| CommonCrypto / EVP hook | + Java Cipher/MessageDigest/Mac（LSPlant） |
| fishhook import hook | + inline hook + PLT/GOT + syscall + QBDI |
| Mach-O dump | + dex dump + InMemoryDex + oat/vdex + ELF so 重组 |
| 无 | Dex 索引 / smali / xref / 按需反编译 |
| 无 | ClassLoader 追踪 |
| 无 | Java 方法级 trace |
| 无 | 三层架构（Agent / idhd / Web） |
| HTTP 在 dylib 内 | HTTP/MCP/DB 移到 idhd 守护进程 |

## 关键工程实践（建议移植）

1. **fail-loud 健康监控** — hook 失败、服务异常必须可见
2. **事件分类 + O(1) 计数** — 悬浮窗/Web 统计不遍历
3. **异步日志落盘** — 不阻塞被 hook 调用方
4. **dlsym 重定向** — 捕获函数指针间接调用
5. **网络↔加密关联** — `correlate_request` 时间窗分析
6. **噪点过滤 + 噪声板** — 系统噪音可查看可反馈
7. **MCP 与 HTTP 同源数据** — 避免两套逻辑
8. **交互式测试宿主** — 每个 hook 有确定触发按钮
9. **审查日志** — 便于 Issue 反馈（不含敏感明文）

## 不要照搬的部分

- **不要把 HTTP/MCP/DB 放在 Agent so 里** — Android 版用 idhd 守护进程
- **不要假设 only import slot hook** — Android 需多 backend
- **不要只做 Mach-O** — Android 主线是 DEX + ELF
