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

## 进行中

- [ ] v0.2 Dump Engine

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

- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。
