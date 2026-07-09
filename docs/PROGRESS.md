# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 当前阶段

**需求定稿 / 项目启动**（尚无代码）。下一步是 v0.1 骨架。

## 已完成

- [x] 需求评审定稿：模块 A–W，通用逆向分析工具定位，明文边界观测为第一卖点
- [x] 决策已折叠进 `REQUIREMENTS.md` / `DEVELOPMENT_PLAN.md`，删除分歧层 FEASIBILITY.md（一份方案）
- [x] git 仓库初始化、`.gitignore`、`CLAUDE.md`、本进度文件
- [x] 测试设备就绪：Pixel 6 Pro / Android 16 / SDK 36 / arm64-v8a / rooted（serial `1A281FDEE003ZV`）

## 进行中

- [ ] （无）

## 下一步（v0.1 骨架）

1. 初始化 monorepo 目录：`agent/` `daemon/` `web/` `proto/` `sandbox-app/` `tests/`
2. proto v0：`Ping` / `ProcessInfo` / `MapsRegion` / `Event`
3. `idhd` 最小可运行：HTTP `/health` + WebSocket + Agent 注册
4. `libidh_agent.so` bootstrap：连 idhd、上报 pid/package、maps 枚举；**双入口**（注入器加载 + 宿主 dlopen 模拟注入）
5. `sandbox-app` 最小宿主 + 模拟注入自加载 agent（建立可验证回路）
6. Web Dashboard 空壳：显示已连接 Agent

## 验收信号（每个版本必须可 pass/fail）

- v0.1：agent 连上 idhd；maps 条目数与 `adb shell cat /proc/<pid>/maps` 一致；Dashboard 显示在线
- 后续版本验收标准见 `DEVELOPMENT_PLAN.md` §11 测试策略

## 未决 / 待办提醒

- 构建工具链选型（NDK/CMake for agent；idhd 语言：C++/Rust/Go 待定）在 v0.1 敲定后回填 `CLAUDE.md` 的 build 命令
- ART 结构 resolver 需覆盖 SDK 36（设备版本）优先

## 会话日志（倒序，简短）

- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。
