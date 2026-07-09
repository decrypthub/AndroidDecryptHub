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

- [ ] v0.2 Dump Engine — **核心已完成并验证**，剩 so 重组 + dex header 修复

### v0.2 已完成并验证（tools/verify_v02.sh + verify_v02_dump.sh，均 exit 0）

- [x] idhd↔agent 命令通道（`cmd`/`cmdResult`，pending-promise + 超时；每 session socket）
- [x] 按需全量 maps `GET /api/process/maps`（2599 段，前 40 与内核 verbatim 一致）
- [x] `memory.read` `POST /api/memory/read`（/proc/self/mem pread + base64；读到真实 ELF 头）
- [x] dex/ELF magic 扫描 `GET /api/memory/scan_magic`（dex/cdex/elf/zip/oat/vdex 全命中；分块重叠、边界跨块、/dev 跳过、上限）
- [x] `memory.search` `POST /api/memory/search`（hex/text 模式）
- [x] region dump + sha256 去重 `POST /api/memory/dump` + `/api/dumps[/download]`（对 mock dex **字节级 sha256 校验通过**，kind 按 magic 推断，重复 dedup）
- [x] sandbox 增 mock dex（direct ByteBuffer，确定性内容，AntiDumpMock 雏形）

### v0.2 剩余

- [ ] so 重组：按 ELF program header 从内存段重建可用 .so（文件型直接复制 / 内存型拼接修 header）
- [ ] dex header 修复（file_size/checksum/signature）——为 v0.3 ART 抽取铺路
- [ ] Web：Memory Explorer / Dump Center 最小页

## 下一步

1. v0.2 收尾：so 重组 + dex header 修复（+ 各自 verify 脚本）
2. → v0.3 ART 结构级 Dex 捕获（ClassLinker/DexCache 遍历，SDK 36 resolver）

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

- 2026-07-10 (loop#1)：v0.2 Dump Engine 核心完成——命令通道 + maps/read/scan_magic/search/dump+dedup，全部真机验证（dump 对 mock dex 字节级 sha256 校验）。3 次提交。
- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。v0.1 端到端验证。
