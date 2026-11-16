# P0：作用域、设置与非破坏性初始化

2026-11-16。本文描述已实现的 Host 源码行为；未部署到当前运行服务。对应审计 F01、F02、F04；设备身份/多设备控制、任务控制权与 USB/LAN 统一仍按后续阶段实施。

## 作用域更新

`writeScopePackages` 写入前重新读取完整 scope.json，只替换 packages。现有 policy（含 false 开关、暂不在 scope 的旧条目）和未知顶层/嵌套字段保持不变；版本/模式以最新文档为准。输入缺失、不可读或损坏时拒绝更新。

默认 ADB writer 使用独立上传/暂存文件，在 root 目录设 owner/mode/SELinux label 后 rename 替换，不再 cp 覆盖正在读取的配置。回读核对完整 JSON，而非只核对包名单。ScopeIO 注入点用于测试，产品调用继续使用既有 ADB 路径。

本轮没有改手机协议、Kotlin/C++ 常量或 Manager 的写入方式；不能据 atomic rename 宣称已解决跨手机/Host 的并发覆盖。共享 revision/CAS 属于后续控制层改造。

## 设置统一入口

MCP `settings(action=patch)`、HTTP `POST /api/config` 和 `POST /api/settings/import` 全部调用 `settings_service.patchSettings`：

1. 在独立候选配置中规范化 patch，同一进程的提交排队串行执行。
2. 临时文件写入、fsync、rename 原子保存；保存失败不发布内存状态、不操作目标。
3. 发布配置；涉及 enabled/目标模块时，等待所有相关目标的实际 capture 安装/停止结果。
4. 返回 persisted、runtimeApplied、逐目标 runtime.targets、错误和延后生效字段。保存成功但目标失败时 ok=false、persisted=true；HTTP 为 502，MCP 标 isError。保存失败为 HTTP 500，非法配置为 400。

输出过滤即时作用于后续入库；ui/保留策略变更不重装 Hook。startup 对未来 hello 生效；autoDumpDex 对未来自动采集启动生效，响应 deferred 说明这一点。当前全局 capture.enabled 的作用范围保持原语义，目标级授权和接管在后续阶段收敛。

保留策略只保存配置并返回 maintenanceRequired，不在设置请求中删除历史记录。所有 MCP 工具返回 ok=false 的结果也会携带 isError=true，避免把业务失败包装成工具成功。

## 初始化与存储

- 导入 state、service、MCP/HTTP 模块不建目录、不重放历史、不打开 SQLite、不清理数据、不访问设备或监听端口。
- 正常可执行入口 index.ts 在监听前调用 `initializeHost()`；恢复设置、事件、工件与有界内存捕获视图。恢复幂等，不按年龄/数量裁剪磁盘、不改来源 sidecar；缺少包来源时仅补内存视图。
- DEX SQLite 在实际索引操作时按需打开。已有损坏缓存不会因工具注册表被导入就被重建。
- 新建 dump/捕获写入保留磁盘历史；内存视图仍有界，并记录淘汰。启动和会话定时 sweep 不回收工件。捕获 ID 在新 drain loop 启动时接续已恢复历史。
- 未设环境变量时保留旧布局：仓库 captures/ 与 adhd-data/。设置 ADH_DATA_DIR 后，dump 默认位于该根的 captures/，不再穿透到仓库 captures/。ADH_CAPTURES_DIR 可显式指定独立工件根。
- **旧外置 DATA_DIR 用户升级**：旧版本的 dump 可能仍在仓库 captures/。新版不会移动或删除它们；如需继续读取旧目录，升级入口显式设置 ADH_CAPTURES_DIR 为旧目录，再另行安排数据迁移。不要为了测试而指定操作者旧目录。

新测试入口会移除继承的 ADH_DATA_DIR/ADH_CAPTURES_DIR，再给每个测试进程分配临时默认根。手工 import 只获取注册表，不再自动加载历史；需要完整历史的独立 Host 客户端应显式调用 initializeHost。

## 显式维护

以下接口以更新后的 Host 为前提，本轮未在当前现场执行：

```text
MCP settings {"action":"maintenance"}                         # 预览
MCP settings {"action":"maintenance","dryRun":false,"confirm":true}  # 执行
GET  /api/maintenance                                       # 预览
POST /api/maintenance {"dryRun":false,"confirm":true}        # 执行
```

默认 dryRun=true。显式 dryRun=false 但没有 confirm=true 时拒绝执行。预览返回当时策略下的工件数量/字节、捕获逐包数量与错误，不返回捕获内容；执行时按当前策略重新计算，报告实际删除数和失败。它不是跨请求事务或任务 pin 系统，P1 以后再增加持久任务与证据引用保护。

本轮移除了启动、定时 sweep、新 dump、设置保存及捕获追加路径的磁盘自动裁剪。磁盘保留策略需通过上述维护入口显式执行；内存 ring/视图容量继续受限。已有 REST data/clear 是另一条显式删除入口，未改变其原有语义。

## 验证与边界

新增作用域 fake IO、MCP/面板/导入真实 HTTP handler + fake agent、临时文件子进程测试。设备子进程在业务模块导入前被替换/拒绝；HTTP 仅监听系统分配的 loopback 测试端口。旧捕获、旧工件、损坏 SQLite 均为生成的合成数据。

覆盖策略/未知字段保留、损坏输入拒写、完整回读、三入口启停/失败/保留策略一致、原子保存失败不改运行状态、并发设置提交、纯导入与幂等恢复保持文件字节/mtime、显式维护确认、新工件不清历史、新捕获 ID 不重复。Host 回归与类型检查结果见 PROGRESS.md；未运行真机注入/升级验收。

本轮最终信号：新增隔离回归 25/25，完整 Host 回归 489/489（0 fail / 0 skip），typecheck rc=0，v71 tools=91/problems=0，提交差异空白检查通过。
