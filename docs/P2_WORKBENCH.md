# P2：人类任务工作台（2026-11-16）

任务窗口读取 P1 执行层保存的任务和结果。人在窗口里查看、搜索、下载结果。AI 通过 CLI / MCP 提交任务，任务控制也走这两个入口。

本次源码位于独立 worktree，原工作目录保持 P1 提交。原因是运行中的 Host 会按需读取 public 静态文件：仅保持 Node 进程不重启，仍不足以保护刷新中的现有面板。P2 没有部署到当前实例，没有更改真机或 USB/LAN 协议。

## 人类工作流

- 现场页从「任务」打开列表，也可直接访问 `/workbench`。现场的「算法设置」显示当前应用，六类算法按包名分别保存。首次独立设置前沿用已有的 Host 默认值。全部关闭也会保存，应用重连会读取自己的设置。程序化 Hook 方案由 MCP 和配套 `adh` CLI 管理。
- 每次勾选只提交包名和改动的一项。只有该应用的在线会话收到命令，正在使用 Hook 方案的会话保留方案策略。算法开关和一键脱壳使用普通面板身份，并经过共享操作层的版本和控制权检查。其它配置写入使用操作员凭据。
- 任务列表支持搜索、负责人和状态筛选及分页。任务与其中的操作显示标题、状态和时间。AI 提交的操作随原任务展示，点击「查看结果」按需读取。
- 已保存的原始结果和晚到结果均可下载 JSON。页面最多预览 120000 字符，下载包含全部已保存内容。Host 只保存摘要时，页面会标明。任务标题和结果以纯文本显示。
- 操作员身份、控制代次、意图键和副作用步骤可通过 `adh tasks get` 检索。

## P2 初版配置编辑与冲突处理

下面记录 P2 初版的配置编辑交互。`workbench-model.js` 中的草稿比较和校验仍有独立回归测试。

配置表单覆盖当前 Settings 的视图、捕获/类型/模块、保留策略和启动策略，继续调用共享 settings 服务。导入只合并进草稿；提交前校验已知字段、类型、范围、包名和符号，拒绝未知或会被静默过滤的值。导出的是最后读到的 Host 配置，未提交草稿不会混入导出。

每份草稿独立保存编辑时的 Host 版本，不受后台任务刷新影响。提交只发送实际修改的字段；不会把整份旧配置覆盖回去。例：编辑时 displayCap=300，人类改成 411；同时 AI 将该值改为 377 并设置 fileModule。旧版本提交被拒绝，草稿保留，界面并列显示“编辑时 / 当前值 / 草稿意图”。人类选择“保留修改，按最新版本重新核对”后，仅保留本来修改的 displayCap，未修改的 fileModule 采用 AI 的新值。重新核对不执行写入，必须再次明确提交。

提交返回 queued/running 只表示已接受。界面独立跟踪本次操作，即使关闭通用自动刷新也继续读取其实际终态。等待期间禁止修改/导入这份草稿，避免完成回读覆盖用户后续编辑。成功时读取实际配置并提示 Host 仍由人类持有；失败、部分应用或 unknown 时保留草稿与核对入口。配置保存不会自动删除历史采集。

若 HTTP 提交响应未确认，界面保留意图键，提供只读查询，不直接重发写入。查询未找到记录也不证明尚在途的请求永不执行；必须继续核对。全量重载页面会丢失本地草稿/凭据，已接受的任务与结果仍保存在 Host。

## 模块和协议增量

| 模块 | 增量 |
|---|---|
| `public/workbench.js` / `.css` / `.html` | 独立和嵌入的任务列表，显示状态、时间及已保存结果 |
| `public/workbench-model.js` | 草稿差异、校验、并列比较与显式 rebase；无 DOM/I/O，可直接回归 |
| `public/operation-client.js` | 页面内存凭据、统一 HTTP 传输、明确的未确认响应、版本提交；现场旧动作也经过相同 guard |
| `public/operations.js` | 现场页薄适配；挂载同一工作台、共享 client，关闭时停止本地轮询 |
| `operations.ts` / `task_store.ts` | task revision、详情聚合、搜索分页、意图查询、有限副作用日志、开始/结束记录 |
| `execution_context.ts` / `service.ts` / settings/maintenance | 派发与确认关联到具体步骤；agent 命令名、Host 保存/维护动作，不记录参数载荷 |

仍为 **92 个 MCP 工具**，`operations` 增加可选字段：

- `list`: q/state/owner，全量过滤后分页；nextTaskOffset、nextOperationOffset 分别表示两种列表，保留旧 nextOffset。
- `get(taskId, limit, offset)`: task 含 revision、operationCounts、resources、unresolved；操作独立分页。
- 任务 pause/resume/cancel/complete: CLI/MCP 可用 `_operation.expectedTaskRevision` 做 CAS，冲突返回 STALE_TASK。省略时保持 P1 兼容，角色保护仍适用于人工暂停和未完成的操作员子操作。
- `get(idempotencyKey)`: 在当前调用角色的命名空间只读查找原 operation，支持未收到提交响应后的核对；不重新执行。

TaskStore schemaVersion 保持 1，增量字段可选。旧任务按 revision=0 读取，不为展示而重写历史；没有日志或开始/结束时间的旧操作明确标“未记录”。新操作初始化空 effects，区分“无受跟踪步骤”和“旧记录没有逐步日志”。Task 状态变化更新 revision；执行完成导致状态/汇总变化时也可能使旧面板观察失效。

startedAt/finishedAt 是 Host 开始处理和记录终态的时间。CLI / MCP 可进一步核对 settled、inFlight 和 unknown。

副作用日志每项最多 **64 条**，超出记录 effectsDropped；派发有独立 ID，异步并行响应不会对错步骤。状态 dispatched/acknowledged/failed/unknown 描述 Host 的派发/响应事实；acknowledged 不证明业务成功，operation/result 仍提供实际业务结论。deadline 或恢复后的不确定性保留 uncertainAt，晚到确认不删除此前的未知事实。没有参数、内存字节、密钥或 shell 命令文本。通用 external 日志和未埋点内部步骤不构成完整副作用审计；日志不是目标状态证明，也不提供回滚。

没有新增部署、自启动、真机命令、权限提升或后台自动接管；稳定设备身份、配对/TLS、USB/LAN 统一 RPC 和目标侧撤销仍属后续阶段。

## 验证与复现

独立 worktree 复用既有依赖（本轮不安装或改动依赖），复制并校验相同的 sandbox ELF；不共享运行数据。测试启动器移除继承的数据根/捕获根/operator 密钥，每个进程使用临时数据。显式提供 `ADH_CLI_SOURCE` 指向相邻 adh-cli 源码，继续实测公共 CLI；缺失外部 CLI 源码时该项打印原因并 skip。

```text
cd daemon
npm run typecheck
npm test
node test/fixtures/p2_workbench.ts
```

用 `node test/fixtures/p2_workbench.ts --app-capture` 可在浏览器切换两个合成应用，分别勾选后刷新，取消一个应用的最后一项，并核对另一个应用的勾选和命令记录。

UI fixture 在加载业务模块前禁止真实设备子进程，使用随机 loopback 端口、OS 临时目录、合成 session/socket 和固定合成 operator 密钥。双应用模式的 WebSocket 快照来自合成会话。测试专用的 `__fixture` 路由可模拟并发修改或核对命令归属。

新增回归 14 项涵盖 task CAS、旧记录、过滤分页、并行日志、日志上限、意图查询、配置差异/rebase、校验、传输未确认、凭据与 HTTP 集成。完整 Host **525 passed / 0 failed / 0 skipped**，类型检查通过。浏览器用 ego-browser 实测任务/结果/下载、人类暂停恢复与 STALE_TASK、unknown/lateResult/显式核对、接管释放、配置 STALE_CONTROL/保留草稿/rebase/确认结果、导入导出、文本安全渲染、独立与现场入口、390px 窄屏。截图实际查看后修复了嵌入页面的 main 全局样式冲突。具体交付状态见 PROGRESS.md。
