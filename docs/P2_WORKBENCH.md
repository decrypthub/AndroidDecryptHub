# P2：人类任务工作台（2026-11-16）

P2 在 P1 的统一执行层上补齐人类工作台。AI 仍默认自主规划和执行；人类查看、搜索、下载结果及编辑本地草稿，不会自动暂停 AI。只有明确提交修改、暂停任务或接管范围才改变运行状态。

本次源码位于独立 worktree，原工作目录保持 P1 提交。原因是运行中的 Host 会按需读取 public 静态文件：仅保持 Node 进程不重启，仍不足以保护刷新中的现有面板。P2 没有部署到当前实例，没有更改真机或 USB/LAN 协议。

工作台需要配套 P2 Host，不能只替换静态资源；缺少 task revision 时面板拒绝修改任务。

## 人类工作流

- 现场页“任务工作台”打开工作台；“设置”进入同一工作台的配置编辑。也可直接访问 `/workbench`。现场页保留原数据维护/历史设置入口，不同时叠开两个设置界面。
- 任务列表支持全库搜索、负责人/状态筛选及分页。任务详情显示名称、ID、版本、负责人、人工暂停标记、创建/更新时间和操作总数；操作记录独立分页，支持查看实际终态、来源、目标代际、deadline 和版本。
- 操作详情按需读取已保存结果与 lateResult，可下载 JSON。界面最多预览 120000 字符，下载的是全部“已保存内容”；如果 Host 只保存了省略摘要，界面明确说明下载也无法恢复被省略的数据。未加载、尚无结果与执行未知分别呈现。结果/任务文本用 textContent 渲染，不解释目标提供的 HTML。
- 人类暂停具名任务后，保留 heldByOperator；AI 不能自行恢复。人类显式恢复只允许后续工作，不自动重放失效、超时或取消的操作，也不释放资源控制权。取消单条操作和取消整项任务分开，已派发步骤不会自动回滚。
- 控制权显示所选 Host/目标的已观察 revision、epoch、hostEpoch；接管、交还 AI、核对 unknown 都使用这次观察的版本，不在点击时暗中刷新。切换范围会先清空旧范围快照；新范围读取失败时不会误用旧目标进行控制。
- unknown 以独立警示显示隔离状态。人类必须检查副作用、晚到结果和目标实际状态，再勾选确认并显式解除隔离；Host 处理仍在等待时后端拒绝解除。原 unknown 和 resolvedAt 保留，不把人工核对改写成原调用成功。

关闭工作台不取消任务，也不自动交还控制权。凭据仅保存在当前页面内存，现场与其工作台共享同一 client；独立工作台页面不继承其他页面权限。观察模式和连接操作员都不等于接管。角色与实际控制权分别显示，避免把“有凭据”误当成“已经暂停 AI”。

## 配置编辑与冲突

配置表单覆盖当前 Settings 的视图、捕获/类型/模块、保留策略和启动策略，继续调用共享 settings 服务。导入只合并进草稿；提交前校验已知字段、类型、范围、包名和符号，拒绝未知或会被静默过滤的值。导出的是最后读到的 Host 配置，未提交草稿不会混入导出。

每份草稿独立保存编辑时的 Host 版本，不受后台任务刷新影响。提交只发送实际修改的字段；不会把整份旧配置覆盖回去。例：编辑时 displayCap=300，人类改成 411；同时 AI 将该值改为 377 并设置 fileModule。旧版本提交被拒绝，草稿保留，界面并列显示“编辑时 / 当前值 / 草稿意图”。人类选择“保留修改，按最新版本重新核对”后，仅保留本来修改的 displayCap，未修改的 fileModule 采用 AI 的新值。重新核对不执行写入，必须再次明确提交。

提交返回 queued/running 只表示已接受。界面独立跟踪本次操作，即使关闭通用自动刷新也继续读取其实际终态。等待期间禁止修改/导入这份草稿，避免完成回读覆盖用户后续编辑。成功时读取实际配置并提示 Host 仍由人类持有；失败、部分应用或 unknown 时保留草稿与核对入口。配置保存不会自动删除历史采集。

若 HTTP 提交响应未确认，界面保留意图键，提供只读查询，不直接重发写入。查询未找到记录也不证明尚在途的请求永不执行；必须继续核对。全量重载页面会丢失本地草稿/凭据，已接受的任务与结果仍保存在 Host。

## 模块和协议增量

| 模块 | 增量 |
|---|---|
| `public/workbench.js` / `.css` / `.html` | 独立/嵌入两种工作台；任务、控制权、结果、副作用和配置视图；移动窄屏布局、焦点和禁用反馈 |
| `public/workbench-model.js` | 草稿差异、校验、并列比较与显式 rebase；无 DOM/I/O，可直接回归 |
| `public/operation-client.js` | 页面内存凭据、统一 HTTP 传输、明确的未确认响应、版本提交；现场旧动作也经过相同 guard |
| `public/operations.js` | 现场页薄适配；挂载同一工作台、共享 client，关闭时停止本地轮询 |
| `operations.ts` / `task_store.ts` | task revision、详情聚合、搜索分页、意图查询、有限副作用日志、开始/结束记录 |
| `execution_context.ts` / `service.ts` / settings/maintenance | 派发与确认关联到具体步骤；agent 命令名、Host 保存/维护动作，不记录参数载荷 |

仍为 **92 个 MCP 工具**，`operations` 增加可选字段：

- `list`: q/state/owner，全量过滤后分页；nextTaskOffset、nextOperationOffset 分别表示两种列表，保留旧 nextOffset。
- `get(taskId, limit, offset)`: task 含 revision、operationCounts、resources、unresolved；操作独立分页。
- 任务 pause/resume/cancel/complete: `_operation.expectedTaskRevision` 可做 CAS，冲突返回 STALE_TASK，不改变任务。面板始终携带；旧 CLI/MCP 省略时保持 P1 兼容，但人类暂停/未完成 operator 子操作的角色保护继续强制执行。
- `get(idempotencyKey)`: 在当前调用角色的命名空间只读查找原 operation，支持未收到提交响应后的核对；不重新执行。

TaskStore schemaVersion 保持 1，增量字段可选。旧任务按 revision=0 读取，不为展示而重写历史；没有日志或开始/结束时间的旧操作明确标“未记录”。新操作初始化空 effects，区分“无受跟踪步骤”和“旧记录没有逐步日志”。Task 状态变化更新 revision；执行完成导致状态/汇总变化时也可能使旧面板观察失效。

startedAt/finishedAt 是 Host 开始处理和记录终态的时间。deadline 时记录终态不代表 handler 或目标已经停止；界面分别显示 settled、inFlight 和 unknown。

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

UI fixture 在加载业务模块前禁止真实设备子进程，使用随机 loopback 端口、OS 临时目录、合成 session/socket 和固定合成 operator 密钥。它不启动正式 index，不配置 adb reverse，没有真实 WS/手机连接；用于任务/配置工作流验收，不等于真机采集验收。fixture 的 __fixture 路由仅存在于测试文件，用于模拟并发修改。

新增回归 14 项涵盖 task CAS、旧记录、过滤分页、并行日志、日志上限、意图查询、配置差异/rebase、校验、传输未确认、凭据与 HTTP 集成。完整 Host **525 passed / 0 failed / 0 skipped**，类型检查通过。浏览器用 ego-browser 实测任务/结果/下载、人类暂停恢复与 STALE_TASK、unknown/lateResult/显式核对、接管释放、配置 STALE_CONTROL/保留草稿/rebase/确认结果、导入导出、文本安全渲染、独立与现场入口、390px 窄屏。截图实际查看后修复了嵌入页面的 main 全局样式冲突。具体交付状态见 PROGRESS.md。
