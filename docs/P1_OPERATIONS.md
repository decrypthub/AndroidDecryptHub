# P1：统一操作、持久任务与控制权（2026-11-16）

后续 P2 已补齐人类工作台，并增补 task revision、结果/副作用查看和配置冲突核对，见 [P2_WORKBENCH.md](P2_WORKBENCH.md)。下文保留 P1 实施边界；P2 的新增可选字段兼容旧账本和 CLI，不自动重写历史。

本次交付是 Host 源码与 CLI 源码，未部署到当前分析现场。没有更改 agent、设备 APK、TCP 线协议或 USB/LAN 传输。AI 仍自主规划，recipe 是可选工具；人类面板可以查看任务、提交修改、接管和释放。

配套 `adh-cli` 本地提交：`f086459`（未推送、未发布）。

## 一个执行层

MCP `/mcp`、包固定 MCP、REST `/api/*`、浏览器面板、公共 Python `adh` CLI、仓库开发 CLI 均进入 `Operations`。普通查询保持轻量；显式携带 taskId 的查询、离线分析与所有写操作有持久 operation。原业务 handler 是内部原语，直接 import handler、ADB 或操作系统管理员脚本不属于此协调边界。

| 模块 | 职责 |
|---|---|
| `operation_registry.ts` | 工具/REST 的效果分类、别名、Host 或目标作用域；未分类 MCP 工具和 POST 默认受写保护 |
| `operations.ts` | 提交、去重、队列、控制权、版本检查、deadline、取消、恢复 |
| `task_store.ts` | 权威 SQLite 事务账本，显式初始化，损坏报错，不自动重建 |
| `execution_context.ts` | 跨 await 的执行上下文；实际命令/文件写入前 checkpoint，分辨已发送和已确认 |
| `operation_host.ts` | 当前 Host 单例、目标代际解析、响应封装、自动策略的 epoch 约束 |
| `access_context.ts` | 人类 operator 凭据；请求 JSON 自称 human/operator 不生效 |
| `http/routes_operations.ts` / `mcp.ts` | 相同任务与控制 API 的两个前门 |
| `public/operations.js` | 面板版本缓存、冲突反馈、任务/控制权对话框 |

Host 整体修改与所有目标写串行；同目标写串行，不同目标可以并行。提交和真正执行前都检查版本；接管或取消以后，已经运行的多步任务在下一次副作用边界停止。启动延迟策略也绑定原 controlEpoch/hostEpoch，接管再释放不会使旧定时指令复活。

## 版本与人类修改

受保护写入必须附加 `_operation`：`expectedRevision`、`controlEpoch`、`hostEpoch`。通过 `operations(action=snapshot, tool, arguments)` 观察后，原样提交；版本冲突 `STALE_CONTROL` 必须重新观察和规划，不自动替换旧版本重试。

- revision 在接管、释放、显式核对与写入开始时递增，即使写入失败，也不复用原版本。
- 目标 resource 包含 session、PID、UID、进程 starttime；旧 agent 没有 starttime 时显式标为 legacy。这是 Host 会话代际，不是后续 P3 的稳定设备身份。
- 认证的人类第一次修改自动接管；人类接管使该作用域排队的旧 AI 操作失效，暂停其所属 task。运行中的旧操作后续副作用被拒绝。人类写等待已有命令确认，保证旧命令不会在面板修改之后由 Host 再发出。
- operator 持有目标时，AI 对该目标和 Host 全局的写入都被阻止；Host 接管阻止所有 AI 写。查询可继续。释放必须显式执行；释放 Host 不会顺带释放独立接管的目标。
- 控制权切换不修改现有 Hook 配置，不重启目标。API 不接受 JSON 中的 owner/state/resource 覆盖持久操作身份。

`idempotencyKey` 表示一次意图；同角色、同键、同规范业务参数和目标返回原 operation，跨 REST/MCP 不重复执行；同键不同参数报 `IDEMPOTENCY_CONFLICT`。为新意图生成新键。不得为绕过失败而自动更换键或版本。

## 任务、超时和取消的真实含义

Task 是持久分析目标；operation 是一次调用。任务可 active/paused/cancel_requested/cancelled/completed/unknown，操作可 queued/running/cancel_requested/succeeded/failed/cancelled/unknown。`submit` 成功只表示已接受，必须查询 operation 的终态与结果。

| 情况 | 持久反馈 |
|---|---|
| 排队时取消 | cancelled，未派发，`mayHaveExecuted=false` |
| 运行时请求取消 | cancel_requested；拒绝后续步骤，不能宣称目标已停止 |
| 请求取消时命令已经完成 | succeeded + `cancelRequested=true`，如实保留结果 |
| 已完成部分步骤后停止 | cancelled/failed + `partialEffects=true`，没有自动回滚 |
| deadline 前未派发 | failed + DEADLINE_EXCEEDED |
| 派发后 deadline 或断连 | unknown，目标是否执行未确认，写作用域隔离，禁止自动重试 |
| 超时后收到成功或失败 | 保留 lateResult；原 unknown 不改写为 succeeded |
| Host 退出后恢复 | 排队未发送项 cancelled；运行项 unknown，不自动重放 |

命令进度 `cmd.done` 的 state/targetStopped 明确表达 unknown 与 `targetStopped=false`。HTTP 504、MCP isError、持久任务反馈一致。单个 operation 的 cancel 不取消整个具名 task；通过 taskId 取消整项任务。AI 也不能通过整任务 pause/cancel 干扰其中尚未完成或未核对的 operator 操作。人类暂停具名 task 后保留 heldByOperator，只有人类显式 resume 才恢复，旧 AI 不能自行恢复或取消。unknown 不能经任务取消伪装成已确认 cancelled。

unknown 写入必须由 operator 检查实际目标后 `resolve(acknowledge=true)`。Host handler 仍在等待时禁止解除隔离；已停 Host 的遗留状态允许人工核对。resolve 只记核对与新 epoch，保留 unknown 原记录、晚到结果和 resolvedAt；它不证明旧目标命令停止或已回滚。若旧进程/命令仍可能运行，操作者必须先在目标侧处理，Host 无法撤回已上线路由的旧 agent 命令。

## API 与命令行

新增第 **92** 个 MCP 工具 `operations`，actions：snapshot、create、list、get、submit、pause、resume、cancel、complete、takeover、release、resolve、hold。所有旧工具 schema 公布可选 `_operation`，写入在执行时强制校验。`notifications/cancelled` 按 X-Adh-Client-Id 与 requestId 找到对应 operation。

`POST /api/operations` 使用相同 action；`POST /api/operations/prepare` 接收 path/method/arguments，只返回分类与版本，不执行。REST 可在 body `_operation` 或 `X-Adh-Operation` JSON 头传版本；回复 `X-Adh-Control`。旧的不带版本写入返回 CONTROL_REQUIRED，普通查询兼容。面板沿用此前读取到的 revision，不在提交时静默刷新旧编辑；409 要求刷新检查。

公共 `adh-cli` 需使用同次 P1 源码；未发布到 PyPI，也未替换本机已安装 CLI：

```text
adh tasks create --title "分析目标请求" --endpoint 127.0.0.1:18088 --json
adh run TOOL --arguments JSON --task-id TASK_ID --idempotency-key INTENT_ID --endpoint 127.0.0.1:18088 --json
adh tasks get OPERATION_ID --include-result --endpoint 127.0.0.1:18088 --json
adh tasks cancel OPERATION_ID --endpoint 127.0.0.1:18088
adh tasks cancel --task-id TASK_ID --endpoint 127.0.0.1:18088
adh control snapshot --session SESSION --endpoint 127.0.0.1:18088
```

`adh run` 只观察一次并异步提交，适合超过 MCP HTTP 请求生命周期的操作；`adh call --operation JSON` 保留 AI 事先观察的版本。任务列表支持 limit/offset；completed/cancelled task 不重新打开，应创建新任务。原开发 CLI 是同一服务的 HTTP 客户端，为自身新命令观察一次版本，不自动重试。

## 凭据与持久化边界

显式 `initializeOperations()` 在监听前创建 `ADH_DATA_DIR/operations/` 下的 SQLite 与私有 `operator-access.json`，也可在 Host 环境指定 `ADH_OPERATOR_TOKEN`。面板“任务与控制权”使用密码框接入；密钥只在页面内存中。CLI 只有显式 `--operator` 才从当前进程的 ADH_OPERATOR_TOKEN 读取凭据，stdio AI 代理忽略继承的 operator 密钥。凭据不会嵌入公开 HTML、API 响应、提交和示例。

operator 证明请求意图，不构成本机 OS 管理员权限隔离，也不是完整 LAN 配对/TLS 认证。稳定设备身份、USB/LAN 统一 RPC、目标侧撤销协议仍待后续阶段。已有监听与数据文件未在本轮升级。

账本 schemaVersion=1，元数据最多 32 MiB / 10000 operations；满时拒绝新增，不自动删历史。结果与 lateResult 原子保存到 results/，超过 8 MiB 的响应以 omitted/bytes/sha256 摘要保存，调用方必须检查省略标记，不把它当完整证据。结果可能包含私有分析材料，目录不得提交或公开；备份应包含整个 operations/。权威 SQLite 损坏时停止写入并报告，不能按 DEX 缓存逻辑删库重建。当前没有自动归档、跨机 HA 或任意分析代码的持久续跑。

后台 Hook/collector 的 start 操作成功表示配置/启动确认，并不表示后台采集已经结束；停止仍走原工具 stop。取消 start operation 不是自动停止已启动的 collector。

## 隔离验证

`npm run typecheck`、`npm test` 通过；回归覆盖角色伪造、跨入口去重、旧版本拒绝、具名任务取消、局部副作用、超时晚到成功/失败、断连、持久恢复、共享 SQLite 控制与损坏保护。测试先禁止设备子进程，再建立 loopback 临时 Host + 合成 agent；公共 Python CLI、开发 CLI 实际调用该 Host。面板用 `test/fixtures/p1_panel.ts` 的随机端口、临时存储和合成数据完成操作验证。没有启动正式 index、运行 dev_up/真机门禁、修改 adb reverse、停止目标或重启服务。具体计数记录在 PROGRESS.md。
