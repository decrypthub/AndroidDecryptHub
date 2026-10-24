# 复杂原生计算链的取证流程

本流程使用现有 MCP 工具；范围与下一步仍以 REQUIREMENTS / DEVELOPMENT_PLAN / PROGRESS 为准。
工具帮助分析者形成可验证证据，不把猜测、一次中间原语命中或一个样本的参数升级成通用结论。

## 0. 远程 Agent 的入口

不需要先拿到这份仓库文档。MCP initialize 已携带全局入门说明，`analysis_guide` 也出现在工具列表中：

```json
{"topic":"start"}
```

随后按需要查询 `writer`（从已知缓冲找真实写者）、`crypto`（明确配对与原语核验）、
`trace`（有界主动调用追踪）或 `stuck`（超时、冻结、无事件与槽位耗尽）。
返回内容包含前置条件、工具调用顺序、变量来源、结果检查与失败分支。读取指南本身不操作设备。
其中 `$session` / `$tid` / `$buffer` 等是模板变量，必须用现场结果替换成正确类型后才调用；
不能把 eligibleForRootWatch 当作该线程正在写这个缓冲的证明。
crypto 中的公开 abc→MD5 只演示参数格式，不能冒充目标证据。

2026-10-24 已通过本机安装的 `adh mcp --endpoint ...` 实测：初始化说明透传，86 工具可见，
五条指南均可查询。已有客户端需要重新连接以刷新初始化说明与工具列表。
这验证了接入与文档可达性，没有把它写成新 Agent 的未知样本盲测通过。

## 1. 锁定身份，先区分没运行与没观察到

缺少历史上下文时先调用同一入口的状态评估：

```json
{"action":"assess","topic":"stuck","session":"<实际 sessionId>","hookId":7}
```

hookId 是可选的，必须替换为当前会话真实编号。没有 session 时返回选目标建议，不替选进程。
topic 仍为 start/writer/crypto/trace/stuck；writer 可额外提供已观察到的 buffer 和 tid。
返回 stage/summary、facts/missingEvidence/doNotConclude，以及一条 next 调用的目的、效果、期望和时机。
checkpoint 可交给另一个 Agent 重跑，但只携带标识参数，不是完整案件历史，不含原始字节/密钥。

评估读取当前会话最近至多 64 条 Host 保留记录，必要时做一次 3 秒预算的 native_hook status。
它不布防、触发、重放、重启、drain 或上传 helper；下一条建议可能具有明确标示的效果，尚未执行。
它区分零命中、过滤、抽样/额度抑制、在途回调、提交未保留，以及超时和明确拒绝回复。
已知丢失与过期健康快照保持显式。whole-capture 的 output/key 缺原始长度时，核验仍会 unavailable：
须独立建立长度依据，不能拿收到的前缀长度升级完整性。提供的地址/TID 也只是候选，不自动证明真实写者。

用 `process_list` 选定一个明确 session，读取 `capabilities`。不要在多进程目标里默认选最后一个进程。
`runtime_diagnostics` 可在 agent 无回应时从 root procfs 核对身份、代际、冻结事实与现存线程：

```json
{"session":"<明确会话>","serial":"<专用测试设备>","limit":32}
```

`frozen`、`traced`、`process-exited`、`identity-mismatch` 与 `unknown` 含义不同。
旧 agent 没有 hello starttime 时，`sessionGenerationVerified:false` 不能被隐去。
诊断不给目标解冻、不启动应用，也不覆盖未来线程。

## 2. 受控调用与边界观察

先用反汇编确认入口；不能把函数中间的 BL 当成完整入口。用 `java_call` 或 `native_call`
建立可重复触发；一次只改变一个输入维度，保留未经重新排版的请求/JSON 原始字节。

通过 `native_hook` / `native_look` 观察输入、输出与调用链。`mem` 在命中时复制入口内容，
`memAfter` 复制原函数返回后的窗口。按 session/TID/hookId/seq 匹配两者，不靠“时间很近”。
`memory_read` 的字节在 `b64`；不能因没有 `hex` 把成功读取报成失败。

对于高频入口先限制范围：`tid` / `returnAddress` / `filter` 筛选调用，
`sampleEvery` / `throttleMs` / `maxEvents` 限制事件。后面三者不关闭已选调用的改写。
非默认 `tid/returnAddress/sampleEvery/maxEvents` 先验证 agent status 的 `observationControlsVersion>=1`；
旧 agent 或查不到能力时拒绝安装，不能把参数静默丢弃后继续。
核对 `hits/filtered/selected/sampledOut/throttled/limited/emitted`；`emitted` 是提交捕获环，
另看环与 Host 保留窗口的丢失计数。`native_look` 没有事件时仍会报告观察计数和读取错误。

卸载要看原位置是否恢复，以及资源是否退休保留；不要用“等了一段时间”证明任意线程都离开了跳板。
GOT/sites/vtable 和 hard-inline 退休后的物理槽、旧上下文不再用于其它目标；sites/vtable 页永久保留。
soft-inline 只允许同目标、相同 stub 形态重新启用，不能承诺任意暂停线程在两次观察间的绝对代际切分。
固定 16 槽是进程级预算，耗尽要新进程，不自动重启目标。`retiredPages/Bytes` 只计 sites/vtable 自管页，
不包括 Dobby 共享池或 QBDI。任意栈参数 ABI/异常展开不能从 FP8 测试推断已经全部覆盖。

## 3. 从输出地址追到实际写者

有明确缓冲地址与已有 TID 时，可使用 `root_watch prepare/start/status/read/stop`。
事件来自内核保存的 PC/GPR/调用链/线程栈；它没有函数重放，也没有异步 heap 的原子快照。
命中后才读 heap 可能已读到释放后复用的对象，不能把它当成命中时的证据。

核对完整性和停止原因。`event-limit`、丢失、节流、主动停止与采集损坏都限制结论范围。
工具只覆盖指定现存线程，r/rw/x 与其它 ROM 必须分别验收，不能由参考设备 w 的通过推断。

## 4. 核验每个阶段，分开中间结果与最终字段

`crypto_evidence` 接收明确配对的 input/output/key/params：可以传带来源和完整长度的精确字节，
也可用 `{captureId,field:"mem",reg:"x0",offset:0}` 选择特定窗口。
已知 `inl` / `requested` 不可被较短的 `expectedBytes` 覆盖。截断、缺失、错身份为 unavailable，
不是算法不匹配。相同线程本身不构成配对依据。

算法候选可省略，让核验器检查支持的候选；自定义 add/xor 参数需从证据给出，工具不猜密钥。
给观察标明 `intermediate` / `final`；例如 MD5 与某个中间缓冲相同，不能据此说最终签名就是 MD5。
输出到下一阶段输入、密钥或掩码的整块精确相等会形成内容链接；它证明相等，不证明执行因果。
参数按真实字节 fingerprint 分组，不依赖分析者给的标签。

`save/read/list/drop` 负责私有台账。默认分页只返回来源和摘要；只有 `includePayload:true`
才展开原始材料。`analysisComplete` 与 `captureCollectionComplete` 分开，后者未知时是 null。

## 5. 需要更多指令时再扩大记录

`trace_session prepare` 加载明确的 QBDI 库；`record` 会主动调用函数，需要 `confirm:true`。
记录在 Host `DATA_DIR/traces`，随后用 `query` / `stats` / `slice` 获取有界结果：

```json
{"action":"record","session":"<明确会话>","symLib":"<模块>","symbol":"<入口>","args":["1","2"],"confirm":true,"capacity":65536}
```

它使用虚拟栈和整数参数，记录 instrumented-module 内的指令；不是目标原始调用的完整执行录制。
最大执行工作预算 1000000 条，保留最多 65536 条，Host 每页 128 条、排空预算 30 秒。
指令处的时间预算不能硬中断未插桩的外部阻塞调用。
必须分别看 `stopReason`、`retvalValid`、`complete`、`transportComplete`、截断计数与 `released`。

`slice` 是保守寄存器依赖：支持的算术可追，遇到内存来源、外部调用或未支持指令则报告 barrier，
不伪造内存别名或完整污点链。in-hook `traceInsns` 仍为带副作用、上下文不全的 replay，
会执行一次重放再执行原函数；某个重放窗口没有写入，不能排除真实整条路径。

## 6. 用未参与推导的输入验算

独立复现器不得查询捕获输出或再次调用目标。参数来源、输入的原始编码、逐条匹配数和缺记录数要分开。
改变请求、独立参数、进程、设备或库版本，是不同的验证维度。

参考验收 v124 每次生成新 seed：4 种组合链、6 组参数 profile、分块二进制输入和打乱记录。
54 条阶段匹配、2 条不匹配、6 条不可验证记录证明证据核验和组织能力；
它已给定参数与配对来源，不证明从未知混淆二进制端到端盲解。
完整内存污点、未知 VM 自动解码与参数初始化盲定位仍是独立能力，不能由这组通过替代。

真实材料只进 gitignored DATA_DIR/captures/dumps，不提交目标密钥、token 或明文。
