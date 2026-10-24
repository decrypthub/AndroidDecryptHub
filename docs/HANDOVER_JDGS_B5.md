# 京东 jdgs b5 / b6：当前交接（2026-10-23，第五十二轮）

## 1. 当前结论与交付范围

**计算链已经独立复现**。同一份设备/库参数配置下，13 组新 oracle 调用的 b5、b6 各 **13/13**
逐字节对上；另有历史完整真机捕获的请求行 **12/12**、签名 JSON **13/13** 对上。
复现器使用标准 MD5、HMAC-SHA256 和两组逐字节变换，计算时不调用目标，不查询已捕获的输出。

必须分清范围：**参数的运行时取值已取得，初始化/派生链尚未全部还原**。
36 字节 HMAC key、16/32 字节变换各自的两组参数来自本机取证，不能据此宣称所有设备、所有库版本
共用这些值。不同请求与多个历史进程的验证说明本配置跨请求/进程稳定，不是跨设备验证。

本机私有交付（均 gitignored，**不要提交或公开内容**）：

- `dumps/jdgs-b5/reproduce.mjs`：纯离线计算器，CLI 接受 profile JSON + 原始消息文件。
- `dumps/jdgs-b5/profile.json`：本机参数配置，含密钥；必须与代码分开保管。
- `dumps/jdgs-b5/validation.json`：13 组受控调用与复算结果。
- `dumps/jdgs-b5/historical-validation.json`：历史捕获的匹配/缺配对统计。
- `adhd-data/_verify/codex_*.mjs/json`：本轮实验与原始证据；不是产品代码。

## 2. 实测公式

令 `T_n(v)[i] = ((v[i] + A_n[i]) mod 256) XOR B_n[i]`。
`A_16/B_16` 与 `A_32/B_32` 是不同的参数数组，不要混用。

```
H = MD5(message)                       // 16 个原始字节，不是 hex 文本
P = T_16(H)                           // 16 个原始字节
Q = HMAC_SHA256(K, P)                  // K 为本路径的 36 字节原始 key
result = lowercase_hex(T_32(Q))        // 64 个 hex 字符

b5 = result(原始请求行字节)
b6 = result(不含 b6 的签名 JSON 的原始字节)
```

b6 的 JSON 顺序、大小写、空白和编码都是输入的一部分。本轮从目标实际送入 MD5 的 JSON
取证核对；新 oracle 的 JSON 顺序为 `b1,b2,b3,b4,b5,b7`，不带空白。
**旧结论“b6 = md5(JSON)”错误**：那是中间原语的输出，不是最终 b6。

13 组验证包含 8 条不同请求、一次重复请求，以及分别只改变 eid 独立参数、e5、uuid、第二参数。
上述独立参数保持请求行字节不变时，b5 不变；**此前同时改 eid 参数和请求行 `eid=`，不能证明二者
分别进入 preimage**。当前证据支持本路径 b5 直接以请求行作为消息，不能扩展成对所有入口的声明。

历史证据：

| 捕获 | 完整请求行 → b5 | 完整签名 JSON → b6 | 限制 |
|---|---|---|---|
| `b5full.json`，旧 pid 434 | 12/12 | 13/13 | 同 tid 的编码器记录精确匹配 |
| `hash_out.json`，旧 pid 32041 | 请求行被截断，未纳入 | 6/6 | 不用截断输入得出否定结论 |
| `b5after.json`，旧 pid 6228 | 6 条有精确匹配 | 6 条有精确匹配 | 另外 4 个完整输入没有可配对编码器记录，不能算算法不匹配 |

## 3. 找到它的证据链

1. `native_hook` 观察 MD5 边界、HMAC 边界、hex 编码器；用 `(pid, tid, hookId, seq)` 对齐。
2. app 域 `perf_event_open` 的 errno 13 不代表 root 域也不可用。
   本轮在 **SELinux Enforcing** 下，从独立 root 进程成功观察真实写入，没有降低安全策略。
3. 数据观察点定位到 `libjdg+0xff40c: strb w9,[x8]`。两段程序交替写同一字节，最后写入的
   前 8 字节分别与同次 b5/b6 **8/8** 对上。
4. `PERF_SAMPLE_REGS_USER` + `PERF_SAMPLE_STACK_USER` 给出内核在事件处保存的寄存器和线程栈。
   栈中的三段 32 字节材料经字节加法、模 256、异或，与 b5 **32/32** 对上；换请求后两组参数不变。
5. `libjdg+0x8b408` 是六参数 HMAC 包装入口：key/keyLen、message/messageLen、out/outLen。
   本路径分别观察到 keyLen=36、messageLen=16；标准 HMAC-SHA256 对该次实际参数与输出完全一致。
6. 对 HMAC 的 16 字节输入另设观察点；内核栈中的原始消息正是同次 `MD5(请求行)`，经过另一组
   16 字节变换后 **16/16** 对上。随后写离线计算器并做未参与推导的新请求验证。

库偏移只属于这份已分析版本，不进任何产品默认值：

| 偏移 | 实测用途 |
|---|---|
| `0x8c1f8` | MD5 包装，不能把它当作全部摘要原语的普查点 |
| `0x8b408` | HMAC 包装（6 个寄存器参数） |
| `0x98c1c` | hex 编码器 |
| `0xff40c` | 解释器的字节写指令，具体操作由程序数据决定 |
| `0xf643c` | printf 式模板解释器；“不是格式化器”的早期记录已被后续实验纠正 |

## 4. 本轮新增的通用能力

`root_watch`（Host MCP，源注册表第 82 个工具）由 Host 启动独立 root collector：

```
bash tools/build_root_watch.sh
root_watch { action: "prepare", serial: "<设备>" }
root_watch { action: "start", session: "<明确会话>", tid: <已有线程>,
             addr: "0x...", width: 8, mode: "w", durationMs: 5000,
             maxEvents: 128, stackBytes: 8192 }
root_watch { action: "status", id: "..." }
root_watch { action: "read", id: "...", afterSeq: 0, limit: 8,
             registers: true, stackAddress: "0x...", stackSize: 128 }
root_watch { action: "stop", id: "..." }
```

- 只覆盖**一个已存在的 TID**，不继承未来线程。Host 独立核对 session 的真实 PID/进程名/UID。
- 不用 ptrace、不改目标代码、不重放函数、不改 SELinux；不在 Agent 或 Device Daemon 中做分析。
- 只保存内核事件中的 GPR/调用链/栈；**异步读 heap 不是命中时快照**，本轮已遇到对象释放后
  被 Java 渲染缓冲复用的例子，所以产品没有把这种读法伪装成原子证据。
- 有时间/事件数/内存边界；丢失、节流、损坏、主动停止及事件上限均明说。
  `event-limit` 的 `complete` 为 false；时间结束先关事件、再最终 drain。
- 真机 `verify_v121_root_watch.sh` PASS：独立硬件自检、沙盒实际 2 次写、GPR/栈、分页、停止、
  事件上限、错误 TID；r/rw 未单独验，x 在本轮探索中未捕获到命中，不能承诺可用。

**当前运行状态（2026-10-24，第五十四轮更新）**：日常 HTTP 8088 / Agent 8761 已切换当前源码，
实际 MCP 返回 **85 工具，包含 root_watch**，1 个已有设备会话重连；通过日常服务调用 prepare 的
硬件自检 complete=true、samples=1。此前结束旧进程被自动审批拒绝的运行限制已解除。
新 agent 仍只在新建 ARM64 自加载测试宿主验证，未替换已安装应用或京东进程；没有发布新 bundle。

## 5. 必须撤回的历史排除与操作坑

- 现有 in-hook QBDI 是**虚拟栈重放**，之后原函数还会再跑一次，不是原始执行的完整录制。
  它没有完整的调用点寄存器/栈；`0x97144` 的反汇编实际以 `bl` 开头，是函数中段。
  不能把这些重放里“未见写入”提升为对真实整条路径的排除。
- `memory_read` 返回 **`b64`**。旧分析 helper 只看 `hex`，把成功读取报成 `no hex`；这些失败不能
  用作“内存失效/平台拒绝”的证据。具体错误与 `short/requested` 仍必须逐次读。
- `native_call` 在**短命 watchdog worker** 上执行，调用 `gettid` 得到的线程随后会退出。
  root 观察点若要配受控调用，用同步 `java_call` 的持久命令线程；`android.os.Process.myTid()` 可确认。
- 命中后再从 root 读 heap 会竞争：本轮内核寄存器里的 bank 地址，等 root 读时内容已经变成
  Java 类名文本。只能使用内核寄存器/栈、或另有时序保证的现场拷贝。
- 暂停式 ptrace 原型出现未正确处理的 `TRAP_HWBKPT`，导致目标退出；未纳入产品。不能归因为
  “京东完整性校验/反调试”，产品实现仅使用不接管信号的 perf 路径。
- 后台冻结会使 session socket 看似在线但命令不回应；本轮 `wchan=do_freezer_trap`、
  `TracerPid=0`，前台启动目标后恢复。不要把它当作 agent 死锁。
- 原有身份、捕获完整性规则仍适用：按 `(hookId, seq)` 配对，先对计数/输入长度，丢失窗口内
  只能报告留下来的记录；真实数据不进仓库。

## 6. 真正剩下的工作

1. 继续还原 K 与两组长度参数的初始化/派生，验证换设备/换 b1/换库版本时哪些值变化。
   当前计算器依赖私有 profile，这一限制不能隐去。
2. 将本机私有参数提取流程整理成可重复取证步骤；产品保持通用，不能内置京东偏移或参数。
3. 日常 8088 已于第五十四轮加载 `root_watch` 并通过硬件自检；旧 AI 客户端需刷新 MCP 工具列表、
   重新选择会话。新 helper 尚未纳入旧 v0.5.0 发布包，下一次正式发版需按仓库版本规则打包。
4. 2026-10-24 已补有界 active-call trace 的 Host 落盘/分页/查询/统计/保守寄存器切片，
   `crypto_evidence` 动态证据台账与随机参数参考挑战，详见 `ANALYSIS_WORKFLOW.md`。
   原始整次执行全路径录制、完整内存污点、未知 VM 自动还原依然没有完成；
   新能力没有解决上述私有 profile 初始化，也不能把已给定参数的挑战当成盲解证明。
