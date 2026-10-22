# 交接：京东 jdgs 的 `b5`（新会话从这里开始）

> 用途：把这件工作从**一个上下文耗尽**的会话完整交出去。文档只写本会话实际验证过的东西；
> 凡是"没验证"的地方都明确标注为未验证。工作中的现场数据（密钥、明文、抓包）在 gitignored 的
> `adhd-data/`、`captures/`、`dumps/` 下，**不要提交**。

## 0. 一句话状态

`b5 = hex(X)`，X 是 32 字节；**渲染链路已完全解开**，**X 的产地未找到**；唯一剩余的路径是
**in-hook trace（尚未实现）**。四条旁路已排除，每条都有复现记录（见 §3）。

## 1. 已确定的事实（都有证据，不是推断）

| 结论 | 证据 |
|---|---|
| `b4 = base64(RC4_key20(zlib.compress(fingerprint_json,6)))` | 412/412 字节对上 |
| `b6 = md5(不含 b6 的 JSON)` | **10/10 完整消息**，用哈希驱动**自己写出的字节**验证（长度 564–1663） |
| `b5 = hex(X)`，X 32 字节 | 正面识别：hex 编码器输入 hex 后正好等于目标自己写进 JSON 的 b5 |
| `libjdg+0xf643c` 是 **printf 式模板解释器**，不是 VM | 描述符四块缓冲分离：+0x10 常量池（含 `====`/`%s_%s`/`0.3.0`/`%lld`/`b1..b6`）、+0x18 参数向量、+0x20 编译后的模板程序、+0x28 寄存器堆、+0x30 同一份向量 |
| 486 号 opcode = **hex 渲染指令** | case `0xf65b0..0xf664c` 内含 `bl 0x101da0`（0xf65f8），其返回地址 `0xf65fc` 正是每次 hex 编码器命中的栈帧 |
| 486 的调用约定 | `0x101da0(count, &REG[A], &REG[B], pc, dst, 0, 0)`；`x1 = x26 + (word@pc+4 ^ key2)`、`x2 = x26 + word@pc+2`（**B 不异或**）、槽位**字节**寻址、`x26 == x1`。key2 = `0x00b9` |
| 上面这条经过**可证伪检验** | 两份独立现场命中：`A=0`、`B=0x138`、`x2-x1=0x138`、`x1-A == x2-B` |
| 哈希驱动 `0x8c1f8` 是 **md5** | 输出 == md5(完整消息) 10/10；x2 处 32 字节中**前 16 是摘要**，后 16 是线程级状态 |

## 2. 关键地址与常量（相对 libjdg 模块基址）

```
0xf643c   渲染入口 f(dst, cap, descriptor)
0xf65b0   486 号 opcode 的 handler（hex 渲染）
0x101da0  子解释器（486 调它，内部再经 0x102d10 → 0x102d50 → 0x103270 → 0x104000 蹦床
          → 0x98c1c hex 编码器）
0x98c1c   通用 hex 编码器，签名 (src, 32, &outLen)
0x8c1f8   哈希驱动 (buf, len, out)，5 状态派发，实为 md5
0x156240  派发表    0x156270 派发状态   0x156284 SHA-256 IV   0x1562a4 SHA-256 K
          （IV/K 是**标准值但按小端逐字存放**：读出 67 e6 09 6a … / 98 2f 8a 42 …）
```

**arena 槽位关系（很强的结构线索）**：`encoder.src = hash.out - 0x50`，在每次捕获里都是主导差值
（76/92/34 次），即同一块线程私有 arena：`+0x400` 是编码器读的 32 字节，`+0x410`/`+0x450` 是两次
md5 输出。**没有任何一次哈希驱动调用写 `+0x400`**（用 filter 钩子验证，filter 不会漏采样）。

## 3. 已排除（每条都有方法 + 结果）

| 假设 / 路线 | 方法 | 结果 |
|---|---|---|
| `b5 = sha256(请求行/JSON)` | 钩哈希驱动抓全部消息（两窗口 = 2048B，覆盖 1563–1663B） | 不匹配 |
| 换算法 | md5/sha1/sha512/sha512-256/sha3-256/blake2s/sm3 × {BE, LE32, LE64, REV} | 6080 组全不匹配 |
| `b5 = sha256(JSON 去掉 b5)` | 三种文本切法 | 不匹配 |
| `b5 = RC4 密钥流` | 钩 KSA 拿 20 字节 key，用已 256/256 验证的教科书 KSA 重放，扫 4096 字节 × 3 字节序 | 不匹配 |
| X 含线程 md5 | 三份捕获、38 个 X，`X[0..16]`/`X[16..32]` 比对 | 0 命中 |
| X 是渲染的参数之一 | 链式窗口读整片参数对象簇（400B） | X 不在其中 |
| 事后 trace 已释放上下文 | 抓参数 → hard unhook → trace | **必死**（复现 3 次） |
| 独立 `native_call 0x101da0` | 自建 bank/dst/指令副本 | **必死**（依赖解释器帧） |
| 种描述符驱动 formatter | 五块缓冲全拷、五个指针全改指向副本、程序尾部填非法 opcode | **必死**（bank 里是指向值对象的指针，对象图无法重建） |
| 硬件写入监视 | `hw_watch set`（沙盒 + 真机） | `perf_event_open` **errno 13**，平台拒绝；**并据此纠正"hw_watch 触发打死目标"的旧记录——断点从未装上，是 arm 路径的问题** |

## 4. 下一步：实现 in-hook trace（唯一剩余路径）

### 4.1 为什么必须是它

"先抓参数、事后再 trace"必然踩已释放内存；而命中点那一刻内存是活的。所以要能在**钩子回调里**
就地跑一小段 QBDI。

### 4.2 接口

`native_hook` 安装时多两个字段：

```
traceInsns: 200     0 = 关（默认）。命中时就地跑这么多条 QBDI 指令
traceFrom:  "x0"    可选；以该寄存器里的代码地址为起点，缺省用被钩函数入口
```

事件记录里追加**同一个记录内**的子对象（不要另发一条记录——`memAfter` 的教训：多一条记录就多一种配错方式）：

```json
"trace": { "insns": 200, "seen": 200, "stopReason": "completed|instruction-budget|time-budget|ran-away",
           "mnemonics": [{"mnemonic":"ldr","count":12}, ...], "first": ["0x…: ldr x0, [x1, #8]", ...] }
```

### 4.3 实现步骤

1. 从 `agent/src/trace/qbdi_trace.c` 抽出
   `int adh_qbdi_run_from(uint64_t pc, const uint64_t *gpr, int budget, int time_ms, qbdi_summary_t *out)`。
   用 `qbdi_setGPRState` 灌入 x0..x7，再 `qbdi_run(instance, pc, 0)`（API 已确认存在：
   `agent/third_party/qbdi/include/QBDI/VM_C.h:143`；`stop=0` 表示跑到函数返回）。
2. **per-thread VM**（`pthread_getspecific`），**绝不引入全局锁**——钩子可能并发命中，全局锁会把
   目标线程串行化，等于给目标装隐形瓶颈（违反"agent 只采集、不拖累目标"的红线）。
3. 三条守卫一个都不能省：指令预算、墙钟（复用第 4 轮加的 `ADH_QTRACE_TIME_MS` 机制）、exec-range。
4. `native_hooks.cpp`：`traceInsns`/`traceFrom` 解析 → 事件 JSON 组装完、`adh_capture_push_text` 之前
   调用上面的函数，把 summary 拼进同一条事件。
5. 默认值必须"关"：`traceInsns: 0` 时事件里**不得**出现 `trace` 键。

### 4.4 验收

`tools/verify_v117_inhook_trace.sh`（device，参照 `verify_v112/v113/v114/v115` 的写法）：

- 钩沙盒里一个已知函数，`traceInsns: 32` → 事件里有 `trace`，`insns>0`，`stopReason` 在
  文档化集合内，`first[0]` 的地址等于被钩函数入口（或 `traceFrom` 指定地址）；
- 同一钩子 `traceInsns: 0` → 事件里**没有** `trace`；
- 目标存活。

同时把 `native_hook` 的描述、`daemon/src/mcp.ts`、`docs/mcp-tools.md` 一起更新，并加一条 host 单测
断言默认 payload 不带 `traceInsns`。

### 4.5 拿到之后干什么（分析侧）

钩 `0x101da0`，`traceInsns: 200`，看它内部到底调了什么、有没有循环、常量是什么；再钩 `0xf643c`
的 486 分支看 `dst` 静态缓冲里写出什么。目标是回答"X 由谁写进 arena+0x400"。

## 5. 工具用法备忘（本会话踩过的坑，能省你几个小时）

- **`memory_read` 的参数是 `size`，不是 `len`**。传错时每个地址都回 `bad size`，看起来像权限问题。
- **两个钩子抢一个小环形缓冲会互相饿死**：`0x101da0` 不节流时 38 次命中把 encoder 记录全挤掉
  （`enc=0`）。给热点钩子加 `throttleMs`，或用 `filter`。
- 装钩子前先 `capture_stop`：自动 HTTP/加密捕获会把环形缓冲几秒翻一遍。
- 记录连接必须用 `(hookId, seq)`；`seq` 是**每钩子**编号。`memAfter` 现在带同一个 seq 且形状归一。
- **`native_call` 传 NULL 目的指针会直接杀目标**（本轮重启京东 3 次）。要调"会写输出"的函数，先 `malloc`。
- 钩**极热**的函数（如 `strlen`）本身就会打死目标，与 stub 无关。
- `hw_watch` 在这台设备上被平台拒绝（errno 13），别再去"修"它。
- **含非 ASCII 的源码不要走 PowerShell 的 `Get-Content | Set-Content` 往返**（会把中文写成乱码）；
  用 edit 工具。
- trace 现在有 **4 秒墙钟上限**（`stopReason:"time-budget"`）；目标在命令中死亡会**立刻**返回
  `the target disconnected while this command was running`，不再静默 60 秒。
- 京东有 ~7 个进程，启动捕获策略会对每个都 arm，日志里 `dropped=` 是设计行为。

## 6. 仓库状态与验收

- 工作区干净；`cd daemon && npm run typecheck` 为 0；`npm test` **330 通过**。
- 已注册的 device 门禁：`verify_v112_indirect_window`、`verify_v113_memafter_seq`、
  `verify_v114_window_chain`、`verify_v115_trace_time_budget`（均在 `tools/verify_all.sh`）。
- 本会话新增：`@` 间接窗口、`@#n` 链式解引用、`mem` 六窗口（总数 4 KB 成为约束）、
  `memAfter` seq/形状修复、trace 墙钟上限、断连立刻带原因失败。
- 最近的提交：`ad9233d`（六窗口）、`ad92919`（hw_watch 被平台拒绝）、`7d23d8e`/`7dee450`（in-hook
  trace 设计与起步清单）、`781b2ed`、`fb48227`、`519c9d6`、`f3b5ffe`、`aa4b94f`、`d6bb6cd`。
- 现场数据（密钥、b5 样本、捕获 JSON）在 `adhd-data/_verify/` 下，gitignored；里面有大量可复用的
  脚本（`check_operands.mjs`、`bank_follow.mjs`、`addr_link.mjs`、`addr_match.mjs`、
  `filter_out.mjs`、`vm_isa.mjs`、`vm_table_dump.mjs`、`vm_summary.mjs`、`t_hwwatch_*.mjs` 等）。
