# 交接：京东 jdgs 的 `b5`（新会话从这里开始）

> 用途：把这件工作从**一个上下文耗尽**的会话完整交出去。文档只写本会话实际验证过的东西；
> 凡是"没验证"的地方都明确标注为未验证。工作中的现场数据（密钥、明文、抓包）在 gitignored 的
> `adhd-data/`、`captures/`、`dumps/` 下，**不要提交**。

## 0. 一句话状态

`b5 = hex(X)`，X 是 32 字节；**渲染链路已完全解开**，**X 的产地未找到**。第四十七轮把
**in-hook trace 做完并上了门禁**（`native_hook { traceInsns, traceFrom }`、`verify_v117`），
并用它读到了 `0x101da0` 的真实指令流；同时拿到了**不登录也能签名的 oracle**，b5 现在可以按需取样。
仍然没解的是"X 由谁写进那个 arena 槽"，所以 **b5 复现器还没交付**。

## 1. 已确定的事实（都有证据，不是推断）

| 结论 | 证据 |
|---|---|
| `b4 = base64(RC4_key20(zlib.compress(fingerprint_json,6)))` | 412/412 字节对上 |
| `b5 = hex(X)`，X 32 字节 | 正面识别：钩通用 hex 编码器，输入 hex 后等于目标自己写进 JSON 的 b5 |
| `libjdg+0xf643c` 是 **printf 式模板解释器**，不是 VM | 描述符四块缓冲分离：+0x10 常量池（含 `====`/`%s_%s`/`0.3.0`/`%lld`/`b1..b6`）、+0x18 参数向量、+0x20 编译后的模板程序、+0x28 寄存器堆、+0x30 同一份向量 |
| 486 号 opcode = **hex 渲染指令** | case `0xf65b0..0xf664c` 内含 `bl 0x101da0`（0xf65f8），其返回地址 `0xf65fc` 正是每次 hex 编码器命中的栈帧 |
| 486 的调用约定 | `0x101da0(count, &REG[A], &REG[B], pc, dst, w5, bank)`；`x1 = bank + (word@pc+4 ^ key2)`、`x2 = bank + word@pc+2`（**B 不异或**）、槽位**字节**寻址、key2 = `0x00b9`；**第四十七轮 trace 现场确认 `mov x26, x6` —— bank 基址是第 7 个参数 x6** |
| 上面这条经过**可证伪检验** | 两份独立现场命中：`A=0`、`B=0x138`、`x2-x1=0x138`、`x1-A == x2-B` |
| `0x101da0` 的入口 | trace 前 24 条：`sub sp,#0xc0` → 保存 x19–x28/x29/x30 → `mrs x22,TPIDR_EL0`、`ldr x8,[x22,#0x28]` → `mov x26,x6` / `mov x25,w5` / `mov x19,x4` / `mov x28,x3` / `mov x27,x2` / `mov x24,x1` → `ldrh w23,[x3]`、`ldrh w9,[x3,#6]`、`ldrsh w8,[x3,#8]`、`ldrh w20,[x3,#0xa]`（解 10 字节指令记录）→ `cmp w23,w0` / `b.lt` |
| `0x98c1c` 是**纯函数** | trace：`stp` 保存 x19–x26 → `cbz x0`/`cbz x1` 守卫 → `bfi x23,x20,#1,#63`（2n+1）→ `bl 0xafd78`（分配）→ GOT 桩跳转；钩它不改变行为 |
| 每次签名编码器被调 **2 次，src 同一槽** | 一次 32 字节 = b5 的 X，一次 32 字节 = b6；**b6 也是 64 hex / 32 字节**，而 `md5(签名 JSON)` ≠ b6 的任何一半 —— §2.1 的"b6 = md5(JSON)"**在本路径上不成立，待复核** |


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
（76/92/34 次）。第四十七轮的现场数据把这条写得更准：**每次签名编码器被调两次，src 是同一个槽**
（先 b5 的 32 字节，再 b6 的 32 字节），而两次 md5 的 out 都落在 `src+0x50`（不是两个不同槽）。
**没有任何一次哈希驱动调用写这个槽本身**（filter 钩子验证过，第四十七轮同样没看到）。

## 3. 已排除（每条都有方法 + 结果）

| 假设 / 路线 | 方法 | 结果 |
|---|---|---|
| `b5 = sha256(请求行/JSON)` | 钩哈希驱动抓全部消息（两窗口 = 2048B，覆盖 1563–1663B） | 不匹配 |
| 换算法 | md5/sha1/sha512/sha512-256/sha3-256/blake2s/sm3 × {BE, LE32, LE64, REV} | 6080 组全不匹配 |
| `b5 = sha256(JSON 去掉 b5)` | 三种文本切法 | 不匹配 |
| `b5 = RC4 密钥流` | 钩 KSA 拿 20 字节 key，用已 256/256 验证的教科书 KSA 重放，扫 4096 字节 × 3 字节序 | 不匹配 |
| X 含线程 md5 | 三份捕获、38 个 X，`X[0..16]`/`X[16..32]` 比对 | 0 命中 |
| X 是 md5/sha1/sha256/sha512/sha3-256/ripemd160 的"可见材料"整串或其一半 | 第四十七轮：oracle 现取 b5/b6 + 现场抓的请求行/签名 JSON/JSON 去 b5/b4 原文与 base64 解码/b1..b7/eid/uuid，含两两拼接与 H(H(m)) 一层，共 1360 组 | 全部不匹配 |
| X 是两次 md5 的拼接 | 哈希驱动每次签名只被调 2 次，两个 out 都在 `src+0x50`，都在 X 窗口外 | 排除 |
| X 是渲染的参数之一 | 链式窗口读整片参数对象簇（400B） | X 不在其中 |
| 事后 trace 已释放上下文 | 抓参数 → hard unhook → trace | **必死**（复现 3 次） |
| 独立 `native_call 0x101da0` | 自建 bank/dst/指令副本 | **必死**（依赖解释器帧） |
| 种描述符驱动 formatter | 五块缓冲全拷、五个指针全改指向副本、程序尾部填非法 opcode | **必死**（bank 里是指向值对象的指针，对象图无法重建） |
| 硬件写入监视 | `hw_watch set`（沙盒 + 真机） | `perf_event_open` **errno 13**，平台拒绝；**并据此纠正"hw_watch 触发打死目标"的旧记录——断点从未装上，是 arm 路径的问题** |

## 4. in-hook trace：已交付（第四十七轮），下面是**实际接口**与它读到的东西

### 4.1 接口（与设计一致，已落地）

```
traceInsns: 200     0 = 关（默认）。命中时就地跑这么多条 QBDI 指令（上限 4096）
traceFrom:  "x0"    可选；x0..x9 | x29 | x30，用该寄存器里的代码地址当起点；缺省用被钩入口
```

事件记录里追加**同一条记录内**的子对象；`traceInsns: 0` 时**连键都没有**：

```json
"trace": { "insns": 200, "seen": 200, "stopReason": "instruction-budget",
           "start": "0x…", "stopPc": "0x…", "capped": false,
           "mnemonics": [{"mnemonic":"ldr","count":12}, …],
           "first": ["0x…: ldr x0, [x1, #8]", …] }
```

`stopReason`：`completed | instruction-budget | time-budget | ran-away | left-range | did-not-run | reentrant`。
细节与"代价清单"见 `agent/src/trace/qbdi_trace.h`（trace 会**执行**被 trace 的函数、栈参数与浮点参数不保证、
VM 每线程常驻）。

### 4.2 用它读 `0x101da0` 读到了什么

sites 模式（函数序言不动）+ `traceInsns: 200`，命中点就地跑满 200 条（`instruction-budget`）：

```
+0x101da0  sub sp, sp, #0xc0          ; 标准大帧
+0x101da4  stp x28, x27, [sp, #0x60]  ; 保存 x19–x28
+0x101dc0  mrs x22, TPIDR_EL0         ; 线程私有结构
+0x101dc4  ldr x8, [x22, #0x28]
+0x101dc8  mov x26, x6                ; ★ bank 基址 = 第 7 个参数
+0x101dcc  mov w25, w5
+0x101dd0  mov x19, x4                ; dst
+0x101dd8  ldrh w23, [x3]             ; 指令记录（10 字节）逐字段解析
+0x101ddc  ldrh w9,  [x3, #0x6]
+0x101de0  ldrsh w8, [x3, #0x8]
+0x101de4  ldrh w20, [x3, #0xa]
+0x101df0  mov x24, x1                ; &REG[A]
+0x101dec  mov x27, x2                ; &REG[B]
+0x101df8  cmp w23, w0  / b.lt        ; 计数校验
```

**它不写那 32 字节**：trace 里没有向 `[x1]` 写 32 字节的序列；`x1` 只是被读出来交给编码器
（`x4` 是另一个静态缓冲，前后各 32 字节在 `memAfter` 里变化与 X 无关）。所以"X 由谁写进槽"的答案
在**上游的另一条模板指令**里，不在 `0x101da0` 内部。

### 4.4 第十四轮（2026-10-23）：把"猜 preimage"换成"问出来"，并纠正两个模型错误

这一轮没有再猜算法，先做了两件"便宜且能定死范围"的事。

**(a) oracle 差分：b5 到底依赖什么**（`adhd-data/_verify/b5_deps.mjs`）

| 改哪一个输入 | b5 |
|---|---|
| 请求行（追加 `&n=1` / `area` 的 `_0`→`_1`） | **变** |
| eid（元素 2 与请求行里的 `eid=` 同时改） | **变** |
| e5（元素 4） | **不变** |
| uuid（元素 5） | **不变** |
| 同一输入重复签 | **不变**（确定） |

所以 b5 的 preimage 只可能来自 **请求行 + eid**（+ 库内常量）。上一轮那 6080 组搜索是在
"不知道 preimage 由哪些字段组成"的前提下撒网，**eid 从来没进过材料集**。

**(b) 两个模型错误，必须替换掉**

1. **"每次签名哈希驱动被调 2 次"是幸存者偏差**：钩子计数 `hits=12` 而落到 store 的只有 4 条
   （采集环被挤掉）。单独一个哈希钩、无节流、并强制 drain 重测：一次签名里 `md5(请求行)` 与
   `md5(签名 JSON)` **都写同一个 out** = `encoder.src + 0x50`。那个 32 字节块 =
   `digest(16) || state(16 = 指针 + 计数)`，和 X / D **没有任何关系**（`md5(X)`、`md5(X[0:16])`、
   `X[0:16]==digest` 等 7 种关系全否）。所以 **X/D 不是这条哈希驱动的输出**。
2. **bank 槽里是指向值对象的指针**，不是内联值：`@x1`（deref 窗口）直接读出了 `"1"`、`"3.6.5_0"`、
   `"3.0\0%lld\0b1\0b2…"`、appKey 片段。因此 **`x1` 不可能等于编码器的 src**（那是 *解引用后* 的对象
   地址）——此前两次"按 `x1 == encoder.src` 过滤"必然 0 命中，原因就在这里。

**(c) 现场结构（新）**

- `0x101da0` 有**两个**调用点（相隔 0xa0，都在 libjdg，`form=bl`），sites 钩默认**同时补**两处；
  两个点的 **x6 都是 0**（不是 bank）——"bank 基址 = x6"只在不带此参数的路径上成立。
- `sites: N` 只补**地址最低的 N 个**；想只留 486 那一条，可先补两个、再用
  `memory_write {force:true}` 把不要的那个点的 `orig` 写回（钩子仍以为它补着，代码已不跳 thunk）。
  实测：只留一个点后，该点每个签名命中 **478 次**（模板每个字段都要渲染一次）。
- 10 字节指令记录按 u16 LE 读是 `[index][位移(0x120/0x138)][A^0xb9][len][0xffff]`，且
  **`x2 - x1` 恰好等于 `word@pc+2`（B）**、`A = word@pc+4 ^ 0xb9`；实测 index 1..115、len 1..11。
  `x1 - A` 不是常数（每次渲染的值栈基址不同），所以不能靠它反推 bank。

**(d) 现在真正的障碍：容量**

486 点每签名 478 次命中，而采集环只有 **128** 条 → "在 478 次里按值找出哪一次是 b5"会在
记录落盘前被挤掉。判别量目前一个都没有：`count(x0)` 恒 `0x10`、`dst(x4)` 恒定、A/B 每字段不同。
**这就是下一步要解决的第一件事**（放环 / 过滤 / 或只对单次命中做定向 dump）。

**(e) 下一轮的具体做法（按顺序）**

1. **给 `mem` 加负偏移窗口**（`x3-40:40`，agent 解析 + host 文法 + 单测）。理由：记录是 10 字节连续
   数组，**前一条指令记录就在 `x3-10`**；生产那 32 字节的 opcode 极可能就在紧邻的那条。没有负偏移，
   "往后看"永远看不到生产者。
2. 容量：用 `traceInsns` 时只留一个窗口；对 478 次/签名的钩子，把 `mem` 压到 `x3-40:40,x3:10`（50 B），
   再把采集环**临时**放大到 1024（`CAP_RING`，仅分析构建），或者在 oracle 前先 `capture_stop` 并让
   `native_look read` 每 100 ms 强制 drain 一次。
3. 拿到前一条记录后，按 `[index][位移][A][len]` 的语义找"写 32 字节"的那条（`len=0x20` 的候选），
   再对它的操作数做同样的 deref 读取——直到出现 X 的来源。
4. 另一条并行路线：`0xf643c`（单步解释器）的 `traceInsns`，预算 2000–4000，从 486 case 命中点往前
   无法走，但可以从"上一条记录的 pc"起跑（`traceFrom` 某寄存器若正好指向它）。

### 4.5 验收（已注册进 `tools/verify_all.sh`）

`tools/verify_v117_inhook_trace.sh`（device）：sites 钩 `traceInsns:32` → 事件有 `trace`、`seen=32`、
`stopReason` 在文档化集合内、`mnemonics` 非空、`first[0]` 地址 **== 被钩入口**；inline 钩同一函数 →
起点是 Dobby trampoline 且 `first[0] == start`、能看见 `sub sp…` → `ldr x17,#8` → `br x17` 跳回函数体；
`traceInsns` 缺省 → 事件**没有** `trace` 键；`traceInsns + skipOriginal` 被拒；两次调用返回值不变、目标存活。

### 4.4 下一轮的第一步

1. **X 的产地未定**（b5 复现器因此没有交付）：具体做法见 §4.4(e)。一句话：给 `mem` 加负偏移窗口，
   把命中点**前一条**指令记录读出来，顺着它找"写 32 字节"的 opcode。
2. 复核 §1 的 b6 结论：现场数据里 b6 = hex(32 字节)，而 md5(签名 JSON) 不是它。要么 b6 的含义不是
   md5(JSON)，要么 oracle 这条路径与 App 真实路径不同——先用真实 App 的一次签名对照一下。
3. 需要更长的 trace 时直接加 `traceInsns`（上限 4096），墙钟 300 ms 在钩子里，别指望跑完一个完整的
   解释器循环。

## 5. 工具用法备忘（三轮踩过的坑，能省你几个小时）

- **两个模型错误（第十四轮纠正，务必按新的来）**：① **bank 槽里存的是指向值对象的指针**，不是内联值
  （`@x1` deref 能直接读出 `"1"`、`"3.6.5_0"`、appKey 片段），所以"`x1` == 编码器 src"这种假设必然
  0 命中；② 钩子的 `hits` 与收到的记录数**不是一回事**（一次 `hits=12` 只有 4 条落地），任何
  "每次签名调用 N 次"的结论都必须先确认没有记录被环挤掉。
- **`0x101da0` 有两个调用点**，sites 钩默认两个都补；只有 `sites:N` 能限数量，且**按地址从低到高**。
  想只留 486 那一条：先补两个，再用 `memory_write {force:true}` 把另一个点的 `orig` 写回去。
- **热点钩 vs 采集环**：486 点每签名命中 **478** 次，环只有 **128** 条。要么 `filter`（但没有可用判别量），
  要么临时放大环，要么把 `mem` 压到 1–2 个窗口并强制 drain（`native_look read` 会走 `drainSession`）。
- **不登录也能签名（最有用的一条）**：`java_call {detach:true}` 回放
  `Bridge.entry(101, [byte[] "POST /client.action <40hex>&area=…&eid=…", "-§§-…", eid, "1.0", e5, uuid, null])`，
  5 ms 一次，返回完整 jdgs；同一输入 b5 恒定、改输入 b5 就变、**改 e5/uuid 不变**。脚本：
  `adhd-data/_verify/who_writes_x3.mjs`、差分用 `b5_deps.mjs`（登录页也能用）。
- **QBDI 在真机目标里要先装**：`libQBDI.so not available (dlopen)`。`adb push` 到 `/data/local/tmp`
  → `su cp` 进 `/data/data/<pkg>/files/`（`chown` 成 app uid、`chcon u:object_r:app_data_file:s0`）
  → `load_library {path, symbol:"qbdi_initVM"}`。沙盒自带这个库，所以沙盒门禁不会暴露这条。
- **对这个目标用 `mode:sites`，不要 inline**：给 libjdg 自己的函数下 inline patch 后，签名时进程
  SIGSEGV 在 `libjdg+0x10404c`（变参蹦床里），坏地址像被截断的指针；只装 sites 钩时同一操作存活。
  疑为它自己的完整性检查，本轮未证明（记录在 PROGRESS 第四十七轮）。
- **`memory_read` 的参数是 `size`，不是 `len`**。传错时每个地址都回 `bad size`，看起来像权限问题。
- **记录能不能读，取决于 daemon 的 drain 循环**：每条会话的 drain 是 hello 之后**异步** arm 的，
  启动瞬间读 `live_captures` 会看到空 store（`capture_stop` 回的 `drainLoop:"none"` 就是这个）。脚本
  要先等 `drainLoop:"armed"`（v117 的做法），别把"还没 arm"读成"功能坏了"。
- 装钩子前先 `capture_stop`；App 自己在登录页就会签上千次（真实请求行 1.5–1.7 KB），等它安静下来
  再做 oracle 实验，否则记录会被它的流量挤掉。
- 记录连接必须用 `(hookId, seq)`；`seq` 是**每钩子**编号。`memAfter` 带同一个 seq 且形状归一。
- **`native_call` 传 NULL 目的指针会直接杀目标**。要调"会写输出"的函数，先 `malloc`。
- 钩**极热**的函数（如 `strlen`）本身就会打死目标，与 stub 无关。
- `hw_watch` 在这台设备上被平台拒绝（errno 13），别再去"修"它。
- **含非 ASCII 的源码不要走 PowerShell 的 `Get-Content | Set-Content` 往返**（会把中文写成乱码）；
  用 edit 工具。
- trace 有 **4 秒墙钟上限**（独立 trace）/ **300 ms**（钩子内）；目标在命令中死亡会**立刻**返回
  `the target disconnected while this command was running`，不再静默 60 秒。
- 京东有 ~7 个进程，启动捕获策略会对每个都 arm，日志里 `dropped=` 是设计行为。
- 硬解（hard unhook）过的 inline 目标**在本进程内不能再挂**（Dobby 池状态），要换 sites 或重启 App。

## 6. 仓库状态与验收

- 工作区干净；`cd daemon && npm run typecheck` 为 0；`npm test` **339 通过**。
- 已注册的 device 门禁：`verify_v112_indirect_window`、`verify_v113_memafter_seq`、
  `verify_v114_window_chain`、`verify_v115_trace_time_budget`、**`verify_v117_inhook_trace`**。
- 第四十七轮新增：in-hook trace（`traceInsns`/`traceFrom`、per-thread VM、三条守卫、同记录内
  `trace` 子对象）、host 侧规范化与默认 payload 无 trace 键、`native_look` 显示 trace、
  `nativeHookIdentity` 头部窗口放大（trace 事件 ~3 KB）、exec-range 快照改不可变发布。
- 现场数据（密钥、b5 样本、捕获 JSON、oracle 脚本）在 `adhd-data/_verify/` 下，gitignored。本轮新增：
  `who_writes_x*.mjs`（oracle + 编码器/子解释器对拍）、`arena_block.mjs`、`arena_dump.mjs`、
  `pair_structure.mjs`、`x_search.mjs`、`sub_pair.mjs`、`sub_trace.mjs`、`qbdi_in_target.mjs`
  （装 QBDI + 真 trace）、`trace_budget.mjs`（预算阶梯）。

