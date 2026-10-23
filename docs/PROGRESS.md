# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 2026-10-23（第四十九轮）—— 写观察点（`traceWatch`）落地：工具第一次用事实回答"谁写了这块内存"

### 一、能力：`native_hook { traceWatch: "x0:32" }`（agent + host + 门禁）

硬件观察点在这台设备的 app 域被平台拒绝（`perf_event_open` **errno 13**），所以"哪条 store 写了这块
内存"此前**没有任何答案**——指令 trace 只知道跑了哪些代码，不知道哪次写落在哪。现在：

- 窗口文法与 `mem` 完全一致（寄存器 + **有符号偏移** + 可选 `@` 一层解引用），因为调用方在命中当刻
  手里只有寄存器，绝对地址会过期；
- 范围**命中当刻**算出，**只在该次 run 内**挂 `qbdi_addMemRangeCB(QBDI_MEMORY_WRITE)`，
  run 结束立刻 `qbdi_deleteInstrumentation`（per-thread VM 跨命中复用，不删就会让下一次命中替上一次付钱）；
- 事件里追加 `traceWatch {lo, hi, count, truncated, hits:[{pc, insn, addr, size, value}], error?}`，
  与 `trace` 在同一条记录里；`traceWatch` 不配 `traceInsns` 直接拒（"装了钩却从不观察"是最坏的谎）；
- status 回显 `traceWatch`；host `normalizeTraceWatch` 只接受**恰好一个窗口**，默认 payload 不带该键。

验收（`tools/verify_v119_trace_watch.sh`，device，通用夹具"读 8 字节 + `buf[0]^=0xff`"）**PASS**：

```
{"count":1,"hit":{"pc":"0x747958a204","insn":"strb w9, [x0]","addr":"0xb4000073df1fd800",
                  "size":1,"value":"0xbe"}}
```

—— 写入指令、地址、宽度、值全是 QBDI 报的访存事实；同一钩子不带 `traceWatch` 重新激活时事件里
**没有**该键且 `trace` 仍在。Host 343 测试（+3）、`tsc` 0；回归 `v117/v118/v114` 全绿。

### 二、外部资料（公开分析，2024 版）给的形状，与我们的现场数据交叉验证

公开分析把 b5 描述为 `sha1(请求行 + " " + AES_CBC(md5(xor(请求行, key)), key, iv))`，其中
`key = f(b1 .jdg.xbt 文件名, 固定 IV 串)`；样例里 b5/b6 是 **40 hex（SHA-1）**。

- **对得上**：b5 只依赖请求行（element 0）、与 e5/uuid 无关、同输入恒定——正是该形状的必然结果；
- **对不上**：该形状要求最后有一次摘要（40 hex），而我们干净单钩普查（`hits=2`，全捕获）只有
  两次 md5（请求行 161B / JSON 440B，输出都落在 `encoder.src+0x50`），**没有任何 sha1/sha256 调用**；
  且我们的 b5/b6 是 **64 hex（32 字节）**。→ 这一版把最后一步换成了 **VM 内联实现**（不走哈希驱动），
  或 32 字节 = 两段摘要拼接。缺的仍然是"这 32 字节由谁写"——正好是上面那件工具要回答的。

### 三、下一步（工具侧，按"别的 Agent 不看文章也能干"排序）

1. `traceWatch` 已可用 → 下一步把它用在"值的产地"上（**generic**：先 `mem`/`traceWatch` 找到写者，
   再跟它的输入一层）；
2. **把 oracle 与差分固化成工具命令**（这一轮还是手写脚本）：`oracle.record/replay` + `diff_params`
   （自动依赖矩阵、文本字段二分到字节）——这是"新 Agent 上手"的门槛；
3. **动态密码学台账**：自动挂已知原语并标注 {alg, in, out, caller, tid, 次序}，把"这个参数到底由哪些
   标准算法拼出来"从手工 Findcrypt 变成一条命令；
4. 沙盒加一个**参考挑战**目标（形态像 libjdg、算法由我们控制），把"能分析同等难度"变成可跑的 PASS/FAIL。

## 2026-10-23（第四十八轮）—— 命中点窗口能往回读（v118）；b5 的输入面被差分钉死，两个模型错误被纠正

### 一、能力：`mem` 支持负偏移（`x3-40:40`）

模板解释器的指令记录在一整片连续数组里，"产出这个值的上一条指令"在 `pc-10`——**只往前看的文法
永远回答不了"上一条是什么"**。所以这一轮把命中点窗口改成有符号：agent `parse_window` 接受 `-`，
命中时按有符号算地址（借位到 0 以下报 `underflow`，不是变成巨大地址），canonical 保留负号、
status 回显；`@#<n>` 的下标仍是字节下标（负值拒）。Host 同文法、`±65535` 上限。

验收：`daemon/test/native_hook_mem.test.ts` +1 条（正负、`-0` 归一、`@x1-8`、上限、`@#1-8` 被拒），
**340 通过**、`tsc` 0；`tools/verify_v118_negative_window.sh`（device，已注册）——已知 16 字节图案后调
**冷**夹具（参数 `buf+8`），记录里 `offset:-8`、`hex` 恰好是那 16 字节、status 回显 `x0-8:16`、
目标存活，**PASS**。回归：`v107`（mem 窗口）、`v114`（链式）、`v106`（host）、`v117`（trace）全 PASS。

### 二、JDG 侧：b5 的输入面（oracle 差分，这次是"问"出来的，不是猜）

| 改哪一个输入 | b5 |
|---|---|
| 请求行（`&n=1` / `area` 的 `_0`→`_1`） | **变** |
| eid（元素 2 与请求行里的 `eid=`） | **变** |
| e5（元素 4） | **不变** |
| uuid（元素 5） | **不变** |
| 同输入重复签 | **不变** |

→ preimage 只可能来自 **请求行 + eid**（+ 库内常量）。上一轮 6080 组搜索里 **eid 从未进过材料集**。

### 三、两个必须替换掉的模型错误

1. **"每次签名哈希驱动被调 2 次"是幸存者偏差**（`hits=12` 只有 4 条落地）。单独一个哈希钩、无节流、
   强制 drain 重测：`md5(请求行)` 与 `md5(签名 JSON)` 都写**同一个 out** = `encoder.src + 0x50`；
   那个 32 字节块 = `digest(16) || state(16 = 指针 + 计数)`，与 X/D **无任何关系**（7 种关系全否）。
   → **X/D 不是这条哈希驱动的输出**。
2. **bank 槽里是指向值对象的指针**（`@x1` 直接读出 `"1"`、`"3.6.5_0"`、`"3.0\0%lld\0b1…"`、appKey 片段），
   所以"`x1` == 编码器 src"必然 0 命中——此前两次按 `x1` 过滤失败的原因就在这里。

### 四、现场结构（新，均已复现）

- `0x101da0` 两个调用点（`0xf65f8` 与 `0xf6698`，相隔 0xa0），sites 钩**默认两个都补**；两个点的
  **x6 都是 0**（不是 bank）。`sites:N` 只补地址最低的 N 个；**只留一个点的手法**：先补两个，再用
  `memory_write {force:true}` 把不要的那个点的 `orig` 写回（钩子仍以为补着，代码已不跳 thunk）。
- 两个点**都是高频**（每签名数百次），所以"在命中里按值找 b5"仍受采集环（128）限制；
  但**负偏移窗口已经能读到前一条记录**（实测 `x3-10`/`x3-20` 可读，10 字节记录含
  `[index][segment 0x120/0x138/0x1a0][A^0xb9][len][0xffff]`，且 `x2-x1 == word@pc+2`）。
  开放细节：当前记录带 `0xffff` 终止符，紧邻它之前的那条**没有**（步长未必是固定 10 字节），
  下一轮先把这个定死，再按 `len=0x20` 找"写 32 字节"的那条。
- 真机目标要先装 QBDI 才能 trace（`load_library` + 私有目录那份），这一轮已在 JDG 里跑通。

## 2026-10-22（第四十七轮）—— in-hook trace 交付并上了门禁；JDG 侧拿到真实 trace，b5 的产地仍未定

### 一、能力：`native_hook { traceInsns, traceFrom }`（agent + host + 门禁）

**接口与语义**（`agent/src/trace/qbdi_trace.h` 是唯一规格，含"代价"清单）：

- `traceInsns: N`（0 = 关，默认）→ 命中的 **那一条记录**里多一个 `trace` 子对象，不另发记录；
  `traceInsns: 0` 时事件里**连键都没有**（"没开 trace" 与 "开了没看到" 必须可分）。
- `traceFrom: "x0".."x9"|"x29"|"x30"` 用该寄存器里的代码地址当起点；缺省用被钩入口。
  和 `skipOriginal`/`returnSet` **互斥**（trace 会执行原件，而那两项存在的意义就是不让它跑）。
- `trace` 字段：`insns/seen/stopReason/start/stopPc/capped/error/mnemonics[{mnemonic,count}]/first["0x…: insn"]`。
  `stopReason ∈ completed | instruction-budget | time-budget | ran-away | left-range | did-not-run | reentrant`。

**实现里几个不显然的地方（都留了注释）**：

- `adh_qbdi_run_from(pc, gpr, budget, time_ms, summary)` + `_ex(..., instrument_hint)`：
  gpr 布局 = `x0..x8, x29, x30, x18`；**per-thread VM**（`pthread_getspecific`，析构里 terminateVM+对齐释放），
  **没有全局锁**；三条守卫（指令预算 / 墙钟 300 ms / exec-range）在同一个回调里。
- **exec-range 快照改成"不可变 + 原子发布"**：原来每次 trace 都原地 free/rebuild，钩子并发命中时会把
  数组从另一个线程脚下抽走。现在只在"起始地址不在快照里"时重建，旧快照不释放（代价是"新代码出现"次数级的泄漏）。
- **起点选择**：sites/got 用被钩入口；**inline 必须从 Dobby trampoline 起跑**——入口是我们自己的分支，
  QBDI 跟过去就回不到模拟器（第 10 轮在 libjdg 上以 SIGBUS 收场）。同时把 `ctx.target` 所在模块加进
  instrumented ranges，否则 trampoline 跳回函数体的第一条指令就被判 `left-range`。
  （第一版把 hint 先交给 `addInstrumentedModuleFromAddr`，它返回 true，于是 trampoline 那一页**从没被加进去**，
  现象是 `did-not-run`。）
- **结束条件**：`pc == lr` 在 PREINST 里先停（"函数返回"不能靠 QBDI 自己），加上预算/墙钟/exec-range；
  都不是的时候报 `left-range`（调用进了没插桩的模块），而不是谎称 `completed`。
- **重入**：`__thread` 深度计数。被 trace 的函数又调到钩子时，那次命中记 `stopReason:"reentrant"`，
  绝不在同一个线程上开第二个 run。
- **mnemonic 用反汇编的第一个 token**（`ldr`），不是 `a->mnemonic`（LLVM 的 `LDRWui`）——而且 QBDI 的
  反汇编串**以空格开头**，不先 trim 会得到空 mnemonic（第一版就是这样：trace 正常、直方图全空）。
- host：`normalizeTraceInsns`（0..4096，非数字/负数抛错）/`normalizeTraceFrom`/`nativeTracePayload`
  （**默认 payload 不含这两个键**，有单测）；`native_look read` 把 trace 合成一行；`state.ts` 的
  `nativeHookIdentity` 头部窗口 4096 → 16384 hex（带 trace 的事件 ~3 KB，`seq` 会掉出旧窗口）。
- 单测 330 → **339**（+`native_hook_trace.test.ts` 6 条、identity 1 条、native_look 2 条），`tsc` 0。

**门禁**：`tools/verify_v117_inhook_trace.sh`（device，已注册 `verify_all.sh`）：

- sites 钩 `adh_trace_target` + `traceInsns:32` → 事件有 `trace`，`seen=32`、`stopReason=instruction-budget`、
  `mnemonics=[ldr×11 add×8 str×6 cmp×3]`、`first[0]` 地址 **== 被钩入口**；
- inline 钩同一函数 + `traceInsns:32` → 起点是 trampoline（`start != target`），`first[0]` 地址 == `start`，
  且能看到 `sub sp…` → `ldr x17,#8` → `br x17` 跳回函数体；
- `traceInsns` 缺省 → 事件**没有** `trace` 键；`traceInsns + skipOriginal` 被拒；
- 被钩函数返回值两次都还是 30（trace 只观察），目标存活。
- 回归：`v110`（trace guard）、`v115`（墙钟）、`v10_qbdi`（独立 trace）、`v113`（memAfter seq）、
  `v107`（mem 窗口）、`v114`（链式窗口）全 PASS —— 说明 `qbdi_trace.c` 的重构没有改变既有行为。

### 二、JDG 侧：oracle + 真实 trace，b5 的产地仍未知

**先说能复用的（下一轮直接抄）**：`Bridge.entry(101, [byte[], "-§§-…", eid, "1.0", e5, uuid, null])`
用 `java_call {detach:true}` 回放，**在登录页也能签**，5 ms/次；同一输入 b5 恒定、改输入 b5 就变。
于是"为一条请求等用户点屏幕"这件事过去了：`adhd-data/_verify/who_writes_x3.mjs` 是完整脚本。

**本轮在现场量到的（都有脚本与 JSON，在 `adhd-data/_verify/`）**：

- 每次签名，通用 hex 编码器（`0x98c1c`）被调 **2 次，src 是同一个 arena 槽**：一次 32 字节的 hex 就是
  `b5`，另一次 32 字节的 hex 就是 `b6`。**b6 也是 64 hex = 32 字节**；`md5(signed JSON)`（现场算的，
  与哈希驱动自己的输出一致）**不等于** b6 或其任何一半 → 交接文档里 "b6 = md5(JSON)" 在这条路径上不成立，
  需要按"32 字节渲染值"重新验证（下一轮第一件事）。
- `0x101da0` 的真实 trace（sites 模式，命中点就地 200 条，`stopReason=instruction-budget`）：
  `mrs x22, TPIDR_EL0` 取线程私有结构、`ldr x8,[x22,#0x28]`、**`mov x26, x6`**（x6 才是 bank 基址）、
  `mov x25,w5`、`mov x19,x4`（dst）、`mov x28,x3`（指令记录）、`mov x27,x2`/`mov x24,x1`（两个槽指针）、
  随后 `ldrh w23,[x3]` / `ldrh w9,[x3,#6]` / `ldrsh w8,[x3,#8]` / `ldrh w20,[x3,#0xa]` 解指令记录，
  `cmp w23,w0` / `b.lt` 做计数校验。
- 编码器自己的 trace：`stp` 保存 x19–x26 → `cbz x0/x1` 守卫 → `bfi x23,x20,#1,#63`（2n+1）→
  `bl 0xafd78`（分配）→ GOT 桩跳转。**是个纯函数**，钩它安全。
- **QBDI 在真机目标里默认不可用**：`libQBDI.so not available (dlopen)`。需要
  `push` 到 `/data/local/tmp` → `su cp` 进 app 私有目录（chown 成 app uid、`chcon u:object_r:app_data_file:s0`）
  → `load_library {path, symbol:"qbdi_initVM"}`。做完这一步 trace 才真的跑起来。

**没解决的**：X（b5 的 32 字节）由**谁**写进那个 arena 槽。本轮排除/定死了这些：

- 不是 md5/sha1/sha256/sha512/sha3-256/ripemd160 的任何"可见材料"整串或其一半（请求行、签名 JSON、
  JSON 去 b5、b4 原文与 base64 解码、b1..b7、eid、uuid；含两两拼接与 H(H(m)) 一层）。
- 不是两次 md5（哈希驱动每次签名只被调 2 次，两个 out 都在 `src+0x50`，且都在 X 窗口之外）。
- 槽里的值在渲染前就在了：`0x101da0` 只是把它读出来交给编码器，**它自己不是写入者**（trace 里没有向
  `[x1]` 写 32 字节的序列；`x1` 是槽指针，`x4` 是另一个静态缓冲）。

**下一轮的第一步（已定）**：找"生产这个 32 字节"的那条模板指令。可行路径：钩 `0xf65b0`（486 case）不行
（`br` 跳表，sites 抓不到）；可行的是钩 `0x101da0` 的**上一层** `0xf65f8` 的调用者不可达时，改为
"给 `0x101da0` 传进来的 x1 `memory_read` 前后对比"：在 `memAfter` 里读 `x1`（已有能力），配合
`filter` 按 `x1` 值筛选——但 `filter` 只有 8 个寄存器且值必须绝对（arena 每线程不同，脚本里现学现用）。

**一条重要的工具/目标事实（未定因，但可复现）**：给 libjdg **自己的函数**下 inline patch（例如编码器入口）后，
签名时进程 SIGSEGV 在 `libjdg+0x10404c`（变参蹦床 `0x104000` 里），坏地址像被截断的指针；
**只装 sites 钩（函数序言不动）时同一操作存活**。倾向"inline patch 触发了它自己的完整性检查"，
本轮没有证明。**对这个目标一律用 `mode:sites`。**

## 2026-10-22（第四十六轮）—— 本轮只做状态核对；实现留给下一轮（附起步清单）

工作区干净、`tsc` 0、330 条测试全过、`mem` 窗口已 6、六条 API 就绪（`@` / `@#n` / `memAfter`+seq /
`time-budget` / 断连立刻失败 / 6 窗口）。**in-hook trace 本轮没有动代码**：它是一个跨 `qbdi_trace.c`
与 `native_hooks.cpp` 的改动（per-thread VM 生命周期 + JSON 预算 + 三条守卫），在剩余预算里硬写
风险高于收益——宁可留给下一轮一次做完整并配 v117 验收。

下一轮的起步顺序（照第四十五轮的设计走）：

1. `adh_qbdi_run_from(pc, gpr, budget, time_ms, summary)` —— 从 `qbdi_trace.c` 抽出，用
   `qbdi_setGPRState` + `qbdi_run(instance, pc, 0)`；
2. per-thread VM（`pthread_getspecific`），**不引入全局锁**；
3. `native_hook` 的 `traceInsns` / `traceFrom` 解析 → 事件 JSON 里追加 `trace` 子对象（**同一条记录**）；
4. `tools/verify_v117_inhook_trace.sh`（32 条 / 0 条两种情形 + 目标存活）；
5. 用它去读 `0x101da0`：命中点就地跑 200 条，看它到底调了什么、还算不算得下去。



## 2026-10-22（第四十五轮）—— in-hook trace 的设计定稿（下一轮直接实现，不再讨论）

这轮把最后一项能力的**接口、数据流和验收**定下来，避免下一轮从零讨论。

### 接口

`native_hook` 安装时多两个字段：

```
traceInsns: <int>      0 = 关（默认）。命中时就地跑这么多条 QBDI 指令。
traceFrom:  "x<reg>"   可选。以该寄存器里的**代码地址**为起点；缺省则以被钩函数入口为起点。
```

事件记录里多一个字段：

```
"trace": { "insns": N, "seen": M, "stopReason": "completed|instruction-budget|time-budget|ran-away",
           "mnemonics": [{"mnemonic":"ldr","count":12}, ...],   // 前 16 名
           "first": ["0x…: ldr x0, [x1, #8]", …] }              // 前 32 条，每条 ≤ 48 字符
```

### 实现路径（复用已有件，不新写 VM）

1. `agent/src/trace/qbdi_trace.c` 已经有完整的 VM 生命周期、exec-range 守卫、指令预算、墙钟上限。
   抽出 `int adh_qbdi_run_from(uint64_t pc, const uint64_t *gpr, int budget, int time_ms,
   qbdi_summary_t *out)`：initVM → allocateVirtualStack → setGPR（x0..x7 来自 `gpr`）→
   `qbdi_call` 不可用（我们要从任意 pc 跑），改用 `qbdi_run(instance, start, stop)`——**已确认存在**
   （`agent/third_party/qbdi/include/QBDI/VM_C.h:143`），配合 `qbdi_setGPRState` 先灌入命中的
   x0..x7 即可从任意 pc 起跑；`stop=0` 表示跑到函数返回。
2. `native_hooks.cpp` 在事件 JSON 组装完之后、`adh_capture_push_text` 之前调用它，把 summary
   拼进同一个事件（**不要另发一条记录**：事件与它的 trace 必须在同一条里，否则又要靠 seq 配对，
   而 memAfter 的教训已经证明"多一条记录就多一种配错"）。
3. 预算默认 `traceInsns=200`、墙钟 300 ms：钩子跑在目标线程上，**必须假定它会跑飞**——
   三条守卫（指令预算 / 墙钟 / exec-range）一个都不能省。
4. 可重入与线程安全：QBDI 的 VM 是**每线程**的，钩子可能并发命中，所以 `adh_qbdi_run_from`
   要用 `pthread_getspecific` 持有 per-thread VM，或用一个"每线程一次性"的小池；**绝不能用一把
   全局锁**（会把目标线程串行化，等于给目标装了个隐形瓶颈）。

### 验收（device）

`tools/verify_v117_inhook_trace.sh`：
- 钩沙盒里一个已知函数，`traceInsns: 32`，命中后事件里必须有 `trace`，且
  `insns>0`、`stopReason` 在文档化集合内、`first[0]` 的地址等于被钩函数入口（或 traceFrom 指定的地址）；
- 同一钩子再跑一次 `traceInsns: 0`，事件里**不得**出现 `trace` 键（回归：默认不许有开销）；
- 目标存活。

### 为什么这是唯一剩下的路（本会话已逐条排除）

事后 trace 已释放上下文：必死；独立调 `0x101da0`：必死（依赖解释器帧）；种描述符驱动 formatter：
必死（bank 指向的对象图无法重建）；硬件写入监视：平台拒绝 perf（errno 13）。**只剩"命中点就地"**。



上一轮把"写入监视 arena 槽"列为剩下的第一条路，并说先在沙盒验证。验证结果很干脆：

```
沙盒:  perf_event_open failed: Permission denied (errno 13)
       - perf events are usually forbidden for apps (perf_event_paranoid=2/3),
         and SELinux can deny them even when the sysctl allows it
真机:  同样的 errno 13
```

**结论：`perf_event_open` 在这个 domain 里没有权限**，两个进程一致。所以：

- 这不是"hw_watch 有 bug"，是**平台不允许**；`hw_watch` 的报错文本已经把原因写清楚了
  （这正是好错误信息该有的样子：说清"为什么"而不只是"失败了"）。
- **顺带纠正一条历史记录**：案例里写的"`hw_watch` 在这个目标上反复把进程搞死"，真因更可能是
  **arm 路径在权限失败后的处理**，而不是"断点触发把目标打死"——断点从未真正装上。
  这条纠正很重要，否则后面还会有人去"修 hw_watch 的崩溃"。

于是剩下的路只有一条：**在钩子命中点就地跑 N 条 QBDI 指令（in-hook trace）**。
它解决的是本会话反复踩到的同一件事：**"先抓参数、事后再 trace" 时，参数指向的内存已经失效**
（bank/值对象/程序块都是请求作用域）。第 4 轮加的墙钟上限已经让"就地 trace 即使跑飞也能收住"
在机制上成立，这是下一步唯一需要的产品能力。



## 2026-10-22（第四十三轮）—— 窗口上限提到 6；种描述符驱动 formatter **确认为不可行**（原因是对象图）

### 一、能力：`mem` 窗口 4 → 6（总数 4 KB 变成真正的闸门）

上一轮失败的根因是"5 块缓冲区、4 个窗口"：formatter 的描述符把常量池(+0x10)、参数向量(+0x18)、
模板程序(+0x20)、寄存器堆(+0x28) 放在**四个不同分配**里，`+0x30` 还是那份向量。4 个窗口表达不了，
于是被迫少拷一块并清零——而**半份描述符比没有更糟**。

- agent `ADH_MEM_WIN_MAX` 6；daemon `NATIVE_MEM_WIN_MAX` 6（否则 daemon 会拒掉 agent 接受的 spec）；
- 关系从 `TOTAL == MAX*LEN` 变成 `MAX*LEN >= TOTAL`：6×1 KB 会超 4 KB，所以**总数成了真正的约束**，
  测试改成断言这个关系（原来那条等式断言会立刻过期，正是它自己的注释警告过的事）；
- `@#n` 的越界校验也跟着用新常量；mcp 描述与 `mcp-tools.md` 同步；
- 单测 12 条全过、全量 330、typecheck 0；提交 `ad9233d`。

### 二、结论：种一份描述符去驱动 formatter —— **不可行，原因明确**

五块全拷（描述符/常量池/参数向量/模板程序/寄存器堆），描述符五个指针全部改指向副本，
程序副本尾部用 `0xffff` 填成"非法 opcode"（否则截断的 1 KB 程序会走进全零区，而**零字解码出来仍是
合法 opcode**，这才是"截断副本变成野跳转"的机制）。结果仍然是：

```
native_call formatter -> ok=false error: the target disconnected while this command was running (it may have crashed)
alive: NONE
```

真因在数据结构本身：**寄存器堆里装的是指向"值对象"的指针**，拷寄存器堆不等于拷那些对象，
渲染器一解引用就踩到已释放内存。要让它成立，得把整个对象图重建出来——代价远超收益。**这条路封死。**

### 三、于是分析只剩两条路（都不需要再试错的猜测）

1. **写入监视 arena 槽（`hash out - 0x50`）**：先用沙盒验证 `hw_watch`（perf 断点）本身在这套
   内核/ROM 上是否已经可用——历史记录里它在这个目标上多次致死，所以**先在沙盒上验证，再上真机**。
2. **把 `0x101da0` 的 trace 改成"边跑边采"**：既然"先抓参数、事后再 trace"必然踩死内存，那就需要
   agent 支持在钩子命中点就地跑 N 条 QBDI 指令（本会话早期就列为最想要的能力）——第 4 轮加的墙钟上限
   让这件事在机制上可行了。



## 2026-10-22（第四十二轮）—— 独立调用 `0x101da0`：**确定不行**（不是崩溃猜测，是有原因的失败）

先把上一轮那个"未定"结掉：

1. 上一轮怀疑的 1.6 MB drain 回复**不影响客户端**——实测 `capture_stop` 的 HTTP 回复只有 **938 字节**
   （`status=200`，`drained=0 drainedOk=true complete=true`）。那两次 `ECONNRESET` 是**目标重启窗口里的
   偶发**，不是稳定缺陷。测量结果否掉了我自己的假设，记在这里以免下一轮再顺着它走。
2. 给 harness 的 `post()` 加了"网络错误重试 3 次"（只改 gitignored 的 `_verify/_lib.mjs`，
   不掩盖产品错误：`ok:false` 仍然照原样返回）。加完之后同一条命令一次跑通。

3. **独立驱动渲染指令 = 致命**：自己 `malloc` bank/dst/指令副本，按已校验的调用约定
   `native_call 0x101da0(0x10, bank, bank+0x138, ins, dst, 0, 0)`，目标是**当场死亡**：

```
native_call -> ok=false error: the target disconnected while this command was running (it may have crashed)
alive: NONE
```

注意这条错误文本本身是**上一轮修的成果**：以前这里会是 60 秒静默 + `command timeout`，现在立刻
说出真因。结论：`0x101da0` 不是可独立调用的函数，它依赖解释器帧（`x26/x27` 之外还有帧内状态），
**这条路封死**，不必再试。

### 于是 X 的产地只剩两条路

- **(A) 写入监视**：arena 槽（`hash out - 0x50`，同线程稳定）已知，用 `hw_watch` 抓写者。
  历史记录里 `hw_watch` 在这个目标上多次致死，但现在有 `filter` + 立刻失败的错误通道，
  值得**先用一个安全目标（沙盒）验证 `hw_watch` 本身是否已修好**，再上真机。
- **(B) 种一份"活"的描述符去驱动 formatter `0xf643c`**（不是 `0x101da0`）：它是正规入口
  `f(dst, cap, descriptor)`，而描述符布局已全部读出（+0x10 常量池 / +0x18 参数向量 / +0x20 模板程序
  / +0x28 寄存器堆 / +0x30 参数向量）。把这几块都 malloc 出来、抄进去、改指向自己的副本，
  就能得到一个"给输入看输出"的渲染 oracle——**这条比 (A) 更安全**，因为它不依赖已释放的帧。

下一轮先做 (B)：先把 formatter 自己驱动起来（哪怕只渲染一个常量），再逐步把 32 字节喂进去。

### (B) 第一次尝试：失败，原因是我自己造成的

按 (B) 组了 `x2:64,@x2+16:256,@x2+32:1024,@x2+40:256`（描述符 / 常量池 / 模板程序 / 寄存器堆），
把四块都 malloc 抄好、把描述符 `+0x10/+0x20/+0x28` 指向副本，然后
`native_call 0xf643c(dst, cap, descCopy)` —— **目标当场死亡**。

原因写在代码里：`+0x18` 和 `+0x30` 这两块我**没拷**（4 个窗口的上限），于是把它们**清零**了，
而 `+0x18` 正是渲染指令读取的参数向量。也就是说这次不是"formatter 不可独立驱动"的证据，
而是"我喂了一份残缺的描述符"。下一轮必须先解决"5 块缓冲区、4 个窗口"的矛盾（提高
`ADH_MEM_WIN_MAX`，或分两次捕获同一份描述符的四个字段），**不能填零**。




## 2026-10-22（第四十一轮）—— 操作数模型用两份真实命中**过了可证伪检验**；独立调用 oracle 暂未成立

上一轮给出了一个假说：`A = word@pc+4 ^ key2`、`B = word@pc+2`（B 不异或），且 `x1 = base + A`、
`x2 = base + B`。**本轮把它当预测来检验**（`check_operands.mjs`，离线，输入是两份现场命中）：

```
tid=880  pc=0x72da988a72  words: 0x1 0x138 0xb9 0x1 0xffff 0x2
  A = word@pc+4 ^ 0xb9 = 0x0     B = word@pc+2 = 0x138
  x1 = 0x72da98c440 -> base = x1-A = 0x72da98c440
  x2 = 0x72da98c578 -> base = x2-B = 0x72da98c440     两者一致 ✓
tid=822 同样 words、同样 A=0/B=0x138，x1-A == x2-B ✓
```

两处独立命中都满足"同一个 base"，而且 `x2 - x1 = 0x138 = B - A` 精确成立。
所以三个常量（key2=0x00b9、B 不异或、槽位**字节**寻址）现在有事实支撑，不再是推断。

顺带确认：那条反复出现的模板指令字是 `0x0001 0x0138 0x00b9 0x0001 0xffff 0x0002`，
即"渲染 bank+0 处的值，第二个槽在 bank+0x138"。

### 独立调用 oracle：本轮没成立（记录为"未定"）

想法：既然调用约定已确定，就自己 malloc 一块 bank、把指令字抄进自己的内存、用
`native_call 0x101da0(0x10, bank, bank+0x138, ins, dst, 0, 0)` 直接驱动它——成功的话 b5 就变成
一个"给输入看输出"的函数（这是最直接的可复现路径）。

本轮这一跑在目标重启期间被 `ECONNRESET` 打断，**没有形成结论**；不作"不可行"记录。
下一轮重试并在失败时把 `native_call` 的返回/目标存活状态都打印出来（上一轮已验证：目标在命令中死亡
现在会立刻返回带原因的错误，不会再静默 60 秒）。

第二次重试同样在**第一步**（`capture_stop` / 装钩子）就被 `ECONNRESET` 打断，而 daemon `/health`
是 200、进程活着。日志给了线索：

```
cmdResult op=capture_drain id=cku matched=true bytes=1650712
[capture] session s_1f05k DROPPING - ring full: dropped=927 seq=1183 (complete:false)
```

即一次 drain 的回复有 **1.6 MB**。这不是"目标崩了"，而是**客户端在这条大回复上被重置**。
下一轮先处理这个：`capture_stop` 的调用方不该被一次 1.6 MB 的 drain 拖死（daemon 只用到其中的
`count`/`dropped`，却把整包留在链路上），要么在 daemon 侧限制单次 drain 的字节数、要么让 MCP 回复
只带计数——这属于"工具该打磨的地方"，比继续硬推分析更优先。




## 2026-10-22（第四十轮）—— 目标在命令执行中死掉时，立刻给出**有名字的失败**

上一轮给 trace 加了墙钟上限，但这一轮再试"拿现场参数去 trace 子解释器 `0x101da0`"时仍然是
**60 秒静默 + 目标重启**。真因不在预算：**参数指向的 bank 已经释放**，被 trace 的代码解引用垃圾指针，
进程当场死了。trace 的预算只能约束"跑多久"，管不了"跑的时候会不会炸"。

但这次静默本身是个必须修的缺陷：**调用方分不清"慢"和"死"**。修法在 daemon 侧：

- `pending` 的每条命令带上 `sessionId`；
- 新增 `failPendingFor(sessionId, reason)`：清理定时器、删表、以带原因的错误 reject；
- agent socket `close` 时调用它——日志实测：`agent CLOSE com.jingdong.app.mall s_78i4: failed 2 pending command(s)`。

于是同一次崩溃现在立刻返回：
`the target disconnected while this command was running (it may have crashed)`，
而不是等满超时再报 `command timeout`。

- 单测 `daemon/test/pending_disconnect.test.ts`：只失败该会话的命令（另一个会话的命令保留），
  并且清掉了定时器（否则测试进程会被 timer 拖住）。**2 条全过，typecheck 0。**
- device 实测：`trace_sub.mjs` 触发同一次崩溃 → daemon 日志里出现上面那行，不再有 60s 静默。

### 顺带记录：这条路暂时走不通（结论，不是猜测）

拿**已释放**的 bank 去 trace 子解释器，进程必死（本轮复现 3 次）。要让这条路可用，必须
"种一份仍然有效的 bank"——即把参数指向的内存**整族**复制到 malloc 出来的缓冲区，并重写其中所有
指针。这是可行的（`@`/`@#n` 已经能把整族读出来），但工作量比一个 round 大，留给后续。



## 2026-10-22（第三十九轮）—— 渲染指令的参数编码**用现场数据校正了**：`x1` 就是寄存器堆基址

上一轮我怀疑"`x26` 不是我以为的基址"。这一轮用一次现场命中把编码定死（`slots.mjs`）：

```
现场：x0=0x10  x1=0x72da98c440  x2=0x72da98c578  x3=0x72da988a72  x4=0x7318185420
      x2 - x1 = 0x138
指令字：0100 | 0138 | 00b9 | 0001 | ffff …
```

对照 handler 486 的三条指令：

```
f65b0  ldrh w8, [x21, #0x4]     ; A（后面 eor 了 key2）
f65b4  ldrh w9, [x21, #0x2]     ; B（**没有 eor**）
f65c0  eor  w8, w8, w24
f65c8  add  x1, x26, w8, sxth   ; x1 = x26 + A     ← 注意是 add，不是 add lsl#3
f65cc  add  x2, x26, x9         ; x2 = x26 + B
```

于是：`word@pc+2 = 0x0138` 正好等于 `x2 - x1` ✓；`word@pc+4 = 0x00b9 = key2`，异或后 A = 0，
所以 **`x26 == x1`**（这次调用的基址就是 x1）。`x0 = 0x10` = 16 个参数。
**结论：`x26` 确实是寄存器堆基址，槽位按字节寻址（不是 8 字节下标），且只有 A 参与异或。**

### 寄存器堆的形状（本轮实测）

`x1` 起 160 字节里是一个 **16 项指针数组**，指向一小片连续堆对象：

```
000:0x0 008:0x0 010:0x743b91a940(→"…3.6.5…") 018:0 020:0 028:0
030:0x…4e80 038:0x…4f30 040:0x…4e40 048:0x…4f20 … 078:0x…4de0 080:0x…4ed0
```

- 这些对象里有一个明确含 **`3.6.5`**（App 版本串），所以它们是**参数值对象**，不是摘要；
- 另两个发现：**formatter 的输出缓冲 `x4` 是 libjdg 里的静态缓冲**（base+0x14d420），不是堆；
- **两次尝试都没有在任何参数对象里找到 X**（`bank_follow.mjs`：`x1:160` + 链式窗口 400 字节，
  `X inside a bank/chain window: 0`）。

### 所以现在的判断

X **不是作为普通参数传进渲染指令的**：要么它由子解释器 `0x101da0` 从这些参数**算出来**（那才是
要复现的算法），要么它是参数对象里某个字段的**父对象**（还需再跳一层）。

### 下一轮

1. 用**同一个 tid** 把"渲染调用"和"encoder 命中的 X"对齐，取该次渲染的 `x3`（pc）与 `x0=0x10`，
   离线把这条模板指令的 A/B 解出来，确认渲染的到底是哪个参数；
2. 把 `x1` 起 160 字节里 16 个参数对象**逐个**用链式窗口读（4 个窗口分两次跑），
   确认哪个对象带着 32 字节二进制；
3. 若确认是子解释器算出来的，就把 `0x101da0` 的入口参数（`x0..x6` 已可读）连同它内部的
   0x102d10/0x102d50 调用一起纳入 trace（trace 需要加墙钟上限，见前面记的缺陷）。



## 2026-10-22（第三十八轮）—— b5 的"产地"缩到一条地址关系上；486 号渲染指令的参数配方解出来了

### 一、渲染指令 486 的参数配方（静态，读 handler 得到）

```
f65b0  ldrh w8, [x21, #0x4]     ; A（异或 key2 后是槽位号）
f65b4  ldrh w9, [x21, #0x2]     ; B
f65b8  mov  w0, w19             ; x0 = 参数个数
f65bc  ldrh w19,[x21, #0xa]     ; 本指令长度在第 6 个字
f65c8  add  x1, x26, w8, sxth   ; x1 = &REG[A]      ← 值槽地址
f65cc  add  x2, x26, x9         ; x2 = &REG[B]
f65d0  mov  x3, x21             ; x3 = pc（格式说明）
f65c4  mov  x4, x25             ; x4 = 输出缓冲
f65f8  bl   0x101da0            ; (n, &REG[A], &REG[B], pc, dst, 0, 0)
```

所以**被渲染的值来自 `x26 = *(state+0x28)` 那块寄存器堆里的 A/B 槽**，不是从描述符某个字段直接来的。
但实测：在 formatter **入口**处 `*(x2+0x28)` 那块全是 0，而在 `0x101da0` 入口处 `*(x1)`/`*(x2)` 也是 0
（124 次 null）——即槽位是在子解释器执行过程中才被填的，入口处读不到。

### 二、一条很强的结构性线索：线程私有 arena 的固定槽位

把三次独立捕获里"hash 驱动输出地址"和"hex 编码器输入地址"做对照（`addr_link.mjs`）：

```
encoder src = hash out - 0x50        76 / 92 / 34 次（每次捕获的主导差值，无第二种）
例(full_msg)：hash out = 0x72f08b0450，enc src = 0x72f08b0400
             另一路 hash out = 0x72f08b0410
```

也就是**同一块线程私有 arena 的固定槽**：`+0x400` 是编码器读的 32 字节，`+0x410`/`+0x450` 是两次 md5 输出。
这解释了为什么 b5 的 X 既"存在过"又"事后搜不到"——它在一个每请求复用、用完即被覆盖的槽里。

### 三、否定结果：**没有任何一次 hash 驱动调用把输出写进 +0x400**

按"同一线程、输出地址 == 编码器输入地址"配对（`addr_match.mjs`，14s、1400 行、16+16 条），
`address matches: 0`，只有稳定的 -0x50 邻接。所以 X **不是这个 md5 驱动**写的。

但顺着"32 字节摘要上下文"静态找，进程里确实有一族构造器把 `[ctx+0x18] = 0x20`（32 字节摘要长度）：
`0x8dbe0`、`0x8dc40`、`0x8dd34`、`0x8de78`、`0x8dfb4`。而 `0x8daf0` 那一族设的是 `0x10`（16 = md5）。
**下一轮就从这五个构造器入手**：找谁调用它们、以及它们初始化出来的上下文被哪次驱动调用消费——
若其中一次的输出落在 arena+0x400，X 的产地就闭合了。

### 三之补充：本轮结束时的硬结论（都用"不会漏"的方法做的）

1. **过滤钩子给出确定答案**：先用 encoder 学到线程的 X 槽地址（同线程稳定，实测 14 次命中同一地址），
   再装 `filter: x2=<该地址>` 的驱动钩子——**filter 命中数 0**。过滤钩子不会漏采样，所以这不是
   "没采到"，而是"这个驱动从不写那块内存"。同时 `memAfter` 仍产出 4 条 after 记录（seq=0，
   正是被 filter 拒绝的调用），证明钩子活着。
2. **全 .text 里引用 SHA-256 IV/K 表的只有两处**（`0x8c3f4`、`0x8c5a4`，都在驱动 0x8c1f8 的子函数里）。
   第三处 `0x1274ac` 的 `#0x2a4` 是 `adrp 0x66000` 的**字符串字面量**，不是 0x1562a4，属于 grep 误配。
   所以这个库里没有"第二个 SHA-256 实现"。
3. **X 也不含线程的 md5**：三份捕获、38 个 X，`X[0..16]` 或 `X[16..32]` 等于本线程任一次 md5 的
   命中数为 **0**；`X == md5||md5` 也是 0。

合起来：**X 既不是 md5、也不是 SHA-256、也不是它们的拼接**。arena 的布局（相对 encoder 的源地址：
md5 在 +0x10 和 +0x50，X 占 +0x00..+0x1f）说明它跟这些摘要在同一块结构里，但**写入者另有其人**。

### 三之三、下一轮的第一件事（已经具体到指令）

把 486 号指令里 A/B 两个槽位号**解出来**（`A = word@pc+4 ^ key2`、`B = word@pc+2 ^ key2`），
然后核对 `x1 == x26 + A*?` 是否成立——`x26` 的步长是 8（double 槽）还是别的，要靠这次核对定下来。
如果对不上，说明 `*(state+0x28)` 不是寄存器堆基址，而我一直在错的地址上找值槽（这能解释
"入口处槽位全是 0"）。这一步是纯离线 + 一次现场核对，不需要新功能。



### 四、方法上的两条记录

- 两个钩子抢一个小环形缓冲会互相饿死：`0x101da0` 不节流时 38 次命中把 encoder 记录全挤掉
  （`enc=0`）；给热点钩子加 `throttleMs` 才让关键钩子活下来。
- `memAfter` 现在真的可用了：本轮靠它把"驱动输出 == md5(完整消息) 10/10"钉死，
  并在 `fmt_out.mjs` 里第一次从 formatter 自己的输出侧取样（虽然 x0 并不是输出缓冲，见上）。



## 2026-10-22（第三十七轮）—— 链式解引用落地；hash 驱动被证明是 **md5**（10/10），并暴露了"截断取样"这个测量错误

### 一、能力：`mem` 可以链式跟指针（`@#2+8:256`）

`@x2+32:512` 只能跟一层。而真正要看的结构常常是三层：format 描述符 → 参数向量 → 值。新增
`@#<n>+<off>:<len>`：**取第 n 个窗口已拷到的字节，在 +off 处读一个 u64，再从那个地址拷窗口**。
窗口按顺序处理，所以引用的一定是更早的窗口；安装时校验"8 字节必须落在该窗口内"。

- agent：`parse_window`/拷贝循环/记录（记录里带 `deref:true`、`ptr`、`from:<n>`）；
  `parse_mem_spec` 增加 `froms[]`；规范化为 `@#1+8:128`。
- daemon：`parseMemWindows` 接受同一语法并做同样校验，两侧不会一个收一个拒。
- 验收：`tools/verify_v114_window_chain.sh`（device）——三个 malloc 组成 C←A←B 的链，
  窗口 1 必须解到 A、窗口 2 必须解到 C 且字节是 `5a00`。**PASS**。
- 单测：`native_hook_mem.test.ts` 增 1 条（含"引用未来窗口""8 字节越界"两种拒绝），12 条全过。

### 二、结论：SHA-256 驱动的输出**就是 md5**，10/10 完整消息

这一轮第一次用**驱动自己写出的字节**（`memAfter` 修好之后）做判定，而不是在宿主重算：

```
driver out == md5(full message):  10/10      （消息长度 564..1663，两条窗口拷满）
```

**顺带纠正两个此前的错误**：

1. 之前把它叫"SHA-256 驱动"是错的——它算的是 **md5**，输出 16 字节。x2 处那 32 字节里，
   **前 16 字节是摘要**，后 16 字节是线程级状态（同一线程多次调用尾部相同）。
2. **此前所有"sha256/md5 对不上 b5"的结论都受同一个错误影响：消息被截断在 1024 字节**。
   `mem x0:1024` 只拷一个窗口，而请求行有 1550~1663 字节。所以那些"对不上"有一部分是
   **测量错误**，不是目标的算法。这一轮改成两窗口（2048 字节）之后，md5 立刻 10/10 对上。
   （"协议分析：能用捕获对上的公式必须对过再写出来"——这次是反例：没对上的必须写清是哪种没对上。）

### 三、X 仍然不是这几类（现在这些排除是"完整消息"上做的）

- 不是 `sha256(完整消息)`；
- 不是两个 md5 拼接（任意两条消息的摘要、两种顺序，全部试过）；
- 不是同一条消息的 `md5||md5`。

所以 b5 的 32 字节来自**另一种原语**，而且不是这个 md5 驱动。下一轮的方向：`0x101da0`（子解释器）
是 486 号渲染指令调用的那个函数，被渲染的值是它的**参数**；但它的 x0/x1 常常不是可读指针
（本轮 `mem x0:32,x1:32` 全是 `unreadable`），所以要用 `mem:"auto"` 让它自己挑像指针的寄存器，
再拿 backtrace 定 caller。本轮已把该钩子加 `throttleMs:60`（否则 38 次命中把环形缓冲挤爆、
encoder 记录全被淘汰——这也是"先装热点钩子会饿死关键钩子"的又一次实证）。



## 2026-10-22（第三十六轮）—— 两个真实缺陷 + 一个能力和一条结论：jdgs 的 b5 不是这几类哈希

本轮是"边分析边修工具"的典型一轮：目标（京东 jdgs 的 b5）还差最后一跳，但**工具被修好了两处**，
而且这两处都是"看起来没问题、实际会让结论跑偏"的类型。

### 一、能力：`mem` 现在能跟一层指针（`@x2+32:512`）

`mem` 以前只能从寄存器取窗口。而混淆目标里真正要看的结构全是**指针的指针**：VM 帧把"当前指令记录"
放在 `*(state+0x20)`、派发表槽位指向目标、链表头指向首节点。在 libjdg 上实测：解释器的指令记录
就在 `*(state+0x20)`，等第二次 `memory_read` 去读时**那一页已经 munmap**，所以拿不到。

- 语法：`@x2+32:512` = 读 `(x2+32)` 处的 u64，再从**那个地址**拷 512 字节。
- 记录里带 `deref:true` 和 `ptr:"0x…"`，读不到就是 `null`/`unreadable`，绝不猜。
- 实现：`agent/src/hook/native_hooks.cpp` 的 `parse_window`/拷贝循环/记录输出；宿主侧
  `daemon/src/native_hook_args.ts` 的 `parseMemWindows` 同步接受 `@`（否则 agent 收到了、daemon 先拒了）。
- 验收：`tools/verify_v112_indirect_window.sh`（device）——在同一份记录里，普通窗口必须是
  **指针值本身**，deref 窗口必须是**指针指向的字节**，两者都不能少；沙盒里用 `atoi` + 我们自己 malloc
  的两个缓冲区构造这个形状，PASS。

### 二、缺陷：`memAfter` 的记录**没有 seq**，所以按 `(hookId, seq)` 永远配不上

文档写明"寄存器事件和内存记录按 `(hookId, seq)` 配对"，而 post-call 记录以前**根本没有 seq**。
后果不是"少一个字段"，是**每一份"函数写了什么"的拷贝都被读者静默丢掉**——本轮在目标上三次得出
"memAfter 什么也没产生"的结论，其实记录一直在环形缓冲里，只是配不上。

- 修法：`adh_native_hook_record` 增加 `seq_out`，stub 把它放在保存区尾部的空槽 `[sp,#240]`，
  after-stub 再把它作为第 4 个参数交给 `adh_native_hook_after`，记录里写 `"seq":N`。
  （不放进 ctx：那会在多线程热钩子上把两次命中混在一起。）
- 顺带修形状：after 记录以前是**平铺**的（`reg/offset/got/hex` 在顶层），pre 记录是 `mem:[…]`。
  宿主预览函数读 `obj.mem`，所以 post-call 拷贝的预览**一直是空的**。现在两边同形。
- 验收：`tools/verify_v113_memafter_seq.sh`（device）——pre 与 after 必须同 seq、同窗口、同字节，PASS。

### 三、结论：京东 jdgs 的 b5 不是这四类（都是有实验的排除，不是猜）

用「先证明能对上，再写公式」的标准，本轮把 b5 的输入侧排除到只剩一条路：

| 假设 | 做法 | 结果 |
|------|------|------|
| `b5 = sha256(请求行)` / `sha256(JSON)` | 钩 SHA-256 驱动 `libjdg+0x8c1f8`（`(buf,len,out)`，5 状态派发），抓全部消息；26 份完整消息 | **不匹配**（含 LE32 字节序） |
| 同上但换算法 | md5/sha1/sha512/sha512-256/sha3-256/blake2s/sm3 × {BE, LE32, LE64, REV} | 6080 组**全不匹配** |
| `b5 = hex(sha256(JSON 去掉 b5))` | 只对同一 payload 去掉 `"b5":"…"`（三种切法）再哈希 | 不匹配 |
| `b5 = RC4 密钥流` | 钩 KSA 拿 20 字节 key，用**已验证 256/256 的教科书 KSA** 重放，扫前 4096 字节 × 3 种字节序 | 不匹配 |

同时确认了两件事，把方向压缩到"VM 自己算的"：

1. **`libjdg+0xf643c` 不是格式化器，是字节码解释器的单步**（本轮纠正了上一轮的判断）。
   反汇编：`ldr x8,[x2,#0x20]` → `ldrh w23,[x8,#4]` → `ldrh w9,[x8,#8]` → `eor` → `cmp #0x23a` →
   `table[…]` → `br`。指令记录是 **10 字节**（`db02` 之后 4 个 u16），跳表在 `.rodata` 0x64320。
   `trace_digest` 只跑出 31 条指令就 `completed`、返回 1，正是因为**用一份过期的 state 重放**会走
   "opcode 越界"的出口分支——不是函数小，是参数死了。
2. **SHA-256 的 IV/K 是标准值，但按小端逐字存放**（进程内 0x156284 读出 `67 e6 09 6a …`，
   0x1562a4 读出 `98 2f 8a 42 …`）。所以"结构是 SHA-256 却怎么也对不上"这类现象，先怀疑字节序。

下一步（已具备条件）：用 `@x2+32:512` 在**命中当刻**拿到 VM 的指令记录（本轮已验证能拿到 512 字节，
`ptr` 就是 `*(state+0x20)`），再把 0x64320 跳表按 opcode 静态映射到 case，就能读 b5 那段字节码。

### 三之二、已经拿到 VM 程序本身（结构性发现）

同一份 `@x2+32:512` 在**5 个不同请求**上各取一次，结果**逐字节相同**：程序是**按 URL 类型的静态字节码**，
请求数据不在代码里。

**程序块布局（从解释器自己的派发读出来的，不是猜的）**：

```
0xf6468  ldr  x8,[x2,#0x20]        ; x8 = 程序块
0xf6470  ldrh w9,[x8,#8] ; eor w9,w9,w23 ; cmp #0x23a   ; w23 = ldrh w23,[x8,#4] = XOR key
0xf64b4  add  x21,x8,#0xa          ; PC 从 header+10 开始
0xf6500  ldrh w8,[x21] ; eor w8,w23  ; opcode = [pc] ^ key
0xf6518  ldr  x8,[x20,x8,lsl#3]     ; 表在 0x64320，8 字节一项
0xf66d0  add  x9,x28,x9             ; case = 0xf64bc + entry
```

所以块是 `[u16][u16][u16 key][u16 key2][u16 首 opcode][u16 流…]`，流里每个字异或 `key` 才是 opcode，
**操作数另用 `key2` 异或**（`eor w8,w8,w24`）。解码后是**定长 5 字（10 字节）一条**：
`[opcode][arg][arg][arg][0x231]`。本轮抓到的 b5 程序是 **41 条指令**，opcode 在 41 条里全不重复
（267/275/283/139/…/115），即**每条指令一个专属 handler**——这就是为什么静态 xref 永远找不到"复用的派发"。

**handler 表已可离线读**（`adhd-data/_verify/vm_table.mjs`）：0x64320 起 571 项，`case = 0xf64bc + int64`，
op 0 → case 0xf64bc（就是"无效/返回 1"的出口，自洽）。举两个已解出的语义：

- **op 267**（case 0xfab34）= `REG[a] = (REG[arg1^key2] >= POOL[imm64]) ? 1 : 0`，pc += 14；
- **op 3**（case 0xf6530）= `jmp pc + (int16)[pc]`（相对字节跳转），pc = target+2。

即：**这是一个变长线程码 VM，`x26 = *(state+0x28)` 是寄存器堆，`x27 = *(state+0x10)` 是常量池**。
剩下的活是"把 41 个 handler 逐个写成语义 + 读这 41 条指令"，纯离线，不再需要设备。

**ISA 已解（离线，`adhd-data/_verify/vm_summary.mjs` + `vm_table_dump.mjs`）**：
571 项分发表全部读出（569 非零、530 个不同 case、40 个 case 被多个 opcode 共用）。寄存器堆按 **8 字节槽、
以 double 访问**（`ldr d0,[x26,x8]`），所以这是**数值/JS 语义**的 VM。指令布局：
`[opcode u16][body…]`，**PC 指向 opcode 之后**，下一条 opcode 预取在 `pc + size - 2`，
`size ∈ {8,10,12,14}`（8 = 3 个 body 字；14 = 6 个 body 字，含 imm64）。

已确认的 opcode 家族（举例）：`561`=减法（`sub/add/neg`，size=10）、`267`=`>=` 立即数池、
`234/238/242/226/243/195/203/211/219/171/187/227/275/283/307/315/323`=各类浮点比较
（`fcmp` + `cset lo/ls/hi/hs/lt/le/gt/ge/ne/mi`）、`139/163`=乘法、`27/59`=无符号取模（`udiv`+`msub`）、
`43`=有符号取模、`11/35/179`=移位/取反、`115`=乘加、`490`=多路比较（`b.lt/eq/ne` 链）、
`131/147`=取值、`155`=存属性、`347/331/355/363`=纯 `add` 链（拼接）。

### 三之三、一个必须记下来的否定结果：cap=65 抓到的程序**不是** b5 的产生者

把这 41 条指令全部解出来后，它的语义是**纯"比较 + 加减"**，**41 个 handler 里没有一个 `bl`/`blr`**——
没有调用的程序不可能算出 32 字节摘要。所以：

- `mem x2` 拿到的"当前程序"是 assembler 为了**格式化数字**临时跑的一段（时间戳 `%lld`、字段拼接），
  和 b5 无关；
- 也就是说 **`x1 == 65` 这个过滤器选错了 VM 调用**。真正可靠的那条线索只有一个：**通用 hex 编码器
  `0x98c1c` 的输入 hex 后等于目标自己写出的 b5**（正面识别，4/8 命中）。
- 下一轮的正确做法：**用 hex 编码器当锚点**——它在命中当刻带 `backtrace`，同线程里紧邻它之前的那次
  VM 调用才是 b5 的产生者；把 `backtrace` 里的返回地址与 0xf643c 的调用点对齐后，再按 `(tid, 次序)`
  取那一次的 `@x2+32:1024`，而不是按 `cap == 65` 取。

### 三之四、锚点法已经落地：**opcode 486 就是 hex 编码**

`0xf65f8`（`bl 0x101da0`）落在 case `0xf65b0..0xf664c` 里，而这张表把它对应到 **opcode 486**；
紧邻的 487（case 0xf664c，内含 0xf6698 的第二次 `bl 0x101da0`）是它的孪生。于是"哪个程序在算 b5"
变成一条可检索的属性：**含 486 的程序才是**。

顺带把 size 表离线建好了（`vm_isa.mjs` → `vm_isa.json`）：477 个 opcode 有定长，
`size = nextOpOff + 2` 在全部 477 条上**零反例**（size 直方图 2/6/8/10/12/14/16/18/22/24），
94 个是 pc 运行时决定的（3 分支、486/487 调用、490 多路比较）。这就是读这个 VM 需要的全部元数据。

按此扫描（`vm_find_program.mjs`，钩解释器入口 + `@x2+32:1024`）：**15 个不同程序块里 10 个含 486**，
所以"编码器调用确实来自 VM"。但**框架还有一个未闭合点**：按 `key = block[+4]`、`pc = block+0xa`
走，每一步都得到 opcode `561`（每 10 字节重复），显然不是"41 条各不相同的指令"。
两种可能：(a) 561 是宏指令/超级指令，真正的子操作在 payload 里；(b) 我对 `[*x2+0x20]` 的解释
（"程序块从 +0 开始"）偏了 8 字节，真实指令流从别处开始。**判定方法已经具备**：把捕获到的
**状态**和**程序块**各拷一份到 malloc 出来的内存、改写其中的指针（+0x10 常量池、+0x28 寄存器堆、
+0x20 程序块指向副本），再 `trace_digest 0xf643c` —— 这次上下文是活的，能看到 pc 真正怎么走。
这正是上一轮"种 contexto"失败的反面：上次种的是已释放的调用帧，这次种的是**只读的程序与状态**。

**本轮试了，结果是超时 + 目标重启**（60s `command timeout`，pid 从 9677 变成 12408）。两点教训：

1. **`trace_digest` 只有"指令条数预算"，没有"墙钟预算"**，而且它跑在命令通道上：一个同步的 VM
   在 QBDI 下把通道占满 60s，调用方只看到超时，分不清"还在跑"和"已经死了"。应加 wall-clock 上限
   （例如 5s）+ 到达上限时按"未完成"返回，并把 200000 条预算在慢目标上换算成时间再校验。
2. 种副本时 `+0x18`/`+0x30` 这两个字段也指向原始块家族，我只改了 `+0x10/+0x20/+0x28`；计算跳转
   （486/487/3）用它们算出来的目标会落到我们副本之外。**所以要么把整族指针都指向副本，要么把
   计算跳转的目标范围也用 `mem` 窗口一并拷出来**——这是下一轮的第一步。

### 三之五、**纠错：`0xf643c` 不是 VM，是"格式串解释器"**——这一步把 b5 的方位彻底定住了

用 `@` 解引用把 `x2` 指向的四个缓冲区都摊开之后，框架问题自己消失了（`find_x_in_args.mjs`）：

```
x2+0x10 -> 常量池: "====\0\0%s_%s\0" "0.3.0\0" "%lld\0" "b1\0b2\0b3\0b4\0b5\0b7\0b6\0" …
x2+0x18 -> 参数向量: {ptr, ptr, ptr, 0x67c}      ; 0x67c = 1660，正好是一条请求行的长度
x2+0x20 -> 编译后的模板程序（`====` + 10 字节记录串）
x2+0x28 -> 值槽/寄存器堆
x2+0x30 -> 与 +0x18 同一份参数向量
```

所以：**`0xf643c` 是一个 printf 式模板解释器**，模板字符串是 `"====%s_%s" + "0.3.0" + "%lld"`
（正好能拼出 `…==.X_Y.0.3.0.<时间戳>` 这种形状），`x1` 只是输出缓冲区大小——这就是为什么
cap 会取 16/50/65/193 四个值（不同字段、不同缓冲）。**通用 hex 编码器（opcode 486 → `bl 0x101da0`
→ `0x98c1c`）只是它的一个"渲染指令"。**

**结论：b5 的 32 字节 X 不是在这里算的，format 只负责把它渲染成 64 个字符。X 走 `x2+0x18` 那条
参数向量进来。** 这也解释了之前所有"把它当 VM 读"的困惑：那 41 条"指令"其实是模板指令，
全 561 的走法是我按 VM 尺寸表解码模板得到的必然结果。

下一步（唯一还缺的一环，而且是工具缺口）：**追一层指针链**。`@x2+24:256` 只到"参数向量"，
要拿到向量里那三个指针**指向的值**还需要"解引用后再解引用"。两种做法：

- 立刻能用：两段式——先用 `@x2+24:256` 拿到向量里的指针值（记录里就有），马上 `memory_read`
  这三个地址；请求还没结束时它们通常还活着。
- 该补的产品能力：**链式解引用**（`@@x2+24:32:256` 之类），或给 `mem` 的 deref 语法加"在上一窗口
  的第 N 个 8 字节处再跟一层"。这一轮已经证明：**分析这类结构，卡住我的从来不是缺少某个算法，
  而是"指针只能跟一层"。**

**另一个新暴露的缺陷**：`memory_read` 对 libjdg `.bss` 里某些地址（例如 `base+0x195cf0`）**同一进程内
一次 `size=32` 成功、下一次同样参数只回 `no hex`**，而且不带任何原因字段（没有 `unmapped`/`short`/`EIO`
的区分）。本轮 `bss_scan` 因此无法稳定工作。文档承诺了 `requested/short`，实现上应把失败原因带出来——
否则"读不到""地址错了""目标拒绝 `open("/proc/self/mem")`"三者无法区分，而这是本轮踩到的三个坑里最难
自查的一个。

### 三之六、给 b5 一个"可检索"的终点
现在离"算法"只剩两步，而且都不需要猜：

1. 用 486 作为签名找到一个**含 486 且框架自洽**的程序（当前 15 个块里 10 个含 486，但走出的
   指令流全是 561，说明框架还没对上）；
2. 把该程序的每条指令按 `vm_isa.json` 的 size 解开、按已解出的家族（比较/加减/取模/移位/拼接）
   翻成伪代码，b5 的输入就在其中——因为 `b4`（412/412 对上）和 `b6`（6/6 对上）已经证明这套
   JSON 的字段是可逐条复现的，b5 只差"用哪几个字段、按什么顺序、做了什么算术"。




顺带用池里那条字面量 `====.%s_%s.0.3.0.%lld` 做了一次定向验证：b4 本身是 base64 且以 `==` 结尾，
模板的 4 个 `=` 正好把它补到 `====`，于是试了 `"<b4 补齐>==.<x>_<y>.0.3.0.<b7>"` 的 4248 种组合
（x/y 取 b1/b2/b3 的两两排列 × 三种补齐方式 × 两种字节序），**全部不匹配**。这条线索到此为止，
再往下的代价是"读懂解释器的 0x23b 个 opcode"，不是再猜几个字符串。

### 四、本轮顺带记录的两个"测量陷阱"（写进 CASE_STUDIES）

- `native_call` 的 `args` 会填 x0..x7：**给被调函数一个 NULL 的目的指针会直接把目标打死**
  （本轮重启了京东 3 次）。要调一个"会写输出"的函数，先 `malloc` 一块再传。
- 钩**极热**的函数（`strlen`）本身就会打死目标，跟 stub 无关；做 `memAfter` 的 A/B 必须用冷函数
  （`atoi`/`labs`），否则 A 组也崩，实验什么都证明不了。同理，`memory_read` 的参数是 `size` 不是 `len`，
  传错时每个地址都回 `bad size`，看起来像权限问题。

## 2026-10-22 —— MCP 面板收成三段：安装 / 连接 / 配置（跟 iOS 面板同形）

用户给了 iOS 版的面板截图（安装 `pip install ios-decrypt-hub` → 连接 `idh connect <host>` → 配置 `mcpServers` 片段），
一句话点评本轮之前的实现：「跟写作文一样」。结论：**不要把客户端怎么配置讲一遍**，三段就够——
`adh`（PyPI `android-decrypt-hub`，源码 `decrypthub/adh-cli`）是产品入口，`adh connect` 存地址，`adh mcp` 把
`POST /mcp` 转 stdio；客户端要的只是那 8 行 JSON。

本轮返工（前两版都错了：先是面板摊 HTTP 端点 + JSON-RPC，再是我给开发侧 CLI 加了个同名 `mcp` 子命令、面板列五个客户端命令）：

- `daemon/src/mcp_onboarding.ts` 只剩四个字段：`note`（"仅限可信网络"）、`install`（`pip install android-decrypt-hub`）、
  `connect`（`adh connect host[:port][/package]`）、`config`（`mcpServers` 块，`args` 写成一行）。删掉
  `MCP_CLIENTS`/per-client 命令/endpoint/pinned/clients/tools/verify —— 面板不用的就不生成。
- `GET /api/mcp/config` 用请求 Host 生成 connect 地址，`?package=` 让 connect 带上包名，非法包名 400；payload 不再夹 `quickAsks`。
- 面板：`安装` / `连接` / `配置` 三段，各一个复制按钮，页脚只有"仅限可信网络"。配置块在 HTML 里有默认值（断网/旧 daemon 也能看），
  由 API 覆盖；**单测逐字节比对 HTML 默认值与 `adhClientConfig()`**，防两边漂移。
- 验收：`mcp_onboarding` 8 条单测（三字段形态、JSON 可解析且不含 http、钉包只改 connect、HTML 默认值一致、包名/Host 校验）；
  `tsc` 0；临时实例 `/api/mcp/config` 三段内容正确、`?package=` 与 400 正确；`verify_v19_settings` PASS；
  面板 headless 截图核对（普通 + 钉包两态）。
- **没有重启用户正在跑的 8088 daemon**（上面有 6 个京东会话）——新路由要重启 `adhd` 才生效；旧 daemon 上配置块显示 HTML 默认值，
  安装/连接仍按当前页面地址生成。
- 顺手发现（**不是本轮引入**）：`v10_webui` 的 4 条旧断言（file browser / one-click dump-all / dump download /
  workbench chrome）在 HEAD 上本来就红——`dumpAllDex` 和旧 dump 面板已在 937c3c9 随"一键脱壳"改版删除，断言没跟着改。
  本轮没动它，避免和并发会话正在改的 dump 面板打架；下次动 Web 时一并修。

下一步：重启 `adhd` 后刷新面板，按面板顺序真跑一遍 `pip install` → `adh connect` → 在 Claude Code 里 `claude mcp add …`，
确认 `adh devices` 为 online 且客户端能列出 ADH 工具。

## 2026-10-22 —— Web「系统」页：检测摘要不再撑满半屏

截图反馈：`系统` 页左侧上半屏是空白，5 条记录挤在底部。根因是 `#sy-radar`（`.detect-radar`）和列表一样是
`.list-pane` 的直接子元素，吃到了 `.list-pane > div { flex:1 }`，一行摘要被拉成半个窗格。修法一行：
`.list-pane > .detect-radar { flex:0 0 auto; overflow:visible }`——两个类选择器压过 `div`，不依赖书写顺序。

顺带两处显示修正（同一张截图里的「看不懂」）：

- 摘要从裸「未开」改成「系统检测：未开」，细则进 `title`：写清去 Manager → 应用 → Hook 配置 → 系统检测 打开，
  并列出 `caveat` 与 `unchecked` 的未覆盖项（这两个字段接口一直返回，之前直接丢掉了）。
- 列表时间统一 24 小时制（新增 `fmtTime()`，`hour12:false`）：`toLocaleTimeString()` 跟浏览器 locale，
  中文界面里显示成 `5:35:08 PM`。

回归守卫 `daemon/test/web_system_pane.test.ts`（5 条）：读 `public/index.html` 断言 opt-out 规则存在且压过
`.list-pane > div`、`#sy-radar` 仍在 banner/列表之前、摘要文案与 `title`、没有裸 `toLocaleTimeString()`、内联脚本可解析。
本机沙箱里 `npm test` 的 `node --test` 子进程 spawn 被拒（EPERM），单文件用 `node test/web_system_pane.test.ts` 直接跑（5 pass）。

## 2026-10-22（第三十五轮）—— **密钥可按需抓取并逐位置验证**；b5 又排除 816 种构造

### 一、能力：20 字节会话 key 现在**随手可取**

上一轮只能靠"重启 + 抢时间窗"抓 KSA。这一轮把它变成一条稳定配方：

```
native_hook { addr: libjdg+0x89480, mem: "x1:32", memAfter: "x0:258" }
```

- `+0x89480` 的实际签名是 **`KSA(state258, key, keylen)`**（`strb w8,[x21,x8]` 填 S=0..255、`strh wzr,[x21,#0x100]` 清 i/j），所以 `x0` 是 258 字节状态、**`x1` 是 key、`x2` 是 keylen**；
- `mem` 在入口抓 key，`memAfter` 在返回后抓状态 → 一次命中同时拿到"输入"和"输出"；
- 本地跑一遍教科书 KSA，与抓到的状态比对：**256/256 位置全等**（三个线程各验一次，不是"接近"）。

抓到的两个 20 字节 key：

```
tid 25730: 599887fa82edfe742c13b88e8b98ebe3e521b98a
tid 25731: edf787fa82edfe74987cb88e8b98ebe3514eb98a
```

对比印证了文档里的结构：`[3..7]=fa82edfe74`、`[10..15]=b88e8b98ebe3`、`[18..19]=b98a` **完全相同**，只有 **`[0..1]`、`[8..9]`、`[16..17]` 三个 16 位字段**在变（`[2]` 本次为 `0x87`，文档记的历史值是 `0x60`，也属可变）。同一个函数还会被别处当**通用 KSA** 使用（有一次 `x2=0x20`、key 是 ASCII 的 32 个 hex 字符）。

这条能力对 b4 也直接有效：以前要"重启抢窗口"，现在任何时刻钩一次就能同时拿到 key 与 KSA 后的状态。

### 二、b5：816 种构造全否（本轮新增的排除）

用上一轮同样的办法：钩 md5 本体拿到 args/JSON 两份 preimage（JSON 里**已经带着 b5**），钩 KSA 拿到**同线程**的 key，然后按 tid 联合起来试：

| 构造族 | 结果 |
|---|---|
| `HMAC-SHA256(key, ·)` / `HMAC-MD5(key, ·)` | 否 |
| `sha256(key‖m)` / `sha256(m‖key)` | 否 |
| `sha256/sha1/md5(m)` 单独 | 否 |

`m` 遍历了：args 全文、`POST <path>` 之后的剩余、JSON 去掉 b5、b4 的 ASCII、**b4 的 base64 解码后**、`md5(args)` 的字符形式。共 **816 组 × 76 份 preimage × 13 把 key**，零命中。

顺带查了两件事：

- **`+0x98c1c`（通用 hex 编码器）确实在签名路径上被调用，且入参长度 `x1=0x20`（32 字节）** —— 形状正好是"32 字节 → 64 hex"。但它抓到的 `x0` 内容却是 `POST /client…` / `{"b1":"68dd5…`（args 与 JSON 文本），所以**要么它不是静态读出来的 `hex_encode(in,len,out)`、寄存器角色不同，要么它并不是 b5 的生产者**。这条没定性，下一轮补 `memAfter` 看输出即可判明。
- key 与状态都能复现这一点，反过来证明 b4 的 RC4 就是标准 KSA + 标准 PRGA —— 与第十一轮结论一致。

### 三、下一步（已定，按顺序）

1. 钩 JSON 追加点 `+0x102260`（记录里它按 `body → jdgs JSON` 的固定顺序追加），把 `"b5":"<64hex>"` 出现的那一次连同**源指针**抓住 → 顺着源指针回查是谁写的；
2. 给 `+0x98c1c` 补 `memAfter`，用输出判定它到底是不是 hex 编码器（`*out_len == len*2`）；
3. 若以上都指向"外部/Java 产出"，再回头验 `Bridge.entry` 的 oracle 回放（第八轮已知 `java_call {detach:true}` 3 ms 能拿回完整 jdgs）。

### 四、第 1 步先跑掉了：**参数拼接口味 950 组全否**

服务端签名最常见的是"参数按 key 排序后拼接"，而我此前只试过**原样顺序**，这是个明显的空格。补上：

| 变体（× `sha256`/`md5`/`sha1`/`HMAC-SHA256(key,·)`/`sha256(key‖·)`） | 结果 |
|---|---|
| 原样、按 key 排序、值拼接、仅 key、`k=v` 小写化、带 `POST <path>` / 只带 path / 只带 method | 全否 |

共 **950 组 × 19 个不同 b5**。**结论：b5 不是"对可见入参做排序/裁剪/改大小写后的普通摘要"。**

### 五、顺带查到的两件事（有价值，但都不是 b5）

- **`libcrypto.so`（Conscrypt BoringSSL）里的 `SHA256()` 一次性入口确实在签名线程上被调用**，入参以**会话 key 开头**：
  - 一次是 ASCII 形式 `f9574f60dda83b2634898264e14a82db`（就是 KSA 那边见过的那个 32 字节 ASCII key）；
  - 另一次是**裸的 20 字节 key** 后接 0。
  两次的输出（`03a0d711…` / `ee2d7b78…`）**都不等于任何 b5**。所以"有一条 keyed SHA-256 路径"是真的，只是不是 b5 这条；同时它说明**"不走 Java JCA"并不能排除 BoringSSL 的一次性入口**——下一轮找 b5 时这条要一起钩。
- 进程里除 `libjdg.so` 还有 `libWangyinCryptoLib.so`、`libjdJmaEncryptUtil.so`：b5 由**别的 so** 产出的可能性还没排除。

### 六、第 2/3 步也跑掉了：blob 其它入口 + 常量盐 + 两段拼接

**静态：哈希 blob 的真实入口只有 4 个**（范围 `0x8c1f8..0x8d200`，按"有正常 prologue 的 `bl` 目标"筛）：

| 入口 | 调用者数 | 已钩 | 结果 |
|---|---|---|---|
| `0x8c1f8` | 1（`0x98998` md5_hex） | 是 | 52/52 全是 16 字节 md5 |
| `0x8c840` | 10 | 是 | 命中 94 次，**没有 32 字节输出对上 b5** |
| `0x8caf4` | 3 | 是 | 命中 360 次，同上 |
| `0x8d144` | 3 | 是 | 命中 184 次，同上 |

后三个的 `x2` 不是输出指针（`memAfter` 读到的是栈内容），所以"它们是不是 SHA-256"仍未定性；但**没有一个是 b5 的生产者**。

**1.63M 个常量窗口全否**：把 `libjdg.so` 里每个 4 字节对齐的 16/20/24/32 字节窗口当成盐，试 `sha256(k‖m)`、`sha256(m‖k)`、`hmac(k,m)`，`m` 取 args 全文／去掉方法路径／JSON 去掉 b5 —— **零命中**。所以 b5 不是"SHA256(硬编码盐 ‖ 入参)"。

**两段拼接也否**：此前试 `md5(args)+md5(json)` 是**循环的**（那份 json 里已经含 b5，永远不可能对上）。这次先把 b5 那一对删掉再算：`md5(args)‖md5(json−b5)` 及另外 31 种组合 —— 仍然零命中。

### 七、最有价值的一条结构事实：**b5 是"算好了再传进来"的**

用 `filter:"x0=65"` 钩 `malloc`（32 字节摘要 hex 成 64 字符必然要 65 字节缓冲），按调用者做直方图，libjdg 里只有两处：

- `libjdg+0x98c1c`（那个通用 hex 编码器）：确实按 `len=32` 被调用，但**入参是 args / JSON 的文本**，不是 32 字节摘要；
- `libjdg+0x8db48`：反汇编是 `strlen(x)+1` → `malloc`，也就是**把一段已经存在的 64 字符串复制一份**（`[x19+0x18]=0x10` 的 64 字节上下文）。换句话说 **b5 在这个点之前就已经是 64 个字符了**，它的生产者在 **JSON 组装点的上游**。

这条把搜索方向从"哈希 blob"整体移到了"组装点上游"，也解释了为什么一路猜哈希构造全否——**它可能根本不是在这段代码里算的**。

### 八、本轮新发现的两个工具缺陷（都已记录，未修）

1. **在"软撤过的地址"上重装会造出一个死钩子**：在已软撤的 `0x8c1f8` 上再 `hook` 返回了 **id=11 且 0 命中**（旧补丁还在、新补丁无效），而预期是**复用/重新激活旧 hook**。第三十三轮修过 reactivate，但那次验的是"换 filter 重装"；这次是"带 `mem`+`memAfter` 重装"，reuse 匹配没命中。**这是同一个缺陷类的残留口子。**
2. **`status.hooks[]` 只列 active 的 hook**，soft 撤掉的只体现在 `slots.used`。后果：`unhook_all` 这类按列表清理的工具**看不到它们**，于是"used=5 但 hooks=[]"看起来像 bug（其实不是），而且这些槽位在进程内再也无法按 id 释放。至少应让 `status` 可选列出 inactive 项与其 id。

### 九、往上游走了一层：**b5 是"SHA-256 结果对象"的 hex 字段**

顺着 `strdup` 那个点回查，找到它的入口 **`+0x8daf0`**：

```
stp x29,x30,[sp,#-0x30]!      ; fn_8daf0(const char *s)
ldr x8, [x21, #0x498]         ; 从 GOT 槽 0x156498 取分配器
mov x20, x0                   ; s
mov w0, #0x40                 ; 64 字节上下文
blr x8                        ; 分配
... stp q0,q0,[x19] / stp q0,q0,[x19,#0x20]   ; 清零 64 字节
str w8, [x19, #0x18]          ; w8 = 0x10
... strlen(s) -> malloc(len+1) -> 复制字符串
```

`[ctx+0x18] = 0x10` + 一个 **64 字符**的 hex 字符串 —— 这个组合就是**"算法=SHA-256（id 0x10）、hex 结果"的对象**。所以可以确定：

- **b5 是 SHA-256 的 hex（32 字节 → 64 字符）**，这个结论现在是结构证据，不再是猜测；
- 但它**在进入 JSON 组装之前就已经算完了**，libjdg 这一段只是把现成的字符串包进结果对象。

又试了"签载荷本身"这一族（`ep` / `ext` / `eid` / `x-api-eid-token` / `functionId` 各自、解码后、以及 `ep+ext` 组合的 `sha256`/`md5`）—— 仍然零命中；顺带确认这三条请求的 `ep` 完全相同（`sha256(ep)=7966e34c…`），而 b5 各不相同，所以 **b5 不覆盖 `ep`**，与"b5 依赖 args/body"一致。

### 十、累计否掉的构造（截至本轮）

| 族 | 组数 |
|---|---|
| body 形状 / 入参组合（第 13–19 轮） | 43 |
| 排序/重序列化参数（本轮） | 950 |
| 硬编码盐 × {prefix,suffix,hmac}（本轮，163 万窗口） | 1.63M |
| 两段 `md5‖md5` 拼接（本轮，修正了循环测试） | 32 |
| 载荷参数族（本轮） | 30 |
| RC4/标准密码（第 6 轮） | 172 |
| HMAC/加盐（第 4/13 轮） | 53 |

**结论：继续猜 message 已经没有生产率。** 下一步必须是**能观测 message 的手段**，而不是再猜。

### 十一、把"哪一家的 SHA-256"查清了（以及我自己的三次翻车）

先纠正一条**硬结论**：`libjdg` 里那套 SHA-256（IV 在 `+0x156284`、K 在 `+0x1562a4`、被 `+0x8c3f0` 引用）**在 jdgs 路径上根本不执行** —— 直接钩 `+0x8c3f0`（读 K 表的那条指令）签名期间 **0 命中**。所以 b5 的 SHA-256 不在 libjdg 自己的那份实现里。

同时确认：

- **`main` 的 ABI**：`main(JNIEnv* x0, jobject x1(常量 0x7c582198), jint opcode x2, jobjectArray x3)`；
- **运行期确实走 opcode 101（`x2=0x65`）**：签名时抓到（tid 21166/21231），而 102（`x2=0x66`）是环境查询轮询；
- **`libcrypto.so` 的 `SHA256` 在签名期间真的被调用**（3 线程 × 2 次），输出是 32 字节真摘要，但**没有一个等于 b5**；
- **`libjdJmaEncryptUtil.so` 带完整 SHA-256 常量表**（IV `+0x7fa0`、K `+0x10e10`），是仅剩的候选；它的代码位置还没定（ADRP 严格匹配找不到，和 libjdg 一样是 `ldr q` 缩放问题）。

**三次自己造成的翻车（这是本轮真正拖慢我的原因，必须记下来）**：

| 事故 | 后果 | 教训 |
|---|---|---|
| `base+0x8c1f8` 手算成 `0x731e41f1f8`（漏 `0x80000`，正确是 `0x731e49f1f8`） | 装在了一段"看起来合法"的代码上，**0 命中**，我据此差点写下"签名不走这条路" | 地址一律由脚本从活体 maps 算（`hook_off.mjs`），不再手算 |
| 比对脚本按 `seq` 找 `NATIVE_HOOK_MEM`，**没带 `hookId`** | `seq` 是按钩子各自编号的 → 把 md5 的记录当成 SHA256 的，得出"两者输出相同"的假象 | 所有记录联结都必须 `(hookId, seq)` 双键 |
| 在前台是 **ADH Manager** 的情况下对着屏幕滑动 | 京东在后台、没有签名流量，于是"md5 0 命中"被误读成"签名不发生" | 触发前先 `dumpsys activity` 确认前台是谁 |

### 十二、再排除三族，并修正一个对 `0x98c1c` 的误解

- **向量元素拼接**（222 组）：`args` / 去掉 `POST <path>` 的剩余 / `eid` / 占位串 `-§§-…` / `"1.0"` 的**有序两两拼接**与 `&` 连接，配 `sha256`/`md5` —— 零命中。**b5 不是"对 101 向量多个元素拼接"求摘要。**
- **libjdg 自带的 SHA-256 彻底出局**：签名期间 `+0x8c3f0`（读 K 表那条指令）**0 命中**。
- **`libcrypto` 的 `SHA256` 出局**：签名期间确实被调用（3 线程 ×2 次），32 字节真摘要，**没有一个等于 b5**。
- **`0x98c1c` 的理解要修正**：钩它拿到 `inLen=32`、入参是 **32 字节二进制**，而 `memAfter:"x0:68"` 读到的**不是 64 个 hex 字符**（是二进制、且部分与入参相同）。所以要么它不是"把 32 字节 hex 成 64 字符"的函数，要么 `x0` 在返回时不是那块缓冲。**弄清它的真实语义之前，不能再拿它当 b5 的候选。**

### 十三、又一个工具缺陷：**命令通道会被 install/unhook 反复折腾堵死**

现象：连续几次 `native_hook`（装/撤同一地址、带 `memAfter`）之后，**`agent_ping` 也开始超时**，整个会话失去响应；只有重启目标进程才恢复。

- 不是设备问题（`adb` 正常、daemon `/health` 200）；
- 不是单个 spec 的问题（同样的 `memAfter` 规格在**新进程**上一次就装好）；
- 看起来是**命令线程被某次 install 卡住**，后续命令排在同一条通道上。

必须修：**任何单条命令都不能让会话失去响应**。至少要给 install/unhook 加超时与"放弃后回到空闲"的路径。

### 十四、**b5 的原材料拿到了：`b5 = hex(X)`，X 是 32 字节**

这是本轮唯一的实质突破，而且是可复核的：

1. 先钩"每字节调一次"的 hex 辅助函数 `+0x9a6a4` + `backtrace`，按调用者做直方图 → 两个族：`md5_hex` 的 32 个展开点，以及 **`+0x98c94`（通用编码器 `+0x98c1c`）123 次**；
2. 按 `(hookId, seq)` 双键正确联结后重测（此前那次是把 md5 的记录读成了编码器的）：

```
4 of 8 encoder inputs, hexed, equal a captured b5
```

**即 `b5 = hex(X)`，X 就是交给编码器的那 32 字节。** 这个结论不再依赖任何猜测。

3. 顺着编码器的回溯往上找，发现它是在 **`+0xf643c`** 里被调用的：

```asm
0x9796c  adrp x0, 0x14d000
0x97970  add  x0, x0, #0x420      ; 目标缓冲 = libjdg+0x14d420（全局）
0x97974  mov  w1, #0x41           ; 容量 65  ← 正是 32*2+1
0x97978  mov  x2, x19             ; 上下文
0x9797c  bl   0xf643c
```

**顺带纠正前几轮的一个错判**：`+0xf643c` 曾被写成"4 阶段游标机、不是摘要缓冲"，实际上它是 **`f(dst, cap, ctx)` 的收尾函数**，负责把 32 字节格式化成 64 个 hex 字符（`cap=65` 就是证据）。同时它对 `libjdg+0x156xxx`（SHA-256 常量页）**没有任何引用** → **它只格式化、不哈希**，X 是调用者算好传进来的。

### 十五、下一步（唯一必要的一步）

X 是 32 字节、`b5 = hex(X)`，所以"b5 的公式"这个问题现在等价于 **X 是怎么算出来的**。已知的约束：

- X 不等于任何标准哈希的可见构造（约 4000 组 + 163 万盐窗口全否）——**这些否定现在依然有效**，因为它们本来就是在比 b5；
- `+0xf643c` 自己不哈希，X 来自它的调用者（`+0x9796c` 所在函数，链上还有 `+0x9723c`/`+0xd97f4`）；
- libjdg 自带的 SHA-256（读 `0x1562a4` 那条 `0x8c3f0`）签名期间 **0 命中**；libcrypto 的 `SHA256()` 输出 **不等于 X**。

所以下一步是：**钩 `+0x9796c` 所在函数的入口，用 `mem` 把上下文里的 32 字节字段定位出来**，然后看这个字段是被谁写的 —— 也就是接着往上走一级。必要时用 `trace_digest` 跑 `+0xf643c` 一次（现在有止损，不会杀进程）确认它到底读上下文的哪些偏移。

### 十六、产品打磨（本轮先把工具补好）

**① 原生钩子记录带上身份：`hookId` / `seq` / `phase`**

`NATIVE_HOOK` / `NATIVE_HOOK_MEM` 的身份以前只存在于**载荷 JSON 内部**，而 `seq` 是**按钩子各自编号**的 —— 于是"把寄存器和它的内存副本配对"只能由调用方自己拼，拼错也不报错。这一轮我就是这么错了两次（把 md5 的记录读成 SHA256 的）。现在：

- 入库时把 `hookId` / `seq` / `phase` 抬成独立字段（`state.ts::nativeHookIdentity`）；
- `live_captures` 新增 **`hookId`** 过滤，描述里写明"配对必须 `(hookId, seq)` 双键"；
- 响应投影也带上这三个字段（第一次实现时**投影把它们丢了**：过滤生效但读不到，属于同一种"看起来对"的错）。

**实现时踩到的第二个坑**：提取窗口只取前 256 字节，而 `NATIVE_HOOK` 事件约 900 字节、`seq` 在末尾 —— 结果 `hookId` 拿到了、`seq` 丢了。现在窗口 4096 字符，并加了一条**故意超过 600 字节**的单测把它钉住（原来的短 fixture 根本测不出来）。

真机（沙盒）验证：

```
live_captures {hookId:1}     -> total 2
  NATIVE_HOOK      hookId=1 seq=1
  NATIVE_HOOK_MEM  hookId=1 seq=1
live_captures {hookId:999}   -> total 0
```

**② `native_hook` 回显"这个地址落在哪个模块+偏移"**

我两次把 `base+0x8c1f8` 算错，而工具**照装不误**、随后 0 命中 —— 读起来和"这段代码不在路径上"一模一样，为此浪费了两轮。现在安装成功后会回显：

```
正确:  install ok=true   resolved: libjdg.so 0x8c1f8
错误:  install ok=true   resolved: libjdg.so 0xb1f8     ← 现在一眼可见
```

实现：`classifyAddress` 增加 `moduleOffset`（**从同一文件的最低映射算起**，不是从所在段算——否则会报成段内偏移），`assertCallableAddress` 一并返回模块名/偏移。

**③ 纠正一条我自己的误判**

上一节把"daemon 崩了两次"记成了产品缺陷。复查后：daemon 一直活着（`/health` 200），那两次 `exit code 1` 是我用 `Select-Object -First 200` **截断了它的 stdout 管道**。**这条不算产品的账**，已从缺陷清单移除；真正值得记的只有"死进程会被当成在线并被自动装 capture_start"这一点（待办，未修）。

**验证汇总**：`tsc` 干净、`npm test` **324 pass / 0 fail**（较上轮 +2）、`verify_v107` 真机 PASS。

**顺带发现（未修）**：`verify_v107` 在"刚重启沙盒、agent 还没连上"时会 `FAIL: command timeout`，紧接着重跑变 `SKIP`。它应该**先等 agent 上线再装钩子**（现在只是重启后固定 sleep）。这是验收脚本自身的时序缺陷，不是产品缺陷。

### 十七、修好"命令通道被堵死"的**真根因**：hard unhook 的静默循环没有上界

代码读出来的，不是猜的：

```c
for (int round = 0; round < 80 && !quiet; round++) {
    ...
    if (after == before && round >= 4) quiet = true;
    else if (after != before) round = 0;      // ← 热钩子上命中一直在涨，round 永远被清零
}
```

**热钩子（hex 编码器、malloc、main）上这个循环永不退出**；而它跑在 agent 的**命令线程**上，于是后续每条命令都排在后面 → `agent_ping` 也超时、只能重启目标。这一轮我撞了两次，都记成了"工具莫名失联"。

修法：**加总时限**（1.5 s）+ 连续静默计数，超时后**照常恢复原始字节**并 `LOGE` 说明"没等到静默窗口"。安全性不变：恢复的是本函数自己的 prologue，而 trampoline 在**另一块永不释放的池**里，已经进去的线程不会被抽走地板（这条残余竞态本来就是 hard unhook 的既有说明）。

真机验证（沙盒，`daemon/tmp_hook_lifecycle.mjs`）：

```
hot hook (malloc) → hard unhook ok=true，耗时 53 ms，之后 agent_ping 仍应答 ✅
```

**同时纠正我上一轮的一个错误结论**：我说过"在软撤过的地址上重装会造出死钩子（id=11、0 命中）"。用对照实验重测：

```
first install id=2 → trigger → hits=1
soft unhook ok=true
reinstall   id=3 → trigger → hits=1，且新的 mem spec 生效（x0:8,x0+7:1）
```

**重装是好的** —— 那个"0 命中"只是当时**没有签名流量**（App 停在登录页），我又一次把"没触发"读成了"没工作"。reactivate 路径本来就是"给操作者一个新 id"，而不是复用旧 id，这点也确认了。

### 十八、`status` 现在列得出软撤的钩子，也撤得掉

上一节说 `status.hooks[]` 只列 active、软撤的既看不见也释放不了。这一轮把它补完整 —— 而且发现是**两处**问题，缺一个都不算修好：

1. **列表**：`adh_native_hook_status_json` 里 `if (ctx.active != 1) { ...; continue; }` 直接跳过它们。现在单独输出 `inactive[]`（`hooks[]` 仍只表示"活的"，语义不变）：

```json
{"slots":{"used":1,"active":0,...},"count":0,"inactiveCount":1,
 "hooks":[],"inactive":[{"id":1,"mode":"inline","patched":true,"mem":"x0:8","state":"soft-unhooked"}]}
```

2. **释放**：`find_hook_locked` 只认 `active == 1`，所以**即使列出来了，按 id 撤也答"no native hook with id N"**。改成按 `used` 查（软撤的上下文仍带 `patched/target/replacement`，hard unhook 的路径本来就是齐的）。

真机验收（沙盒）：

```
install id=1 -> soft unhook -> status: used=1 activeHooks=0 inactiveCount=1 inactive id=1 state=soft-unhooked
-> 按 id hard unhook ok=true -> used=0 inactiveCount=0
```

**顺带纠正第三个误判**：我曾说"死进程仍被当成在线、被自动装 capture_start"。查了 `index.ts` 的 socket close 处理（会正确置 `online=false` 并停掉 drain）和实际 pid 列表后确认：那些 pid 是**京东自己的其它进程**（`jdpush` / `widgetProcess` / `manto0`…，这个包一共 7 个进程），**在线判定是对的**。真实现象只是"启动策略给**每个**进程都装了 `capture_start`"，代价是 5 条 drain 循环的噪音 —— 这是设计取舍，不是僵尸会话，**没有改**（要改得先定策略：只装主进程？还是设上限？这需要产品决定）。

### 十九、定位 VMP：四张关键表全在同一个 blob 里

新工具 `native_xref`（第 80 个 MCP 工具）用**精确匹配**跑 libjdg，结果非常干净：

| 表 | 精确引用 |
|---|---|
| SHA-256 K `0x1562a4` | `add@+0x8c3f0` |
| SHA-256 IV `0x156284` | `add@+0x8c59c` |
| VMP 状态 `0x156270` | `add@+0x8c210` |
| 分派跳表 `0x156240` | `add@+0x8c21c` |

**四条全在 `0x8c1f8` 那一个函数体内** —— 也就是说 SHA-256 的初始化与轮常量都在这个"合并 + 扁平化"的 blob 里，走**内部派发**而不是 `bl` 入口。这就解释了为什么把它当普通函数来钩（假设 `(data,len,out)`）永远只得到 md5 的结果：**b5 的摘要在 blob 内部由 VM 算出来**，只能靠 trace 观测。

**工具的假阳性顺手修了**：`window` 默认从 512 改成 0。旧默认把我报的 `ldr@+0x8c858` 当成"读 K 表"，实际那个函数（`0x8c840`）是**析构器**（`[x19]` 取下个、`[x20+0x10]` 递归、`[x21+0x4a0]` 是 `free` 的 GOT 槽），只是因为 `0x1564a0` 落在 `0x1562a4` 的 512 字节窗口里。

### 二十、抓到了 jdgs 组装上下文：**字段顺序 b1,b2,b3,b4,b5,b7,b6**

钩 `+0xf643c`（`f(dst, cap=65, ctx)` 的格式化函数）并抓 `x2` 指向的上下文，前 256 字节里有：

```
"b1\0b2\0b3\0b4\0b5\0b7\0b6\0"   "%lld\0"   "%s_%s\0"   "0.3."
```

- **`b6` 排在最后**、而 b5 在它之前 —— 与"`b6 = md5_hex(JSON 去掉 b6)`、b6 最后追加"的结论**独立吻合**；
- 这是 jdgs 的组装现场（字段名表 + 格式化串）；X（b5 的 32 字节原像）不在这 256 字节里，说明它在更靠前的阶段就已算完。

### 二十一、trace 第一次打到真实目标：格式化器**不是** X 的产出者

用真实参数（从命中现场抓的 `dst/cap/ctx`）trace `+0xf643c`：

```
stopReason=completed  retvalValid=true  instructions=31  loops=[]  calls=[]  elapsed=211ms  目标存活
```

- **只有 31 条指令、零循环零调用** —— SHA-256 要上千条、连"32 次 hex 循环"都不止 31 条。**所以 `0xf643c` 不计算 X**，它只做渲染/传递，X 是它的**调用者**算好的。
- 这 31 条是**旧 ctx 的提前退出分支**（重放的 ctx 来自几秒前的一次真实调用，已失效）。所以"重放 trace"只能看骨架，要看到真实路径必须用**活着的 ctx**。
- 顺带证明 trace 现在是安全的：`completed`、`retvalValid:true`、**目标存活**，`stopReason` 也如实报告。

**`0x9796c` 所在的函数就是 JSON 组装器**：它前后是一串 `bl 0x102260`（追加字段），在 `0x9797c` 处调用 `f(dst, 65, ctx)` 把上下文渲染进全局缓冲。也就是说 **b5 的渲染点在组装器里，而 X 在更上游就被算好了** —— 与"X 在 256 字节上下文里找不到"一致。

### 二十二、下一步（下一步只剩这条，而且必须是活上下文）

1. 钩**组装器入口**（`0x9796c` 所在函数，用 `native_xref`/反汇编定边界），`mem:"auto"` + `bt`，把**传给格式化器的那个 ctx 指针**连同它的内存一起抓下来；
2. 在同一次命中里同时钩 `md5` 本体拿到该请求的 b5 → 算出 X → **在 ctx 里定位 X 的偏移**；
3. 找到偏移后，读**写这个偏移的代码**（`native_xref` 对 ctx 结构无能为力，但可以从 `0x8c1f8` blob 里那四条派发点入手），或者对"填 ctx 的那个函数"再 trace 一次。

### 二十三、X 的产地在 `0xf643c` 的调用树里（**本轮最硬的结论**）

钩**通用 hex 编码器** `+0x98c1c`（`mem:"x0:32"` + `backtrace`），只保留"输入 hex 正好等于某个 b5"的调用。4 次命中，回溯**完全一致**：

```
libjdg+0x104050 (thunk)  <- 0x10328c <- 0x102d44 <- 0x1020cc <- 0xf65fc <- 0x97980 <- 0x9723c
```

- `0x97980` 是组装器里 **`bl 0xf643c` 的返回地址** → **编码器是在 `0xf643c` 内部被调用的**；
- 所以 **X 是在 `0xf643c` 的调用树里算出来并立刻 hex 掉的**。这同时解释了之前三个反常：
  - 按 `(data,len,out)` 钩 `0xf643c` 拿不到 32 字节输出；
  - 那次 trace 只有 31 条指令、零调用 —— **旧 ctx 走了空路径**，不是真实路径；
  - `memory_search` 找不到 X —— 它是瞬时缓冲，调用结束即失效。

### 二十四、还排除了两个假设

- **X 不在格式化器的上下文里**：512 与 1024 两种窗口、37 + 9 份捕获、11 个 X 候选，**零命中**。所以 `cap=65` 那次不是"把 ctx 里的 X 渲染成 hex"。
- **`cap` 是 16 / 50 / 65 / 193** 四种 —— 同一个格式化器服务多个字段，65 只是其中之一。

### 二十五、下一步：给 trace 一块**活上下文**

trace 是"我调一次"，但 `0xf643c` 的真实路径只在**自然执行**时出现；而 tracer 又**拒绝带补丁的地址**，所以"抓 ctx → 硬撤 → trace"这条路上 ctx 早已失效（就是那 31 条）。

可行的做法（下一轮直接做）：

1. 钩 `0xf643c` 用 `mem: "x2:1024"` 把**整块 ctx 内容**抓下来；
2. 用 `native_call malloc` 拿一块新内存、`memory_write` 把 ctx 字节**种进去**，得到**稳定的副本**；
3. `trace_digest { addr: +0xf643c, args: [dst, "65", 副本地址] }` —— 此时指针有效，走的是真实路径（VMP 分派 + 那次编码器调用），就能看到它到底算了什么。

## 2026-10-22（第三十四轮）—— 工具打磨收尾 + **b6 破译：它是 jdgs 明文 JSON 的 MD5**

### 一、工具打磨（P2 全部清掉）

1. **`mem` 上限 192×4 / 512 → 1024×4 / 4096**（本轮真正的阻塞点）
   - 现象：签名前像（preimage）是 **1530–1636 字节**，旧上限单窗口 192、总计 512，于是**唯一值得看的那块缓冲恰恰是工具读不到的**——上一轮反复"候选全否"，有一半原因是只看到前 192 字节。
   - 改法：`ADH_MEM_WIN_LEN 1024`、`ADH_MEM_WIN_TOTAL 4096`；`NATIVE_HOOK_MEM` 记录的缓冲改成按上限推导 `ADH_MEM_WIN_TOTAL*2+512`（以后再改上限不会静默截断）；daemon `native_hook_args.ts` 同步；单测改成**从常量推导**期望值（旧测试把 192/512 写死，改上限必然红，这次正是这么发现的）。
2. **事件里的 `fp` 默认省略**：8 个 vector 寄存器约 600 B/条，128 条就是 75 KB 纯噪声。现在 **q0–q7 全零就不发 `fp`**，整对象要么全有要么全无 → 纯整数调用不再付这笔钱，真用 FP 的调用仍报八个（`0.0` 参数仍能与"未使用"区分）。
3. **`mem` / `memAfter` 共用一套窗口语法**：抽出 `parse_window()` + `format_window()`，两处各自手写的解析（错误文案、offset 上限、canon 拼法**都已经漂移过**）合一；`memAfter` 只保留真实差异（单窗口 + 更大的长度上限）。
4. **`hw_watch action:"hit"` 不再阻塞**：它和 `status` 一样是只读查询却走阻塞锁，正在 arm 时取不到命中链——而命中链**只有它一个出口**。改成 trylock，busy 时明确回 `busy`。
5. **`docs/mcp-tools.md` 重新生成**：65 → **79** 个工具（漂移 14 个），`filter` / `since` 首次进文档；并补写 `live_captures.since`（采集游标，不是时间戳）、`capture_start.epoch`、`hw_watch.hit`、`native_hook` 的 `filter` / `writeHex` / `errno` / `fp` 语义——这些参数此前**只在 schema 里，描述里一个字没有**。

验证：`tsc` 干净、`npm test` **298 pass / 0 fail**（比上一轮 +118 条，含新增断言）、agent 重新构建并部署（`sandbox`/`module` 两侧哈希一致）、JD 冷启后 hook 实测 60 / 132 次命中。

### 二、b6 破译：**`b6 = md5_hex(明文 JSON 去掉 b6)`**

上一轮把"body → jdgs JSON 的追加顺序"摸清了但没拿到收尾那一步。本轮换了思路：**不去猜输入，直接钩哈希本体**。

- 静态定位：SHA-256 的 IV/K 表在 `libjdg+0x156284 / +0x1562a4`（常量扫描命中）；唯一引用 K 表的代码在 `+0x8c3f0`，属于 `+0x8c1f8` 开头的那个函数；它只有一个调用者 `+0x98998`，而 `+0x98998` 只分配 **33 字节**（32 hex + NUL）→ 说明这条链做的是 **16 字节摘要的 hex**，不是 SHA-256。
- 运行时：在 `libjdg+0x8c1f8` 上装 inline hook，`mem:"x0:1024,x0+1024:1024"` + `memAfter:"x2:32"`，一次拿到「完整输入 + 目标自己算出的输出」。
- 结果：**52/52 次命中全部是 MD5**（`md5(前 x1 字节)` 逐字节等于目标写出的 16 字节），一次请求两次调用：

| preimage | 长度 | 内容 | 我们的 MD5 | 目标输出 | |
|---|---|---|---|---|---|
| A | 1530 / 1536 / 1629 | `POST /client.action <query/body>` | `f481e601…` / `a4195d07…` / `a6ccc9ca…` | 完全一致 | ✅ |
| B | 568 / 564 | `{"b1":…,"b2":…,"b3":…,"b4":…,"b5":"<64 hex>","b7":…}` | `5a1587c1…` / `31fd151e…` / `a84fdb44…` | 完全一致 | ✅ |

所以：

- **`b6` = `md5_hex(jdgs 明文 JSON)`，而这个 JSON 里还没有 b6**（键序固定 `b1,b2,b3,b4,b5,b7`）；
- 一次请求**另有**一次 `md5_hex("POST <path> <args>")`（32 hex），用途未定位；
- `b5` 在被哈希之前**已经填好**，长度 **64 hex = 32 字节**。

### 三、b5 仍未定，但排除了一大片

`b5` 的产出点不在 `+0x8c1f8` 这条链上（52/52 全是 md5），而全模块**只有一个 hex 格式化器**（33 字节分配，即 32 hex），**没有 65 字节分配**——也就是说 libjdg 内部没有"把 32 字节 hex 成 64 字符"的代码。因此 b5 要么是**两个 32-hex 串拼接**，要么由**别的模块/Java 层**产生。已逐条否掉：

- `sha256("POST <path> <args>")`、`sha256(args 去掉方法与路径)`、`sha256(path+args)`；
- `md5(args)‖md5(json)`、`md5(json)‖md5(args)`、`md5(args)‖md5(args)` 等 9 种两段组合；
- `sha256/patch(b4)`、`sha256(b1+b4+b7)`、`sha256(b4+b7)`；
- `sha256(JSON 去掉 b5)` / `md5(JSON 去掉 b5)`（两级签名假设）；
- b5 的任何 ≥8 字符子串**都不出现**在 args 字符串里（不是"从入参里搬过来的"）；
- **设备常量当 key 也不行**：`HMAC-SHA256(appKey/eid/androidId, args)`、`sha256(key+args)`、`sha256(args+key)`（三种 key）全否；
- **"签名按解码后的 body 算"这条也否**：`sha256/sha1/md5` × {整条 args、args 去掉方法路径、两者 URL 解码后} 共 12 组全否。

已知的强约束：同输入连调 3 次 `b5` **完全一致**，而同批的 `b4`、`b7`、uuid 每次都变——所以 b5 **不依赖 b4/b7/uuid**，只依赖可见入参 + 某个稳定量（key 或设备常量）。设备常量已经当 key 试完，剩下就是那 20 字节会话 key。

下一步指向 **HMAC-SHA256**：模块里确实带着 SHA-256 常量表（只是这条链不走），而 b5 恰好是 32 字节。要验它必须先有 20 字节会话 key —— 也就是要重启 App、在新线程首次签名时抓 KSA（上一轮记录过的手法）。

### 四、trace 实测 + 两个真缺陷（**修完并验证**）

上一轮完全没用 trace（只有 hook + 静态 ELF 分析）。这一轮补做，先撞上两个缺陷，都修了：

| 调用 | 结果 |
|---|---|
| `trace_digest {symLib:"libc.so", symbol:"malloc"}` @ 沙盒 | ✅ `143` 条指令、`retval` 正常 |
| `trace_digest {addr: libjdg+0x8c1f8}` @ 京东 | ❌ `command timeout` → **SIGBUS(pc=0x2a, BUS_ADRALN)**，进程被杀（`tombstone_10`, 15:59:48） |

**根因（不是"加固模块跑飞"，是我们自己留的补丁）**：那个地址上刚装过 `native_hook` 并被 **soft unhook** —— 而 soft unhook 的语义是"**补丁留在原地但停用**"（为了免 Dobby 重新激活）。于是函数入口仍是 `b <trampoline>`，QBDI 老老实实跟着这条跳转进了 trampoline，**再也回不到模拟器**，最后落到 `pc=0x2a`（`pc`/`lr` 都是它）。修完后在**没有补丁的同一个地址**上重测：`1327` 条指令、`stopReason:"completed"`、`retvalValid:true`、1.2 s —— **libjdg 的 trace 本身是好的**。

**修复 1（真正的止损）**：`qbdi_trace` 现在**拒绝**带我们自己补丁的地址，并在错误里点名 hook id 与状态（`active` / `soft-unhooked`）。判断依据是 `used && patched && target`，**不能**用 `active`——要抓的恰恰是 `active==0` 的 soft 状态。

**修复 2（纵深防御）**：每个被插桩的指令地址都要命中"可执行映射快照"（一次读 `/proc/self/maps`，二分查找），不在其中就 `QBDI_STOP` 并报 `stopReason:"ran-away"` + `stopPc`；另有 `200000` 条指令的执行预算（此前只有**采集**上限，执行没有上限，所以能跑到宿主超时）。宿主侧把这几个字段摆到结果顶层：`stopReason` / `stopPc` / `retvalValid`，非 `completed` 时 `truncated:true` 并写明"摘要只覆盖前缀"，**不再把 x0 冒充返回值**。

**验收**：新增 `tools/verify_v110_trace_guard.sh`（device，已并入 `verify_all.sh`），真机 PASS：

```
clean (无补丁)        → stopReason=completed, 4 指令
soft-unhooked (id=1)  → 502 拒绝，错误里含 "id 1"
active       (id=2)   → 502 拒绝，错误里含 "id 2" + "active"
hard unhook 之后再 trace → completed（地址能被重新追踪）
沙盒进程              → 存活
```

### 五、方法教训（都写进 CASE_STUDIES）

- **扫描器"什么都没找到"和"真的没有"长得一模一样**：我的 ADRP 扫描一开始报 0 个引用，原因是 JS 里 `w & 0x9f000000` 是**有符号**的负值，跟 `0x90000000` 永远不相等。修正后同一文件立刻有 12342 条 ADRP。差一点据此得出"这些常量表没有代码引用"的错误结论。
- **`Number.parseInt('0x41', 16)` 与我以为的不一样**：写死 radix 16 时前缀被吞，"找 65 字节分配"实际在找 101，于是又得到一次"0 处命中"。改成 `Number()`。
- **"trace 把目标打死了"第一版归因是错的**：我当场写成"QBDI 的返回模型被目标的扁平化控制流带偏"，还据此说要"拒绝这类模块"。修完一测才发现**根因是我们自己 soft unhook 留下的补丁**——同一个符号不加钩子就能干净 trace 1327 条指令。**教训：崩溃归因必须先做一个"对照组"实验**（同地址、无补丁），否则会把我们自己的状态写成目标的特性。
- 结论：**分析脚本也必须 fail-loud**——凡"0 命中"必须同时打印"我到底扫了多少条指令/多少个字节"，否则 0 只是一个沉默的谎。

## 2026-10-22（第三十三轮）—— 修好"软撤后重装"：reactivate 分支漏更新 after/filter

### 根因

`adh_native_hook_install` 里有一条 **reuse/reactivate** 路径（软撤之后重新 hook 同一地址时复用已安装的 stub，不再碰 Dobby）。它更新了 `mem_*`、`write_*`、`errno`、`throttle`，**唯独没有更新 `after_*` 和 `filter_*`**：

```cpp
copy_cstr(old.mem_spec, ..., mem_canon);   // ← 到这里就结束了
// after_arg/after_len/after_spec、filter_reg/filter_val/filter_spec 都还是上一轮的旧值
```

后果：软撤后用新的 `filter`/`memAfter` 重装，**照旧按旧配置观测**，而且不报错——正是"改了没效果"那类最难查的问题。

### 修复

1. reactivate 分支补齐：`after_arg/after_off/after_len/after_spec` 与 `filter_reg/filter_val/filter_spec` 全部按本次参数重写；
2. reuse 匹配增加**stub 形态一致性**判断（`(after_len > 0) != (old.after_len > 0)` 就不复用）：post-call stub 与普通 stub 是两个不同的桩，不能在没有 Dobby 的情况下互换；
3. 这样"软撤 → 换 filter → 重装"就**不需要重启目标**（此前每次都要重启 App，已经为它重启过三次）。

### 真机验证（同一进程，无重启）

```
install A:  id=1  filter=x2=0x7317e8dbb0   ok=True
soft unhook: ok=True
reinstall B: id=2  filter=x2=0x7317edd4b8  ok=True      ← 换了过滤值
status:      id=2  filter=x2=0x7317edd4b8  hits=166  verdict=fired
capture(since=epoch): 99 条 native 事件
```

- **抑制**（上一轮）：不匹配时 0 事件；
- **命中**（本轮）：匹配时 `hits=166`、事件正常落库。

两个方向都验证过，目标过滤才算真正可用。

## 2026-10-22（第三十二轮）—— 工具打磨：采集游标 + `status` 可观测 + 目标过滤**验证生效**

按复盘清单开工，三条 P0 里两条已落地并真机验证。

### P0-1 采集游标（`epoch` / `since`）

- `capture_start` 现在返回 `epoch`（当前捕获流的最大 `Capture.id`）；
- `live_captures` 新增 `since`：只回 `id > since` 的记录。
- 真机：`capture_start` → `epoch=45230`；随后用 `since:45230` 只拿到本次采集的 13 条记录。

**这条解决了本轮反复踩的坑**：以前"这轮有没有新记录"无法判断，读到的是跨会话累积的旧数据（实测混入过 107 条）。

### P0-3 `status` 暴露生效配置

`native_hook status` 的每条记录现在带 `afterActive` 与 `filter`：

```
filter=x2=0x73186ee574  afterActive=False  hits=0
```

以前只能靠"有没有记录"反推配置有没有生效，现在直接可读。

### P0（目标过滤）：**抑制已验证**

同一个 thunk hook、同一次签名：

| | 未过滤（此前） | 加 `filter` 后 |
|---|---|---|
| native 事件数 | 128+（环被打满） | **0** |

说明：不匹配的命中被丢弃（不计数、不发事件、原函数照常执行），目标过滤按设计工作。

### 顺带纠正一个假设

~~过滤用的 `x2` 取的是 RC4 入口（`base+0x89574`），结果 0 命中——而观察到的 `x2` 实际值是 `0x7321f88808` 一类。说明**宿主调用 thunk 的 `x2` 不是被调函数指针**（此前第三轮据此推断"x2=目标"是错的）。~~

**上面这段是错的，已撤回。** 用**当前会话**的基址重算后，`x2` 全部落在 libjdg 内，就是被调函数指针（第三轮的推断是对的）：

```
14 x 0x731e6f3bb0 → libjdg+0x94bb0     13 x …54b8 → +0x964b8
10 x …3724 → +0x94724                  8 x …a268 → +0x12b268
 8 x …caf0 → +0x8daf0                   6 x …98a8 → +0x12a8a8
```

教训：**换算偏移必须用当次会话的基址**（进程重启后基址会变），否则会得出完全相反的结论——上一次就是这么错的。

而 RC4 入口（`+0x89574`）不在前 128 条里，说明环只留下了这次签名的**前段**调用（或 PRGA 走的是另一条入口）。下一轮用 `filter` 逐个命中上面这些目标（先 `+0x94bb0`，14 次），看哪个是"body → 摘要"那条链。

### P0-2 native 事件带上 `tid`

事件 JSON 头部加了 `"tid":%d`（`gettid()`），daemon 侧的 `Capture.tid` 从此有值。真机：

```
capture_start → epoch=45670
live_captures {since: 45670} → id=45671..45674 func=NATIVE_HOOK tid=15741（全部同线程，符合预期）
```

这解决了"两个 hook 在不同线程命中、只能按顺序配对"的老问题（早前 `RC4(state,D)≠C` 就是配错对造成的）。

### 验证方式

agent 链接通过、`tsc` 干净；真机状态与计数见上表。

### 剩余（下一步）

1. **P1-7 daemon 热重载**：改用 `node --watch src/index.ts`，避免"改了 `mcp.ts` 不生效"再白跑一轮；
2. **确定 jdgs 的过滤值**：先跑一次未过滤的 thunk hook，统计 `x2` 分布（现在有 `since`，一次采集就能干净统计），再用真实值过滤；
3. 回到 `b5`/`b6`：按 `tid` + `since` 抓 `0x102260` 的 body→jdgs 追加序列。

## 2026-10-22（第三十一轮）—— 追加序列是「body → jdgs JSON」，且存在两条 body 路径

对 `0x102260` 的记录做**内容过滤**（只留 `POST` / `{"` 这类可读前缀），一次签名 266 条里有 14 条是真正的追加：

```
POST /client.action 1c820f9e3171c89cc741…     ← 本次请求的 body
POST /client.action 1c820f9e3171c89cc741…
{"b1":"68dd5803-07c3-44d7-8881-0b213bf81b51","b2":"3.6.5_0",…   ← jdgs 输出 JSON
POST /client.action 44136fa355b3678a1146…     ← 另一条路径的 body
…
```

两个关键事实：

1. **顺序固定**：先 body、后 jdgs JSON，且在多次签名里稳定重复（不是随机顺序）。
2. **存在两条 body 路径**：`1c820f9e…` 与 `44136fa3…` 同时出现 —— 说明 `0x102260` 被多处复用，分析时必须**按本次 body 前缀筛选**，否则会把两种逻辑混在一起（这也是上一轮"前 40 条全是游标快照"的成因：记录里混着对象快照与不同路径的追加）。

**对公式的收窄**：
- `b6` 很可能就是"body + jdgs 文本"这个对象的滚动摘要；
- `b5` 只吃 body —— 对应序列里"只有 body、没有 jdgs"的那几次调用。

**下一步**：按 `1c820f9e…` 前缀筛出属于本次签名的调用 → 用已修好的 `memAfter` 抓该对象追加完成后的状态 → 若仍无 32 字节，就 hook 追加之后的收尾调用。

## 2026-10-22（第三十轮）—— **找到 b5/b6 的输入构造点：`0x102260` 把 body 和 jdgs JSON 追加进同一对象**

在 `libjdg+0x102260`（`0x975c0` 里逐个字段追加用的那个函数）上挂 `mem:"x1:96"`，一次签名抓到 **118 条**记录，其中两条是决定性的——`x1` 指向被追加的内容：

```
504f5354202f636c69656e742e616374   |  "POST /client.action 1c820f9e3171c89cc741f55dadee40b97ae0645f…"
7b226231223a2236386464353830332d   |  "{\"b1\":\"68dd5803-07c3-44d7-8881-0b213bf81b51\",\"b2\":\"3.6.5_0\",…"
```

也就是说这条链**把请求 body（1530 B）和 jdgs JSON 的内容追加进同一个对象**。这正好对应之前定性出来的覆盖面：

- `b5` = f(body)
- `b6` = f(body + 其余入参)

→ **`0x975c0` + `0x102260` 就是 `b5`/`b6` 的输入构造点**，不再是"猜"。之前排除 `0xf643c`（4 阶段游标机）也与此相容：游标机在这条链上是"推进/收尾"，真正的数据是经 `0x102260` 追加进去的。

**下一步（很具体）**：把 `0x102260` 的**完整追加序列**按顺序抓下来（每次的 `x1` 内容 + `x2` 长度），看：
1. 除了 body 与 jdgs 之外还追加了什么（时间戳/nonce/盐）；
2. 追加完之后是否有 `init/update/final` 形态的调用（那才是哈希本体），或摘要直接由游标机边追加边混合（那样 `b5`/`b6` 就是该对象内部的滚动状态）。

### 现场顺带确认

- 118 条记录里既有 `x2:64` 的对象快照（`36010000…` 那批），也有大量 `x1` 的追加内容（body、`{"b1":…`、`1.0`/`32` 这类字段值），说明 `0x102260` 被复用于多种追加。
- 这条 hook 是 inline 且**没有崩目标**，可以放心继续在这条链上做实验。

## 2026-10-22（第二十九轮）—— `0xf643c` 是 4 阶段游标机，不是摘要；并现场验证两条工具缺陷

用第 28 轮修好的 `memAfter` 做了干净的前后对比（`mem:"x2:64"` + `memAfter:"x2:64"`，一次签名命中 4 次，`pre=4 post=4` 逐对可比）：

```
#0 pre (310,568,4462)  → post (435,992,10522)
#1 pre (435,992,10522) → post (732,672,6622)
#2 pre (732,672,6622)  → post (732,672,6622)   ← 不变
#3 pre (732,672,6622)  → post (310,568,4462)   ← 回到起点
```

- `post[#i] == pre[#i+1]`，4 个阶段轮转 → 这是**同一个对象按阶段推进**，不是"每次独立计算"；
- 每次 `ret=0x0`，头三个整数（像 offset/length/count），其余是堆指针，**没有 32 字节摘要、没有 hex 字符**。

→ `f643c` 排除，`b5`/`b6` 不在它这里产生。

### 现场确认的两条工具缺陷（已进复盘清单）

1. **hard unhook 毒化地址**：`target was hard-unhooked earlier in this process: its backend state is stale, restart the target before hooking it again` —— 同一进程内无法重新 hook，只能重启 App。代价高，应支持"软 unhook 优先"或"原地重装"。
2. **采集存储跨会话累积**：安装失败那次仍读到 **107 条**旧记录，没有 `since`/游标就分不清本轮与上一轮。这是 P0-4。

## 2026-10-22（第二十八轮）—— **修好 `memAfter`：`slot_ids` 映射在首次安装时没写**

### 根因（终于定位）

`adh_native_hook_after`（`native_hooks.cpp` L679-680）靠 `g_native_hook_slot_ids[slot]` 把内部 slot
翻译成对外 id，取不到就 `return`：

```cpp
int hook_uid = g_native_hook_slot_ids[hook_id].load(...);
if (hook_uid <= 0) return retval;          // ← 静默，没有任何记录
```

而这个映射**只有两条路径会写**：reset（写 0）和 reactivate（写 id）。**首次安装成功的那条路径
从来没写过它**，所以 `hook_uid` 恒为 0 → after 路径直接返回。

这解释了全部现象：`install ok:true`、stub 选了 after 版、`afterSpec` 解析正确，但**一条 after 记录都没有**；
而 pre 记录不受影响，因为它的 id 是 stub 里 `mov x1, #N` 直接传的，不查这张表。

### 修复

在发布 `active = 1` **之前**无条件写入映射（`native_hooks.cpp`，`reset_throttle_counters(slot)` 之后）：

```cpp
g_native_hook_slot_ids[slot].store(id, std::memory_order_relaxed);
```

另外补了一条安装日志，让"配置是否真的到了 install"一眼可见：

```
native_hook install id=1 slot=0 mode=inline stub=after afterSpec="x00:64" arg=0 off=0 len=64
```

### 验证（真机）

| | 修复前 | 修复后 |
|---|---|---|
| `NATIVE_HOOK_MEM` 总数 | 4 | 8 |
| 其中 `phase:"after"` | **0** | **4** |

修复后的记录样例（`mem:"x2:8"` + `memAfter:"x0:64"`，挂在 `libjdg+0xf643c`）：

```json
{"hookId":1,"phase":"after","ret":"0x0","reg":"x0","offset":0,"requested":64,"got":64,
 "hex":"c0a5ae217300000008d8b72173000000…"}
```

### 顺带发现（待办）

1. `afterSpec` 规范化成了 `x00:64`（`off=0` 时格式串多打一个 0）——只是显示瑕疵，解析结果 `arg=0 off=0 len=64` 是对的。
2. `0xf643c` 的返回值是 **0**（`ret:"0x0"`），所以 `memAfter:"x0:64"` 读到的不是摘要。抓它的产物要看**返回后的 `x2` 对象**（`memAfter:"x2:64"`），或跟踪它内部写 hex 的指令。

## jdgs 分析总结（截至第二十三轮，交接用）

### 已完全确定并逐字节验证

```
b4 = base64( RC4_key( zlib.compress(fingerprint_json, 6) ) )
b1 = Bridge.getAppKey()     36 字符 UUID
b2 = "3.6.5_0"              b3 = "3.0"
b7 = 调用时刻毫秒时间戳
fingerprint_json = {"e1":<eid>, "e2":"1.0§§0§§<包名>|<32hex>|<版本>§§…", "e3":<ms>, "e5":<e5>, "e4":…}
key  = 传给 libjdg+0x89480（RC4 KSA）的 20 字节，每线程一份、缓存复用
```

- 验证方式：抓同一次调用的 key + `b4`，`RC4(key)` 解出 `78 9c …` → inflate → 指纹 JSON；再用 `jdgs_gen.py`（CPython zlib level 6）从明文重新生成 `b4`，**412/412 字符完全一致**。
- key 结构：`[2]=0x60`、`[3..7]=fa82edfe74`、`[10..15]=5f8e8b98ebe3`、`[18..19]=5e8a` 恒定；`[0..1]`/`[8..9]`/`[16..17]` 三个 16 位字段变动。

### 已定性、公式未得

- `b5` = f(请求 body)，`b6` = f(body + 其余全部入参)；两者**不是**可见字节的直接 SHA-256（24 种 body 形状 + 19 种入参 + HMAC/加盐/固定串全否）。
- 计算层：**不是** Java JCA（31 个 hook 零命中）、**不是**宿主调用 thunk（256 条调用里无 1530/32 长度参数、无一次性目标）→ **libjdg 内联**。
- 已知路径：jdgs 输出组装点 `libjdg+0x975c0`（读 `x3` 得到 `[{"b1":…`）→ 参数处理器 `libjdg+0xf643c`（`x3=29` 与 body 参数个数一致、`x4=379`、`x0=libjdg+0x14d420` 运行期指针表；一次签名命中 4 次，**hook 不崩目标**）。

### 工具经验（避免重走）

- 京东上**禁用 `hw_watch`**：perf 硬件断点会被反篡改检测，已三次 SIGSEGV。
- `live_captures` 必须在 `java_call_result` 后**等 ≥2 s** 再读，否则读到空环。
- PRGA（`0x89574`）**只装无 `mem` 的纯观测 hook 是安全的**；带 `mem`/`memAfter` 会崩。
- RC4 状态每线程缓存 → KSA 只在新线程首次签名时跑；抓 key 必须"重启 App → 立刻抓"。
- 目标压缩用 **zlib level 6**；Node 的 zlib（zlib-ng）产不出同样字节，用 CPython。

### 未完成

1. `b5`/`b6` 的确切公式（下一步：`0xf643c` 的返回值或其内部写 hex 的指令）；
2. key 里三个 16 位字段的语义（与 `e3`/nonce 的相关性）。

## 2026-10-22（第二十七轮）—— `memAfter` 解析没问题：怀疑落在 inline 模式的 after-stub

读了 `native_hooks.cpp` L994–1051 的 `memAfter` 解析器，对 `x0:64` 完全合法：

```
p[0]=='x' && p[1]=='0' && p[2]==':'   → ok
after_reg = 0
':' 后读十进制 64，上限 ADH_MEM_AFTER_MAX（64 不超）
canon = "x0:64"，after_len = 64
```

随后 L1085 用 `after_len > 0` 选择 `after_stub_for_id(slot)`，所以 **stub 是 after 版本**。也就是说：**spec 没被拒、stub 也选了 after 版，但命中后没有记录**。

剩下两个可能，按可能性排序：

1. **inline 模式下 after-stub 不被调用**（早前能工作的那次是 `compress` 的 **GOT** hook；最近的失败全是 **inline**）——这是最像的；
2. `ctx.after_arg/after_len` 的赋值时机在 hook 激活之后，命中时读到 -1（L1283 在 activate 之后的话就会这样）。

**判断方法（下一轮直接做 A/B）**：用同一个 `memAfter:"x0:512"` 分别装 **got**（compress）和 **inline**（`0xf643c`）两种 hook，各触发一次签名：
- got 有 after 记录、inline 没有 → 结论 1 成立，修 after-stub 的 inline 路径；
- 两者都没有 → 是回归，对照 `git log -p` 找差异。

## 2026-10-22（第二十六轮）—— 更正：只留一个 hook 也没有 after 记录；怀疑与 `agent_main.c` 重建有关

上一轮把 `memAfter` 失效归因于"after 配置是全局单份、被后续 install 重置"。本轮做了**只保留一个 hook** 的干净实验（撤掉全部 → 只装 `0xf643c`，`mem:"x2:8"` + `memAfter:"x0:64"`）：

- `installed:` 为空（说明撤干净了），新 hook `id=10`，`ok=true`；
- 签名正常（`b5=88682d91274d382c4f36…`）；
- 记录：`mine=4`，**仍然全是 pre 侧**（`x2` 快照），**after 依旧 0 条**。

→ 上一轮的"全局 ctx 被覆盖"**不是**充分原因（单 hook 也失败）。after 路径在当前 agent 构建上就是没工作。

**新的怀疑方向（重要）**：早前 `compress` 的 `memAfter:"x0:512"` 是**能**产出 `phase:"after"` 记录的，那次发生在我**重建 `agent/src/bootstrap/agent_main.c` 之前**。重建时 `cmd_native_hook` 的参数是我按 `native_hooks.h` 的签名补的（`mem/memAfter/writeReg/writeOff/writeHex/errno`），**很可能某处没接对**（JSON 键名、参数顺序或 after_spec 未透传），导致现在 `memAfter` 到了 native 侧就是空串。

**下一步（优先级最高）**：核对 `agent_main.c` 里 `cmd_native_hook` 的实参顺序与 `native_hooks.h` 里 `adh_native_hook_install` 的形参顺序是否一一对应（尤其 `after_spec` 是第 20 个参数、在 `&hook_id` 之前），以及 dispatch 里 `json_get_str(line, "memAfter", …)` 的键名与 daemon 发送的键名一致。**这条不修，`b5`/`b6` 的返回值就抓不到。**

## 2026-10-22（第二十五轮）—— `memAfter` 不产记录的根因：after 配置是**全局单份**，被后续 hook 覆盖

读 `agent/src/hook/native_hooks.cpp` 定位到具体机制：

- after 配置存在**一个全局 `ctx`** 里：`ctx.after_arg` / `ctx.after_len` / `ctx.after_spec`（L78/80/81）。
- 每次 `adh_native_hook_install` 都会把它们**重置**：`ctx.after_arg = -1; ctx.after_len = 0; ctx.after_spec[0] = 0;`（L929-932）。
- 命中时 `adh_native_hook_after(retval, regs, hook_id)` 虽然**拿到了 `hook_id`**，但读的仍是那个全局 `ctx`（L675-676）；`after_arg < 0` 就直接返回（L678），**不产生任何记录**。

所以真实序列是：我先装了带 `memAfter` 的 hook，之后又装了别的 hook（compress/thunk/0x975c0…），**后一次 install 把 after 配置清成 -1**，等签名跑起来时 after 路径看到 arg=-1 就静默返回了。这解释了"早前 compress 的 `memAfter` 能用（当时只有它一个 hook）、现在不行（多 hook）"。

**缺陷定性**：after 窗口的参数应当是**每 hook 一份**（按 `hook_id`/slot 索引的数组），而不是全局单份。修复点：
1. `ctx.after_arg/after_len` → `after_arg[ADH_NATIVE_MAX_HOOKS]`、`after_len[...]`；
2. install 只写自己 slot 的那一项，不重置全局；
3. `adh_native_hook_after` 用 `hook_id` 索引取值（它已经有这个参数）。

**规避**（当前可用）：**先撤掉所有别的 hook，只留带 `memAfter` 的那一个**，再触发签名。

## 2026-10-22（第二十四轮）—— 发现 `memAfter` 单独使用不产生记录（插件缺陷）

为了抓 `0xf643c` 的**返回值**（很可能就是 b5/b6 的 32 字节摘要或其 hex 缓冲），在它上面只装 `memAfter:"x0:64"`（不带 `mem`），并做了"清空采集 → 装 hook → 重放 → `capture_stop` → 再读"的干净循环：

- hook 安装成功（`hook=8`），签名正常（`b5=88682d91274d382c`）；
- 读 `live_captures` 并按 `hookId 8` 过滤：**0 条**（`total=24` 全是上一轮 hook 5 的陈旧记录）。

**这暴露出一个真实的插件缺陷**：`native_hook` 只给 `memAfter` 不给 `mem` 时，命中不产生 `NATIVE_HOOK_MEM` 记录——after 记录应当独立于 pre 记录存在。要修的地方在 `agent/src/hook/native_hooks.cpp` 的 after 路径（只为 `mem_spec` 建 per-hook 快照，`memAfter` 单独设置时没有上下文可写）。

规避方式（当前可用）：同时给 `mem` 和 `memAfter`（上一轮实测两者同给时 hook 5 有记录），即 `mem:"x2:8", memAfter:"x0:64"`。

## 2026-10-22（第二十三轮）—— `0xf643c` 的对象不是摘要缓冲

给 `0xf643c` 挂 `mem:"x2:64"` + `memAfter:"x2:64"`（一次签名命中 4 次，`call ok`，`memRecs=4`，**目标没崩**）。这 4 次的前 64 字节：

```
seq1: 310, 568, 4462, 0, 指针…
seq2: 435, 992, 10522, 0, 指针…
seq3: 732, 672, 6622, 0, 指针…
seq4: 与 seq3 相同
```

- 头三个是整数（像是**偏移/长度/游标**：310/568/4462、435/992/10522、732/672/6622），后面是堆指针；**不是 32 字节摘要，也没有 64 位 hex**。
- `memAfter` 没有产生独立记录（after 记录按 `phase` 区分，这批只有 pre），所以"函数往这个对象写了什么"还没观测到。
- 结论：`x2` 是**工作对象**（游标+缓冲描述符），摘要不在它的前 64 字节里。要抓输出得看它**返回后**写到哪儿（`x0` 返回值 / 对象里的指针目标）。

**下一步**：在 `0xf643c` 返回时用 `returnValue` 或对返回值指向的内存做 `mem` 观测；或直接 hook 它内部调用的写入点（`strb/str` 到 hex 缓冲）。这条路径安全（本轮 4 次命中未崩）。

## 2026-10-22（第二十二轮）—— `0xf643c` 的入参对上了 body 的参数个数

hook `libjdg+0xf643c`（`0x975c0` 在组装完 7 个字段后调用的那个函数），一次签名命中 **4 次**，入参：

```
x0=0x7320399420 → libjdg+0x14d420（运行期填好的指针表）
x1=0x10  = 16
x2=0x72d66397c0   对象指针
x3=0x1d  = 29     ← 正好等于请求 body 的参数个数（29 个）
x4=0x17b = 379
x5=0x70b3b7b46e   5 字节值
x30=libjdg+0x976ec（0x975c0 里的返回地址）
```

- `x0` 换算后正是那张**运行期填充的指针表**（`0x14d420`），`x3 = 29` 与 body 参数个数吻合、`x4 = 379` 像一个长度。
- 说明 `0xf643c` 是**按表逐项处理 body 参数**的函数（喂给摘要/序列化），这正是 `b5` 覆盖 body、`b6` 覆盖 body+入参 的实现位置。
- 一次签名里它被调 4 次 → 分别对应 body、参数、以及两次收尾。

**下一步（已具体到寄存器）**：在 `0xf643c` 上挂 `mem`（`x2` 对象、`x5` 那 5 字节），把每次调用的输入/输出都抓下来；再对齐"哪一次的输出等于 b5/b6"。这条路径不需要硬件观察点，也不会崩目标。

## 2026-10-22（第二十一轮）—— 定位到 jdgs JSON 的组装点（b5/b6 就在这条路径上）

在 `libjdg+0x975c0`（此前认为的"7 字段序列化器"）上装 hook，一次签名命中 **1 次**，入参：

```
x0=0x74400fb710 x1=0x74400fb700 x2=0x74400fb770
x3=0x733354f600 x4=0x5fa(1530) x5=0x74400fb720 x6/x7=libjdg 数据指针
```

读 `x3` 指向的缓冲：内容是 **`[{"b1":"68d…`** —— 即**正在组装的 jdgs 结果数组**。

所以 `0x975c0` 不是"指纹序列化器"，而是 **jdgs 输出 JSON 的组装点**；`b5`/`b6` 就在这条路径上被写进这个缓冲。这是目前离 `b5`/`b6` 最近的一个确定位置（比之前"猜输入"强得多）。

**下一步**（已具体化）：在该缓冲上做 `mem` 观测，或 hook `0x975c0` 的**下游调用**（它内部经 `0x102500`/`0x102260`/`0xf643c` 组装），把"写 32 字节 hex 到缓冲"的那一步抓出来；`x4=1530` 与 body 长度一致这一点也值得单独确认（可能是同一套缓冲复用）。

## 2026-10-22（第二十轮）—— 宿主调用里没有 b5/b6 的生产者

修掉上一轮的时序问题（读 `live_captures` 前固定 `Start-Sleep 2`），同一实验抓到 **256 条宿主调用**事件，按目标地址与参数筛：

- 参数里出现 `1530`（body 长度）/`64`/`32`/`20`（摘要长度）的调用：**0 条**；
- 目标地址**只出现一次**的调用（"一次性的生产者"特征）：**0 个**（每个目标都重复多次）。

→ `b5`/`b6` 不是通过 `0x104000` 那个"宿主调用"机制算的，而是 **`libjdg` 内部内联计算**的。这也和"RC4 是唯一走宿主调用的密码学"这一观察一致。

**工具侧确认的坑**（两次踩到，已写进操作习惯）：`live_captures` 必须在 `java_call_result` 之后**等 drain**（≥2 s）再读，否则读到空环/被覆盖的环。

**下一步**：既然不是宿主调用，就在 101 分支内部找写入点——用 `mem` 窗口在 `main` 的返回路径上抓 32 字节 hex 字符串的生成，或对 body 指针下"读观察"（原生 hook 的 `mem` 只支持写前/写后快照，读观察要靠 `hw_watch`，但它在京东上会崩目标，**此路不通**）。现实可行的只剩：在 `0x975c0`（7 字段序列化器）与 `0xf643c`（逐字符状态机）这条链上做定点 `mem` 观测。

## 2026-10-22（第十九轮）—— b5 又 10 种形状落空：猜测这条路走完了

在第十七轮 14 种之后，再补 10 种"实现上合理"的 body 形态（含 URL 解码、UTF-16LE、大小写归一、成对重编码），4 种算法 + 2 种 HMAC 全部落空：

| 形状 | 长度 | sha256 前 8 |
|---|---|---|
| body 原始 | 1530 | `09246ae9` |
| query 解码后 | 1244 | `374c4703` |
| body 解码后 | 1264 | `15b362bf` |
| query UTF-16LE | 3020 | `2db98803` |
| body UTF-16LE | 3060 | `5133b48b` |
| `+`→空格 / `%20`→空格 | 1510 | `d0c6c8be`（与 query 相同） |
| query 全小写 / 全大写 | 1510 | `16d208b6` / `841c6f5e` |
| 成对重编码 | 1776 | `e989e7f6` |
| **目标 b5** | | **`88682d91`** |

**合计 24 种 body 形状 + 19 种入参候选 + HMAC/加盐/固定串，全部落空。** 结论：`b5` 的输入不是"可见字节的某种直接拼接"，继续枚举没有信息量——必须**抓生产者**（原生侧），这是唯一剩下的路。

## 2026-10-22（第十八轮）—— JCA 捕获 0 命中：b5/b6 不走 Java 密码学

用 `java_hook action:"crypto"` 装 JCA 捕获（`Cipher`/`Mac`/`MessageDigest`/`Signature`，**31 个 hook 全部安装成功**，`backend=art v6.4`，`available=true`），然后做一次签名并抓 `JAVA_HOOK` 事件：

- 事件数 **0**；`status` 里 `patched=0`、各 hook `hits=0`。
- 同时 `b5`/`b6` 正常产出（`88682d91…` / `509c5b72…`）。

→ **`b5`/`b6` 不是 Java 侧 `MessageDigest`/`Mac` 算的**，结合"进程内存里没有 SHA-256 常量表"，可以判定：这两个 64-hex 字段由 **libjdg 的原生（混淆）实现**产出，和 RC4/key 那套是同一层。

这一步的价值是把"去 Java 层找"这条分支彻底关掉——之前它看起来最像（64-hex、Android 常见做法），实测是 0 命中。

**下一步**：在原生侧找"谁读了那 1530 字节的 body"或"谁写了 b5/b6 的 32 字节"。可行手段只剩 hook（硬件观察点在京东上会崩目标）：在 `main` 的 101 分支附近下 `mem` 窗口，或用已有的"宿主调用"thunk（`0x104000`）按目标过滤做定点观测。

## 2026-10-22（第十七轮）—— b5 对 body 的 14 种形状全部落空

在"`b5` 覆盖请求 body"的基础上，用**同一份 body**（1530 B，29 个参数）扫了 14 种"实现上合理"的形状，4 种算法（sha256/sha1/sha512/md5）+ 2 种 HMAC 全否：

| 形状 | sha256 前 8 字节 |
|---|---|
| body 原始 | `09246ae9` |
| query（去掉 `POST /client.action `） | `d0c6c8be` |
| 参数排序后 `k=v&…` | `d0c6c8be`（**与 query 相同**——这个请求的参数本来就是字母序，排序是空操作） |
| 参数排序后拼接 `kv…` | `c231d155` |
| 只取参数值 | `0683e52b` |
| `/client.action <query>` | `53732e3c` |
| `POST/client.action<query>` | `69bf7b8b` |
| 末尾加 `\n` / `\0` | `c3533256` / `873e6573` |
| 排序后 `&\n` | `fc3e876a` |
| `sorted&+key` / `key+sorted&` | `2c4843af` / `fde3f946` |
| `body+key` / `key+body` | `3e9c6861` / `bc020d28` |
| **目标 b5** | **`88682d91`** |

结论：`b5` 不是"把 body（或它的常见归一化形式）直接哈希"得到的。要么还有一层 **salt/密钥 + 变换**（不在这些形状里），要么计算发生在混淆层/Java 侧。**继续猜拼接方式已经没有信息量**，下一步必须抓生产者：hook `MessageDigest.digest()`／`Mac.doFinal()`（Java 侧），或在 native 侧按"谁读了这 1530 字节"下观察点。

## 2026-10-22（第十六轮）—— **修正：b5 不是常量，它覆盖请求 body**

只改请求 body 里的一个参数（`area=1_72_55674_0` → `1_72_55674_1`，其余字节不变）：

| 改动 | b4 长度 | b5 | b6 |
|---|---|---|---|
| baseline | 392 | `88682d91274d` | 基线 |
| body 的 area 值 +1 | 392 | **CHANGED**（`fd288d771fdd`） | CHANGED |

**修正第十四轮的结论**：`b5` 并非"构建级固定常量"，而是**对请求 body（`element[0]`，1530 字节的 `POST /client.action …`）敏感**；它对 nonce/version/eid/e5/拼接串不敏感、跨进程相同，是因为这些实验里 **body 一直没变**（body 里的 `ts=` 也只是每次回放同一份）。

所以目前的分工是：
- **`b5` = f(body)**（只覆盖请求体）
- **`b6` = f(body + 其余全部入参)**（覆盖更宽）
- 两者都**不是**对可见字节直接 SHA-256（第 13 轮 19 个候选 + HMAC/加盐 + 固定串全否），说明还有 salt/变换，或走 Java 侧非标准实现。

下一步：把 body 拆成 `ep`/`ext`/`ts` 分别改，定位 `b5` 的确切覆盖范围与是否有密钥参与。

## 2026-10-22（第十五轮）—— **生成侧逐字节复现成功**（zlib level 6）

```
b4 = base64( RC4_key( zlib.compress(fingerprint_json, 6) ) )
```

用抓到的 20 字节 key + 解密出的指纹明文，`zlib.compress(level=6)` → RC4 → base64，生成的 `b4` 与京东返回的**完全一致**（412/412 字符，`PASS`）。

**关键坑**：压缩实现必须匹配。Node 自带的 zlib（zlib-ng）从第 3 字节起就不同，**CPython 的 zlib 1.3.2 在 level 6 下逐字节相同**。参数扫描（level 1–9 × memLevel 5–9 × windowBits 9–15 × 5 种 strategy）在 Node 里全部落空，换成 CPython 一次通过。

**交付物**（都在 gitignore 的 `adhd-data/_verify/` 内，密钥/明文不入库）：
- `jdgs_gen.py` —— 生成器：`python jdgs_gen.py <key.hex> <plaintext.json> [captured_b4.txt]`，带第四个参数就做逐字节比对并用退出码报告（本轮 `PASS 412 vs 412`）。
- `jdgs_repro.mjs` —— 验证器：解密 / inflate / JSON / RC4 回环 / 本地压缩 五项检查；前四项 PASS（RC4 层逐字节精确），第五项按预期 FAIL（Node zlib 与目标不同，已由 `jdgs_gen.py` 补上）。

**补充**：`b5` 的 32 字节值与它的 hex 字符串都**不在 `libjdg.so` 里**（静态搜索三者全 -1）→ 它不是硬编码常量，而是运行时算出来的（但对入参不敏感、跨进程恒定）。

## 2026-10-22（第十四轮）—— b5 是**固定常量**，b6 是**全入参摘要**

**差分实验（一次只改一个入参，其余不变）**：

| 改动 | b4 长度 | b5 | b6 |
|---|---|---|---|
| baseline | 396 | `88682d91274d` | 基线 |
| nonce `[5]` | 396 | **same** | CHANGED |
| version `[3]` | 396 | **same** | CHANGED |
| eid `[2]` | 392 | **same** | CHANGED |
| e5 `[4]` | 392 | **same** | CHANGED |
| 拼接串 `[1]` | 400 | **same** | CHANGED |

**结论**：
- `b5` **不随任何入参变化**，而且**跨进程重启完全相同**（`88682d91274d382c…`）→ 是**构建/设备级固定常量**（不是会话密钥，也不是请求摘要）。
- `b6` **对每个入参都敏感** → 是**覆盖全部入参的整性摘要**（每调用一份）。
- 这解释了之前"同输入重复调用 b5 相同、b6 不同"的旧观察：b6 里还混了时间/nonce 一类每次变化的东西。

**其它排查**：
- 进程内存里**没有任何 SHA-256 常量表**（`memory_search` 命中 0），而 `libjdg.so` 里有 **SHA-1 的 H 常量**（文件偏移 `0x5abb0`）→ 64 hex 的那两个字段不是"进程内标准 SHA-256 实现"算的，更像 Java 层或走混淆实现。
- 候选测试全部为负：19 个直接输入、HMAC（3 算法 × 3 key × 12 消息）、key/消息两种顺序的加盐摘要、以及 14 个固定字符串（包名/版本/appId/`jdgs`/`checkAccessRights` 等）→ 没有一把中 b5。

**下一步**：只改请求字节（`element[0]` 里改一个参数值）看 b6 是否变化，以确定 b6 是否覆盖 body；再用 `java_call` 直接调 Java 的 `MessageDigest`/`Mac` 路径做对照，或 hook Java 侧摘要调用点。

## 2026-10-22（第十三轮）—— b5 / b6 的 19 个候选全否；key 二次验证通过

**key 再次端到端验证**：换一次调用重新抓 key（`603d63fa82edfe7415b65c8e8b98ebe3dc845d8a`）+ 同次 `b4`（412 字符 → 307 字节），`RC4(key)` 解出 `78 9c 95 8e …`，inflate 出 385 字符的指纹 JSON。说明"20 字节 key + RC4 + zlib"这条链路稳定复现，不是一次侥幸。

**b5 / b6 的排查（19 个候选全否）**：同一次调用的数据里，把下面这些都做了 SHA-256 并和目标比对，一个都没中：
`D`（压缩流）、指纹明文 JSON、`C`（b4 字节）、`b4` ascii、请求字节（1530 B）、`e5`、`eid`、`b1/appKey`（含去横线）、40hex、`key`、`b7`、以及 `D+key`/`key+D`/`b4+key`/`plain+e5`/`e5+plain`/`req+e5`/`e5+req`。
（目标 `b5=88682d91…`、`b6=264c658b…`。）→ b5/b6 不是"对可见数据直接 SHA-256"，更可能是**带 salt/HMAC**，或走 Bridge 的另一个 opcode（之前见过 opcode 106：`(int,"<32hex>&<e5>",long) → 32-hex`）。下一步从 opcode 106 的 native 实现入手，而不是继续猜拼接方式。

## 2026-10-22（第十二轮）—— **jdgs 打通：20 字节 key 找到，b4 可完整还原**
**结论（已逐字节验证）**：
```
b4 = base64( RC4_key( zlib_compress(fingerprint JSON) ) )
key = 传给 libjdg+0x89480（KSA）的 20 字节
fingerprint JSON = {"e1":<eid>,"e2":"1.0§§0§§<包名>|<32hex>|<版本>§§…","e3":<ms>,"e5":…,"e4":…}
```

**怎么拿到的**
1. 上一轮发现状态是**每线程缓存**（后几次调用状态地址不变且不再被写）→ KSA 只在**新线程的第一次签名**里跑。
2. `0x89480`（另一个 RC4 入口，经 thunk 调用）的入参就是 KSA 的：`(state, keyPtr, 20)` —— 无 `mem` 的 hook 只命中 1 次、进程存活。
3. 给它加 `mem:"x1:32"` 在调用当刻拷 key（事后读 key 指针只会拿到被复用的垃圾）。重启 App 制造新线程后一次性抓到：key20=`e89361fa82edfe749d185e8e8b98ebe3542a5f8a`，同一次调用的 b4（C=305 B）。
4. 离线：`KSA(key20)` → PRGA 作用于 C → 首字节 `78 9c …` → **inflate 成功** → 指纹 JSON，键为 `e1,e2,e3,e5,e4`。

**key 的结构（初步）**：两次抓取对比
```
7d1366 fa82edfe74 08 98 598e8b98ebe3 c1aa58 8a
e89361 fa82edfe74 9d 18 5e8e8b98ebe3 542a5f 8a
```
第 3–7 字节、10–15 字节、最后一字节恒定；0–2、8–9、16–18 每次不同（像**指针/时间戳字节 + 固定盐**拼成的 20 字节结构）。同一线程内缓存复用 → 每线程一次。

**下一步**：把 key 的 20 字节按字段拆开（在 KSA 调用点抓 `x1` 前后内存、或用它作为"已知明文"反推字段），以及 `b5/b6` 的输入；最后写复现器对 oracle 逐字节比对。

**补充（同一轮后续）**
- 一次进程里连做 5 次签名，抓到 **5 个 20 字节 key**（每线程一次），结构稳定：
  ```
  a0da60 fa82edfe74 d551 5f8e8b98ebe3 1c63 5e8a
  61d860 fa82edfe74 1453 5f8e8b98ebe3 dd61 5e8a
  3fd660 fa82edfe74 4a5d 5f8e8b98ebe3 836f 5e8a
  f9d760 fa82edfe74 8c5c 5f8e8b98ebe3 456e 5e8a
  b8d560 fa82edfe74 cd5e 5f8e8b98ebe3 046c 5e8a
  ```
  恒定：`[2]=0x60`、`[3..7]=fa82edfe74`、`[10..15]=5f8e8b98ebe3`、`[18..19]=5e8a`；变动的是 `[0..1]`、`[8..9]`、`[16..17]` 三个 16 位字段（像"固定盐 + 三个字段"的结构，不是随机 key）。
- 同一个 hook 还抓到一条 **ASCII 形态的 key**：`A26be459823ecfe7453357ae`（32 hex 字符）——说明 `0x89480` 是被多处复用的"带 key 的 RC4 通用函数"，我们抓到的是其中两次不同用途的调用。
- **压缩侧不可离线复现**：把解出的明文用 Node zlib 重压，9 个 level 得到的长度是 306/307，目标是 **305**；level 6 头两字节对得上（`78 9c`）但从第 3 字节起就不同 → 目标用的是**另一套 zlib（版本/参数不同）**。所以"逐字节生成 b4"要么匹配目标的 zlib 参数（还要再试 memLevel/strategy/windowBits），要么直接取设备自己的压缩输出。

## 2026-10-22（第十一轮）—— **b4 的密码本体找到了：RC4**（密钥流不再是未知）

这一轮把"密钥流是什么"从黑盒变成了具体算法，证据是**逐字节**的。

**1. 怎么命中的：观察点（`hw_watch`）+ 在 hook 返回那一刻 arm**
- 之前所有静态线索都是假的：`0x97b78` 的 `eor lsl #5/#29/#28` 是混淆比较，`0xf6474` 的 `eor` 是逐字符状态机，`0x1020a4` 的 11 项跳转表是**按宽度存储**的辅助（`strb/strh/str/w`）。连续三次误判，教训写进案例 4。
- 真正有效的是：GOT hook `compress`（带 `memAfter`）拿到目标自己的压缩输出 **D**；再在 `compress` 返回的瞬间，用 `x0`（目标缓冲）挂一个 **rw 硬件观察点**（新能力 `hw_watch action:"after"`）。**压缩结束后第一条碰 D 的指令**就是答案：
  ```
  libjdg.so+0x89608  ldrb w9,[x20,x22]      ← 观察点命中的就是这一行（读明文）
  libjdg.so+0x89610  eor  w8,w8,w9
  libjdg.so+0x89614  strb w8,[x19,x22]
  ```
- 它所在的函数入口 **0x89574**，上方 0x89560 是一个 4 条指令的**原地交换**助手；0x895ec 通过重定位指针调用它。

**2. 这就是 RC4（教科书式 PRGA）**
```
i = (i+1)&0xff;  j = (j + S[i]) & 0xff;  swap(S[i], S[j]);
out[n] = in[n] ^ S[(S[i]+S[j]) & 0xff];
```
状态结构 258 字节：`S[256]` + `i`(0x100) + `j`(0x101)。

**3. 抓住了 KSA 之后的完整状态，并自证**
在 `0x89574` 挂 `mem:"x0:192,x0+192:66"`（+ `memAfter:"x2:192"` 拿同一次调用的输出）：
- 抓到的 258 字节里 **S 是 0..255 的合法置换**，`i=0 j=0`（KSA 刚结束的特征）。
- 用这个状态跑 PRGA 覆盖 D，结果与同一次调用 PRGA 写出的 192 字节**逐字节相等**；该前缀又与 `base64decode(b4)` 的前 192 字节相等。
- 结论钉死：**`b4 = base64( RC4_{KSA(key)}( zlib(fingerprint JSON) ) )`**，等长、无前缀，之前所有"等长异或"的观察都是 RC4 的输出。

**4. 密钥还没拿到，但候选被**精确**排除**
KSA 是确定性的，所以"猜 key"可以严格判定（比较 256 字节置换，全等才算中）。已排除：`e5`、`eid`、每次调用的 uuid、完整请求字节（1530 B）、`e5+eid`/`eid+e5`，以及它们各自的 `sha256`/`md5`、`sha256(JSON)`、`sha256(D)`、`md5(D)`、`appKey`(含去横线版) —— **最好候选只有 3/256 位吻合（随机水平≈1）**。
- 下一步（已定）：把观察点挂在**状态缓冲的首字节**上（地址用 `NATIVE_HOOK` 事件里的 `x0`），下一次调用会命中 KSA 的 `S[0]=0` 那条写指令 → 反汇编它 → 拿到 `key` 指针与长度 → 用 `mem` 抓 key（若 key 是运行时派生，再往上一层）。

**6. key 的排查（两轮的结果）**
- 包装函数的形状（`0xdebf0`，帧 0x160）：同一个**栈上状态** `sp+8` 先喂 `0x89480`、再喂 `0x89574`；前面有一次 `memset(dst,0,len)` + `memcpy(dst, 压缩数据, len)`。曾据此假设"key 就是 D 本身"——**离线证伪**：`KSA(D[0:n])`（n=8..512、`sha256(D)`/`md5(D)`/明文 JSON）与抓到的 S 最好只吻合 **2/256**。
- 因此状态是在更外层初始化好再传进来的；且同进程两次调用 S 不同 → **key 每次调用都变**（很可能含时间戳/nonce）。
- 包装函数**没有直接 `bl` 调用者**（`0xdeb74` 的"最近序言"其实是 `write_all`，真入口是 `0xdebf0`；其内部全是 `ldr x8,[table]; br x8` 的间接分支）→ 静态跟不动。
- PRGA（`0x89574`）的 4 个 `bl 0x95878` 调用点（`0x963f8`、`0x965e0`、`0xded74`、`0xdeed4`）**逐个挂 hook 全部 0 命中** → 它实际是通过 `.data.rel.ro` 里的函数指针被调的（`0x14d5a8 → r_addend 0x95878`），不是直接调用。这条也解释了为什么静态调用图是断的。
- 未解决的工具问题：**`hw_watch status` 在出现 hit 之后会超时**（lock 已改成不跨锁 + arm 独立加锁，仍未根治）；命中结果已存在槽里、日志也能看到，但 status 拿不到——下一次先修这个，再看 `hit.chain`（18 帧）里 PRGA 的真正调用者。
- **已修**（同一轮后续）：`status` 改 `pthread_mutex_trylock`，拿不到锁就回 `busy`；命中路径不再往采集环 push（环满会把 watcher 卡住），链改由 `LOGI` 落 logcat。真机验证：命中后 `status` 正常返回 `slot0 active=false pollRc=1 revents=1`。新增 `action:"hit"`（小回复）仍有一个阻塞 bug，暂用 logcat 取链。
- **18 帧链已拿到**（logcat `hw_watch hit ... chain=[…]`，换算成 libjdg 偏移）：
  ```
  #0 +0x89608   PRGA 读明文那条指令
  #1 +0x104050  ← 可变参数 thunk (0x104000) 的返回地址
  #2 +0x10328c  ← compress 调用点 (0x103288) 的返回
  #3 +0x102d44  #4 +0x10212c  #5 +0xf65fc  #6 +0x9782c  #7 +0x97148
  #8 +0x104050  #9 +0x10328c  …（同一组再出现一次）
  #15 +0xa6b40
  ```
  结论：**PRGA 和 compress 都是经同一个"宿主函数调用" thunk（0x104000）被调的**——这就是为什么 4 个 `bl 0x95878` 调用点全部 0 命中（调用走的是 x2 里的函数指针）。下一步：hook `0x104000`，用事件里的 **x2 = 目标地址**列出一次签名里的全部宿主调用，KSA 一定在其中（它紧挨着 RC4 之前）。
- **已读**：`0x14d420` 在运行时是**指针表**（读回 `0x7325ec45c0`、`0x7325f58708`、`0x7325ec1bb0` …），不是 16 字节密钥；`w1=0x10` 是条目数。所以 `0xf643c` 那一步是"按表处理"，不是 key 派生。
- **规模问题记一笔**：一次签名 422 次宿主调用 vs 128 条采集环 → RC4 那两条被冲掉。要枚举宿主调用，需要给 `native_hook` 加"按目标地址过滤"（只记录 x2 命中白名单的调用），否则环永远不够。
- **不用 `mem` 的 PRGA hook 是安全的**：`0x89574` 只观测（无 mem/memAfter）时命中 1 次、进程存活，事件直接给出 RC4 调用的入参：**`x0`=状态（栈）、`x1`=`x2`=同一缓冲区（原地加解密）、`x3`=长度（本次 303）、`x30`=`+0x104050`（thunk 返回地址）**。
- 状态地址**按线程不同**（工作线程池：`0x744267e620` / `0x72f1c60350` / `0x743f0fa620` …）；在状态地址上挂**写观察点后，后续两次调用都没有写命中** → 状态很可能是**每线程初始化一次并缓存复用**（这也意味着同一线程内 S 恒定，key 是会话/线程级的静态材料，不是每调用变化——之前"每次调用不同"的印象来自跨进程比较，需要重新校准）。
- **危险结论**：在 JD 上挂硬件观察点（perf 断点）后目标**第三次 SIGSEGV**（`13:43:04 pid=24370 reason=5 APP CRASH(NATIVE)`）。JDGuard 是反篡改库，硬件断点很可能被它检测到并主动崩。**后续在京东上禁用 `hw_watch`**，改用 hook/静态分析。
- 另一个环境事实：`setenforce 0` 不持久——期间自己回到过 `Enforcing`，每次 arm 前都要重新确认。
- 沿着 18 帧链往上走（静态）：`+0xa6b3c bl 0x96fec` → `0x96fec` 是**六参转发 trampoline**（存参后 `br x8`）→ `0x975c0` 是**7 字段序列化器**（`0x102500` 构造 + 逐个 `0x102260`/`0x102230` append；错误码 11）。序列化完在 `0x976d8` 调 `0xf643c(0x14d420, 16, obj)` —— 即以 `.data.rel.ro` 的一个 **16 字节常量**为输入跑那个"逐字符状态机"函数（1,714 条 `eor` 的那个）。这一层是不是 key 派生，下一轮验证（读 `0x14d420` 的 16 字节、hook `0x975c0` 看 7 个字段到底是什么）。
- 因此状态是在**更外层**初始化好再传进来的（这个包装只负责用它做两段 RC4），KSA 在它的调用者里；且同一进程两次调用的 S 不同 → key 每次调用都变（很可能含时间戳/nonce）。
- 下一步：hook 这个包装函数的**调用者**（或 `0x89480` 的调用点），拿到 KSA 的入参 `(state, key, keylen)`；若 key 来自 `0x15705c` 一类**加密常量**（已在 `.data.rel.ro` 见到密文），就再跟一层解密函数（`0x96dbc(ptr, 4)` / `0x96e0c(ptr, 5)` 那种形态）。
- **注意**：在 `0x89574` 上装带 `mem`/`memAfter` 的 inline hook **两次把京东打崩**（SIGSEGV, APP CRASH(NATIVE)）。该地址后续只在必要时用软钩/短时实验，先取现场再动手。

**7. 这一轮的插件改动**
- 新增 `hw_watch`：`perf_event_open(PERF_TYPE_BREAKPOINT)` + 采样环，命中给 `ip` + 内核调用链，**单次触发后自动撤防**；两种 arm 方式：绝对地址，或 `action:"after"`（某个 native hook 返回时按 `<reg>+<off>` 挂）。内核 5.10 没有 `sigtrap`，所以走采样环而不是信号；**必须先 `PERF_EVENT_IOC_ENABLE`**，否则事件永远不计数（实测：不 enable 时强制写目标地址也不出记录）。
- 平台边界：`kernel.perf_event_paranoid=-1` 也**不够**，SELinux Enforcing 下 app 域 `perf_event_open` 仍返回 EACCES；`setenforce 0` 后可 arm。
- 修掉一个**误报类**缺陷：`memory_search` 会匹配到它自己解码 pattern 的那段栈（随机 pattern 也命中同一固定地址），现在跳过本线程栈。
- 修掉两个把工具自身拖死的问题：`hw_watch status` 在持锁时 `pthread_create` 导致命令超时（改成不跨锁 + trylock）；`hw_watch` 回复超过 900 B 被截成非法 JSON（缓冲 4096/4300）。
- **事故（必须记）**：在 `0x89574` 上装 `mem+memAfter` 的 inline hook 后，京东主进程 **SIGSEGV 崩了一次**（`exit-info` reason=5 APP CRASH(NATIVE)，13:30:40）。RC4 证据在崩之前已抓到；下次在该地址做实验要优先用 GOT/软钩或先备份现场。

## 2026-10-22（第十轮）—— 硬件观察点落地；并抓到一个"搜索匹配自己"的假阳性

按第九轮的分级继续走 ①（粗粒度数据流）→ ②（观察点）。这一轮把 ② 的工具做出来了，同时在 ① 里被一个**假阳性**带偏，纠正过程本身值得记。

**新增能力：`hw_watch`（进程内硬件观察点）**
- `perf_event_open(PERF_TYPE_BREAKPOINT)`（pid=0、cpu=-1），`PERF_SAMPLE_IP|TID|CALLCHAIN`，mmap 一个 8 页环 + 一个 poll 线程；**命中一次就上报并自动撤防**，记录 `ip`（真正写那条指令）、`tid/pid`、内核调用链，写成 `HW_WATCH` 采集记录。`action:set/clear/status`，4 个槽。
- 内核 5.10 **没有** `perf_event_attr.sigtrap`（5.13 才有），所以走采样环而不是信号——这反而更好：调用链由内核直接给，不用自己从 ucontext 走 x29。
- 真机实测：`setenforce 0` 后 `perf_event_open` **成功**（`ok:true, slot:0`）；SELinux 保持 Enforcing 时返回 **EACCES（errno 13）**，虽然这台机器 `kernel.perf_event_paranoid=-1`——**限制来自 SELinux 的 app 域，不是 perf 参数**。这条要写进工具文档，否则下一个人会以为是 sysctl。
- 结论：观察点在"root 可置 permissive 的测试机"上可用；在普通 app 上不可用（除非目标域被允许）。`hw_watch` 的回复里带 errno，不假装成功。

**① 的意外收获：`memory_search` 会匹配到自己的输入**
- 用 `memAfter` 拿到目标自己的压缩输出 D（`78 9c…`，512 字节窗口），`K = C ⊕ D` 得到 305 字节密钥流；随后 `memory_search` 找 K 的前 16 字节，命中 `74430168f0`（`[anon:stack_and_tls:…]`）。
- 但这个地址在**两个不同进程里完全相同**，而且那块内存里有 `c17z`（agent 自己的命令 id）。用**从未发送过的随机 16 字节 pattern** 再搜一次——**同样命中同一个地址**。
- 根因：`cmd_search` 把请求里的 hex 解码到自己的栈缓冲区，然后扫描所有可读区间，**包括自己正在用的这段栈**，于是"命中自己的输入"。
- 影响：任何一次搜索都可能返回一个固定栈地址的假命中，读起来和真命中一模一样。前面"K 在栈上"的推断就是它导致的，**已纠正**。
- 修复：扫描时跳过 agent 当前线程的栈（`pthread_getattr_np` 取范围）。修完随机 pattern **0 命中**；再找 K → **K 在调用结束后已不在内存里**（缓冲区随帧/堆释放）——这才是诚实的答案。

**下一步（已定，按此继续）**
- K 只在调用期间存在，观察点必须在**写入前**就挂上，所以要先拿到"K 缓冲区的地址"：
  1. `NATIVE_HOOK_MEM` 记录目前只有 `reg/offset/requested/got/hex`，**不带绝对地址**；补上 `addr` 后就能知道 D 落在哪。
  2. 用链上 `0x102d40` / `0x102108` 的 `mem:"auto"`（x0–x8 指针各 64 字节）看参数怎么流；哪一层收到 `(缓冲区, 长度)`，哪一层就是 PRG/XOR。
  3. 拿到地址后 `hw_watch mode:"rw"` 挂上去（读也会触发），一次调用就能指到异或那条指令。
- 备选：QBDI 的 memory-access 回调（只记录触碰某地址的指令），不依赖 perf/SELinux。

**验证**：`tsc` 干净、`npm test` **297/297**；agent 已部署；现场已清（钩子撤、捕获停、watch 清、SELinux 恢复 Enforcing）。

## 2026-10-22（第九轮）—— 判断"要不要上 trace"，并把 trace 的入口补成按地址

先回答"是不是只能 trace"：**不是只能，但 trace 确实是最后一级；而在上它之前还有两级更便宜的。** 顺着这个判断把最后一级先修通。

**先做的两个静态否决（省掉了两次无效 trace）**
- 链上 `0x97b78` 那组 `eor w8,w21,w21,lsl #5` / `#29` / `#28` 看着像 xorshift，实际是**混淆比较**：`cmp (a^(a<<5)), (b^(b<<5))` + `cset eq`，扁平化 CFG 的条件求值。
- `0xf6474` 的 `eor w9,w9,w23` 是**逐字符状态机**（`ldrh` + `eor` + 按 16 位值 0x23a 项跳表），混淆过的字符串函数，不是密钥流。
- 结论：在这段代码里"grep eor 找 PRG"是负收益——必须按数据流定位，而不是按助记符。

**trace 原来缺两样，现在都补上了**
1. `qbdi_trace` / `trace_digest` 只收 `symLib+symbol`，而 `main` 是 RegisterNatives 注册的**非导出**函数。agent 的 `adh_qbdi_trace(void *func, …)` 本来就是按函数指针工作的，所以只改命令层：新增 `addr`（绝对地址），`symLib+symbol` 与 `addr` 二选一；`trace_digest` 同样接受。
2. QBDI 要靠 `dlopen("libQBDI.so")`，目标进程里没有这个库。做法：`adb push` 到 `/data/local/tmp` → `su -c cp` 进 App 私有目录并 `chown` 成 App uid → `load_library`（agent 的 `load_so`）注入。

**真机验证（`aa165071`，京东主进程）**
```
load_library /data/data/com.jingdong.app.mall/libqb.so  → ok, qbdi_initVM found
qbdi_trace {addr: libjdg+0xf6430}  → ok, 3 条指令 adrp/add/ret，retval 正确
trace_digest {addr: …}             → ok, 3 条指令的 digest
```
（顺带发现：daemon 重启后 agent 会自己重连，不用重启 App。）

**上 trace 之前还剩的两级（下一轮的顺序）**
- ① 粗粒度数据流：`native_hook mode=got symbol=compress` + `memAfter:"x0:512"` 拿到目标自己的压缩输出 D，配合 oracle 算出 K = C ⊕ D；再 `memory_search` 找 K 还活着的那块缓冲。
- ② 定位"谁写了 K"：现在缺的是**硬件观察点**（`perf_event_open(PERF_TYPE_BREAKPOINT)`，进程内 4 个槽，命中 SIGTRAP 带 backtrace）。这是比 trace 更准的那把刀，ADH 还没有；QBDI 的 memory-access 回调（只记录触碰某地址的指令）是它的替代方案，agent 也没暴露。
- ③ 才是指令级 trace：对 `main`（0x11000 字节、扁平化）不现实；对几十条指令的叶子函数（PRG 候选）正合适。

## 2026-10-22（第八轮）—— native 入口、opcode 分派、真 oracle；顺手补掉 4 个 agent 上限

目标：接着啃 `jdgs` 的算法入口 / native 流程 / VM 入口。这一轮拿到了前三样，并把「回放一次签名」变成可重复的实验台。

**1. 静态把 native 入口钉死**（`libjdg.so` 1,631,472 B，sha `47dac66f…`，从 APK 的 `lib/arm64/` 直接拉，命令行工具跑的）
- 导出只有 `JNI_OnLoad`（0xa1770）。它建 `com/jd/security/jdguard/core/Bridge` 的类名（32 字节来自 0x5b05f，末尾 4 字节在栈上补成 `idge`），然后 `ldr x8,[x8,#0x6b8]` = JNIEnv idx 215 = **RegisterNatives**，`x2=0x159118`（方法表）、`w3=1`（**只注册一个 native**）。
- 表在文件里是全 0（`.bss`/重定位区），从 `.rela.dyn` 拿 addend 才看得到：`name@0x5bda2="main"`、`sig@0x5bda7="(I[Ljava/lang/Object;)[Ljava/lang/Object;"`、`fnPtr@0xa236c`。**这条以后不用再靠 hook 猜**（案例 4 的缺陷 B 对这类 so 就算闭合了）。
- 顺带看清：`JNI_OnLoad` 还读一个**加密字符串**（0x1593cc）→ `__system_property_get`，`atoi >= 28` 才走 API-28+ 分支——字符串在库里是密文，别指望 `strings` 能捞到。

**2. opcode 分派**（`main` 0xa236c，函数体约 0x11000 字节，控制流扁平化）
```
sub w8, w8, #0x65      ; 101
cmp w8, #8             ; 101..109
ldrh w11, [0x63e48 + w8*2]
br x10                 ; 跳转表基址 0xa3858
```
`cmp w8,#0x3e6; b.gt 0xb3580` → 大于 998 的 opcode 走另一条路。case 101（签名）从 **0xa3858** 开始。`entry` 是**通用 RPC**：101 签名、102 环境查询（`[7,1]`/`[17]`… 回 `s1=0;…|h1=0;…`、路径）、106 摘要（`(int, "<32hex>&<e5>", long)` → 32 字节 hex）。

**3. 第一次看到完整的 101 调用向量**（3,318 字符，之前只有 524）
```
[ byte[1530] "POST /client.action <40hex>&area=…&eid=…&ep=<urlenc JSON>&ext=<urlenc JSON>&…",
  "-§§-§§-§§-§§-§§-§§-§§-", <eid>, "1.0", "@A0K5NOx…=", <uuid>, null ]
```
- 元素 0 = 完整签名输入（含 `ep=`/`ext=` 两个 **URL 编码的 JSON**：设备指纹与扩展字段，和 jdguard 自己的 `e2` 是两套）。
- 元素 4 = `e5`（44 字符 base64，33 字节）；元素 5 = 每次调用一个 uuid；元素 6 = null。

**4. oracle 打通（这是本轮的钥匙）**
把同一份向量用 `java_call {detach:true}` 原样回放，**3 ms** 返回完整 jdgs：
```
b1=68dd5803-…（= getAppKey()，装内 UUID） b2=3.6.5_0 b3=3.0
b4=base64(…)=408 字符 b5/b6=sha256 hex b7=<调用时刻 ms>
```
于是「签名」从"只能等目标自己发"变成"可以任意重复的实验"。

**5. oracle 给出的第一批硬结论**
| 实验 | 结果 |
|---|---|
| 同输入连调 3 次（间隔 ~50 ms） | `b4` **每次不同**；`b5` 三次完全一致；`b6` 每次都变 |
| 只改 nonce（元素 5） | `b5` 不变；**`b4` 变了且长度 408→396 字符** → nonce 进了被压缩的明文，不只是密钥流 |
| `b5` 候选输入 | `sha256(请求字节)`、`sha256(请求十六进制文本)`、`sha256(40 hex body 摘要)`、`sha256("/client.action")` **全不中** |
| `b6` 候选输入 | `sha256(base64decode(b4))`、`sha256(b4 ascii)` **都不中** |

**6. native 调用链（`compress` 命中当刻的 8 帧，backtrace 抓的）**
```
main(0xa236c) → 0x97144 → 0x97828 → 0xf65f8 → 0x102108 → 0x102d40
             → 0x103288（六参转发助手）→ 0x104000（可变参 thunk, blr x9）→ zlib compress
```
- `native_hook mode=got module=libjdg.so symbol=compress` 命中 1 次（slot `0x7322583588`），证明 **101 路径确实调 libz `compress`**。
- 注意：`0x9a240` 那组 `deflateInit_/deflate/deflateEnd` **不是** 101 的路径（在那条地址上 inline hook 命中 0 次）；同一个 so 里两套压缩代码，别混。
- `0x103288` 是个把 6 个参数塞栈再 `blr` 的转发器（`0x104000` 里 `ldp x0..x7,[sp]` + `blr x9`），所以静态 call graph 在 deflate 收尾处又断一次。

**7. 这轮修掉的 agent 上限（都是"工具挡住了下一步"，不是顺手改的）**
| 症状 | 根因 | 处理 |
|---|---|---|
| `Bridge.entry` 的参数只看到 524 字符，只能看到第一个元素 | `bounded(Object[])` 用**单值**上限 `MAX_VALUE_CHARS=512` 截整个数组 | 数组参数改用 `MAX_ARG_CHARS`，并把它 1600 → 4608；`byte[]` 的 hex 不再被 512 截（注释写的 2048 字节这才生效） |
| `java_call` 回放报 `unterminated JSON string` | `agent_main.c` 的 `jargs[2048]` 截断 3 KB 的 args JSON | 改 16 KiB，并注明原因 |
| `Object[]` 里放不了 `byte[]`（`entry` 的第一个元素就是） | JSON 数组只能表达字符串/数字 | 新增 `{"$bytes":"<utf8>"}` / `{"$bytesHex":"<hex>"}` 包装，`make_java_arg_typed` 优先按它造 `byte[]` |
| `entry` 返回 `[Ljava.lang.String;@ec1a0e7` | 返回值用 `String.valueOf(Object)`，数组变身份串 | 数组返回值逐元素渲染（上限 64 槽，超出标 `…(N slots)`） |

**8. 还没修的两条（记下来）**
- `native_backtrace` 只从 daemon 的捕获库里找事件，而库要靠 `capture_start` 的 drain 环才有数据：**没开捕获时 hook 明明命中（hits=1），backtrace 却报 "no NATIVE_HOOK event"**。应该在找不到时按需 drain 一次。
- 重启后 `process_list` 还列着刚被 kill 的旧会话（`online` 有几十秒窗口），按它选会话会打到死进程。脚本里现在先 `agent_ping` 再选；工具层应该自己保证（或 `pickSid` 校验 liveness）。

**验证**：`tsc` 干净、`npm test` 全绿；agent 已重建并部署（1,086,624 B，`v26` 导出集仍是 5 个）；真机实验全部在 `aa165071` 上完成；撤钩子 + 停捕获已做。

## 2026-10-22（第七轮）—— 回头补插件缺口：分页、过滤、Dalvik 反汇编、`java_call` 隔离

第六轮之后把案例 4 的缺陷表（A–H）过了一遍，逐条改剩下的。**改了 4 处（F/G/H + `java_call` 隔离），另有 2 条明确不改**，每处都有可复现的验收信号。

**F：`native_analyze` 输出治理**（`analysis.ts`，原来无任何截断）
- 1.6 MB 的混淆 so 一次回吐约 19 MB strings，等于把调用方的上下文打满。现在：`maxStrings`（默认 500，1..5000）分页 + `stringsOffset` 翻页，回包里 `stringsTotal` / `stringsReturned` / `nextOffset` / `longStrings` / `scanCapped` 说清漏了什么；单条超 `maxStringChars`（默认 200）截断并计数；符号每向 4000 上限，`exportsTruncated` / `importsTruncated` 带真实数量。
- 顺手修了个真 bug：扫描循环到 `buf.length` 就停，**EOF 结尾的那条字符串一直丢**（现在的单测直接断言它）。
- 验收：`daemon/test/analyze_strings.test.ts` 5 条（分页/截断/去重/minLen/越界）。

**G：`live_captures` 加 `session` / `package` 过滤**（`state.ts` 的纯函数 `filterLiveCaptures` + `mcp.ts`）
- 原来只有 `category`，沙盒自检记录和目标记录混在一条流里，只能靠读每条记录去分辨；`http_exchanges` 早就有这两个过滤，现在是同一套语义（记录先按自己的 package 戳，进程退出后仍可归属）。
- 验收：`daemon/test/capture_filter.test.ts` 5 条（含"无戳记录不靠猜归属"）。

**H：`dex_method_code` 加 Dalvik 反汇编**（新模块 `daemon/src/dalvik.ts`）
- 不自己写指令表：Dalvik 有约 15 种指令宽度，写错一条后面全程错位、但输出仍然"像对的"。改为在 host 上调 SDK 的 `dexdump -d`，输出重定向到临时文件后**流式解析**（大 dex 的反汇编比 dex 本身大得多，不能进 maxBuffer），只保留命中的方法，每方法 `maxInsns`（默认 400）+ `insnsTruncated`。
- 踩到的坑：这台机器 build-tools 的 `dexdump -o` 直接报 `Can't open …: Invalid argument`（四种版本都一样），所以用 spawn + 继承 fd 把 stdout 写进文件，不走管道也不走 `-o`。
- 工具缺失/不属于 dex/头校验过期时回 `available:false` + 具体原因（提示先 `dex_repair`），**原始 bytecode 照旧返回**。
- 验收：`daemon/test/dalvik_disasm.test.ts` 7 条，其中一条真跑 `dexdump` 解本仓库自带的 `adh_java_hook_bridge.dex`（无 dexdump 的机器自动 skip）。

**`java_call` 隔离（新能力：`detach` + `java_call_result`）**
- 症状：`Bridge.entry` 这类"等自己线程"的方法一调就把整条命令通道拖死，daemon 只看到超时，连"还在跑还是死了"都问不出来。
- 做法：agent 侧新增独立 attach 线程（`java_enum.cpp`：`adh_java_call_async_start` / `_status` / `_list`，保留最近 16 个 job），`java_call` 带 `detach:true` 立即回 `callId`；新 op `java_call_result` 查 `running | done | failed`（带 `elapsedMs`、目标方法、结果或目标自己的异常文本），`callId:0` 列全部。host 侧 `java_call_result` 多了 `waitMs`（0..30000，250 ms 一poll），省得调用方自己写轮询。
- 真机验收（`aa165071`，`com.jingdong.app.mall` 主进程 `s_1bp1`）：`Thread.sleep(15000)` 以 `detach` 启动 **87 ms 返回**；睡眠期间 `agent_ping` **3.17 ms**（改动前会一起卡死）；1.6 s 时查到 `running`；最后 `done elapsedMs=15007`。抛异常的用例 `Integer.parseInt("zz")` 回 `failed` + `java.lang.NumberFormatException: For input string: "zz"`。
- 防呆：旧 agent 没有这个 op 时 `detach` 会被静默忽略而退回同步调用，所以 host 先查 `caps.ops`，缺 `java_call_result` 就报错，不允许"看起来 detach 了其实没 detach"。

**明确不改的两条**
- **B（动态注册的 native 看不到）**：`java_enum` 至少能标出 `native`（实测 `Bridge` 只有 `main` 是 native），但拿到 fnPtr 要么读 `ArtMethod.data_`（按 API 版本解析 ART 布局）、要么把 `JNI_OnLoad → RegisterNatives → ADRP/ADD 表地址` 这条静态链自动化。两条都是正经特性，不是顺手能改的；手动配方仍在案例 4 的 C 行。
- **C（hello 预装 `jni_hook`）**：不是没修，是**证明不安全后撤回**（SIGILL + ART GC 空指针），已从启动策略移除。

**顺带发现的两件事（写进案例 4）**
- `Bridge.getAppKey()` 在 **`:jdpush` 进程里返回 null**，主进程里才是那个 36 字符的 appKey——JDGuard 的状态是**按进程**的，注入到哪个进程会直接改变 oracle 的答案。
- `docs/mcp-tools.md` 是从 `/api/mcp/doc` 生成的，但文件头写着 65 tools，实际早已 77——**文档已漂移**；已重新生成（78 tools），以后加工具就重跑 `adhd-data/regen-mcp-doc.mjs`。

**顺带修好两条坏掉的门禁**（都是"验收脚本本身也是代码"那一类）
- `tools/verify_v71_mcp_registry.sh`：把 heredoc 喂给 `node` 的 stdin 时默认按 **CommonJS** 求值，而脚本正文有顶层 `await import(...)`，于是**每次运行都报 SyntaxError 并 FAIL**——跟 registry 有没有坏无关。加 `--input-type=module` 修好；同一组断言用 Windows node 24 实跑：`tools=78 problems=0`（这台机器的 `bash` 是 WSL、其 node 加载不了 `.ts`，那部分是环境限制，不是脚本问题）。
- `tools/verify_v26_footprint.sh`：`llvm-readelf` 不可用时它不报"缺工具"，而是把空输出当成 `defined-exports=none` 判产物失败——**假红**，读起来和真的足迹回退一模一样。现在预检：不可用就 `RESULT:SKIP` + `⏭`（与 v90/v101 一致）。这两条都实测过：v26 现在 SKIP，v71 的断言组 PASS。
- 顺带核对：新 agent 的动态导出仍是脚本要求的 **5 个**（`JNI_OnLoad` + 4 个 `adh_agent_*`），新加的 `adh_java_call_async_*` 全部 hidden，没有扩大足迹。`FEATURE_STATUS` 里写的"4 个"是旧数，已改。

**验证**：`tsc` 干净；`node test/run.mjs` **297/297**（280 + 17 条新增）；device 侧改动全部真机回归（上面 `java_call` 那段的数字）。**没跑** `verify_all.sh`（按"改什么跑什么"）。

## 2026-10-22（第六轮）—— 把"标准密码学"这一层彻底排除

用 `memAfter` 拿到**同一次调用的精确 D 与 C**后，可以干净地试标准构造（不再有本地 zlib 噪声）：

| 候选 | 结果 |
|---|---|
| `AES-128/256-CTR`、`ChaCha20` × `{e5 ascii / e5 各种 base64 解码 / sha256(e3) / sha256(e3+e5) / md5(e3+e5)}` × `{zero / e3 / e4 / sha256(e3)[:16]}` | **112 种组合全不中** |
| `RC4`（无表常量，最符合"扫描不到结构"的特征）× 12 种种子 × 5 种 drop（0/256/768/1024/3072） | **60 种全不中** |
| K 的 32 字节块之间是否有哈希链（`K[i]=sha256(K[i-1])`、带 counter） | 无 |

**另一个修正是 `e4`**：它在同一次 App 进程内稳定，但**重启后会变**（上一轮是 `cfed316d…`，本轮是 `91c61d85…`）——所以它是"每次会话"的标识，不是"每次调用"的 nonce。

**顺带看到的（目标行为，不是我们的工具）**：签名链路里 jdguard 会 `access()` 一长串模拟器痕迹（`vboxguest.ko`、`vboxsf`、`qemu_pipe`、`goldfish`、`bluestacks`、`androVM`…）。这类探测正是 `detect_summary` 的 `sysModule` 钩子能直接汇总的东西；本次没有开 sys 钩子，是从 `access` 的 GOT 上顺带看见的。整段采样里**没有** `/dev/urandom` 之类的随机源读取。

**结论**：`keystream` 既不是 AES/ChaCha/RC4，也不是请求或设备字段的直接哈希；它是 libjdg 自定义 VM 里的 PRG，且每次调用都换一条。要再往下走，需要能进 VM 的观测手段（非导出地址的指令级跟踪 / VM 字节码提取），这已经超出"在边界上抓"的范畴。

## 2026-10-22（第五轮）—— `memAfter` 落地，并用它把模型修正成"等长异或"

**插件新能力：`native_hook` 的 `memAfter`**（agent `hook/native_hooks.cpp`）
- 语义：安装后选"调用原函数再回来"的 stub（而不是尾跳），在主函数返回后复制**一个**窗口（`x0:256` / `x2+16:32`，1..512 字节），事件带 `phase:"after"` + `ret`，与调用前的 `mem` 记录区分开。
- 只对要 after 的 hook 生效；其它 hook 仍是尾跳（连 x0/s0 的返回值都不碰）。寄存器/返回值原样交回（stub 里额外保存 q0-q3，避免浮点/向量返回值被后置回调破坏）。
- 主机侧 `memAfter` 有独立语法与上限（1..512），不复用 `mem` 的 192×4 上限；agent 侧也独立解析，避免"上限不一致"。
- **自验证**：对 zlib `compress` 装 `memAfter:"x0:320"`，抓到的 `78 9c …` 用 `inflate` 解回来**正好是那 371 字节指纹 JSON**（真机 `aa165071`）。

**模型修正（重要）**：用目标自己的压缩输出重算，`|C| == |D|` 精确成立（295/295、294/294、294/294、293/293）。所以

```
b4 = base64( zlib_compress(JSON) ⊕ keystream )     // 等长，无前缀
```

第三轮那句"1 字节前缀"是本地 zlib 与目标 zlib 差一个字节造成的假象，已改。

**新证据：密钥流带"每次调用的盐"**。同一个请求（同 `t=`、同 functionId）在同一次操作里的两次调用，`b4` 完全不同；换成精确压缩流后任意两次调用的 K 只有 0–0.7% 一致。所以 K 不只由请求决定，还混入了每次调用的量（最可能是 `e3` 时间戳）——这与"服务端能解"是自洽的（服务端知道设备密钥 + 大致时间）。

## 2026-10-22（第四轮）—— 密钥流"按请求"派生，但 PRG 是自定义的

**拿到签名输入本体**：把 `byte[]` 的渲染上限临时提到 2048 后，hook `Bridge.entry` 直接看到 native `main(101, …)` 的第一个参数（255 字节的 ASCII）：

```
POST /client.action <40 hex digest>&area=1_72_55674_0&build=102918&client=android&
clientVersion=16.1.50&ef=1&eid=<eid>…
```

也就是说**签名覆盖请求行 + body 摘要 + 选定的 query 参数**——这解释了为什么 `b4` 每次请求都不同，而同一请求的两次调用会共享密钥流（本轮实测：同请求两对 K 前缀一致；不同请求 0–1.4%）。

**排除项（本轮新增）**
- `libjdg` 虽然导入了 `rand`/`random`/`srand`，但签名路径**一次都没调用**（`srand`/`rand` GOT 钩子 40 秒内 0 命中），所以密钥流不是 libc 随机数。
- 库里没有任何教科书 PRNG 常数（Java LCG、MSVC、splitmix64、xorshift*、golden ratio、RC4 初始化表）——只有 SHA-256 的 K 表。
- 对 `SHA256 / SHA1 / MD5 / HMAC-SHA256` × `{请求, 请求+e5, 请求+e4, 请求+eid, 请求+appKey, 请求+e2}` × `{前缀, 后缀, counter0}` 共 53 种构造，**全部不匹配**。

**卡点**：密钥流是 libjdg 自定义 VM 里的 PRG，种子至少包含请求内容与某个设备侧秘密（`e5` 稳定、`e4` 稳定，都没有直接作为密钥出现）。要再进一步，需要的不是猜公式，而是**能在 VM 内部落脚的观测手段**（见下）。

**插件改动**：`AdhJavaHookBridge.MAX_ARG_BYTES` 64 → 2048（协议分析时 `byte[]` 往往就是签名输入/请求体，截断后无法哈希或重放；单次事件变大是可控代价）。

## 2026-10-22（第三轮）—— `b4` 的结构定死了：流式异或，不是块加密

**结论（真机采样 + 离线复算）**

```
b4 = base64( 1 字节前缀 ‖ ( zlib_compress(fingerprint JSON) ⊕ keystream ) )
```

`b4` 解出来 295 字节 = 1 字节前缀 + 294 字节载荷；载荷与 `zlib(JSON)` 等长，逐字节满足 `C[1+i] = D[i] ⊕ K[i]`。

**证据**
- 同一签名操作内的两次事件（`tid=4156` 与 `tid=3919`，同批次）各自独立恢复出的密钥流 **291/294 字节一致（99.0%）**；其余任意两两只有 **0.0%–1.4%**。一个错误的模型不可能给出 99% 的一致。
- 3 个不一致字节来自本地 zlib 与目标实现（Android zlib）压缩输出的微小差异，不是密钥流。
- 排除项：**不是 AES-CBC/ECB**——同一操作内明文只差 4 字节（e3 时间戳），密文只差 6 字节且位置保持（216..221），没有任何雪崩；**也不是纯 deflate**（逐字节比对 0/295 命中）；**也不是固定密钥流**（跨操作 0% 一致）。

**顺带纠正两个前几轮的误判**
- `e4`、`e5` 不是 nonce：6 次调用（跨约 90 秒）**完全不变**，是装机/会话常量。
- 按时间戳把 `NATIVE_HOOK_MEM`(compress) 和 `JAVA_HOOK`(genSign) 配对会错——同一个毫秒里会有 2 个并发签名，必须按 **tid** 配对。这也是本轮的采样方法学教训。

**仍未知**：`keystream` 怎么派生。同一时刻的调用共享它，跨 30 秒就完全不同，说明它按"操作/时间窗"生成，且不来自 `e4`/`e5`/`e3` 的简单哈希（对 `SHA256/MD5(e3/e4/e5/e1/e2/组合)` 与计数器模式都试过，全部不匹配）。剩下的是 libjdg 自定义 VM 里的 PRG，静态侧只有 `JNI_OnLoad` 可以落脚。

**本轮没有改插件代码**；代价最大的一步是配对方法，已被 `tid` 解决（`live_captures` 记录本来就带 `tid`，不需要改工具）。

## 2026-10-22（第二轮）—— 把 JDGuard 的门面挖开，并补上两个真缺口

**新拿到的（都在真机 `aa165071` 上验过）**
- `Bridge` 就是 JDGuard 的 Java 门面：`com.jd.security.jdguard.core.Bridge`。它只暴露 `static native Object[] main(int, Object[])` 和一层 `entry(int, Object[])`，其余是 `getAppKey/getJDGVN/androidId/getBizNum/setContext/...`。
- **`b1` 不是设备 UUID，是 JDGuard 的 appKey**：`Bridge.getAppKey()` 返回的就是 jdgs 里那个值；`b2 = getJDGVN()+"_0"`（`3.6.5_0`），`b3` 固定 `3.0`，`b7` 毫秒时间戳。`Bridge.androidId()` = 请求 body 里出现的那个 16 hex。
- **签名输入全看到了**：hook `Bridge.entry`（`stack:true`）拿到 `opcode=101` 和完整参数数组：

  ```
  [ byte[1727] "POST /client.action <md5(body)>…", "<设备占位串>", <eid>, "1.0", <e5>, <nonce-uuid>, null ]
  ret = [ "{\"b1\"…\"b4\"…\"b5\"…}" ]
  ```

  也就是说 **b4 的输入 = 请求行 + body 摘要 + 设备字段 + e5 + 每次不同的 nonce**，native 负责拼 JSON、zlib 压缩、二次变换、Base64。配合上一轮抓到的压缩前明文，整条链的边界已经闭合，只剩那 296 字节的变换在 libjdg 的 VM 里。

**插件改动**
- **`java_call` 支持数组**（agent `runtime/java_enum.cpp`）：`T[]` 参数按 JSON 数组逐元素编组，`byte[]` 参数按 JSON 字符串的 UTF-8 字节编组；参数类型名同时接受 `java.lang.Object[]` 和 `Class.getName()` 的 `[Ljava.lang.Object;` 描述符形式。没有它，`main(int, Object[])` 这类分发器根本调不动（这正是"把签名器变成可查询 oracle"的前提）。实测 `String.format("%s-%s", ["a","b"])` → `a-b`。
- **`memory_disasm` 的"零页"失败修掉**：`capstone-wasm` 在**一条指令都解不出来**时抛异常，且把成功码打进文案（`Failed to disassemble, error: OK (CS_ERR_OK)`）。现在返回 `count:0` + `undecodedBytes` + `note`（"不是 AArch64 代码：填充/字面量池/数据"）。真机复验：同一 `module+offset`（`libjdg.so+0x103f80`）从报错变成明确回答。新增 `daemon/test/capstone_disasm.test.ts`（零页 / 0xff / 真指令三种），`npm test` **280/280**。

**撞到的目标侧约束（也是插件的边界）**
- 用 `java_call` 直接调 `Bridge.entry(101, …)` 复现签名：第一次传 `String` 当第一个元素 → 目标在 `GetArrayLength` 上 **abort**（`JNI DETECTED ERROR … not an array: java.lang.String`），说明调用确实进了 `main`；改成 `byte[]` 后再调 → **命令超时、随后进程被杀**。
- 结论：`entry` 依赖真实调用上下文（初始化/线程/Looper 或有效 nonce），**从 agent 的命令线程异地调用会挂死**；而 `java_call` 没有隔离——一个阻塞的目标方法会把整条命令通道一起拖死。这条要写进工具说明（已写 `docs/mcp-tools.md`），下一轮若要 oracle，得先加"调用跑在目标自己的线程 + 超时后可放弃"的机制，或改为**驱动真实请求**再读回参。

## 2026-10-22 —— 真机实战：京东 `jdgs` 逆向（插件能力的第一次"硬目标"体检）

目标 `com.jingdong.app.mall` 16.1.50（`aa165071`，SDK 35，Zygisk 注入）。目的不是"抓到一个参数"，而是**用一次难目标把插件缺什么暴露出来**。

**走通的链路（全部通过 ADH，没有 Frida/手工 IDA）**
1. `scope.json` 加包 → 重启 App → agent 自动注入（`s_xxxx` 在线）；`triage` 一把过（2690 regions / 11 dex / 19 个 TLS hook）。
2. **抓包**：`capture_start` 自动锁定 `libjavacrypto.so`，`SSL_write/SSL_read` 明文直出；`http_exchanges` 拼出完整请求。`jdgs` 是**请求头里的 JSON**：`{"b1","b2","b3","b4","b5","b6","b7"}`。
3. **定位生成点**（静态索引）：`dump_all_dex`（11 dex / 87 MB）→ `dex_index_search` 命中 `HttpSettingTool#doSignUsingJdGuard`、`JDGuardHelper$1#genSign`、`DongSigninHelper#getJDGS`，调用链直接给到 `ParamBuilderFor*#setupParams`。
4. **动态确认**：`java_hook genSign(URI,byte[],String,String,boolean)` + `stack:true`，返回 Map 就是 `{jdgs={...}}`——`jdgs` 为**每个签名请求**生成，不止登录 SDK。
5. **拿明文**：`libjdg.so` 无 EVP/AES 常量（`native_crypto_const` 只报 SHA-256/MD5/SHA-1/Base64），改用 `native_hook mode=got module=libjdg.so symbol=compress`（zlib 的 `compress(dest,destLen,src,srcLen)`），`mem:"x2:192,x2+192:192"` 两次窗口拼回**压缩前 371 字节明文**（`x3=0x173` 对得上）：`{"e1":<eid>,"e2":"1.0§§0§§<pkg>|<32hex>|<ver>§§-…§§32","e3":<ms>,"e5":<33B>,"e4":<uuid>}`。
6. **静态补证**：`native_analyze` 显示 `libjdg.so` 只导出 `JNI_OnLoad`；`native_disasm symbol=JNI_OnLoad` 找到唯一的 `RegisterNatives` 调用 → 方法表 `vaddr 0x159118` → `memory_read` 读出 `{name:"main", sig:"(I[Ljava/lang/Object;)[Ljava/lang/Object;", fnPtr}`。即**整套 native 只有一个 opcode 分发入口**，且 libjdg 内部是自定义 VM/解释器（这也是为什么标准常量扫描看不见它的密码学）。

**结论边界（不吹）**：`b4` = 371 字节 JSON → zlib `compress`（本地同输入算出 293 B）→ 二次变换（296 B）→ Base64。二次变换**不是**标准 AES/ChaCha/zlib：`crypto_variant_scan` 无 AES 结构，`e5` 也不是标准 Base64。它在 libjdg 的 VM 里，本轮**未还原**；`b5/b6` 是标准 SHA-256（64 hex）但哈希输入未定。已确认的字段语义：`b1` 设备 UUID、`b2` JDGuard 版本、`b3` 协议版本、`b7` 时间戳、`e3` 时间戳、`e4` 每次不同的 nonce。

**插件改动（本轮）**
- `agent/java/.../AdhJavaHookBridge.java`：Java hook 事件原来只渲染 `args[0]` 且对象一律 `类名@hash`。改为**全参数 + 类型感知**：`byte[]` → 前 64 字节 hex + 真实长度、`URI/URL/CharSequence` → 字符串、`Map/Collection/JSON` → `toString`、原生数组 → 紧凑展开；单参数保持旧格式（兼容 `lastArg` 断言）。实测 `genSign` 一次事件即给出完整 URI、body hex、content-type、method。
- 撤销一个**危险特性**：曾加过 `settings.startup.jni`（hello 阶段预装 `jni_hook`），真机上 5 分钟内让京东 **SIGILL**（`ILL_ILLOPC`，页边界）并出现 **ART ConcurrentCopying GC 空指针**；根因是对 `libart.so` 的 `RegisterNatives` 做 inline patch，包装函数本身没问题（晚装 40s 存活、hits=0）。已从启动策略移除并写进 `CASE_STUDIES`，`jni_hook` 保持手动命令。
- 回归：`tsc` 0 错、`npm test` **277/277**。**未跑** `verify_all.sh`（本轮无该必要，且 device 全量=82 条冷启）。

**下一轮该补的（按性价比排）**
1. `native_hook` 缺**调用后内存**：拿 `compress` 的输出只能靠"下一次调用前抓 x0"，实测是 0。应加 `memAfter:"x0:293"`（原函数返回后复制），这是"输出侧"的通用缺口。
2. `memory_disasm` 的 `module+offset` 路径直接失败且错误文案自相矛盾（`Failed to disassemble, error: OK (CS_ERR_OK)`）；本轮只能先用 maps 算绝对地址绕过。另：`memory_read` 对代码页偶发返回全 0（同地址换 `via` 仍 0），需要判"读不到"而不是"内容就是 0"。
3. `native_analyze` 的 `strings` 对 1.6 MB 的库回吐 ~19 MB（一次就把上下文打爆），需要分页/过滤/长度截断。
4. `live_captures` **不按 session/package 过滤**，多目标时沙盒的 `ADH_LIVE_*` 与目标混在一条流里（`http_exchanges` 有 `package`，`live_captures` 没有）。
5. `dex_method_code` 只给 bytecode 十六进制，没有 Dalvik 反汇编 → 静态读 Java 逻辑仍然要人肉。
6. 建议把本轮手工做的 **JNI 注册表静态还原** 固化成工具（`jni_table`）：解析 `JNI_OnLoad` → 找 `RegisterNatives` → 读 `JNINativeMethod[]`，全程不碰目标运行时——这才是"库只导出 JNI_OnLoad"的安全解法。

## 2026-10-21 —— `verify_pick.mjs`：别为了一次改动跑 121 条

用户点名的问题：验收脚本不可全信，而 AI 为了稳妥会把 121 条（39 host + 82 device）全跑一遍，既费时间也费 token——device 每条都要冷启一次沙盒，其中 9 条还会重装 APK。

- 新增 `tools/verify_pick.mjs`：按 `git status` 的改动反查候选。默认**只打印、只列 host**；`--device` 才列真机脚本，`--run` 才执行。强规则（改了 `daemon/` → v71+v87）+ 文件名 token 反查（`native_hooks.cpp` → `native_hook`），并有**文档频率过滤**（出现在 >1/4 脚本里的词自动剔除，`agent`/`package`/`memory` 这类不再制造噪声）。
- 已知抖动（`v72`/`v22_capture`/`v08_xref`/`v01`）标 ⚠：同一条最多复跑一次。
- 规则写进 `AGENTS.md` / `CLAUDE.md`（同步）与 `tools/MAP.md`：纯文档改动只跑 `tsc + npm test`；全量只在发版/刷机/用户明确要求时跑一次；**脚本断言也是代码，失败先读断言，别默认产品坏了**。
- 实测：`daemon/` 改动 → 2 条 host；`native_hooks.cpp` → 2 host + 10 device 候选；纯文档 → "没有定向规则" + 最便宜的确认命令。


## 2026-10-21 —— 冷启动前置布防（host 侧，无 Zygisk 也能抢时间窗）

**做了什么**：`settings.startup` 启动策略。会话 hello 到达时、capture loop 启动**之前**，daemon 按策略自动装中和器；`session.startupHooks` 带 hookIds，`/api/agents` 和 `capabilities` 都看得到。开关：`startup.antiDebug` + `startup.packages`（空=全部）+ `ADH_AUTO_ANTIDEBUG=1/0` 覆盖。MCP 新增 `settings`（get/patch），AI 不用切 REST 就能配。

**真机验收（`aa165071`）**
- 开启策略（只限 `com.adh.sandbox`）→ 重启沙盒（**不发任何命令**）→ `startupHooks={"hookIds":[1],"failed":[]}`；`ptrace` 由 `-1` 变 **0**；`access` 仍 `ENOENT`；进程存活。
- 关闭策略 → 重启 → 无 `startupHooks`，`ptrace` 恢复 `-1`。

**撞出来的关键事实（已写进默认值）**：第一版启动计划是 ptrace + access + faccessat 三个。真机上**3 个钩子装完后约 0.5 秒沙盒死亡**——在初始化阶段把 `access`/`faccessat` 全部改成 EACCES，App 自己的路径检查也被打断了。所以启动期默认只装 **ptrace**（TRACEME 返回 0 无害），`access`/`faccessat` 改为 opt-in（`extraTargets`）或等启动完成后再用 `recipe anti_debug`。这是"更早"和"更安全"的边界，不是实现缺陷。

**顺带修掉的测试基建问题**：并行全量仍会随机红（每次不同文件、~2.7s、测试数变少）。根因是**每个测试进程都在写同一个 `adhd-data/`**，Windows 上第二个写者让第一个报共享冲突。现在 `ADH_SKIP_ARTIFACT_LOAD=1` 同时把 `CAPTURES`/`DATA_DIR` 指到按 pid 隔离的临时目录。**连跑 4 次 274/274**（新加 3 条 startup 策略单测后 275）。

**延迟加宽（同日追加）**：`startup.widenAfterMs` + `widenTargets`。启动期只装 ptrace；等 `widenAfterMs` 毫秒后（unref 定时器、每会话一次）自动补 `access`/`faccessat`，App 已初始化完，不会打断它自己的路径检查。真机：hello 时 `hookIds=[1]`、`access` → `ENOENT`；5 秒后 `hookIds=[1,2,3]`、`widenedAt` 有值、`access` → `EACCES`、`ptrace` → `0`、进程存活。单测 **277** 条。


## 2026-10-21 —— recipes 扩到 5 个 + 测试不再依赖开发机工件

**recipes**（host 编排，agent 不变）
- `triage` 现在在采集窗口里**同时开 `module_watch`**，窗口结束 drain 一次再读，summary 多出 `modulesLoaded`（运行中才出现的库）。
- 新增 `http_capture`：布防 TLS →（可选）调用方给一个 Java 触发器 → 等 → drain → **把明文拼成整条 HTTP 请求**，返回 method/path/host/status 样本。0 记录时 summary 明确写"QUIC 或私有 TLS 栈的常见结果"，不让空列表读成"这个 App 没发请求"。
- 新增 `anti_debug`：不带 `confirm:true` 只返回计划；带上则一次装好 `ptrace`（返回 0）、`access`/`faccessat`（返回 -1 + `EACCES`），返回 hookIds；`undoHookIds` 一次卸掉。**返回值与 errno 成对中和**。

**真机验收（`aa165071`，agent `20c5d307…`）**
- `anti_debug` 应用后：`Os.access("/nope")` 由 `ENOENT` 变 `EACCES`；`ptrace` 由 `-1` 变 `0`；`undoHookIds:[1,2,3]` 后两者**逐字恢复**。
- `http_capture`：4 步 ok，records 0 + hint（沙盒没有 TLS 流量，如实说明）。
- `triage`：11 步全 ok（含 module_watch start/stop），crypto 14。

**测试基建（修的是"门禁靠运气"）**
- 并行跑全量时 `syscall_digest.test.ts` 偶发红（约 1/3），单跑 15/15。根因：每个测试进程在 import 时扫描开发机 `captures/` 约 **1.2 GiB**，十几个进程并发读盘。
- 修法：`state.ts` 支持 `ADH_SKIP_ARTIFACT_LOAD=1` 跳过启动期工件采纳；`npm test` 改走 `test/run.mjs`（先设环境再 spawn `node --test`，`stdio:inherit`）。测试从此**不依赖开发机数据**，也快了一个数量级。**连跑 3 次 271/271**。

**没做**：Zygisk 预置 responder —— 本机 Git Bash 起不来，`build_zygisk.sh` / `flash_device.sh` 无法执行，改了也刷不进、验不了。留给能跑那两个脚本的机器。


## 2026-10-21 —— 加载期可见 + errno 中和 + recipes（"一句话"入口）

同一方向的第二片：**看得见运行中才出现的东西**、**能中和成对的检查**、**把多步编排收成一个调用**。

**agent**
- **`module_watch`**：dlopen watch 从"只服务 JNI_OnLoad、只挂一个入口"改成**两个入口都挂**（`dlopen` 与 `android_dlopen_ext`/`__loader_` 别名，各自保留 trampoline），并按需广播 `MODULE_LOAD` 事件（path/handle/base/size）。踩过的坑：只挂第一个解析到的入口时，agent 自己的 `load_so`（走 `dlopen`）完全不触发，事件是空的——两槽修复后真机抓到 `liblog.so`（base/size 正确）。
- **`native_hook` 新增 `errno`**：命中线程上写 errno（throttled 命中同样生效）。和 `skipOriginal`+`returnValue` 配对使用，才能中和"返回值和 errno 一起看"的检查（`access`/`faccessat`）。用 `errno = v` 而不是 `__errno_location()`——后者在 API 26 的 bionic 里没有符号。
- **`java_call` 报 cause**：原来只回 `java.lang.reflect.InvocationTargetException`，AI 拿不到任何可操作信息；现在解包到 cause。这条同时是 errno 的观测器。

**host**
- **`recipes.ts`**：`triage` / `capture_window` / `unpack`。每步报 `ok/ms/error`，一步失败不中断其余；步骤只回小摘要。MCP `recipe` + REST `/api/recipes`、`/api/recipes/run`。
- `module_watch` MCP/REST（`start|stop|status|list`）；`MODULE_LOAD` 归到 `system` 分类，现有视图直接可见。
- `service.ts` 的 `moduleLoads()` 把 MODULE_LOAD 记录解回结构化对象。

**真机验收（`aa165071`，agent sha `20c5d307…`）**
- `module_watch start` → `load_library /system/lib64/liblog.so` → `list` 得到 `{path, handle, base, size:69632, mapped:true}`。
- **errno**：`android.system.Os.access("/nope")` 基线报 `ErrnoException: ENOENT (No such file or directory)`；挂 `access`（`skipOriginal:true, returnValue:-1, errno:13`）后同一调用报 `EACCES (Permission denied)`；卸钩后恢复。这是"返回值+errno 成对中和"第一次被端到端证明。
- **recipes**：`triage` 7 步全 ok（2579 regions、9 条 crypto、topAlgos 有 AES-CBC/CTR/GCM 等）；`capture_window` 带 `JavaCrypto.run` 触发器 → crypto 9 → 14，trigger 步 5ms；REST 同实现同结果。
- MCP 工具 76 个；单测 **271** 条（+agent_caps 3、recipes 3）。

**没做**：Zygisk 预置 responder（要在 `injector/zygisk` 里把策略随 companion 下发，且本机 Git Bash 起不来、无法构建/刷入模块——留给能跑 `build_zygisk.sh`/`flash_device.sh` 的机器）。


## 2026-10-21 —— AI 可自描述 + 能改运行时状态（write / 命中写指针 / caps）

方向：把判断交给 AI，agent 只提供安全、通用、可自纠的原语。本轮补上两样它没有的东西——**写**，和**知道自己能做什么**。

**agent 新增**
- **`write` 命令**（1..4096 字节，`addr`/`hex`/`force`）：`force:true` 才可改只读页，改完立刻恢复原保护、代码页刷 I-cache、回吐被替换字节。地址不在映射内、跨映射、hex 非法一律拒绝，不写前缀。`parse_mem_addr` 同时接受 `0x…` 与裸 hex，并拒绝部分解析（`0x1234zz` 以前会读成 `0x1234`）。
- **命中时写指针参数**：`native_hook` 新增 `writeReg`/`writeOff`/`writeHex`，在命中线程、原函数运行前、寄存器改写之前写入 `*(xN+off)`，且**只写已可写映射**（`adh_mem_write_checked`，绝不 fault 目标）。事件带 `write:{reg,offset,len,ok}`，status 带规格（`x0+0:8`）。这是让出参型反调试可伪造的那一步：`__system_property_get(name, buf)`、调用方传进来的 key 缓冲区。
- **`caps` 帧**：hello 之后立即上报 34 个 op + limits（hookSlots/memWindows/writeMax/frameMax）。`ADH_AGENT_OPS` 与 `strcmp` 派发是两份手写清单，新增 `daemon/test/agent_caps.test.ts` 解析两边源码做契约测试——加 op 忘了另一边会红。

**host 新增**
- MCP `capabilities`（读 agent 自己的 caps，不读文档）、`memory_write`、`memory_restore`（host 记住被替换字节，按地址一键回滚，每会话上限 64 条）。
- REST `/api/capabilities`、`/api/memory/write`、`/api/memory/restore`，与 MCP **共用同一实现**。
- `AgentSession.caps` + `agent CAPS` 日志/广播。

**真机验收（`aa165071`，agent sha `85e21b93…`，模块与沙盒两条路径同 hash）**
- `capabilities`：34 op，`write` 在列，limits 正确。
- **写→读→还原→再读**：`malloc(64)` 得 `0xb4000074422941c0` → 写 `41424344` → 读回 `QUJDRA==`（"ABCD"）→ restore → 读回原字节 `c0fd3479`。
- **只读代码页**：不带 `force` 被拒并报 `r-xp`；`force:true` 成功（`mprotectUsed:true`），`adh_bt_target` 仍返回 `0x40`。
- **命中写**：hook `adh_mem_window_target`（`writeReg:0`, 8 字节全零）后 `memWindowProbe` 由 **48653 → 65280**（正好等于 8 字节清零后的结果），事件 `"write":{... "ok":true}`，status `write:"x0+0:8"`, `verdict:"fired"`。

**顺带修掉的真 bug（都是这轮验证撞出来的）**
- **带 tag 的堆指针读不了**：Scudo 的堆指针顶字节非零（`0xb4…`），`/proc/self/mem` 的 `off_t` 把它当巨大偏移 → `EINVAL`，所以 `memory_read` 对**任何堆地址**都失败。现在 `adh_mem_pread` / `adh_mem_region_end` / `adh_mem_region_of` 统一 `adh_untag()`（用户态拷贝保留 tag，MTE 下仍可用）。
- `cmd_read` 声称支持 `0x…`，实际 `strtoull(...,16)` 遇到 `0x` 直接解析成 0；与 `write` 统一走 `parse_mem_addr`。

**没做**：`setErrno`（`access` 这类只看 errno 的检查还伪造不了）、`MODULE_LOAD` 广播、Zygisk 预置 responder 策略；`write` 的 4096 字节单次上限没有提高（大块 patch 需多次调用，host 侧可循环）。


## 2026-10-21 —— 证据链补强：类型检查 + CI + 门禁修复 + 两个真机 bug

审计的结论是"门禁全绿是手工产物"。本轮把其中可机检的部分补上，并修掉审计抓到的缺陷。

**新增**
- `daemon/tsconfig.json` + `npm run typecheck`（`tsc --noEmit`，先 `strict:false`）。第一次跑出 47 个错，其中 **4 个是调用即 `ReferenceError` 的真 bug**：`mcp.ts` 缺 `flowCorrelate` / `asciiOf` / `b64Of` 的 import（`flow_correlate` 与 `live_captures encoding:"b64"` 一调就炸）、`routes_system.ts` 缺 `hexToPreview`。真机复验：`flow_correlate` 正常返回 correlations/reason；`live_captures` b64 拿回 `ADH_CRYPTO_PLAINTEXT_v1` 的 base64。
- `.github/workflows/host.yml`：`npm ci` → typecheck → `npm test` → `bash tools/verify_v87_mcp_operability.sh`。此前仓库**没有 CI**，红测试就是这样签进 v0.4.0 的。
- `npm test` 改为 `node --test "test/*.test.ts"`：目录形式会把 `test/smoke.ts` 当测试跑并失败。

**修复**
- `verify_v87` 红线门禁：`walkSrc` 对 daemon 树（100% TS）也套 `.c/.cpp/.h` 过滤，**daemon 半边永远扫 0 个文件**。v0.4.0 因此把 `com.adh.sandbox` 加回 `scope_list.ts:195` 而门禁仍绿。现在每棵树声明自己的扩展名，并加"扫到 <40 文件即失败"的下限。**负对照**：往 `daemon/src` 植入一行 `com.adh.sandbox` → `hits=1` 且点名文件；移除 → `scanned=100, hits=0`。
- 目标耦合改按注入方式判定：`autoArmAllowed(pkg, entry, scope)`，`entry === 'jni_onload'`（self-load / 沙盒）总是允许布防，Zygisk 仍要求 scope.json；`SANDBOX_PKG` 常量删除。真机：沙盒会话 `entry=jni_onload` 自动布防，`captureHooks.on=true`、evp/digest/hmac=1/1/1。
- `agent_main.c`：`jni_env_hook` 的非法 `setValue` 分支原来 `return;` 出 `command_loop`，会关掉 agent 唯一的控制连接，agent 重连成**新 session**。真机 A/B：旧 agent 发 `setValue:"abc"` → `s_2piq` 掉线、新 `s_32v5` 出现；新 agent（sha `1ab114f8…`，已换入模块与沙盒两条路径）同一操作 → 报 `ok:false` 且 `s_4v9h` 全程在线（前后 ping ≈7ms）。
- `readBody` 加上限（8MB）：原来无上限、且按块独立解码（多字节字符跨块会变 U+FFFD）。9MB POST 现在返回 **413**、daemon 存活，不再是连接重置。

**数据修正（以运行时为准）**：`/health` 报 `mcpTools: 71`（文档写 65/67/69）；`verify_all.sh` 实际登记 **121** 条（39 host + 82 device，文档写 118/117）；单测 **265** 条（文档写 180）。

**没做**：Git Bash 在本机起不来（MSYS `NtCreateDirectoryObject` 被拒），`tools/*.sh` 未执行；CI 尚未在 GitHub 真跑；全量设备门禁没跑（只做了针对性真机验证）。

## 2026-10-21 —— 协议分析必须先核验

中国移动主进程（已登录）窗口里带两个签名头的 16 条请求，用 `EVP_DigestUpdate` 原文重算后与头一致，0 条不符。另一接口 3 条 body 用捕获到的 AES-128-CBC 密钥解开，明文再加密与 body 逐字节相同。短信登录不在这批交换里；业务大 body 21 条、响应 body 26 条用已看到的密钥解不开。采集环 `complete:false`，结论只覆盖还留在列表里的 37 条。`AGENTS.md` / `CLAUDE.md` 增加「协议分析」：能对上的公式先对上，写出对上几条，没看到的跳单独写明。案例记在 `docs/CASE_STUDIES.md` 案例 3。密钥和明文不进仓库。

## 2026-10-21 —— 原生观察收成一条结果

`native_look` 是看一个原生函数时的正门。`arm` 在函数门口等着（默认 `mem: auto`），`read` 把同一次命中的寄存器和抄到的内存收成一条 `text`，`stop` 默认软卸，这个地址还能再挂。零件 `native_hook` / `NATIVE_HOOK` / `NATIVE_HOOK_MEM` 还在下面。主机门禁 `verify_v108_native_look.sh` 已通过。`aa165071` 沙盒上 `arm` → `memWindowProbe` → `read` 的 `text` 含 `x0 64字节 ADHMEM01`，软卸之后这个函数还可以再挂。总图改成现在在跑的三层：浏览器只读，任务走 MCP，agent 经 TCP 8761 连上来，反汇编留在主机。Host Daemon 已用这份代码重启。

## 2026-10-21 —— 内存窗改成不用先猜寄存器

上一刀的 `mem` 要调用方自己写成 `x0:64`，抓到的字节又落在「加解密」里、标题是 `NATIVE_HOOK_MEM`。那是验收能过的形状，拿去拆目标时用不上。现在 `mem` 可以写 `auto`：命中时从 x0–x8 里挑读得动的指针，每个抄 64 字节，最多 4 个，整数跳过。列表归到「系统」，标题是「函数参数 / 入口内容」，预览是抄到的文本。显式 `x0:64` 仍可用。`aa165071` 上沙盒 `memWindowProbe` 用 `auto` 命中，预览是 `x0 64字节 ADHMEM01...`，函数返回值仍是 48653。抄的仍是进门时的内容；函数跑完写回去的结果还要另做返回时再抄，那一步要改返回地址，改错会把目标进程打死，这次没做。Host Daemon 已用这份代码重启，agent so `9556f89050c304f2` 已换进沙盒和模块目录。已经在跑的其它目标要冷启动才吃到新 so。

## 2026-10-21 —— native hook 命中当时的内存窗

强防护目标上，指针指向的缓冲区经常在函数返回前就被复用，事后 `memory_read` 读到的是下一轮。`native_hook` 增加可选 `mem`（`x0:64` 或 `x0+16:32,x2:8`，寄存器只允许 x0–x8，最多 4 窗、每窗 192 字节、合计 512、偏移 ≤65535）。命中线程在调用原函数之前用 `process_vm_readv` 拷贝（不换 SIGSEGV 处理函数；syscall 被 seccomp 挡住时才退到 `/proc/self/mem`）。字节进单独的 `NATIVE_HOOK_MEM`，用 `seq` 和当条 `NATIVE_HOOK` 配对。坏地址记 `unreadable`，不把进程打死。被 `throttleMs` 压掉的命中不拷。坏规格在主机和 agent 两边都拒绝安装。Capstone 仍在主机；QBDI 不进这次改动。

主机门禁 `tools/verify_v106_native_mem_window.sh` 已通过。真机 `aa165071` 上 `tools/verify_v107_native_mem_window.sh` 已通过：沙盒 `Detection.memWindowProbe` 在 `adh_mem_window_target` 返回前把首字节异或掉，窗口仍是进入时的 `4144484d454d3031`，偏移窗是 `31`；`adh_add_target` 的 x0 是整数 20，窗口报 `unreadable`，`siteProbe` 仍返回 84，进程还在。沙盒 APK 已 `pm install -r`，agent so 已换进沙盒和模块目录（`b21e3d6cffdbc958`）。已经在跑的其它目标要冷启动才吃到新 so。Host Daemon 已用这份代码重启。

## 2026-10-21 —— v0.4.1 刷入

首页状态条重组随 **v0.4.1 / versionCode 24** 刷入 `aa165071` 并已重启（Manager、模块、`update.json`、`AGENT_VER` 同号；Device Daemon 仍为 versionCode 11）。重启后 `zygisk_loaded=YES`，`device_daemon_ready=YES`，模块描述为「运行中」。公开 Release 的 zip 还没上传。

## 2026-10-21 —— 首页状态条重组

状态图标改成圆形徽章，标题下加一行原因（模块版本 / 设备服务未连接 / 加载器未激活 / 模块未安装）。语言切换在说明行右侧，是一条等宽胶囊，用固定的中性色，不再跟着异常色走。刷新与标题同一行。首页卡片与顶栏底角统一为 16 dp。

## 2026-10-21 —— 首页状态放大、动画、中英文

首页状态仍是一条横栏，标题用 headlineSmall。进首页时整条淡入上移一次，然后停住。中英文切换留在标题右侧。调试版已装到 `aa165071`。

## 2026-10-21 —— Manager 底部三页

Manager 改成底部 Tab：**首页**（运行状态、模块/应用版本、型号、Android、架构、对照公开 `update.json` 是否有更新、Web UI）、**应用**（注入范围）、**证书**。Hook 配置仍从应用行进入，盖住底栏。勾选仍当场写入，应用页不再放单独的保存按钮。调试版已装到 `aa165071`。

## 2026-10-21 —— Manager Hook 配置按功能分页

Hook 配置从一列开关改成三页：**加解密**（摘要 / HMAC / 对称 / 非对称 / AEAD）、**系统抓包**（TLS 明文）、**系统检测**（反调试 / root / 属性）。页上不放说明段落，只留 tab 和开关。右上角是应用名和包名，点一下复制包名；没有「恢复默认」。开关仍是同一份 `CaptureFamilies`，关掉的族下次注入不装。未改策略协议。调试版 Manager 已 `pm install -r` 到 `aa165071`。

## 2026-10-20 —— v0.4.0 发版

**v0.4.0 / versionCode 23**（Manager 同号；Device Daemon 11；`AGENT_VER` `0.4.0`）。本版相对 v0.3.15：一键脱壳产品化（冷启/全进程/边抠边显/一次一条记录）、脱壳期抑制本包装钩、Frida 退出产品面、捕获按包落盘与自动布防、系统检测 Manager 开关、Web UX 收短。产物 `adh-bundle-v0.4.0.zip`；`update.json` 指向公开 Release。

## 2026-10-20 —— 脱壳记录改成「一次一条」

脱壳历史不再把 zip + 每个 DEX 平铺：列表只显示每次脱壳一条，点进去看全部 DEX 并可「下载全部」。系统检测摘要收成「未开 / 已开 · 暂无 / 已开 · 计数」，去掉长篇说明。

## 2026-10-20 —— 产品 UX：脱壳/捕获诚实提示

扫出的 P0/P1 已落地一批：脱壳指引改为「重启 App」；「暂停刷新」；清空本页确认；顶栏本包未装钩；unpack protect；CLI/MCP 对齐一键脱壳。文案已再次收短。

## 2026-10-20 —— 系统检测：白话摘要 + Manager 开关

Web「系统」页检测摘要改成普通人能懂的中文（未开启 / 已开启暂无发现 / 计数），不再提 `sysModule`、GOT、`detect_modules`。Manager 每个应用的 Hook 配置新增「系统检测」（policy `y`，**默认关**）；打开后 agent 才装 ptrace/access/属性类钩子，Host 开捕时若全局 `sysModule` 为空则对该包跑 `detect_modules` 自动选库。关掉则强制不装。需重编 agent + Zygisk + Manager 后冷启动目标才生效。

## 2026-10-20 —— 一键脱壳：加固目标防闪退

学习通（SecNeo）实测：冷启动 HELLO 后自动 `capture_start` 装 GOT 钩 → ~1.5s 内进程自杀，脱壳根本没跑到。修复：unpack 全程 `suppressCaptureArmForUnpack`（hello 不布防、不 autoDump）；已有在线 session 时默认 reuse、不强杀；settle 提到 4s。脱壳结束后也不自动回布防。

## 2026-10-20 —— 一键脱壳边抠边显

每个 DEX 保存后立刻写入 `adhd-data/packages/<pkg>/unpack/<runId>/dex/…`，并经 WS `unpack.dex` 推到网页左侧记录（可下载）；跑完再写 `bundle.zip` + `unpack.done`。体感对齐 Frida dex dump 逐条刷出。

## 2026-10-20 —— 一键脱壳：自动冷启动 + 扫全进程

`POST /api/unpack/run`：adb `force-stop` → 打开 LAUNCHER → 等 agent 上线并短暂 settle → 对该包每个在线 session dump DEX → SHA 去重打 zip。用户不用先手动开 App。`launch:false` 可跳过启动（调试用）。

## 2026-10-20 —— 一键脱壳扫全包所有在线进程

不再让人手点主进程 / `:pushservice`。`POST /api/unpack/run` 收 `package`，对该包每个在线 session 跑 dump，按 SHA 去重，打进同一个 zip（`dex/main/`、`dex/pushservice/`… + manifest）。Dump 页去掉进程切换条。

## 2026-10-20 —— Frida Gadget 退出产品面

注入后端页去掉 Frida 缓存/加载命令；`/api/backends` 与 MCP `backends` 不再返回 `gadget`；`classifySession` 不再标 `frida_gadget`。`verify_all` 不再跑 `verify_v30_fridagadget`。官方路径只剩 Zygisk + 模拟注入。历史脚本可留在 `tools/`，不当交付入口。

## 2026-10-20 —— 网络列表不再单列 TLS 控制帧

`#528` 这种 17 字节的 `SSL_read` 是 HTTP/2 GOAWAY，不是请求。网络列表只留已经配成对的 HTTP 请求和响应。拼不成请求的 TLS 记录（控制帧、没有连接号）记一笔略过，不再各占一行。agent 侧同样不把「整段都是 SETTINGS / PING / GOAWAY / WINDOW_UPDATE / PRIORITY / RST_STREAM」的明文写入捕获环；带前言、HEADERS 或 DATA 的仍记。这一版 so 还没换进正在跑的进程。

## 2026-10-20 —— Dump 页改成一键脱壳打包

不再把「枚举 DEX 再逐个点」当主交互。`POST /api/unpack/run`：对在线进程跑完整 dump → 把成功保存的 DEX 打成 zip（`dex/*` + `manifest.json`），写入 captures，tag=`unpack-bundle`。网页左侧是脱壳记录（可下载），右侧是已加载 SO / 包内·私有目录 SO。包内目录含 `lib/`、`files/` 与 maps 里已映射路径的父目录。

## 2026-10-20 —— v0.4.0：真源 + 自动布防 + 门禁瘦身

- **捕获真源**：按包 `adhd-data/packages/<pkg>/captures.jsonl`；启动回放；每包 retain；maxAgeDays（默认 14）；按包清空/导出 jsonl；磁盘统计 API。
- **自动布防**：scope 内（或沙盒）进程上线且未强制停 → `armCaptureHooks`（drain→stop→start）；网页开关语义改为强制停/恢复；名单仍只读 `scope.json`。
- **Dump**：进程不在线时仍列出该包已落盘的 DEX/SO。
- **门禁**：`tools/verify_host.sh` / `ADH_VERIFY_MODE=host` 只跑 host 子集；全量仍是默认 `verify_all`。
- **清理**：Zygisk 去掉死字段 `b=`；模块 X/Xposed 历史见 `docs/archive/RETIRED_MODULE_X_AND_XPOSED.md`。
- **版本**：v0.4.0 / versionCode 23（Manager 同号；Device Daemon 10）。刷机后生效 companion 与 Manager。

## 2026-10-20 —— 捕获按包落盘（真源）+ 轻量清理

（已并入上条 v0.4.0。）

## 2026-10-20 —— 系统检测捕获补了结果、现代入口和清单

`capture_start` 的 system 钩子以前只记下「调用发生了」：`ptrace` 没有返回值，`access` 没有 mode 和结果，`__system_property_get` 没有读到的值，进程里还有一块没人读的 64 条分类缓冲。现在这五条都是只观察再转发，文本里带返回值、路径或属性值、以及命中时的 `lr`：

- `ptrace`、`access`、`faccessat`、`__system_property_get`、`__system_property_read_callback`
- `sysModule` 可以是逗号分隔的多个模块，最多 8 个，多出来的在回执里标 `sysTruncated`
- Host `GET /api/detect/summary` 和 MCP `detect_summary` 把这些事件收成反调试 / root / 签名 / 模拟器 / 完整性。普通文件打开不进清单；`JAVA_HOOK` / `NATIVE_HOOK` 也不进，除非是 `detect_java` 点名的那几个方法
- `detect_modules` 只在当前包自己的 `.so` 里找上述导入，系统库排除。`detect_java` 必须 `confirm:true` 才会装；`File.exists` 要单独点名

分类在 `daemon/src/detect.ts`，单测 `daemon/test/detect_summary.test.ts`。要在真机上看到新字段，需要重新编译并注入 agent。伪造 `PTRACE_TRACEME` 返回值仍然没有。

## 2026-10-20 —— 网络列表记录完整 HTTP 请求

`SSL_write` / `SSL_read` 仍是一段段明文。HTTP/1.1 按连接拼成一对。HTTP/2 现在在 Host 上按帧拆开、用 HPACK 解掉头块，再按流号把请求和响应配成一条。gzip、deflate、br 照旧在这里解开。二进制正文不再当成 UTF-8 贴出来，详情里给十六进制。还没出现请求的 HTTP/2 连接（只有前言和 SETTINGS）不单独占一行。没有 `conn` 的旧记录仍然拆不开。WebView 和 QUIC 还是不在这条通道上。

## 2026-10-20 —— 加解密列表按算法、大小和钩子显示

加解密列表一行是算法名、方向、输入到输出的字节数，第二行是明文开头和钩子。Java 记录用 `Cipher.getAlgorithm()` 的名字（`SHA-256`、`AES/CBC/PKCS5Padding`），钩子写成 `Cipher.doFinal` 这种。Native 的 `EVP_DigestUpdate` 分不出 MD5 和 SHA-256，行上写「摘要 · 未识别」，旁边是钩子名。有密钥只打标记。输入被截短时大小后面标「截断」。没有输入也没有输出的 init 不进列表。展示逻辑在 `daemon/src/crypto_view.ts`。多次 `Update` 仍然各占一行：记录里没有上下文编号，收成一条会把不同次调用拼在一起。

## 2026-10-20 —— Dump 页的目标与改进计划

Dump 页要做两件事。DEX：壳解密并交给 ART 之后，把正在执行的真实 DEX 脱出来；读不完的内存和壳本身不算脱出来。SO：同一页看清「包目录里有哪些」（磁盘上可能是加密或处理过的）和「哪些已经加载进内存」（导出的是内存映像）。

当前页做不到：标题仍是「一键 Dump 所有 DEX」；左边是已保存文件的 SHA，20 个截断 DEX 和完整文件混在一起，完成行用的是头里的大小；右边只有导出成功的内存 SO，包内文件和「已加载但导不出」的库都看不见。多进程时静默用最后上线的 session。

页面已按这个目标改完（Host + 网页，未改 agent，未刷机）。打开 Dump 清点：左列每个 DexFile 写连续可读长度和头里的大小；右列上「已加载」、下「包内文件」；默认主进程（进程名不含 `:`），其他进程可切换。脱壳只保存读满且类表能走完的 DEX，短读不落盘、行上不给下载。SO 仍按 `p_filesz` 读满才保存。单测 `daemon/test/dump_inventory.test.ts` 通过。网页在进程不在线时显示「没有在跑的进程」。前程无忧 pid 18486 的 agent 从更早一次导出后就不再读 socket（两条到 `8761` 的连接仍停着），这次清点没能在这个进程上跑出来。

## 2026-10-20 —— 勾选和 Hook 开关当场写入注入范围

网页右上角读的是手机上的 `/data/adb/adh/scope.json`。Manager 里的勾选和 Hook 家族开关以前只改内存里的草稿，要点「保存」才写文件；这份文件从 10 月 18 日后再没写过，所以新应用不会出现。现在这两处一改就写入同一份文件。`ScopeWriter` 单测通过。调试版 Manager 已装到 `aa165071`，没有重启、没有刷模块。上次那次勾选没进文件，要在新 Manager 里再勾一次。网页名单几秒内跟上；注入仍然要等目标应用下次打开。

## 2026-10-20 —— 新勾选的应用不用等名字解析完才出现在切换里

网页切换读的是手机上已经保存的 `/data/adb/adh/scope.json`。原先要等每个新包的应用名从 apk 里解出来，这一次 `/api/apps` 才返回，名单会停在旧的几项上。现在包名先进入列表，名字随后补上。读范围文件失败时保留上一份名单。

## 2026-10-20 —— 文件页不看应用在不在跑

沙盒目录在手机上，不在进程里。文件页按包名用 root 列 `/data/data/<包名>` 并读里面的文件，进程退出也能看。路径先限制在这个包的沙盒里，再交给 `adb` + `su`。加解密、系统、网络的已有记录同样不因为「未连接」被藏起来；顶栏只显示在线还是未连接。导出已加载的 DEX / SO 仍然要进程在，因为那些字节在内存里。

## 2026-10-20 —— Dump 页可以导出当前应用已加载的 SO

右边的 SO 列以前只有「已经保存过的 SO」。前程无忧没有存过，所以一直是空的。现在「导出已加载 SO」只取这个包自己目录里已映射的 `.so`（`/data/app/<包名>/lib` 和 `/data/data/<包名>`），系统库和 `libadh_agent.so` 不收。选择逻辑在 `daemon/src/so_select.ts`。

主进程 pid 18486 上实测：39 个里 **7 个保存成功**（`libmmkv.so`、`libreact_render_core.so` 等），页面刷新后右边就是这 7 行。另外 28 个按段的 `p_memsz` 去读，在页边界短读（BSS 尾巴没有映射），4 个内存里没有 ELF 头（`libexec.so`、`libexecmain.so`、`libijm-emulator.so`、`libijmDataEncryption.so`），这 32 个没有落盘。重组改为只要求 `p_filesz` 读全，BSS 留零；文件字节本身读不全仍然失败。导出之后这个进程的 agent 不再应答，文件字节这条路径还没有对这 32 个重跑。

## 2026-10-20 —— Dump 列表按包名找回已保存的文件

Dump 页只显示包名等于当前应用的工件。Host 重启后这些文件被当成没有包名，所以选中任何一个应用都是「暂无」。现在每个工件旁边写一份来源（包名、是否完整）；已经落盘、事件日志里有记录的，启动时补上包名。读不完整的在大小后面标「不完整」。

## 2026-10-20 —— Dump 页左右分列

Dump 页已保存列表分成左右两列：左边 DEX（含 cdex），右边 SO。SO 用工件的 tag 显示文件名。仍只列出包名等于当前应用的工件。

## 2026-10-20 —— 网络页按 SSL 连接把 HTTP/1.1 请求和响应配成一对

`SSL_write` / `SSL_read` 仍是一条条明文，但 agent 在记录上带了 `SSL*`（字段 `conn`）。Host 按会话加这个指针把发送、接收各自拼回去，用 `Content-Length` 或 chunked 拆开，再按顺序配对；gzip、deflate、br 在这里解开。网页网络列表优先显示这一对，点开左边是请求、右边是响应。HTTP/2（客户端前言）和没有连接号的旧记录仍按发送、接收分开。WebView 不走这条通道。配对逻辑在 `daemon/src/http_exchange.ts`，单测 `daemon/test/http_exchange.test.ts`。要在真机上配成对，需要重新编译并注入带 `conn` 的 agent。排空缓冲区按整条 16 KiB 记录扩容，避免同一批里的第二条 TLS 明文被截短。

## 2026-10-20 —— 版本号 v0.3.15

网页按应用切换、网络列表显示 URL，按小补丁升到 **v0.3.15 / versionCode 22**。模块 `version`、Manager `versionName`、`update.json` 一致。公开仓库已发 [v0.3.15](https://github.com/decrypthub/AndroidDecryptHub/releases/tag/v0.3.15)：`adh-bundle-v0.3.15.zip`（20,424,795 B，SHA-256 `d83e60c7a928b37a00bc212e94c31f4580ebc0fba1fcb15b11bd9937c8c9f8a1`），匿名下载 200，`main` 上的 `update.json` 已是这一版。私有仓库工作区没有为此另做提交。

## 2026-10-19 —— 网络列表预览改成 URL

网络页左侧原来把 TLS 明文的开头整段贴出来。请求现在显示 `方法 + URL`（头里有 Host 就是 `https://主机/路径`，没有就只留路径），响应只留状态行。系统页仍然是空的：当前捕获只装了 `libjavacrypto.so` 上的加解密和 TLS，文件模块和系统模块都是空的，Java / Native 方法钩子也不会在注入时自动装，所以文件、ptrace、系统属性进不了「系统」。

## 2026-10-19 —— 切到应用却没有记录：转发断了，捕获也关着

网页名单本身是好的（前程无忧51Job、漫播、抖音）。`aa165071` 上 `adb reverse` 空了，进程里的 agent 连不上本机，所以切换之后一条记录都没有，Dump 和文件浏览也没有可用进程。Host 现在每 15 秒把 `tcp:8761` 和 `tcp:8088` 的 reverse 补上。另外 `adhd-data/settings.json` 里实时捕获是关的，加密模块名还是空的；已打开捕获，模块用回 `libjavacrypto.so`。顶栏每个应用标「在线 / 未连接」，列表为空时说明是没连上还是捕获关着。

## 2026-10-19 —— 顶栏下拉直接切换应用，并显示应用名

右上角不再套一层再选。下拉本身就是注入范围里的应用，一项一个名字（前程无忧51Job、漫播、抖音）和包名，点一下就切。详情单独一个按钮，里面是应用名、包名和进程日志，不再包着切换。名字从各应用 base.apk 的清单读出来，读不到时仍显示包名。

## 2026-10-19 —— 网页右上角就是注入范围里勾选的应用

右上角不再跟「有没有连上、进程还在不在」走。Host 用 adb 读手机上的 `/data/adb/adh/scope.json`，下拉里就是这份勾选名单，顺序与文件一致。当前 `aa165071` 上是 `com.job.android`、`com.uxin.kilaaudio`、`com.ss.android.ugc.aweme`。选中哪个就看哪个的捕获和进程日志，进程没开也能切过去。

## 2026-10-19 —— Java 钩子改为点名安装，沙盒不再在启动时改 ART

沙盒装 Java 钩子时死在 `ClassLinker::LinkCode`：算法钩子给每个重载开一条线程，和 `Class.forName` 叠在一起，跳进没映射的页。现在同一时刻只允许一个安装者，重载在同一条线程上逐个装。注入时不再调用 `adh_java_crypto_arm` / `adh_ssl_bypass_arm`，沙盒也不例外。会话用 `java_hook` 的 `action:crypto` 或 `action:bypass` 再装。`aa165071` 上新 so 换进沙盒后：v43 通过且进程还在；v104 装上 31 个算法钩子，探针 `ok aes=32 gcm=32 hmac=32 digest=32 rsa=256 sign=256`，进程还在；干净进程上 v28、v61、v66 通过。

## 2026-10-19 —— 网页按应用看记录，不按会话

外部界面的切换单位改成包名。选中一个应用后，加解密 / 系统 / 网络里是这个包所有进程留下的捕获；Java / Native hook 命中在「系统」里。进程退出后这条应用还在列表里，标成「已退出」，记录不跟着清。进程日志（连上、退出、Dump）写在应用菜单下面，按包过滤。文件浏览和 Dump 仍要有一个在线进程。应用列表来自已经连上过 Host 的包，外加内存里还留着捕获的包；手机上的注入范围决定谁会被注入，Host 不读那份范围文件。

## 2026-10-19 —— 注入时不再用 LSPlant 改 ART

抖音进程死在 `MarkCompact::UpdateLivenessInfo`，栈上有它自己的 `libnpth`。原因是 agent 一启动就 `adh_ssl_bypass_arm` + `adh_java_crypto_arm`：LSPlant 用 Dobby 改 ART 的 JIT/GC 移动，和 npth、jato 抢同一条回收路径。LSPosed 不会在进进程时做这件事。当天仍让沙盒在启动时装算法钩子；次日沙盒也改成命令安装，见上一条。其它进程只连上 Host，等 `capture_start` 再按名字装 GOT。证书绕过也不再在注入时打开。

## 2026-10-18 —— 抖音请求抓到了，七神头在 HTTP/2 明文里

`aa165071` 上把 `com.ss.android.ugc.aweme` 加回作用域，冷启动后对 `libsscronet.so` 做 `capture_start`。`SSL_write` / `SSL_read` 按符号名装上。这次 38 条发送、167 条接收，记录没有被 2048 字节截断。两条请求的头块解出全部七个签名头：`GET /common`（abtest）和 `POST /aweme/v2/commerce/bff/cold_start`。`crypto_identify` 把这轮记成 TLS 205、AEAD 56、Java MD5 56、SHA-1 44、SHA-256 2、RSA 2，密钥 0。Cronet 这条模块的摘要 / HMAC / EVP 对称钩子没装上（`notInstalled`），七神不是在这里算出来的。进程随后退出，不在了。

## 2026-10-18 —— 抖音 TLS 明文：Cronet 的 SSL_write 不在系统 libssl

`libsscronet.so` 的 `SSL_write` / `SSL_read` 从 `libttboringssl.so` 解析，按系统 `libssl.so` 的地址去对 GOT 对不上。指定单个模块时改为按符号名替换，并调用槽里原来的函数。抓包记录从 2048 字节提到 16384 字节，环仍是 128 条、约 2 MiB：2048 会把 HTTP/2 头块截在签名头之前。`aa165071` 上冷启动抖音能装上这两处钩子，明文是 HTTP/2。进程随后死在抖音自己的 GC 钩子（`libnpth` 插在 ART MarkCompact 里）。作用域里已去掉 `com.ss.android.ugc.aweme`，避免继续注入把应用打进安全模式。

## 2026-10-18 —— 沙盒 Java 算法探针，验证插件能钩住并采集

沙盒加了 `JavaCrypto.javaHookProbe`：AES-CBC 加密再解密、AES-GCM、HmacSHA256、SHA-256、RSA-2048、SHA256withRSA 签名并验签。这些调用指定平台 Provider，不经过沙盒自己的 `ADH-Intercept`。加解密页有「Java 钩子探针」按钮。

`aa165071` 上 `tools/verify_v104_java_hook.sh` 通过：装上 31 个 Java 算法钩子，java 通道抓到上述明文、密钥和 `SHA256withRSA` 的 sign/verify，探针返回 `ok aes=32 gcm=32 hmac=32 digest=32 rsa=256 sign=256`，进程仍在。验签记录原先被标成 `sign`，因为 `initVerify` 里的 `Verify` 大小写对不上，后面的 `verify()` 又沿用了这个操作名。桥接类改为按小写方法名判断，重新生成 dex 并编进 agent 后，验签记录的操作名是 `verify`。

## 2026-10-18 —— Manager 可导入系统 CA

用户导入 PEM 或 DER 后，Device Daemon（协议 v18）只保存带 CA 标记的证书到 `/data/adb/adh/cacerts/<subject_hash_old>.N`。`post-fs-data.sh` 在 zygote 起来之前把它们和现有系统根证书拷进 tmpfs，再 bind 到 Conscrypt APEX 与 `/system/etc/security/cacerts`。没有导入的证书时不挂载。界面里确认后才由 Daemon 重启。`:core:test`、`:daemon:testDebugUnitTest`、`:manager:testDebugUnitTest` 通过。`aa165071` 已刷入 v0.3.14 并重启：模块状态「运行中」，`zygisk_loaded` 与 `device_daemon_ready` 都在。开机日志写的是 `no user certificates`，因为还没有导入证书。ColorOS 文件管理会把 `*/*` 选择器里的 `.pem` 置灰，导入改为按 `application/octet-stream` 打开。新的 Manager 已装到 `aa165071`，不用重启手机。

## 2026-10-17 —— 注入范围：搜索收成图标，列表分已开启 / 全部

注入范围页不再占一整行搜索框。右上角是搜索图标，点开后在顶栏输入，返回即退出。原来那一行是「已开启」和「全部」；已经有勾选时默认停在「已开启」。系统应用过滤只在「全部」里出现。

## 2026-10-17 —— Manager：Hook 配置独立成页，版本收到顶栏

应用列表里的 Hook 配置不再用底部弹层。从某一行进入单独一页，后面加能力有地方放。首页顶部固定三行：`ADH 运行中` / `ADH 运行异常`，下面是模块版本和应用版本。不再重复运行状态，也不写 Zygisk。Web UI 卡片只留在线状态和那一个地址。记住电脑地址仍在打开首页时静默写入，不在卡片上解释。

## 2026-10-17 —— 勾选范围并打开应用后，网页仍显示未连接目标

网页能用局域网打开，但注入进目标的进程一直只拨手机自己的 `127.0.0.1:8761`。没做 `adb reverse` 时它连不回电脑，网页上没有进程、没有日志，只写「未连接目标」。现在：Manager 从 `/health` 拿到电脑地址后，经 Device Daemon 记到 `/data/adb/adh/host.endpoint`（协议 v17，Daemon 自己不扫网）；Zygisk 在启动 agent 前把这个地址交进去。agent 仍先试回环，失败再拨记住的地址。`:core:test` 与 `:manager:testDebugUnitTest` 通过。`aa165071` 已刷入并重启：Manager 把电脑记成 `192.168.200.108:8761`，冷启动已勾选的应用后 Host 上出现在线会话（`entry=start`）。模块打包会在 agent 源码比 `.so` 新时重编，导出表包含 `adh_agent_set_endpoint`。

## 2026-10-16 —— Manager 首页 Web UI 显示局域网地址

手机和电脑在同一 Wi-Fi（`192.168.200.178` / `192.168.200.108`）时，浏览器能直接打开 `http://192.168.200.108:8088`。首页之前只探 `127.0.0.1:8088`；没做 `adb reverse` 就判未连接，卡片退回本机回环地址，手机浏览器打不开电脑。现在：同一网段的地址优先于 VMware / 虚拟网卡；回环探不到时，在手机所在的 Wi-Fi `/24` 上找 `service=adhd` 的 `/health`，找到就显示那条局域网地址。Daemon 上报的 LAN 列表也丢掉 APIPA 和 VMware / vEthernet（正在跑的进程要重启后才换列表）。`:manager:testDebugUnitTest` 与 `daemon/test/lan_address.test.ts` 通过。`aa165071` 装上 debug Manager 后首页为「Web UI 在线 / http://192.168.200.108:8088」。

## 2026-10-16 —— v0.3.14：KernelSU / Magisk 模块更新

之前的 `module.prop` 没有 `updateJson`，所以 KernelSU、KernelSU Next 和 Magisk 的模块页不会出现更新。这一版加上公开地址 `injector/zygisk/update.json`（`version` / `versionCode` / `zipUrl` / `changelog`）。模块版本与 agent 一起升到 **v0.3.14 / versionCode 21**。已经装在手机上、且旧模块没有这个字段的，管理器仍然不会提示，需要手动刷入这一次。公开仓库 [v0.3.14](https://github.com/decrypthub/AndroidDecryptHub/releases/tag/v0.3.14) 已发布：`adh-bundle-v0.3.14.zip`（20,337,015 B，SHA-256 `15c5ccd9dd6b9f0ef04d196a35fbb326529a5ba9b4b360a763400cf257f2afb1`）匿名下载返回 200，`main` 上的 `injector/zygisk/update.json` 也是 200。公开源码树仍是 v0.3.12 快照加这份更新清单，不是私有仓库的完整历史。

## 2026-10-16 —— Java 层算法也进采集

native 的 EVP 钩子看不到 `Cipher.getAlgorithm()`、密钥和 `doFinal` 的明文边界。注入之后，在 `javax.crypto.Cipher`、`javax.crypto.Mac`、`java.security.MessageDigest`、`java.security.Signature` 的 init / doFinal / digest / sign / verify 上装只观察的钩子，记进原来的 `jcaptures`。原方法照常执行。策略里关掉的族不装。

证书钩子先让路：LSPlant 不能两根线程同时装。某个重载把安装线程卡死时，这一条放弃，后面的重载继续。漫播三个进程都装上 31 个算法钩子，主进程记到 `AES/CBC/PKCS5Padding decrypt`，`:player` 记到 `AES/GCM/NoPadding encrypt`。进程还在。agent `cf64b24d892c955c`。没有单独的门禁脚本。

## 2026-10-16 —— 注入进目标就放行 Java 证书校验

同一台已 root 的手机上，别人的模块勾上作用域就能抓包。我们之前把 Java 证书钩子删了，是因为装钩把进程打死。这次接回去，并且只改我们自己写错的地方。

- 装钩前用 `Class.forName(name, true, loader)` 把类初始化完。Android 12 及以上不钩 `Class::SetStatus`（`paciasp` 开头，Dobby 改写后会跳进没映射的内存）。
- 也不钩 `ClassLinker::RegisterNative`。钩着它的时候，漫播在 `libimagepipeline.so` 的 `JNI_OnLoad` 里死在 `RegisterNatives`（`SIGSEGV` / `SI_TKILL`）。关掉绕过、不初始化 LSPlant 时，同样三个进程是活的。
- 不改 Conscrypt 的 `TrustManagerImpl` / `Platform` 入口。改 `SSLContext.init`（TrustManager 换成全信任）、`TrustManagerFactory.getTrustManagers`、`okhttp3.CertificatePinner.check` 两个重载、两个 HostnameVerifier。
- 只换 `SSLContext.init` 时，启动后没有一次 `checkServerTrusted` 被调用，代理仍然解不开。补上 `TrustManagerImpl` / `Platform` 之后（agent `a8af2c039b505528`）三个进程仍在。用户确认代理已经能抓到包。

## 当前阶段 —— 🔧 v2.0+ 加固与重构（进行中）

**v0.1–v1.0 全部实现并逐项验证（`tools/verify_all.sh` 35/35，真机 + host）——那一轮证明"每条能力路径可跑通"。**
现进入 **v2.0+ 加固重构轮**：针对评审锐评的 14 点，把每条路径从"能演示"做到"能在对抗、并发、无样本、
无 sandbox 耦合下不骗人"。权威路线见 `DEVELOPMENT_PLAN.md §6.9`（WS-A…WS-K + v2.0–v2.6 排期 + 门禁清单）。
旧 v0.2–v1.0 路线归档于 `DEVELOPMENT_PLAN.md §7`。

**三条总原则（门禁）**：① 不为过测而耦合（agent 内 `com.adh.sandbox` 常量 = 0，目标模块名不硬编码，
全来自命令参数）；② 不胡乱兜底 / fail-loud（hook 装不上、缓冲溢出、解不动一律显式报错 + 计数上报，
绝不 `ok:true replaced:0` 或虚高恢复率）；③ 红线不动（重分析在 adhd，hook/采集在 agent）。

## 2026-10-14 —— Java 钩子先初始化类，API 31+ 不再钩 SetStatus

这台 ColorOS Android 15 的 `libart` 里，`Class::SetStatus` 以 `paciasp` 开头。LSPlant v6.4 会去钩它，Dobby 改写后的入口从 `MarkVisiblyInitialized+1664` 跳进 zygote GC 位图之间的空洞 `0x79c325500c`。状态 14 是 kInitialized，15 是 kVisiblyInitialized；v6.4 在 API≥30 一律把 15 当成要保存入口的点，保存动作正好发生在这次调用里。

两处改动：API≥31 不再安装 `SetStatus` 钩子，备份状态改为 14；`java_hook` 改用 `Class.forName(name, true, loader)`，类初始化完再换入口（和 Xposed 的 `findAndHookMethod` 一样）。`loadClass` 只解析、不初始化，静态方法还停在 resolution trampoline 上。

沙盒 `com.adh.sandbox`（agent `130f602514dc4818`）冷启动后装上 5 个钩子：`HashMap.get`、`SSLContext.init`、`TrustManagerFactory.getTrustManagers`、`TrustManagerImpl.checkServerTrusted` 两个重载。连续 5 分钟 session 未断，`HashMap.get` 命中从 48 增到 584，crash buffer 为空。上一份 agent 在同一条路径上约 30 秒死于 `0x79c325500c`。测完已 `unhook 0`。这仍不是漫播上的一小时证明，也没有把删掉的 13 条证书 profile 装回去。

## 2026-10-13 晚 —— 删掉 Java SSL 绕过

13 条 Java 证书校验 profile 在这台 Android 15 / ColorOS 上会把目标打死：故障地址固定在 `0x79c325500c`（zygote GC 位图之间的空洞）。先死在 `ClassLinker::SetupClass`，改成静默回调之后同一批进程仍在约一小时后死在 `MarkVisiblyInitialized`。开关、profile、`TrustAllManager`、`bypassKind`、作用域 `b` 段、Manager 开关和 `verify_v104` 已删除。旧 scope 里的 `b` 读入时忽略，下次写入丢掉。

抓包留下 native TLS 明文（采集族 `t`：`SSL_read` / `SSL_write`）。它不改目标接受哪张证书，所以外部代理仍然解不开这个应用自己钉死的连接。下面白天的记录是这条功能当时怎么加上的，不再是当前行为。

## 2026-10-13 —— SSL 绕过开关（JustTrustMe 等价）：让代理能抓 Java 栈目标的包 + 一轮评审修复

- **需求**：用户要用代理（Charles / Reqable / 自己的 mitm）抓目标 App 的包，而 ADH 此前**完全不做**任何
  SSL 绕过（`agent/` 与 `daemon/` 里 `TrustManagerImpl`/`X509TrustManager`/`checkServerTrusted`/
  `HostnameVerifier`/`CertificatePinner` 零命中）。用户明确选择"纯 hook、不装系统 CA、不改手机环境"。
- **为什么必须是 Java 侧**：Android 上 OkHttp / HttpsURLConnection 这一栈的信任决策在 Java 里做——
  Conscrypt 用 `SSL_CTX_set_custom_verify` 把链交给 `com.android.org.conscrypt.TrustManagerImpl`，
  最终走 Java PKIX。所以**钩 BoringSSL 的 `X509_verify_cert`/`SSL_get_verify_result` 对这类目标无效**
  （实测：`getTrustedChain*` 钩子每次连接都命中，libssl 层钩子从不进入）。通用收窄点只有一处：
  `com.android.org.conscrypt.Platform#checkServerTrusted`（两个重载，void）与 `#checkTrusted`
  （boolean）——**所有** X509TrustManager（系统的、App 自己装的 pinning 实现）都从这里过。
- **新增 `agent/src/hook/ssl_bypass.{c,h}`**：13 条 profile（`TrustManagerImpl.getTrustedChainForServer`
  ×2、`SSLContext.init` 换 `@trustAllManagers`、`TrustManagerFactory.getTrustManagers`、
  `Platform.checkServerTrusted` ×2 + `checkTrusted`、`ConscryptEngine.verifyCertificateChain`、
  okhttp 的 `CertificatePinner.check` ×2 与两个 HostnameVerifier）。`TrustManagerImpl` 的每个信任决策
  返回 `java.util.List`，所以 `skipOriginal` 单独用会把 Conscrypt 变成 null ⇒ 用 `@arg0List` 把**对端出示的
  链**当可信链返回（真绕过，且完全不看证书内容）。
- **启动期装钩是致命的（实测三次）**：任何 Java 钩子只要在目标还在链接类时落地，进程就在
  `ClassLinker::SetupClass` 上 `SIGSEGV`（`pc` 落在不属于任何映射的空隙里）。**根因不是 `b=1`，而是
  daemon 对每个新会话都会自动发 `capture_start`**（`service.ts startCaptureLoop`），于是"随会话自动布防"
  约 1 秒就触发安装。修法：`SB_MIN_UPTIME_SEC = 10` 的**运行时长门禁** + 延迟线程在窗口过后**自动布防**
  （外部抓包工具因此不需要任何 ADH 命令）；`capture_start` 路径仍幂等，早发等于空操作。代价如实写明：
  `SSLContext.init` 只能改写**我们到达之后**构造的 context，但每次连接的决策点（Conscrypt 链检查、
  okhttp pinner、hostname verifier）不受延迟影响。
- **契约（刻意偏离既有模式）**：SSL 绕过**不是** capture family。六族是**被动采集**，缺键按"开"；
  这一项是**主动篡改目标行为**，所以**缺键按"关"**（Kotlin `optBoolean("s", false)`、companion
  `family_on(bypass,"s",0)`、agent `policy_flag_closed`）。`scope.json` 里它是**兄弟段** `{"b":{"s":true}}`
  而不是第七个族键，`CaptureFamilies` 的文件头写明"别把 SSL 绕过加到这里"。`AdhProtocol.VERSION`
  15 → **16** + 新增 `MIN_BYPASS_VERSION`：`RootScopeBinder.setScopeJson` 是 decode→re-encode，
  低版本 daemon 会**静默丢掉 `b` 却照样回保存成功**（UI 会显示"已开"而目标仍在 pinning），所以
  Manager 写入前门禁、低了如实报失败。
- **回执（哪里能看到装没装上）**：`capture_start` 回包新增 `sslBypass`（`on N/M miss:<条目>`，
  `miss` 就是该目标本来没有的类），daemon 侧 `recordCaptureHooks` 把它写回 `session.bypass`。
  **hello 里的 `bypass` 结构上不可能是结论**（延迟安装，hello 早就发出去了），所以它只报
  `off` 或 `pending: arms at 10s uptime`——`state.ts` 里那条"hello 时结论已知"的注释是错的，已改。
- **本轮评审发现并修掉的缺陷**（两个评审 agent + 逐条复核）：
  - **C1** `inspection.c` 的 `vesc_cap = strlen(vsrc) + 1` 会**丢掉每个字段值的最后一个字符**
    （`json_escape` 允许增长到 2 倍，且循环条件是 `o + 2 < n`）→ 改 `* 2 + 1`，用从 `util.c` 逐字提取的
    `escape_test` 验证（35 / 18 / 47 字节三例，旧式全缺尾字符）。
  - **C2** 无 LSPlant 配置**编译不过**（调用点没护栏）→ `agent_main.c` 的 `#include` 移进
    `#ifdef ADH_HAVE_LSPLANT`，加惰性占位；两种配置都编过（有 LSPlant 1,030,624 B / 无 703,640 B），
    占位版现在会把"unavailable: no Java hook backend"如实写进回执，而不是留空。
  - **C3（最严重）** `device/:core` 不认识 `b`，而 daemon 是 decode→re-encode ⇒ **任何一次 Manager
    作用域保存都会抹掉手工加的 `b` 段**，而且 Manager 永远显示不出来。新增 `BypassFlags`、
    `ScopeConfig.bypass` / `withBypass` / `bypassFor`、`ScopeJson` 编解码（稀疏写入，只在开时写 `b`）、
    Manager 面板的开关 + 列表行红色徽标（文案中英同步）、`MIN_BYPASS_VERSION` 写入门禁。
  - 清理：删掉死代码 `adh_ssl_bypass_install()`、修 `ssl_bypass.h` 自相矛盾的头注释（"启动时装"vs
    "拒绝在启动窗口内装"）与 profile 重复编号、把产品源码注释里的真实目标名换成中性描述、
    `install_now` 现在两波都重试（boot classpath 优先）。
- **门禁**：新增 `tools/verify_v104_ssl_bypass.sh`（device）：两轮冷启动，**只差一个 `b` 键**——
  `b.s=true` 必须让 hello 带 `,b=1` 且安装回执 `on N/M` 里**不含** `TrustManagerImpl`/`Platform`，
  无 `b` 段（但有 capture 策略）必须回**正好 `off`**；同时断言 verdict 经 `capture_start` 回包
  → `session.bypass` 真的到达会话。`verify_all.sh` 117 → **118（36 host + 82 device）**。
  `verify_v87_mcp_operability` PASS（红线扫描零命中）；daemon `smoke` OK，`flow` 11/11；
  `device` gradle `:core:test`/`:manager:testDebugUnitTest`/`:manager:assembleDebug` 全绿
  （新增 6 条 `b` 相关单测，含"encode(decode(x)) 不能吞掉 `b`"的回归）。**真机端到端此前已验**：
  手机未装任何 CA 的前提下，mini-mitm 解出 `POST /api/v549/user/login/password` 明文。
- **真机收尾时抓到的第二个真 bug：作用域是按「进程名」匹配的，勾包名只覆盖主进程**。
  在真机上（`aa165071`，三进程目标 `com.uxin.kilaaudio` / `:core` / `:player`）逐个名字单写进
  allowlist 得到判决性结果：**只写 `com.x:core` → 只有 `:core` 拿到 agent；只写 `com.x` → 只有主进程拿到**。
  根因：Zygisk 的 `nice_name` 是**进程名**，而落盘的作用域 / 逐包策略 / Manager 界面全都按**包名**，
  注入器又拿 `nice_name` 去做字面匹配（companion 的 `scope` / `policy` 动词同一把 key）。
  这与 `REQUIREMENTS` 的"支持多进程 App：每个进程独立 session"直接矛盾，且**目标的网络栈在哪个进程
  决定了抓包成不成功**——正是"抓不到包"的一类真实成因。
  **修法**（`injector/zygisk/jni/main.cpp`）：新增 `package_of()`，scope 与 policy 都**先按进程名、再按包名**
  各问一次（窄的优先，保留"只想盯某一个进程"的用法）；hard-exclude 对两个 key 都判；
  agent 侧 `report()` 把名字按 `:` 拆开，`hello.package` = 包名、`hello.process` = 进程名，
  于是多进程 App 在 daemon/面板里**归到一个包**下、每个 session 仍可溯源到进程。
  **验收（真机，刷模块+重启后）**：只写包名 `com.uxin.kilaaudio` → 主进程 / `:core` / `:player`
  **三个进程全部拿到 agent**，且三个都拿到同一份 `b=1` 策略；只写 `:core` → 仍然只有 `:core`。
  `verify_v104` 复跑仍 PASS。
- **诚实记录：没有重现出"自动化冷启动 → 代理抓到明文"**。开着 `b`、三个进程都装好绕过（真机日志
  `on 12/13`）、系统代理也已设成 `127.0.0.1:8899`（`adb reverse` 在），冷启动目标后
  **代理侧 0 个连接**，而目标自己的 socket 直接打到 443（`/proc/net/tcp`，uid 10333，远端 443/6783/7001），
  同时应用界面内容正常加载。即：**这一轮里目标没有走系统代理**。上一轮同机同代理确实抓到过登录请求
  （`dumps/kilaaudio/mitm4-login-success.log`），所以它的代理行为是**随情境变化**的，而这不在 ADH 能控制的
  范围里。结论要分开说：**绕过本身是有效的（真机可证）**；能否经代理看到明文还取决于目标愿不愿意用系统代理。
  自己动手确认只需 30 秒：解锁手机 → 开目标 App → 等 15 秒（绕过在启动窗口后才武装）→ 点登录。
- **签名预算收口（同日，上一轮被 API 400 打断）**：SSL 绕过最初把信任管理器写成 `AdhJavaHookBridge` 的内部类，
  dex 里多出带这个类名的描述符，`scan_agent_signatures.sh` 的计数超过预算 10，`verify_v88` FAIL。
  拆成同包独立类 `agent/java/com/adh/agent/TrustAllManager.java` 后，`AdhJavaHookBridge` 回到 10，
  `com.adh.agent` 仍是 1。产物 **1,031,056 B / `1a2ff558…`**，与设备
  `/data/adb/modules/adh/libadh_agent.so` 一致（17:46 写入，无需再刷模块：注入时按文件现读）。
  **2026-10-13 18:25 复跑（`aa165071`）**：`v88` PASS；`v75` PASS（主进程过滤后仍能对上 `pidof`）；
  `v42` PASS（沙盒模拟注入，LSPlant v6.4 / ART init）；`v102` 两轮 PASS（flag 行含 `b=0`）；
  `v104` PASS（沙盒 `on 8/13`，缺的是 okhttp；无 `b` 段时正好 `off`）。
  同一份 so 冷启动目标后，主进程 / `:core` / `:player` 三个会话都带到 `b=1`，
  hello 在启动窗口内如实报 `deferred: uptime < 10s`。
- **绕过回调不再走观察路径（同日晚，闪退）**：`b.s` 打开后三个进程都在 `ClassLinker::SetupClass`
  跳进 zygote GC 位图中间的空洞（地址每次都是 `0x79c325500c`），进程活了几十秒才死，请求跟着没了。
  观察回调每次命中都做 `getClass()` / `getReturnType()` / 拼字符串；类还在定义时这么做，入口会被写成那块空洞。
  绕过改成 `bypassKind`：命中后直接返回装钩时定好的值（跳过 / `true` / 对端证书链 / trust-all 数组），
  不反射、不拼字符串、不上报。产物 **1,031,728 B / `e79c88cb…`**。
  这只去掉了快路径：21:21 冷启动后 90 秒没死，但 **22:24 原进程（uptime 3774 s）仍死在同一地址**，
  栈是 `ClassLinker::VisiblyInitializedCallback::MarkVisiblyInitialized`。静默回调没有修掉。
  已把该机 `scope.json` 的 `b` 段去掉（fail-closed），并 force-stop 目标，避免下次启动再装这批 Java 钩子。

## 2026-10-12 —— `live_captures` 补 `encoding:"b64"`：捕获记录终于能**逐字节**还原


- **症状（真机暴露）**：想拿 ADH 当"抓包工具"用（目标 App 有证书钉扎，代理走不通）时发现，
  `live_captures {includeText:true}` 给的 `ascii` 是**有损**渲染 —— `asciiOf()` 把每个非可打印字节
  换成 `.`，一个 `\r\n` 变成 `..`。结果是：能**读**JSON 正文，但**不能解析**：无法给 HTTP 分帧、
  无法 gunzip（响应基本都带 `Content-Encoding: gzip`）、无法拿回二进制体。
  另外 `ascii` 硬切在 4096 字符且**不报**，`inl` 与 `ascii.length` 对不上才知道被切了。
- **修法**：`daemon/src/flow.ts` 加 `b64Of(hex)`（无损、字节级，奇数字节/非 hex 一律**拒绝**而不是编造）；
  `live_captures` 加 `encoding`（`"ascii"` 默认，保持旧行为 / `"b64"` 精确字节，上限 65536 B）。
  **不再有静默截断**：两条路径都回报 `bytes`（真实长度）与 `truncated`（只有被切才 true）。
  单测 `test/flow.test.ts` 新增"b64Of 把 asciiOf 丢弃的字节原样还回来"（含 CRLF 往返、gzip 魔数、空/奇数/非 hex）。
- **门禁**：`verify_v87_mcp_operability` PASS（红线扫描零命中）；`daemon` 单测 180/180；`smoke` OK。
- **验证**：改完后用新字段跑通真机的请求/响应配对 —— `POST /api/v549/user/login/password`
  （141 B 表单）+ gzip 响应解出 `{"h":{"code":1013,...}}`，主机名/长度/正文全部对得上。
  顺带解释了上一轮"抓到的签名重放失败"的疑团：那个 `d17dc042…` 是**另一次**密码登录
  （密码框里有 16 字符残留文本），不是密码登录那一路的参数，签名当然对不上。
- 消费者的样板脚本在 `dumps/kilaaudio/netlog.mjs`（gitignored）。

## 2026-10-12 —— 漫播登录协议整条还原：签名算法破译 + 独立客户端跑通到业务判定

- **成果**：`com.uxin.kilaaudio` 1.6.18 的 `POST /api/v549/user/login/password` **完整实现**，
  表单四字段（`mobile` / `password` / `source` / `sign`）与真机请求**逐字节相同**，
  独立 Python 客户端（`dumps/kilaaudio/manbo_login.py`，仅标准库）发出的请求服务端**接受**。
- **算法**（全部来自 `libanonymous.so` 静态符号 + 反汇编，再用线上请求对齐）：
  - `mobile` = `base64(AES-128-CBC(key,iv,PKCS7)(手机号))`；`password` 同一对 key/iv；
    `source` = 区号（观察值 `86`）。
  - `sign` = `MD5( salt + mapToQuery(params) )`：参数按 key 升序拼 `k=v&k=v`（值不 URL 编码），
    `salt = EncryptSalt("6zF0R8;/") = "3aU9I1;/"`（逐字符仿射变换，常量在 `.rodata`，可直接读文件）。
  - 名字唬人的 `EncodeTool1` **实测就是标准 MD5**（IV 与 K 表原样），`EncodeTool2` 才是 SHA-256。
- **pass/fail 信号**：随机号码从 `{"code":11,"msg":"http请求签名校验失败"}` 变成
  `{"code":1013,"msg":"用户不存在"}` —— 协议层全过，只剩"这个号没注册"的业务判断。
  真账号的端到端成功留给用户用自己的号验（目标里没有可用账号：`/data/data/<pkg>/` 无登录态存储）。
- **方法论（可复用）**：① **载荷从 SSL 明文拿**（`live_captures` `category:'net'`），不需要任何 Java 钩子；
  ② **别拿 hook 到的签名反推算法**——签名是参数的函数，载荷不对反推的方程就是错的（前一轮就栽在这）；
  ③ 目标 so 没 strip 就先读符号再读反汇编，比在 Java 层猜拦截器快一个数量级。
- **暴露的 ADH 缺陷（新）**：装 LSPlant Java 钩子（仅 `okio.RealBufferedSink#writeUtf8` 一处）后目标约 6 s 内
  在 `ClassLinker::SetupClass` 路径上 `SIGSEGV`，`pc` 落在**不属于任何已加载 so 的 `<unknown>` 映射**
  —— 指向被替换过的 ART。同一条时间线上 **native（GOT）钩子全程稳定**。已记入 `CASE_STUDIES.md` 待办：
  在定位并修好这个崩溃点之前，能用 native 手段就不上 Java 钩子。
- 文档：`docs/CASE_STUDIES.md` 案例 2 增加"签名算法"小节与缺陷 F/G；现场记录（含密钥/明文）
  在 gitignored 的 `dumps/kilaaudio/ANALYSIS.md`。

## 2026-10-12 —— Zygisk Next 报"1 module(s) with issue: adh"：我们真在泄漏伴生 socket

- **症状**：Zygisk Next 1.5.0 把自己的状态写进 `/data/adb/modules/zygisksu/module.prop` 的 description：
  `[✅zygote, ✅zygote_ocomp, ✅zygote_secondary, ⚠️1 module(s) with issue: adh, Root: ✅KernelSU …]`。
  它 WebUI 里的解释是 **"improper use of the Companion API, which may cause process crashes and memory
  leaks"**（另一处 Fn.CompanionFd 分支链到 wiki 的 `#fd-leaking` 锚点）。
- **根因**（就是我们的错）：`injector/zygisk/jni/main.cpp` 里给 `note()` 做转发的那条伴生 socket
  **被缓存成 `g_companion_socket` 之后从不关闭**——只有"发失败"那条分支才 `close()`。而 pre-specialize 结束
  进入 app 域后那条连接已经不可用（注释里本来就写着"measured - the connection does not survive the
  switch"），于是**每一个被注入的进程都白拿着一个死 fd 活到进程结束**。另外两个调用点（`mark` / `scope`）
  是当场 `close()` 的，只有转发这条漏了。
- **修法**：把转发明确成**只在 pre-specialize 窗口存在**的东西——`release_companion_relay()`（关 fd +
  置 `g_companion_relay_open=false`），由 `preAppSpecialize()` 这个新外壳在**所有返回路径**上调用
  （原来的函数体改名 `pre_specialize_inner`，所以 hard-exclude / 不在作用域这些提前 return 也一样被覆盖），
  并在 `postAppSpecialize()` 开头再幂等调一次兜底。`companion_log_line()` 增加 `g_companion_relay_open`
  门禁，post-specialize 不会再开新连接（在那里调 `connectCompanion()` 本身就是不当用法）。
- **验收（真机 `aa165071`，两处独立证据）**：
  - Zygisk Next 自己的状态行 `⚠️1 module(s) with issue: adh` **消失**（刷入修复版并重启后重读 module.prop）；
  - 同一个被注入的目标 `com.android.settings` 冷启动三次：**修复前 sockets=9 / totalFds=373，
    修复后 sockets=7 / totalFds=195**。socket 的差数正是那条死连接（另有 1 个来源未定，见下）；
  - **注入本身没被这次重构搞坏**：`verify_v102_policy` 两轮仍 PASS（说明 `mark`/`scope`/`policy`
    三个伴生动词在重构后都还工作）。**诚实记录**：totalFds 少掉 178 比"一个 fd"多得多，
    这一项没有被单变量控制住（前后各只测了一轮环境），我不把它算作修复的成果。
- **新增门禁** `tools/verify_v103_zygisk_companion.sh`（device）：断言"模块本次启动确实跑过"（`zygisk_loaded`
  标记，防止"没加载所以没意见"冒充通过）+ "Zygisk Next 的状态行没有把 adh 列为有问题的模块"，
  并打印冷启动目标进程的 socket/fd 计数作证据。装 Zygisk Next 才跑，否则 SKIP。门禁 116 → **117（36 host + 81 device）**，
  `CLAUDE.md`/`AGENTS.md`/`HANDOVER.md`/`FEATURE_STATUS.md` 的 live 计数同步。
- **顺带**：`CASE_STUDIES.md` 增补"案例 2 — 漫播"（脱敏）；完整密钥/明文记录只在 gitignored 的
  `dumps/kilaaudio/ANALYSIS.md`。**仍未提交**（本条与上面的逐包策略是同一次提交）。



## 2026-10-12 —— 逐包 Hook 策略（勾了哪个 App，就只给它选中的算法族装钩子）

- **需求**：ADH 的作用域是"勾选列表"，勾谁对谁生效；用户要的是**每个勾上的 App 再单独配一份**——这个 App 要不要 Hook
  摘要(MD5/SHA)、HMAC、对称(AES)、非对称、TLS、AEAD。动机是 2026-10-11 的实测：某个轻度混淆的目标在钩子生效期间
  以 `SIGSEGV (SI_USER)`（注入信号，不是真崩）自杀，疑似完整性自检——**少装钩子就是少暴露面**。配置**存在手机上**
  （`/data/adb/adh/scope.json`），用户用 Manager 改、AI 用 adb 改**同一份文件**，两条路径看到的东西不分叉；没有 AI 时
  用户自己也能用。**本版不做**：SSL 绕过开关（等 profile 收尾；**已于 2026-10-13 做出，见上**）、MD5/SHA 拆成两个开关（两者在本工具里走同一个
  `EVP_DigestUpdate` 入口，拆开要额外读算法名）。
- **契约（`device/:core`）**：`scope.json` 加**可选** `policy` 段，`version` 1 → 2；新增 `CaptureFamilies`（六布尔，
  缺省全开）与 `ScopeConfig.policy`，`ScopeJson` 走短键 `{"c":{"d":true,"h":false,…}}`（与 `InstalledAppsJson` 同理：
  同一份 JSON 要过 Binder）。**缺段 / 缺包 / 缺键一律按"开"** → 老 scope 文件、老 Manager、老 daemon 不写该段即保持正确；
  `encode` 丢弃默认值与已出作用域的条目，所以该段只承载非默认项（作用域里去掉一个 App，它的策略自动消失）。
  `AdhProtocol.VERSION` 14 → **15** + 新增 `MIN_POLICY_VERSION`——`RootScopeBinder.setScopeJson` 是 decode→re-encode，
  低于该版本的 daemon 会**静默丢掉 `policy` 却照样回保存成功**，所以 Manager 侧写入前按它门禁、低了如实报失败。
- **界面（`device/:manager`）**：作用域页每行的 `⋮` 菜单加「Hook 配置」，面板用 `ModalBottomSheet`（**本仓第一个
  对话框/底部面板**，此前全仓只有 `DropdownMenu` 与 `Snackbar`）；非默认的行显示小徽标，一眼看出"这个 App 的钩子被裁过"。
  顺带修掉一个真 bug：老的 `save()` 只传 `selected`，会把 `version`/`mode`/策略**全丢掉**，现在整份 config 写回。
  文案中英两份同步。
- **送达链路**：companion（root）多一个动词 `policy <包>` → 一行紧凑标志 `d=1,h=0,s=1,a=1,t=1,e=0`（照 `scope <包>` 的
  容错读法，缺省全开）；实例侧在 `preAppSpecialize` 取回，连同包名交给**新导出** `adh_agent_set_policy`。
  两个门禁同步：`agent/exports.map` 与 `tools/verify_v26_footprint.sh`（三个导出 → **四个**）。
- **agent 侧**：`g_families` 门控**每一次安装**的每一组（digest/hmac/symmetric/asymmetric/tls/aead），关掉的组
  **根本不调 `adh_got_replace`**，并在回执里列进 `skipped`。`EVP_DigestSign*` 同时服务 HMAC 与 PKEY 签名两条路，
  所以它的规则是"**两者之一开着就装**"（`on_dsign = hmac || asymmetric`）。host 侧 `captureInstallCounters` 把
  `skipped` 里的名字排除出 `installed/attempted`——否则"没要求"会被读成"要了却没装上"。
- **⚠️ 中途被自己的红线门禁抓到，并因此改掉了设计**：第一版让 agent 在 `adh_agent_start()` 时**自己武装**（照 daemon 的
  默认模块名硬编码一个 JCE provider 名字），`verify_v87_mcp_operability` 的 WS-B 红线直接报
  `target-specific names in product code: agent/src/capture/capture.c`。**修法不是把门禁放宽，而是删掉自我武装**：
  - GOT 补丁需要一个**模块名**，而"agent 不携带任何模块名"是 WS-B 红线的原意（模块归调用方）；
  - agent 唯一能不靠调用方拿到的名字是"**扫描每一个 file-backed 模块**"，而 settings 契约明确警告那是会**在 init 期
    钩到框架 crypto、可能拖垮启动**的高级模式，不能当默认；
  - 把模块名再抄一份进 `scope.json` 会造出**同一个旋钮的第二个真相源**（daemon 的 `cryptoModule` vs 手机上的值），
    两处不一致时"有没有 host 连着"会决定同一个 App 被钩在哪个模块里——那是真 bug。
  于是现在的语义是：**agent 只持有策略，由下一次"调用方发起的安装"应用它**。诚实边界照旧且更清楚：**决定**策略不需要
  主机（它存在手机上，经 companion → agent 送到），**安装与观测**仍然需要主机。
  另一处小坑：v87 是**纯子串扫描**，所以连"解释这条红线"的注释里写出那个模块名都会 FAIL——改成不写它的描述。
- **验收**（全部现场跑过，不是"看起来对"）：
  - **单元**：`device`: core `ScopeJsonTest` **12**（+逐包策略往返 / 缺省全开 / 未知键容错 / `version`==2）、manager
    `DaemonScopeRepositoryTest` **7**（+2：假模型现在**照实模拟 daemon 的 decode→re-encode**，否则"字段被静默丢掉"
    这条路径永远测不出来）+ `WebUiRepositoryTest` 2、daemon `CallerAuthorizerTest` 1 —— 2026-10-12 全绿；
    daemon `node --test` **180 pass / 0 fail**。
  - **协议/足迹**：`verify_v26_footprint` PASS（`defined-exports=JNI_OnLoad adh_agent_set_package adh_agent_set_policy
    adh_agent_start`）；`verify_v87` PASS（`target-name hits=0`）。
  - **真机端到端**（`aa165071`，agent 重建后 sha `b8dc7137…` 已推入 `/data/adb/modules/adh/libadh_agent.so` 并与本仓逐字节同 sha）：
    新增 `tools/verify_v102_policy.sh`，**两轮冷启动**——关 hmac+AEAD → agent 的 hello 报
    `policy=d=1,h=0,s=1,a=1,t=1,e=0`、安装回执 `skipped=hmac,aead` 且 `hmac=-1`/`aead.seal=-1`、其余 8 个族**没有一个**
    是 -1（含 `digestSign=1`：hmac 关了但非对称开着，共享入口照样装）；全开 → `skipped` 为空、10 个族一个不缺。
    `ADH_POLICY_TARGET=com.uxin.kilaaudio bash tools/verify_v102_policy.sh` → **PASS**（沙盒未装，故用漫播）。
  - **门禁**：`verify_v102_policy.sh:device` 已登记，115 → **116（36 host + 80 device）**，`CLAUDE.md`/`AGENTS.md`/
    `FEATURE_STATUS.md`/`HANDOVER.md` 的 live 计数同步。
  - **host 半段**：**35 PASS / 1 FAIL**。唯一 FAIL 是 `v19_settings`，且是**环境**不是产品：本机 daemon 起在
    `ADH_DATA_DIR=C:/Users/diiho/adh-data`（这棵树在 SMB 上，SQLite 索引不能放那儿，见 `state.ts` 那段注释），而脚本读的是
    `$ROOT/adhd-data/settings.json`；`ADH_DATA="C:/Users/diiho/adh-data" bash tools/verify_v19_settings.sh` → 全 PASS。
    另：`v10_webui`/`v10_export`/`v26_footprint` 三条只打 `✅ … PASS` 不打 `RESULT:` sentinel（既有约定，不是失败）。
- **设备状态**：验收脚本自带的还原已把 `scope.json` 写回
  `{"version":2,"mode":"allowlist","packages":["com.chaoxing.mobile","com.uxin.kilaaudio"]}`（**无 policy 段**＝全开，
  与改动前行为一致）。测试中我手写过一份显式全开的 `policy`，已删除——`ScopeJson.encode` 本来也会丢掉它。
- **刷机**：`bash tools/flash_device.sh --reboot`（`aa165071`）——单靠推 agent `.so` 不够：**逐包策略要能从 Manager 界面
  存下去，设备上的 Device Daemon 也必须是 v15 的 `:core`**，否则它 decode→re-encode 时会静默丢掉 `policy`。刷入后核对：
  模块内 `daemon.apk` = 本仓 `daemon-debug.apk`（`0e169a56…`）、已安装的 `com.adh.manager` base.apk = 本仓
  `manager-debug.apk`（`75c0e778…`，即带「Hook 配置」的那版）、模块内 `libadh_agent.so` = `b8dc7137…`；
  `zygisk_loaded=YES`、`device_daemon_ready=YES`，重启后重连隧道再跑一次 `verify_v102_policy` 仍 **PASS**。
  注：`com.adh.daemon` 不是安装包，它以 root `app_process` 从模块目录启动，所以"新版 Device Daemon"= 模块内那份 APK 换新。
- **未提交**。**未做**：SSL 绕过开关（等 profile 收尾，含漫播那种"App 自己比对指纹"的定位结果）、MD5/SHA 拆分。

## 2026-10-12 —— 三处修复（用户点名的：capture 默认值、dex 索引库、密钥/IV 抓取）

- **`capture_start` 的 file/sys 模块默认值**（`daemon/src/state.ts`）：原来默认指向沙盒自己的模块，在真机上等于
  **静默少装 6 个钩子**（"模块名没加载"和"这个 App 不导入"在回执里长得一样）。改成 `fileModule:''`/`sysModule:''`
  ＝**两个类别都不装**，并加一条迁移：老 settings 里若还是沙盒默认值，启动时清成 `''`。要钩就必须显式说出模块名
  （`file_probe` 就是用来告诉你该说哪个的）；沙盒自检自己显式传模块名（v20/v05）。
- **dex 索引库自愈**（`daemon/src/dex_index.ts`）：SMB 双写导致 `dex-index.sqlite` 出现过 `SQLITE_CORRUPT`，之后**每一次**
  `dex_index`/`dex_index_search` 都答"没有"，而 dex 明明躺在 `captures/` 里（陈旧答案比没有答案更糟）。现在建库/查询
  统一走 `withIndex()` 包壳：识别 corruption 错误 → 丢弃坏库 → 重建 schema → 重试一次，四个 `*Inner` 是真正的实现体。
  配套决定：**这台机器的 daemon 数据目录指向本地盘 `C:/Users/diiho/adh-data`**（`ADH_DATA_DIR`），因为本仓工作树在
  SMB 上，索引库放那儿就是反复坏。
- **对称加密的 key/IV 抓取**（`agent/src/capture/capture.c`）：`EVP_CipherInit_ex` 拿 key、`EVP_CipherUpdate` 拿数据，
  两个入口**必须成对挂**才能给一条本地 AES 记录配上它的密钥；`EVP_CIPHER_CTX_free` 负责让槽位回收。加了
  `KEY_SLOTS`/`key_store`/`key_lookup`/`key_forget` 这套 ctx→key 的连接，`CapRec`/`emit_caprec` 带上 key/iv，
  daemon 侧 `Capture` 直接落 `keyHex`/`ivHex`。**诚实记录**：在漫播的登录流上恢复出的那把 key
  **并不解**它登录字段里的那串密文——所以"拿到 key"与"看懂这条链路"是两件事，别把前者写成后者。
  （密钥与明文的原值只留在 gitignored 的 `dumps/kilaaudio/ANALYSIS.md`，不进仓库。）

## 2026-10-11 —— 移除 Xposed 后端

已整段删除；详情与删除清单见 [`docs/archive/RETIRED_MODULE_X_AND_XPOSED.md`](archive/RETIRED_MODULE_X_AND_XPOSED.md)。官方注入只留 Zygisk；Frida/eCapture 仍为实验脚本。

## 2026-10-11 —— v0.3.12 重建并真机刷入（含刷机脚本的 Windows 阻断修复）

- 环境：**Windows 工作站** + 参考设备 `aa165071`（OnePlus PGP110 / SDK 35 / arm64-v8a / KernelSU + **Zygisk Next 1.4.2**）。设备上原本**没有** ADH 模块（`/data/adb/modules/adh` 不存在，只剩 10-10 的 zygisk 残留标记），本次是重新刷入。
- 从当前源码在 Windows 上重建：`libadh_agent.so` **1,014,984 B**（sha256 `018116ce2267fae2…`，替换掉设备上旧的 `78d9d20f…`）、`adh-zygisk.zip`、`adh-bundle-v0.3.12.zip`（20,329,668 B）；companion 的 `zygisk_module_entry` / `zygisk_companion_entry` 两个导出已校验。device/ 无源码变更，Manager/Daemon APK 复用既有产物。
- `tools/flash_device.sh --no-build --reboot` 刷入后实机核对：模块已合并进 `/data/adb/modules/adh`（`zygisk/arm64-v8a.so` 在位）、设备上的 `libadh_agent.so` 与本仓构建**逐字节同 sha256**、`module.prop` 状态「运行中」；重启后 `zygisk_loaded=active`、`adh-device-daemon`（root，pid 3126）与 `zn-zygisk-companion64 adh` 均在跑，作用域仍为 allowlist `com.chaoxing.mobile`。**本次没有跑设备门禁**，故最近一次真机全量结果仍是 2026-10-01 的 **114 PASS / 1 FAIL / 2 SKIP**，不得把本次写进新的真机通过。
- **修掉一个真实阻断**（`tools/lib/env.sh` `refresh_agent_so`）：它把 POSIX 主机路径 `/tmp/adh_agent_refresh.sh` 直接交给 Windows `adb.exe`，而 `flash_device.sh` 顶部 `export MSYS_NO_PATHCONV=1` 又关掉了 Git Bash 的路径转换，于是 `adb push` 报 `cannot stat` → `set -e` 在 `pm install` 之后中断脚本——**模块只进 `modules_update/`、`--reboot` 从不执行**（表现为"刷了但没生效"）。改为先用 `cygpath` 转换主机侧路径、并在两次 push 期间显式钉住 `MSYS_NO_PATHCONV`（`install_apk_root` 已有同样写法）。修复前后各复现/验证一次，`rc` 从 1 变 0。
- 注意：该设备上**没有** `com.adh.sandbox`（沙盒 App 未安装），设备侧验收脚本要先装沙盒才有意义。本次改动**尚未提交**。

## 2026-10-09 —— v0.3.12 可刷入预发布包已公开

- 公开仓库 `decrypthub/AndroidDecryptHub` 的 `main` 增加 `439bc00`，标签 `v0.3.12` 指向该提交；[GitHub Release](https://github.com/decrypthub/AndroidDecryptHub/releases/tag/v0.3.12) 已创建为 **prerelease**。匿名下载链接返回 200，三个附件均显示 `uploaded`：`adh-bundle-v0.3.12.zip`（20,261,727 B）、对应的 LSPlant 修改后源码归档、`SHA256SUMS`。
- 从公开源码拉取 LSPlant v6.4 + DexBuilder + parallel-hashmap、Dobby 1.2、可选 QBDI 0.12.1，编译 `libadh_agent.so`（1,036,720 B）、Device Daemon、Manager 与 Zygisk companion；`device :core:test :daemon:assembleDebug :manager:assembleDebug` 成功。公开源码此前 Host 单测 **178 PASS / 0 FAIL / 1 SKIP**。ZIP 解压完整性、必要文件、Manager SHA-256、两个 APK 签名、arm64 ELF 架构、许可证材料均通过主机检查。ZIP SHA-256：`8c09b1ace579b6a4d84bea06523151729f547f12b88eee685cb0a6e351c73695`。
- **本次没有对任何手机刷入或跑设备门禁。** 这个可安装包是主机验证过的预发布产物；最近一次完整真机门禁仍为 2026-10-01 的 **114 PASS / 1 FAIL / 2 SKIP**，不得把本次构建写成新的真机 PASS。Manager 使用此构建本地 debug 签名，未来不同签名的 APK 不能直接覆盖安装；QBDI 运行时库未随 ZIP 交付。
- 二进制 ZIP 增加 MIT、LGPL-3.0、GPL-3.0、Apache-2.0 许可文本；Release 附精确修改后的 LSPlant 与子模块源码，公开标签含 ADH 应用源码与构建脚本。此私有开发仓同步打包脚本和许可材料，`build_zygisk.sh` 在 SMB 非可执行位环境用 `bash ./gradlew`。

## 2026-10-09 —— AndroidDecryptHub 公开源码快照准备

- 用户确认公开到 `decrypthub/AndroidDecryptHub`，沿用 iOS 项目的 MIT，采用**清理后的单次源码快照**，不公开本私有仓库的 377 个历史提交。
- 独立导出目录 `/home/r/AndroidDecryptHub-public` 已生成根提交 `8af6c5f`（418 个文件）：加入中英 README、MIT LICENSE、第三方 NOTICE、构建与安全边界文档；排除内部交接/实战文档、构建产物和捕获数据，并将本机用户名及真实目标案例测试数据改成通用/合成内容。私有仓库原有 Git 历史未复制到公开目录。
- 导出验收：`npm ci` 成功；Host 单测 **178 PASS / 0 FAIL / 1 SKIP**；CLI `--help` 与相关 Bash 语法检查通过；418 个提交文件的凭据/私钥/本机路径扫描 **0 命中**。本次没有运行设备验收，也没有触碰日常手机。
- **已公开发布**：[decrypthub/AndroidDecryptHub](https://github.com/decrypthub/AndroidDecryptHub) 的 `main` 已推送根提交 `8af6c5f`。细粒度 PAT 可创建仓库但缺 `Contents: write`，于是本机经用户在 GitHub 设备页授权 `gh auth refresh`，切换成 `gho_` OAuth（`repo/read:org/gist/workflow`）后推送成功。匿名 GitHub REST API 确认 `private=false`、默认分支 `main`；远端提交列表只有该根提交，树共 418 个文件，README/LICENSE/NOTICE 存在，内部交接/案例文档和构建/捕获产物不存在；GitHub License API 识别为 MIT。原私有仓库 377 个旧提交未进入公开历史。

## 2026-10-09 —— 新功能开发前的能力复核（未变更范围）

- 本次只做代码/文档复核与 Host 单测，**没有重跑真机门禁**。当前 agent 命令分支 **33**、MCP 工具 **65**、`verify_all.sh` 脚本 **117**；`cd daemon && node --test test/*.test.ts` 实跑 **179 PASS / 0 FAIL**。最近一次真机全量结果仍是 2026-10-01 的 **114 PASS / 1 FAIL / 2 SKIP**，不可将本次 Host 通过写成新一轮真机通过。
- 能力收敛：官方 Zygisk 注入、Java/native/JNI 与 crypto/TLS/file/syscall 观测、内存/DEX/SO dump、DEX 索引/xref/反汇编/算法识别和 Web/MCP/CLI 已成体系；真实加固目标学习通的 13 个真 DEX 已与手工提取结果逐字节同 hash（`CASE_STUDIES.md` 案例 1）。
- 新特性最明显的产品缺口：`adh` CLI 目前仅 `doctor/target/unpack`，作用域、冷启动、探针、捕获与报告仍需人工串联；`flow_correlate` 仅同线程 + 200ms 共现，WS-I 的内容关系确定性关联**未做**；案例 1 的原生 I/O 路径曾出现 GOT 钩子 5 分钟 0 命中，尚缺从零命中走到真实路径的调查编排。
- 发布边界仍需收口：协议 v13 对应 release bundle 尚未重建/刷入；agent TCP `8761` 监听 `0.0.0.0` 且无鉴权，信任模型待决；覆盖证据主要来自沙盒与少数真机目标，产品边界保持 arm64-v8a only、ART 结构解析验证集中在 SDK 35/36。
- 候选方向供下一轮选题：①可追溯调查会话（现有原语的 CLI/MCP 编排）；② WS-I 确定性 crypto↔TLS 关联；③原生 I/O 路径定位。**这只是评估结论，不新增规格或第二份路线图**；选定后同步修改 `REQUIREMENTS.md` 与 `DEVELOPMENT_PLAN.md` 并给出独立 pass/fail 验收。

## 2026-10-01 —— 范围收口 + 9 条沙盒耦合命令真删（用户决议"收尾"）

**一句话**：两份"待确认"提案并入正文并删除原文（不再有第二份计划）；agent 里最后 9 条沙盒耦合命令真删，
能力改由 `capture_start` + `java_call` + `native_hook` 提供；连带 **6 个 MCP 工具 / 9 条 REST 路由 /
11 个验收脚本**改写；红线门禁从"agent 一侧"扩到"**两侧 + 不得回归**"。

### 1. 删的不是"类名耦合"——提案描述已被量测订正

提案写这 9 条"全写死调 sandbox 类、hook 写死 libjavacrypto"。**实测**：`grep -rn 'com\.adh\.sandbox' agent/src` 早就是 **0**，
类名一直由 daemon 传（`SANDBOX` 常量在 `daemon/src/state.ts`）。真正残留的是**触发契约**：
6 条命令把目标**方法名**写死成 `run()`（`()V` / `()Ljava/lang/String;` / `()I` 三种签名各占一处），
其中 3 条另外写死 `libjavacrypto.so`。这正是 §6.9.0 ① "所有 hook / trigger 目标一律来自命令参数"的违反点，
而 grep 门禁**结构上看不见方法名**。另发现同形态的第 9 条 `file_hook_test`（不在原列表里），用户确认一并删。

### 2. 能力怎么补回来（用户要求"能力不丢"）

| 被删命令 | 现在的真实路径 | 验收脚本 |
|---|---|---|
| `crypto_hook_test` / `net_hook_test` / `file_hook_test` | 持续捕获（`capture_start`，模块名由调用方给）+ `java_call` 触发 | v04_crypto / v07 / v20_file |
| `detect_watch` | 持续捕获的 **system 类**（ptrace/access/sysprop，只观测） | v05_detect |
| `flow_watch` | daemon 侧纯模块 `daemon/src/flow.ts`（读捕获流做 tid+200ms 关联） | v07_flow |
| `trace_run` | `native_hook mode=got` + `java_call` + 在事件 `x0` 处 `memory_read` 读回参数 | v10_trace |
| `inline_crypto_test` | `native_hook mode=inline`（相同 Dobby 入口 hook） | v28_inlinehook |
| `crypto_probe` | `got_enum` | v47 |
| `jni_probe` | `java_call` + `object_inspect`（读 `Build$VERSION.SDK_INT`） | v03 |

**新增 MCP 原语**：`capture_start` / `capture_stop`（此前躺在 `INTERNAL_OPS` 里、只有 Web 设置能开）。
两者共用一个实现 `service.ts:setCapture`，并由 v87 断言"不许绕过它直发 agent 命令"。

### 3. 过程中量出来的四个真问题（都不是"改完就好"）

1. **`capture_start` 的计数会撒谎**：`adh_got_replace` 按**槽位当前值**匹配，槽里已经是我们的 wrapper 时返回 0——
   与"这个符号没导入"无法区分。实测：重复 `capture_start` 报 `14/27`，**先 stop 再 start 报 `23/27`**，
   而剩下 4 个（`file.openat/read/write/syscall`）是 `libjavacore.so` 真的不导入。
   → 改成**先归零再装**（drain → stop → start），计数才是权威的；`rearmed:true` 如实标注。
2. **`capture_stop` 会静默毁掉 ring**（`cap_reset`）：新工具**先 drain 再 stop**，回报 `drained/drainedOk/dropped`，
   任一不干净 → `complete:false`。
3. **关联谓词曾经只认 `EVP_*`**：存储里的 **Java 层富采集**把记录命名成 `encrypt/digest/hmac`，
   照前缀匹配会**静默丢掉 65 条里的 61 条**。→ 改用 daemon 自己的 `category` 分类（`flow.ts` 里带单测锁住）。
4. **`live_captures` 回复里没有 `func`/`tsNs`**：脚本无法按"哪个边界触发的"断言。→ 补上（向后兼容）。

### 4. 牙齿检查（每条都留下"破坏后确实变红"的证据）

- `flow.ts` 把 tid 判等改坏 → `flow.test.ts` 10 条里恰好跨线程那条转红（8 pass / 1 fail）。
- 删掉 `MCP_TOOLS` 里的 `capture_start` → `v87` 报 3 条 FAIL（工具缺失 / 空描述 / 未声明裁决）。
- `v94_device_script_routes` 在编辑中途**如实报出**"还有 4 个脚本引用已删路由"——它就是这个改动的排序哨兵。
- agent 侧：`grep -c 'strcmp(op, "'` 42 → **33**，且 v87 新增"9 条禁令 op 不得回归"的断言。

### 5. 计数（都可现场复算）

agent 命令分支 **42 → 33**；MCP 工具 **69 → 65**；HTTP 路由 **93 → 84**；`INTERNAL_OPS` **6 → 1**；
门禁 **118 → 117**（eCapture 降级为实验脚本、移出闸门）；daemon 单测 **169 → 178**。
设备上 agent 换成**本机构建**的 `78d9d20f…`（1,036,832 B；当天第二次重建，见下）——本机现在能用 NDK r29 + cmake 构建 `.so`
（`HANDOVER §1.5` 已订正：那里原先写的"没有构建链"已过时），APK 仍需要 gradle。

### 6. 本轮门禁：**114 PASS / 1 FAIL / 2 SKIP**（117 条 = 36 host + 81 device）

设备 `aa165071`，设备上 agent `78d9d20f…`（本机 NDK r29 构建，且由 `install_apk_root` 自动回刷），
daemon 为本轮源码。**前两轮门禁的 device 半段验的是旧 agent**（见 §6.7），所以以这一轮为准。

**唯一的 FAIL**：`v01` —— 它自己会跑 `build_agent.sh` + `gradlew`，本机没有 gradle
（agent 那半本机已能构建，见 `HANDOVER §1.5`）。
**两条 SKIP 全是环境**：`v31`/`v32`（缺 gradle 重建 Xposed 模块 APK）。**`v37`/`v99` 已修成真跑**（见 §6.8）。

> 口径说明：本轮全量跑的是"功能上等价、但还差两处收尾修正"的 daemon 源码——
> 门禁开始后我又修了 `flowCorrelate` 吞掉 `maxPairs` 参数（本仓库禁止"接受但忽略的 flag"）
> 与一段只写不读的死状态，并重启 daemon 复跑了受影响的 host 门禁（`v71`/`v87`/`v10_mcp`/`v94`）与
> 一条设备脚本（`v04_crypto`），全部 PASS。后续 §6.5–§6.7 的三项修复各自都单独复验过。

### 6.5 追加：`v22_capture` 的记账缺口已定位并修复（本轮第二个实质修复）

**症状**：WS-C 的恒等式 `emitted+backlog+dropped == seq` **恒差 3455**（多次复现、数值稳定），
文档里挂了两轮"偶发、未定因"。先删掉两个嫌疑消费者（一次性探针 / `withCaptureSuspended`）后缺口**依旧**。

**根因（两层，第二层是真正的那层）**：

1. **口径不一致**：agent 的 `seq/dropped` 是它**整个进程**的累计值（跨 daemon 重启继续涨），
   而 daemon 的 `emitted` 只统计**本会话**收下的记录 → 任何一次重启都留下**永久偏移**。
2. **跨会话聚合把"途中态"冻成了永久残差**：`capture()` 先在锁外 `seq++`、再 trylock；
   若采样正好落在"已计数、结果未定"的窗口里，这一条就同时不在 ring 也不在 dropped。
   活会话下一次采样就自愈；但**会话结束在那一刻时就永久冻结**。门禁每个脚本都重启 App，
   于是几十个死会话各冻结一两条，累加成了几千——**看起来像静默丢记录，其实一条都没丢**。

**修复**（daemon + agent 各一处小改）：
1. health 按**会话基线**回报（原始 agent 值留在 `baseline`），恒等式在会话窗口内成立；
2. health **只聚合在线会话**，历史残渣单列 `staleSessions` / `staleResidual`（不折叠、不隐藏）；
3. 残差**拆成三类并各自命名**：`agentResidual`（agent 自算的 `seq-drained-backlog-dropped`）、
   `agentLost`（daemon 按同一式子算）、`daemonLost`（agent 弹出过但 daemon 没收下）；
4. agent 新增累计 `drained`（弹出过多少条）——没有它，"agent 真丢"与"daemon 丢响应"无法区分；
5. 记账**先于** `processDrain`，且**每轮 drain 各自记账**；
6. `/api/captures` 顶层的 health 字段改成 **spread**，不再手抄子集——
   手抄版悄悄漏掉了新字段，导致脚本可以"断言一个永远看不到的字段而通过"（这次就踩了）。

**验证**：连跑 5 次**精确成立**（含"只重启 daemon、agent 累计不变"这个原本必挂的条件）；
`agentResidual=0 agentLost=0 daemonLost=0 liveSessions=1 staleSessions=0`。

**排除过程也留档**（避免下次重走）：把记账顺序改回"先处理后记账"→ 仍通过（0 次 drain 失败），
说明顺序不是主因；停掉原生钩子 → 残差停止增长（锁定在原生捕获路径）；新会话单独看 → 两侧都是 0
（锁定为聚合产物）。

### 6.6 追加：`v05_detect` 在门禁里挂而单跑通过 = 切片问题

`live_captures` 列的是**整个 store**（最新在后），门禁里目标进程有其他系统类事件在跑，
于是 `limit:300` 那 300 条里**没有一条是本次触发产生的**（`events=300` 而 debug/root/prop 全 false）。
修法：按触发时间过滤（`ts >= t0`）并把 limit 提到 1000 —— 断言只认**本次触发**产生的事件。

### 6.7 追加：门禁的 device 半段一直在**验旧 agent**（本轮最该记住的一条）

v22 在门禁里第三次挂、单跑却过。查下去发现：**设备上跑的 agent 是 `82e0cfb5…`——最初那个**，
而本仓构建已经是 `78d9d20f…`。

- **覆盖点**：`verify_v02.sh` 会 `install_apk_root` 把 9/27 那个 APK 重装回去（v01 在本机早就死在
  `build_agent.sh` 的缺工具链那一步，所以不是它）。APK 里**自带一份 agent**，重装即把热替换的
  `.so` 覆盖回旧版。
- **后果**：`verify_v01/v02` 之后的所有 device 脚本，验的都是**旧 agent**。本轮我把 `.so` 换掉、
  重建、部署，然后跑门禁——门禁 "111 PASS" 而设备上跑的是三个版本前的二进制。**这就是 §3.1
  说的"门禁绿着撒谎"，只是这次撒谎的是我没有把部署闭环写进工具链。**
- **修法（一处）**：`install_apk_root` 装完 APK 后调用新的 `refresh_agent_so()`，把
  `agent/build/libadh_agent.so` 推回沙盒的 native 库目录（解压式安装 → 纯文件复制，不需要 gradle）
  与 Zygisk 模块目录，并打印两侧 sha。这样"装了 APK"这个动作**自己**保证设备跑的是本仓构建。
- **教训**：改 agent 源码后，"重建 + 部署 + 确认设备 hash == 本仓 hash"是一个不可省的闭环；
  本次已把最后一步做进工具链，不再靠人记得。

### 6.8 追加：把"环境 SKIP"变成真检查（v37 / v99 的跨平台进程控制）

`v37`（agent 重连）与 `v99`（工件重启后回流）都要**重启 Host ADH Daemon**，而它们用的是
`netstat -ano` + `powershell Stop-Process`——在 Linux 上 **no-op**，于是两条门禁在这台机器上
一直静默 SKIP。同一类坑还有三处：`v07`/`v07_flow`/`v34` 清理 TLS 夹具用的
`powershell Get-NetTCPConnection` + `taskkill` 在 Linux 上**也是 no-op**，结果**陈旧的 TLS 服务器会残留**
（实测：补上跨平台清理后第一次运行就杀掉了一个 8762 上的陈旧监听——正是文档警告的
"下一轮可能是在跟陈旧服务器对话而通过"）。

- 新增三个共享 helper（`tools/lib/verify_common.sh`）：`daemon_pid_on_port`（ss/lsof → netstat 回退）、
  `verify_stop_pid`（PowerShell / kill）、`verify_kill_port`（清端口）；`v07`/`v07_flow`/`v34`/`v37`/`v99` 改用它们。
- **顺带挖出一个真问题**：`v99` 重启 daemon 后只等 **10 秒**（20×0.5s）就发请求，而本机冷启动要
  **~45 秒**（SMB 上重新哈希 280 个工件）→ `ECONNREFUSED` 崩在 fetch 上。这正是它"以前只能 SKIP"的另一半原因。
  新增 `verify_start_daemon`（setsid 完全脱离终端 + 240s 预算），`v37`/`v99` 共用。
- **结果**：两条从 SKIP 变**真跑且 PASS** —— `v99`：重启后 **143 个磁盘工件全部重新采纳**、
  标 `disk-reload`、无悬空路径、预算可读；`v37`：daemon 重启后 agent **同一 pid** 重连、
  拿到**新 session**、通道可用（532 个模块）。

### 7. 未完成 / 已知代价

- **TRACEME 中和没有控制面**：唯一开关随 `detect_watch` 一并删除；要恢复须显式设计默认关闭的 opt-in（WS-J 已记录）。
- **eCapture 移出门禁**：能力覆盖随之失去（脚本仍在、手动可跑且本轮仍 PASS）。
- `capture_start` 的**先归零再装**意味着它会短暂卸下再装回钩子；这段时间目标产生的事件不会被捕获（已在工具描述里写明）。
- agent TCP `8761` 无鉴权仍是**未决**项（`REQUIREMENTS §20.1`）。

## 2026-09-29（二）—— 接手第一轮：环境定性 + host 门禁的真实数字（**29 PASS / 5 FAIL / 2 SKIP**）⚠️

**结论先说**：`docs/FEATURE_STATUS.md` 与 `HANDOVER.md §7` 记的"host 子集 36/36 PASS"**在本接管机上不复现**。
按 `RESULT:` 句柄分类，36 个 host 脚本的真实结果是 **29 PASS / 5 FAIL / 2 SKIP**。
逐条查完，**5 个 FAIL 里没有一个是"代码坏了"**，但其中 2 个是**测试自身有缺陷**（下面第 4、5 条），必须修。

### 1. 接管机档案与文档假设不符（已订正 `HANDOVER.md §1.5`）

- **本机是 Linux，不是 Windows，且没有构建链**：无 `cmake`/`ninja`/`clang`/`gradle`/`sdkmanager`；
  `/usr/lib/android-sdk` 只有 `platform-tools`。`sandbox-app/local.properties` 与
  `agent/build/CMakeCache.txt` 记的都是 **Windows 路径**（`C:\Users\diiho\…\ndk\28.2.13676358`）。
  → **`agent/build/`、`device/*/build/` 是 Windows 侧构建后经 SMB 落到共享树里的产物。**
  （只跑门禁不需要构建；要重建就得回 Windows 侧，或在本机装齐 NDK 28.2.13676358 + SDK + cmake 3.22.1。）
- 工作树挂在 **SMB2**（`//Russell.lan/X`）：daemon 冷启动 **~33s**（从磁盘恢复 290 个工件 / 1304 MiB），
  单个 host 脚本 40–80s，进程卡 `D` 状态是正常现象。
- `node` 实测 **v22.23.2**（文档写 v24）。strip-only TS 仍可跑，但 v24 的差异已经真实咬人一次——见第 4 条。

### 2. 设备侧：**不需要重刷**（度量过，不是推断）

补齐 OPPO/OnePlus 的 udev 规则（`51-android.rules` 原先只有 Google `18d1`，所以 `22d9` 报
`no permissions`）后 `aa165071` 恢复为 `device`。实测 `su -c id` → `uid=0(root)`（SukiSU Ultra）。

**设备上刷的包与 HEAD `c273ef4` 逐字节一致**：`libadh_agent.so` `82e0cfb5…`、`manager.apk` `e0b2a83d…`、
`daemon.apk` `87c2df98…`、`zygisk/arm64-v8a.so` `e565bfdc…`（模块 `v0.3.12`）。
→ `FEATURE_STATUS.md` 里"需重建 release bundle 后再刷机"是**过时结论**（已订正），**跑全量门禁不缺任何东西**。

### 3. 门禁数字要把 SKIP 和 PASS 分开算（**方法学订正**）

`HANDOVER.md §2.2` 给 A 组的配方是 `bash tools/$s >log && echo PASS`，**它把 SKIP 算成 PASS**
（SKIP 通常 `exit 0`）。本轮 31 个"PASS"里有 **2 个其实是 SKIP**：
`verify_v90_jni_table_abi.sh`（`RESULT:SKIP jni.h not found …/windows-x86_64/…`）与
`verify_v99_artifact_store.sh`（`RESULT:SKIP`，重启逻辑是 Windows-only 的
`netstat -ano` + PowerShell `Stop-Process`）。**"36/36" 很可能就是这么来的。**
→ 统计一律以各脚本的 `RESULT:` 句柄为准，别只看退出码。

### 4. 两个**真缺陷**（在被测代码以外——是**门禁自己**不可靠）

- **`verify_v101_crypto_variants.sh` 的第 1 步断言永远不可能成立**：它 `grep -qE '^ℹ fail 0$'`，
  而 `ℹ` 是 node **spec reporter** 的标记；只要输出不是 TTY（脚本用 `UNIT="$(…)"` **永远是管道**），
  node 就走 **TAP reporter**，打印的是 `# fail 0`。当天实测：单元测试 **13 pass / 0 fail 确实全过**，
  脚本仍报 FAIL。**这不是 node 22 的问题——是断言写死了 reporter 格式。**（同一模式还出现在
  `verify_v99` / `verify_v15_dumpall` / `verify_v100`。）
- **`verify_v99_artifact_store.sh` 的 reporter 分支少了 `exit 1`**：它打印
  `RESULT:FAIL (…unit tests did not all pass)` 之后**继续往下跑**，然后在 Windows-only 的重启逻辑上
  落到 `RESULT:SKIP` + `exit 0` —— **一条本该红的断言被后面的 SKIP 洗成绿**。

### 5. `verify_v29_dexindex.sh` 的 FAIL 是**可复现的**，不是抖动（**根因见第 11 条：库损坏，不是网络盘慢**）

它的通过条件含 **`hit.queryMs < 250`**（以及 `maxCachedMs < 250`）。实测该值 **465.86ms**（单独重跑同样 ~466ms）。
逐 dex 量下来根因是 **"索引后第一次查询"的一次性代价**，且随方法数爆炸：

| dex | methods | 索引后第 1 次查询 | 后续查询 |
|---|---|---|---|
| `classes.dex` | 58,775 | **49,237 ms** | 47,306 / 46,390 ms |
| `classes2.dex` | 251 | **2,914 ms** | 2,428 / 2,702 ms |
| `classes3.dex`（`hit` 落在这里） | 754 | **414 ms** | 35 / 38 ms |

结构原因（**已于第 11 条查明并订正**）：当时记的是"2.1 GB WAL 库放在 SMB 上 → 网络往返慢"，
**这个归因不准确**。真实原因是**库已损坏**（`SQLITE_CORRUPT`），49 秒是损坏库的行为，
不是网络盘的正常往返代价——同一个索引挪到本地盘后，`queryMs` 是 **1.72ms**，整个 `unpack` 1 秒。
见第 11 条。**唯一成立的那部分结论**：250ms 这个预算是照健康库定的，它确实在**库坏了**的时候先红。

### 6. 三个纯环境 FAIL（缺 Windows 路径下的 LLVM 工具）

`verify_v08_disasm.sh` / `verify_v08_analyze.sh`：daemon 报
`spawn …/windows-x86_64/bin/llvm-objdump.exe ENOENT`；
`verify_v26_footprint.sh`：直接调 `tools/lib/env.sh:17` 写死的
`…/windows-x86_64/bin/llvm-readelf.exe`，于是 `defined-exports=none` 而断言失败。
`daemon/src/analysis.ts:12` 与 `env.sh:17` **都把 Windows 工具链路径写死**（`analysis.ts` 可用
`ADH_LLVM_BIN`/`ADH_OBJDUMP`/`ADH_READELF` 覆盖；`env.sh` 的 `READELF` **不可覆盖**）。
→ 装 `llvm`（apt 有 21.1.6）能给 daemon 两个工具，但 `env.sh` 得先改成 host-aware；
`verify_v90` 还要 NDK 的 `jni.h`（sysroot）。

### 7. 全量 118 条门禁已跑完：**103 PASS / 11 FAIL / 4 SKIP**（`HANDOVER §5` 第一梯队第 1 项 ✅）

OPPO 插回并授权后跑 `tools/verify_all.sh`（先 `export ANDROID_SERIAL=aa165071`，见第 8 条）。
分档：**host 36 = 29 PASS / 5 FAIL / 2 SKIP**；**device 82 = 74 PASS / 6 FAIL / 2 SKIP**。
设备未重刷（跑前复核四个文件 sha256 仍与 HEAD 一致），`su -c id` → `uid=0(root)`。

**11 条 FAIL 没有一条能归到产品代码**：

| 类别 | 脚本 | 根因 |
|---|---|---|
| 环境（缺 Windows 工具链 / 依赖是 Windows 装的）· 7 | `v01` `v02_so` `v08_disasm` `v08_analyze` `v26_footprint` `v29_dexindex` `v30_fridagadget` | `cmake.exe`（`v01`）；`llvm-readelf.exe`/`llvm-objdump.exe` 写死在 Windows NDK 路径（`v02_so:10` / `env.sh:17` / `analysis.ts:12`）；`v29` 见第 5 条；**`v30` 新查出**：`tools/frida/node_modules/esbuild` 装的是 **`@esbuild/win32-x64`**，Linux 上 `bundle failed`，所以 Gadget 脚本打包不了（`loader rc=1`） |
| **门禁自身缺陷** · 2 | `v100_adh_cli` `v101_crypto_variants` | 第 4 条那个 `^ℹ fail 0$` 断言——**两条都被赛前预测命中** |
| 文档已登记的偶发/未定因 · 2 | `v72_site_hooks_cross` `v22_capture` | `v72` 失败形态与 `FEATURE_STATUS.md §2` 记录的**逐字相同**（`scopeAll.siteCount:0` / `hits:3` / `scopeNamed` → `target already hooked by id 1`）；`v22` 是那条已知的记账抖动 |

**4 条 SKIP 也全是环境**：`v37_agent_reconnect`（`netstat -ano | grep LISTENING`，Linux 打的是 `LISTEN`
→ 匹配不上）、`v90_jni_table_abi`（缺 NDK `jni.h`）、`v32_backend_control`（`gradle unavailable`）、
`v99_artifact_store`（重启逻辑 Windows-only）。**赛前那张"可预期环境噪声"表里 4 条全部命中**，
没有出现意料之外的红——这一点本身就是结论：**device 半段在这台机器上是健康的**。

对照 2026-09-23 的 `113 PASS / 0 FAIL / 0 SKIP`（当时 34 host + 79 device = 113）：脚本数从 113 长到 118，
红的全部落在上面这些类别里，**没有一条指向被注入的代码**。

### 8. `verify_all.sh` 自身的多设备隐患（**已发现，未改**）

它开头调 `bash tools/dev_up.sh`（不带 serial），device 脚本前又跑
`adb shell am force-stop com.adh.sandbox` / `am start`（**也不带 `-s`**）——多设备时都会落到
`adb devices` 的第一台（本机曾是那台未授权的 Pixel）。**跑之前必须 `export ANDROID_SERIAL=<serial>`**
（adb 自己认这个变量，所以一处 export 就全覆盖）。这条**没有改代码**，只是记下来。

### 9. 门禁守卫修复：把"永远匹配不上"的断言收成一处实现 ✅

第 4 条那两个缺陷（`v100` / `v101`）已修，并**顺带发现 `v15_dumpall` 和 `v99` 犯的是同一个错**——
两处都是**打印 `RESULT:FAIL` 之后没有 `exit 1`**，继续往下跑，最后由后面的 `verify_gate` 用
`RESULT:PASS` 把失败**盖成通过**。所以"失败被洗成绿"是**两处**，不是一处。

**修法：加一个共享 helper，不再各抄一份**（`tools/lib/verify_common.sh`）：

```bash
verify_unit_pass "<label>" <test-file> [min_pass]
```

它做四件事：① 解析**两种** reporter（`ℹ fail N` spec / `# fail N` TAP）并先剥 ANSI；② 要求
`rc == 0`；③ 要求 `fail == 0`；④ **要求 `pass >= min_pass`**（下限）。调用点：
`v101`(13) / `v99`(8) / `v15_dumpall`(4) 改用 helper 并 `exit 1`；`v100` 的断言在 JS heredoc 里，
按同样口径改（`unit.status===0 && fail===0 && pass>=10`，并剥 ANSI）。

**为什么必须带下限**：`node --test` 对一个**加载失败的**测试文件也可能退 0，只查 `fail 0` 会放过
"静默空跑"；下限同时挡住"用例被删光还绿"。

**按 §3.1 验牙齿**（不是只看它变绿）——把被测能力临时破坏，断言守卫必须红。5 项全过：

| 齿检 | 结果 |
|---|---|
| 真跑通过 → 绿 | OK |
| 塞一个**必然失败**的用例 → 必须红 | OK 红 |
| 测试文件**不存在** → 必须红（防静默空跑） | OK 红 |
| `min_pass` 高于实际用例数 → 必须红；等于 → 绿 | OK 红 / OK 绿 |
| 两种 reporter + **带 ANSI** 的 spec 输出都能解析 | `#`/`ℹ`/带色 `ℹ` 三种输入都正确取到数字 |

（探针测试文件用完即删，已确认不在仓里。）

**逐个复跑结果**：

| 脚本 | 修复前 | 修复后 |
|---|---|---|
| `v101_crypto_variants.sh` | FAIL（单元门假红） | 单元门 `pass=13 fail=0 rc=0` → 第 2 步**如实 SKIP**（本机没 clang）。装上工具链后会真跑第 3+4 步 |
| `v99_artifact_store.sh` | **假 SKIP**（`RESULT:FAIL` 被洗掉） | 单元门 `pass=8 fail=0` → 之后如实 SKIP（重启逻辑仍 Windows-only） |
| `v15_dumpall.sh` | 结局对、但失败会被洗掉 | 单元门 `pass=4 fail=0` → **device 段全绿 `RESULT:PASS`**（4 dex dump/去重/下载/分类/索引） |
| `v100_adh_cli.sh` | FAIL（单元门假红） | **22 checks / 0 problems 全绿** |

`v100` 转绿还**顺带完成了 `HANDOVER §5` 第一梯队第 2 项**：`adh target` / `adh unpack` 的
**真机端到端第一次真正跑过**（"target resolves the agent and reports live facts"、
"unpack classifies every DexFile (real vs carrier)"、"--out is consumed: one file per REAL dex
lands on disk with the reported byte count" 全过）——此前 `FEATURE_STATUS` 记的是"真机端到端尚未验证"。

### 10. `v100` 在门禁里是**另一条** bug 导致的红（修完后另发现 2 个真缺陷）

修完第 9 条后全量复跑，`v101` 如期由红转 SKIP，但 **`v100` 仍然红**——且**不是**断言失败，是
**JS 异常崩溃**：`[eval1]:157:49`。两轮门禁的崩溃行号相差正好 8 行 = 我那次编辑加的行数，
即**同一逻辑行**。追下去是**两个独立于本次修复的真缺陷**：

**(a) `v100` 里 4 处裸解引用 `report.dexCount` 让脚本崩掉，把真失败藏在栈里。**
`report = dryJson?.report`（dry `unpack` 没产出可解析报告时是 `undefined`），同段其它每一处都写了
`report?.`，只有 `--include-carriers` 那两行的 4 处是裸的 → `TypeError: Cannot read properties of
undefined (reading 'dexCount')`，**整个脚本当场挂掉**，`problems` 一条都打不出来。
改成 `report?.dexCount` 后不再崩，而是**如实判负**并打出 `expected=undefined`。
（齿检：`node -e` 直接对 `undefined` 跑两种写法——旧写法抛 TypeError，新写法表达式为 `false`、报文可读。）

**(b) `adh doctor` 会把**已经退出的进程**当成"刷入的 agent"，于是刷机升级后**永远报 MISMATCH**。**
`daemon/src/cli.ts` 的版本配对循环遍历注册表里**所有** agent，**不筛 `online`**。
实测注册表里有 4 条：3 条 `offline`（其中 `com.adh.manager agentVer=0.2.0` 是**好几次刷机之前**留下的
进程记录）+ 1 条 `online`（`0.3.12`）。于是源码 `0.3.12` 与模块 `v0.3.12` 明明一致，
`doctor` 却报 `MISMATCH with the flashed agent` 并 `❌ FAIL` ——而**磁盘上的 .so 本来就是新的，
"重刷"根本治不好**。这正好砸在 `HANDOVER §2.5` 说的用途上（"doctor 会直接告诉你该不该重刷"）。
修法：只把 **`online`** 的进程算作"刷入的 agent"，并把忽略掉的 offline 条数**显式报出来**
（`in-sync with the running agent (3 offline session(s) ignored)`），不再用
`problems.some(p => p.includes('runs agent'))` 这种字符串反查来推 drift。

**齿检（§3.1：必须证明警报没被捂死）**：把 `agent_internal.h` 的 `AGENT_VER` 与 `module.prop` 的
`version=` 一起改成假值 `9.9.9-TEETH`，`doctor` **立刻**报
`MISMATCH with the running agent` + `❌ doctor FAIL`，并点名
`com.adh.sandbox (pid 13242) runs agent 0.3.12 but this checkout builds 9.9.9-TEETH — rebuild+reflash: …`。
改完用备份还原，`git status` 干净、两个值回到 `0.3.12` / `v0.3.12`。
→ **假阳性去掉了，真检测还在，而且现在会报 pid。**

**(c) 顺带观察（未修）**：一轮全量门禁把沙盒 `force-stop`/`start` 了 82 次，`/api/agents` 会积到
`agents 4`（3 条 offline + 1 条 online）——**已退出的会话不会当场清掉**，`doctor` 的 listing 因此变长。
**但不是"只增不减"**：2026-09-30 复查时（同一个 daemon 进程，uptime 26.4h 未重启）设备一拔掉
注册表就回到 **0 条**，说明**断连时会清**。所以是"一轮之内越跑越吵、设备断开即清"，
不是无界泄漏。已由 `v35_sessions` 覆盖会话清理；门禁自身仍无清理步骤。

### 11. **dex 索引库损坏** —— "偶发 device 失败"的真根因；顺带修掉一串"失败被静默吸收" ✅

**起因**：修完第 9/10 条后，`v100` 在全量里**第 3、4 轮仍然红**，而且第 4 轮连**前三轮都绿的
`v15_dumpall` 也红了**。两条都不是崩溃，是"agent 不可用"式的失败。三个不同脚本红在同一条路径上，
就不该再当成 flake 了。

**根因（一次复现拿到）**：`adh-data/dex-index.sqlite` **已损坏**。直接打 REST 路由（绕过 CLI）拿到：

```
classifyError = "database disk image is malformed"     ← SQLite 的 SQLITE_CORRUPT
—— 4 个 dex 里 3 个是这样
```

**为什么坏了**：这个库在 **SMB 共享树**上，而**同一棵树被两台机器同时在使用**——
最直接的证据是：**在 Linux 上连把它改名都做不到**（`mv` → `设备或资源 busy`；`truncate` 能成功、
`rm` 报 `输入/输出错误`），而本机**没有任何进程**持有它。**远端写者**才是答案。
（SQLite 官方也确实说 WAL 不能用于网络文件系统，但那是**次要**因素：
实测到的真因是并发写者，改日志模式防不住——所以**没有改默认值**。）

**为什么藏了四轮**（两层静默吸收，都是"不 fail-loud"）：

1. `daemon/src/service.ts` 的 `realDexCount = dexes.length - carrierCount`——**分母来自 `dexes.length`**，
   于是 3 个根本没分类成功的 dex **照样算成"真代码"**。回包 `realDexCount: 4` 却只有
   `realBytes: 489960`，**两个本该一致的数字互相矛盾**，这就是线索。而 `v15_dumpall` 的恒等式
   `real + carrier === dexCount` 因为右边也是同一个推导，**永远成立、等于没测**。
2. `daemon/src/cli.ts` 的 `reportSummary` 只投影
   `sha256/bytes/classes/methods/carrier/shape`，把 `service.ts` **已经记下来的
   `classifyError` 丢掉了**（外层 catch 写的 `error` 同样被丢），于是 `problems: []`、
   `failed: 0`——**看起来完全正常**。

**修法（三处，都是"别静默"）**：

- `service.ts`：`realDexCount` 改成只数**分类明确判为真代码**的（`carrier === false`），
  并新增 `unclassified` 与顶层 `classifyError`。谎报的 `4` 变成如实的 `1`。
- `cli.ts`：`reportSummary` 带上 `classifyError`/`error`/`unclassified`；人读输出把未分类的
  dex 标成 `failed`（此前标 `real`，和警告自相矛盾）、打出
  `⚠ 3 of 4 dex(es) could not be classified — database disk image is malformed`，
  并**计入 `problems`**（→ `❌ unpack: FAIL` + `exit 1`）。
- `v15_dumpall`：恒等式补上第三个桶（`real + carrier + unclassified === dexCount`），
  这样"有人没被记账"就真的会红；失败时**打出原因**而不是只打计数。

**根因修复**：`state.ts` 新增 `ADH_DATA_DIR`（默认不变，仍是仓库内 `adhd-data/`），
把数据目录指到**本地盘**。实测同一份数据：

| | 库在 SMB（损坏） | 库在本地 NVMe |
|---|---|---|
| `adh unpack` 分类 | **1/4**（3 个 `SQLITE_CORRUPT`） | **4/4**，1 秒 |
| `v29` 的 `queryMs` | 466ms（预算 250ms）→ FAIL | **1.72ms** → PASS |
| `v15_dumpall` | `shaped=1/4` FAIL | `shaped=4/4 unclassified=0` PASS |
| `v100` | 4 条 agent-不可用式失败 | 全绿 |

→ **第 5 条对 `v29` 的归因（"网络盘往返慢"）据此订正：那是损坏库的行为，不是网络代价。**

**顺带查到**：`v07`/`v07_flow`/`v34` 起的 TLS 测试服务器在 Linux 上**杀不掉**（清理走 PowerShell，
是 no-op），实测残留了一个活了 23 小时的 `daemon/tls_test_server.mjs`。副作用不只是脏——
**下一轮 `v07` 可能是在跟这个陈旧服务器对话而通过**。

### 12. `v100` 门禁内必红 —— **已定位并修复：它解析到了 ADH Manager，不是沙盒** ✅

**事实**：`v100_adh_cli` 在**六轮全量门禁里全部红**，而**单独跑全绿**（含复刻门禁时序）。

**根因（第 6 轮那条"给失败加诊断"的改动直接命中）**：加诊断后门禁第一次就把它打了出来——

```
adh: target com.adh.manager is not usable (agent did not answer agent_ping; art_dexfiles failed: unknown)
adh: /api/unpack/dump-all -> HTTP 504: { "error": "command timeout" }
```

`v100` 取的是 `online[0].package`（**没有按包过滤**）。而 **ADH Manager 自己也被同一个 Zygisk 模块注入、也会注册成 agent**；
门禁里 **`verify_v31_xposed`**（就在 `v100` 前一位）会把 `com.adh.manager` force-stop 后重启以测 Xposed 薄模块
（`TARGET="com.adh.manager"`），于是 Manager 成为"第一个 online"，`v100` 的**全部 agent 相关断言**就都对着
一个不会 dump dex 的进程跑。**单独跑时 Manager 不在运行**——所以六轮全红、单独必绿。
修法与其它 device 脚本一致：**按 `com.adh.sandbox` 过滤**（`online` 只按 `online` 过滤本身就是错的）。

**另有一条容易混淆的情况值得记下**：agent 可能**已注册为 online 但实际不响应**
（`agent_ping` 不通 / `art_dexfiles` 返回 `unknown` / `dump_all_dex` → `HTTP 504 command timeout`）。
经历整轮门禁之后的长命沙盒就会是这样，**而门禁会为每个 device 脚本重启沙盒所以看不到**；
单独复现时必须自己先 `force-stop` + `start`，否则会把"陈旧沙盒"误当成别的问题（我就先踩了一次）。

**验证**：修复后按门禁完整时序（重启沙盒）跑 → **22 checks / 0 problems PASS**，
且注册表里存在 Manager 条目时仍正确解析到沙盒。**仍需第 7 轮全量确认门禁内转绿**（单跑过 = 不算）。

### 13. Xposed 模块里**悄悄捆着三版本前的 agent**（`doctor` 是对的，测试是错的）✅

**发现路径**：第 6/7 轮 `v100` 换成在 **`doctor` 断言**上红，注册表给出原因：

```
com.adh.manager  pid 22542  online  entry=jni_onload  agentVer=0.2.0     ← 源码是 0.3.12
  loaded as:                      （selfModule 为空——0.2.0 那个年代还没这个字段）
```

**根因**：已安装的 Xposed 模块 APK **自己捆了一份 agent**，仓库里那份是 **0.2.0**（322,032 字节），
而当前 checkout 构建的是 **0.3.12**（1,030,312 字节，sha `82e0cfb5…`）。
把这份旧 agent 弄上线的是 **`verify_v31`**——它以 `com.adh.manager` 为目标做 force-stop + 重启，
而它**正好跑在 `v100` 前一位**。

`tools/build_xposed.sh` 本身是**对的**：它把当前 agent 拷进 jniLibs，还校验 APK 里那份是否过期
（`die "module APK still carries a stale libadh_agent.so"`）。**但 `verify_v31` 只在 APK *不存在*时才重建**——
文件在，于是这份过期副本被无限复用。

**修法**：`v31` 现在把"捆的 agent 与 `agent/build/` 不一致"视同"缺失"，重建并复检。
**在没有 gradle 的机器上重建会失败，于是它如实 SKIP 并给理由**，而不是拿一个**我们并不发布的 agent**
跑通之后报 PASS：

```
RESULT:SKIP module APK stale and not rebuildable
⏭ Xposed backend SKIP (agent 0.2.0 bundled, gradle/AGP unavailable to rebuild)
```

**这不只是测试问题**：**Xposed 后端可能一直在目标进程里跑旧 agent 而没人发现**——
对一个"前提是你知道目标进程里究竟跑着什么"的工具来说，这是实打实的缺陷。
（顺带解释了 `v100` 六轮全红：gate6 是它解析到 Manager 本身（已修），gate7 是 `doctor` 因这个 0.2.0 报 MISMATCH。）

### 以前未解决时排除过的五条路（保留，避免重复走）

| 假设 | 实验 | 结论 |
|---|---|---|
| 索引库损坏 | 移到本地盘、4/4 分类 | 已修，v100 仍红 → 不是它 |
| 同一沙盒上重复跑会坏 | 连跑两次 v100（不经重启） | 两次都 PASS，pid 不变 → 排除 |
| 注册表出现两个 online 会话 → `target` 判为歧义而拒绝 | 重启后逐秒采样 12 秒 | 始终只有 1 个 online；`adh target` 正常解析 → 排除（**但方向对了：确实与"哪个 agent"有关**） |
| 沙盒被 LMK/低内存杀掉 | 设备 logcat 查杀进程记录 | 只有显式 force-stop，无 LMK 记录；daemon 日志显示失败窗口内会话未断开 → 排除 |
| `v22_capture` 的爆发把 daemon 拖到超时 | `v22_capture` 后紧接跑 v100 | v100 PASS → 排除 |

### 顺带记录

- `tools/dev_up.sh` 用 `adb devices | awk 'NR==2{print $1}'` 选设备：本机 `NR==2` 是那台**未授权**的
  Google 机，于是 `adb reverse` **静默落在错的设备上**。跑之前必须
  `export ANDROID_SERIAL=aa165071`（`flash_device.sh` 同理）。
- `tools/frida/node_modules/` 是**跨 OS 共享树上的 Node 依赖**：Windows 装的就带 `@esbuild/win32-x64`，
  Linux 上跑不了 `v30`；反过来在 Linux 上 `npm install` 也可能顶掉 Windows 那份。**这类依赖不该跟着 SMB 树走。**
- 容器/主机侧都没改任何被测代码；本轮只改了文档 + 一条 udev 规则。

## 2026-09-29 —— 变异算法识别：补上"加解密"这一项的整类漏检 ✅

**问题（度量出来的，不是推测）**：ADH 识别加解密有两条路——运行时按**调用到哪个库函数**命名（`crypto_capture`），
以及按**标准常量**在二进制里找（`native_crypto_const` 的固定 9 条表）。**一个自己实现算法并魔改的 App 同时
绕过两条**：没有库调用可命名，也没有标准常量可匹配。更糟的是旧扫描**不是安静地瞎，是会主动误导**——见下面验收里
那条断言：对教科书库与变异库它返回**完全相同的算法名**，并且在变异库上仍报 `MD5-init`（那是 SHA1 init 的前 8 字节
撞上的**假阳性**）。

**形态是从真实样本确认的**，不是我想的：研究参考仓库 `CYRUS-STUDIO/CyReverse`（135MB，clone 到仓库外）得到
四份真实变异，四种形态各不相同——

- `md5_change_constant.cpp`：**K 表不动，init 被原位改写**，且只改每个字的**最高字节**（`0xaa452301` vs `0x67452301`）
- `sha1_change_constant.cpp`：**镜像**——IV 不动，**5 个轮常量被改写**（`0xAA827999/0xBB827999/0xCCD9EBA1…`）
- `custom_base64_alphabet.cpp`：标准字符集的 **64 字符置换**（大小写互换 + URL-safe 尾巴）
- `dynamic_base64_alphabet.cpp`：码表**运行时按输入长度算**（`out[i ^ (len%64)] = std[i]`）——静态注定看不见
- `custom_crc32_table.cpp`：多项式被换成 **`0xd76aa478`（MD5 的 K[0] 被拿去当 CRC 多项式）**，表还是运行时生成的

**修法**
1. **`daemon/src/crypto_variants.ts`（新，纯函数）**：按**结构**识别，而不是按标准常量。核心规则是"变异者通常
   只改一部分，所以要用**活下来的那部分**做锚点"：MD5 由**未被改动的 K 表**锚定、缺席的 init 作为变异证据；
   SHA1 **从另一端**锚定（IV 在位、轮常量缺席）。变异判定**必须带证据**（缺了哪个标准件 + 被改的那份有多接近，
   例如"16 字节窗口与标准 init 相符 12/16"）。base64 码表按**形状**找（64 个互不相同、几乎全在字符集内、且是被
   隔离的一段），并数出漂移量。`limits` 字段**主动自述盲区**（运行时生成的表、连锚点一起改的变异、单个 32 位常量
   不足为凭——`0xd76aa478` 既是 MD5 K[0] 也被那套变异 CRC 当多项式用了）。
2. **接线**：REST `POST /api/native/crypto_variants` + MCP 工具 `crypto_variant_scan`（工具数 68→69；`native_crypto_const`
   的描述里加了指向它的那句，否则调用方找不到第二层）。标准常量表 `CRYPTO_CONSTS` 从 `analysis.ts` **导出复用**，
   不留第二份。
3. **编译靶子 A/B**：`fixtures/crypto-variants/{std,variant}.c` + `tools/build_crypto_variants.sh` → 两个真实
   arm64 ELF（`-O0`，否则常量会被折进立即数、靶子就不再含有自己的常量）。`std` 是教科书常量（负对照），
   `variant` 携带上面那几种真实变异。

**验收（host，无需设备）**
- `daemon/test/crypto_variants.test.ts` **13/13**（向量取真实变异字节）；`verify_v101` **11/11** 断言，`RESULT:PASS`。
- 负对照成立：教科书库**一条 variant 判定都没有**；变异库给出 `MD5:variant`（缺 init，12/16）、`SHA1:variant`（缺轮常量）、
  `base64 variant(subs=54)`，并把 CRC-32C 如实报成"另一套标准"而不是变异。
- **缺口那条断言**（这是本轮的核心证据）：旧扫描对两个库返回**同一组算法名**，且在变异库上报 `MD5-init`——
  一个假阳性。新层给出的正是旧层给不了的**判定**。
- **编译靶子当场抓到一个合成单测抓不到的真 bug**：MD5 的 16 字节 init 是 SHA1 的 20 字节 init 的**前缀**，
  于是"MD5 init 是否存在"对任何同时含有 SHA1 的镜像都答 yes——变异库因此被误判成 `MD5:standard`。
  13 条合成单测全绿也没抓到它，因为它们的 buffer 从不同时含两份 init，而**真实 .so 通常两份都有**。
  已修（按 SHA1 init 的偏移过滤），并补了一条单测与一条断言。这条是"为什么靶子必须编译、不能自己拼"的实证。

**仍然不能覆盖的（下一步，不在本轮承诺内）**：运行时生成的码表（动态 base64）、连锚点一起换掉的变异
（自定义 S-box / 自造轮函数）。后者只能靠**指令级结构**（`trace_digest`/QBDI）或运行时捕获——那是下一片。

## 2026-09-28 —— `adh` 命令行：把"解析目标"收成一处 ✅

**问题**：ADH 在产品意义上**没有命令行**——`daemon/package.json` 没有 `bin`，`src/` 下没有 `cli.ts`，
命令行面只有「启动 daemon + 117 个验收脚本 + curl」。代价可以量化：**117 个 verify 脚本里 114 个内嵌 node
脚本，其中 76 个各自重抄了一遍"找在线 agent → 按 `connectedAt` 取最新 → 拿 sessionId"**；我自己每轮开工
也手抄一次，加 `verify_v98` 时还是照抄。对照组是刚审计完的 `xls-probe`：有 `doctor`、`--json`、退出码把
"断言失败"与"没测成"分开，ADH 在这件事上比它的用户项目还原始。

**修法**
1. **`daemon/src/cli.ts`（新）**：`adh` CLI，**纯客户端**——只 import `config.ts`（无 import 即无漂移，
   且同一份可打远程 daemon）。`doctor` 报 daemon 健康 + **刷入的 agent 版本 vs 本仓源码版本**配对
   （读 `agent_internal.h` 的 `AGENT_VER` 与 `module.prop`，再与 agent 自报的 `agentVer` 比）+ 后端矩阵；
   `target` 解析**唯一** agent 并报活体事实（ping / `memBackend` / `libartJniGetVms` / dex 数）；
   `unpack` 一键 `dump_all_dex` + 逐 dex 分类 + `--out` 落盘（默认只落真 dex）。
   退出码复用门禁三态，不另立词汇：`0 ok / 1 fail / 2 usage / 3 unavailable`（= SKIP）。
   歧义目标**必须报错**（列出候选与 `--package`/`--session` 建议），绝不静默换一个进程——这是这条命令唯一不能犯的错。
2. **flag 纪律**（`cli.ts` 顶部写清，两条守卫兜住）：flag**按子命令**声明，未知/错位 = 用法错（exit 2）；
   `daemon/test/cli_args.test.ts` 断言"声明了就必须有人消费"；`tools/verify_v100_adh_cli.sh` 断言
   "每个 flag 都有**可观测效果**"。理由是实的：接受但忽略的 flag 比没有这个 flag 更糟——命令 exit 0
   却做了别的事，而操作者会信它（`xls-probe --proxy`，见 `CASE_STUDIES` 邻仓审计）。
3. **`tools/verify_v100_adh_cli.sh`（新，注册为 `:device`）**：13 条 daemon 侧断言 + target/unpack 侧断言。

**过程中量出来的两个真问题**（都不是猜的）
- 最初用 `fetch` + `AbortSignal.timeout`：abort 确实在 2s 触发，但进程**又活了 8.7s**（undici 的待决 connect
  句柄在 Windows 上不可取消），改用 `process.exit` 还会撞 libuv 断言。→ 换 `node:http` + 显式 destroy。
- 换完仍然**谎报**：`req.setTimeout` 只约束 socket **空闲**、不约束 connect，于是 `--timeout 2` 的错误
  在 **5106ms** 才出现、文案却写着 "timed out after 2s"。→ 改成自己的墙钟定时器（实测 2090ms 出结果、
  2099ms 退出），并让 `verify_v100` 断言这个界（`< 4000ms`）——**这条断言就是防它回退成谎话**。
- 顺带记一条环境约束：本仓无构建步骤，node 以 strip-only 跑 `.ts`，**TS 的 parameter property
  （`constructor(readonly x: T)`）不被支持**，直接语法错。新写的 `.ts` 别用。

**验收**
- `daemon/test/cli_args.test.ts` **10/10**（含"AGENT_VER 与 module.prop 必须同步升"这条真回归守卫）。
- `verify_v100`：daemon 侧 **13 条全过**；`doctor` 0.19s 干净退出（stderr 0 字节）；`--port` 错 → exit 3
  且报文点明端口与 `ECONNREFUSED`；未知/错位 flag → exit 2 并列出可接受集合；`--json` 可解析。
- **真机那半本轮未跑**：设备当时是 `a22fecdd unauthorized`（需要手机上点"允许 USB 调试"），
  所以 `target`/`unpack` 的端到端**仍属未验证**，脚本在无 agent 时按规矩 SKIP（exit 0 + 末行 `SKIP (...)`），
  不计入"已验证"。设备回来后的第一件事就是跑完整 v100。

## 2026-09-26（三）—— 按计划加固：第 1 项 验证真实化（WS-L）✅

> 从学习通案例的 5 条工具级结论出发，按 `CASE_STUDIES.md` 的顺序逐项修复。
> **第 1 项优先**：它让后面每一项都在真实路径上被验证。路线图新增 **WS-L**（`DEVELOPMENT_PLAN §6.9.1`）。

**问题**：79 个 device 验收全跑在沙盒自加载路径上，那条路径**结构上不可能**产生 memfd 加载的 agent、
也不会遇到拒绝 `/proc/self/mem` 的目标。于是 `art_dexfiles`/`java_hook`/`trigger` 与整条读内存链路
在真机上整组死掉，门禁却全绿。更具体地：`verify_v75_zygisk_memfd.sh` **已经创建了那个真实条件**
（注入非沙盒 App、`entry=start`、memfd 身份）却只断言 `compat_probe.agentExecMappings>=1`——
**从不断言 Java 能力**，所以 agent 拿不到 JavaVM 时它照样 PASS。

**修法**
1. 新增 `tools/verify_v98_injected_java_surface.sh`：复用 v75 的 scope 快照/恢复 + 冷启动技术，
   断言注入 agent 的 `compat_probe.backends.jniReflect/artDexCapture === true`、
   `libartJniGetVms === true`、`art_dexfiles ok === true`、`java_enum(java.lang.String)` 走通反射。
2. agent 新增**强制直读**：`mem_read.c` 的 `adh_mem_fd()` 在被强制时直接返回 -1，于是
   `cmd_read`/`cmd_search`/`cmd_scan_magic`/`art.c`/`trace` **全部自动走直读分支**（各调用点本就按
   `mem >= 0` 分支，无需改动）。新 op + MCP 工具 `mem_backend`（`auto|direct|proc`）。
3. 扩 `verify_v97_memread_direct.sh`：强制直读后断言 `memory_search` / `memory_scan_magic` /
   `art_dexfiles` / `memory_dump` **全部仍工作**，且分块 dump 与自动路线 **sha 相同**，然后恢复 auto。

**验收（含 mutation 对照，证明测试不是摆设）**
- `verify_v98`：把 JavaVM 查找临时改成 `return NULL`（模拟修复前）→ **FAIL**，症状是与真实缺陷一字不差的
  `jniReflect=false artDexCapture=false` + `art_dexfiles: ok=false error="no JavaVM"`；
  恢复修复 → **PASS**。
  · 这个对照还暴露一个设计要点：`libartJniGetVms` 在变异版里**仍然是 true**（符号查找没被变异），
    所以真正抓到 bug 的是**能力断言**，不是机制断言——两层都留着是对的。
- `verify_v97`：15 项断言全 true（含 `searchOnDirect` / `scanOnDirect` / `dexOnDirect` / `dumpIdentical`）。
- **学习通真机复验**（新 agent）：`memBackend=direct` / `memOpenErrno=13` / `memRead=true` /
  `jniReflect=true` / `art_dexfiles 14 DexFiles` / 强制直读下 search + art_dexfiles 仍工作。
- **顺带确认**：`com.android.settings` 上也是 `memBackend=direct` —— **第二个真实目标同样拒绝
  `/proc/self/mem`**，说明这条回退不只对学习通有价值。

### 第 2 项 — 工件生命周期（持久化 + 回收）✅

**问题**：`dumps` map **只在内存**，daemon 重启后磁盘工件全部"消失"（`dumps_list`/`/api/dumps`/按 sha 下载/
`dex_index` 一律答"没有"，而文件好好躺在 `captures/`）；且磁盘**没有任何回收**，本轮实测留下约 1.27GB。

**修法**（纯 daemon）
- `daemon/src/artifacts.ts`（新，**纯模块、无 fs/state 依赖**）：`artifactKindOf` 认三种命名
  （`<sha16>.<kind>.bin` / `<sha16>.so` / `<sha16>.dex`），`planArtifactEviction` 定回收策略。
  抽成纯函数是为了**能直接单测**——`state.ts` 拥有存储，这个模块拥有决策。
- `state.ts`：启动时 `loadArtifactsFromDisk()` **重新哈希并采纳** `captures/` 里的文件（流式哈希，
  大 dump 不爆内存）；来源标 `disk-reload` 而不是编造 session/addr/tag；新增
  `settings.artifacts{maxBytes:8GiB, maxAgeDays:14}`（可经 `/api/config` 调）与 `pruneArtifacts()`；
  `configStats().artifacts` 让回收**可观测**而不是后台静默规则。
- `service.ts`：`pruneArtifactsAndIndex()` 把回收接到 **dex 索引行**的删除上（删了 dex 文件还留着索引行，
  `dex_index_search` 就会答出字节已不存在的命中——**陈旧答案比没有答案更糟**）。`dex_index.ts` 依赖
  `state.ts`，所以反向不能 import，用回调注入避免成环。
- 回收在**三处**跑：每次新工件落盘后（`persistArtifact`/`dumpRegion` 尾部，dedup 命中时不跑）、
  启动时一次、daemon 已有的 60s 清扫里一次（有几条路由直接写工件、绕过前两个，靠定时兜住）。

**验收**：新增 `tools/verify_v99_artifact_store.sh`（host，注册在最后因为它会**真的重启 daemon**）——
先跑 8 项纯策略单测，再重启后断言磁盘上每个工件都回到 `/api/dumps`、标 `disk-reload`、无悬空条目。
实测：**290 个文件 → 281 个唯一 sha 全部回流**，预算 `{maxBytes:8589934592, maxAgeDays:14}` 暴露。
（修复前这一步是 0 条。）

### 第 3 项 — `native_hook` 机制自证 ✅

**问题**：钩子**装成功但从不命中**，与**目标空闲**无法区分——两者都是 `ok:true / hits:0`。
本次实战里我挂了 7 个符号、观察 5 分钟全 0，只能靠"WebSocket 心跳每 30s 却 0 命中"这种**外部推理**
判断"这条 I/O 路径不走这些符号"。更糟的是 `mode=got` 的 `address`/`target`/`original` **三者同值**
（都是槽的**改写前取值**），所以连"改了哪个槽"都看不出来；`:501` 算出的槽地址被直接丢弃。

**修法**（agent）
- `got.c` 的 `adh_got_replace_by_name_ex` 增出参，把**写槽前的页权限**带出来；`native_hooks.cpp`
  为每个钩子存 `slot_addr` / `slot_perms_before` / `installed_at_ms`。
- 状态里新增：`slot`（被改写的重定位槽地址）、`slotsPatched`（got 恒为 1——装不上会 fail-loud）、
  `slotCurrent`（**现在**重读该槽，≠ `replacement` 就说明补丁被别的代码覆盖了）、
  `pageProtRestored` + `pagePermsBefore/Now`（`got_write_slot` 会把页保护还原；**留一个可写的
  RELRO 页是可被目标看见的足迹**）、`installedAtMs` / `firstHitMs`、
  以及派生的 **`verdict`：`fired` | `installed-never-fired`**。
- `firstHitMs` 在 stub 里只花一次 relaxed load、首次命中时写一次，热路径不引入锁。
- 顺带：`item[2048]` 对 sites 钩子（sitebuf 1400）本会**截断出非法 JSON**，提到 4096。

**验收**：扩 `verify_v61_got_by_name.sh` 钉住全部新字段。实测（真机沙盒，`libadhdetect.so:adh_trace_target`）：

| | 触发前 | 触发后 |
|---|---|---|
| `slotsPatched` / `slot` | 1 / `0x783c0d3778` | 同 |
| `slotCurrent` | `0x77a3ea35f4`（我们的 stub） | 同 |
| `pagePermsBefore` → `Now` | `r--p` → `r--p`（`pageProtRestored:true`） | 同 |
| `firstHitMs` | **0** | 1790435321477（装上后 13ms） |
| `verdict` | **`installed-never-fired`** | **`fired`** |

### 第 4 项 — 扫描瞄得准 + 诱饵判定 ✅

**问题**：`memory_search`/`memory_scan_magic` 按 maps 顺序扫、受全局额度约束，**没有任何区间参数**。
学习通有 3700+ 区域，额度在框架 OAT 上就耗尽，根本到不了 app 堆——当时只能把额度调大。
`dump_all_dex` 只报数量不报性质：14 个里哪个是 120MB/17 类的**诱饵壳**，得人肉考古。

**修法**
- agent：`cmd_search`/`cmd_scan_magic` 增 `minAddr`/`maxAddr`（0=不限）。**窗口外的区域直接跳过而不是裁掉**，
  所以额度花在你要问的那段；回复一律回显生效窗口（`"all"` 或 `"lo-hi"`），
  `scan_magic` 补 `regionClipped`——**部分扫描不能再读起来像全扫描**。
- `dex.ts` 新增**纯函数** `classifyDexArtifact(size, classes, methods)`：按**每类字节数**判定
  （真实 dex 几百字节~几 KB/类；SecNeo 载体是 6.8 MiB/类）。抽成纯函数是为了能直接单测。

### 第 5 项 — 加厚一键入口（**未恢复**已删的恢复会话）✅

`dumpAllDex` 从"报数量"变成**带判定的报告**：逐 dex `{classes, methods, bytesPerClass, carrier, shape}`
+ 顶层 `{dexCount, realDexCount, carrierCount, totalBytes, realBytes, index{built,reused}, carriers[]}`。
分类与**建索引是同一次 pass**（复用 `ensureDexIndex`），所以 dump 完立刻可 `dex_index_search`。
**明确没做**：T0/T1 快照、全量触发、recover+重建——那是 `855f3db` 有意删掉的链路。

**验收**
- 新增 `daemon/test/dex_artifact_shape.test.ts`（4 项，v15 里跑）：用**学习通实测数字**钉死正例
  （120,451,440 B / 17 类 → carrier；13,705,120 B / 9093 类 → 不是），含"0 类"、
  "阈值是严格大于"、"100MB 但 6 万类仍是真代码"三个边界。
- 扩 `verify_v15_dumpall.sh`：断言逐 dex 都被分类、`realDexCount+carrierCount==dexCount`、
  沙盒上 `carrierCount===0`、`index.built>=1`。
- **学习通真机正例**：`dexCount 14 / realDexCount 13 / carrierCount 1`，
  `totalBytes 263,763,804` vs **`realBytes 143,312,364`**（把 120MB 外壳与真代码分开），
  载体那条 `classes=17 | 6.8 MiB per class (> 1 MiB): a carrier, not code`，
  `index{built:14,reused:14}`，全程 18.9s。窗口：排除 app 的区间正确返回 `count=0`。

### 第 6 项 — 小项 ✅

- **agent 版本可问**：`compat_probe` 增报 `agentVer`，直接用**已经编译进二进制**的 `AGENT_VER`
  （本来就用在下行 hello 与 JNI_OnLoad 日志里）→ **不新增任何字符串**，v88 字符串去特征门禁不受影响。
  同时把 `AGENT_VER` 提到 **0.3.12** 与模块版本对齐，并在 `agent/src/MAP.md` 写明规则：
  **模块发运这个 .so，所以「刷了哪个 agent」和「刷了哪个模块」不能是两个答案**，两者必须同升同刷。
- **agent TCP 8761 监听 `0.0.0.0` 且无鉴权**：**本轮不改**（按约定只记录决策点，见 `FEATURE_STATUS §2`）——
  它是信任边界决策，改动牵动 Device Daemon / Manager / adb reverse 三处。

**六项全部落地。** 收口：`verify_all.sh` 116 项；模块升到 **v0.3.12** 并刷入。



## 2026-09-26（续）—— 两个阻断点已修复并真机验证（另含 C/D 两项加固）

上面那节暴露的 A/B 两个缺陷**已在 agent 内修掉**，未改协议、未改注入器。学习通在**不施加任何
绕法**的情况下完成了完整脱壳。

**A. 内存读取不再依赖 `/proc/self/mem`**（新增 `agent/src/bootstrap/mem_read.c`，成为唯一后端）
- 目标能打开该 fd 时**行为与改动前逐字节一致**（`pread`），所以既有验收不会漂移；打不开时才走
  **直读**：先在 `/proc/self/maps` 里确认区间可读，再 `memcpy`，全程包在一个 SIGSEGV/SIGBUS 短守卫里
  （拷贝途中映射消失 → 报告读取失败，而不是把目标打死）。守卫窗口内其他线程的真崩溃会链回原处置。
- fd **按命令释放**（`adh_mem_fd_release`）：原实现每条命令 open/close，改动后若长驻 fd，等于在目标里
  留一个「有人在读我内存」的可观测信号。验收脚本现在直接断言命令结束后 `/proc/<pid>/fd` 里没有它。
- 每条回复都点名实际走的路线（`via` / `backend`），`compat_probe` 增报 `memBackend` / `memOpenErrno` /
  `libartJniGetVms` —— 能力降级不再静默。
- 新增 `read ... via=direct`（MCP `memory_read` 的 `via` 参数），可在**目标伪造 `/proc/self/mem` 返回**
  时对照两条路线。

**B. Zygisk 注入下拿得到 JavaVM**（`runtime/jni.c`）
- `JNI_GetCreatedJavaVMs` 改为**从已加载的 libart.so 里按内存镜像查符号**（复用 `adh_resolve_sym`），
  `dlopen` 只作最后兜底。memfd 加载的 agent 被 linker namespace 拒绝 dlopen 的问题绕开了，
  且 Gadget / Xposed 两条后端同样受益——**注入器不需要改**。

**C. 扫描预算与截断如实上报**（`bootstrap/mem.c`）
- `scan_magic`：`MAXHITS` 256→2048、`TOTALCAP` 512MB→2GB、`PERREGION` 64MB→256MB；
  `search`：`TOTALCAP` 1GB→2GB、`PERREGION` 128MB→256MB。旧的额度被框架 OAT 的 dex magic 吃光，
  根本扫不到 app 堆。被裁掉的区域现在报 `truncated`（scan）/`regionClipped`（search），不再静默跳过。

**D. `dex_repair` 不再内联回吐整份 dex**（`daemon/src/service.ts` 新增 `persistArtifact`）
- 原实现把修复后的 dex 以 `repairedB64` 原样回吐：120MB 的 dex → 160MB 的回复，直接撑爆 MCP/HTTP
  回复与落盘上限（本次实战里我自己就被它顶掉过一次工具输出），而调用方本来就已经持有这些字节。
- 现在**落成正式工件**（与 `dumpRegion` 同一目录/命名/去重），回复只给头字段 + `sha256`/`size`/`kind`/`path`，
  于是修复后的 dex 可以像别的 dump 一样被索引和下载。改前确认过 `repairedB64` **没有任何消费方**
  （web UI 与脚本都不读）。`verify_v02_dexrepair.sh` 相应补了一条"按 sha 取回的字节必须等于修复结果"。

**验证**
- 新增 `tools/verify_v97_memread_direct.sh`（已入 `verify_all.sh`）：只读代码映射为锚点，自动路线与
  `via=direct` 返回**逐字节相同**且各自点明路线；对 `---p` 区间直读干净失败且目标存活；
  `compat_probe` 三个新字段形状正确；无遗留 mem fd。
- **真机（学习通 / SecNeo，无 prctl 绕法）**：`compat_probe` = `memBackend:"direct"`、`memOpenErrno:13`、
  `memRead:true`、`libartJniGetVms:true`；`memory_search` 直命中真实类；
  **`art_dexfiles` 由 `no JavaVM` 变为 `ok:true / count:14 / loaders:100`**；
  **`dump_all_dex` 一键产出 14 个 dex，其中 13 个真 dex 与手工挖出的结果 sha256 逐字节相同**
  （外加 120MB 外壳占位）。产物在 `dumps/chaoxing-7.0.4/dex-native/`。
- 回归：`verify_all.sh`（114 脚本）**114 PASS / 0 FAIL / 0 SKIP**。

**仍未做**
- 信号守卫的故障路径无法确定性覆盖，验收脚本明确不声称覆盖它。
- A 的绕法（`native_call libc.so prctl [4,1]`）不再是流程的一部分，仅作应急处置留档。
- `verify_v22_capture.sh` 的记账不变量偶发不成立（与本次改动无关，见 `FEATURE_STATUS.md §2`）。



## 2026-09-26 —— 真机脱壳实战：学习通（`com.chaoxing.mobile` 7.0.4，SecNeo 梆梆加固）

> 完整复盘（含可复用的加固形态情报与工具改进结论）见 [`CASE_STUDIES.md`](CASE_STUDIES.md) 案例 1。

**这是 ADH 第一次在真机上对一个真实加固 App 完成完整脱壳，并且顺带暴露了两个此前从未被门禁覆盖的
真实缺陷（见下）。** 设备 OnePlus PGP110 `aa165071` / Android 15；模块 `adh` v0.3.10 已刷入并运行。

**结果**：13 个 dex，共 143,312,364 字节、**98,135 个类、748,297 个方法**；
`dex_coverage` 逐个 dex `recoveryRate=1`、`unresolvable=0`；13 份 dex 的 checksum 与 signature 全部有效
（无方法抽取）。产物：`dumps/chaoxing-7.0.4/dex-adh/classes01..13.dex`（gitignored）。

**实际链路（全部经 ADH，未用 adb 读内存）**：
1. `scope.json` 写入 `com.chaoxing.mobile` → `am force-stop` + 冷启动 → zygisk 日志 `in scope … will inject`，agent online（`s_16ct`，ping 8–13ms）。
2. `compat_probe` 报 `memRead:false`、`artDexCapture:false`、`jniReflect:false` —— 两个阻断点。
3. `native_call libc.so prctl [4,1]` 恢复进程可 dump → `memory_read` 立即恢复。
4. `memory_search` 搜真实类名 `Lcom/chaoxing/mobile/study/account/LoginActivity;` 定位真载荷所在区域。
5. `memory_dump` 按精确 addr+size 逐个取出 13 个 dex → `dex_index` / `dex_coverage` 验收。

### 本次暴露的 ADH 缺陷（A/B/C 已在上一节修掉，D 待做）

> 下面按**发现当时**的原样保留，作为根因记录；A/B/C 的修法与验证见上一节，D（`dex_repair` 内联回吐）仍未做。

- **A. `/proc/self/mem` 在 non-dumpable 目标上 EACCES，agent 全部读内存能力失效。**
  SecNeo（梆梆）调 `prctl(PR_SET_DUMPABLE,0)`，于是 `open("/proc/self/mem")` 返回 **errno 13**——
  连进程读自己都拒绝。`mem.c` 的 `cmd_read`/`cmd_search`/`cmd_scan_magic`、`runtime/art.c`、
  `trace/commands.c` 全部只走 `/proc/self/mem`，因此 `memory_read`/`memory_search`/`memory_dump`/
  `scan_magic`/`art_dexfiles` 一起挂。**本次绕法**：`native_call libc.so prctl [4,1]` 就地恢复（3µs）。
  **正解**：agent 本就在目标地址空间内，应加**直接解引用读取**（先查 `/proc/self/maps` 确认区间可读，
  再 `memcpy`；`/proc/self/mem` 作为回退），或 `process_vm_readv(self)`。
- **B. Zygisk 注入路径下没有 JavaVM，所有 Java/ART 能力失效。**
  agent 由模块经 memfd 加载（maps 里是 `/memfd:jit-cache (deleted)`），`adh_jni_attach` 的兜底
  `dlopen("libart.so")` 被 linker 拒绝：
  `library "libart.so" needed or dlopened by "/memfd:jit-cache (deleted)" is not accessible for the namespace "(default)"`；
  裸名 `libart.so` 也不在 app namespace 搜索路径里。于是 `art_dexfiles` / `java_hook` / `trigger` /
  `object_*` 全部 `no JavaVM`。模块在 `onLoad(api, env)` 本来就握着 `JNIEnv`，**正解**：
  `postAppSpecialize` 里 `env->GetJavaVM(&vm)` 并通过新导出 `adh_agent_set_vm` 交给 agent
  （需加进 version script 白名单）。
- **C. `memory_scan_magic` 的预算到不了 app 区域。** `MAXHITS=256` / `TOTALCAP=512MB`，而框架 OAT 的
  dex magic 命中就占满了配额（实测 `scanned=463MB, truncated=true`），扫不到 `0x7c…` 之后的 app 内存。
  本次靠 `memory_search` + 已知地址绕过。建议支持地址区间/区域过滤或提高预算。
- **D. `dex_repair` 把整份修复后的 dex 以 `repairedB64` 内联回吐**（120MB dex → 160MB base64），
  超出 MCP 回复与落盘上限。建议只回头部字段并**把修复结果落成工件**。

### 关于此类壳的路线结论（重要）

学习通的外壳 dex（ART 命名为 `[anon:dalvik-classes.dex extracted in memory from …/base.apk]`，
120,451,440 字节）是**诱饵**：`file_size` 被吹到 120MB，但 `class_defs_size` 只有 17，
内容是 `com.secneo.apkwrapper.*` + ARouter 路由表。
**真 dex 在 `[anon:libc_malloc]` 区域里（`0x7cf6000000`+，13 个 dex 等距排布），ART 没有给它命名**——
也就是说**只靠 `art_dexfiles`（ART DexFile 枚举）会完全错过真载荷**，必须走内存扫描/区域 dump。
这条对 SecNeo/梆梆系样本应作为默认路线。

## 历史：2026-09-23 验收与范围收口

**状态快照**：测试设备 OnePlus PGP110 `aa165071` 在线；Host ADH Daemon 与 adb reverse 已启动。本轮已从产品中退役并移除 Android UI 自动化（模块 X），AI Agent 直接使用 adb。2026-09-23 最终执行 `tools/verify_all.sh`：**113 PASS / 0 FAIL / 0 SKIP**。完整状态见 `docs/FEATURE_STATUS.md §2`。

**已完成的修复**：QBDI `qbdi_addCodeCB()` 事件 ID 的失败哨兵判断修正；native hook 在限流时仍正确应用 `returnValue`；syscall 扫描验证前重启沙盒以清除仍驻留的软补丁；v50/v77/v80/v81/v85 验收断言和 v91 JNI 各探针卸钩/摘要时间窗修正。Device `:core:test :daemon:assembleDebug :manager:assembleDebug` 成功。

**模块 X 退役边界**：已删除；摘要见 [`docs/archive/RETIRED_MODULE_X_AND_XPOSED.md`](archive/RETIRED_MODULE_X_AND_XPOSED.md)。保留 adb、Manager 注入 scope/模块状态/目标进程启停。协议当时升到 v13；HTTP/WS MCP 仍在 Host Daemon。

**剩余验证/决策**：v84 native batch 的设备侧验收仍未纳入门禁；cdex/041 需要真实样本；agent TCP `8761` 无鉴权的 LAN 信任边界待定；DEX 重建保留旧副本导致文件增大仍是已记录限制。协议 v13 的 release bundle 还未重建或刷入。

### 2026-09-23 本轮改动

- 移除手机自动化功能，明确 AI 手机交互由 adb 承担；MCP 工具现为 67 个，验收门禁由 118 项收敛到 113 项。
- 修复 QBDI callback 安装失败检测、限流路径返回值替换，以及 syscall / trace / JNI 验收的状态隔离和断言问题。
- 最终全量：**113 PASS / 0 FAIL / 0 SKIP**；Device Gradle：`:core:test :daemon:assembleDebug :manager:assembleDebug` 成功。
### v2.0+ 进度
- [~] **v5.04 真机首跑（aa165071）：13 个失败逐个定性，7 个当场修掉（2026-09-19，真机 + host 验收）**：手机接上后第一次跑**带真机的全量门禁**：**100 PASS / 13 FAIL / 5 SKIP**。逐个定性后发现两类——**产品问题 3 个**、**测试脚本自身的问题 10 个**（这些脚本此前只有 host 半，真机半从没跑过）。
      · **产品修复**：① `jni_env_hook` 的 install/uninstall 回复用 32 KB 固定缓冲，**静默**只带回 159/228 个槽位（v64 因此把 228 装成"159"）——改成与 `action:status` 相同的 128 KB，并补 `total/emitted/truncated` 如实上报；② `file_probe`/`crypto_probe` 的地址是裸十六进制（其余 API 一律 `0x…`），v87 的"解析出非零地址"因此判假——统一成 `0x%llx`；③ 沙盒夹具 `jniArrayElementsProbe` 的 7 个 `Get*ArrayElements` 传 `NULL` 取 isCopy，agent 如实报 `-1`（"调用方没问"），而 v91 要 `isCopy=[01]` —— 夹具改为传 `&is_copy`，让"真值"这条路真的被验证。
      · **测试脚本修复**：v91（region 读取的预览断言写成要求整串 `ADH-STR`；末尾对已卸槽位重复卸载 → 改为先问 status 只卸在挂的；并补"failed checks"诊断，不再无声 FAIL）、v89（把继承字段写到了 `sConfig` 而不是 `sInherited` 的 holder；产品侧手测 `ok:true 5->9` 正常）、v83（`stackOuter(String)` 少了 params）、v82（int 参数传了字符串 `'3'`，agent 按 fail-loud 拒绝）、v64（从 install 回复数已装槽位 → 改从 status 数，并断言回复的 truncated 口径）、v59（两个 field-ID 事件的期望写成固定串，实际 value 是 `class#field -> 运行时 jfieldID`，改为前缀匹配；补 failed-check 诊断）、v88（把整个进程的字符串搜索收窄到 **agent 自己的 r--p/r-xp 段**——夹具自己的 log tag、fixture 模块名与 maps 里的路径本来就在进程里）。
      · **修复后真机门禁**：**109 PASS / 6 FAIL / 3 SKIP**（v59 随后单独复跑也转 PASS，即 110/5/3）。
      · **仍未收口的 5 项（有现场证据，未修）**：① **v51_qbdi_args / v10_qbdi**：`libQBDI.so` 已在 APK 里（6.5 MB，dlopen+dlsym 都成功），但 `qbdi_addCodeCB` 返回 0 —— 同一版本 QBDI 在上一台设备（13f54a46）通过过，需要按设备/ROM 对比（QBDI VM 初始化或 ColorOS 的 mmap/exec 限制）；② **v77_syscall_watch_libc**：夹具 `libadhdetect.so` 里确实有 2 个 `svc #0`（`llvm-objdump` 实测，`adh_direct_gettid` 0x2da8），但宿主 `syscall_watch` 的扫描报 "attributed 0 of 0 sites"——要查 dump/扫描用的是哪段字节；③ **v81_device_syscall_digest**：libc 的 `uname` 站点挂上了（installedCount=1）却没有事件，需确认夹具的 uname 路径是否真的走 libc stub；④ **v86_device_throttle**：限流下 `returnValue` 改写 **0/20** 生效（v4.48 的承诺是"限流只压事件、不改行为"）——要么实现有回归，要么夹具/脚本的调用路径不对，需要读 `record_site` 命中路径；⑤ v41 已转 PASS（Manager 桥接恢复），v36/v38/v39/v40 仍 SKIP（自动化桥未连接）。
- [~] **v5.03 第十一轮评审收口：1 条 P1 + 7 条 P2（2026-09-19，host 验收 PASS；真机待做）**：这一轮审的是 v5.01/v5.02，**P0 无**。
      · **P1-1 原始 map 截断时仍报"map 重建成功"**：读旧 map 的循环遇到读不动的条目直接 break，之后**无条件** `mapRebuilt=true`——评审把 sandbox dex 截到只剩 3 条 map 条目，重建回 `mapRebuilt:true, layout.ok:true`，而新 map 只有 6 条（17 类里缺 11 类：string_data / debug_info / type_list …）。依赖 map 的消费者会找不到这些区，自检却给绿。现在**读不全就抛错**（路由 422），v96 新增该负对照。
      · **P2**：① `verifyDexLayout` 补 `file_size === 文件长度`、`data_off + data_size === 文件长度`（此前把 file_size 改成 12345、data_size 改成 7 也能 PASS）；② 引用检查不再用 `set.size &&` 空转——class_def 指向的 class_data、方法 code_off 指向的 code_item **必须**在 map 里，且 header 说存在的 6 个固定区 + string_data 必须被列出；③ 重复 midx 的 capture 不再静默去重，回报 `duplicateCaptures`；④ **API 回复补齐文档承诺的字段**（`mapRebuilt/mapEntries/relocated*/unmatchedCaptures/skippedCaptures/duplicateCaptures/layout`）——`/api/dex/rebuild`、`/api/dex/recover` 与 MCP `dex_recover` 都带上；⑤ 恶意 `dm/vm`（可达 2^32-1）在 5 个内联 class_data 循环里不再空转（评审实测 500 万次 70ms、外推约 60s/类），统一加 `p > buf.length` 边界；⑥ REST `native_call`/`native_hook` 也把**原始** addr 交给守卫（此前 REST 仍 `String(addr)`，`addr:0` 的回退只在 MCP 生效，两端分叉）；⑦ cursor 语义收口：`Number(null) === 0` 会把"时间窗等待"变成"从头开始的全量 cursor"，现在 `num.ts:cursorNumber()` 把 null/''/[] 与非有限值一律视为"未给"，MCP 与 `agent_events` 共用。
      · 验收：daemon `node --test` 164；v96 新增"截断源 map 必须被拒"+"file_size 篡改必须报"两条负对照，v95/v96/v12/v13 全部 PASS；host 全量门禁 **34 PASS / 0 FAIL / 84 SKIP**（118 脚本）。
- [~] **v5.02 第十轮评审收口：1 条 P1 + 9 条 P2（2026-09-19，host 验收 PASS；真机待做）**：这一轮审的是 v4.99/v5.00（外加 v5.01 的一处交互），**P0 无**。
      · **P1-1 `/api/dex/method_code` 的 `recovered` 把 `unresolvable` 的条目算成"已恢复"**：走不通的 item 仍带着从 header 读到的 `insnsSize`，于是同一个方法同时进 `recovered` 和 `unresolvable`，`empty` 又把它排除。现在 `recovered = codeItemHex 非空`、`empty = count - recovered - unresolvable`（**三者之和恒等于 count**，v95 新增断言）。
      · **P2**：① `extractMethodCode` 先 `readCodeItem` 再读 header——`code_off` 越界此前会让 `readUInt32LE` 抛 RangeError，把"每条方法各自如实报告"变成不透明的 500（v95 新增"改坏一个 4 字节 code_off uleb"的负对照：条目必须带 `unresolvable`、coverage 的 `unresolvable/missingTotal` 各 +1、路由三计数自洽）；② 拆出 **`codeItemEnd()`**（只走不拷贝 hex），`analyzeCoverage`/`verifyDexLayout` 不再为 46k 个方法各构造一次十六进制串（恶意 handler list 曾能让每条都构造一个与文件同量级的串）；③ LEB 解码加 `p < buf.length` 边界 + EOF 哨兵（此前会读 `buf[len]`，Node 下良性、换运行时就不是）；④ `missing` 列表仍封顶 5000，但新增**真实 `missingTotal`**，`stillMissing` 与 `/api/dex/coverage` 的 `missingTotal` 不再少报；⑤ `rebuildStandardDex` 把空 capture 收进 **`skippedCaptures`** 返回，不再静默丢弃；⑥ agent 侧 outstanding 计数改为**先计数后创建**（create 失败回退），修掉"worker 先跑完再自增"导致的永久 +1（撞满 4 个上限且无存活 worker 时会永久拒绝调用）；⑦ phone 面最后两处 NaN（`notificationLimit`/`notifications.limit`）统一 `finiteNumber`；⑧ `phone_wait` 的 cursor 非数字视为"未给"（`n > NaN` 恒 false 曾让等待静默匹配不到），`agent_events.inWindow` 同口径；⑨ `addr:0`（JSON 数字）按"未给地址"处理，回退 module+symbol；⑩ `/api/dex/recover` 对 rebuild 的抛错映射 422（与 `/api/dex/rebuild` 一致），不再 500。
      · 验收：agent 零告警重建（1,023,328 B）；daemon `node --test` **163 → 164**；v95 增负对照后 PASS；v96/v12/v13 继续 PASS；host 全量门禁 **34 PASS / 0 FAIL / 84 SKIP**（118 脚本）。
- [~] **v5.01 WS-E 第二片：重建 dex 的 map_list 真的描述文件（2026-09-19，host 验收 PASS；真机待做）**：WS-E 里"rebuild 真正重建 map_list"这条收口。此前重建把新 code_item/class_data **追加到旧 map_list 之后**，map 就不再描述这个文件——jadx/IDA 靠 class_defs 还能找到方法，但任何信 map 的消费者（ART verifier、其它 dex 工具）都读不到它们。
      · 新布局：`[原始字节] [重定位的 code_items（每个 4 字节对齐）] [重写的 class_data items] [新 map_list]`；每个 class_def 的 `class_data_off` 与每个方法的 `code_off` 都改指新副本，旧副本留在文件里成为**不再被 map 列出的 slack**（追加式重建的代价：沙盒 dex 9,604,000 → 13,215,556 B）。
      · 新 map_list = 原有条目（去掉 map_list / class_data / code_item 三类）+ 新的 `code_item`（offset=新区起点、size=重定位条数）+ 新的 `class_data_item`（同理）+ 新的 `map_list` 条目；header 的 `map_off` / `file_size` / `data_size` 与 signature/checksum 同步。
      · 新增 `readClassDataItem()`（class_data 完整解析 + end 偏移）与 **`verifyDexLayout()`** 自检：map 必须存在、每类只出现一次、按 offset 排序；它列出的 code_item 区必须**逐条走得通**（46,228 条）、class_data 区同理（5,895 条）；每个 class_def 必须指向被列出的 class_data、每个方法 code_off 必须指向被列出的 code_item；checksum/signature 必须与字节一致。重建回复带 `layout{ok,errors,mapEntries,classDataItems,codeItems}`——"map 重建过了"从注释变成有证据的断言。
      · 验收：新增 `tools/verify_v96_dex_map.sh`（host）——原始 dex 自检 PASS（17 条目 / 5895 / 46228）、重建后 `mapRebuilt` 且 `layout.ok`、map 计数与实际写入数一致、注入的 try/catch 方法经**重定位副本**仍字节一致、无 capture 的重建同样 map 一致，外加两个负对照（截断 16B、篡改 map 条目 → 自检必须拒绝）；v12/v13/v95 全部继续 PASS；host 全量门禁 **34 PASS / 0 FAIL / 84 SKIP**（118 脚本）。
      · WS-E 剩余：**cdex/041**（需样本，按计划标 PENDING）。
- [~] **v5.00 第九轮评审收口：1 条 P1 + 9 条 P2（2026-09-19，host 验收 PASS；真机待做）**：这一轮审的是 v4.94–v4.98（地址守卫 / 看门狗 / v4.96 收口），**P0 无**。
      · **P1-1 守卫校验的地址与 agent 实际调用的地址可以不是同一个**：宿主守卫走 `parseAddress()`（裸数字串=十进制），agent 走 `strtoull(...,0)`（前导 0=**八进制**）——`"010000000000"` 在守卫眼里是 `0x2540be400`、在 agent 眼里是 `0x40000000`（评审用 gcc 实测）。现在 `assertCallableAddress()` 返回**归一化后的 `0x…` 串**（新增导出 `normalizeAddressForAgent()`；MCP 与 REST 都改发这个串），空白串 trim 成空走 module+symbol（此前会带着空格进 agent 的 addr 分支解析失败）✓。agent 侧 `native_call` 的 addr 分支同时补上 `adh_addr_is_executable()`——agent 端口可被直连，不能只靠宿主守卫。
      · **P2 全部落地**：① 守卫覆盖 `mode=sites|vtable` 的裸 addr（此前只 inline；agent 侧本来就有可执行性兜底，但"每条裸地址路径都过守卫"这句话此前不成立）；② 守卫只在 `action=hook` 生效（unhook 只用 hookId，陈旧 addr 不该把卸载挡住）；③ MCP `native_hook` 的守卫与下发**同一个 session**（此前守卫 `pickSid(a.session)`、下发 `agentCmd(a.session)` 各自解析，期间有 session 上下线就会校验 A、装到 B）；④ agent 侧**未回收 worker 计数**（`ADH_NATIVE_CALL_MAX_OUTSTANDING=4`）——对"永不返回"的函数连续重试不再能把目标塞满线程栈（此前只文档化了并发代价）；⑤ 看门狗窗口只覆盖**调用本身**：worker 先发布 `call_done`+结果再跑 JNI 探测，探测没在窗口内完成时如实回 `exceptionProbe:"unavailable"` + 调用结果（此前会把**已返回**的调用报成"还在跑"），attach 失败也不再静默当成"无异常"；⑥ 修掉"FP 返回值落在全局"的注释（实际写的是 per-call out 指针，这正是并发 worker 不串值的原因）；⑦ `/api/module/dump` 的 dedup 命中不再借旧 meta（source/complete/session/tag/addr 按本次请求重算，与 v4.96 的 dumpRegion 同规则）；⑧ phone 面剩余 NaN（`intervalMs`/`lookbackMs`/`stableMs`/`maxScrolls` + `phone_text` 的 `maxNodes`/`maxTextLength`）统一走新抽出的 `num.ts: finiteNumber()`（`Number('abc')` 曾让 `slice(0, NaN)` 渲染出空屏且不报错）；⑨ 文案更正——"未映射地址装 inline hook 会崩"不实（agent 自 `88e8e75` 起在任何 patch 之前就 `adh_addr_is_executable` 拒绝），宿主守卫的价值是**更早、更一致**地报错，sites/vtable 与看门狗并发代价也补进 REQUIREMENTS。
      · 验收：agent 零告警重建（1,023,296 B）；daemon `node --test` **162 → 163**（地址归一化 1 条，含十进制/八进制分歧的回归）；`normalizeAddressForAgent` 单测覆盖 trim / 大小写 / 裸 hex / 全数字 / 非法串；host 全量门禁 **33 PASS / 0 FAIL / 84 SKIP**（117 脚本）。
- [~] **v4.99 WS-E 第一片：带 try/catch 的 code_item 完整读取 + 重建字节一致（2026-09-19，host 验收 PASS；真机待做）**：WS-E 点名的"`tries!=0` 方法静默跳过、恢复率虚高"在这里收口——沙盒 dex 里 **1166/46228** 个具体方法带 try/catch，此前它们的 `codeItemHex` 一律是空串：`dex_method_code` 看不见、`dex_recover` 捞不回来，而覆盖率报告照样显示 100%。
      · `dex.ts` 新增 `readCodeItem()`：按规范走完 **header(16B) + insns + 4 字节对齐的 tries[] + encoded_catch_handler_list**（sleb128 的 handler size、type/addr 对、catch-all），越界或 handler 列表残缺一律返回 null。
      · 诚实口径：`extractMethodCode` 对解不动的 item 回 `unresolvable` 理由而不是静默空串；`analyzeCoverage` 新增 `unresolvable`（解不动的 item **不再算 present**，且进入 `missing` 供恢复流程处理）与 `unresolvableMethods`（带理由，上限 200）；`recoverFromSnapshots` 的报告列出每条恢复失败的理由；`/api/dex/method_code` 支持 `limit`（默认 200，上限 5000）并回报 `unresolvable` 计数。
      · fail-loud：`rebuildStandardDex` 注入前逐个校验 capture 是**完整** code_item（半截 insns / 缺一半 handler 列表 → 抛错，REST 回 422），不再把半截件原样追加进新 dex。
      · 验收：新增 `tools/verify_v95_dex_trycatch.sh`（host）——coverage `unresolvable=0`、挑一个 tries>0 方法断言 item 比 insns 长（99B vs 72B）、strip→missing→recover→rebuild 后**整件字节一致**（含 tries/handlers）、负对照（截断的 capture 必须 422 被拒）；`daemon/test/dex_codeitem.test.ts` 5 条单测（对齐/多 handler/catch-all/截断/不可能值）；daemon `node --test` **157 → 162**；v12/v13 继续 PASS；host 全量门禁 **33 PASS / 0 FAIL / 84 SKIP**（117 脚本）。
      · 仍未做（WS-E 剩余）：rebuild 的 **map_list 重建**（当前保留旧 map，追加项只在 class_defs 可达）与 **cdex/041**（需样本，按计划标 PENDING）。
- [~] **v4.98 地址守卫再补一处：`native_hook mode=inline addr`（2026-09-19，host 验收 PASS）**：v4.97 把 `native_call` 的守卫收敛成共享函数后，同一类"拿裸地址对目标下手"的路径还有一条——`native_hook` 的 `mode=inline` + `addr`（在未映射/不可执行地址上装 inline hook，同样崩在目标里）。
      · `mcp.ts` 与 `/api/native/hook` 路由都先过 `assertCallableAddress()`；守卫文案改为中性（"…refusing to use it as a call or hook target"，同一函数服务两种动作）。
      · 顺带确认 `jni_onload action=call` 只接受 **module**（内部解析符号），不是裸地址，因此不需要同一守卫——已核对 schema。
      · 验收：`mcp.ts`/`routes_runtime.ts` 均可正常 import（78 工具）；daemon `node --test` 157；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.97 `native_call` 的地址守卫收敛为一份（MCP 与 REST 不再分叉）（2026-09-19，host 验收 PASS）**：v4.94 把活体校验加在 **MCP handler** 上，但 REST 路由 `/api/native/call` 直接透传 agent——而设备脚本走的正是 REST，所以那条路当时等于没校验（和早先"REST 漏参数"是同一类分叉）。
      · 新增共享 `assertCallableAddress(sid, addr)`（memory.ts）：空地址=走 module+symbol 放行；否则取 maps → 未映射/不可执行分别给出明确错误；`mcp.ts` 与 `routes_runtime.ts` 都调用它。两个入口现在共用一份判断，改一处不会漏另一处。
      · 顺带核对：`routes_runtime.ts` 与 `mcp.ts` 均可正常 import（78 个 MCP 工具）；daemon `node --test` **157**。
      · 验收：host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.96 第八轮评审收口：2 条 P1 + 4 条 P2（2026-09-19，host 验收 PASS；真机待做）**：这一轮评审的是 v4.91–v4.93（它审的 HEAD 早于 v4.94/v4.95，所以"native_call 原始地址无校验"那条已在本分支修掉）。
      · **P1-1 dump 的 dedup 会借旧 meta**：`dumpRegion` 按 sha 命中已有工件时直接返回**旧 meta**——旧请求是 `complete:true, requestedSize:N`，新请求（2N，实际只读到 N）拿到同样的字节前缀就会命中，于是"短读"又变成了"完整"。现在 dedup 分支按**本次**请求重算 `size/requestedSize/complete` ✓。
      · **P1-2 `phone_task` 的 NaN 会把时限变成无限**：`Number('abc')` → NaN 一路穿透（`Math.max/min` 不修 NaN）→ `remainingMs() <= 0` 永不成立、注入给 `wait`/`wait_any` 的 NaN 超时让轮询永不退出、NaN retries 让 `attempt >= retries` 永假；MCP 层没有 schema 校验，所以可达。现在统一走 `finiteNumber(value, fallback, min, max)`（timeout / retries / retryDelay 全部 NaN-safe）✓。
      · **P2**：syscall `counters` 增加 `basis: since-install | window-lower-bound` 并在 note 里说明"计数是自安装累计、下面的分组才是窗口"；`qbdi_trace` 补"回复缓冲连 header 都放不下"的早退（当前不可达的契约洞）；`phone_task` 在**预算耗尽**导致步骤失败时改回报 `timedOut:true`（而不是一个看不出原因的 step error），重试注入的超时也改为 `max(0, …)`；`captureStoreStats(session)` 支持**按 session** 统计（evicted/pushed/oldestTs/oldestId），并把淘汰说明抽成 `storeLossNote()` 供 **syscall digest / java_trace / jni_field_digest** 三处共用（此前只有 syscall digest 有）。
      · 单测：store 的窗口判定（`sinceMs`/`sinceCaptureId`/无窗口/未知 session）×1、counters basis 期望值更新 → daemon `node --test` **157**。
      · 验收：agent 零告警重建；daemon 157 测试通过；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.95 `native_call` 看门狗：卡死的调用不再冻住会话（2026-09-19，host 构建/门禁 PASS；真机待做）**：v4.94 把"调用本身没有超时"留作已知边界，这一版把它做掉——后果很重：一个不返回的目标函数会把 **agent 命令循环整个堵死**，之后所有命令都排在它后面，host 只能看到自己的超时。
      · agent：目标调用改在**独立线程**上跑，命令线程用 `pthread_cond_timedwait` 等 **15 秒**（早于 host 的 20s，保证 host 收到的是我们的诚实答复）；超时回 `ok:false, timedOut:true, watchdogSeconds:15`，说明"调用仍在目标里跑、结果不可用、会话仍可用"；成功回带 `timedOut:false`。
      · 两个语义细节：挂起 Java 异常的检查挪进 worker（异常是 **per-thread** 的，必须在真正发起调用的线程上查）；超时路径**故意让 job 泄漏**（worker 可能还在写它——一个小结构体换掉 use-after-free）。
      · 沙盒夹具新增 `adh_slow_leaf()`（纯 C、`sleep(30)`、按符号可调），`verify_v49_native_call.sh` 新增看门狗段：断言 `timedOut:true`、耗时落在 14–19s，且**紧接着的 ping 必须成功**（后半句才是看门狗的意义）。
      · 仍未做：worker 线程无法被取消（目标函数只能等它自己返回），本版保证的是"会话可用 + 如实上报"。
      · 验收：agent 零告警重建；`build_detect.sh` 重建（`llvm-nm` 可见 `adh_slow_leaf`）；v49 `bash -n` + 内嵌 JS `node --check`；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.94 `native_call` 的原始地址先过活体校验（2026-09-19，host 验收 PASS；真机待做）**：v4.92 把"原始地址不做存活性校验"记成了已知边界，这一版把能修的那一半修掉——**调用前先查活体 maps**。
      · 新增纯函数 `classifyAddress(regions, addr)`（`mapped` / `executable` / `path`，end 不包含，非法地址不映射）并有单测；`native_call` 在处理原始 `addr` 时先取一次 maps：**未映射** → `ok:false, "not in any mapped region (stale or wrong)"`；**映射但不可执行** → `ok:false, "... mapped (path) but not executable - refusing to call it"`（以前这两种都会直接跳进去，崩在目标里）。
      · `module+symbol` 路径本来就每次重解析 maps ✓（卸载后即 target not found），这条补的是裸地址那条路。
      · 仍未做（如实保留）：调用本身**没有超时**——daemon 的 20s 只是放弃等待，agent 命令循环会一直阻塞在被调函数里；要修需要在 agent 侧加看门狗线程，不在这一版。
      · 单测：`memory.test.ts` 增 `classifyAddress`（可执行 / 可读写 / 未映射 / end 边界 / 垃圾输入）→ daemon `node --test` **156**。
      · 验收：host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.93 digest 口径补最后一处：daemon 侧事件环的淘汰也要说（2026-09-19，host 验收 PASS）**：第七轮评审还点了一条——`captureHealth` 只反映 **agent 侧**环形缓冲的丢包，**daemon 侧**内存捕获列表按 `capture.retain`（默认 1000）从头淘汰的记录没有任何计数，于是"窗口内事件被淘汰过"这件事在 digest 里不可见。
      · `state.ts` 新增 `captureStoreStats()`：分别统计累计 `pushed`、`evicted`、当前 `retained`、`retain` 与最老保留记录的 `oldestTs`（`pushCapture` 每次淘汰自增，不是估算）。
      · `syscall_digest` 现在把两类丢失分开写在 note 里：agent 环丢包（原有 `ringNote`）与 **daemon 存储淘汰**——仅当请求窗口确实被淘汰影响时才提示（无 `sinceMs` 时窗口 = 全部保留记录；有 `sinceMs` 且 `oldestTs > sinceMs` 时说明请求起点早于最老保留记录）。
      · 单测：新 `capture_store.test.ts` 把 retain 调到 50、推 70 条，断言"保留 50 / 计入 70 次 push / evicted ≥ 20 / oldestTs 有效"，并在 finally 里还原共享状态。
      · 验收：daemon `node --test` **155** 通过；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.92 第七轮评审剩余 5 条 P2 收口：native_call / liveDisasm / automation / 工作流时限（2026-09-19，host 验收 PASS；真机待做）**
      · **native_call 地址严格解析**：`strtoull(addr, NULL, 0)` 把 `0x1234zz` 当 `0x1234` 调用（负数还会回绕），现在要求"整串必须被消费 + 不 ERANGE + 非 0"，否则 `ok:false` 并给示例格式。
      · **native_call 上报挂起 Java 异常**：被调函数若 `Throw`，返回的 `result` 是无意义的——以前仍回 `ok:true`。现在调用后 attach 检查异常，命中则 `ok:false, pendingException:true, error:"...value is not trustworthy"`（结果字段仍保留，但状态如实）。
      · **模块名解析收敛成一个严格函数**：`resolveModule()`（精确 basename/path → 唯一后缀 → 唯一包含 → 歧义抛 `ModuleAmbiguousError`）被 `liveDisasm`、`syscall_watch`、`/api/module/dump`（歧义 → 409 + candidates）共用；`libc` 不再在 libc.so / libc++.so / libcutils.so 之间静默挑一个。`liveDisasm` 另补：size 非正/NaN 直接报错（以前 `Math.max(4, NaN)` 静默变 4），`module+offset` 越界报错。
      · **automation 要求显式 `ok:true`**：设备回包省略 `ok` 时以前按成功 resolve（半截/旧格式帧看起来像成功），现在必须 `msg.ok === true`。
      · **`phone_task` / `phone_skill run` 有总时限**：新增 `timeoutMs`（默认 120s，夹紧 5s–10min），每一步与每次重试都按"剩余预算"夹紧自己的 timeout，耗尽时返回 `timedOut:true` + 停在哪一步（此前只有单步超时，N 步最坏 N×timeout，卡死的步骤会把每一步都拖满）。
      · **如实标注重组 .so**：`/api/module/dump` 的 meta 增加 `note`："reassembled from memory: offsets == vaddrs, section headers dropped, not byte-exact"（它是给 dynsym/符号分析用的，不是磁盘复刻）。
      · 新增/更新单测：`resolveModule`（精确/唯一/歧义/未加载）→ daemon `node --test` **154**。
      · 已知边界（如实记录，未修）：`native_call` 走**原始地址**时不做存活性校验、调用本身没有超时——daemon 的 20s 只是放弃等待，agent 的命令循环会一直阻塞在被调函数里；用 `module+symbol` 可避免（每次重新解析 maps，卸载后即 "target not found"）。
      · 验收：agent 零告警重建；daemon 154 测试通过；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.91 第七轮评审（能力面）收口：三处"看起来成功"改成如实上报（2026-09-19，host 验收 PASS；真机待做）**：评审对 memory / syscall / call / trace / automation 五个面做了独立审计，4 条 P1 全是"结果看起来成功、实际不完整"，先修三条。
      · **P1 内存 dump 链路**：agent `read` 回 `requested/short`；daemon 新增 `readMemEx`（`complete/requested/read`），`reconstructSo` 对每个 PT_LOAD **整段校验**（短读直接抛错——不再让 `Buffer.alloc` 的 0 填看着像真实零区），`dumpRegion` 先校验 size（NaN/负数/超 512 MB 直接拒绝）并在 meta 里带 `requestedSize/complete`；三个出口（`/api/memory/dump`、`memory_dump`、`/api/module/dump`）原样上报。`/api/module/dump` 的模块名匹配改为"精确 basename → 唯一宽松匹配 → 歧义即 409"（此前 `libc` 会在 libc.so / libc++.so / libcutils.so 之间静默挑一个）。v02 设备脚本新增断言：正常 dump `complete:true`、落在未映射空洞上的 dump 必须被拒绝或标记。
      · **P1 syscall digest 吞限流计数**：事件里的 `throttled` 只是"距上次发出"的增量（最后一次被压制的命中永远带不出来），digest 现在额外读 agent 的 `native_hook` status（权威计数）→ 结果给 `counters {hits, throttled, emitted, source}` 并写明"被限流 N 次"；status 不可用时退回事件增量并标注 `source:'events'`（欠计最后一段窗口）。逻辑抽成纯函数 `syscallCounters()` + 单测。
      · **P1 QBDI trace 截断无标记**：agent 侧新增 `seen/cap/truncated`，且 `count` 恒等于实际携带的条数（旧实现先写 header、缓冲满时停手 → "声称 N 条、实际只带 M 条"）；QBDI 生命周期的 5 个调用（initVM / getGPRState / allocateVirtualStack / addMod / addCodeCB）返回值全部检查，"半初始化 VM 跑出 0 条"不再伪装成 `ok:true,count:0`。daemon 侧抽 `traceCompleteness()`（带单测）并把 `truncated` 写成 digest note（删掉按 `list.length>=8000` 猜截断的启发式）；v10_qbdi 设备脚本断言 `count == insns.length && seen >= count && truncated === false`。
      · 顺带：MCP 的 memory/digest 工具描述同步；`node --test` **153**（+2）。
      · 评审另有 4 条 P2（liveDisasm 的 NaN/越界校验、native_call 地址严格解析 + 挂起异常上报、automation 要求 `ok===true`、phone_task 总 deadline）留下一批。
      · 验收：agent 零告警重建；daemon `node --test` 153 通过；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。顺带一提：中途我改 MCP 描述时引入了一个多余的引号，**v71 的注册表门禁当场把 10 个 host 脚本打红**——那条"描述里的撇号会炸掉整个模块"的门禁按设计工作了。
- [~] **v4.90 `file_probe` 补上设备证据路径（2026-09-19，host 语法/门禁 PASS；真机待做）**：v4.87 的路由门禁点出 5 条 api 路由没有任何验收脚本引用，其中 4 条（stealth/hook_all/backtrace/skills）的能力其实由 MCP 面覆盖（`verify_v69`/`v84`+`v86`/`v78`/`v36`），只剩 `file_probe` 真的没人叫过——它正是 `file_capture` 那个 `module` 参数的来源，探测不到就会在下一步以"莫名其妙装不上"的形式暴露。
      · 在既有的设备脚本 `verify_v87_device_probe_fs.sh`（名字就叫 device_probe_fs）里加第 5 段：调 `/api/file/probe`，断言 `ok`、五个符号（open/openat/read/write/close）**都解析出非零地址**、`modules` 非空且都是 `.so`、并且至少有一个模块确实持有这五个中的一个（按符号打印命中数）。"哪个符号被哪个模块 import"随 ROM 变（libjavacore 用 open/close + `__read_chk`/`__write_chk`，别的模块持 plain read/write），所以断言的是"能探测到候选"而不是"必须是某个模块"。
      · 路由门禁的"无人引用"名单随之从 5 条降到 4 条；剩余 4 条已确认由 MCP 面覆盖。
      · 验收：`bash -n` + 内嵌 JS `node --check` 通过；v94 PASS；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.89 第五轮评审收口：C 侧 `ExceptionClear` 归因 + 家门禁两处假阴性 + vendored LSPlant（2026-09-19，host 验收 PASS；真机待做）**：评审把"ADH 自身异常流量不进事件流"这句话又拆开验了一遍，确认只做了 C++ 那一半。
      · **P1-1（已修）**：`ExceptionClear` 同样是可挂槽位，而 C 侧还有 **60 处** `(*env)->ExceptionClear(env)` 直接走表（8 个 C 模块 52 处 + `jni_env_hooks.c` 自己的 7 处 + 1 处是 helper 内部的合法回退）。现在除 helper 的合法回退外全部改走 `adh_jni_exception_clear()`；**vendored LSPlant 的两处清理**（`art_method.hpp` 的 access-flag 探针、`jni_helper.hpp` 的 `ClearException`）也一并处理——做法是 `tools/fetch_lsplant.sh` 新增**第 4 号补丁**（注入 `extern "C"` 声明 + 替换调用，带"未生效即退出"校验），本地树已应用并在副本上模拟验证过补丁逻辑；vendor 树是 gitignored，所以补丁只存在于 fetch 脚本里（下次 fetch 自动重放）。
      · **P1-2（两处家门禁假阴性）**：① 家族 **base** 形态的配对正则 `&table->name\b` 会**同时匹配** `&table->name##V`（`#` 是非单词字符），所以删掉 base case 门禁照样绿——现在锚到分号（`&table->name;`）并补上 `&name##_wrapper;` 这一条；两个负对照（删 base slot case / 删 base wrapper case）现在都会 FAIL。② 安装路径不检查 `env_hook_wrapper(index)` 是否为 NULL，而 `adh_swap_pointer_in_ro_page()` **接受 NULL 替换值**——未来一次误删就能把 NULL 写进 ART 的 JNIEnv 表、目标下次调用即跳空崩溃；现在安装前先取 wrapper 并判空，缺失就拒绝 patch（fail-loud）。
      · **P2（已修）**：字符串预览的长度预查询加上了 `env_budget_left()` 门（预算耗尽后不再多打一次 JNI 调用）；重新激活分支补上"表项仍指向我们的 wrapper"校验（不然别人叠钩后我们会谎报已挂）；v91 `(3i)` 增加 `layout == "ok"` 断言。
      · **口径更正**：`docs/REQUIREMENTS.md` 里最后一处 "84 条签名断言" → 93；`env_exception_pending()` 的旧名残留（FEATURE_STATUS + 源码注释）→ `adh_jni_exception_check()`。
      · 验收：agent 零告警重建（含打过补丁的 LSPlant）；v90 PASS（228/229）；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.88 门禁再补一条："wrapper 只能谈自己的槽位"（2026-09-19，host 验收 PASS）**：评审点出的最后一类"静态检查看不见的错"——手写 wrapper **函数体里写错 `ENV_SLOT_*` 常量**（例如在 `GetVersion_wrapper` 里 `env_note(ENV_SLOT_FindClass, ...)`）：签名对、接线对、布局对，只有真机跑才会发现它把事件写进了别的槽位、也会去还原别人的 original。现在 v90 两条规则：
      · 手写 wrapper：体内出现的每个 `ENV_SLOT_X` 必须等于 `<wrapper 名>`（当前 0 违规）；
      · 宏生成的 wrapper：宏体内**不允许出现字面量 `ENV_SLOT_<名字>`**（槽位必须来自参数 `ENV_SLOT_##NAME`，否则说明这个"通用"wrapper 被硬编码到某一个槽位）。
      · 牙口验证：把 `GetVersion_wrapper` 的 `env_note` 指向 `ENV_SLOT_FindClass` → `FAIL hand-written wrappers referencing another slot: GetVersion uses FindClass`；恢复后 PASS。
      · 验收：v90 PASS（228/229）；host 全量门禁 **32 PASS / 0 FAIL / 84 SKIP**（116 脚本）。
- [~] **v4.87 设备脚本的 HTTP 路由门禁（host-only，116 脚本 = 32 host + 84 device）（2026-09-19，host 验收 PASS）**：设备脚本是整套验收里唯一"必须插手机才能跑"的部分，所以**路由改名/删除以后会在真机上集体失败**、此前没有任何东西能在 host 侧发现。新增 `tools/verify_v94_device_script_routes.sh`：读 daemon 实际声明的每一个 `path:` 路由，扫 `tools/verify_*.sh` 里出现的每个 `/api/...`，对不上就 FAIL（前缀路由按前缀匹配；`'/'` 这种静态/SPA 兜底路由被排除，否则"任何路径都有服务"会让检查永远通过）。
      · 现状：**88 条 api 路由**（与文档里的"88 条 HTTP 路由"对上），脚本引用 **82 条**，**0 条无服务**；另有 5 条 api 路由目前没有任何验收脚本引用（`/api/native/stealth`、`/api/native/hook_all`、`/api/native/backtrace`、`/api/file/probe`、`/api/skills`）——只报信息，不算失败（其中前几条由单元/设备脚本以别的方式覆盖或本就未纳入验收，详见各自章节）。
      · 牙口验证：故意在某脚本里加一条 `http://.../api/does_not_exist_xyz` → `FAIL no route serves /api/does_not_exist_xyz`；同时把注释里的路径（如头部说明里的 "api/settings export→import"）排除掉，避免把散文当端点（第一版就因为 `'/'` 前缀 + 注释误报，两处都已修）。
      · 已接入 `tools/verify_all.sh`（`verify_v94_device_script_routes.sh:host`）；门禁 `32 PASS / 0 FAIL / 84 SKIP`。
- [~] **v4.86 第四轮评审收口：C++ 侧归因缺口（P1）+ 4 条 P2（2026-09-19，host 验收 PASS；真机待做）**：评审独立复算了 v4.75 的错位（确认是真 bug，且受影响的是 **5 个**槽位）并把上一轮的说法逐条对账。
      · **P1（真缺口，已修）**：`adh_jni_exception_check()` 只覆盖了 8 个 C 模块的 52 处，**两个 C++ 模块没切**——`java_lsplant.cpp` 17 处、`java_enum.cpp` 11 处仍是 `env->ExceptionCheck()`，而且它们连头文件都没 include；`g_env_hook_in_ours` 又是 `jni_env_hooks.c` 的 file-static，C++ 侧根本设不了。修：两个文件 include `jni_env_hooks.h`、28 处全改走 helper；并补 `adh_jni_exception_clear()`（`ExceptionClear` 同样是可挂槽位），把 C++ 侧 **16 + 8 处**也切过去——"ADH 自己的异常检查不进事件流"这句话现在才真的成立。
      · **P2-4（越界读）**：`GetStringChars`/`GetStringCritical` 的预览原先假设"字符串自带 NUL 终止"，而 JNI 规范并不保证（critical 缓冲区尤甚）。现在**先取 `GetStringLength`**（在 critical 区之外、用守卫包住）**再按真实长度截断**；查询自身若抛异常只清掉我们那一份（用新的 `adh_jni_exception_clear`），不改目标语义。
      · **P2-5（最后一类静默错位）**：99 个固定槽的 dispatch case 从手写改为**列表驱动**（`ADH_FIXED_SLOT_LIST(ADH_FIXED_SLOT_CASE/WRAPPER_CASE)`）——"case 选中的槽位与它返回的 wrapper 配错、且两者签名相同"这种连签名断言/布局自检/offset 检查都看不见的错，从此由构造消除；v90 的 wiring 门禁改为校验**宏体必须把名字配到自己的字段/wrapper**（负对照：把家族 V 形态的 case 指向 base 字段 → `FAIL ADH_CALL_SLOT_CASES must selects &table->nameV`）。
      · **P2-1/2/3（口径更正）**：家族数是 **31**（19 value + 2 void + 9 NV value + 1 NV void）→ 签名断言 **93 条**（此前文档写 28/84，已全部改）；"布局自检拒绝 install/uninstall/status"应写作**拒绝 install/uninstall**，status 反而会带 `layout: ok|mismatch` + `layoutError`（已按此实现）；v4.75 错位的受影响槽位补上 `AllocObject` → **5 个**。
      · 验收：agent 零告警重建；v90 PASS（228/229，wiring 行现在是 `99 fixed slots dispatched from the list, 36 field accessors and 31 families kept paired, 0 silent wrappers`）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.85 归因卫生：ADH 自己的 JNI 工作不再被记成目标行为（2026-09-19，host 验收 PASS；真机待做）**：v4.79 只把 `ExceptionCheck` 一处改成直调；这一版把**类名解析与会话类装载**这两条"由 ADH 发起、却要经过 JNIEnv 表"的路径也收进守卫。
      · 新增 `adh_jni_ours_enter()/adh_jni_ours_leave()`（保存/恢复上一状态，可嵌套）：`jni.c` 的三个 helper 内部自行进出守卫——`adh_jni_app_class_loader`（FindClass/GetStaticMethodID/CallStaticObjectMethod/GetMethodID/CallObjectMethod）、`adh_jni_class_name`（GetObjectClass/GetMethodID/CallObjectMethod/GetStringUTFChars…）、`adh_jni_load_app_class`（FindClass/…/NewStringUTF）。
        这样无论调用者是谁（wrapper 内部、RegisterNatives 钩子回调、还是 `java_call`/`object_inspect`/`java_trace` 这些命令路径——`capture.c` 里 7 处、`inspection.c`/`actions.c`/`trace/commands.c` 还有 5 处），这些查找都不会再被记成目标事件（此前一旦挂了 `FindClass`/`GetMethodID`/`CallObjectMethod` 等槽位，仪表自己的查找就会污染事件流）。
      · 顺带修掉 `adh_jni_load_app_class` 的一处崩溃隐患：原实现把 `FindClass("android/content/Context")`、`FindClass("java/lang/ClassLoader")` 的结果**未判空**就传给 `GetMethodID`（解析失败即把 NULL class 交给 ART）；现在判空后返回 NULL（拿不到就返回 NULL，语义不变）。
      · 诚实边界（未做，留给后续）：**agent 主动触发的那次调用本身**（`java_call`/`object_invoke` 的 Call* 入口、`crypto_capture` 的触发）仍作为普通事件出现、不带"由 ADH 发起"的来源标记；要区分来源需要给事件加 origin 字段，属于后续设计，这一版不假装做了。
      · 验收：agent 零告警重建（1019 KB）；v90 PASS（228/229）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.84 门禁加牙：接线完整性 + "静默 wrapper" 检查（2026-09-19，host 验收 PASS）**：v90 此前只查"名字↔spec index"与覆盖数字，查不出两类只会在真机上暴露的错：**名字在列表里却没有 dispatch case**（真机上才 fail-loud），以及 **wrapper 装上了但从不发事件**（装了也白装）。
      · 接线：每个固定槽位必须在 `env_hook_slot()` 与 `env_hook_wrapper()` 两个 switch 里各有 case；字段访问器与 Call*/CallNonvirtual 家族则要求对应的宏展开（`ADH_FIELD_SLOT_LIST(ADH_FIELD_SLOT_CASE)`、`ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)` 等）确实存在。**负对照验证过牙口**：临时删掉 `FatalError` 的 slot case，v90 立刻报 `FAIL fixed slots with no dispatch case: FatalError (env_hook_slot)`，恢复后 PASS。
      · 发事件：每个 wrapper 生成宏（`ADH_DEFINE_*`）与每个手写 wrapper 必须含 `env_note(`/`call_emit(`，否则报 silent wrapper；当前 0 个（`env_hook_wrapper` 这个派发函数本身按名字排除）。
      · 验收：v90 PASS（228/229，`wiring: 99 fixed slots reachable in both switches, 0 silent wrappers`）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.83 v4.75–v4.79 的设备证据路径（夹具 + v91 `(3j)`）（2026-09-19，host 构建通过；真机待做）**：这几批槽位此前只有 host 侧证明，按老规矩补上"真机一次跑完"的路径。
      · 沙盒 native 夹具 `Detection.jniFamilyProbe`：八种 `New<Type>Array` + `GetArrayLength`、`NewObjectArray` + 对象数组元素读写（含 **NULL 元素合法** 那一条）、`AllocObject`、**三种形态的 `CallNonvirtualObjectMethod`**（配套新增 `JniNonvirtualBase/Child`：非虚调用必须返回父类实现 `base:t`，返回 `child:t` 就说明 hook 破坏了派发）、反射桥（`FromReflected*` 拿到的 id 必须**等于** `GetMethodID`/`GetFieldID` 的结果；`ToReflected*` 回来的对象名字必须是 `combine`/`counter`）、字符串族（`NewString`/`GetStringLength`/`GetStringUTFLength`/critical 对/`ReleaseStringUTFChars`）、`ExceptionCheck`（无挂起异常时必须报 false）。全过返回 `0xAD91FF`。
      · `tools/verify_v91_jni_env_fields.sh` 新增 `(3j)`：安装这 29 个槽位（27 个由夹具触发；`FatalError`/`UnregisterNatives` 只验证装卸——不能拿活进程触发）→ 被触发者必须各自有事件、关键字段逐条匹配（`len=4`、`index=0 -> 0x0 (null element)`、`class=com.adh.sandbox.JniCallTarget -> 0x`、`via=com.adh.sandbox.JniNonvirtualBase`、`static=0 -> 0x`、`text="ADH42"`、`pending=false` …）→ 逐个卸载；`pass` 纳入 `familyProbeOk`。
      · 诚实边界：`CallNonvirtual` 只触发 Object 形态（另外 27 个返回类型槽位共用同一套宏生成 + 93 条签名断言，但真机只证了 Object 这三个入口）；`FatalError`/`UnregisterNatives` 只证可装卸。
      · 验收：`build_detect.sh` 与 `:app:assembleDebug` 零告警 / 通过；v91 `bash -n` + 内嵌 JS `node --check`；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.82 单一来源 + 运行期布局自检：不再"挂到隔壁函数"（2026-09-19，host 验收 PASS；真机待做）**：v4.81 的组基址断言只钉住"组"，钉不住"组内顺序"。这一版把固定槽位改成**一份列表驱动三处**（枚举值 / 可安装名字表 / 名字映射），并加运行期自检——把"枚举与表错位"从"静默挂错函数"变成"拒绝执行 + 明确报错"。
      · 固定槽位改为 `ADH_FIXED_SLOT_LIST` 单一来源（此前枚举与名字表是两份手写清单，v90 只查"名字↔spec index"、查不出顺序）：枚举值、名字表顺序、`env_slot_name()` 的期望名全由它展开。
      · **这同时修掉一个 v4.75 引入的真 bug**：那 13 个新槽位在枚举与名字表里的插入位置不同（`AllocObject` 在枚举里紧跟 `ReleaseDoubleArrayElements`，在表里却排在 `SetObjectArrayElement` 之后），于是 `GetArrayLength`/`NewObjectArray`/`GetObjectArrayElement`/`SetObjectArrayElement`/`AllocObject` **这五个**槽位安装时会命中"隔壁"的 case——正是字段族那种静默错位（评审 P2-1 预测的同一类问题），只是这次由单一来源从根上消除。
      · 运行期自检 `env_hook_layout_ok()`：对全部 228 个位置比较"枚举给出的名字"与"表里的名字"，任何不一致 → **拒绝 install/uninstall**（status 仍放行，并在回复里带 `layout`/`layoutError`——出问题时正是要看它），并报"第 N 位：枚举说是 X、表里是 Y——拒绝 patch 任何东西"（结果缓存，不重复扫描）。
        诚实说明它的价值分布：对已经单一来源的两块（固定槽位、字段访问器）这条自检接近同义反复、只是兜底；对仍是"手写 `= prev + 3` 链 + 家族 X-macro 列表"两套的 Call*/CallNonvirtual 家族（31 个），它才是真正的门禁——那一层目前还靠这条自检 + v4.81 的组基址断言守着。
      · v90 改成解析新列表，并断言固定槽位恰好 99 条（少一条/多一条都要显式改门禁）。
      · 验收：agent 零告警重建（1018 KB）；v90 PASS（228/229）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.81 评审更正 + 把"整体平移"变成编译错误（2026-09-19，host 验收 PASS）**：subagent 独立复算（从各提交抽取枚举与宏、用 NDK clang 做静态断言，并带负对照）确认了字段错位，但**证伪了我对症状的描述**，这一版按事实改写文档并补上真正能挡住这类错位的门禁。
      · 症状更正：不是"每个字段槽都被拒"。**只有第一个字段 `GetObjectField` 落 `default` 被拒**；其余 35 个命中**上一个字段**的 case，把那个字段的槽位与 wrapper 装了进去、事件名却写成请求的名字——静默错位绑定，比响亮拒绝更危险（被点名字段的真实表项没被动过，它的调用永远不会有事件）。
      · 归因更正："两条总数断言抓出它"不成立（定长数组下恒真 / 错位下同样成立）。真正报错的是中间态的 `-Warray-bounds`（表 215 项 vs `ENV_HOOK_MAX` 216，`g_env_hooks[215]` 越界）。
      · 新增 **组基址断言**：`ENV_SLOT_CallObjectMethod == ENV_FIXED_SLOTS`、`ENV_SLOT_CallNonvirtualObjectMethod == ENV_SLOT_CallStaticVoidMethod + 3`、`ENV_SLOT_GetObjectField == ENV_SLOT_CallNonvirtualVoidMethod + 3`、`ENV_SLOT_SetStaticDoubleField == ENV_SLOT_GetObjectField + 35`——整体平移会在这里编译失败。
      · 结构收口：最后一个家族的 V/A 由"算术别名"改为**真枚举**（别名可删），字段块自然从 `base + 3` 开始。
      · 补齐 **Call*/CallNonvirtual 家族的签名证明**：31 个家族 × 3 形态 = **93 条 `_Static_assert`**（此前这两个家族一条都没有——wrapper 是强转成 `void*` 装进表的，签名错了只会在目标调用时炸）。
      · 验收：agent 零告警重建（1015 KB）；v90 PASS（228/229）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.80 JNIEnv status 可过滤 + 自报完整性（2026-09-19，host 验收 PASS；真机待做）**：228 个槽位的整表 status 已经超过早期一次回复能带的量——**旧实现会在 32 KB 处静默截断**，只回一部分 hooks 且不作说明，验证者会把"缺条目"读成"未安装"。
      · `action:status` 现在可以用 `function` 当过滤器（与安装同语法：精确名 / `Call*` 前缀 / `*Field` 后缀 / `*Field*` 包含 / `all`·`*` 全部），另加关键字 **`installed`**（只看当前挂着的槽位）；解析与匹配**与安装路径共用一份**（`env_filter_parse`/`env_filter_match`），不再有两套模式语言。
      · 回复自报完整性：`total`/`matched`/`emitted`/`truncated`——被过滤或被裁剪都写在回复里，"看起来完整"的残缺列表不再是可能状态；缓冲区提到 128 KB（agent 协议是长度分帧、上限 64 MB），整表 228 项正常一次带回且 `truncated:false`。
      · 安装/卸载路径显式拒绝 `installed` 关键字（它是 status 过滤器、不是槽位名），避免"把本来没挂的槽位当模式批量安装"。
      · MCP 描述同步；v91 新增 `(3i)` 段（真机）：整表必须 `matched==total` 且 `emitted==matched`（或 `truncated` 与 `emitted<matched` 自洽）、`*ArrayRegion` 必须正好 16 项、`installed` 必须只回已挂槽位并包含刚挂上的 `GetJavaVM`。
      · 验收：agent 零告警重建（1015 KB）；daemon `node --test` 151；v91 `bash -n` + 内嵌 JS `node --check`；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.77–v4.79 JNIEnv 表收尾：字符串全族 + 反射桥 + FatalError/ExceptionCheck（2026-09-19，host 验收 PASS；真机待做）**：把覆盖率名单的最后 13 项一次做完——**228/229 表项已可挂**，唯一余项由另一套机制覆盖。
      · v4.77 字符串族补齐 6 槽（覆盖率 **215 → 221**）：`NewString`（UTF-16 → Java 字符串，事件 `len=N text="…"` 有界预览）、`GetStringLength`/`GetStringUTFLength`（`string=.. len=N`）、`ReleaseStringUTFChars`（`string=.. chars=..`）、`GetStringCritical`/`ReleaseStringCritical`。**critical 那一对刻意不调任何 JNI 函数**（规范禁止在 critical 区里再调 JNI）：`GetStringCritical` 用"返回 NULL 即失败"代替 `ExceptionCheck`，预览只读已到手的内存；释放侧只记指针。
      · v4.78 反射桥 + 注销侧 5 槽（**221 → 226**）：`FromReflectedMethod`/`FromReflectedField`（`reflect=.. -> mid/fid=0x..`——id 正是 host 侧与 `GetMethodID`/`GetFieldID` 事件连接的关键，"用反射拿 id、绕开 ID 查询流量"的调用点从此可见）、`ToReflectedMethod`/`ToReflectedField`（带类名与 static 标志）、`UnregisterNatives`（`class=Class -> 0/-1`，卸载 native 绑定的信号）。
      · v4.79 最后两项（**226 → 228**）+ 一处必要的内部改造：`FatalError` **先写事件再调原函数**（规范上它永不返回、进程随即就死，事件是 best effort——ring 靠 host 循环排空）；`ExceptionCheck` 是表里最热的表项，为了不把**我们自己的**异常检查记成目标行为，agent 内部全部改走 `adh_jni_exception_check()`（用已保存的 original 直调、永不经过表）——不只是本文件，另外 8 个模块（bootstrap/capture/actions/art/inspection/jni/jni_method_names/trace）的 **52 处**调用也一起切过来，声明放在 `jni_env_hooks.h` 里，避免"某个模块忘了这条规则"；只有目标自己的调用会进事件（`pending=true/false`，按槽位预算封顶）。
      · 唯一剩下的 `RegisterNatives` 不是缺口：v4.14 起由 `jni_hooks.c` 的**入口 inline hook** 覆盖（JNI_HOOK 事件）；v90 现在把它显式列为 `COVERED_ELSEWHERE`，并加门禁——"未挂且不在该名单"的表项直接 FAIL，不允许悄悄漏掉。
      · 安全网：13 条新 `_Static_assert`；索引 163/164/168/170/224/225、7/8/9/12/216、18/228 由 v90 对 `jni.h` 机检（`checked 228 indices`），覆盖率下限提到 228。
      · 验收：agent 零告警重建（1014 KB）；v90 PASS（228/229，未覆盖名单只剩 `RegisterNatives` 且已分类）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.76 CallNonvirtual 全族入表 + 表/枚举一致性硬约束（2026-09-19，host 验收 PASS；真机待做）**：这一批把最大的剩余盲区一次收完，顺带揪出并修掉一个**从 v4.55 起就潜伏的字段槽位错位**。
      · 新增 30 槽（覆盖率 **185/229 → 215/229 = 94%**）：`CallNonvirtual{Object,Boolean,Byte,Char,Short,Int,Long,Float,Double}Method` 与 `CallNonvirtualVoidMethod`，各三种 JNI 形态（varargs / V / A）。非虚调用是"**调用方自己指定执行哪个实现**、绕过接收者运行时的类"，所以事件在常规成员标签后追加 `via=<class>`——"到底调了谁"是这类调用唯一值得记的东西。
      · **P1（潜伏 bug，本批修复；症状描述经 v4.81 评审更正）**：`ENV_SLOT_CallStaticVoidMethod_end` 是个纯算术锚点，但枚举成员**必然会占用一个值**，于是字段访问器整族的枚举值比它们在 `g_env_hooks[]` 里的位置**大 1**；安装路径"按名字取表位置 → `env_hook_slot(index)` 按枚举值 switch"因此错位——**第一个字段槽 `GetObjectField` 落到 `default` 被响亮拒绝，其余 35 个静默绑定到"上一个字段"的表项与 wrapper**（请求 `GetIntField` 实际挂上的是 `GetShortField` 的槽位与 wrapper），而事件名仍写成请求的那个字段：被点名的字段的真实表项从未被改，它的调用因此**不会产生任何事件**。所以 v4.55 的 36 个字段访问器、v4.58 的 `setValue` 改写、v4.56 的字段摘要从来没有真正生效（真机验收一直是待做，v91 的字段段与 `*Field` 计数在真机上必然失败，所以没人发现）。现在最后一个家族的 V/A 写成真枚举（`ENV_SLOT_CallNonvirtualVoidMethodV/A`），字段块落在 179–214 与表一一对应。
      · 顺带修掉 Call* 族的**重入守卫不对称**：varargs 形态缺少 `g_env_hook_in_ours` 检查（V/A 形态有），agent 自己解析类名时经过 `CallObjectMethod` 的内部调用会被当成目标事件记下来。
      · 安全网升级：`g_env_hooks[]` 改成**不定长数组**并加编译期不变式——表长必须等于 `ENV_HOOK_MAX`、最后一个字段槽是 `ENV_HOOK_MAX-1`，v4.81 又补上**组基址断言**（`ENV_SLOT_GetObjectField == ENV_SLOT_CallNonvirtualVoidMethod + 3` 等）。注意事实边界（评审更正）：暴露这个 bug 的并不是那两条总数断言——定长数组下 `sizeof/sizeof == ENV_HOOK_MAX` 恒真、末字段断言在错位版本同样成立；真正报错的是"不定长数组 + 新增 CallNV 家族而 `_end` 锚点还在"这个中间态的 `-Warray-bounds`。能抓住"整体平移"的是后补的**基址断言**。索引 64–93 由 v90 对 `jni.h` 机检（`checked 215 indices`），覆盖率下限**再提到 215**。
      · 剩余 14 个盲区（v90 名单）：`From/ToReflected*` 4 项、`NewString`/`GetStringLength`/`GetStringUTFLength`/`ReleaseStringUTFChars`/`Get+ReleaseStringCritical` 6 项、`FatalError`、`UnregisterNatives`、`ExceptionCheck`（`RegisterNatives` 已在 v4.14 注册路径覆盖，这里是 env 表口径）。
      · 验收：agent 零告警重建（998 KB）；v90 PASS（215/229，94%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.75 JNIEnv 创建 / 长度 / 对象数组 / AllocObject（2026-09-19，host 验收 PASS；真机待做）**：覆盖名单里剩下的"跟数组有关但不在 region/elements 两族"的表项一次收完——**造数组**（8 个 `New<Type>Array` + `NewObjectArray`）、**问长度**（`GetArrayLength`）、**对象数组元素读写**（`Get/SetObjectArrayElement`）和**不开构造器直接分配对象**（`AllocObject`）。
      · 新增 13 槽（覆盖率 **172/229 → 185/229 = 81%**）：事件分别是 `len=N -> 0x..`（造数组，含元素类名的 `elem=Class`）、`array=.. len=N`、`array=.. index=N -> 0x..`、`array=.. index=N value=0x..`、`class=Class -> 0x..`。
      · 语义细节：`GetObjectArrayElement` 的 **NULL 元素是合法的**，所以 `ok` 跟异常状态走、文案区分 `-> 0x0 (null element)` 与越界抛异常的 `<call failed>`；`New*Array`/`AllocObject` 的 NULL 返回必然伴随异常（OOM/负数长度/Instantiation 问题），`ok` 取 `!failed && result != NULL`，不会把"没造出来"记成成功。
      · 安全网照旧：13 条 `_Static_assert` 签名证明、索引 27/171–182 由 v90 对 `jni.h` 机检（`checked 185 indices`），覆盖率下限**再提到 185**（86 固定 + 36 字段访问器 + 21 族 ×3 = 185，与 spec 索引数一致）。
      · 剩下的 44 个盲区已经在 v90 的未覆盖名单里点名：`CallNonvirtual*` 30 项（最大一块）、字符串 6 项（`NewString`/`GetStringLength`/`GetStringUTFLength`/`ReleaseStringUTFChars`/`Get+ReleaseStringCritical`）、反射桥 4 项（`From/ToReflected*`）、`FatalError`/`UnregisterNatives`/`ExceptionCheck`（`RegisterNatives` 已在 v4.14 的注册路径覆盖，这里是 env 表槽位口径）。
      · 验收：agent 零告警重建（969 KB）；v90 PASS（185/229，81%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.74 数组元素族补上设备证据路径（2026-09-19，host 构建通过；真机待做）**：v4.72 的 14 个表项此前只有 host 侧证明，按 v4.63→v4.64 / v4.70→v4.71 的老规矩补齐真机路径，且这次带上**语义不变量的证明**。
      · 沙盒 native 夹具 `Detection.jniArrayElementsProbe`：七种类型各"Set 种子 → Get 拿指针 → 改第 0 个元素 → Release(copyback) → GetArrayRegion 回读"，回读必须**正好**等于改写后的期望值（`memcmp` 比较 want/back，不是"没等于旧值就算过"）；再多跑一轮 `int[]` + `JNI_ABORT`，回读必须仍是旧值——**hook 不许把 abort 变成 commit**。全过才返回 `0xAD80FF`（7 位类型 + 0x80 abort）。
      · `tools/verify_v91_jni_env_fields.sh` 新增 `(3h)` 段：能力前置检查（旧 agent → SKIP）、夹具缺失（旧 APK → SKIP）、逐个安装 14 个表项 → 触发 → 断言**每个表项各有自己的事件**且形状正确（`len=4`、`elements=0x<非零>`、Get 带 `isCopy=0|1`、Release 带 `mode=<n>(...)`、`first=[…]`）→ Release 预览逐类型精确匹配（copyback）→ abort 轮必须出现 `mode=2(abort)` 且预览里带着那个被丢弃的值 → 逐个卸载；`pass` 表达式纳入 `elementsProbeOk`，事件窗口照旧印 capture health。
      · 验收：`build_detect.sh` 重建 `.so`（`llvm-nm` 可见 `Java_com_adh_sandbox_Detection_jniArrayElementsProbe`）、`:app:assembleDebug` PASS（`Detection.class` 含声明）、v91 `bash -n` + 内嵌 JS `node --check` 通过；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。真机由 v91 一次跑完 `(3f)(3g)(3h)` 三段。
- [~] **v4.73 评审收口：v4.70/v4.71 的 1 条 P1 + 5 条 P2 全部落地（2026-09-19，host 验收 PASS）**：评审独立复跑了 v90 的索引机检并确认 14 条签名证明、四处派发点与 `_Static_assert` 齐全（无 P0/P1 落在 agent 正确性上），报出的问题集中在"验证脚本自己会不会骗人"。
      · **P1（验证脚本）**：v91 的 `fail()` 直接 `process.exit`，而数组区域段的三个硬失败点都在逐个卸载之前——失败时目标进程的 JNIEnv 表**留着被改写的槽位**，后续脚本会看到多出来的事件。现在所有安装都记进 `installedSlots`，`fail`/`skip` 出口统一 `uninstallAll()`，各段落装卸走 `installSlot`/`uninstallSlot`（15 处终态调用全部 `await`）。
      · **P2-1（agent）**：`Get/Set<T>ArrayRegion(arr, 0, 0, NULL)` 这类**零长度无缓冲**的成功调用被记成 `ok=false`。判据改成 `!failed && (buf != NULL || len == 0)`。
      · **P2-2（验证脚本）**：数组区域段缺能力前置检查，遇到旧 agent/旧 APK 会 FAIL 而不是脚本头承诺的 SKIP；现在先查 status 里的槽位名单（旧载荷 → SKIP），夹具方法不存在（`java_call` 非 ok）→ SKIP，只有"夹具跑通但返回码不对"才 FAIL。
      · **P2-3（可诊断性）**：事件窗口加印 `capture health: dropped/backlog/complete`，"事件缺失"与"环被冲掉"不再只能靠猜。
      · **P2-4（夹具）**：`jniArrayRegionProbe` 只在函数末尾查异常——`New*Array` 分配失败时后面几段会带着挂起异常继续调 JNI（CheckJNI 下是 abort）。现在每段 `!a` 立即清异常并返回已得 bits（少一位就不是 `0xAD707F`）。
      · **P2-5（门禁）**：v90 的字段访问器清单从"非空"改成**必须恰好 36 条**（改动列表就得显式改这个数）。
      · 顺带：MCP `jni_env_hook` 的描述补齐到当前能力面（字符串拷贝/pin、直接缓冲、异常流、`GetJavaVM`、引用生命周期、类型自省、monitor/弱引用、数组 region 与数组元素族），并写明 `*ArrayRegion`/`*ArrayElements` 这类后缀通配。
      · 验收：agent 零告警重建（956 KB）；`build_detect.sh` 零告警；v90 PASS（172/229，75%）；v91 `bash -n` + 内嵌 JS `node --check`；daemon `node --test` 151 条；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.72 JNIEnv 数组元素族（pin + 写回）全入表（2026-09-19，host 验收 PASS；真机待做）**：v4.70 补的是"整段 region 搬运"，这一批补**指针族**——`Get<Type>ArrayElements` 直接把数组元素指针交给 native（可能是真指针也可能是副本，`isCopy` 说了算），`Release<Type>ArrayElements` 才是写入真正落地的地方，而 `mode` 决定落还是不落（`JNI_ABORT` = 目标的修改被丢掉）。这是"谁改了数组、改的东西有没有生效"最直接的信号。
      · 新增 14 槽（覆盖率 **158/229 → 172/229 = 75%**）：`Get/Release{Boolean,Char,Short,Int,Long,Float,Double}ArrayElements`（`Byte` 那一对在 v4.19 已覆盖）。事件 `array=.. len=.. elements=.. isCopy=.. first=[…]`；Release 事件额外给 `mode=0(copyback)|1(commit)|2(abort)`。
      · 两条纪律：**长度只在不处于挂起异常时**用 `GetArrayLength` 取（有挂起异常还调 JNI 是非法用法，CheckJNI 会 abort——v4.69 的老教训），预览严格按取回的长度截断到 4 个元素，不会越界读；Release 的预览在**调用原函数之前**读（缓冲区此刻仍有效），所以 `abort` 的事件里显示的正是"被丢弃的那些值"，不是猜测。
      · 文案差异是刻意的：`Byte` 那对沿用 v4.19 的 `hex=`（被 v59/v63 设备断言钉死），新 13 个类型用 `first=[…]`（更可读）。想统一要连设备断言一起改，不在这一版里偷偷改。
      · 安全网照旧：14 条 `_Static_assert` 签名证明、索引 183–198 由 v90 对 `jni.h` 机检（`checked 172 indices`），覆盖率下限**再提到 172**（59/73 固定槽 + 36 字段访问器 + 21 族 ×3 = 172，与 spec 索引数一致）。
      · 验收：agent 零告警重建（956 KB，新槽位名在 `.so` 里可 grep 到）；v90 PASS（172/229，75%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.71 数组区域族补上设备证据路径（2026-09-19，host 构建通过；真机待做）**：v4.70 的 14 个表项此前只有 host 侧证明，按 v4.63→v4.64 的老规矩把真机路径补齐。
      · 沙盒 native 夹具 `Detection.jniArrayRegionProbe`：七种类型各"写回读"一遍（固定内容，便于逐条断言事件预览），全部往返成功才返回 `0xAD707F`（`0xAD7000 | 0x7F`）——少一位就是少一个类型往返，夹具不掩盖失败。
      · `tools/verify_v91_jni_env_fields.sh` 新增 `(3g)` 段：逐个安装 14 个表项 → 触发夹具 → 要求**每个表项各有自己的事件**且 `start=0 len=4 first=[<期望值>]` 精确匹配（Get/Set 两侧都要）→ 逐个卸载；`pass` 表达式纳入 `arrayProbeOk`，头注释同步。
      · 验收：`build_detect.sh` 重建 `.so`（`llvm-nm` 可见 `Java_com_adh_sandbox_Detection_jniArrayRegionProbe`）、`:app:assembleDebug` PASS（`Detection.class` 含声明）、v91 `bash -n` + 内嵌 JS `node --check` 通过；整段在真机上由 v91 执行（当前无设备 → SKIP）。
- [~] **v4.70 JNIEnv 数组区域读写全族（2026-09-19，host 验收 PASS；真机待做）**：覆盖率名单里的下一批——`Get<Type>ArrayRegion` 把 Java 数组整段搬进 native 缓冲、`Set<Type>ArrayRegion` 把 native 数据写回 Java 数组。脱壳/校验/协议解析都走这条批量通道，写回事件还是"目标动了数组内容"的直接证据。
      · 新增 14 槽（覆盖率 **144/229 → 158/229 = 69%**）：`Get/Set{Boolean,Char,Short,Int,Long,Float,Double}ArrayRegion`（ABI 里没有 `SetObjectArrayRegion`，所以是 14 不是 16；`Byte` 那对在 v4.19 已覆盖）。
      · 事件格式 `array=0x.. start=N len=N first=[…]`（最多 4 个元素的有界预览，按类型给格式 `%d`/`%u`/`%lld`/`%g`）；调用抛异常时**不读缓冲区**，事件写 `<call failed>` 且 `ok=false` —— v4.66 那条"失败的拷贝不是证据"的教训直接复用。
      · 安全网照旧：14 条 `_Static_assert`（`Set*ArrayRegion` 的 `const <T> *` 形参由编译器逼出来，手抄错就是编译失败）、索引 199–214 由 v90 对 `jni.h` 机检（`checked 158 indices`），覆盖率下限**再提到 158**；v90 的清单同时补上 36 个字段访问器（59 固定 + 36 字段 + 21 族 ×3 = 158 表项，与 spec 索引数一致）。
      · 验收：agent 零告警重建；v90 PASS（158/229，69%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.69 JNIEnv 类型自省 / monitor / 弱引用 / GetVersion（2026-09-19，host 验收 PASS；真机待做）**：覆盖率名单里再下一批——**类型自省**（反篡改代码天天问"你是不是 XX 类的子类/实例/这个引用是什么类型"）、**monitor**（死锁/反调试的锁行为）、**弱引用对**与 `GetVersion`。
      · 新增 11 槽（覆盖率 **133/229 → 144/229 = 63%**）：`GetVersion`（`version=0x..`）、`DefineClass`（**动态加载类**：name + loader + 字节数 + 结果类）、`GetSuperclass`（`class -> super`，带类名）、`IsAssignableFrom`（`A <- B = true/false`）、`GetObjectClass`（`obj -> class`）、`IsInstanceOf`（`obj class = true/false`）、`MonitorEnter`/`MonitorExit`（`monitor=0x..`，成对出现）、`NewWeakGlobalRef`/`DeleteWeakGlobalRef`、`GetObjectRefType`（`local/global/weak/invalid`）。
      · 安全网照旧：11 条 `_Static_assert`、索引由 v90 对 `jni.h` 机检（`checked 144 indices`），覆盖率下限**再提到 144**；类名解析只在**入口无挂起异常**时做（避免 CheckJNI 下 abort 的老问题）。
      · 验收：agent 零告警重建；v90 PASS（144/229，63%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.68 JNIEnv 引用生命周期（2026-09-19，host 验收 PASS；真机待做）**：覆盖率名单里的下一批——**引用生命周期**。目标创建了哪些引用、有没有释放、有没有把 global ref 泄漏、有没有把 local frame 一直开着，这些都是可直接读的分析信号，而且这 8 个表项是**每个 JNI 库都会碰**的。
      · 新增 8 槽（覆盖率 **125/229 → 133/229 = 58%**）：`PushLocalFrame`（capacity）、`PopLocalFrame`（result → 返回值）、`NewLocalRef`/`NewGlobalRef`（ref → 新引用）、`DeleteLocalRef`/`DeleteGlobalRef`（ref）、`IsSameObject`（a/b/same）、`EnsureLocalCapacity`（capacity）。
      · 安全网照旧：8 条 `_Static_assert` 签名证明、索引 19/20/21/22/23/24/25/26 由 v90 对 `jni.h` 机检（`checked 133 indices`），覆盖率下限**再提到 133**（只升不降）。
      · 验收：agent 零告警重建；v90 PASS（133/229，58%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.67 JNIEnv 异常流 + VM 句柄（2026-09-19，host 验收 PASS；真机待做）**：覆盖率报告（v4.66）点名的下一批高价值表项就是**异常流**——反分析代码常用异常当控制流，"抛了什么、谁清掉的"本身就是信号；`GetJavaVM` 则是目标拿到 VM 句柄去做更激进事情的入口。
      · 新增 6 个槽（覆盖率 **119/229 → 125/229 = 55%**）：`Throw`（事件带 throwable 指针 + 类名）、`ThrowNew`（类名 + **有界消息预览**）、`ExceptionOccurred`（只报指针——**此时异常正在挂起，绝不能再调 JNI 取类名**，否则 CheckJNI 直接 abort，这条写进注释）、`ExceptionDescribe`/`ExceptionClear`（成对出现，看清"谁把异常吞了"）、`GetJavaVM`（vm 指针）。
      · 安全网照旧：6 条 `_Static_assert` 钉死签名、索引 13/14/15/16/17/219 由 v90 对 `jni.h` 机检（`checked 125 indices`），安装期仍 refuse 偏移不符；v90 的覆盖率下限**从 115 提到 125**（只升不降）。
      · 验收：agent 零告警重建；v90 PASS（125/229，55%）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.66 评审收口 + JNIEnv 覆盖率报告（2026-09-19，host 验收 PASS）**：评审给了两条 P1 和一条结构建议，全部落地。
      · **P1（事件可信度）**：`GetStringRegion`/`GetStringUTFRegion`/`GetStringChars` 此前在**调用失败（抛异常）后仍读缓冲区做预览**——越界时 ART 抛 `StringIndexOutOfBoundsException` 且**不写 buf**，于是我们会把**调用方的未初始化内存**当"目标拷走的字符串"打进事件，还报 `ok=1`。现在调用后立刻 `ExceptionCheck`，失败则**跳过预览**、事件写明 `<copy failed, buffer untouched>` 且 `ok=false`；`GetDirectBufferCapacity` 的 `capacity=0` 也改成显式标注（"空直接缓冲 or 非直接缓冲"），不再让人猜。
      · **P1（验收强度）**：v91 的 `textOk` 原本是"三个字符串读取器里两个命中即可"，而三个 wrapper 是**独立代码路径**——现改为**逐个证明**（`utf16 && utf8 && pin && release` 四条独立断言），并把 `strCalls >= 7` 换成 `>= STR_FUNCS.length`（去掉魔数）。
      · **结构建议（已采纳）**：`tools/verify_v90_jni_table_abi.sh` 新增**覆盖率报告**——它本来就有 ABI 字段序与 agent 的索引表，现在直接输出 **`coverage: 119/229 function-table entries hooked (52%)`** 与**未覆盖名单**（`GetVersion`、`DefineClass`、`ExceptionOccurred`、`PushLocalFrame`…），并设了 `>= 115` 的下限门禁。这样"JNIEnv 全表可挂"从一个方向变成一个**数字**，下一步该补哪些槽位由名单而不是手感决定（与 v87 的 op-coverage 同一模式）。
      · 验收：agent 零告警重建；v90 PASS（119 条索引 + 覆盖率报告）；v91 语法/SKIP 通过；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.65 JNIEnv 补"pin 住 Java 字符串"的一对（2026-09-19，host 验收 PASS；真机待做）**：v4.63 覆盖的是"把字符串**拷进** native 缓冲"，另一条常见路径是**直接拿字符串内部指针**（`GetStringChars`）再 `ReleaseStringChars` 放回——指纹/校验代码用它是为了省一次拷贝。
      · agent：JNIEnv 表 117 → **119 槽**。`GetStringChars` 事件带 `string=0x.. isCopy=true/false text="…"`（**有界预览**：最多 24 个字符、遇字符串自带的 `\0` 终止符即停，不会越过字符串尾读内存）；`ReleaseStringChars` 事件带 `string=.. chars=..`，把"pin → 放回"这一对在时间线上对齐。
      · 签名照旧由 `_Static_assert` 编译期钉死；索引 165/166 由 `tools/verify_v90_jni_table_abi.sh` 对 NDK `jni.h` 机检（现在 `checked 119 indices against the ABI`，20 固定 + 21 族 ×3）。
      · 夹具与验收：沙盒探针 `jniStringProbe` 增加 `GetStringChars` + `ReleaseStringChars` 一对（返回调用次数 5 → 7）；v91 的 `(3f)` 段把两者纳入 `STR_FUNCS`，并要求**三个字符串读取器里至少两个**出现 `text="…ADH-STR…"` 预览、`ReleaseStringChars` 事件带 `chars=0x…`——单个入口坏掉不再能蒙混过关。
      · 验收：agent 零告警重建；`tools/build_detect.sh` PASS；v90 PASS（119 条）；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.64 v4.63 的设备半 + 沙盒夹具（2026-09-19，host 验收 PASS；真机待做）**：新加的 5 个表项（字符串拷出 + 直接缓冲）此前只有实现，没有真机验证路径。
      · 沙盒新增 native 探针 **`Detection.jniStringProbe`**：`NewStringUTF` 造一个可识别字符串 → `GetStringRegion`（UTF-16，24 字符）+ `GetStringUTFRegion`（UTF-8，48 字节）各拷一次 → 对 64 字节本地缓冲 `NewDirectByteBuffer` → `GetDirectBufferAddress` + `GetDirectBufferCapacity`，返回实际调用次数。**`tools/build_detect.sh` 与 `sandbox-app` 的 `:app:assembleDebug` 都已在 host 上构建通过**（native 夹具 + Kotlin 声明 + APK）。
      · v91 新增 `(3f)`：逐个安装这 5 个槽 → 取 capture 游标 → 触发探针（`calls ≥ 5`）→ 断言**每个被 hook 的表项都出事件**，且内容达标：字符串事件必须带 `text="…ADH-STR…"` 预览，直接缓冲事件必须带 `address=0x…` 与 `capacity=64`；随后逐个卸载并把结果纳入 `pass`。
      · 验收：host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.63 JNIEnv 再补 5 个表项：字符串拷出 + 直接缓冲（2026-09-19，host 验收 PASS；真机待做）**：评审列的两个盲区正是指纹/算法分析最常踩的路径——**native 把 Java 字符串拷进自己的缓冲区**（`GetStringRegion`/`GetStringUTFRegion`）与**native 把大块数据以直接 ByteBuffer 交给 Java**（`NewDirectByteBuffer`/`GetDirectBufferAddress`/`GetDirectBufferCapacity`）。JNIEnv 表从 112 → **117 槽**（18 固定 + 21 族 ×3）。
      · 事件内容：字符串拷出事件带 `string=0x.. start/len` 与**有界文本预览**（UTF-16 24 字符、UTF-8 48 字节，不可打印转 `.`）——"它把哪个字符串拷走了"直接可读；直接缓冲事件带 `address/capacity`（`NewDirectByteBuffer` 另带返回的 jobject）。
      · 安全网照旧：每个 wrapper 有 `_Static_assert` 钉死与表项的签名一致（签名不符编译期失败，不是真机崩），索引由 `tools/verify_v90_jni_table_abi.sh` 对着 NDK `jni.h` 校验（现在 `checked 117 indices against the ABI`），安装期仍做偏移不符即拒绝。
      · 验收：agent 零告警重建（891,184 B）；v90 PASS；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.62 v91 收口：修掉自己引入的 TDZ + 断言"摘要真的看到改写"（2026-09-19，host 语法/SKIP 验证 PASS；真机待做）**：v4.61 之后，设备脚本应当在真机上把"观测 → 改写 → 摘要"串起来。
      · **自查抓到第二个自伤 bug**：v91 的 `overrideOk` 引用了**尚未声明**的 `const ovRestoreOk`（TDZ），真机执行到那段会直接抛 `ReferenceError`——已把还原步骤提到断言之前。
      · 新增 `(3e)`：覆盖生效并触发探针后，再调 `jni_field_digest`，要求 **`rewrittenSamples ≥ 1`** 且存在 `rewritten ≥ 1` 的分组、其 **`lastRequested === '7'`**（即"目标想写 7、被写成 42"这件事在摘要里可见），并纳入 `pass`。
      · `FEATURE_STATUS` §3 补上诚实的盲区说明：JNIEnv 面目前覆盖「ID 查询 + Call*/NewObject 三形态 + 数组/字符串读取 + 36 字段访问器」，`GetStringRegion`/`SetStringRegion`/`NewDirectByteBuffer`/`GetDirectBufferAddress` 等仍是盲区（同机制可加，索引由 v90 机检）。
- [~] **v4.61 字段摘要区分"被改写的写入"（2026-09-19，host 验收 PASS；真机待做）**：评审点名这是 v4.58 之后最该补的一条——现在摘要把"native 想把 `isRooted` 写 true、被我们改成 false"和普通写入**混在一起**，而那个差值本身就是结论。
      · `daemon/src/jni_field_digest.ts`：detail 解析改成 `field=0x.. value=<应用值> [requested=<原值>]`，新增 **`rewrittenSamples`（顶层）**、**每组 `rewritten` 计数与 `lastRequested`**，并在 `notes` 里明确写出"有 N 次写入被激活的 setValue 覆盖改写"；`lastValue` 语义固定为**目标最终存下的值**（应用值），`lastRequested` 才是目标原本要写的值。
      · 单测 5 → **7**（一条证明改写被单列且 requested/applied 不混；一条证明没有覆盖时不会误报）；MCP 描述写明这层语义；`tools/verify_v92_jni_field_digest.sh` 的断言同步（最小测试数 5 → 7 + "摘要必须暴露 rewrittenSamples"）。
      · 验收：daemon 单测 **151**；v92 PASS；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.60 覆盖功能收口：REST 参数面 P0 + 严格解析 + 范围检查 + 内存序（2026-09-19，host 验收 PASS；真机待做）**：评审在 v4.58/v4.59 里抓到一个**我引入的 P0**——`setValue` 只接进了 MCP，**REST 路由 `/api/jni/env_hook` 把它丢了**，而设备脚本 v91 走的正是 REST，那条"覆盖后 counter 必须变 42"的断言在真机上**永远不可能成立**。已修：
      · **P0**：路由补上 `setValue` 的解析与转发，并在 host 侧加了一条**通用参数面检查**（v92）：把 `jni_env_hook` MCP schema 的每个属性名拿去比对 REST handler 块，缺哪个就红——这次输出 `REST parity: ... forwards all 4 MCP parameters (session, setValue, action, function)`。这类"只接了 MCP、忘了 REST"在本仓库出现过多次（v4.49 scope、v4.50 slotsWritable），现在至少这条路径被机检钉住。
      · **P1**：`setValue` 的解析又犯了 v4.53 抓过的老毛病（`strtoll/strtod` 传 NULL endptr）：`"abc"` 会静默改成 0、`"1e3"` 在 int 字段上得到 1（strtoll 停在 e）而 float 字段得到 1000。现在**整串必须是数字**（endptr 走到结尾 + 查 errno），并且"只有浮点解析成功"时把 `ov_i` 同步成 `(long long)ov_d`，两种字段类型拿到同一个数值；垃圾串直接 fail-loud。
      · **P2 全修**：① **按目标类型做范围检查**（Boolean 0/1、Byte -128..127、Char 0..65535、Short ±32767、Int 全 int 范围、Float/Double 必须 `isfinite`）——`setValue:"300"` 装到 boolean 槽以前会静默写成 `(jboolean)300 == 0`；② `override_active` 改成 **release 发布 / acquire 读取**，值写在标志之前，status 读覆盖时**持同一把锁**（此前是 relaxed + 普通读，严格说是数据竞争）。
      · v91 证据再加固：覆盖前先断言夹具 `counter == 7`（否则"之后是 42"本身可能是夹具本来就是 42）、capture 基线失败不再静默降级成 0、`uninstall` 与 `object_set` 还原的返回值纳入 `pass`。
      · 验收：agent 零告警重建；daemon 单测 149；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.59 覆盖状态可见 + v91 证据加固（2026-09-19，host 验收 PASS；真机待做）**：v4.58 的 `setValue` 是"装了就在改写"，但 status 里看不到——操作者无法确认某个 `Set<Type>Field` 是否仍处于改写状态。
      · agent：`jni_env_hook status` 的每个槽位新增 **`"override"`**（未开启为 `null`，开启时给出整数值；若安装的是小数则给 `%g`）。这样"还有哪些槽在改写"一眼可见，卸载后自动回到 `null`。
      · v91 证据加固（评审指出事件断言可能被**历史事件**满足）：触发前先取 capture 游标，之后的 `JNI_ENV` 事件只统计 `id > cursor` 的；`*Field` 模式卸载的返回值也纳入 `pass`（此前只打印）。
      · 验收：agent 零告警重建；daemon 单测 149；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.58 JNIEnv 字段写入可改写 + 评审 P2 收口（2026-09-19，host 验收 PASS；真机待做）**：评审指出 36 个字段槽位目前**只能看不能改**——而"native 代码把 `isRooted` 写回 false"正是这类分析最常见的诉求，且 native hook 早有 `returnValue` 先例。
      · agent：`jni_env_hook` 新增 `setValue`（数字，**单槽**）：命中的 `Set<Type>Field` wrapper 在调用原函数前把值替换成覆盖值，事件同时给出 **`value=<应用值> requested=<原值>`**；覆盖状态存在槽位里，卸载即清除（不会留着继续改写）。**只允许 boolean/byte/char/short/int/long/float/double**：对象字段需要 agent 不持有的对象引用 → 直接拒绝并说明；`setValue` + 通配模式也被拒绝（"needs a single Set<Type>Field slot"）。实现上覆盖值在安装时解析成 `long long` 与 `double` 各一份，热路径不做字符串解析。
      · 评审 P2 一并收口：`GetFieldID`/`GetStaticFieldID` 在**无异常但返回 NULL** 时不再报 `ok=1`（那会在字段摘要里留一个静默空洞）；预算是"跳过细节"而不是"调用失败"，预算耗尽时事件改为 `ok=<真实结果>` + `value="<budget spent>"`；两个 ID wrapper 补上自己的 typedef 与 `_Static_assert`（签名不符编译期就报错，实测 exit 1）。
      · **自查抓到**：设备脚本 v91 之前写的是 `action: 'hook'/'unhook'`，而 agent 的动作名是 **`install`/`uninstall`**——非 install 会走卸载分支，真机上会"装了个寂寞"。已全部改正，并新增：`*Field` 一次安装 ≥36 槽、`setValue=42` 覆盖 `SetIntField` 后目标里 `counter` 必须变成 42（再卸载并用 `object_set` 还原夹具）。
      · 验收：agent 零告警重建（884,352 B）；v71 注册表 PASS；daemon 单测 149；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）。
- [~] **v4.57 JNIEnv 钩子选择器支持后缀/包含匹配（2026-09-19，host 验收 PASS；真机待做）**：v4.55 之后字段访问器有 36 个槽，但选择器只支持**前缀**通配（`CallIntMethod*`），想一次挂上整个字段族没有写法。现在四种形态都支持：`"*"`/`"all"` = 全部、`Call*` = 前缀、**`*Field` = 后缀**（一次挂上 36 个字段访问器）、**`*Field*` = 包含**（同时命中 `GetFieldID`/`GetStaticFieldID` 与访问器——这正是字段摘要解析名字所需要的组合）。匹配用有界比较实现，不依赖 NUL 终止的子串；命中数/失败数与首个失败原因照旧上报。
      · 接线：MCP `jni_env_hook` 的描述把四种模式与"36 个字段访问器"写清楚（AI 客户端不必猜）；设备脚本 v91 新增一段：用 `*Field` 一次安装，status 里 `installed` 且名字以 `Field` 结尾的槽位**必须 ≥ 36**，再用同一模式整体卸载。
      · 验收：agent 零告警重建；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本）；daemon 单测 149。
- [~] **v4.56 字段事件可归因 + JNIEnv 字段摘要（2026-09-19，host 验收 PASS；真机待做）**：v4.55 的 36 个字段槽位会发事件，但事件里只有一个**不透明的 `jfieldID`**（`field=0x..`）——分析者读不出"这是哪个字段"。
      · agent：`GetFieldID`/`GetStaticFieldID` 的事件 detail 现在**带上它们交出去的 id**（`Class#name:sig -> 0x..`），访问事件这才有名字可对。
      · host：新增 `daemon/src/jni_field_digest.ts`（纯函数 `digestJniFields` + `jniFieldDigest`）：用 id 事件建 `id → Class#name:sig` 表，再把访问事件按 **(accessor, field)** 分组，给出次数、最后值、线程、时间窗；**没见过的 id 保持原始指针并计入 `unresolvedAccesses`**（不猜名字）；空窗口给出"还没 hook 字段槽位"的说明而不是干净结果；drain 走共享 `drainSession`（java_trace P0 的教训）。
      · 接线：MCP `jni_field_digest`（77 → **78** 工具）+ `POST /api/jni/field_digest`；`tools/verify_v92_jni_field_digest.sh`（host：5 条单测 + agent 必须带出 id + digest 必须走共享 drain 且不得发裸 `capture_drain` + MCP/REST 形状）**PASS**；设备脚本 v91 扩成"hook GetFieldID 一起 → 触发探针 → **摘要里至少一组 resolved 且字段名含 `#`**"。
      · 验收：agent 零告警重建；daemon 单测 **149**；host 全量门禁 **31 PASS / 0 FAIL / 84 SKIP**（115 脚本 = 31 host + 84 device）。
- [~] **v4.55 JNIEnv 字段访问器 36 槽（2026-09-19，host 验收 PASS；真机待做）**：评审点名的覆盖缺口——native 代码通过 `env->Get/Set<Type>Field` 读写字段这条路径此前**完全看不见**（`object_set` 只覆盖反射路径）。现在 JNIEnv 表从 76 槽扩到 **112 槽**。
      · agent（`runtime/jni_env_hooks.c`）：新增 36 个槽（Object/Boolean/Byte/Char/Short/Int/Long/Float/Double × Get/Set × instance/static），**一份列表宏驱动枚举/名字表/结构体字段 case/wrapper 派发**（四处不可能漂移），每个 wrapper 转发给保存的原函数并记一条有界事件（`field=0x.. value=..`），沿用既有的重入守卫、预算门与 RELRO 还原语义。
      · **签名安全**：每个 wrapper 都跟它所替换的表项做 `_Static_assert(__builtin_types_compatible_p(typeof(表项), typeof(&wrapper)))`——签名不符**编译期就失败**，不会等到真机把目标的每次 JNI 调用带崩；索引则由 `tools/verify_v90_jni_table_abi.sh` 对着 NDK `jni.h` 机器校验（76 现有 + 36 计划索引全部一致），加上安装期 `slot_offset == spec*sizeof(void*)` 的 refuse 共三层。
      · 夹具与验收：沙盒新增 `HeapProbe.sCounter`（static int）+ native 探针 `Detection.jniFieldProbe`（走 GetStaticObjectField → Get/SetIntField、Get/SetBooleanField、Get/SetObjectField、Get/SetStaticIntField）；`tools/verify_v91_jni_env_fields.sh`（device，**脚本已就绪**）hook 其中 5 个槽、触发探针、要求每个被 hook 的访问器都出事件且 value 含 `field=0x`、表页仍为只读、卸载后槽位还原、进程存活。无设备时干净 SKIP。
      · agent 零告警重建；host 门禁 **30 PASS / 0 FAIL / 84 SKIP**（114 脚本 = 30 host + 84 device）。
- [~] **v4.54 JNIEnv 槽位索引的 ABI 机检（2026-09-19，host 验收 PASS）**：上一轮评审把"补 JNIEnv `Get/Set<Type>Field` 槽位"列为覆盖面的下一台阶，但**索引写错会打到相邻的 JNI 函数**——那会影响目标里每一次 JNI 调用。所以在动它之前，先把"索引表到底对不对"变成机检。
      · 新增 `tools/verify_v90_jni_table_abi.sh`（host，只需 NDK 头）：解析 NDK `jni.h` 里 `struct JNINativeInterface` 的**字段顺序**（4 个 reserved + 229 个函数指针 = 233 槽），与 agent 的 `env_hook_spec_index()` 表（把 `ADH_CALL_VALUE_FAMILIES`/`ADH_CALL_VOID_FAMILIES` 两套宏行展开成 `Name/NameV/NameA`）逐条比对，并检查"要安装的槽位是否都有索引"（缺索引时安装会 refuse）。
      · 结果：**13 个固定槽 + 21 个调用族 × 3 = 76 条全部与 jni.h 一致**（`checked 76 indices against the ABI`，PASS）——这同时证明现有 76 槽是照 AB I 写的、没有历史错位；与 agent 侧原有的运行期保护（`env_hook_slot()` 取真实结构体字段 + `slot_offset == spec * sizeof(void*)` 不符即拒绝 patch）互为呼应。
      · 意义：**下一步加 `Get/Set<Type>Field` 36 个槽位时，索引由本脚本机器校验**——编译器偏移 + 静态 ABI 对照 + 运行期 refuse，三层保证"不会打到邻居"。全量 host 门禁 **30 PASS / 0 FAIL / 83 SKIP**（113 脚本 = 30 host + 83 device）。
      · **下一步（待实现）**：按字段族加 36 个槽位（Object/Boolean/Byte/Char/Short/Int/Long/Float/Double × Get/Set × instance/static），jni.h 给出的期望索引：instance Get 95–103 / Set 104–112、static Get 145–153 / Set 154–162；沙盒需新增走 `JNIEnv->SetIntField/GetObjectField` 的 native 夹具，再加 `verify_v5x_jni_env_fields.sh`（device）验证事件与转发。
- [~] **v4.53b 活体对象：父类链查找 + 继承字段枚举（2026-09-19，host 验收 PASS；真机待做）**：评审指出 `object_inspect`/`object_invoke`/`object_set` 都只对**本类**做 `getDeclaredField`——一个 `class Child : Base` 的字段会被报成 "target field not found"，分析者很容易误读成"这个对象没有该字段"。这是**能不能用**的问题，不是"多一种类型"。
      · agent：新增 `adh_find_field_walk()`（沿 `getSuperclass()` 上溯，`Object.getSuperclass()==NULL` 结束）替换三个命令里的持有者/目标字段查找，失败文案改成 `... (searched the superclass chain)`；`object_inspect` 的**枚举**也从"只列本类"改成走整条父类链，每条记录带上**声明类**（`"class":"com.adh.sandbox.HeapProbe$InheritBase"`），否则对一个继承字段写入后根本没有独立的读回路径。
      · 沙盒：新增 `HeapProbe.InheritBase/InheritChild` + `sInherited` 夹具（字段 `inherited` 声明在父类），`tools/verify_v89_object_set.sh` 增加一段：写 `inherited 5 → 9` → 复读必须看到 `9` **且声明类是父类**（老 APK 缺夹具时该段跳过，不影响其它断言）。
      · 验收：agent 零告警重建；`node --test` 144；host 全量门禁 **29 PASS / 0 FAIL / 83 SKIP**。
- [~] **v4.53 活体对象字段写入 `object_set`（2026-09-19，host 验收 PASS；真机待做）**：目标要求"参考 frida"——`object_inspect`（读字段）与 `object_invoke`（调方法）早就有，但**不能改**：把一个活体实例上的 `isRooted`/`debugChecked`/密钥字段改掉再继续跑，是最常见的分析动作之一，之前只能靠 Java hook 去骗返回值。
      · agent 新增命令 `object_set {className, field, targetField, value}`：`field` 仍是"静态持有者"约定（和 inspect/invoke 一致，沙盒里是 `HeapProbe.sConfig`），`targetField` 是该对象上的字段；值**按字段声明类型**强转（boolean/int/long/float/double/String，其它类型 fail-loud），返回 **before/after**，并**回读一次**证明写入真的落到目标里；Kotlin `val`（编译成 final 字段）会被 ART 拒绝 → 明确报 `set failed - the field is probably final`，不装作成功。
      · MCP `object_set`（76 → **77** 工具）+ `POST /api/object/set`；沙盒夹具 `HeapProbe.Config` 增加三个**可变**字段（`flag`/`counter`/`label`）作为真机验收的 ground truth（v06 只按名字断言值，不受影响）。
      · 验收：`tools/verify_v89_object_set.sh`（device，**脚本已就绪**）——布尔/整型/字符串三种写入的 before/after、**写后用 object_inspect 复读**、final 字段必须 ok:false、还原后进程存活；无设备时干净 SKIP。op 覆盖门禁（v87）自动把新 op 纳入"必须能从 MCP 到达"。host 门禁 **29 PASS / 0 FAIL / 83 SKIP**（112 脚本 = 29 host + 83 device）；agent 零告警重建。
      · **独立评审（read-only，P0 无）**：P1 一条当场修——**数值类型是静默强转**：`strtol/strtoll/strtod` 全都传 `NULL` endptr，`value="abc"` 会**静默写 0** 且回 `ok:true`（before/after 还"证明"写入成功），与描述里的 "no silent cast" 直接矛盾；`"99999999999"` 写 int 字段会被静默截断回绕、`"1e999"` 变 `inf`。现在四条数值分支都走**全量解析 + 范围检查**（`adh_parse_i64_strict`/`adh_parse_double_strict`：endptr 必须走到结尾、查 `errno`、int 查 `INT_MIN..INT_MAX`、浮点查 `isfinite`），失败明确报 `int field expects an integer in int range, got abc`。P2 也修：final 字段不再靠"猜"——先 `Modifier.isFinal(field.getModifiers())`，命中就直接报 `field 'x' is final (Kotlin val / read-only)`，与"值不合法"分开措辞；**参数超长不再静默截断**（`json_get_str` 填满缓冲就 fail-loud，避免把被截断的值写进目标）；`adh_object_value_to_str` 复用已解析的 String class，不再每次 FindClass；v89 的 final 断言收紧成必须命中 `final|read-only`，并新增两条负例（`counter='abc'`、`counter='99999999999'` 都必须被拒）与还原返回校验。
      · **边界（不隐瞒）**：写的是**反射可见的字段**；直接字节码 `iget/iput` 与 JNIEnv `Get/Set<Type>Field` 仍不在观察面内（前者要 ART instrumentation，后者是下一批 JNIEnv 槽位的候选）。继承字段当前只查 `getDeclaredField`（本类），跨类继承要按父类链走。
- [~] **设备队列补齐：v80/v81/v83/v85 的设备半脚本（2026-09-19，host 语法/SKIP 验证 PASS）**：这四项之前只有 host 验证，`FEATURE_STATUS §2` 里写着"待真机"却**没有脚本**——手机回来也无从下手。现在四个都写好了，**13 项待真机全部可执行**。
      · `tools/verify_v80_device_trace_digest.sh`：对 `libadhdetect.so:adh_add_target`（(2+3)*2=10）实跑 QBDI → `/api/trace/digest`，断言 `retval=10`、指令数 ≥3、助记符 ≥2、hot 非空（QBDI 未打包则 SKIP）。
      · `tools/verify_v81_device_syscall_digest.sh`：libc uname 站点 watch → 触发 `adh_libc_uname_probe` → digest，断言 samples ≥1、运行期 x8 =160、**mismatches 为空**、分组里出现发起者（libc 之外的 fixture）、ring 非 lossy，卸载后进程存活。前面还带**正对照**（`adh_add_target(2,3)` 必须可调用），避免把"老 APK 缺 fixture"误判成 resolver 回归。
      · `tools/verify_v83_device_java_trace.sh`：`java_trace start`（HookProbe.ping + stack）→ `java_call stackOuter` 走 stackOuter→stackMiddle→ping → digest（每方法次数、时间线、调用方直方图要出现 stackMiddle/stackOuter、`complete` 不为 false）→ stop 后进程存活。
      · `tools/verify_v85_device_syscall_trace.sh`：一站式链路 start → 触发 → digest（expected 表若没传到位就会以 mismatch 暴露）→ stop。
      · 四个脚本无设备时干净 `RESULT:SKIP`（已实测），注册进 `verify_all.sh`：现在是 **111 脚本 = 29 host + 82 device**；host 门禁仍 **29 PASS / 0 FAIL / 82 SKIP**。
- [~] **v4.52 hook 槽位预算可见 + 批处理按预算截断（2026-09-19，host 验收 PASS；真机待做）**：以前"最多 16 个并发 hook"是**隐藏在失败里**的——第 17 个只是装不上，批量工具还会对着只剩 4 个空闲的 agent 发 16 次安装，然后报 12 条 `install failed`。
      · agent：`native_hook status` 新增顶层 **`slots`**（`max`/`used`/**`active`**/`free`/`byMode{got,inline,sites,vtable}`），其中 **`used` 是"已消耗的槽位"而不是"当前生效的钩子"**——软卸载的 inline 钩子按竞态安全设计保留 stub，槽位直到硬卸载才释放，所以 `free = max - used` 才是真实可用的数字（第一版写成 `max - active`，自查时抓到并修正），`java_hook status` 新增 **`maxHooks`**（active 计数本来就有）——AI 装钩前能先看预算，而不是撞墙。
      · host：`native_hook_all` 先发一次 `native_hook status`，用新纯函数 **`effectiveBatchLimit(requested, freeSlots)`** 决定本批上限：`free=4` 且请求 16 → 装 4 并给出 `limitReason`；**`free=0` 直接 fail-loud**（"unhook something first"）而不是逐符号失败；老 payload 不上报预算时回退到请求值并说明。响应新增 `slots` 与 `limitReason`，`matched`/`installedCount` 的语义不变。
      · 验收：`daemon/test/native_hook_all.test.ts` 7 → **8** 条（预算=4 截断、0 空闲阻断、老 payload 回退、请求夹紧）；`tools/verify_v84_native_hook_all.sh`（host）新增槽位断言（agent 源码必须上报 `slots`、daemon 必须走 status 取预算、响应必须带 `limitReason`），**PASS**。全量 host 门禁 **29 PASS / 0 FAIL / 78 SKIP**（107 脚本）；daemon 单测 **143**。
      · **独立评审（read-only，P0 无）**：P1 一条**当场修**——**安装失败会把槽位永久烧掉**：预留时 `used=1`、失败路径只 `reset_context`（把 `active` 清 0 但不归还 `used`），于是 `find_free_slot_locked` 永远不再选它；16 次失败（打错符号名、地址不可执行……）就能把整个 agent 的钩子预算吃光。现在 `fail` 在 `active==2`（只预留、从未发布，记录器不可能在飞）时**把预留归还**（`used=0`、slot-id/hits 清零）。P2 也修：负数预算不再被夹成 0 并谎称"agent 说 0 空闲"（改成报 `corrupt slot budget (free=-N)` 并拒绝），响应新增 `effectiveLimit`/`requestedLimit` 便于区分"是用户 limit 还是槽位预算截断"，v84 增加两条**钉死语义**的断言（`slots.used` 必须来自 `ctx.used`、失败必须归还预留）。
      · **待真机**：① 连续制造 16 次安装失败后仍能装上新钩子（不再烧槽位）；② 沙盒里挂满 16 个后再调 `native_hook_all`，必须回 `limitReason` + 0 安装（而不是 16 条失败）；卸载几个后同一调用应能装进去。
- [~] **v4.51 去特征 stage 2a：vendored LSPlant 字符串（2026-09-19，host 验收 PASS）**：stage 1 清掉的是**我们自己**的串；`LSPlant`/`lsplant` 这几个来自 vendored 源码，其中最要命的不是日志——**LSPlant 运行时生成的 dex 以 `"lsplant"` 作为 source name**（`lsplant.cc:474`），目标只要枚举已加载 dex 就能读到工具名。
      · 新增 `tools/patch_vendor_signatures.sh`（幂等，带 `--check`）：把三处改成中性——`ScopedSuspendAll("LSPlant Hook")` → `"art hook"`、`logging.hpp` 的 `#define LOG_TAG "LSPlant"` → `"rt.java"`、生成的 dex source name `"lsplant"` → `"generated"`；`tools/fetch_lsplant.sh` 在已有的源码补丁之后调用它（vendored 目录是 gitignored，改 checkout 会被下次 fetch 覆盖，所以补丁必须挂在 fetch 路径上）。
      · 扫描器把 `LSPlant`/`lsplant` 从"预算"提到 **MUST_BE_ABSENT**；`tools/verify_v88_agent_signatures.sh` 新增 **vendor check**（跑 `--check`），这样"重新 fetch 后忘了打补丁"会在门禁里现形，而不是等下一次构建才发现。重建后实测：`LSPlant` 0、`lsplant` 0、`Dobby` 2（预编译 AAR，仍预算内）。
      · **stage 2 仍欠**：Dobby（AAR 里只有预编译静态库，要二进制补丁或从源码重建）、两个导出名、Java bridge 类名与其 10 处诊断串、`adh.reporter.class`（需双读过渡）、`libQBDI.so`、`libzygisk.so`。
- [~] **v4.50 agent 去特征 stage 1 + 签名门禁（2026-09-19，host 验收 PASS；真机待做）**：以前"去特征"只有 stealth pool / memfd / RELRO 还原这类**行为层**措施，**字符串层**没人管——agent 跑在目标进程里，它的 `.rodata` 就是目标能自己读的内存，一次 `strings` 式扫描就能把工具名读出来。本轮把它变成**可测的数字**。
      · 新增 `tools/scan_agent_signatures.sh`：扫 release `.so` 的字符串，分两类——**MUST_BE_ABSENT**（我们自己的身份串，无外部契约，必须为 0）与 **BUDGETED**（还动不了的，每项带一个只许降不许升的上限 + stage 2 修法）。`tools/verify_v88_agent_signatures.sh` 跑它，并带**负对照**：往 .so 副本里植入一个真 token，扫描器**必须**报 FAIL（门禁不能自证）。
      · **stage 1 已清零**：7 个 `ADH_*` 日志 tag → 中性 `rt.*`（仓库内没有任何脚本读 logcat，改动零契约）；agent 自己的日志/错误文案里的 Host ADH Daemon / ADH wrapper / lsplant:: / Dobby* / fetch_dobby.sh / fetch_lsplant.sh 全部改中性；`qbdi_trace` 里的**沙盒 fixture 默认值**（libadhdetect.so / adh_trace_target）删掉——这同时修掉一处**红线违规**（agent 不得硬编码目标模块名），改为 fail-loud 要求调用方给出 symLib+symbol；`got.c` 的自名 fallback 改为 **XOR 混淆**（volatile 表 + volatile key，防止 -O2 把明文折回 .rodata）；CMake 关掉 **DT_SONAME**（用 NO_SONAME 属性），因为我们从来不用 soname 加载（Zygisk/Xposed 走路径，sandbox 走文件名）。
      · 顺带修：`javahook_probe`/`java_hook status` 的 `backend` 值 `"lsplant"` → `"art"`（主机侧没有消费者断言该值），v42/v43 的 SKIP 正则同时接受新旧文案；`verify_v10_qbdi.sh` 改为显式传 fixture（以前靠 agent 的默认值）。
      · **仍是预算内（stage 2，每项都写了修法）**：`adh_agent_start`/`adh_agent_set_package`（两个 loader 的导出契约，改名要同时改 Zygisk/Xposed + 脚本）、`com.adh.agent.AdhJavaHookBridge` + `/adh_bridge.dex`（Java bridge 类名与 code-cache 文件名，需要重生成内嵌 dex）、`adh.reporter.class`（沙盒设置的属性名）、Dobby x2 / DobbyHook x1 / LSPlant x2（**预编译静态库**里的名字，要在 fetch 时打补丁重建）、`libQBDI.so` x2（真实 dlopen 名）、`libzygisk.so` x1。
      · 验收：agent 零告警重建（836,432 B，SONAME 已无）；`tools/verify_v88_agent_signatures.sh`（扫描 PASS + 负对照捕获植入 token + 源码里 fixture 名/旧 tag 不得回归）**PASS**；全量 host 门禁 **29 PASS / 0 FAIL / 75 SKIP**（104 脚本 = 29 host + 75 device）。
      · **独立评审（read-only，P0 无）**：P1 两条当场收口——① **删掉 DT_SONAME 打破了设备脚本 `verify_v02_so.sh` 的旧断言**（它断言"必须有 soname"），已翻成"**必须没有** soname"并写明这是 v4.50 起的预期；② **fixture 默认值只是从 agent 搬到了 daemon**：`mcp.ts` 的 `qbdi_trace` 默认 `symLib='libadhdetect.so'`、`/api/trace/qbdi` 路由默认 `libadhdetect.so`/`adh_trace_target`，等于"真实目标上必然 `symbol not found`"而不是"你必须给 symLib"。现在 `qbdi_trace`/`trace_digest` 的 MCP schema **要求 symLib 必填**、REST 路由缺参回 **400**、`trace_digest` 在 daemon 侧就 fail-loud，fixture 名在整条调用链上都不再出现。P2 也修：`AdhJavaHookBridge` 的 **10 处**诊断串以前不在预算里（stage 2 会变成假目标），现在单列预算；`adh.reporter.class` 的注记改成"stage 2 需要**双读过渡**（否则已接入的目标会静默失去富 reporter）"；扫描器加了"子串匹配是故意的"说明；`verify_v08_analyze.sh` 的过时注释同步。
      · **待真机**：① 沙盒里 `qbdi_trace` 缺 symLib/symbol 必须 fail-loud（v51 走显式参数应继续 PASS，v10_qbdi 已改）；② 目标进程**内存内**扫描确认 deny-list 不存在——**脚本已写好**：`tools/verify_v88_device_memory_signature.sh`（用 agent 自己的 search op 扫已加载镜像，带**正对照** `native_hook`——找不到正对照就判 FAIL，避免"扫了 0 个字节也算过"）。
      · **本轮同时把设备半都补齐了（手机回来一次跑完）**：`tools/verify_v86_device_throttle.sh`（真机装 `throttleMs:200` + 强制返回值的钩子 → 调 20 次：断言 `hits = emitted + throttled`、`throttled` 单调、**被限流的命中照样改写返回值** 20/20）、`tools/verify_v87_device_probe_fs.sh`（`agent_ping`/`engine_selftest` 的 `fired && protRestored && slotPerms[1]=='-'`/1MB `protocol_selftest`/`fs_list`+`fs_read` 读 `/proc/self/cmdline` 与坏路径 fail-loud）。三个脚本在无设备时干净 SKIP（`RESULT:SKIP`），已注册进 `verify_all.sh`（现在是 107 脚本 = 29 host + 78 device）。
- [~] **v4.49 MCP 可操作性（op 覆盖审计 + 探针 + 设备文件系统）（2026-09-19，host 验收 PASS；真机验收待做）**：目标里"让 MCP 完全可操作"此前只是一句**口号**——没有任何东西在检查它。本轮先做**审计**（40 个 agent 命令分支 × MCP 导入图可达性），再修审计出来的缺口。
      · **审计发现**：① `ping` 从 v0.2 起就是**死代码**（agent 侧有实现，Host 侧从来没有任何地方发过它），于是"agent 还活着吗"只能靠发一条真命令等超时；② 三个能力**只有 REST/验收脚本有**：设备文件浏览（`list_dir`/`read_file`）、hook 引擎自检（`gothook_selftest`）、通道自检（`frame_echo`）；③ 反向检查干净——daemon 没有发过 agent 不认识的 op。
      · 新增 5 个 MCP 工具（71 → **76**）：`agent_ping`（5s 快速存活 + 往返延迟，用来区分"目标没了"和"这条命令慢"）、`engine_selftest`（`ok` 是**判定**不是"命令跑通了"：`fired` 且 `protRestored` 才算过，留下可写 RELRO 页的构建直接报 detectable）、`protocol_selftest`（超大帧 + 尾部标记越过老的 8192 单行上限）、`fs_list` / `fs_read`（设备文件系统：1MB 上限 + `truncated` 如实，二进制/超大文件用 `textOmitted` 说明原因而不是把垃圾贴出来）。
      · 逻辑只写一份：新增 `daemon/src/agent_probe.ts`（`agentPing` / `hookEngineSelftest` / `protocolSelfTest`；判定函数纯化，时钟与 sender 可注入）与 `daemon/src/fs_browse.ts`（`listDeviceDir` / `readDeviceFile` / `summarizeFile`），**MCP 与 REST 共用**；`/api/hook/selftest` 的 HTTP 状态改为跟随判定；`/api/fs/*` 保留 v25 依赖的 `text` 与 `ok:false` 契约；新增 `/api/agent/ping`。
      · 验收：`daemon/test/agent_probe.test.ts` + `daemon/test/fs_browse.test.ts`（16 条：延迟测量与时钟注入、三种引擎判定、尾部丢失/截断判定、空路径不发送、二进制与超大文件 omission、坏 base64 拒绝、truncated 不冒充完整）+ `tools/verify_v87_mcp_operability.sh`（host：16 条单测 + **op 覆盖不变式**——每个 agent op 必须能从 MCP 导入图到达，除非在 `INTERNAL_OPS` 里写明理由（3 个仅剩验收脚本使用：`crypto_probe`/`jni_probe`/`inline_crypto_test`）+ 反向幽灵 op 检查 + 五个工具 schema + REST/MCP 共用同一实现的静态断言），**PASS**；全量 host 门禁 **28 PASS / 0 FAIL / 75 SKIP**（103 脚本 = 28 host + 75 device）；daemon 单测 **142**（112 + 30 automation）。
      · HTTP 层实测（守护进程重启到新注册表后）：`/api/mcp/doc` 列出 5 个新工具；`/api/agent/ping` 无 session→400、有 session 无 agent→504；`/api/fs/list` 坏 session→502 且 body 带 `ok:false`（v25 契约）；`/api/debug/frame_echo`、`/api/hook/selftest` 仍走 504。
      · **独立评审（read-only，P0 无）**：P1 两条当场收口——① `INTERNAL_OPS` 里 `crypto_probe` 的理由**引用了不存在的 op**（写成 `crypto_capture`/`file_capture`，那是工具名不是 agent op），且该路由**无人调用**，理由改成事实；`jni_probe` 的脚本名 v04 也改成实际的 v03。② P2 全修：闭包正则从"任意 `.send(`"收紧为 `deps/opts.send`、`resolveImport` 支持带扩展名与 `await import()`；`engine_selftest` 现在把**命令失败**与"引擎坏"分开报（新增 1 条断言）；`frame_echo` 的判定加上 **padLen 回显校验**（截断帧拿不到回显）；`fs_read` 描述与实现统一为"at most 256KB"；`protocol_selftest` 的 kb 夹紧与 REST 路由对齐（0 → 1 KB，而不是悄悄变 64 KB）。
      · **待办（真机）**：`agent_ping` 往返延迟；沙盒上 `engine_selftest` 必须 `fired && protRestored`；`protocol_selftest` 1MB 帧完整；`fs_list`/`fs_read` 走 `/data/data/com.adh.sandbox` 与 `/proc/self/cmdline`，且 v25 的老断言继续通过。
- [~] **v4.48 native 事件限流 `throttleMs`（2026-09-19，host 验收 PASS；真机验收待做）**：热站点（`read`/`write`/`futex`）一秒能打出上万条 `NATIVE_HOOK`，事件环一满，摘要读起来就像"目标没动静"——限流要解决的是这个**诚实性问题**，不是省流量。
      · agent（`agent/src/hook/native_hooks.{h,cpp}` + `agent_main.c`）：每个钩子一个窗口，窗口内**最多发一条事件**；被压掉的命中**照样计数**（下一条事件带 `throttled`＝它代表多少次命中，`status` 带累计 `throttled`），恒等式 `hits = 已发事件 + throttled` 始终成立，日志变稀不会变成"看起来安静"。窗口 0 = 每条都发（默认，行为不变），>0 夹紧到 0..60000 ms 且 status 回显**生效值**；槽位复用与软卸载后重新激活都会清零窗口与计数，不继承上一个钩子的设置。
      · **限流只压事件、不改行为**：参数改写（`argIndex`）、返回值替换（`returnValue`）、`skipOriginal` 在窗口内的命中上照常生效（`record_site` 照常回答"不要调原函数"）——限流永远不会把改行为的钩子变成"偶尔放行"。实现无锁（命中线程上一条 relaxed 时间戳读；窗口判断用单调钟；增量用 `exchange` 取，两个 emitter 不会重复报同一批被压命中），失败模式是"多发一条"，不是阻塞目标线程。
      · host 侧：新增纯函数模块 `daemon/src/native_hook_args.ts`（`normalizeThrottleMs`：缺省/≤0 = 0，>60000 夹紧，非数字**拒绝**而不是当 0；`nativeHookInstallPayload` 统一装配），`native_hook_all` 与 `syscall_watch` 都改走它——"throttleMs 真的上线了"从此是**可单测**的事实，两者响应都回显生效窗口。`native_hook`/`native_hook_all`/`syscall_watch`/`syscall_trace`（MCP + REST `/api/native/hook`、`/api/native/hook_all`、`/api/native/syscall_watch`、`/api/syscall/trace`）全部暴露 `throttleMs`；REST 对非法值回 **400**（不是 502/504，参数错不是设备错）；`syscall_digest` 的 ring 告警文案改成点名 `throttleMs`。
      · 验收：`daemon/test/native_hook_throttle.test.ts`（**12 条**：默认关闭/夹紧/截断/拒绝垃圾值/装配完整性/不悄悄限流，外加**安装回路**——注入式 sender 断言 `native_hook_all` 与 `syscall_watch` 真实发出去的 payload 带 `throttleMs`/`backtrace`，以及"中途失败必须把已装的 hook 交回调用方"）+ `tools/verify_v86_native_throttle.sh`（host：12 条单测 + 断言 agent 侧"先改写后限流、被压命中计数并照常回答 skipOriginal、status 带窗口与累计、增量必须用 `exchange` 取而不是 load+store"、断言 host 工具确实带上该字段、MCP 四工具 schema 有 `throttleMs`），**PASS**；agent 零告警重建通过（836,192 B）。全量 host 门禁 **27 PASS / 0 FAIL / 75 SKIP**（102 个脚本 = 27 host + 75 device）。
      · **独立评审（read-only，P0 无）**：P1 两条当场收口——① 单测从"只测纯函数"扩到**安装回路**（原缺口：删掉 `throttleMs: opts.throttleMs` 八条测试照样全绿）；② 文档不再把 host 装配写成运行时已验证（特性表改成"限流装配，仅 host"，运行时恒等式留在 §2 待真机）。P2 也一并修：60000 上限收敛为 `native_hooks.h` 一处定义（`agent_main.c` 不再抄字面量）、`exchange` 语义写成显式断言、`clock_gettime` 的 vDSO 前提写进注释。
      · **待办（真机）**：对 libc 热站点（`read`/`write`）用 `throttleMs:200` 实跑，断言事件间隔 ≥ 窗口、`hits = 已发事件 + throttled`、`throttled` 单调递增，且带 `returnValue`/`skipOriginal` 的钩子在限流下**每一次**命中都生效。
- [~] **v4.47 一站式系统调用跟踪 `syscall_trace`（2026-09-18，host 验收 PASS；真机验收待做）**：watch / digest / 卸载三个工具分开时，最容易错的两件事——**静态归因没有从 watch 传到 digest**、**drain 没走共享路径**——现在由工具自己保证。
      · `daemon/src/syscall_trace.ts`：`start` = 调 `syscall_watch` 并用它的响应**自动构造 `{hookId: nr}` 期望表**（归因错位以后会以 `mismatches` 形式暴露，而不是被手工抄错）；解不出号的站点进 `unattributed` 并说明『只有运行期 x8 可看』。`digest` = 走共享 `drainSession` + `syscall_digest`（调用方、次数、`paths` 直方图、mismatch）。`stop` = **只卸传入 id**（显式拒绝空列表与 0，不做隐式全卸）。装不上任何钩（模块没有匹配的 svc 站点）时 fail-loud。
      · 新增 MCP `syscall_trace`（action: start|digest|stop）+ `POST /api/syscall/trace`，工具数 70 → 71；`tools/verify_v85_syscall_trace.sh`（host）= 8 条装配单测 + start→digest→stop 合成链路（断言 expected 传到位、stop 只卸自己装的 id）+ MCP schema，**PASS**。
      · **待办**：真机链路（libc uname 站点 → watch(start) → 触发 `adh_libc_uname_probe` → digest 的调用方必须是该 fixture、observed 全 160、无 mismatch → stop 后进程存活），与其它真机项一起排队。
- [~] **v4.46 native 侧批量挂钩 `native_hook_all`（2026-09-18，host 验收 PASS；真机验收待做）**：Java 侧有 `hookAll`（v4.44）之后，native 侧补上同款工作流——**把 libcrypto 里所有 EVP_* 一口气挂上**，而不是手工 dump 符号、算地址、逐个装。
      · `daemon/src/native_hook_all.ts`（host 编排，agent 仍只执行 `native_hook`）：从模块 dump 解析导出表（复用 `parseDynSymbols`，内存重建镜像也能用），按 `prefix/contains/exact` 过滤 **STT_FUNC**（数据符号永不入选、未命名符号忽略），可选 `exclude` 去掉噪声；按**地址升序**取前 `limit` 个（≤16，与 native 槽位上限一致）逐个装 inline hook，返回 `hookIds` + `matched` vs `installedCount`（截断可见）+ 每符号失败明细。`action:unhook` 只卸传入 id。纯函数 `selectExportSymbols` 7 条单测（前缀/包含/精确、数据符号与空名排除、matched≠selected、地址序确定性、limit 夹紧、exclude、相对地址与 size）。
      · 新增 MCP `native_hook_all`（action: hook|unhook，`confirm:true` 必填——地址级 hook 属于强操作）+ `POST /api/native/hook_all`，工具数 69 → 70；`tools/verify_v84_native_hook_all.sh`（host）= 7 条单测 + 合成导出表断言 + MCP schema/confirm 门禁，**PASS**。
      · **待办**：真机实跑（对 `libadhdetect.so` 用 `prefix:adh_` 装一批、逐个触发、unhook 全部、进程存活），与 v77/v78/v79/v80-device/v81-device/v82/v83-device 一起排队。
- [~] **v4.45 Java 类级 trace 摘要 `java_trace`（2026-09-18，host 验收 PASS；真机验收待做）**：Java 侧的"类级时间线"——算法还原时最常用的工作流：**挂一个类 → 触发 → 看什么跑了、按什么顺序、参数返回值是什么**。建立在刚做完的 `hookAll`（v4.44）之上。
      · `daemon/src/java_trace.ts`：三个阶段显式分开（中间通常要由操作者或其它工具触发目标）：`start` = `hook_all` 并**保留**钩子，返回 `hookIds/matched/cursor`；`digest` = 先显式发一次 `capture_drain`（不等后台 1.5s 轮询）再把这些 hookId 的 `JAVA_HOOK` 事件聚合成 **每方法次数/首末时间/线程/最后参数与返回值/错误计数 + 时间线（保留最新窗口）+ 调用方直方图**（`stack:true` 时取 Java 调用链最内层 App 帧）；`stop` = **只卸传入的那几个 id**（绝不用 `unhook 0`，那会把无关钩子一起卸掉）。纯函数 `digestJavaTrace`/`callerOfStack` 有 7 条单测。
      · 新增 MCP `java_trace`（action: start|digest|stop）+ `POST /api/java/trace`，工具数 68 → 69；`tools/verify_v83_java_trace.sh`（host）= 7 条单测 + 合成 trace 断言 + MCP schema，**PASS**。
      · **待办**：真机三阶段实跑（start 挂 `HookProbe` → `java_call stackOuter` → digest 给出两个 ping 重载各自次数与调用方 → stop 后进程存活），与 v77/v78/v79/v80-device/v81-device/v82 一起排队。
      · **评审修复（Heisenberg，commit 同上）**：**P0 —— digest 自己裸发 `capture_drain`，把要读的事件从 agent ring 里弹出后丢弃**（agent 的 drain 是弹出语义，只有把记录写进本地 store 的后台循环才能发这条命令）→ 现在把后台循环的 drain 抽成**导出的、按 session 串行化的 `drainSession()`**（并发调用合并到同一个 promise、`while backlog>0` 多批、`capStats` 一并更新），`java_trace` 与 `syscall_digest` 都改走它，drain 失败会写进 `drain.ok/notes` 而不是伪装成"操作者没触发"；顺带修：`stop` 拒绝 `hookId<=0`（0 = 卸全部，之前会越权）、时间线改用 **agent 的 `tsNs`** 排序（同一 drain 批的 `ts` 相同，之前按 hookId 兜底会打乱真实顺序）、`sinceCaptureId` 让 start 的 cursor 真正生效、未开 stack 时给明确提示、`callerOfStack` 过滤 bridge 的失败标记并归一化 hidden class。单测 7 → **15**（含"必须走 drainSession、不得裸发 capture_drain"这条 P0 回归守卫）；`service.ts` 是核心采集路径，**采集家族脚本（v04/v11/v16/v20/v22/v26）已列入待真机复跑**。
- [~] **v4.44 Java 批量挂钩 `hookAll`（2026-09-18，实现 + 构建完成；真机验收待做）**：目标第 1 条里"普通方法重载方法"的最后一截——以前要挂一个类的全部重载，得先 `java_enum` 再逐个装。
      · `agent/src/hook/java_lsplant.cpp`：`collect_target_methods()` 遍历声明 + 继承链收集匹配方法（`method`/`params` 可选、`"*"` 任意；**去重键 = 方法名 + 参数列表**，否则类级扫描会把 `foo(int)` 与 `bar(int)` 去重掉一个）；`adh_javahook_hook_all()` 对每个方法调用**既有单方法安装路径**（构造器规则、16 槽上限、逐方法回滚全部沿用），返回 `hookIds[]` + `matched`（匹配总数，截断可见）。
      · 命令层：`cmd_java_hook` 新增 `hook_all` 分支与 `limit` 参数，响应带 `hookIds`/`matched`；MCP `java_hook action:hookAll`（映射到 `hook_all`）+ HTTP 同名参数；agent 构建 **0 告警**。
      · 已写好的真机验收 `tools/verify_v82_java_hook_all.sh`：① `hookAll(method=ping)` 必须返回 2 个 id、`matched=2`，`ping(String)` 与 `ping(String,int)` **各自**产生 `JAVA_HOOK` 事件；② 类级 `hookAll(limit=3)` 必须 `installed=3 < matched` 且 status.count 一致；③ `unhook 0` 后进程存活。
      · **待办**：真机执行 v82（与 v77/v78/v79/v80-device/v81-device 一起排队——手机当前不在线）。
- [~] **v4.43 系统调用归因摘要 `syscall_digest`（2026-09-18，host 验收 PASS；真机验收待做）**：评审（Heisenberg）把"监听发生了"与"知道是谁发的"之间的距离点得很准——这正是目标第 4 条要的信号。
      · `daemon/src/syscall_digest.ts`：纯函数 `digestSyscallSamples()` 按 **(nr, 调用方帧)** 分组（次数/首末时间/线程，线程列表有界去重），调用方取 **libc 家族之外的第一帧**（`libc/libc++/libm/libdl/libbinder_ndk/libbase` 跳过；全是 libc 时如实回退到第一帧），号码未知也能分组（`nr:null`，不丢样本），支持名字表覆盖；`syscallDigest()` 从 capture store 读 `NATIVE_HOOK` 事件（`x8` + `bt`）、符号化调用帧、并把**运行期 x8 与调用方给的 `expected {hookId: nr}` 比对**，不一致进 `mismatches`——把"归因写错但没人验证"变成可见事实。`syscall_watch` 已改为带 `backtrace:true` 装钩，所以事件天生带调用链。
      · **参数解码（同轮补齐）**：`daemon/src/syscall_args.ts` 把寄存器快照翻译成人类可读参数——`openat/faccessat/newfstatat` 的**路径**（并按 `O_RDONLY/O_CREAT/O_CLOEXEC…` 位翻译 flags，低位访问模式单独处理）、`memfd_create` 的名字、`uname` 的 utsname 五个字段、`connect` 的 IPv4/IPv6 地址端口、`ioctl` 的 request、`socket` 的 domain/type、`read/write/getrandom/kill/tgkill/prctl` 的标量。指针参数由 Host 经 agent 读目标内存（**有界**：每样本最多 2 次读、`decodeLimit` 默认 40 个样本，可 `decode:false` 关掉），读不到就如实写 `(unreadable)`（延迟读可能已被释放/换页，注释里说明）。摘要因此多了 **`paths` 直方图**（"这段代码在探测哪些文件"——指纹排查最直接的信号）与每组的 `example`（`path=/proc/cpuinfo flags=O_RDONLY|O_CLOEXEC`）。9 条单测（plan/路径/flags 访问模式/uname/双栈 sockaddr/ioctl/不可读指针/二进制垃圾不当字符串/未知号回退）。
      · 新增 MCP `syscall_digest`（+ `POST /api/syscall/digest`），工具数 67 → 68。
      · 验收：`tools/verify_v81_syscall_digest.sh`（host）：**53 条 daemon 单测**（syscall_digest 13 + syscall_args 15 + syscall_watch 14 + trace_digest 7 + backtrace 4，**按文件最小数**断言，删掉某个文件的用例不会仍判绿）+ 合成命中（libc 帧被跳过、uname 组 2 次、read 钩被标成错配）+ 参数解码（`/proc/cpuinfo` + `O_RDONLY|O_CLOEXEC` → 直方图计数 2）+ MCP schema，**PASS**。
      · **待办**：真机链路（watch libc uname → 触发 `adh_libc_uname_probe` → digest 调用方必须是该 fixture、observed 全 160、无 mismatch）。手机当前不在线（`adb devices` 为空），与 v77/v78/v79/v80-device 一起排队。

- [x] **v4.42 两轮独立评审的修复（backtrace / Java stack / syscall 归因）（2026-09-18，host 验收 PASS；真机复验待做）**：评审（subagent）对 v4.38–v4.40 提了 3 个 P1 + 一批 P2，逐条处理如下。
      · **native backtrace（P1）**：① `want_backtrace` 从不在槽位复用时清空/在 reactivate 时重设 → 换目标复用槽位会**继承**上一条 hook 的采集开关（白付栈遍历开销 + 事件里多出 `bt`），现已在 `reset_context` 与 reactivate 两处修正；② agent 的 8 帧上限对 Host **不可见**（`btCount == 8 == bt.length`，看起来像完整链）→ 事件新增 `btTruncated`，Host 映射为 `stopReason: frame-cap-reached` + `truncated:true`；③ `bt[]` 里全是**返回地址**，但只有 live-walk 分支做了 `-4` 修正 → 现在两条路径一致（避免函数边界上一帧之差落到邻居函数）；④ `pthread_getattr_np` 失败会被**永久记住**导致该线程再也不能回溯 → 改为只在成功时落缓存；⑤ 符号 `exact` 的语义（"尺寸覆盖"而非"证明就是它"）写进注释与 note。
      · **syscall 归因（P1）**：① 反向扫描只要**看到 MOVZ** 就当成"x8 最后写入"，中间若有未建模的写（`mov x8,x1`/`ldr x8,[sp]`/`movk`）会给出**自信的错号** → 新增保守谓词 `mayWriteX8()`：比候选更靠近 svc 的指令一旦可能写 x8，就返回 `ambiguous-write`（宁可不归因，不给错号）；同时补上 `movz w8,#imm,lsl #16` 形态、把未建模的 `movk` 标成 ambiguous。**真机覆盖未退**：重跑本机 libc 镜像仍是 **223/224** 归因（`movz-imm` 223 + `ambiguous-write` 1），`uname/openat/getrandom` 全在。② 单元测试里"验证控制流截断"的用例其实探到了 RET（没覆盖 `b`）→ 重写为对第二个 svc 取证，并为 `b`/`cbz`/`br` 各加一例；评审给的 4 个探针（寄存器写覆盖、load 覆盖、未建模 movk、近者优先）全部落成用例（syscall 用例 7 → 14）。③ 过滤空值（`""`/`[]`）原本会当成"过滤零命中"报错 → 现在等于"不过滤"；MCP schema 允许数字项。
      · **验收脚本加固（P1/P2）**：v77 之前只断言"装了 ≥1 个 uname 钩"，一个**只会认 uname** 的解码器也能过 → 增加 `attributedCount ≥ 90% svcCount` 与未知率上限、加**数字过滤**用例（`178 → gettid`）、加**正对照**（先调 `adh_add_target` 证明符号解析没坏，再允许把"fixture 缺失"判为 SKIP）、卸载失败不再静默；v40 的重试会打印每次"dismissed + attempt"；runner 的 skip 判定从"日志里任何一行 `^SKIP`"收紧为"**最后一行**是 SKIP 或存在 `RESULT:SKIP`"（避免整体 PASS 的脚本因为内部提了一句 skip 被记成 skip）。
      · 另外给 bridge 源码加了 ABI 警示注释（改 `nativeReport` 签名必须同时重生成 dex + 改 RegisterNatives 描述符，否则 dex 校验会**响亮**失败）。
      · **待办（真机）**：`v77`（新增的比率/数字过滤断言）、`v78`（btTruncated/帧号修正）、`v79`（Java 链）、`v80` 的设备半（trace_digest 实跑）都还没在手机上跑过——本轮全部只做了 host 验证（18 → 25 条单测 + MCP shape）。

- [~] **v4.41 trace 摘要（AI 自主分析 trace 日志的入口）（2026-09-18，host 验收 PASS；真机验收待做）**：QBDI 一次给 8192 条原始指令，AI 读不完也没法比较；本轮把"trace 日志 → 可读摘要"这一层补上。
      · `daemon/src/trace_digest.ts`：纯函数 `digestTrace()`（无设备可测）聚合 **循环**（只认"被分支指向"的地址作回边目标——第一版把"执行两次的调用点"也当循环，噪声很大）、**调用目标+次数**（`blr` 如实标为未解析）、**内存访问形态**（`[base+off]` 计数；第一版按逗号切操作数，把 `[x1, #0x10]` 切碎了，内存访问数恒为 0，单测当场抓到）、**立即数常量**（内置 crypto magic 表：TEA 黄金比、MD5/SHA1/SHA256 初值、FNV 等）、**分支形态**、**热点指令**，并附诚实注释（命中上限/未解析间接调用/无循环）。`traceDigest()` 负责"跑 `qbdi_trace` + 摘要 + 通过 `module_symbols.ts` 给调用点与热点符号化"。
      · 新增 MCP `trace_digest`（+ `POST /api/trace/digest`），MCP 工具数 66 → 67；模块/符号解析从 `backtrace.ts` 抽到 `module_symbols.ts` 供两者复用。
      · 验收：`tools/verify_v80_trace_digest.sh`（host）：18 条单元测试（digest 7 + backtrace 4 + syscall 7）+ 合成 trace 断言（循环 1 / 调用 1 / 内存 1 / 常量 1）+ MCP schema，**PASS**。
      · **未完成**：真机验收（对 `libadhdetect.so:adh_add_target` 跑 `trace_digest` 并断言摘要内容）；`backtrace.ts`→`module_symbols.ts` 的抽取属重构，`verify_v77/v78` 需在手机空闲后复跑确认。

- [x] **v4.40 Java hook 命中带调用链（native v4.39 的姊妹能力）（2026-09-18，真机 PASS）**：native 侧能看到"谁调进来的"之后，Java 侧同样补上——算法还原里最常问的就是"这个 `ping/encrypt` 是被哪个方法调起的"。
      · **实现**：`java_hook stack:true`（opt-in，默认关：每次命中一次栈遍历）时，`AdhJavaHookBridge` 在回调里用 `Thread.currentThread().getStackTrace()` 采一条**有界**链（最多 12 帧 / 512 字符，`Class#method:line`，最内层在前），并过滤掉采集与 hook 管线（`java.lang.Thread`、`dalvik.system.VMStack`、`java.lang.reflect.Method`、`AdhJavaHookBridge`、LSPlant 的 `com.android.internal.util.NativeBridge_` 合成类）——**第一版没过滤 VMStack/反射帧**，链里混进 `VMStack#getThreadStackTrace` 与 `Method#invoke`，读起来像噪声，加上过滤后链就是应用自己的帧。bridge dex 用 `tools/build_java_hook_bridge.sh` 重新生成（javac=Android Studio JBR + SDK d8），产物一并提交。
      · **事件与状态**：`nativeReport` 的 JNI 签名从 5 参变 6 参（`stack` 为空时**不写字段**，opt-in 语义在事件里也成立）；`JAVA_HOOK` 事件新增 `stack`；per-hook status 增加 `stackCapture`/`lastStack`，status 顶层能力位 `stackCapture:true`（老 agent 会被验收脚本识别为 SKIP，不假通过）。
      · **真机 `aa165071` PASS**（`tools/verify_v79_java_stack.sh`）：沙盒新增 `HookProbe.stackOuter → stackMiddle → ping` 链；hook `ping(String)`（stack:true）后经 `java_call stackOuter` 触发，事件 `stack` 恰为 `com.adh.sandbox.HookProbe#stackMiddle:33 <- com.adh.sandbox.HookProbe#stackOuter:36`（顺序最内层在前、无管线帧），status.lastStack 一致；**同一方法再以不带 stack 的方式 hook** 时事件里没有 stack 字段、返回值 `REAL_HOOK:ADH_STACK` 不变，两次 unhook 后进程存活。
      · 边界：链是 **Java 层**的（ART 里的 Java 帧），看不到 native 调用方——两边要一起用时，native 帧由 v4.39 的 `native_backtrace` 给；`stack:true` 有开销（每次命中一次栈遍历 + 12 帧字符串），热路径建议只对目标方法临时开。

- [x] **v4.39 native hook 命中带调用链（对标 Frida \`Thread.backtrace()\`）（2026-09-18，真机 PASS）**：以前 hook 命中只能告诉你"参数是什么"，但**是谁调进来的**要到 Frida 里才有。本轮把它补齐，并且是"命中当刻"的链，不是事后猜测。
      · **agent 侧（\`agent/src/hook/native_hooks.cpp\`）**：\`native_hook\` 新增 **opt-in\`backtrace:true\`**。命中时在**受害者线程自己身上**采集：先用 \`pthread_attr_getstack\` 取本线程栈边界（thread-local 只算一次），再在边界内逐帧读 \`[fp]\`/\`[fp+8]\` 走 x29 链，最多 8 帧，事件里给出 \`bt\`（\`bt[0]\` = \`x30\`，立即调用者）与 \`btCount\`；同时事件依旧带 \`x29/x30\` 原始值。
      · **为什么必须在命中当刻采**：第一版是"事件里给 x29/x30，Host 事后再读栈"，真机实测 \`[fp]\`/\`[fp+8]\` 已经是 **0**（调用返回后同一段栈被后续调用复用），只有 \`lr\` 可信——于是改成 agent 在命中时走链，Host 事后只做符号化。第二个 bug 同样来自真机：第一次实现把 \`x30\`（代码地址）当栈帧指针传进 walker，链全空；必须从 \`x29\` 起走，并把 \`x30\` 作为第 0 帧。
      · **Host 侧（\`daemon/src/backtrace.ts\`，MCP \`native_backtrace\` + \`POST /api/native/backtrace\`）**：优先用事件里采好的 \`bt\`；每帧按**包含它的 maps 区域**定位模块（原来的 min/max 匹配把沙盒帧错认成 \`base.apk\`——base.apk 的映射散布在整个地址空间，min..max 跨度 4 GB），并用 **PT_DYNAMIC** 解析 \`.dynsym\`（内存重建镜像没有节头表，一样能用）给出"模块 + 偏移 + 最近符号"，符号尺寸覆盖该地址时标 \`symbolExact:true\`。诚实的停止原因写进 \`stopReason\`：未映射返回地址（列表到此为止）、栈不可读、fp 不在可写映射、链不递增/成环；来自 APK 内映射的库报 \`symbolSource=archive-mapped\`，不硬凑符号名。
      · **真机 \`aa165071\` PASS**（\`tools/verify_v78_hook_backtrace.sh\`）：沙盒固定链 \`adh_bt_outer → adh_bt_mid1 → adh_bt_mid2 → adh_bt_target\`（该库用 \`-fno-omit-frame-pointer\` 构建，和 AOSP 的做法一致）——hook \`adh_bt_target\`、经 \`native_call adh_bt_outer\` 触发（返回 67），8 帧的当刻链里**前三帧全部 \`exact\`**（\`adh_bt_mid2+0xc / adh_bt_mid1+0xc / adh_bt_outer+0xc\`），随后两帧落在 \`libadh_agent.so\`（native_call 蹦床的调用方），第 8 项是垃圾地址、被 \`return-address-not-mapped\` 截断而不是当成帧列出来；显式 \`fp=0x1\` 路径返回 1 帧 + \`frame-pointer-outside-stack\`（不编造）。卸钩后进程存活。
      · 单元测试 \`daemon/test/backtrace.test.ts\`（\`symbolize\` 精确/最近/无符号三态、对真实沙盒 \`.so\` 走 PT_DYNAMIC 解出 \`adh_bt_target\` 并验证尺寸覆盖、非 ELF/截断头不抛异常），随 \`tools/verify_v76_syscall_attribution.sh\` 在门禁里跑。
      · **门禁（2026-09-18，冻结在 `fb5b94b`+`5369fa5`）：94 个脚本 → 92 PASS / 0 FAIL / 2 SKIP**（`/tmp/gate10.out`）。两次 SKIP 仍是 v38/v39：v37 会重启 Host Daemon，紧接着的两个脚本遇到自动化桥未重连，按契约跳过（不是通过）。v76/v77/v78 三个新脚本全部在门禁内 PASS；v36/v40/v41（此前每次重启后都会被 ColorOS 跨应用确认弹窗打挂的三个前台相关脚本）本次全绿——见 v4.39 末尾的"门禁稳定性"两条修正。
      · **门禁稳定性修正（v4.39 附带，`5369fa5`）**：设备重启后 ColorOS 会在前台弹一个 SystemUI 的跨应用确认框：v36（自动化）、v40（设备守护进程）因此失败，随后 v41 也会超时。实测：自动化桥当时的 global back **按不掉**（重启后无障碍服务还没起来），但 **`adb shell input keyevent 4`（BACK）能立刻关掉**。于是 ① `verify_all.sh` 在 `dev_up` 后先**有界等待** `/api/automation/status` 报 bridge connected（最多 60s）；② v36/v40 保留"检测到 SystemUI 就按 BACK 再重试"的循环（最多 3 次，走 adb），并且**只有**前台是 SystemUI 时才重试——真回归照样失败，不会藏在"按掉弹窗"后面；③ 顺带修了 v40 的 `serial is not defined`（上一轮改重试逻辑时漏传参数）。诚实记录：有一次重启后的全量门禁被 **adb server 崩溃**（`cannot connect to daemon at tcp:5037`）污染，6 个失败脚本随后**逐个单独复跑全部通过/SKIP**（v02/v36/v37/v39/v66/v70）。
      · 边界：链依赖**帧指针**——第三方库若 \`-fomit-frame-pointer\`，只能拿到 \`lr\` 这一帧（工具如实说明 \`trusted:false\` 与原因）；Java 层调用链（ART 栈回溯）仍不在本工具内，需要时走 \`java_enum\`/ART 结构另做。

- [x] **v4.38 系统调用监听升级：静态归因 + 按名筛选 + 覆盖 libc 封装（2026-09-18，真机 PASS）**：v4.10 只能扫"目标模块自己的 `svc #0`"，而真实 App 极少自己发系统调用——它们调 bionic 包装，桩在 `libc.so` 里。本轮把 L1 从"找得到"做到"看得懂、挑得准"。
      · **静态归因**（`daemon/src/syscall_watch.ts` `attributeSite()`）：对每个 `svc #0` 站点向前最多 10 条指令解码"写 x8 的那条"——`MOVZ x8/w8, #imm` 与 `MOVZ x8, #imm, lsl #16`；遇到任何控制流指令（b/bl/b.cond/cbz/tbz/ret/br/blr/svc）立即停止，**绝不借用相邻桩的号**；解不出来就报 `unknown`，不猜。
      · **筛选与失败语义**：`syscall_watch` 新增 `syscalls` 参数（MCP 数组或 CSV，名字/十进制/十六进制均可，如 `["uname","openat",117]`），只挂归因命中且匹配的站点；**命中 0 个直接报错**（附"归因了几个/共几个站点"），不静默挂 0 个。`native_syscall_scan`（纯静态、不需要设备）同样返回每站点的号与名字，并给出 `attributedCount/unknownCount`。
      · **真机数据**（`aa165071`，Android 15）：bionic `/apex/com.android.runtime/lib64/bionic/libc.so` **224 个 `svc` 站点，223 个成功归因**（`openat`、`getrandom`、`uname`、`getuid/geteuid/getgid/getegid`、`clone`、`munmap`…，1 个解不出）；`tools/verify_v77_syscall_watch_libc.sh` PASS：`libadhdetect.so` 的 direct svc 归因 `gettid(178)` 且按名筛选只挂 1 个；`libc.so + syscalls:["uname"]` 只挂那 1 个 `uname` 站点（`matched=1/224`）；调用沙盒新增的 libc 探针 `adh_libc_uname_probe`（内部走 libc `uname()`）后，`NATIVE_HOOK` 事件以 **x8=0xa0** 命中，逐个卸钩成功、进程存活。
      · **归因解码器有单元测试**（`daemon/test/syscall_watch.test.ts`，`node --test`，7 条：x8/w8/lsl16 三种形态、控制流截断、寄存器来源必须报 unknown、token 解析、未知号命名）：`tools/verify_v76_syscall_attribution.sh`（host，秒级）在门禁里跑它们。**这套测试第一版就抓到一个致命 bug**——JS 位与是**有符号 int32**，`word & 0xffe0001f` 对 `0xd2800008` 这类高位掩码落在负数域，与正向字面量比较**永远不成立**，归因结果全空而 `node --check`／类型剥离／MCP 注册检查全绿；修法是所有掩码比较统一 `>>> 0`。这正是"静态检查不算验证"的又一例。
      · **门禁**：新增 `verify_v76_syscall_attribution.sh`（host：跑单元测试 + 断言 MCP schema 暴露 `syscalls`）与 `verify_v77_syscall_watch_libc.sh`（device）后，全量 `tools/verify_all.sh` **91 PASS / 0 FAIL / 2 SKIP**（两次 SKIP 是 v37 重启 Host Daemon 后 v38/v39 的自动化桥未及重连，按契约跳过）。
      · 边界（未变）：仍是**采样式**观测——每个 hook 站点的事件量受 agent 事件环上限约束，高频 syscall（如 `read`）会产生大量事件且只保留最近的；seccomp/PTRACE_SYSEMU 级别的全量拦截**已决议不做**（2026-10-01，见 `DEVELOPMENT_PLAN §9.1`）。

- [x] **v4.2–v4.7 真机运行时验收（2026-09-18，Android 15 / SDK 35 PASS）**：LSPlant Java hook、Java 枚举/主动调用、native inline hook、GOT 枚举在真机 `com.adh.sandbox` 上全部通过，测试设备 OnePlus PGP110 / serial `aa165071`。以下历史条目的 “runtime pending” 已被本条取代。
      · v4.2 `javahook_probe`：`initOk:true`，backend `lsplant` v6.4；ColorOS 缺失 `VisiblyInitializedCallback` / `JitCodeCache::GarbageCollectCache` 时按 availability 降级，只关闭 JIT movement tracking，不再让 Init 假失败。
      · v4.3 `java_hook`：静态 `HookProbe.ping(String)` + 实例 `instancePing(String)` 均命中，原始返回值 `REAL_*`、`JAVA_HOOK` 事件和逐个 unhook 都正确，进程存活。Android 14+ 拒绝可写 dex，bridge 现在将嵌入 dex 落到 app `code_cache/adh_bridge.dex`、`fchmod 0400` 后交给 `DexClassLoader`。
      · v4.4/v4.5 `java_enum` / `java_call`：两个 `ping` 重载枚举正确；带 `String` / `String,int` 类型参数的反射主动调用返回 `REAL_HOOK:ADH_CALL_ONE`、`REAL_HOOK:ADH_CALL_TWO*3`。修了 agent JSON 提取器不反转义的问题，嵌套 `args` JSON 现在能正确解析。
      · v4.6/v4.7 `native_hook` / `got_enum`：inline hook `libadhdetect.so:adh_trace_target` 命中并产生 `NATIVE_HOOK` 寄存器事件，unhook 后进程存活；GOT 枚举返回 17 个 entry，`ptrace/access/__system_property_get` 可见，`count` 与 entries 一致。沙盒目标函数标记 noinline，避免 JNI 入口把被 hook 目标内联掉导致“安装成功但 0 命中”的假阴性。
      · 验收脚本：`verify_v42_lsplant.sh` … `verify_v47_got_enum.sh` 全部 exit 0；`verify_v43` 的 RESULT 输出修正为 PASS/FAIL。新增到 `tools/verify_all.sh` 设备回归列表。- [x] **v4.8 实时内存反汇编 — Capstone 5 WASM（2026-09-18，真机 PASS）**：新增 Host 侧 `memory_disasm` MCP 工具与 `POST /api/memory/disasm`。它先用 agent 的 `read` 从目标进程取字节，再用 Daemon 内的 Capstone 5 WASM 反汇编；重分析不进入 agent，符合架构红线。支持绝对地址，也支持 `module+offset` 由实时 maps 解析基址；大小上限 64 KiB、地址按 AArch64 4 字节对齐，短读/尾部字节显式报告。
      · 真机 `aa165071`（OnePlus PGP110 / Android 15）验收 `tools/verify_v48_memory_disasm.sh` PASS：先经 `native_hook` 解析 `libadhdetect.so:adh_trace_target`，unhook 后 256 字节读出 64 条指令，首地址与目标一致、包含 `ret`；`module+offset` 路径同样返回 16 条指令。MCP 工具数 58 -> 59，`verify_v10_mcp.sh` 在 59-tool daemon 上 PASS。
      · 已知边界：Capstone 当前固定按 AArch64 little-endian 解码（本产品主 ABI `arm64-v8a`）；未对齐地址直接报错，不静默截断。多架构已决议不做（2026-10-01，arm64-v8a 是产品边界），这条 contingency 关闭。
- [x] **v4.9 native 主动调用（2026-09-18，真机 PASS）**：新增 agent 命令 `native_call`、HTTP `POST /api/native/call`、MCP `native_call`。支持通过 `module+symbol` 或绝对 `addr` 调用 native 函数，最多 8 个 unsigned integer/pointer 参数（AAPCS64 整数寄存器），返回 `result`/`resultDecimal`/`durationUs`；浮点/向量参数暂不支持并显式报告 `fpSupported:false`。
      · 安全边界：任意函数调用可能崩目标，Host 侧（HTTP 与 MCP）强制 `confirm:true`，未确认一律 400；agent 只解析并调用，不做策略判断，保持“采集/执行层”边界。
      · 沙盒新增导出 `adh_add_target(a,b)=(a+b)*2`；`tools/verify_v49_native_call.sh` 真机验证 module+symbol `20,22 -> 84`、无参 `adh_trace_target -> 30`、native_hook 解析地址后 `addr` 调用 `7,8 -> 30`，并断言未确认请求被拒绝、unhook 成功、进程存活。MCP 工具数 59 -> 60。
- [x] **v4.10 直接系统调用监听（2026-09-18，真机 PASS）**：新增 Host 编排 `syscall_watch` MCP/HTTP `POST /api/native/syscall_watch`。Host 先 `reconstructSo` 目标模块、用现有 `svcScan` 找静态 `svc #0` 指令，再对前 N 个地址走 `native_hook` inline hook；agent 仍只执行 hook，不承担扫描/分析。事件沿用 `NATIVE_HOOK`，其中 **x8 是 syscall 号**。
      · 真机 `aa165071` PASS：`libadhdetect.so` 扫到 2 个 `svc`，安装 2 个 hook；调用 `adh_direct_gettid` 后命中 `x8=0xb2`（gettid）事件，返回 2026，unhook 后进程存活。`tools/verify_v50_syscall_watch.sh` 覆盖 scan→hook→call→event→unhook。
      · 当前边界：每个模块默认最多 16 个 svc 站点（`limit` 1..16），超限返回 `truncated:true`；目前看的是直接 `svc #0`，libc/PLT 封装调用仍需结合 GOT/native hook 或后续 syscall 专用 stub。
- [x] **v4.11 QBDI 带参数主动 trace（2026-09-18，真机 PASS）**：`qbdi_trace` 现在接受最多 8 个 unsigned integer/pointer `args`（CSV；MCP 传数组），按 AAPCS64 整数寄存器在 QBDI VM 中调用目标并返回 `retval + per-instruction trace`；参数解析复用 `adh_parse_u64_csv`，非法参数 fail-loud。
      · 真机 `aa165071` PASS：`libadhdetect.so:adh_add_target(20,22)` trace 返回 84，指令流非空（3 条，编译器已常量折叠为 add/lsl/ret）；无参 `adh_trace_target` 仍返回 30、64 条指令。`tools/verify_v51_qbdi_args.sh` 覆盖带参/无参/非法参数三路；旧 agent 忽略 args 时以探针 SKIP，避免假 PASS。
- [x] **v4.12 Java hook 返回值替换 / skip original（2026-09-18，真机 PASS）**：`java_hook` 新增 `skipOriginal` + `returnValue`；LSPlant bridge 在回调里跳过 backup 调用，按目标返回类型转换替换值（boolean/byte/char/short/int/long/float/double/String/Object/null），并照常写 `lastReturn` 与 `JAVA_HOOK` 事件。status 增加 `returnOverride:true` 能力标记，旧 agent 可被验收脚本识别为 SKIP。
      · 真机 `aa165071` PASS：hook `HookProbe.ping(String)` 设 `skipOriginal:true,returnValue:"ADH_OVERRIDE"`，调用 `recordPing` 得到替换值，再读 `lastPingResult` 仍为 `ADH_OVERRIDE`，证明调用方可见；随后 unhook 成功。`tools/verify_v52_java_override.sh` 覆盖 capability → install → caller-visible override → status → unhook。
      · 顺带修了 v4.3 验收脚本只检查第一条历史 `JAVA_HOOK` 捕获的回归假失败：现在遍历同日事件找匹配项。
- [x] **v4.13 Java hook 参数改写（2026-09-18，真机 PASS）**：`java_hook` 新增 `argIndex/argValue`，bridge 在调用 backup 前按目标参数类型转换并替换参数（`argIndex=-1` 表示不改写），`lastArg` 记录改写后的可见值；status 增加 `argRewrite:true` 能力标记。与 `skipOriginal/returnValue` 组合后，Java 层已具备 observe / 改参 / 换返回值 / 跳过原方法四件套。
      · 真机 `aa165071` PASS：hook `HookProbe.ping(String)` 设 `argIndex:0,argValue:"ADH_REWRITTEN"`，以 `ADH_ORIGINAL` 调用 `recordPing`，原方法仍执行且调用方拿到 `REAL_HOOK:ADH_REWRITTEN`；`lastPingResult` 回读一致，status hits/lastArg/lastReturn 正确，unhook 后进程存活。`tools/verify_v53_java_arg_rewrite.sh` 覆盖 capability → install → original-invoked rewrite → caller-visible return → unhook。
- [x] **v4.14 JNI `RegisterNatives` hook（2026-09-18，真机 PASS）**：新增 agent 命令 `jni_hook`、HTTP `POST /api/jni/hook`、MCP `jni_hook`，action 为 install/uninstall/status。实现直接 inline-hook `JNIEnv->RegisterNatives` 函数指针；每次注册最多记录 16 条 `JNI_NATIVE` 事件，包含 class/method/signature/fnPtr/index/total，并原样转发给原 JNI 实现。Host 将 `JNI_NATIVE` 归入 system，显示为 `JNI Hook / RegisterNatives`。
      · 真机 `aa165071` PASS：hook 安装到 libart `RegisterNatives`（target 非零），触发 sandbox `Detection.jniRegisterProbe()` 后 status `hits=1,lastCount=1`，捕获到 `com.adh.sandbox.Detection.jniRegisteredProbe()I` 事件；随后新注册的 `jniRegisteredProbe()` 通过普通 JNI 返回 `0xAD11`，uninstall 后进程存活。`tools/verify_v54_jni_register_hook.sh` 覆盖 install→trigger→event→registered-call→status→uninstall。
      · 仍未覆盖：`JNI_OnLoad`、单个 `JNIEnv` 表函数（如 CallStaticObjectMethod）的通用 hook，以及注册函数指针重定向；下一批继续。
- [x] **v4.15 native hook 改参 / 换返回值 / 跳过原函数（2026-09-18，真机 PASS）**：`native_hook` 新增 `argIndex/argValue/skipOriginal/returnValue`。固定 arm64 stub 现在把 `adh_native_hook_record` 的返回值作为 skip 标志：stub 先恢复被改写的 x0-x7，若 skip 则直接 `ret`，否则跳原 trampoline；事件保留原始入参快照并附加 rewrite/skip 字段，status 同步暴露配置。
      · 真机 `aa165071` PASS：`adh_add_target(a,b)=(a+b)*2` 上先用 `argIndex:0,argValue:7` 把 `1,2` 改成 `7,2 -> 18`；再用 `skipOriginal:true,returnValue:0x54` 跳过原函数并返回 `84`；status、unhook、进程存活均正确。`tools/verify_v55_native_rewrite.sh` 覆盖两种路径。v4.6 native hook 验收也修成遍历历史事件，复跑 PASS。
      · 当前边界：native 参数/返回值以 raw 64-bit register 处理，覆盖 x0-x7 整数/指针与 x0 返回值；浮点/向量参数、栈上传参和 128-bit 返回值仍显式不支持。
- [x] **v4.16 评审后稳定性加固（2026-09-18，真机 PASS）**：两位独立 subagent 评审后修复了本轮 hook 代码的 P0/P1：
      · GOT：新增 exact-module + `adh_got_replace_by_name_ex`，native GOT hook 的 `original` 现在直接取“实际被替换槽的原值”，不再独立解析另一个槽；模块名改为 basename 精确匹配，多槽/多模块命中直接 fail-loud。
      · native_call：参数序列化改为显式剩余空间检查，修掉 `snprintf` would-be-length 造成的 size_t 下溢越界写。
      · JNI RegisterNatives：安装前先发布真实函数入口，安装窗口内并发注册不再返回 JNI_ERR；original 指针用 `__atomic` acquire/release；wrapper 的 re-entrancy 标志改为原函数返回后再清；类名改用 `GetObjectClass`，避免 hook 内触发 FindClass/类加载。
      · native/Java 生命周期：unhook 默认改为 **软卸载**（保留已安装 stub/LSPlant hook，只停用配置），同 target/signature 再次 install 直接 reactivate，不再对已 patched 函数二次 DobbyHook / LSPlant Hook，也不再 `DobbyDestroy` 释放正在使用的 trampoline。status 增加 `patched` 计数。
      · 安全/输入：inline 绝对地址必须 `confirm:true`，agent 校验目标位于 executable mapping；active 发布顺序移到所有字段之后；重复 target fail-loud；Java bridge 增加 `ready` 安装窗口自旋、ADH 自有 backup global ref、事件字符串 512 字符上限。
      · 真机 `aa165071` PASS：native 与 Java 同一目标各连续 24 次 install/unhook 后行为恢复、agent 存活（`tools/verify_v56_hook_stress.sh`）；v4.3/v4.6/v4.12–v4.15 全部复跑 PASS。
      · 已知边界：软卸载会在目标里保留 stub/LSPlant patch（去特征场景需要后续 hard-unhook/quiesce 方案）；JNI_OnLoad 仍未覆盖；Java/native 的唯一目标数仍受 16 槽上限约束——**超出时 fail-loud 并给出释放建议**，这是产品语义（`REQUIREMENTS §21.2`）。
- [x] **v4.37 去特征：Zygisk 注入的 agent 不再以文件路径出现在目标 maps（2026-09-18，真机 PASS）**：之前 Zygisk 伴生进程直接 `android_dlopen_ext` 模块目录里的 `libadh_agent.so`，目标 maps 里就是一行 `/data/adb/modules/adh/libadh_agent.so` —— 这是注入留下的最后一个"一眼可见"指纹（沙盒审计的 `agentNamedExec` 一直报 1）。
      · **做法**：伴生进程把 agent 复制进 `memfd_create("jit-cache")`，再让 linker 从那个 fd 加载；目标 maps 里于是只剩 `/memfd:jit-cache (deleted)`，与 ART 自己的 JIT cache **同名**（inode/大小/私有可执行映射仍可区分，v75 就是按这三点断言的）。关键细节：memfd 必须在 **post-specialize（App 域）** 创建 —— 在 pre-specialize（zygote 域）创建的话，App 域的 linker 连 `stat /proc/self/fd/N` 都会被拒（真机报 `unable to stat file for the library ... Permission denied`），所以 pre-specialize 只保留"打开模块目录 fd"，复制与加载都放到 specialize 之后。
      · **伴生进程协议**：实例侧不再自己读 scope（它前后 uid 不同、且 `/data/adb` 是 0700），改为通过 `api->connectCompanion()` 让**以 root 运行的伴生进程**读 `/data/adb/adh/scope.json` 并回答"在不在范围内"（`scope <pkg>` → `1`/`0`）；marker 走同一协议（`mark`）。
      · **注入决策可审计**（本轮最大的自我改进）：新增 `/data/adb/adh/zygisk_inject.log`，逐条记录 preAppSpecialize 的 uid、scope 问答、memfd 复制、加载策略与结果；实例侧写不进 `/data/adb` 时**经伴生进程转发**落盘；再不行且存在开关文件 `/data/adb/adh/zygisk_debug` 时写进目标自己的 `cache/adh_zygisk.log`（默认关——那是目标可见的痕迹）。就是靠它把两次静默失败分别定位成"scope 文件内容被写坏"和"memfd 在 specialize 前创建、加载期权限不足"。
      · **加载策略链**：`USE_LIBRARY_FD` → 只读 fd 复制 → 纯路径 `dlopen`，任一成功即用；全部失败则**回退模块路径**（功能优先，日志明说"agent 会出现在 maps 里"）。agent 自身也改成不依赖文件名：`adh_self_module_name()`（dladdr 推导）取代硬编码的 `libadh_agent.so`（GOT 自检 / stealth pool 的自家 GOT 查找 / 足迹统计）。
      · **评审后的加固（2026-09-18 第二轮）**：① 单实例守卫原先"按文件名匹配"在 memfd 下失效，改成按 **PT_LOAD span + 加载顺序**匹配（`adh_image_span_of()`）；第一版改动把"自己"排除在扫描外，结果**两个副本都会认为自己不是第一个而全体沉默** —— 修成"第一个 span 相同的条目（含自己）才是 owner"，并写进注释。② `module_base_of()` 对"我们自己"的名字查询直接返回自家 base：memfd 名 `jit-cache` 与 ART 的 JIT cache 同名，按名扫描可能解析到 ART。③ 足迹统计 `agent_exec` 从"名字包含"改为**地址区间**（`adh_self_image_bounds()`）。④ 伴生协议加固：按 `\n` 读满一整行（超长/截断一律拒绝）、未知命令不再**兜底当 mark**、控制消息全长度写 + 读回 ack、实例侧复用**一条**伴生连接（服务侧改成一连接多请求循环）、决策日志到 512 KiB 轮转、App 缓存调试日志路径校验包名（只允许 `[A-Za-z0-9._]`）。⑤ 删掉未使用的 `fallback_fd/fallback_path`（编译器警告即嫌疑）。
      · **实测边界（修正上一轮记录）**：伴生连接**活不过 postAppSpecialize** —— pre-specialize 的决策行（含 `in scope`、`skip not-in-scope`）现在稳定落在 root 决策日志里，但 post-specialize 的 `agent copied into memfd N` / `agent loaded … -> memfd:jit-cache (loaded)` 只能从**开关文件打开的** App 缓存调试日志里看到（当轮记录误把这些行算到 root 日志上，此处以本轮真机实测为准）。因此 memfd 结果的权威证据改为**目标内自证**（见下一条验收脚本）。
      · 真机 `aa165071` 验证（`com.android.settings`，**不自加载** agent）：`grep -c libadh_agent /proc/<pid>/maps` = **0**，只有三个小 `/memfd:jit-cache (deleted)` 映射（text/rodata/data，inode 与 ART 自己的 jit-cache 映射不同），daemon 侧 `com.android.settings entry=start` 在线；`tools/verify_v75_zygisk_memfd.sh` 把这四件事 + ELF 头读回绑成一条可复跑的验收；沙盒（自加载）路径不受影响。
      · **本轮门禁**：`tools/verify_all.sh` 脚本数 90 → **91**（新增 v75）：**89 PASS / 2 瞬时 FAIL** —— `verify_v36_automation` 与 `verify_v40_device_daemon` 在跑时设备处于锁屏 + OEM 跨应用确认弹窗在前台（`fg=com.android.systemui`），两个脚本**单独复跑均 PASS**（本轮判定：非回归）。v75 在门禁内 PASS。
      · **第四轮（评审三轮：身份精确化 + 验收不再可能假 PASS）**：① 单实例身份从"PT_LOAD span"升级为 **GNU build ID**（`adh_build_id_from_phdr()`/`adh_self_build_id()`，从内存里的 PT_NOTE 读，回调内直接解析所以不再嵌套 `dl_iterate_phdr`；span 仅作没有 build ID 时的回退）——同一文件的任何副本（模块目录 / memfd / 沙盒自加载）build ID 必然相同，而无关模块即使 span 撞车也不会被误判；image 范围同时改成 `[base+min_vaddr, base+max(vaddr+memsz))`（原来把 span 直接加在 `dli_fbase` 上，只有 `min_vaddr==0` 的布局才成立）。② `inspection.c` 的自身范围**只在解析成功时缓存**（原来一次瞬时失败会把 `agentExecMappings` 永久钉成 0）。③ v75 加固：SKIP 分支**不再打印 RESULT:PASS**（`verify_all.sh` 同步把顶层 SKIP 记为 skip 而不是 pass，之前"没装模块也算 PASS"的记账被修正）、要求会话是**本次冷启动之后新建**（`connectedAt >= startedAt`、pid 不在启动前的集合里、同一 pid 只有一个在线会话）、`entry` 必须是 `start`、memfd 路径必须**精确等于** `/memfd:jit-cache (deleted)`、ELF 头改读 **offset==0** 的那个私有映射（布局无关）、并要求 agent 自己的 `compat_probe.agentExecMappings >= 1`（目标内自证按地址认出了自己的镜像）。真机复验全绿：`3 private + 3 shared jit-cache regions`、私有 inode 与 ART 的不同、`agentExecMappings=1`。
      · **最终门禁（本轮第 4 次全量，代码冻结在 `0bd9bbc`）**：**89 PASS / 0 FAIL / 2 SKIP** —— 这是本项目第一次拿到"零失败"的全量结果。两次 SKIP 是 `verify_v38_automation_watchdog` / `verify_v39_notifications`：v37 会在脚本内**重启 Host ADH Daemon**，紧接着的这两个脚本遇到自动化桥尚未重连，于是按契约打 `RESULT:SKIP`（exit 0）；新的 runner 把这类情况记为 skip 而不是 pass——以前它们要么被算成 PASS（假通过），要么（更早的 `RESULT:SKIP` 变体）被算成 FAIL。
      · **门禁自己抓到的一个回归（记下来）**：v75 从"写死 `.Settings`"改成"按 target 解析启动组件"时，第一版把 `cmd package resolve-activity --brief` 的**多行输出**（ColorOS 会多打一行 `priority=...`）整段塞给 `am start -n`，组件名非法 → 应用根本没起 → 日志窗口里没有 scope 行，脚本报"never answered the scope query"。修复：只取形如 `pkg/Activity` 的 token，并加一次 monkey 兜底重试；失败证据里现在同时打印**当时的窗口焦点**（若是 SystemUI 在前台就明说"被 OEM 跨应用弹窗挡住"）。修好后连续两次真机 PASS（每次 memfd inode 都不同，说明确实是新一次加载）。① 伴生协议再加固 —— 客户端 socket 设 `SO_RCVTIMEO/SO_SNDTIMEO`（1 s，注入在 App 启动路径上，不能让卡死的伴生无限阻塞）、伴生侧逐字节读前 `poll()`（15 s 空闲即断，半开连接不再钉住循环）、socket 写入全部改 `send(..., MSG_NOSIGNAL)`（伴生先关连接时不会再让 app 吃 SIGPIPE）、回复必须读到 `\n` 且**内容精确匹配** `ok`/`0`/`1`（"err" 或半截回复不再被当成成功，会触发 app-cache 兜底）、超长行在拒收前把该行**读完丢弃**（流不再错位）、决策日志改为**原地 `ftruncate` 到上限**（去掉 rename，避免多实例并发时把刚写的行搬进 `.1` 而读者漏读）、`append_decision_line()` 返回 bool（写失败 LOGE 并让调用方继续走兜底）。② **注入结果现在有一条与后端无关的落点**：agent 在 hello 里上报自己的映射路径与基址（`selfModule`/`selfBase`，来自自身 `dladdr`）——Zygisk 注入的会话显示 `/memfd:jit-cache (deleted)`，自加载/沙盒显示真实 `.so` 路径；daemon 逐条记进 HELLO 日志并随 `/api/agents` 暴露，因此"这次注入到底加载成了什么"不再依赖目标可见的调试日志（那只是最末兜底）。真机复验：`selfModule=/memfd:jit-cache (deleted)`，v75 增补该断言后仍 PASS。
      · 诚实边界：模块目录里的 `libadh_agent.so` 仍然存在（**交付物与来源**），只是不再出现在目标进程 maps 里；`memfd:jit-cache` 这个名字本身仍与 ART 的 JIT cache 同名（这正是目的），inode/大小仍可区分；Xposed 后端与模拟注入路径不经过这段代码；开关文件存在时会在目标 `cache/` 留一个调试日志（默认不创建）。- [x] **v4.36 指针槽覆盖面：真实对象虚调用 + 可写函数指针（slotsWritable）（2026-09-18，真机 PASS）**：v4.35 的验收只用了"全局函数指针表"，评审点名两个缺口：真实 C++ 调用形态（对象里放 vptr、表在 RELRO、`ldr vptr/ldr slot/blr`）与**运行时可写**的函数指针（回调变量）。
      · 沙盒新增两组 fixture（C 结构体模拟 **C++ vtable 的内存形态**，不是 C++ 编译器生成的 virtual 分派；`ldr vptr/ldr slot/branch` 已由本地反汇编确认）：① 对象分派——`struct adh_obj { const volatile struct adh_obj_vt *vptr; }` + RELRO 里的 `adh_obj_vtable`，探针 `adh_obj_call()` **只经对象**取槽再间接调用（不是全局表）；② 可写回调——**file-local** 的 `adh_cb_target` + 可写(=`rw-`)槽 `adh_cb_slot`，探针 `adh_cb_call()` 走该槽（返回 a*100+b）。
      · 真机 `aa165071` PASS（`tools/verify_v74_slot_object_callback.sh`）：对象侧 `mode=vtable` 命中**对象表那一个槽**（`kind=data`、`perms=r--`、`orig` 就是函数地址），**只调对象探针**后 `hits=1`（命中归因到间接路径），函数地址处 24 字节前后逐位相同（**本次 slot hook 没有写该段代码**；同进程 before/after 比对，未与磁盘 .so 比对），hard unhook 后槽位读回 == 原值（且安装期间读回的活值**就是 agent 报的 thunk**、该 thunk 落在 `/memfd:jit-cache`）、thunk 页从 maps 消失、探针仍 84；可写侧**默认必须 fail-loud**（"writable slots were skipped; pass slotsWritable:true to include them"），`slotsWritable:true` 后命中 `rw-` 槽、`hits=1`、探针值正确，unhook 后槽位还原、thunk 页同样从 maps 消失、回调目标函数的 24 字节前后逐位相同、探针仍 304。
      · 这一轮也再次验证了 fail-loud 的价值：`adh_cb_target` 一开始是导出符号，模块自己就给它建了一个**只读 GOT 槽**，于是"默认跳过可写槽"根本没被触发（默认安装直接成功）——改成 file-local 后才真正只存在可写引用，默认路径如期报错。
      · 评审后加固：① 成功路径也回传 `skippedWritable`（默认只改只读槽时，"还有 N 个可写槽被跳过"不再只出现在失败信息里）；② revert 前先读槽现值，只有它**仍等于我们的 thunk** 才写回原值——目标自己改写过的槽原样保留并回传 `slotChangedByTarget`（绝不覆盖目标的新指针）；③ agent 侧同时接受字符串与 JSON 布尔 `slotsWritable`（直接打 HTTP 传 `true` 不再被静默当 false）。
      · 诚实边界：可写槽是**安装时刻**的快照值，目标之后自行改写该变量不受我们跟踪（现在 revert 也不会覆盖它，见上）；对象虚表必须是**已被重定位**的静态表（运行时动态拼出来的 vtable 不在范围）；仍不支持 skipOriginal/returnValue（返回值 bank 依目标而定）。
- [x] **v4.35 指针槽（vtable）hook：间接调用也能"零代码改写"（2026-09-18，真机 PASS）**：v4.33/v4.34 解决了直接 `B`/`BL`，但加固 App 的加密入口常常是 **C++ 虚函数 / 函数指针表**（`ldr x0,[xObj]; ldr x8,[x0,#off]; blr x8`）——既没有可改的"入口"，也没有单一调用点。本轮补上第三个"完全不动代码"的后端：`native_hook mode=vtable`。
      · 做法（`agent/src/hook/slot_hooks.c`）：扫描**可读非可执行的 data 段**（默认目标模块，`scope` 支持 all/指定模块），找 8 字节对齐且值等于目标地址的槽位，把槽位值换成我们自己的 thunk——**函数本体与任何调用点都不改**。槽位常在 `.data.rel.ro`（RELRO），因此写回走既有的 `adh_swap_pointer_in_ro_page`。thunk 复用 v4.33 那套已自检的编码器（指针调用不受 ±128 MB 限制）。
      · **顺手做了个诚实的分类**：一个槽位到底是"导入槽（GOT）"还是"普通数据（vtable/回调表）"由重定位类型判断——只有 `R_AARCH64_GLOB_DAT`/`JUMP_SLOT` 算 GOT，`RELATIVE`（vtable 里那些指针式重定位）算 data，状态里逐槽回传 `kind`。这条分类不是学术问题：**改 GOT 槽会改变该模块内 `&symbol` 解析到的地址**，验证里就把这个副作用如实打出来了。
      · 真机 `aa165071` PASS（`tools/verify_v73_vtable_hook.sh`，沙盒新增 `const volatile` 函数指针表 + 只经该表间接调用的 `Detection.slotProbe()`、`vtableAddress()`）：`slotCount=2`（vtable 槽 `kind=data` `perms=r--`、模块 PLT 槽 `kind=got`）→ **`entryUnchanged=true`**（在"从 vtable 里读出的函数地址"处直接读 24 字节，安装前后逐位相同；不是靠符号解析）→ 相邻槽（另一个函数）`subUnchanged=true` → `slotProbe()` 仍返回 84、两个探针后的**聚合** `hits=1`（间接路径的命中未单独归因；同一次安装也会命中该模块的 PLT GOT 槽，所以直接调用同样被重定向），同时 `siteProbe()` 直接路径仍 84 → thunk 页在 `/memfd:jit-cache` → hard unhook 后 16 字节槽位区**逐位还原**、thunk 页 munmap、探针仍 84。审计 `antiHookProbe` 此时会报 `prologueDiffers=true`：因为它在模块内取 `&adh_add_target` 会读到被换掉的 GOT 槽——验收脚本把这个副作用原样打印，并注明"代码真值以直接读函数地址的 24 字节为准"。
      · 评审后加固：默认**只改只读（RELRO）映射里的槽**（可写数据段里"值恰好等于目标地址"的字更可能是常量/RTTI，而不是调用点），要改可写槽必须显式 `slotsWritable:true`（没有任何命中时错误里会写明 "writable slots were skipped"）；回滚时若某个槽还原失败，**保留该 thunk 页**并把 `pageKept` 报到 status（与 sites 后端同一策略）；验收新增"被改的槽都是只读映射"与"该槽的 orig 就是函数地址"两条断言。
      · 诚实边界：只改**安装时刻**存在的槽位（目标运行时重建的表不跟踪）；可写槽位可能被目标自己改回；运行时用指针算术拼出来的跳转（如手写 jump table）不在范围；槽位那 8 个字节本身对"检查这张表的人"可见（函数代码依然不可见）；同样不支持 skipOriginal/returnValue（返回值 bank 依目标而定，fail-loud）。
- [x] **v4.34 call-site hooking 跨模块（scope=all / scope=<module>）（2026-09-18，真机 PASS）**：v4.33 的零入口改写只覆盖"调用者和目标在同一个模块"。真实 App 里加密函数常被**另一个 so** 调用（算法库 ↔ 业务壳），所以本轮把扫描范围打开。
      · 做法：`native_hook mode=sites` 新增 `scope`——`module`（默认，只看目标模块）、`all`（所有**文件映射**的可执行段；JIT memfd 与匿名页被显式跳过，agent 自身模块也必须能解析出来才允许用 `all`，否则 fail-loud）、或一个模块名/basename（只看它）。每个调用点**各自分配一个 near thunk 页**（不同模块的调用点可能相距 >128 MB，共用一个页会超出 BL 范围）；PLT stub 解析（`adrp x16; ldr x17,[x16,#off]` → 读 GOT）跨模块同样适用，GOT 槽的可读性用同一张映射表判断。
      · 扫描顺序按优先级：**目标模块 → /data 下的应用自有模块 → 其余系统库**。一开始用"扁平预算"，64 MB 全花在系统库上、压根没走到 App 自己的模块（报 "scan budget hit" 且 0 站点）；现在先扫应用自有模块，预算 128 MB，`scanned`/`truncated` 如实回传。
      · 映射表改为**动态分配**（4096 项）：之前栈上 512 项的表在 2600 个映射的进程里会在到达 App 自己的库之前就截断，导致"目标模块解析不到"（真机报错 `could not resolve the module of target ...`），两个坑都记在这里。
      · **顺手抓到一个自己引入的严重 bug**：重写 thunk 编码时把"跳过块之后的跳转"用错了函数（`enc_branch()` 收的是**字节地址**，我传了**指令下标**）→ 生成了 `b .`（跳到自己），调用一次就把目标线程 100% 钉死。现在 thunk 生成后**先自检**（两条 pc 相对分支、两个字面量、recorder/original 地址都要对）才允许安装；这条自检已经写进 `emit_thunk`。
      · 评审后加固：memfd 路径其实以 `/` 开头、原来的"非 `/` 开头"过滤**没拦住 JIT 页**（现在显式跳过 `/memfd:`）；PLT stub 读到的 GOT 槽现在必须与 stub **同模块**（否则 .text 里形如 `adrp+ldr` 的数据字可能被误判成调用点）；站点超范围/回滚失败时不再泄漏或拆掉仍在使用的 thunk 页（保留的页现在通过 status 的 `sitesPageKept` 对客户端可见）；映射表满会显式上报；编码器加了立即数范围守卫（掩码静默截断会生成"看起来合法"的错误指令）。
      · 真机 `aa165071` PASS（`tools/verify_v72_site_hooks_cross.sh`）：沙盒新增跨模块 fixture `libadhplugin_a.so:adh_plugin_call_adder`（链接 libadhdetect 并调用 adh_add_target，Java 侧 `Detection.pluginProbe()`）→ `scope=all` 找到 **3 个站点、2 个模块**（目标模块 `b`+`bl`、插件模块 `b`），三个探针都返回 84、命中 `hits=3`，目标自己的审计**依然** `prologueDiffers=false / entryBranchesOutside=false / anonExec=0`，三张 thunk 页都是 `/memfd:jit-cache`（各自贴近自己的调用点）→ hard unhook 后三个调用点**独立读回等于 agent 记录的原值**、在 maps 读取成功的前提下三张 thunk 页**已不再映射**（`mapsReadAfterUnhook>0` 已断言）、探针仍 84 → `scope=libadhplugin_a.so` 只选中插件模块那一个站点。`scope=all` 约 1.8 s（`module` 约 30 ms），`truncated:true` 是系统库阶段的预算耗尽，如实上报。
      · 诚实边界（与 v4.33 相同，另有新增）：仍只覆盖**直接 B/BL**（跨模块也行，但间接调用/函数指针/虚表要走 mode=got 或 mode=inline）；`scope=all` 受 128 MB 扫描预算限制，超出部分不扫且报 `truncated:true`；调用点自身字节会被改写（目标查调用方也能看见）；sites 不支持 skipOriginal/returnValue（返回值 bank 不确定，fail-loud 拒绝）。
- [x] **v4.33 call-site hooking：入口序言一个字节都不动（2026-09-18，真机 PASS）**：v4.32 把"匿名可执行页"这条痕迹做掉了，但**函数入口被改写**这条还在（目标自己比对自己序言就能看见，v69 里 `prologueDiffers/entryBranchesOutside` 在 stealth 下依然是 true）。本轮补上"不改入口也能拦"的那一半：`native_hook mode=sites`。
      · **做法**（`agent/src/hook/site_hooks.c`）：扫描目标模块自己的可执行段，找出**调用该函数**的 `B`/`BL` 指令（每个 hook 最多 8 个），把它们改写到我们自己的 near thunk；**目标函数本体实现上不写一个字节**（验收只证明审计的 24 字节窗口内与构造时快照相等，不是与磁盘对比）。thunk 是手写编码的 arm64（每条编码都先和 `llvm-mc` 对过），流程：按入口 stub 同样的 256 字节布局保存 x0-x9/x29/x30/x18/q0-q7 → 调 `adh_native_hook_record_site`（复用既有事件流、命中计数与整数改参）→ 回填寄存器 → `blr` 真函数 → 返回其结果。**补丁是我们自己的**，所以 install/unhook 可逆、可重复（没有 Dobby 的陈旧状态问题）。
      · 两个必须踩过才知道的坑：① **PLT/尾调用**——同模块里调用一个可被插入（interposable）的符号会走本地 PLT stub，编译器还可能把它优化成尾调用 `b <stub>`，所以扫描器必须做一层 PLT 解析（`adrp x16; ldr x17,[x16,#off]` → 读 GOT 槽比对目标）并且**同时匹配 B 和 BL**；② **补丁 opcode 必须和原指令同形**：把尾调用 `b` 改成 `bl` 会让 thunk 返回到"下一条指令"（那里恰好是函数本体），于是 CPU 卡在函数入口 100% 空转（真机上用 `debuggerd -b` 抓到 PC 恒定在入口），现在按原形分别写 `b`/`bl`。
      · thunk 页用 `memfd:jit-cache` + `MAP_FIXED_NOREPLACE` 在 ±128 MB 内解析（BL 只能跳这么远）：先让内核按 hint 落位，再试模块各段尾部，再 2 MB 粗扫 + 64 KB 精修；**一开始用 64 KB 盲扫 ±128 MB 在 2600 个映射的进程里要 ~15 秒，把 agent 命令线程堵死**（所有命令超时），改成有界搜索后毫秒级。
      · 真机 `aa165071` PASS（`tools/verify_v70_site_hooks.sh`）：干净进程基线 → 装 sites hook（`siteCount=2`，**两种形态都有**：尾调用 `form="b"` `0x01400077c → 0x014004018`、真调用 `form="bl"` `0x094000774 → 0x094004050`）→ 两个 fixture 都返回 84、命中 `hits=2`，同一时刻目标自己的审计**依然报 prologueDiffers=false / entryBranchesOutside=false / anonExec=0**（入口零改写 + 无匿名可执行页，两条都是目标侧独立审计给的）→ thunk 落在 `/memfd:jit-cache (deleted)` → hard unhook 后**两个调用点字节各自逐位读回等于原值**、thunk 页**已 munmap**（status 的 `pageKept` 用于极少数"线程还在 thunk 里"的例外）、status 清空、调用仍 84 → **同进程**再装一次照常命中（证明不依赖重启）→ 重开进程再装也成功。
      · 诚实边界：只覆盖**同模块内直接 B/BL**（含一层 PLT/尾调用 stub；跨模块、函数指针、虚表要用 mode=got 或 mode=inline）；每个 hook 最多 patch 8 个调用点，且**调用方**那几个字节当然可被检查；`skipOriginal/returnSet` 在 sites 模式**直接 fail-loud 拒绝**（返回值落在 x0/x1 还是 d0/d1 取决于目标，跳过调用等于把未定义值交给调用者——要换返回值请用 mode=inline）；thunk 页在 `munmap` 前有静默窗口，命中还在动就保留（宁可留着也不砸正在执行的线程），此时 status 报 `pageKept:true`，不假装"什么都没留下"。
- [x] **v4.32 去特征：inline hook 的匿名可执行页消失（2026-09-18，真机 PASS）**：目标做"反注入"最省事的一条是扫 `/proc/self/maps` 里**没有路径的可执行页** —— 装一个 inline hook 就会多出 Dobby 的 trampoline arena（真机实测 +2 个 4 KiB r-x 匿名页），而正常 ART 应用只会出现**有名字的** `/memfd:jit-cache`。本轮把这条痕迹做掉，并用**目标自己的审计**验收，而不是自说自话。
      · 实现（`agent/src/hook/stealth_pool.c`，**默认关闭**）：libdobby.a 静态链接进 `libadh_agent.so`，它的 `mmap` 调用走**我们自己的 PLT/GOT 槽**（readelf 证据：`mmap@LIBC` JUMP_SLOT，且在 RELRO 段内）。`stealth on` 用 `adh_swap_pointer_in_ro_page` 把该槽换成自家 interposer：仅在**线程本地的重定向窗口**（`adh_inline_hook` 调 Dobby 的那几毫秒）内，把 `MAP_ANONYMOUS` 且 ≤1 MiB 的分配改写成 `memfd_create("jit-cache")` + `MAP_SHARED`（同时清掉 `MAP_PRIVATE`——它和 `MAP_SHARED` 同时置位就是 `MAP_SHARED_VALIDATE` 这个未定义组合），地址提示/保护保留、匿名映射本来偏移就是 0，因此 Dobby 的 near 分配仍在原位；任何一步失败都**回退真 mmap** 并如实上报 errno。窗口是**线程本地**的：窗口开启期间该线程上**任何**符合条件的匿名分配都会被改写（不只 Dobby 的 arena），这是这条能力的诚实边界。`stealth off` 把槽换回 libc 原值。
      · 目标侧审计（沙盒 fixture `Detection.antiHookProbe`）：自己解析 `/proc/self/maps` + 自己在构造函数里拍的序言基线，报 4 个信号：匿名可执行页数、序言是否被改、是否有路径含 "agent" 的可执行映射、入口第一条指令是否跳到本模块之外。它不认识我们，只认事实。
      · 真机 `aa165071` PASS（`tools/verify_v69_stealth_pool.sh`）：干净进程 → `anonExec=0 / prologueDiffers=false / entryBranchesOutside=false`；装 inline hook（未开 stealth）→ `anonExec=2 / true / true`、trampoline 落在匿名页（**审计确实看得见我们**，说明这个检测是真的）；hard unhook → 序言与入口恢复（匿名页仍在，如实记录）；重开进程 + `stealth on` 后同一 hook → **`anonExec=0`**、trampoline 落在 `/memfd:jit-cache (deleted)`、`memfdExec 2→4`，且 `adh_add_target(20,22)` 仍返回 84 **并且 hook 命中数 hits≥1**（84 本身不足以证明调用真的过了 hook）；同一时刻目标审计**依然**报 `prologueDiffers/entryBranchesOutside=true`（这条已写进验收断言，不是口头声明）；`stealth off` 后 status 里**现场读回**的 `slotNow` 为 0、`originalMmap` 是 libc 的 mmap（还原前会先比对槽位仍指向自家 interposer，被别人改过就 fail-loud 不动它）。
      · 诚实边界：① **入口序言被改写掩盖不掉**（stealth 下 `prologueDiffers/entryBranchesOutside` 依然 true）——要"序言也不变"只能改用 GOT/表项 hook（已有）或 ART 层 Java hook（LSPlant 不改 .text）；② 已建好的旧 arena 不搬家，只有开启后的**新**分配进 memfd；③ opt-in + Host `confirm:true`，符合"默认不自隐藏"红线；④ memfd 名故意与 ART 的 JIT cache 同族（这正是去特征的点），代码与 MCP 描述直说这件事。
- [x] **Device Daemon 自愈：system_server 重启后 binder 发布不再永久卡死（2026-09-18，真机 PASS）**：v36/v41 两条真机验收长期 FAIL（"ADH Device Daemon is unavailable"），现场证据指向**设备侧状态**而非验收脚本：`adh-device-daemon` 进程活着（已跑 15h47m）、模块目录在、Manager 已装、Host 桥正常，但 daemon 每秒重试 publish 全部 `DeadObjectException`。
      · 根因：`ActivityManager.getService()` 返回的是**进程内缓存的单例代理**（IActivityManagerSingleton）。这台机器 system_server 在开机约 4h 后重启过一次（daemon 进程 ETIME 15:47 vs system_server 11:59），缓存 binder 早已失效；发布循环又只在"Manager pid 变了"时才重试，于是 daemon 表面健康、Manager 永远连不上。
      · 修法：`ExternalProviderPublisher` 每次尝试都从 `ServiceManager.getService("activity")` + `IActivityManager$Stub.asInterface` 取**全新代理**（`ActivityManager.getService()` 降级为兜底），1s 重试循环因此在 system_server 重启后自愈，不需要重启手机或重刷模块。
      · 部署注意：daemon.apk 必须由 `tools/build_zygisk.sh` 生成（它注入 `-PadhManagerCertSha256` = Manager 证书指纹）；不带该属性直接 `./gradlew :daemon:assembleDebug` 出来的 APK 会在启动时 fail-loud 拒绝运行（"manager certificate digest is missing"，本轮踩到过）。热更新路径：push 新 daemon.apk 到 `/data/adb/modules/adh/` → kill 旧进程 → `setsid nohup device-daemon`，无需重启。
      · 验证：真机 `aa165071` 热更新后 `verify_v41_postflash.sh` 3 FAIL → **5 PASS**（含 root input 注入）、`verify_v36_automation.sh` PASS，全量 `verify_all.sh` **84 pass / 0 fail / 0 skip**（此前 82/2）。
- [x] **v4.31 native 浮点参数 / FP 返回（2026-09-18，真机 PASS）**：native 这一半以前只有整数寄存器 —— hook 事件只有 x0-x7，`native_call` 遇到 `float/double` 参数只能传垃圾（`fpSupported:false`）。本轮把 FP bank 补齐。
      · **主动调用**：`native_call` 参数改类型化语法 `f:<float>` / `d:<double>`（进 s0-s7 / d0-d7），其它 token 仍进 x0-x7；AAPCS64 两个 bank 独立计数，各限 8 个，`argCount` 为两者之和。FP 返回公布 `fpResult`(d0 原始 64 位) / `fpResultDouble` / `fpResultFloat` / `returnBank:"d0"` —— FP 返回的目标 x0 是陈旧值，所以显式标注来源而不是把 `result` 冒充返回值；NaN/Inf 位型序列化成 `null`（`%.9g` 会打出非法 JSON `nan`，直接毒死 daemon 的命令解析）。
      · **调用通路是汇编**（`agent/src/runtime/fp_call.S`）：x0-x7 从 ints[]、d0-d7 从 fps[] 装载，`blr` 后把 d0 落到 `g_adh_fp_call_result`。必须汇编 —— naked C 版本在 -O3 下参数寄存器被 clobber；`blr` 覆盖 x30，所以 x29/x30 必须入栈（第一版漏存，返回时直接跳回 trampoline 崩掉）。
      · **事件侧**：`NATIVE_HOOK` 事件新增 `fp:{d0..d7,s0..s7,q0hi..q7hi}` —— 每个 lane 同时给 double 与 float 两种读法（float 参数只填低 32 位）。注意**不做猜测**：两种读法都可能是"有限数"（d1=4.0 同时给 `d1="4"` 与 `s1="0"`），"哪个才是调用方用的"必须由目标签名判定，所以两个都给出；高 64 位留 raw hex 供 vector/struct 参考。
      · **顺手修的旧 bug**：事件序列化把格式串拆成了**多个 `snprintf` 实参**（相邻字面量才拼接，逗号分隔就成了实参）→ `hookId` 打印成字符串指针低 32 位、JSON 在 82 字节处被截断。现在统一走 `adh_json_append()`（按 cap 夹紧，snprintf 的 would-be 长度不再把 offset 推出缓冲区、不再下溢 size_t），缓冲 3072 字节，写满显式报截断。
      · **评审后加固（同日）**：① P1 —— FP 返回值原来落在一个**全局变量**里（写全局与读全局之间无同步），两条并发 `native_call` 会互相串值；现在 `adh_fp_call` 多收一个出参指针（x3 先存栈，因为 x3 是 caller-saved），结果写进**调用方自己的槽**。② 事件 id 不再兜底编造：槽位没发布过 id 时不发事件（编一个 Host 从未签发过的 id = 骗人）；reactivation 分支补上 `g_native_hook_slot_ids` 同步，否则 status 报新 id、事件还带旧 id。③ JSON 真被写满时改发 `{"hookId":N,"truncated":true}`（半截对象不是 JSON，daemon 解不开），不再把截断内容推给 capture 环。④ 参数解析全面 fail-loud：`strtod/strtoull` 查 `errno==ERANGE`、`endp==t` 零消耗、`f:` 超 float 范围（含 `f:nan`）直接拒绝、`1,,2` 这类空参数报错（以前静默跳过 → 后面所有参数错位一个寄存器）、args 回显超 279 字节先拒再调。⑤ 返回值精度 `%.9g` → `%.17g`（double 精确往返；`%.9g` 会把 102.00000149011612 报成 102.000001，正好把 float32 取整的证据抹掉）。
      · 沙盒新增 `adh_fp_target(float,double,int)=a*b+c`（double 返回）、`adh_fp_target_f`（float 返回）、以及三个**不能互相抵消**的探针：`adh_fp_order_fd` / `adh_fp_order_df`（a*100+b*10+c，两种类型顺序都必须给 291.0，才能证明"第一个 FP 参数"真的是第一个 FP 寄存器）、`adh_fp_mix`（0.1f*1000+2，钉住 `f:` 真的按 float32 取整）、`adh_fp_nan`（确定性 NaN 返回）。
      · 真机 `aa165071` PASS（`tools/verify_v68_native_fp_args.sh`）：`f:2.5,d:4,1 -> fpResult 0x4026000000000000 / fpResultDouble 11`、`f:1.5,d:2,3 -> 6`、float 返回 `0x41300000 / fpResultFloat 11`、两种类型顺序都 -> `0x4072300000000000 / 291`、`f:0.1` 宽度探针 -> `102.00000149011612`、NaN 返回 -> `fpResultDouble:null`、整数路径 `20,22 -> 84` 不回归；六条 fail-loud：未知类型 `x:1.5`、空参数 `1,,2`、整数/浮点越界、第 9 个整型/浮点参数（各报 "at most 8"）。同一函数的 inline hook 事件同时含 `"x0":"0x1"` 与 `"s0":"2.5"`/`"d1":"4"`；soft unhook 后调用仍返回 11 且**不再产生新事件**（unhook 前后事件数都是 1），进程存活。
      · 已知边界：hook 侧只**读** FP 参数（改参仍只支持 x0-x7 整数槽，FP 参数改写未做）；128-bit / vector / 结构体**返回值**（q0 高 lane、x0+x1 双寄存器返回）与栈上传参一律**不解析且无提示**，调用方需按签名自行判定；FP 参数上限 8（v68 已验到第 9 个被拒），且没有"栈上第 9 个参数"这种回退。
- [x] **v4.30 load-time `JNI_OnLoad` 拦截（2026-09-18，真机 PASS）**：目标里点名的 `jni_onload` 能力补上"加载时"这一半 —— 以前只能对**已加载**模块 list/hook/call，现在能在模块刚映射、VM 还没调用之前就把 `JNI_OnLoad` 挂上，甚至**替换**这次调用。
      · 实现：新增 `runtime/dlopen_watch.c`，按 `android_dlopen_ext` → `dlopen` → `__loader_android_dlopen_ext` 顺序解析并 inline hook **一个** dlopen 入口（懒安装：只有 `jni_onload watch` 才装，默认足迹不变）。wrapper 先跑原 dlopen，再把 (path, handle) 交给 `jni_onload` 的 watch：匹配模块名 → `dlsym("JNI_OnLoad")` → 在 VM 调用之前装 inline hook → 返回原 handle。事件带 `phase:"load"`，可带 `skipOriginal/returnValue` 把这次 load-time 调用替换掉。
      · 顺手把 `jni_onload unhook` 从"软卸载"改成**真还原**（快照 24 字节原始序言 → `adh_patch_code_bytes` 写回），否则上一个 watch 的 patch 会一直占着 onload 槽位、挡住下一次 watch；被还原过的地址再 hook 会 fail-loud 提示重启目标（Dobby 状态陈旧，与 native hard unhook 同一套策略）。watch 失败（无 JNI_OnLoad / 槽位忙）会记录 `g_watch_error`、在 status 里回显，并发一条 `phase:"watch-miss"` 事件，不静默。
      · 真机 `aa165071` PASS（`tools/verify_v67_jni_onload_watch.sh`）：watch `libadhplugin_a.so` → 触发 `System.loadLibrary` → 断言事件 `{"module":"libadhplugin_a.so","retval":65542,"phase":"load","skipped":false}` 且插件自身计数=1；unhook 后 watch `libadhplugin_b.so` 带 `skipOriginal+returnValue` → 事件 `"skipped":true`、插件计数=**0**（真被替换）、`System.loadLibrary` 仍成功；unwatch 生效、进程存活。
      · 同批 v57/v54/v58/v62/v64/v65/v66/v46/v05 共 10 项全 PASS。
      · 已知边界：同时只保留一个 JNI_OnLoad hook 槽（要换模块先 unhook）；dlopen 入口只 hook 一个（够覆盖 VM 的加载路径）；不走 dlopen 的（如自实现 linker/直接 mmap 加载）不在覆盖范围。
- [x] **v4.29 native hard unhook（真·卸载）+ 足迹核算（2026-09-18，真机 PASS）**：软卸载会把 Dobby stub/trampoline 一直留在目标里（可被扫描/指纹），本轮补上按需的真卸载。
      · 实现：装 hook 时先 **快照 24 字节原始序言**，并**校验补丁真的落到入口**（比较前 4 字节；Dobby 说成功但字节没变就直接报错，不再"成功但其实没挂上"）。`unhook {hard:true}` 在静默窗口（命中计数连续 ~25ms 不动）后用 `adh_patch_code_bytes()`（mprotect→memcpy→icache flush→恢复权限）**把原始字节写回**并释放槽位。
      · 为什么不用 `DobbyDestroy`：真机复现了"DobbyDestroy 之后再 DobbyHook → 崩在 Dobby 自己的 memcpy（SIGSEGV：trampoline 池已释放但分配器仍引用）"。因此 hard unhook 改为**自己回写原始字节、完全不碰 Dobby 池**：代码恢复、补丁消失、对新地址装 hook 依然正常；代价是**同一地址在本进程内不能再 hook**（Dobby 状态陈旧）——这点 fail-loud 明确拒绝并提示重启目标，不装作支持。
      · 真机 `aa165071` PASS（`tools/verify_v66_native_hard_unhook.sh`）：`adh_trace_target` 与 `adh_add_target` 各走一轮 install→命中→hard unhook→行为恢复（30 / 84），status `count=0 patched=0`；同地址再 hook 返回 "target was hard-unhooked earlier in this process…"；`rwx` 全程 0，anon-exec 足迹 0→2 且**两轮不增长**（Dobby 池复用而非每 hook 泄漏）；进程存活。
      · 顺带：`got_enum` 现在回报 `packedSize`；同批 v46/v47/v49/v55/v56/v61/v04/v05/v26 共 10 项全 PASS。
      · 已知边界：hard unhook 后同地址需重启进程才能再 hook；Dobby 池页（r-x，2 页）在进程生命周期内保留；未做线程挂起的绝对静止（静默窗口 + 补丁只经 stub 触达，残余竞态已记录）。
- [x] **v4.28 java_hook 完整性：构造器 hook + 继承成员解析（2026-09-18，真机 PASS）**：把 Xposed 类框架的两块基本能力补齐。
      · **构造器**：`java_hook {method:"<init>", params:"int"}` —— 桥接层新增 `isConstructor`：回调收到的 `args[0]` 是"正在构造的对象"，原构造器通过 LSPlant 给的 backup 在该 receiver 上执行，返回值必须仍是这个对象（`new` 的结果），否则目标会拿到 null。真机证据：`lastArg="21"`（实参可见）、`lastReturn="…JniCtorTarget@…"`（对象正常）、`NewObjectA(21)` 之后 `totalValue()==42` 不变。构造器**不允许** `skipOriginal`/`returnValue`（装不上就明确报错，不装作支持）。
      · **继承成员**：`java_hook{className:"JniDerived", method:"baseValue"}` 现在会沿 `getSuperclass()` 链解析（最多 10 层），签名里报**声明类**（`com.adh.sandbox.JniBase.baseValue()`），因为 LSPlant hook 的是 ArtMethod，作用域本来就是声明类 + 其子类。
      · 过程中修掉一个自己引入的错：重写成员扫描时漏了"方法名比对"，只剩参数类型匹配 —— 结果 hook `JniDerived.baseValue` 实际装到了同参数的 `derivedValue` 上（`hits=0` 暴露）。现在名字 + 参数类型双条件匹配；构造器路径按参数类型匹配（构造器无名字）。
      · 真机 `aa165071` PASS（`tools/verify_v65_java_ctor_inherited.sh`）；同批 v42/v43/v44/v45/v52/v53/v58/v64 共 9 项全 PASS（同一桥接层，参数改写/返回值覆盖未受影响）。
      · 已知边界：接口 default 方法未走接口链解析；构造器 hook 不支持"跳过原构造器"（语言语义上也没有意义）。
- [x] **v4.27 Call* 全族覆盖 + 通配安装 + 抑制语义修复（2026-09-18，真机 PASS）**：槽位从 40 扩到 **76**（13 固定 + 21 族 × 3 形态）——补齐 `CallBoolean/Byte/Char/Short/Int/Long/Float/Double`（实例）+ `CallStatic*` 同名族（含 static Boolean/Long）+ `NewObject`，每族 varargs / V / A 全装；新增**通配安装**：`function:"*"`/`"all"` 或前缀式（如 `"CallIntMethod*"`、`"Call*"`）一次装/卸多个槽位，回包给 `applied`/`failed`，不会静默跳过。
      · **修掉一个会"隐藏目标行为"的严重缺陷**：原先的 `__thread` reentry 标志把"目标自己的那次调用"也罩住了 —— 于是目标在 hooked 调用内部再发起的 JNI 调用（Java→JNI 回调、反射调用链）全部被当作"我们自己的递归"静默吞掉。全量安装时 `java_call` 本身就经由 `CallStaticIntMethodV` 进入，导致探针里所有调用都不再被记录（hits=0、无事件）。现在标志改名为 `g_env_hook_in_ours` 且**只包住 ADH 自己的 instrumentation JNI 调用**（成员名反查、类名、数组长度），目标调用一律在标志清零状态下执行；varargs 包装改为转发到**保存的 V 原函数**而不是实时表，因此不再需要靠标志去重。
      · 顺带给状态加了 `last`（每槽位最近一次事件文本，有界 192B 快照）：目标流量大时捕获环会被冲掉（实测守护进程 1000 条环里 990 条是 app 自己的 `FindClass`/`GetStaticMethodID`），ring-based 断言会变成竞态；`hits` + `last` 则不受影响。verify 脚本因此改成"命中数 + last 标签"双证据。
      · ABI 守卫再次发挥作用：新增 19 族时它按 JNI 规范逐槽校验偏移（`env_hook_spec_index`），通配安装 76 个槽位 `applied=76 failed=0`；任何索引漂移都会 fail-loud 而不是 patch 到相邻函数。
      · 真机 `aa165071` PASS（`tools/verify_v64_jni_call_types.sh`）：`*` 装 76 槽 → `Detection.jniCallTypesProbe()`（实例 A 形态 + 静态 varargs 形态各 7 种返回类型）→ 14 个族全部命中且 `last` 里都有解析后的 `com.adh.sandbox.JniCallTarget#flag()Z` 一类标签，探针位掩码 `0xAD7F7F` 在装前/装后/卸后一致 → `*` 卸载后 76 槽全部还原（slotValue==original）、RELRO 仍 `r--`、进程存活。同批 v54/v58/v59/v60/v62/v63/v43/v46/v05/v26 共 11 项全 PASS。
      · 已知边界：`CallNonvirtual*`（super 调用）与 `GetPrimitiveArrayCritical` 之外的其它基本类型数组族未接入；varargs 形态的 hook 只覆盖走 varargs 入口的调用者（C 代码），C++ 调用者走 V —— 要全覆盖就装整族（通配一条命令即可）。
- [x] **v4.26 byte[] 原地回写 / critical 数组 hook（2026-09-18，真机 PASS）**：补上评审指出的盲区 —— 之前只有 `SetByteArrayRegion` + `GetByteArrayElements`，看不到"取指针→原地解密→回写"这条最常见的落点。新增 4 个槽位：`ReleaseByteArrayElements`(192)、`GetByteArrayRegion`(200)、`GetPrimitiveArrayCritical`(222)、`ReleasePrimitiveArrayCritical`(223)，共 40 个槽位。
      · `ReleaseByteArrayElements` 在 original 之前预览调用方缓冲区（mode 0 / JNI_COMMIT 才回写，JNI_ABORT 明确标注 `(no copyback)`），事件形如 `len=8 mode=0 writeback hex=a0a1a2a3a4a5a6a7`；`GetByteArrayRegion` 在调用后预览读出的数据。
      · critical 数组有硬约束：Get/ReleasePrimitiveArrayCritical 之间**不允许再调 JNI**（否则可能死锁/被 CheckJNI 拦）。因此长度在 Get 时用 `GetArrayLength` 取好，按**返回的缓冲区指针**存进 8 槽 stash，Release 时按指针取走并清空（consume-on-release，避免句柄回收后误用旧长度），全程不在 critical 区内做 JNI 调用。
      · 真机 `aa165071` PASS（`tools/verify_v63_jni_array_writeback.sh`）：装 6 个槽位 → 触发 `Detection.jniArrayWriteProbe()`（0x01..08 → Get/ReleaseByteArrayElements 改写成 0xA0..A7 → 读回验证 → critical 区改写成 0xB0..B7 → 再读回）→ 断言 7 条精确事件（含两组 writeback hex）与探针位掩码 `0xAD4003` → uninstall 后表项还原、进程存活。同批 v54/v58/v59/v60/v62/v05/v26 复跑 PASS。
      · 已知边界：`GetPrimitiveArrayCritical` 的长度只在其 Get→Release 配对内有；未覆盖 `GetBoolean/Char/Short/Int/Long/Float/DoubleArrayElements` 等其它基本类型数组（同一机制可继续加）。
- [x] **v4.24 JNIEnv `Call*Method` / `NewObject` 全形式 hook（2026-09-18，真机 PASS）**：把表槽位机制扩到调用族，共 **36 个槽位**（9 个固定 + 9 个族 × 3 种入口）：`CallObjectMethod` / `CallBooleanMethod` / `CallIntMethod` / `CallLongMethod` / `CallVoidMethod` / `CallStaticObjectMethod` / `CallStaticIntMethod` / `CallStaticVoidMethod` / `NewObject`，每族都有 **varargs / V / A** 三个入口。
      · 为什么必须三种都装：NDK `jni.h` 的 C++ `JNIEnv_` 包装是"自己组 `va_list` 再调 `...V` 入口"（`CallObjectMethod` → `functions->CallObjectMethodV`），C 代码直接调 varargs 入口，生成的代码常走 `...A` 入口 —— 只 hook 一种就会整类漏掉。varargs wrapper 通过**实时表**转发到 `...V` 入口（链上装过 V 也能正确执行，reentry 标志避免重复计数）。
      · 成员名反查：JNI 没有 `jmethodID → 名字` 的接口，新增 `runtime/jni_method_names.c` 用反射反查（遍历接收者类的继承链 → 逐个成员拼 JNI 签名 → 用 `GetMethodID/GetStaticMethodID` 拿回 candidate 与目标 mid 比对），带 **mid 键缓存**（64 条、无锁读）与**每进程扫描上限**（512 次），只在"该槽位还在发事件"的窗口内执行。事件形如 `com.x.Y#combine(Ljava/lang/String;I)Ljava/lang/String; args("ADH_CALL",7)`。
      · **ABI 自检（这轮最有价值的一步）**：新增 `env_hook_spec_index()` —— 每个槽位的 JNIEnv 表偏移必须等于 JNI 规范里 `JNINativeInterface` 的字段序号（FindClass=6、GetMethodID=33、CallObjectMethod=34…、SetByteArrayRegion=208），装 hook 前比对，不符就 fail-loud 拒绝 patch。第一次跑就抓到我自己索引表里两处错误（NewStringUTF 163→167、GetStringUTFChars 165→169），**避免了默默 patch 到相邻 JNI 函数**这种最危险的事故。
      · 真机 `aa165071` PASS（`tools/verify_v62_jni_call_hooks.sh`）：装 NewObjectA / CallObjectMethodA / CallIntMethodA / CallVoidMethod(varargs) / CallStaticObjectMethod(varargs) → 触发 `Detection.jniCallProbe()`（A 形态建对象 + 调用、varargs 形态调用实例与静态方法）→ 断言 5 条事件里都出现解析后的 `class#method(sig) args(...)` 与探针位掩码 `0xAD300F`（调用真的产生了预期结果）→ uninstall 后 hits 冻结、返回不变、`slotValue == original`、RELRO 仍 `r--`、进程存活。
      · 调试过程留档：反射反查最初把 `getReturnType/getParameterTypes` 查在 `java.lang.Class` 上（应查 member 类），抛 `NoSuchMethodError` 后又在 pending exception 下继续调 JNI → CheckJNI 直接 abort（crash report 定位）；修好后每条访问器都在 member 类上解析，且**每步都自带异常清理**，绝不在有 pending exception 时继续。
      · 已知边界：`CallNonvirtual*`、`CallByte/Char/Short/Float/Double*`、`GetPrimitiveArrayCritical`、`ReleaseByteArrayElements`、`GetByteArrayRegion` 未接入（同一机制可继续补）。
- [x] **v4.23 JNIEnv hook 评审加固（2026-09-18，真机 PASS）**：对 v4.18/v4.19 的独立评审整改（评审全文要点按 P0/P1/P2 落地）：
      · **P0 热路径**：原来只限制"发事件"的条数，类名反射 / 数组 hex / 字符串拷贝却**每次调用都做**（文件头还声称有界，属于自欺）。现在 `env_budget_left()` 作为唯一闸门：预算耗尽后每次调用只剩一次原子自增；`hits` 改为**统计每一次被拦截的调用**（成功/失败都算），不再只在"有结果"时计数，避免高频失败路径看起来 0 命中。
      · **P0 异常语义**：成员 ID wrapper 在 original 抛错后**不再做任何反射**（CheckJNI 下带 pending exception 调 JNI 会 abort），改为发一条不带类名的事件（`?#name+sig`，`ok:false`）；`adh_jni_class_name()` 的 park/rethrow 保留作为纵深防御，并补掉 PushLocalFrame 失败路径的 local ref 泄漏。
      · **P1 验收强度**：状态新增 `slotValue`（读的是**表项实时值**，不是缓存）与 `original`；v58/v59 现在断言"安装后 slotValue != original、卸载后 slotValue == original"，证明表项真的被改写并写回，而不是只翻了个 active 标志；`tablePerms` 断言保留。
      · **P2 诚实性**：`status` 在 attach 失败时改为 fail-loud（ok:false + "no JavaVM/JNIEnv"），不再用陈旧 table 报成功；事件 JSON 增加 `ok` 字段区分"查找成功/失败"；MCP 工具描述补全 9 个入口（此前 enum 与描述漂移）。
      · 评审提出但**本次未做**（记录待办）：`ReleaseByteArrayElements` / `GetByteArrayRegion` 未覆盖（in-place 解密回写路径看不到最终明文）；verify 脚本的"能力缺失 → SKIP"在 `verify_all` 里仍计 PASS（项目既有约定，需单独收紧）；生产库上 `GetFieldID` 复用 jmethodID typedef 的 UB 只是规范层面（arm64 ABI 一致）。
      · 真机 `aa165071` 复跑 PASS：v58 / v59 / v60 / v54 / v43。
- [x] **v4.22 GOT hook 两处回归修复（2026-09-18，真机 PASS）**：全量 `verify_all.sh` 跑出 **72 pass / 4 fail**，其中两条是"已文档化能力其实已经悄悄失效"的回归（另两条 v36/v41 是设备侧 Binder 状态，不在本次范围）：
      · **按名 GOT 替换整条失效**：`adh_got_replace_by_name*` 把 `/proc/self/maps` 的完整路径传给 `module_base_of()`，而该函数在 v2.x 加固时改成"basename 精确比较"，于是永远匹配不上 → 静默返回 0（`detect_watch` 报 `hooked:{ptrace:0,access:0,prop:0}`、`native_hook mode=got` 报 "symbol/slot not found"）。修复：`module_base_of()` 自行归一化参数（basename 或完整路径都能解析），并保留加固过的"不匹配子串"语义。
      · **APS2 packed reloc 解码器从未生效**：`DT_ANDROID_RELASZ`(0x60000012) 在 dynamic 段解析里被漏读，`find_packed_reloc_slot()` 因 `android_relasz < 4` 永远直接返回 NULL → 只在 packed 段里的 `EVP_AEAD_CTX_seal/open`、`EVP_PKEY_encrypt/decrypt` 等符号永远找不到（capture_start 报 `aead.seal=0`、`pkey.*=0`）。修复：两处 DT 循环都补上 0x60000012。
      · 可见性补强：Host 现在把 agent 的 capture_start/capture_stop 回包按会话存为 `session.captureHooks`（`/api/agents` 直接可见），"hook 到底装没装上"不再只能靠 logcat 猜；真机修复后计数为 `evp/digest/hmac/digestSign/sslWrite/sslRead=1, pkey{sign,verify,encrypt,decrypt}=1, aead{seal,open}=1, file{readChk,writeChk}=1, sys{ptrace,access,prop}=1`。
      · 新增 `tools/verify_v61_got_by_name.sh`（按名 GOT hook 全链路，回归守卫）；`verify_v26` 的 AEAD 断言改为"任一通道捕获明文 + 原生 hook 安装计数"（原生 record 会被 Java 通道去重规则吃掉，属设计行为，不是缺陷）。
      · 真机 `aa165071` 复跑 PASS：`verify_v05_detect.sh`、`verify_v26_cryptocoverage.sh`、`verify_v61_got_by_name.sh`、`verify_v04_gothook.sh`、`verify_v47_got_enum.sh`。
      · 未解决（环境，非代码）：`verify_v36_automation.sh` / `verify_v41_postflash.sh` 报 "ADH Device Daemon is unavailable" —— 模块 `/data/adb/modules/adh` 在位、`adh-device-daemon` 进程在跑、`manager.apk.sha256` 与已装 Manager 一致、Host `automation/status` 的 bridge 已连接，说明卡在 Manager→Device Daemon 的 Binder 调用，需要设备侧重启守护进程/重刷后再验。
- [x] **v4.20 JNIEnv hook 行为不变性修复 + CheckJNI 发现（2026-09-18，真机 PASS）**：修掉一个会**改变目标行为**的缺陷 —— 成员 ID wrapper 里为了拿类名要跑 `Class.getName()` 反射，而反射返回时会把调用方原本 pending 的异常清掉，等于吞掉目标的 `NoSuchMethodError` / `NoSuchFieldError`。现在 `adh_jni_class_name()` 先 `ExceptionOccurred` + `ExceptionClear` park 住调用方异常，做完自己的活再把**同一个 throwable** `Throw` 回去（自己的异常照旧清掉），失败路径也照常发事件。
      · 意外收获（真机 crash report）：沙盒 debug 包是 debuggable，Android 对它启用 **CheckJNI**，所以 `env->functions` 指向的是 CheckJNI 表，我们替换的表项 original 仍是 CheckJNI 包装 —— ART 的参数/异常检查依旧生效。同一次崩溃还确认了：**在 pending exception 下调用 GetMethodID 会被 CheckJNI 直接 abort 进程**（`JNI DETECTED ERROR IN APPLICATION`，ActivityThread 之外的线程同样致命），所以 fixture 只覆盖合法子集（失败的查找本身是合法的：返回 NULL + 抛异常）。
      · 真机 `aa165071` PASS（`tools/verify_v60_jni_env_preserve.sh`）：`Detection.jniEnvExceptionProbe()` 在「未安装 hook / 安装 4 个成员 ID hook / uninstall 之后」三种状态下返回值均为 `5`（bit1 = NoSuchMethodError 仍 pending，bit4 = NoSuchFieldError 仍 pending），且两次失败查找都被捕获成 JNI_ENV 事件；同批 v58/v59/v54/v43 复跑 PASS。
      · 测试方法的教训：这类"hook 是否改变目标行为"的检查必须做 **A/B 对照**（装/不装/卸后同值），只断言"事件出现"无法发现异常被吞。
- [x] **v4.19 JNIEnv 字段 / 字节数组表项 hook（2026-09-18，真机 PASS）**：把 v4.18 的表槽位机制扩到 4 个新入口：`GetFieldID` / `GetStaticFieldID` / `GetByteArrayElements` / `SetByteArrayRegion`（共 9 个槽位）。
      · 事件信息量提升：成员 ID 事件现在带所属类（`<class>#<name><sig>`，如 `com.adh.sandbox.Detection#load()V`、字段 `…JniEnvHolder#marker:I`）—— 类名解析走 `Class.getName()`，只在"该槽位仍在发事件"的窗口内做（有界），且嵌套 JNI 调用被 reentry 标志挡住，不会自我递归。新增共享 helper `adh_jni_class_name()`（`runtime/jni.c`），`jni_hooks.c` 里原先私有的一份改为复用。
      · 数组事件带长度 + 前 24 字节 hex 摘要（`SetByteArrayRegion` 还带 start），这类"跨 JNI 边界写入 byte[]"的数据正是脱壳/解密场景最关心的明文落点。
      · 真机 `aa165071` PASS（`tools/verify_v59_jni_env_arrays.sh`）：4 个槽位分别 install（各自独立 entry）→ 触发沙盒新增的 `Detection.jniEnvArrayProbe()`（一次调用完成 GetFieldID / GetStaticFieldID / SetByteArrayRegion(8B) / GetByteArrayElements）→ 断言 4 条精确 JNI_ENV 事件与 hits → 逐个 uninstall 后 hits 冻结、探针返回值 0xAD1008 不变、`tablePerms` 仍为 `r--p`、进程存活。同批 v58（成员 ID 改用新格式后）/v54/v43 复跑 PASS。
      · 已知边界：`Call*Method` 系列未接入（可变参数入口需要转发 varargs，方案待定）；仍未覆盖 GetByteArrayRegion / ReleaseByteArrayElements 等。
- [x] **v4.18 JNIEnv 函数表逐项 hook（2026-09-18，真机 PASS）**：新增 agent `jni_env_hook`、HTTP `POST /api/jni/env_hook`、MCP `jni_env_hook`（install/uninstall/status），覆盖 5 个 JNIEnv 入口：`FindClass` / `GetMethodID` / `GetStaticMethodID` / `NewStringUTF` / `GetStringUTFChars`。
      · 实现方式与前面的 native/Java hook 不同：**不 patch 函数体，而是替换 JNIEnv 函数表里的槽位指针**（C 里 `JNIEnv*` 本身就是函数表指针，同一 VM 的所有 env 共用这张表）。因此没有 trampoline、没有 patch 窗口、uninstall 就是把原指针写回；ART 内部 C++ 直调的路径不经过该表，本能力看的是"经由 JNIEnv 表的调用"（正是 native 库的用法）。
      · 表在 libart 的 **RELRO 段**（真机实测 `/apex/com.android.art/lib64/libart.so` offset `0xe00000`，槽位偏移与 ART `JNINativeInterface` 索引一致：FindClass `+0x30`、GetMethodID `+0x108`、GetStaticMethodID `+0x388`、NewStringUTF `+0x538`、GetStringUTFChars `+0x548`），所以新增 `adh_swap_pointer_in_ro_page()`：临时 mprotect 该页 → 对齐写入新指针 → **立即恢复原保护**；每条结果回显该页实时 perms（`tablePerms` / 每个槽位的 `perms`），把"有没有偷偷留下可写页"变成可断言信号。
      · 热路径约束：wrapper 不阻塞、不无界分配；每个槽位最多发 256 条 `JNI_ENV` 事件，之后只累加 `dropped`，且入 ring 走既有 try-lock。
      · 真机 `aa165071` PASS（`tools/verify_v58_jni_env_hook.sh`）：5 个槽位分别 install（各自独立 entry 地址）→ 触发沙盒新增的 `Detection.jniEnvProbe()`（一次调用分别经过这 5 个入口）→ 断言 5 条精确 `JNI_ENV` 事件 + hits → 逐个 uninstall 后 hits 冻结、探针返回值不变、`tablePerms` 三次采样均为 `r--p`、进程存活。同批复跑 v4.3/v4.6/v4.7/v4.14/v4.16/v4.17 全 PASS，MCP 工具数 63 -> 64。
      · 已知边界：只覆盖 5 个入口（Call* / GetFieldID / GetStaticFieldID 等待补）；CheckJNI 开启时 `env` 指向 check 表，此时 patch 的是那张表（仍能拦住 App 的 JNI 调用），但两套表不互通。
- [x] **v4.17 JNI_OnLoad 枚举 / hook / 主动调用（2026-09-18，真机 PASS）**：新增 agent `jni_onload`、HTTP `POST /api/jni/onload`、MCP `jni_onload`，覆盖 list/hook/unhook/call/status。list 通过 `dl_iterate_phdr` 收集已加载 `.so`、用 `dlsym` 找导出 `JNI_OnLoad`；hook 对真实导出地址做 inline patch；call 用真实 `JavaVM*` 手动执行；unhook 采用软卸载，再次 call 走原实现且不新增 hit。Host 将 `JNI_ONLOAD` 归入 system，`call` 必须 `confirm:true`。
      · 真机 `aa165071` PASS：列出 406 个候选、3 个含 `JNI_OnLoad`（含 `libadhdetect.so`）；hook 后手动调用返回 `JNI_VERSION_1_6`（65542），产生 `JNI_ONLOAD` 事件；软 unhook 后再次调用仍返回 65542 但 hits 不变，进程存活。`tools/verify_v57_jni_onload.sh` 覆盖全链路。
      · 明确边界：这里 hook 的是**已加载模块**的 JNI_OnLoad；真正的 load-time 拦截（dlopen 返回后、VM 调用 JNI_OnLoad 前）仍未实现，后续需要拦截 linker/`android_dlopen_ext` 或 ART LoadNativeLibrary 路径。
- [x] **LSPlant v6.4 可选静态打包（2026-09-17，构建 PASS / 设备 runtime probe 待部署）**：把历史半成品重新接回 agent，但按当前红线收敛为“显式探测、默认不初始化”。新增 `tools/fetch_lsplant.sh`（v6.4 + dex_builder + parallel_hashmap；带 ColorOS/A15 `GetMethodShorty` 反射兜底和 deopt 入口缺失容忍补丁）、`agent/src/hook/java_lsplant.{h,cpp}` C-ABI shim，以及 CMake 可选静态链接；LSPlant 复用现有 Dobby 静态 inline 后端，不新增运行时 `.so`。
      · 新增 agent 命令与 MCP 工具 `javahook_probe`，仅报告 `available/initOk/backend/version/error`；不会在 `JNI_OnLoad` 自动初始化，也不安装任何 Java hook。设备 runtime probe 脚本为 `tools/verify_v42_lsplant.sh`（未部署新 agent 前明确 SKIP，不加入全量回归）。
      · 已验证：`tools/build_agent.sh` 编译并链接 LSPlant/DexBuilder 成功（release `.so` 322,208 -> 425,752 B），`tools/verify_v26_footprint.sh` PASS（无 `.symtab`/`.debug`、仍仅 3 个动态导出、无 RWX LOAD），`daemon/test/smoke.ts` 在 LSPlant 版 daemon 上 PASS，MCP 工具数 52 -> 53；真机注入/初始化仍未验证，需显式安装/刷入新 agent 后再跑 v4.2。
- [x] **通用 `java_hook` v2：多 hook + 有界事件流（2026-09-17，build PASS / runtime pending）**：在 LSPlant 静态打包之上补齐可用动作面：`java_hook {action:hook|unhook|status, id?, className, method, params}`，`params` 为逗号分隔的参数类型（空 = 无参）。目标类经 app ClassLoader 加载，方法用 `getDeclaredMethods` 按名称+参数类型精确匹配；agent 仍不硬编码任何 sandbox/目标类名。
      · 固定 helper `AdhJavaHookBridge`（约 1.9 KB DEX）新增 `hookId` 和 `nativeReport`：每次回调通过 LSPlant 返回的 backup `Method.invoke(null, args)` 调用原始方法，记录 `hits/lastArg/lastReturn/lastError`，并把一条 `JAVA_HOOK` 事件推入现有 capture ring（有界、复用 WS-C 记账，不新增无界队列）。Java 源码、dex 和 C 数组头均有生成器 `tools/build_java_hook_bridge.sh`。
      · 最多 16 个并发 hook，id 稳定；`status` 返回 `hooks[]`，`id=0` 可 unhook 全部，指定 id 可卸载单个；Host 侧 HTTP `POST /api/java/hook` 与 MCP `java_hook` 均支持 `id`。`JAVA_HOOK` 在 Host 侧归入 system 捕获，显示为 `Java Hook / 方法调用`，`phone_wait` 可用 `captureCategory:"system"` + `captureContains` 等待。
      · 沙盒确定性验收靶子 `com.adh.sandbox.HookProbe.ping(String)` + 显式 `HookProbeReceiver` 广播触发器；`tools/verify_v43_javahook.sh` 覆盖 install → broadcast 触发 → 原始返回值 → 每 hook hits/lastArg/lastReturn → `JAVA_HOOK` 事件入 capture → unhook；`tools/verify_v42_lsplant.sh` 覆盖 probe + status。两者在未部署新 agent/sandbox APK 时明确 SKIP。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 616,784 -> 624,264 B）；`dexdump` 检查 helper 含 `nativeReport`/`hookId`/`callback`；`tools/verify_v26_footprint.sh` PASS；daemon `node --check`、30/30 automation tests、沙盒 `:app:assembleDebug`、独立 smoke（54 tools）均 PASS。真机 hook 安装/事件回放仍未验证，需部署新 agent/sandbox 后执行 v4.2/v4.3。
- [x] **Java 类/成员枚举（2026-09-17，build PASS / runtime pending）**：新增只读反射枚举面，补齐“枚举类、枚举成员、普通/重载方法”的基础能力。Agent 命令与 Host 入口：`java_enum {className}`、HTTP `POST /api/java/enum`、MCP `java_enum`；MCP 工具数 54 -> 55。
      · 输出类名、superclass、interfaces、classLoader、interface/enum 标记，以及 constructors / methods / fields；每项含 modifiers、synthetic（方法额外含 bridge），方法含返回类型和参数类型列表，能直接区分同名重载。成员上限 500，超限返回 `truncated:true`，避免大类把响应撑爆；不做索引/解析，重分析仍在 Host。
      · 沙盒 `HookProbe` 增加 `marker` 字段与 `ping(String,Int)` 重载，`tools/verify_v44_java_enum.sh` 断言能看到两个 `ping` 重载和字段；未部署新 agent 时明确 SKIP，不加入全量回归。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 624,264 -> 637,248 B），静态字符串含 `java_enum/superclass/constructors/classLoader`，`tools/verify_v26_footprint.sh` PASS，daemon `node --check` / 30 项 automation tests / 独立 smoke（55 tools）均 PASS；真机枚举仍未执行。
- [x] **Java 主动调用 `java_call`（2026-09-18，build PASS / runtime pending）**：在枚举能力之上加入反射调用面：`java_call {className, method, params, field?, args[]}`、HTTP `POST /api/java/call`、MCP `java_call`；MCP 工具数 55 -> 56。
      · 支持 static 方法和 instance 方法（instance 用 `field` 指向持有 receiver 的静态字段）；`params` 精确匹配重载，`args` 支持 JSON string / number / boolean / null，按目标参数类型装箱；异常、参数数量不匹配、找不到方法均 fail-loud，不做静默兜底。
      · 沙盒复用 `HookProbe.ping(String)` 与新增的 `ping(String,Int)` 重载；`tools/verify_v45_java_call.sh` 分别调用两个重载并断言原始返回值；未部署新 agent 时明确 SKIP。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 637,248 -> 662,024 B），静态字符串含 `java_call/argument count mismatch/receiver field not found`，`tools/verify_v26_footprint.sh` PASS，daemon `node --check` / 30 项 automation tests / 独立 smoke（56 tools）均 PASS；真机主动调用仍未执行。
- [x] **Native hook 统一管理（2026-09-18，build PASS / runtime pending）**：新增 agent 命令 `native_hook`、HTTP `POST /api/native/hook`、MCP `native_hook`；MCP 工具数 56 -> 57。支持 `got`（module+symbol）和 `inline`（module+symbol 或绝对 addr）两种安装方式，最多 16 个并发 hook，`unhook id` / `id=0` 全部卸载，`status` 返回 mode、module、symbol、address、original/replacement 与 hits。
      · arm64 固定 16 个 naked stub，每次命中记录 x0-x8/x18（同时保存/恢复 q0-q7，避免破坏浮点参数），并把 `NATIVE_HOOK` 事件推入有界 capture ring；Host 显示为 `Native Hook / 函数调用`。GOT 模式用现有 GOT slot 替换，inline 模式复用 Dobby 后端；不做静默兜底。
      · 沙盒新增 `Detection.nativeHookProbe()` → `adh_trace_target()` 与 `NativeHookProbeReceiver` 广播触发器；`tools/verify_v46_native_hook.sh` 覆盖 inline install → JNI 触发 → hits/寄存器事件 → unhook，未部署新 agent/sandbox 时明确 SKIP。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 662,024 -> 671,216 B），静态字符串含 `native_hook/NATIVE_HOOK`，`tools/verify_v26_footprint.sh` PASS，daemon `node --check` / 30 项 automation tests / 独立 smoke（57 tools）均 PASS；真机 native hook 触发仍未执行。
- [x] **独立评审后的 P0/P1 修复（2026-09-18，build PASS / runtime pending）**：修复 review 发现的两个 P0：① `sendCmd` 的领域参数会覆盖协议 `id`，导致 hook 命令实际执行但 Host 永远超时；现在协议字段最后展开，且领域序号统一改名 `hookId`。② `AdhJavaHookBridge.callback` 对实例方法漏传 receiver；现在按 LSPlant 契约取 `args[0]` 作 receiver、其余参数作为实参，并新增 Kotlin object 实例方法 + `INSTANCE` 静态 receiver 的 v4.3 覆盖。
      · 稳定性修复：native slot 卸载后永久退役、不再清空 original、事件使用真实 hookId，消除 in-flight stub 跳空/跳错函数的 race；hook status 改为 64KB 动态缓冲；v4.4–v4.6 不再把 `timeout` 当旧 payload 而误 SKIP；Java hook 卸载后保留 bridge/backup global refs 并退役 slot，避免 LSPlant `UnHook` 非原子造成 UAF；`java_call` 字段访问异常显式清理并报告，加入 local-frame 边界；LSPlant 生成的 class/source/field 名改为非 LSP 默认命名。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 673,664 B）、`tools/verify_v26_footprint.sh` PASS、daemon `node --check` / 30 项 automation tests / 独立 smoke（57 tools）均 PASS；v4.2–v4.6 仍未真机部署，保持 pending。
- [x] **GOT 表枚举 + 导入符号 original 回退（2026-09-18，build PASS / runtime pending）**：新增 `got_enum {module, filter?}`、HTTP `POST /api/native/got_enum`、MCP `got_enum`；MCP 工具数 57 -> 58。解析内存 ELF 的 `DT_JMPREL`/`DT_RELA`，输出每项 `slot/symbol/value/type`，默认最多 4096 项并标记 `truncated`；packed `DT_ANDROID_RELA` 暂显式标记 `packedUnsupported:true`，不假装完整。
      · Native GOT hook 现在优先读取 relocation slot 的当前 resolved value 作为 original，因此 `open/access/ptrace` 这类导入符号不再因“本模块未定义该符号”而失败；模块内定义符号仍回退到 `adh_resolve_sym`。
      · 沙盒新增 `tools/verify_v47_got_enum.sh`，枚举 `libadhdetect.so` 并断言能看到 `ptrace/access/__system_property_get`；未部署新 agent 时明确 SKIP。
      · 已验证：`tools/build_agent.sh` 通过（release `.so` 673,664 -> 675,744 B），`tools/verify_v26_footprint.sh` PASS，daemon `node --check` / 30 项 automation tests / 静态工具盘点（58 tools）均 PASS；真机 GOT 枚举仍未执行。
- [x] **模块 X 可选手机自动化（2026-09-16，真机 PASS）**：默认关闭的 AI 手机控制面已落地 —— Host `automation.ts` 通过 loopback TCP 8763 + `adb reverse` 接收 Manager 的 AccessibilityService 客户端；MCP 新增只读 `automation_status`、`phone_observe`（控件树优先，树为空/非语义时 JPEG 截图兜底）、`phone_find`（紧凑选择器查询）、`phone_wait`（出现/消失等待 + 虚拟列表 scroll-until-found）、`phone_act`（selector/ref 优先，归一化坐标兜底；tap/long_press/swipe/scroll/set_text/global）、`phone_app`（open/stop/restart）。关闭时 `phone_*` 从 `tools/list` 隐藏，设备侧独立执行包名 allowlist，不复用注入 scope，不提供任意 shell。继续打磨：`phone_find`、selector action、`phone_wait`（activePackage/出现消失/scroll-until-found）、`interactiveOnly` 与 bounded tree、全屏坐标修正、扩展 global actions；Device Daemon 协议 v6 增加 root `open`（旧 daemon 自动回退），需随下一次模块构建部署。
      · 真机验收：OnePlus PGP110 / Android 15 / serial `aa165071`，`tools/verify_v36_automation.sh` PASS —— 16–17 个可用节点、`phone_find` 命中、selector/ref 点击切换标签、`phone_wait` 命中、JPEG 兜底约 52 KB、归一化坐标点击与滑动；另用 MCP 实测 `phone_app restart com.adh.sandbox`、ColorOS 跨应用确认框的 `phone_wait` + selector 点击，以及 LSPosed 30 模块虚拟列表 6 次 scroll-until-found。新增 `daemon/test/automation.test.ts` 覆盖桥协议/超时/设置边界。
- [x] **自动化稳定性与可部署 bundle（2026-09-17）**：修复全量回归中 v3.6 偶发的 observe 超时 —— 根因是命令处理占住 bridge socket 线程，已把命令执行与读取解耦、增加 12s 卡死看门狗和 stale node 容错；重跑 `verify_all.sh` 为 52/52。新增 Device Daemon protocol v6 root `open`、activePackage wait、扩展 global actions；协议 v7 自动化 AccessibilityService 读取/显式启停与用户 opt-in 自动修复（`/data/adb/adh/automation.enabled`）；协议 v8 root 屏幕状态/唤醒/非安全锁屏解除。root CLI 已在真机验证：enable 写入 marker+服务；模拟系统移除服务后 `--automation-ensure` 自动修复；disable 删除 marker+服务后 ensure 不会擅自重开；`--device-status`、`--device-wake`、`--device-dismiss-keyguard` 均 PASS，bridge 能重连。另新增结构化 `phone_task` 任务执行器和 16-snapshot 保留策略；v3.6 真机验收包含 3-step task 与 stale-ref 回归，最终全量 `verify_all.sh` 为 52/52（v3.6 已提前隔离执行）。已构建并推送 `injector/zygisk/dist/adh-bundle-v0.3.7.zip`（sha256 `ff815abdd0985610d84fb957dfbe5f052fbcd069105a8d02ec409b95a5b824f7`）到设备 `/sdcard/adh-bundle-v0.3.7.zip`；旧包已移除，尚未刷入。
- [x] **phone_wait 进程内信号等待（2026-09-17，真机 PASS）**：AI 等手机不再只能等界面 —— `phone_wait` 新增 agent 事件与捕获过滤：`agentEvent`（精确 type）/ `agentEventContains`（事件 JSON 子串）、`captureCategory`（crypto/net/file/system）/ `captureContains`（捕获文本子串）；同类过滤 AND、事件与捕获竞速，命中即返回，纯信号等待不需要无障碍服务。匹配在 Host（新增 `daemon/src/agent_events.ts`）完成，agent `.so` 仍只做采集，目标进程不承载等待逻辑。真机暴露并修掉两个真问题：
  ① **竞态**：动作与等待是两次 MCP 调用，信号常常在两次调用之间就到达 —— `phone_observe`/`phone_find` 返回 `cursor`、`phone_act` 额外返回动作派发前的 `cursorBefore`；`phone_wait` 支持 `afterCaptureId`/`afterEventSeq` 按游标匹配（游标模式不看时间戳），无游标时用 `lookbackMs`（0..300000）回看。
  ② **明文不可检索**：捕获在存储里是 hex，preview 把非 ASCII 打成点，`ADH手动_AES_#` 这类标记永远匹配不上 —— 匹配索引与返回负载都增加 UTF-8 解码文本 `item.text`（二进制解不出 U+FFFD 就不返回）。另外 `phone_task` 的 `wait` 步超时从"静默继续"改为步骤失败（`wait_timeout`），可被 `retries`/`stopOnError` 处理。
  · 真机验收：OnePlus PGP110 / Android 15 / serial `aa165071`，`tools/verify_v36_automation.sh` PASS —— 点击沙盒「AES-CBC」后按 `cursorBefore` 等待，414ms 内命中 `AES/CBC/PKCS5Padding` 捕获且 `item.text` 为完整明文 `ADH手动_AES_#3_订单金额=99.00元`；不存在的标记 fail-loud 超时。另人工验证「点击 → 间隔 4s（模拟慢回合）→ 带游标等待」仍命中（游标不看时间戳），`lookbackMs` 回看亦命中。`daemon/test/automation.test.ts` 10/10，全量 `verify_all.sh` 52/52。
  · 验收同时覆盖 `phone_task` 的 fail-loud：一个等不到控件的 `wait` 步现在返回 `ok=false` + `failedStep=0` + `wait_timeout`，不再静默继续（真机 PASS）。
  · ColorOS 反复清理：本轮内无障碍服务被系统关掉两次（`accessibility_enabled=0`、`Enabled services:{}`，而 opt-in marker 一直在），每次都用 root CLI `--automation-ensure` 一键修复并重连 bridge —— 这正是 v0.3.7 设备侧 5s 自愈循环要覆盖的场景；未刷入 v0.3.7 前，长时间无人值守会静默失去自动化能力。已知缺口（下一个模块包之前不会自愈）：Host daemon 重启会让已注入目标失联（agent 只在 `JNI_OnLoad` 拨号一次，无重连），本轮靠 `phone_app restart` 重新拉起沙盒；无障碍 bridge 侧不受影响（设备侧自带 2s 重连）。

- [x] **phone_wait 超时诊断（2026-09-17，真机 PASS）**：按"自己操控"时踩到的坑打磨 —— 等待超时后 AI 只能再去翻 `/api/captures` 才知道"其实收到了什么"。现在信号等待超时会带回窗口内实际出现的记录摘要 `saw`（`captures`/`events` 各最多 3 条 + `totals` 计数，按游标或时间窗计算）与当时的 `cursor`，AI 可直接改写过滤条件重试。真机验收新增一条确定性检查：先点「AES-CBC」拿到 `cursorBefore`，再用一个不存在的标记等待 → 4s 超时，断言 `saw.totals.captures >= 1` 且看到的捕获里确有 AES 算法（即超时摘要不是空壳）。
  · 复现到的稳定性事实：本轮内 ColorOS 三次把已启用的无障碍服务清掉（`accessibility_enabled=0`、`Enabled services:{}`，Manager 进程仍在跑），每次都靠 root CLI `--automation-ensure` + opt-in marker 恢复。结论：**未刷入 v0.3.7 前，长时间无人值守必然掉线**；刷入后设备侧 5s 自愈循环才会兜住这类系统级清理。

- [x] **修复：回归脚本自己关掉手机自动化（2026-09-17，真机 PASS）**：全量 `verify_all.sh` 后无障碍服务总会消失，查 logcat 定位到根因 —— `tools/verify_v31_xposed.sh` 为让框架重新注入而 `su -c 'am force-stop com.adh.manager'`，而 **Android 规定 force-stop 会摘掉该包的无障碍服务**（`Force stopping com.adh.manager` → `mEnabledServices = []` → 服务条目被移除）。修法：脚本在第 4 步前记住 `enabled_accessibility_services`/`accessibility_enabled`，收尾时若发现我们的服务条目被摘掉就原样写回（真机验证：before 启用 → v31 PASS → after 仍启用，并打印还原提示）。这与 v0.3.7 的设备侧 5s 自愈互补：脚本负责自己的副作用，daemon 负责系统/OEM 的清理。
- [x] **set_text 真机不可用修复 + 系统面读取验收（2026-09-17，真机 PASS）**：按"自己找应用"的真实任务实测，暴露 `phone_act {action:'set_text', resourceId, text}` **永远选不中目标控件** —— 同一个 `text` 既被当作输入内容、又被当作隐式选择器（要求控件当前文本已等于待写入值，于是每次都 `selector_not_found`）。修法：隐式选择器按动作剔除 `text`（显式 `selector:{text:...}` 仍有效），规则抽到 `daemon/src/phone_selectors.ts` 以便单测；选择器解析加 ≤3 次 / ~500ms 有界重试，吸收动画与列表滚动的瞬时抖动。另实测并固化两条"AI 接管手机"的关键面：① **通知栏可读**（`global notifications` 后 `phone_observe` 返回 `com.android.systemui` 52 节点、44 个带文本，快捷开关与通知正文都能读）；② **启动器搜索框可写**（桌面 → 上滑 → 搜索 → `phone_find {editable:true}` 拿 resourceId → `set_text` 写入 `ADH_SET_TEXT_v1` → 再次 find 读回同值）。
  · 顺带确认的路径与限制：从桌面抽屉点击应用图标能正常拉起应用（实测微信 → `com.tencent.mm` 前台），没有跨应用限制；但 `phone_app open` 在旧 daemon（协议 5，Accessibility fallback）上会触发 ColorOS 跨应用确认框（`com.oplus.securitypermission`；不在 allowlist 时 fail-loud 报出包名），这正是刷入 v0.3.7 后 root `open` 要消除的路径。allowlist 内的系统弹窗（如 `com.android.shell` 的错误报告框）AI 能识别并点掉。
  · 验收：`daemon/test/automation.test.ts` 14/14；`tools/verify_v36_automation.sh` 真机 PASS（新增 3 项：通知栏可读、搜索框可编辑、set_text 写后读回；agent 信号等待 5 项同样通过）。

- [x] **phone_skill：把操控流程沉淀成可复用配方（2026-09-17，真机 PASS）**：目标里"AI 自己制定操控任务、驾轻就熟"缺的不是单个动作，而是**复用**——之前每轮都要重新推导"先等哪个界面、再点哪个控件"。新增 MCP `phone_skill`（save / list / run / delete）：主机侧 `adhd-data/skills.json` 保存命名配方，`run` 直接复用 `phone_task` 的执行器（同样的重试、`stopOnError`、agent 信号等待、allowlist 门槛）。安全上与 `phone_task` 同级、不多一分：步骤类型只允许 observe/find/wait/act/app/device（≤30 步）、不能嵌套 skills、无 shell；文件被篡改或损坏时丢弃条目而不是执行（单测覆盖）。
  · 真机验收：保存 `v36-crypto-tab`（等待沙盒前台 + 点"加解密"）→ list 可见 → run `ok=true` 两步全过 → 非法步骤 `shell` 被拒（`unsupported type 'shell'`）→ delete 生效；`daemon/test/automation.test.ts` 17/17。

- [x] **phone_observe mode=text：省上下文的紧凑屏幕视图（2026-09-17，真机 PASS）**：AI 操控手机时真正稀缺的是上下文 —— 同屏控件树 JSON 实测 7488B，而 `mode=text` 渲染同一棵树只要 945B（约 **8×**）。输出一行标题（前台包/分辨率/rotation/snapshot/nodes/cursor）+ 每节点一行（`[ref] Class "文本" desc=… id=… @bounds (editable/selected/disabled) actions=…`），只打印非默认状态与除 `click` 之外的动作以去噪；`snapshotId` 与 ref 保留，可直接喂给 `phone_act`（真机验证：从文本视图取 ref 点击"加解密"标签，`selected=加解密`）。
  · 实现为纯函数 `daemon/src/phone_text.ts`（单测覆盖裁剪、上限、空/异常输入、噪声剔除），host 侧渲染，设备侧不变。

- [x] **AI 自派任务实机通过 + phone_app 前台验证（2026-09-17，真机 PASS）**：本轮直接拿"打开 SukiSU Ultra／LSPosed 看装了哪些模块"当验收任务，全程只用 MCP（桌面找图标 / 应用内滚动 / 紧凑文本视图读取）。结果：SukiSU Ultra（KernelSU 模块）读到 10 项 —— AndroidDecryptHub（adh 22.2 MB，运行中）、Ksu/KSUnext/SukisuUltra 环境一键隐藏、Play Integrity Fix [INJECT]、Reqable Certificate Installer、Sunnynet、Tricky Store、TS Enhancer Extreme、爱玩机工具箱核心拓展、Vector（zygisk_vector 14.7 MB）、Zygisk Next（zygisksu 6.5 MB）；LSPosed/Vector 读到 30 个模块（0 启用）—— ADH Xposed Bridge 0.1.0、Ai助手 4.11、Ai助手 Lite·网关、AppRetention 5.2.2、BillDelete、ConfirmReceipt、DyCapture、GroupOrder、JDex2 1.6、jdgs-rpc、NormalDelete、NotifyDelete、OnlyPayLink、OrderDebug、RecycleDelete 等（分页 scroll-until-further 读取）。
- [x] **phone 输入保真：协议 v9 根注入 + “手势被吞”可观测（2026-09-17，真机 PASS）**：按“自己操控手机”实测时踩到自动化最阴的一个坑 —— **部分 Compose 界面接受 `AccessibilityService.dispatchGesture` 却根本不响应**：手势回调正常返回 completed，屏幕纹丝不动，接口却报成功。命中现场：SukiSU Ultra 与 Vector/LSPosed 管理器的底部标签（同一坐标 `adb shell input tap` 立刻生效）。修法分三层：
- [x] **允许名单不再撞墙：一键把被拒绝的包名加进来（2026-09-17，真机 PASS）**：自派任务实测「打开设置 → 搜“电池” → 进电池健康」时，ColorOS 把该页放在 **`com.oplus.battery`**（topResumedActivity 实测），被允许名单拒绝 —— AI 当场停住，只能等用户去翻设置页。现在：① 每次 `blocked_package` 拒绝都被 Host 侧 `phone_blocked.ts` 记下**包名**（内存、最多 8 条、去重计数、单调序号排序；不记页面内容）；② `GET /api/automation/status` 增加 `blocked[]`；③ Web「设置 → 手机自动化」新增「被拒绝的包名」行 + 一键添加按钮，点击写入 textarea 并保存。日志/订单等敏感内容不落盘，边界不变。
- [x] **冷启动与系统浮窗自愈 + 可复用配方（2026-09-17，真机 PASS）**：把「打开设置 → 搜电池 → 进电池健康」做成配方 `settings-battery-health` 后连续复跑，暴露两个真实缺陷：① 冷启动（force-stop 后拉起）前台切换慢，`phone_app open` 5s 窗口会把成功启动报成 `verified:false`；② ColorOS 把系统设置子页做成**占用活动窗口的浮窗**（`com.oplus.battery`），在它前面拉起别的应用会在浮窗后面落定、5s 后仍未验证。修法：open 的验证窗口放宽到 12s 并在 4s 处**有界重发一次**启动意图（`relaunched` 标注）；若前台仍是**系统包**（`com.android.*`/`com.oplus.*`/`com.coloros.*`/`com.heytap.*`/`android`），按一次返回键再重发启动并标 `dismissedBlockingPackage` —— 第三方应用永远不会被自动返回键打扰。
- [x] **bundle v0.3.9：把已验证的 daemon/manager 装进可刷包（2026-09-17，真机 PASS）**：v0.3.8 之后协议又走到 v9、Manager 增加了浮窗自愈，但 `/sdcard` 上的包还是旧的 —— 现在版本号推进到 **v0.3.9（versionCode 16）**，用 `tools/build_bundle.sh` 重新构建：Manager `0.3.9/16`、证书摘要 `970a78b5…407feb` 已编入新 daemon（不再靠手工 `-PadhManagerCertSha256`），内含 `libadh_agent.so`、`zygisk/arm64-v8a.so`、`manager.apk`（+sha256）、`daemon.apk`、`module.prop` 等 15 个文件。产物 `injector/zygisk/dist/adh-bundle-v0.3.9.zip`，SHA-256 `8da969c1ee2021cbb7f1a960508bdb025e25af58e1b238d4c4709141cb7495af`，已推送到 `/sdcard/adh-bundle-v0.3.9.zip`（本机与设备哈希一致，旧 v0.3.8 已删除）。
- [x] **浏览器 / WebView 真机操控 + changed 语义修正（2026-09-17，真机 PASS）**：把「用浏览器搜 android automation 并读结果」当验收任务，第一次跑通全链路：打开 `com.heytap.browser` → 点搜索框 → `set_text "android automation"` → 点搜索 → 等待稳定 → `mode=text` **读到百度结果页的 WebView 文本**（GitHub android-automation、魔搭 MCP server、腾讯云「常用的7种Android手机自动化测试工具」等标题+摘要），截图核对一致。
- [x] **配方多状态恢复：wait_any / onlyIf + WebView 实测（2026-09-17，真机 PASS）**：把「浏览器搜索并读结果」沉淀成参数化配方时撞到真问题 —— 应用会从**不同状态**恢复（浏览器停在首页或结果页、设置停在首页或搜索页），而 `phone_wait` 只能表达一种预期；另外配方无法表达「这个控件在就点」。补两个原语：
- [x] **IME 动作键：给「应用不理自己的提交按钮」补一条路（2026-09-17，真机 PASS）**：追查「浏览器搜索按钮点了不提交」时确认：无障碍点击与 root 注入点击都会返回 `changed:true` 但页面不跳转（该浏览器只认键盘动作键/回车）。新增 `phone_act {action:"ime", key:"search|done|go|send|next|previous"}`：对当前聚焦的可编辑控件执行 `ACTION_IME_ENTER.id`，无焦点时回退到第一个可见可编辑控件；Android 11 以下或找不到输入框时 fail-loud（`ime_action_unsupported` / `no_focused_field`）。
- [x] **桥接免 adb reverse：host 广播 LAN 地址 + 客户端端点轮换（2026-09-17，部分验证：端到端被跨网段阻塞）**：此前自动化桥只能靠 `adb reverse` 把 tcp:8763 转发到 host，拔掉数据线就彻底失联。现在：① host 在 `helloAck` 里带上自己所有 LAN 地址（实测返回 `["192.168.200.108","192.168.150.1","192.168.159.1"]`）；② 客户端维护端点列表 —— 配置地址（默认 loopback）优先，其后是 host 广播过的地址，去重并最多保留 4 个；③ **TCP 连通不等于对面是 host**（同网段别的设备也会 accept），因此连上后必须在 3s 内收到 `helloAck`，否则轮换到下一个端点；④ 成功用过的地址写进 SharedPreferences，服务重启后自动带上，所以**只要成功连过一次**，之后拔线也能自己直连；⑤ 桥默认仍只监听 loopback（`ADH_AUTOMATION_HOST` 可改），网络暴露面不变。
- [x] **Manager 首页显示真实桥接状态（2026-09-17，真机 PASS）**：重装 Manager 后截图发现首页卡片写着「手机自动化 已关闭」并隐藏桥接行，而系统里无障碍服务是启用的、bridge 也在线 —— 典型的「UI 说谎」。修三处：① `AutomationBridgeClient` 把 `connecting:/connected:/error:` 状态回传，服务写进 `AutomationStatus.bridgeState`；② 首页每 2 秒轮询该状态并在 `ON_RESUME` 重读开关（之前只在首次组合或手动刷新时读），所以从系统设置返回后立刻是真值；③ 重装/重启瞬间无障碍列表可能还没稳定，读取改为短暂重试（3 次 ×400ms），并且**只要桥接实际连着就显示桥接行**，过期开关不再能掩盖真相。展示文案区分传输：`已连接（USB/adb reverse）` / `已连接（局域网 <ip>）`。
- [x] **v0.3.9 包内容刷新到今天的 manager/daemon（2026-09-17，真机一致）**：v0.3.9 最初打的包不含今天的 Manager 修复（桥接状态显示、防说谎、LAN 记忆），且模块目录里的 manager 也比当前构建旧。现在：① 设备模块目录的 `manager.apk`（`537339ae…f417ef`）与 `daemon.apk`（`81246690…f8ae0fb`）更新为当前构建；② 重新执行 `tools/build_bundle.sh`，包内 `manager.apk`/`daemon.apk` 与模块目录**逐一哈希一致**；③ 重新推送 `/sdcard/adh-bundle-v0.3.9.zip`，本机与设备 SHA-256 均为 `08b33e2c4a7948fd4b94e5b9e7c3e035eb84a8d15202a79fc6fc49c4cf519ddd`（旧 v0.3.8 已删）。
- [x] **onlyIf 在真实任务里落地（2026-09-17，真机 PASS）**：设置从「搜索结果页」恢复时，直接点「搜索编辑框」会失败（首页才有那个控件）。实测用一条带守卫的任务绕过：`tap 搜索编辑框 {onlyIf: 搜索编辑框}` → `set_text 电池健康` → 等结果 → 点进电池健康。真机结果：守卫步返回 `skipped:true`，后续步骤继续，7 步全过，最终停在 `com.oplus.battery` 的电池健康页（智能充电保护/充电上限保护可见）。这条把「配方必须写死起始状态」的限制真正解除了一半 —— 起始状态不同也能一条任务走通。
- [x] **连续多任务演练（2026-09-17，真机 3/4 + 桥接零超时）**：用 `adhd-data/drill.mjs` 顺序跑 4 个任务，模拟「AI 连续接管」的节奏：① `settings-battery-health`（15.6s，到电池健康页）→ ② `browser-search`（5.8s，**失败**：浏览器首页没有可编辑节点，守卫步 `skipped`，`set_text` 找不到目标）→ ③ `open-sukisu-modules`（0.25s）→ ④ `settings-battery-health`（15.3s）。总计 37.0s，**bridge timeouts=0**、snapshots=14（保留上限 16 未溢出）、全程无卡死命令。
- [x] **混合连续演练 3/3 + 新配方 sukisu-module-list（2026-09-17，真机 PASS）**：为了让「连续接管」不只在系统设置里成立，新增并实测 `sukisu-module-list`（开应用 → 点底部「模块」标签〔坐标 690,2162 实测校准〕→ 等稳定 → 向下滑一屏 → 返回模块列表文本，含模块名/版本/作者）。随后跑混合序列：`settings-battery-health`(14.9s) → `sukisu-module-list`(5.8s) → `settings-battery-health`(15.6s)，**3/3 全绿**，总 36.3s，bridge timeouts=0、snapshots=14。
- [x] **设备级音量 + 修复「模块开机启动静默失败」（2026-09-17，真机 PASS）**：补上 AI 还管不了的一类设备状态 —— 音量。协议 **v10** 新增 `getVolumeJson`/`setVolume`，`phone_device` 增加 `volume_status`（music/ring/alarm/voice 四个流的当前值与最大值）与 `volume_set {stream, index}`（index 夹到该流上限，未知流明确拒绝）。真机验收：`alarm 12 → 8 → 12` 往返成功，`index=999` 夹到 `16`，`stream=bogus` 得到 `daemon rejected volume_set`，其余流（music=0/ring=0）未被触碰、测试后已复原。
- [x] **剪贴板读写（协议 v11，2026-09-17，真机 PASS）**：Android 10+ 对后台进程隐藏剪贴板，UI 工具本来完全碰不到它。现在 `phone_device` 增加 `clipboard_read` / `clipboard_write {text}`（上限 8 KiB）：无障碍服务**优先用自己的进程上下文**（用户正在交互的那个上下文，这台 ROM 上框架只认它），失败再回退到 root daemon（协议 v11 的 `getClipboardText`/`setClipboardText`）。真机验收：写入 19 字符含中文 → 读回完全一致（`source:"service"`）。根 shell 上下文在这台 ROM 上写剪贴板被框架拒绝（实测 CLI 写成功但读回为空），所以回退顺序按「service 优先」设计，这一点已记录在案。
- [x] **模拟开机流程验证（2026-09-17，真机 PASS）**：把模块 `service.sh` 部署到设备并用「杀掉所有 adh-device-daemon / 清 marker / 执行 service.sh」的方式模拟 Magisk 开机流程。结果：`service_rc=0`、`ready=1`、pid 落盘、只有一个守护进程实例，桥接恢复 online；随后复验 `volume_status`（alarm 12）、`volume_set 10 -> 10 -> 复原 12`、`phone_app open SukiSU` 全部正常。这证明上一轮修的回退链在真实启动路径上工作（此前 `--propagation` 会让开机后守护进程永不启动）。
- [x] **根输入支持长按 + 按选择器解析（协议 v12，2026-09-17，真机 PASS）**：此前长按只能走无障碍手势，而「吞手势」的应用就完全长按不了。协议 v12 增加 duration-aware 的 `injectInputTap2`，`phone_act {action:"tap", durationMs>=600}`（含 `inputMode:"root"`）会转成零距离长压；同时根输入路径现在接受 snapshotId+ref，不再强制要求原始坐标（此前 selector-only 的 root tap 会报 `input requires x and y`）。
- [x] **刷机后一键验收脚本 v4.1 + 剪贴板能力澄清（2026-09-17，真机 PASS）**：新增 `tools/verify_v41_postflash.sh`：刷机重启后直接跑，会等最多 90s 让开机脚本自己把守护进程拉起来，然后依次验证 daemon ready/pid、桥接 online、协议 v10+ 音量（读 + 写回环并复原）、剪贴板回环、根输入注入真的到达窗口；任何一步不成都会 FAIL。
- [x] **v4.1 并入全量回归（2026-09-17，57/57）**：`verify_v41_postflash.sh` 已加入 `tools/verify_all.sh` 的设备段（紧跟 v4.0）。全量重跑结果 57/57，0 skip。沙盒新增剪贴板靶子后所有既有验收仍全绿，刷机后验收也进入常规回归。
- [x] **真机刷入 + 重启：开机自启验证通过（2026-09-17，用户授权后执行，PASS）**：用户明确授权后执行了完整流程：① 刷入前校验 `/sdcard/adh-bundle-v0.3.9.zip` 哈希 `bc5fa2bfa3e5a21c7364496ef315d3abca97cd803d968dfa70db6f105e0d99cd`（与设备一致）；② 用 KernelSU 的 `ksud module install` 刷入（安装器自动校验并安装 Manager `0.3.9/16`）；③ 模块目录确认 `version=v0.3.9 / versionCode=16`、`service.sh` 含回退链；④ `adb reboot`，**41 秒**后 `sys.boot_completed=1`；⑤ **重启后未手工启动守护进程** —— 由 `service.sh` 自启，实测 `ready=1`、`device_daemon.pid=3092`、**PPID=1（init 拉起）**、单实例，模块描述自动变为「状态：运行中」，`zygisk_loaded=active`；⑥ 建立 adb reverse 后桥接自动重连 online。
- [x] **特性版本 v0.3.10（versionCode 17）：手机自动化能力包（2026-09-17，真机 PASS）**：把本轮全部手机自动化特性收进一个正式版本并 bump：模块 `version=v0.3.10 / versionCode=17`，Manager `0.3.10/17`，daemon 版本标签同步为 `0.3.10`（binder 协议独立为 v12，不受影响）。用 `tools/build_bundle.sh` 重新构建（它会自动重建 Manager → 提取签名摘要 `970a78b5…407feb` → 重建内嵌该摘要的 daemon → 重新打包 zygisk + agent），产物 `injector/zygisk/dist/adh-bundle-v0.3.10.zip`。
      · 本版包含的能力：控件树/截图双层观察、文本紧凑视图、find/wait/wait_any/onlyIf、动作含 tap/long_press/swipe/scroll/set_text(提交)/IME 动作键/global、**手势被吞时 root 输入兜底**（协议 v9）、**长按经 root 注入**（v12）、**设备级音量**（v10）、**剪贴板读写**（v11）、root `open` + 冷启动重试 + 系统浮窗自愈、通知读取（opt-in）、命名配方 + Web 技能库面板 + 保存预检、被拒绝包名一键加白、桥接脱线重连（LAN 地址记忆）。
      · 刷入验证：v0.3.9 与 v0.3.10 均在真机完成刷入 + 重启（开机自启 PASS、v4.1 六项 PASS）；v0.3.10 为同一代码基线的版本号收口（sha256 `edac47b9…79c4`），按“元数据变更不重跑全量”的约定只做定向验收，不再重复 57 项全量。
      · `tools/verify_v41_postflash.sh`：**PASS 6/6** —— 开机脚本启动守护进程、非安全锁屏解除、协议 v10+ 音量可读、音量写回环并复原、剪贴板写入→前台应用读回一致、根输入注入到达窗口。
      · 全量回归（含 v4.1）：**57/57，0 skip**；刷机后模块载荷（agent/zygisk）已更新，注入会话实测 `com.adh.sandbox` online（`entry=jni_onload`）。
      · 过程中暴露并修掉一个验收脚本缺陷：刚重启的设备停在**锁屏**（`locked:true`），keyguard 占住前台导致 App 启动落在其后 → 剪贴板检查失败。现在 `verify_v41_postflash.sh` 会先通过受认证的 daemon **解除非安全锁屏**（安全凭据永不触碰），再跑 UI 探针；已复验 6/6。
      · 另注：本轮尝试把该流程派给独立任务执行，该任务首轮模型调用即被本机代理拒绝（`CC Switch ... missing field call_id`），未接触设备，已确认状态为 systemError。
- [x] **新配方 settings-search-read：设置里搜任意关键词并读结果（2026-09-17，真机 PASS）**：参数化配方（`query`），步骤 = 打开设置 → 等前台稳定 → 有「搜索编辑框」才点（守卫）→ 等稳定 → 写入关键词 → 等稳定 → 返回结果列表文本。真机三次运行：`电池`（从搜索结果页恢复，守卫步 SKIP，读到电池模式/电池健康等）、`网络`（读到移动网络/国际上网/蓝牙网络共享）、`蓝牙`（冷启动，守卫步执行，读到蓝牙/蓝牙网络共享/管理车载蓝牙）。
      · 与 `settings-battery-health` 的分工：前者是「搜任意词看有什么」，后者是「直接进电池健康页」。两者都自带状态守卫，冷启动与恢复态都能跑。技能库现共 10 条。
      · 为验证剪贴板新增了沙盒靶子（读剪贴板按钮 + `adh_clipboard_echo`）。这次实测修正了上一轮的判断：`clipboard_write` 写进去的内容，前台应用确实能读到（写入 18 字符 hello-from-adh-剪贴板，点沙盒按钮，回显完全一致）。真正的规则是只有不在前台的进程读不到，上一轮 Manager 不在前台所以读到空。因此 `clipboard_read` 在需要读的应用处于前台时是完整可用的。
      · 影响面：`verify_v36_automation.sh` 复跑 PASS（沙盒新增控件未破坏既有断言）。
      · 真机验收：桌面上 900ms 根注入长按进入桌面编辑模式（`changed:true`，出现壁纸/小组件面板）；按选择器的 root tap 正确居中到节点。
      · v0.3.9 包再次重建（协议 v12 daemon + 长按 + 最新 manager），新 SHA-256 `bc5fa2bfa3e5a21c7364496ef315d3abca97cd803d968dfa70db6f105e0d99cd`，已推送 /sdcard（本机与设备一致），设备模块目录同步。
      · 顺带确认一个剪贴板的真实边界：读剪贴板需要读取方在前台（Android 10+ 隐私规则）。Manager 在前台时 `clipboard_write`/`clipboard_read` 走 service 上下文完全正常（`post-flash 复验 2026` 往返一致）；当前台是别的应用时，service 与 root daemon 两个上下文都读不到，这是系统限制而非实现缺陷，已记录。
      · v0.3.9 包随之重建（含 v11 daemon、剪贴板、音量、service.sh 回退链），新 SHA-256 `50413f80cd03bfa3e906130d66470f61e00f128dafb0866a5faac3b96bd58f12`，已推送 `/sdcard/adh-bundle-v0.3.9.zip`（本机与设备哈希一致）；设备模块目录的 manager/daemon 同步为该包内版本。
      · **过程中发现一个会更影响新装的 bug**：模块 `service.sh` 用 `unshare --propagation slave -m` 启动守护进程，而 toybox 与这台 ROM 的 busybox **都不接受 `--propagation`** —— 也就是说**重新刷入后开机，守护进程根本不会起来**，自动化桥会一直离线。已改为「探测式回退链」：busybox `unshare -m` 可用就用 → 否则 toybox `unshare -m` → 否则直接启动；并确认直接启动在 KernelSU/SukiSU 环境下工作正常。另一个同源坑：daemon 构建必须带 `-PadhManagerCertSha256=<manager 证书摘要>`，否则守护进程按设计 fail-fast（本轮踩到并修正）。
      · v0.3.9 包已随之重建（含 v10 daemon、音量能力、service.sh 回退链、最新 manager），新 SHA-256 `162179ef1ab184d657787f9b073502121fe1ad16c5142d6a35585f9714849fa3`，已推送 `/sdcard/adh-bundle-v0.3.9.zip`（本机与设备哈希一致）。
      · 定位过程中的一个真实教训：底部标签用截图估算的坐标（678,2244）会落到「设置」页，按无障碍节点（690,2162）才是「模块」标签 —— 这类固定 chrome 用节点坐标而不是截图估算更可靠，已写进配方描述。
      · 技能库现 9 条：`settings-battery-health`、`sukisu-module-list`、`browser-search`(有限制)、`otp-autofill`、`open-app-and-read`、`sandbox-open-tab`、`open-sukisu-modules`、`open-lsposed-modules`、`shade-read`。
      · 结论：跨应用连续操控本身稳定（含两次设置深链、一次 root open、状态切换），失败集中在浏览器首页的输入框可达性 —— 配方已记录该缺陷，后续需要「先点搜索栏再等可编辑节点」的步骤（或在首页用坐标点搜索栏）。
      · 预算视角：设置深链单次约 15s，主要开销在 `wait stable` 的稳定判定（每次 ~1.2s）与跨包页面加载；对交互式对话够用，对批量任务可考虑降低 `stableMs`。
      · 重启设备守护进程后复验：`ready=1`、bridge online、`phone_app open` / `phone_observe` / `phone_act global home` 全部正常。
      · 免线（LAN）路径仍为环境阻塞：临时在 host 上监听 `0.0.0.0:9876`，手机 `nc 192.168.200.108 9876` 实测 BLOCKED —— 与防火墙无关（三个 profile 全关），确认是**跨网段不可路由**，不是代码问题。
      · 真机验收：连续三次「安装 → force-stop → 启动」后截图，卡片稳定显示「已开启」+「桥接：已连接（USB/adb reverse）」，与 `automation_status` 一致；期间 bridge 全程 online。
      · 验证：`helloAck` 实测携带三个 LAN 地址；设备经 loopback 正常连接、`phone_app`/`phone_observe`/`phone_act` 均正常。**免线路径本身在当前环境无法端到端验证**：测试机在 `192.168.1.0/24`，host 在 `192.168.200.0/24`，手机 `nc 192.168.200.108 8763` 实测 CLOSED —— 记为「环境阻塞（跨网段）」，不记为通过。
      · 真机验收：沙盒输入框 `ime/search` 成功返回 `{action:"ime",key:"search"}`；在桌面执行时明确报 `no_focused_field` 并附带当前屏幕。
      · 说明：`browser-search` 配方的提交环节仍未完全收口（该 ROM 浏览器偶发不提交，无论按钮点击、root 注入还是 IME 动作），配方不作为可靠技能；浏览器读结果的能力已用直接工具调用验证过。
      · `phone_wait_any` / `phone_task` 的 `wait_any` 步骤：多个条件任一命中即成功并回报 `condition` 下标；全部不命中时 fail-loud（`wait_any_timeout` + 最后失败原因）。实现时抓到一个真 bug：`waitPhone` 用 `{timedOut:true, matched:false}` 表达未命中而不是抛错，早先的循环会把「没命中」当成命中直接返回 —— 现在检查 `matched===true && timedOut!==true`。
      · `phone_task` 步骤级 `onlyIf`：守卫选择器不存在时该步记 `skipped:true` 而不是失败，后续步骤继续。
      · 真机验收：两条件探针（先微信、后浏览器）返回 `condition:1`；都不可命中时 `wait_any_timeout ... last=condition 1 did not match`；`onlyIf` 守卫的点击被跳过且后续 observe 正常执行。浏览器场景另用工具直接跑通「打开浏览器 → 聚焦输入 → 输入 android automation → 搜索 → 读百度结果页 WebView 文本」，截图一致。
      · 已知未竟：`browser-search` 配方的「点搜索按钮」这一步在该浏览器上不稳定（无障碍与 root 注入都偶发不触发提交），配方暂不作为可靠技能；留待后续用更稳的提交方式（IME action / 引擎选择）收口。
      · `tools/verify_all.sh` **56/56，0 skip**；MCP 工具总数 51 → **52**（新增 `phone_wait_any`）。
      · 任务暴露 `changed` 判断的两个真实缺陷并修掉：① **几何哈希误报**——SukiSU 光标闪烁这类动画让「什么都没发生」的点击报 `changed:true`，反而吞掉了它最需要的 root 兜底；签名改为「可见文本/描述的有序集合」，不再哈希几何。② **WebView 滚动漏报**——滚动只改变哪些结果行在屏内，文本节点身份没变；改为前后各采样两次（间隔 260ms、要求稳定），既压掉动画噪声又能识别真实滚动。修完复验：SukiSU 设置页点击 `changed:true`；稳定沙盒页空白处点击 `changed:false` → 自动 root 兜底且前后树完全一致；浏览器 WebView 滑动 `changed:true`（此前是 false）。
      · `tools/verify_v36_automation.sh` PASS。浏览器（`com.heytap.browser`）已加入本机允许名单（12 项），可作为 WebView 场景靶子。
      · 同时把手机对齐到该包：Manager 升到 `0.3.9/16`（同签名，数据保留），模块目录 `manager.apk`/`daemon.apk`/`manager.apk.sha256` 更新为包内同版本文件，重启守护进程后 Binder 链路恢复（bridge online）。验收：冷启动 `settings-battery-health` 配方在更新后仍然 `ok=true`，末步读到电池健康页。
      · **仍未刷入**：刷入 v0.3.9 后模块目录的 agent/zygisk 也会与当前 daemon/manager 完全一致；建议刷完重跑 `tools/verify_all.sh`（当前 56/56）。
      · 真机验收：`com.oplus.battery` 在前台时 `phone_app open com.android.settings` → `verified:true` + `dismissedBlockingPackage:"com.oplus.battery"`；冷启动 settings 实测 781ms 内 `verified:true`。配方 `settings-battery-health`（9 步，前置 `am force-stop`）连跑 **3/3 全绿**，末步读到电池健康页（智能充电保护/充电上限保护）。
      · 过程中修正一个配方反模式：从设置首页按返回会**退出设置**，导致后续选择器落到上一个应用 —— 配方改为冷启动直进，不再做多余的返回。
      · 真机验收（MCP + Web UI 双面）：把 `com.oplus.battery` 从名单移除 → `phone_act` 报 `blocked_package` → `/api/automation/status` 返回该包 → 浏览器里点「+ com.oplus.battery」→ 配置持久化、提示行自动消失 → `phone_observe` 立刻读到电池健康页（智能充电保护/充电上限保护/电池健康引擎优化）。`daemon/test/automation.test.ts` 28/28。
      · 顺带确认：中文文本输入可用（沙盒输入框 `你好，世界 中文输入测试` 截图 + 读回一致），设置搜索「电池」得到 5 条结果 —— 中文搜索/输入这条链路在真机是通的。
      · **可观测**：设备侧每次 tap/swipe 前后计算窗口文本签名（最多 60 节点，SHA-1，320ms settle），结果新增 `changed` 字段；一次性动作不再“假装成功”。
      · **自动兜底**：`phone_act` 收到 `changed:false` 时自动用同坐标走 root 注入重试一次（`inputMode:"accessibility"` 可关闭），返回 `fallback:"root"` + `injected` + 新 `changed`，调用方不需要知道哪个应用吃手势、哪个应用吃输入。
      · **根注入能力**：Device Daemon protocol **v9** 新增 `injectInputTap` / `injectInputSwipe`（绝对像素、整数夹取、固定 `/system/bin/input`，不是任意 shell），Manager 侧 `phone_act {action:"input", mode:"tap|swipe"}` 或 `inputMode:"root"` 可达。daemon 侧 `daemon.apk` 与模块目录 `manager.apk` 已更新并重启，Manager APK 已重装；`manager.apk.sha256` 同步。
      · 顺带修两个真 bug：① 手势后立即取签名会把“已发生的界面变化”读成没变（导致无谓的 root 重试并可能二次点击）→ 加 320ms settle；② 兜底结果原样覆盖 `action`（root swipe 回成 `input tap`）→ 现在保留原 `action` 语义。另：daemon 构建必须带 `-PadhManagerCertSha256=<manager 证书 SHA-256>`，否则内嵌摘要为空、守护进程 fatal（本轮真机踩到并修正）。
      · 真机验收：`phone_act` 点 SukiSU 底部“设置”`changed:true`（无障碍手势生效）；故意点空白区得到 `changed:false` → 自动 `fallback:"root"`；Vector 仓库/模块页 root 注入 tap 实测切换成功；桌面横向 swipe `changed:true`；`tools/verify_v36_automation.sh` PASS，全量 `verify_all.sh` **56/56**。
  · 过程中暴露并修掉一个会误导 AI 的真 bug：`phone_app open` 在旧 daemon（协议 5）上走 Accessibility fallback，会被 ColorOS 跨应用确认框吞掉 —— 接口回 `ok`，但前台其实是 `com.oplus.securitypermission`，AI 只能靠等待超时才察觉。现在 `open`/`restart` 打开后轮询验证前台（≤5s），成功返回 `verified:true`+`foreground`，失败返回 `verified:false`+实际前台包+提示（确认弹窗 / 加入 allowlist / 刷 v0.3.7 走 root open）。同机实测：`open org.matrix.vector.manager` → `verified:false foreground=com.oplus.securitypermission`；`restart com.adh.sandbox` → `verified:true`。
  · 技能库落地：把两条真实流程存成配方 `shade-read`（开通知栏→读→关）、`open-sukisu-modules`、`open-lsposed-modules`（`app open` + `wait activePackage` + `observe mode=text`），下轮一条 `phone_skill run` 即可复现；`open-lsposed-modules` 的失败也验证了"技能返回结构化失败而不是假装成功"。
  · 验收：`daemon/test/automation.test.ts` 20/20；`tools/verify_v36_automation.sh` 连续两轮真机 PASS（新增 `phone_app restart` 前台验证；另把"超时看到过什么"的断言改成不依赖采样窗口内的特定算法 —— 沙盒自动流会持续挤占最近样本，属测试脆弱而非实现问题）。

- [x] **agent 断线自愈重连（2026-09-17，真机 PASS）**：Host daemon 每次升级都会重启，而 agent 只在 `JNI_OnLoad` 拨号一次、连接一断线程就退出 —— 目标从此永久失联（captures/events 与 `phone_wait` 的进程内信号一起哑掉），只能重启目标 App 才恢复。改为**无限重连**：连接关闭后 1s 重拨，连不上每 500ms 重试；首个失败与每 ~20 次记一次日志（避免刷屏，也让缺 `adb reverse` 保持可见）。改动在 `agent/src/bootstrap/agent_main.c`（约 15 行，仍是一个休眠线程，不引入队列/缓冲）。
  · 验收：新增 `tools/verify_v37_agent_reconnect.sh`（已并入 `verify_all.sh`）—— 记录沙盒会话与 app pid → 杀掉 daemon 进程并**校验端口真的释放**（`taskkill //F` 在 `MSYS_NO_PATHCONV` 下会静默失败，改用 PowerShell 停进程，否则会假装通过）→ 重启 daemon → 25s 内必须出现**同一 pid** 的新会话且能应答命令。真机：before `s_17p8` pid=15066 → after `s_1837` pid=15066（同进程）`answers-command=true modules=533`。全量 `verify_all.sh` 53/53。
  · 顺带收口 set_text 验收靶子：原先借用 ColorOS 启动器搜索/模块管理器搜索框，会因页面状态与 ROM 行为漂移（一次点"搜索"进了浏览器、一次管理器首页没有搜索框而 FAIL）。改为沙盒宿主自带的 `adh_input_probe`（`sandbox-app` 状态页新增一个带 id 的 EditText），v3.6 现在稳定通过：定位 → `set_text` → 读回 `ADH_SET_TEXT_v1`。

- [x] **phone_task 步骤链式引用（2026-09-17，真机 PASS）**：编排任务时最别扭的是"上一步刚 find 到的 ref，下一步 act 用不了"——两次 MCP 调用之间 ref 会过期，AI 只能改用选择器重新解析或再观察一次。现在步骤可引用前序结果：`{{stepId}}` / `{{stepId.path.to.0}}`（整串模板保留原类型，字符串内嵌则转字符串），规则在 `daemon/src/phone_templates.ts`（纯函数 + 单测：路径/数组下标/类型保持/未知名/缺失路径）。未知名与缺失路径**必须 fail-loud**（`template_unknown_step` / `template_path_missing`），不静默替换成空值。`phone_skill` 保存的配方同样适用。
  · 真机验收：`phone_task` 三步 —— `find 状态标签` → `act tap snapshotId={{find_tab.snapshotId}} ref={{find_tab.nodes.0.ref}}` → `wait 状态`，`ok=true` 且界面确实切到选中；错误引用 `{{missing.ref}}` 返回 `ok=false` + `template_unknown_step`。全量 `verify_all.sh` 53/53。

- [x] **phone_skill 参数化配方（2026-09-17，真机 PASS）**：配方只能一次性录制就还是"死"的 —— 现在可以声明参数：`save` 时给 `params: ["tab"]`，步骤里写 `{{input.tab}}`，`run` 时用 `inputs: {tab: "脱壳"}` 传值，`defaults` 可给可选参数兜底。缺必填参数返回 `skill_missing_input` 且**一个步骤都不执行**（不拿空值去点界面）。参数名有校验（≤10 个、标识符风格、不允许重名、`input` 为保留命名空间），`list` 会回显每个配方的 `params`/`defaults` 供 AI 自描述。规则放在 `daemon/src/phone_skills.ts`（纯函数 + 单测）。
  · 真机验收：保存 `sandbox-open-tab`（params=["tab"]，步骤 = find `{{input.tab}}` → tap templated ref → wait `{{input.tab}}`）→ `run inputs={tab: "网络·文件"}` 返回 `ok=true` 且界面确实切到该标签；`run` 不带 inputs 直接 `skill_missing_input: tab`。同源检查已并入 v3.6（保存→传参运行→缺参拒绝→删除），全量 `verify_all.sh` 53/53。

- [x] **phone_wait 手势滚动（2026-09-17，真机 PASS）**：`scroll:true` 的 scroll-until-found 只会发 `ACTION_SCROLL`，而翻页器与自绘列表直接拒绝它 —— 实测启动器首页报 `active window rejected scroll forward`，AI 因此翻不动桌面找图标。现在 `scrollMode=gesture` + `axis=vertical|horizontal` 用真滑动（归一化坐标）代替，纵向 forward=上滑、横向 forward=左滑，`maxScrolls` 仍限次。几何抽到 `daemon/src/phone_gestures.ts`（纯函数 + 单测：方向断言、端点都在屏内、axis 归一化）。
  · 真机验收（v3.6 末段，guard 在启动器是否 allowlist）：`phone_wait {activePackage:com.android.launcher, textContains:__ADH_NO_SUCH_LABEL__, scroll:true, scrollMode:gesture, axis:horizontal, maxScrolls:2}` → `timedOut=true scrolls=2 pageChanged=true`（`美团外卖/钉钉/…` → `ADH Sandbox/拼多多/得物…`），即两次真滑动都被接受且桌面确实翻页；全量 `verify_all.sh` 53/53。

- [x] **动作失败自带现场（2026-09-17，真机 PASS）**：AI 操控时最费回合的不是失败本身，而是"失败了却不知道屏幕上有什么"。现在 `phone_act` 的失败（selector 未命中 / ref 过期 / 手势被窗口拒绝 / 前台被 allowlist 拦）都会附上**当前屏幕的紧凑文本视图**（复用 `mode=text` 渲染，默认 25 行）与原错误；现场本身读不到时（例如前台是不在 allowlist 的系统弹窗）附上读不到的原因，不掩盖原始错误。等待类失败此前已有 `saw` 摘要，两条路径互补。
  · 真机验收（v3.6）：`phone_act {action:tap, text:__ADH_NO_SUCH_NODE_v1__}` 的报错同时含 `selector_not_found` 与 `--- current screen ---`，且屏幕文本确为 `com.adh.sandbox` 的实时树；全量 `verify_all.sh` 53/53。

- [x] **设备侧命令硬超时：卡死不再拖垮整条通道（2026-09-17，真机 PASS + 已装 Manager）**：用真实任务做耐力测试（连跑"打开 SukiSU → 读模块 → 打开 LSPosed → 读模块清单 → 回沙盒"）时复现到**通道级故障**：设备侧 `observe` 永久卡住，之后所有命令（含 `app`）全部超时，`bridge.pending` 长期为 1，只能靠 root CLI 关/开无障碍服务恢复。根因：`rootInActiveWindow`/节点属性是到目标 App 的 binder 调用，**目标窗口被 ColorOS 冻结/无响应时会无限阻塞**；而设备侧看门狗只把 `commandBusy` 闸门放开、**从不回答主机**，于是锁住的命令把后续请求一起拖死。修法（`device/manager` 的 `AutomationBridgeClient`）：每个命令进池执行并设 **10s 硬截止**（早于主机 20–25s），超时必定回 `command_timeout` 并附"重试或重启该应用"提示、同时释放闸门；仅当 ≥3 个命令堆积才回收连接（一次卡死不该让连接白掉 2 秒）。服务 `status` 现在回显 `bridge{inFlight,timeouts,commandActive}` 便于诊断。
  · 可验证性：设备侧新增惰性故障注入 op `selftest_sleep`（只睡在桥接命令线程里，不碰窗口），主机侧新增验收/诊断入口 `POST /api/automation/selftest?op=...`（把原始 op 转发给设备，不进产品 MCP 面）。新验收 `tools/verify_v38_automation_watchdog.sh`（已并入 verify_all）：注入 20s 睡眠 → 断言 10.0s 收到 `command_timeout`、**下一条命令仍被服务**（不是超时/掉线）、设备自报 `timeouts>=1`。
  · 真机结果：故障注入 PASS（elapsed=10041ms，follow-up 得到策略级回答而非超时）；同一套耐力流程从 0/3、1/3 提升到 **3/3**；全量 `verify_all.sh` **54/54**。本轮按用户此前"可以装自编译 Manager"的口径安装了 `manager-debug.apk`（同包名同签名，v0.3.7 刷入会覆盖；安装后系统自动拉起新进程并重连 bridge）。

- [x] **输入后提交（键盘动作键）（2026-09-17，真机 PASS）**：只会"打字"不会"提交"等于搜索/登录/发消息都做不完。`phone_act {action:set_text, ...}` 新增 `submit:true`：写完 `ACTION_SET_TEXT` 后对同一控件下发 `ACTION_IME_ENTER`，成功回 `submitted:true`，控件拒绝则 fail-loud（`ime_enter_rejected` / `ime_enter_unsupported`），不假装已提交。实现细节记一笔：`ACTION_IME_ENTER` **只有 `AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER` 形式**，没有 int 常量（编译期 unresolved）。
  · 可验证性：沙盒宿主 `adh_input_probe` 旁新增 `adh_input_echo`（`OnEditorActionListener` 回显"提交回显：<文本>（action=N）"）。真机：`set_text {resourceId:adh_input_probe, text:ADH_SUBMIT_v1, submit:true}` → `submitted=true`，随后 `phone_find {textContains:提交回显}` 读到 `提交回显：ADH_SUBMIT_v1（action=0）`，即应用真的收到了键盘动作。Manager APK 随本轮改动重新编译安装（同包名同签名）。
  · 全量 `verify_all.sh` 54/54。

- [x] **phone_wait 稳定等待（settle before read/act）（2026-09-17，真机 PASS）**：AI 在"刚启动/刚切页"的界面上读树或点击，最容易拿到半渲染结果（我的耐力脚本就因此连挂两轮）。新增 `phone_wait {stable:true, stableMs:600}`：对屏幕签名采样，**连续 stableMs 不变**才返回；签名 = 前台包 + 节点类名/文本/hint/描述/边界/checked/selected/enabled，**刻意忽略 snapshotId/cursor/ref**（这些每次快照都在抖，计入会让"稳定"永远不成立）。返回里带 `signature`、`waitedMs`、`snapshotId` 与**可直接动作的 refs**（上限 60 条），所以 settle 之后不必再多一次 observe；超时返回 `stable:false` + `changedAgoMs` 说明"最后变化距今多久"。纯函数在 `daemon/src/phone_stability.ts`（单测覆盖签名稳定性与 settle 判定）。
  · 真机：沙盒上 `waitedMs=874ms` 后返回稳定快照并直接用其中的 ref 切到"加解密"标签；真实流程"重启管理器 → 等界面稳定"实测自动等 1869ms，返回快照里已含 4 个可点底部导航项（此前只能写死 sleep 1800ms）。全量 `verify_all.sh` 54/54。

- [x] **紧凑文本视图可同时返回截图 + 真机沉淀出可复用配方（2026-09-17）**：`phone_observe {mode:text, includeScreenshot:true}` 现在一次调用给两样东西 —— 可读文本（含 ref，可直接动作）+ JPEG（给 AI 看像素），真机 `text=1260B image=74500`。另外把今天摸索出来的通用流程沉淀成参数化技能 `open-app-and-read`（params: pkg/nodes）：`app restart {{input.pkg}}` → `wait activePackage` → `wait stable` → 返回可直接动作的稳定快照；用 `com.adh.sandbox`（21 节点 / 1348ms settle）与 `com.sukisu.ultra`（42 节点 / 1647ms settle）两个输入各跑一次均 `ok=true`，即一个配方服务任意已授权 App。过程中我自己的失误也被 fail-loud 拦住：`defaults` 里放了未声明的参数 → `invalid_skill_params: default for unknown param`。
  · 全量 `verify_all.sh` 54/54（v3.6 新增"文本+截图同回"检查）。技能库现有 5 条：`open-app-and-read`、`sandbox-open-tab`、`shade-read`、`open-sukisu-modules`、`open-lsposed-modules`。

- [x] **通知读取（opt-in listener）（2026-09-17，真机 PASS + 已装 Manager）**：先按"不新增权限"的思路试了无障碍事件，拿到**否定结论**：`TYPE_NOTIFICATION_STATE_CHANGED` 在 Android 15 上仍会到达（logcat 可见 `pkg=com.adh.sandbox`），但 `event.text`/`contentDescription` 为空，`parcelableData` 虽仍是 `android.app.Notification` 却只剩 `android.appInfo`/`android.reduced.images` 两个 extra，title/body 全为 null —— 平台已把通知正文从无障碍通道剥离。于是按正规做法实现 `NotificationListenerService`（`device/manager` 新增 `notify/AdhNotificationListener.kt`）：内存环形（≤30、不落盘）记录 `ts/package/title/text/key/ongoing/clearable`，Manager 首页新增"通知读取"卡片（显示授权状态 + 一键跳到系统"通知使用权"设置）；无障碍服务新增 `notifications` op 暴露环形与 `granted/connected` 状态；Host 新增 MCP `phone_notifications`，并由 `automation.notifications`（**默认 false**）把关，关闭时 fail-loud `notifications_disabled`，未授权时 fail-loud `notification_access_not_granted` 并指明设置路径。
  · 关键工程细节：光写 `settings put secure enabled_notification_listeners` **不会**让系统绑定（dumpsys 的 Allowed listeners 里始终没有我们），必须走 `cmd notification allow_listener <component>`；验收脚本因此用它来"借"授权，并在结束时 `disallow_listener` + 还原原值，**手机最终状态与运行前一致**（实测跑完 `enabled_notification_listeners` 回到 `[]`）。
  · 真机：`tools/verify_v39_notifications.sh` PASS —— ①开关关闭时工具被拒（`notifications_disabled`）②借用授权后 `granted=true connected=true` ③`cmd notification post` 发的通知被读到（`pkg=com.android.shell title=ADH_ACCEPTANCE`）④`sinceMs` 增量轮询为空（符合预期）⑤退出时释放授权。全量 `verify_all.sh` **55/55**。

- [x] **通知接进等待原语 + automation_status 全貌（2026-09-17，真机 PASS）**：光"能读通知"还不够，AI 真正需要的是"点发送 → 等验证码到达 → 提取填入"的闭环。`phone_wait` 支持 `notificationContains`（标题/正文/多行文本子串）与 `notificationFrom`（包名），命中回 `kind:"notification"` + `{package,title,text,ts,key}`；同样受 `automation.notifications`（默认 false）与系统授权两道门槛，未授权报 `notification_access_not_granted`。纯通知等待不依赖控件树，可与选择器/agent 信号/稳定等待竞速。
  · `automation_status` 补齐为"一次调用摸清能力"：开关、隐私开关（screenshot/notifications/maxNodes）、包名 allowlist、桥接状态 + **设备实时状态**（前台包、快照数、通知授权/缓冲/watchdog 计数），设备离线时该字段降级为 `{error}` 而不是整工具失败。
  · 真机验收（v3.9 新增两条）：①先起等待 → 1.5s 后发通知，**1.68s 命中**；②`phone_task` 四步 —— 重启沙盒 → 等前台 → **等通知取码** → `set_text` 用 `{{code.item.text}}` 填入并提交，`ok=true` 且应用回显 `提交回显：ADH_OTP_task_…（action=0）`。全量 `verify_all.sh` **55/55**。

- [x] **submit 假成功修复：ACTION_IME_ENTER 需要输入法已附着（2026-09-17，真机 5/5）**：把"等通知 → 模板填码 → 提交"整链做成任务验收时暴露了一个假成功 —— `set_text {submit:true}` 仍回 `submitted:true`，但应用侧 `OnEditorActionListener` 没触发（回显停在初值）。根因：`ACTION_IME_ENTER` 在**没有 IME 附着**时是空操作却返回 true，而"刚启动/刚切页"的界面正是这种状态。修法：写入前先 `ACTION_FOCUS` + `ACTION_CLICK` 唤起输入法，submit 路径再等 250ms，然后才 `ACTION_SET_TEXT` → `ACTION_IME_ENTER`；真机压力验证 **5/5**（每轮强制重启沙盒，即最坏情形，回显都拿到本轮标记）。顺带把验收里的最终断言从"立刻 find"改成 `phone_wait {textContains:"提交回显"}` —— 应用是在收到 IME 动作后才更新回显，立即采样本身就是竞态。

- [x] **受保护窗口截图必须 fail-loud（§31.3 规则 4 真机验证，2026-09-17）**：做规格对照审计时发现这条规则**从未实测**。补上后发现真实行为比设想更糟：`FLAG_SECURE` 窗口下 `takeScreenshot` **不报错**，回调照样成功，只是内容全黑（保存下来目视确认：只有状态栏，应用区域纯黑）。也就是说服务会把一张"假屏幕"交给 AI —— 正是规则 4 禁止的。修法：设备侧返回前做黑帧检测（`looksBlank`：48×48 网格采样，≥98% 近黑，或整帧同色且暗），命中即抛 `screenshot_failed: captured frame is blank/black — the window is probably protected (FLAG_SECURE) or the screen is off`。
  · 可验证性：沙盒宿主新增"开启/关闭安全窗口"按钮（`window.setFlags(FLAG_SECURE)`）做确定性靶子。v3.6 新增 4 项：能开启安全窗口 → 截图 **fail-loud**（不再返回黑图）→ 能关闭 → 截图恢复（82KB JPEG）。全量 `verify_all.sh` **55/55**。

- [x] **截图错误码可执行化 + 独立开关验证（2026-09-17，真机 PASS）**：补规则 4 验收时被一次 `screenshot error code=3` 挡住，查 SDK 常量确认是 `ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT`（**截图频率限制**）——框架对连续截图限速，直接失败会让 AI 白跑一轮。两处改进：①设备侧把框架错误码翻成可执行文案（1 内部错误 / 2 失去无障碍权限 / 3 频率限制 / 4 无效显示 / 5 无效窗口 / 6 受保护窗口），未知码保留原始数字；②对 3 自动等 400ms **重试一次**。另验证 §31.4 的"截图可单独关闭"：`automation.screenshot=false` 时截图请求得到 `screenshot fallback is disabled on the host`（明确拒绝而非静默不给图），重开后恢复（82KB JPEG）。
  · 全量 `verify_all.sh` **55/55**；v3.6 现覆盖规则 4 全链路（受保护窗口 fail-loud → 关闭恢复）与截图独立开关。

- [x] **v6/v7/v8 设备侧能力真机验收（就地重启守护进程，2026-09-17，全 PASS）**：之前这几项一直"等刷机"，本轮用仓库自带的方式绕开了：模块目录里的 `daemon.apk` 已被回归替换为**带 Manager 签名摘要**的新构建（bundle 里的 `bca84d0f…`），于是按 `module/service.sh` 的同一行重启常驻守护进程即可（`busybox unshare --propagation slave -m /data/adb/modules/adh/device-daemon`；注意 toybox 的 `unshare` 不认 `--propagation`，直接跑会静默失败）。重启后经 MCP 实测：`phone_device status` → `{interactive:true,locked:false}`；**root `open` 走 `via=device-daemon` 且 `verified:true`（不再弹 ColorOS 跨应用确认框）**；`lock` → `{interactive:false,locked:true}`；`wake` → `{interactive:true,locked:true}`；`unlock` → `{dismissed:true,locked:false}`；**v7 自愈**：root 抹掉 `enabled_accessibility_services` 并置 `accessibility_enabled=0`，守护进程 5 s ensure 循环在 ≤20 s 内自动修回（条目恢复、开关回到 1）。新增 `tools/verify_v40_device_daemon.sh`（已并入全量；守护进程仍是旧载荷时 SKIP，不假装通过）。
  · **顺带拆掉一颗我埋的雷**：`tools/verify_v32_backend_control.sh` 会把无证书摘要的 **CLI 构建** `cp` 到模块目录的 `daemon.apk` —— 那个载荷跑一次性命令没问题，但作为常驻守护进程会立刻崩（`IllegalStateException: manager certificate digest is missing`），**下次重启手机后 Device Daemon 就是死的**（我的回归跑过多次，等于反复埋雷）。修法：脚本先备份模块自有载荷、**备份失败就拒绝覆盖**（SKIP），并在它自己的 `restore()` 里链式还原 —— 注意我第一版用 `trap restore_payload EXIT` 无效：脚本后面已有 `trap restore EXIT` 且结尾 `trap - EXIT`，会被覆盖/清掉。修后实测 v32 跑完模块载荷仍为 `bca84d0f…`，全量回归 56/56。
  · 现状：手机上的 Manager（App）与模块目录里的 `daemon.apk` 已是新构建，常驻守护进程在跑新代码；但模块目录其余文件（`manager.apk`/`libadh_agent.so`/zygisk 等）仍是已刷的 v0.3.3 载荷。**要全量一致仍需刷 v0.3.7**，届时重跑 v3.6–v4.0 确认即可。

- [x] **v0.3.8 bundle：把今天的所有改动打进可刷包（2026-09-17，已构建+推送，尚未刷入）**：旧 `adh-bundle-v0.3.7.zip` 里的 Manager 是**今天改动之前**构建的（没有通知监听、黑帧保护、submit 修复、通知卡片），刷下去反而比手机上现有版本旧。因此把版本提到 **v0.3.8 / versionCode 15**（`injector/zygisk/module/module.prop` + `device/manager/build.gradle.kts`）并重跑 `tools/build_bundle.sh`。包内件逐一核对：`manager.apk` sha256 `c786a095…`（与本地新构建一致，含通知监听/黑帧保护/提交修复/通知卡片）、`daemon.apk` sha256 `bca84d0f…`（带 Manager 签名摘要，含 root `open` + 5s 自愈）、`libadh_agent.so` 322208 字节（含断线自愈重连）、`module.prop` = v0.3.8/15。
  · 产物：`injector/zygisk/dist/adh-bundle-v0.3.8.zip`，sha256 `2c76080053bcae9a9621f1a6a06a60bec6c4b716fdd412b2a447ec5f234b1c8f`，已推送到手机 `/sdcard/adh-bundle-v0.3.8.zip`（旧包已删除，/sdcard 只保留最新）。**尚未刷入**：刷入后建议重跑 v3.6–v4.0 做一次全链路确认（届时模块目录的 `manager.apk`/`libadh_agent.so`/zygisk 也会更新到同一版本，全量一致）。

- [x] **Web 控制台：通知开关入口 + 桥接状态显示修复（2026-09-17，浏览器实测）**：做"新用户能不能自己开起来"的检查时发现两处：①今天新增的 `automation.notifications` **在设置面板里没有任何入口**（只能 curl）；②面板的"桥接状态"永远显示 `已开启 · 但允许包名为空` —— 因为 REST `/api/automation/status` 只返回 `settings/bridge`，而 UI 读的是顶层 `r.packages?.length`（该字段只有 MCP 工具版有）。修法：设置面板新增「允许 AI 读取通知」开关（含"还需在手机 Manager 授予通知使用权"的说明），REST 路由补上 `packages` 字段。
  · 用真浏览器（Codex In-app Browser）实测，而不是只看静态文件：设置 → 手机自动化 页面渲染出 `ID: setAutomationNotifications`（默认未勾选）；AX 点击后 `/api/config` 变为 `notifications: true`，再点一次恢复 `false`（**隐私开关不会被我留在打开状态**）；桥接状态修复后显示 `已连接 · PGP110 · SDK 35`。全量 `verify_all.sh` 56/56。

- [x] **手机侧授权路径实测 + 自控护栏入规格（2026-09-17，截图为证）**：Web 端入口补齐后，把**手机那条路径**也真实走了一遍（此前只写了代码没看过渲染）：①Manager 首页两张卡片渲染正确 —— "手机自动化（可选）"已开启、"通知读取（可选）"显示"未授权：点击右侧按钮…"并带 Android 15 正文不下发的说明；②点卡片齿轮**正确跳到系统「设备与应用通知」权限页**（标题与权限说明可见）；③该页列表里确实出现 **AndroidDecryptHub**（当前"不允许"，用户可自行点开授权）；④全程 `enabled_notification_listeners` 保持为空 —— 我没有替用户授权。
  · 过程中撞到并记录了一条既有安全护栏：用 MCP 驱动 Manager 自身时设备侧直接拒绝（`app_control_denied: package com.adh.manager cannot be controlled`）。查实现：`PackageControl.mayControl` 经 `HardExcludes`（system_server/zygote/zygote64/**com.adh.manager**）与阻断表（com.adh.daemon/android/com.android.systemui）硬拒 —— 防止"用无障碍驱动承载无障碍的 App"形成自控环路，也避免误停系统界面。已写入 `REQUIREMENTS §31.4`。

- [x] **未发布口径：删除 IDH 兼容/兜底（2026-09-16）**：只保留 `libadh_agent.so` 单交付名、`adh_agent_start` 单导出入口。Zygisk 只从 module dir 打开新文件名，不再尝试旧文件名、绝对路径或旧 dlsym；Xposed 只走 `System.loadLibrary("adh_agent")`，删除了 `/proc/self/maps` 二次路径扫描；agent 内部 `idh_*` helper 全部改为 `adh_*`，reporter 只认 `adh.reporter.class`；daemon/tools 不再读取 `IDH_*`，数据目录固定 `adhd-data/`，也不再迁移 `libidhdetect.so`。历史段落里的 IDH 事件/日志证据仅用于说明当时现象，当前代码不包含这些兼容路径。Zygisk + app `System.loadLibrary` 的混态由 native 首载 copy owner guard（`dl_iterate_phdr` link-map order）收敛为单会话；Zygisk 早于 app 设置 `adh.reporter.class` 时，winner copy 的 reporter watcher 会迟绑定，v24 Java rich capture 仍 PASS。两轮真机 `verify_all.sh` 均 51/51。
- [x] **v1 范围收敛（2026-09-16）**：发布面只保留 `docs/FEATURE_STATUS.md §2` 的 51 项已验收能力。未验收、半成品或没有真实触发源的能力，已从 agent / daemon / Web UI / MCP / tools / 发布文档中删除；历史细节只留在 `docs/archive/`，不再作为产品入口或发布说明。`tools/verify_all.sh` 51/51。
- [x] **Web UI 会话模块修复：会话无限堆积 + 选择器"白屏"（2026-09-16）**：两个独立缺陷 ——

- [x] **脱壳主流程简化为一键 dump 所有 DEX（2026-09-16）**：删除 Web Dump 面板里的 T0/T1、覆盖率、主动枚举触发、恢复/重建会话；新增 `/api/unpack/dump-all` 与 MCP `dump_all_dex`：ART DexFile 枚举 → 逐个 dump → SHA-256 去重 → 下载。底层 dex 修复/索引等高级静态工具保留，但不再混入一键脱壳入口。验收改为 `tools/verify_v15_dumpall.sh`，真机 PASS。
      ① **daemon 从不清理 `sessions`**：每次 App 重启都新增一条，一个下午的测试留下 20 条死会话（列表里全是历史会话）。
      修法：`state.ts` 新增 `pruneSessions()`（每包最多保留 `OFFLINE_KEEP_PER_PACKAGE=2` 条离线 + 超过 `OFFLINE_RETENTION_MS=10min` 一律丢弃，**绝不动在线会话**），并在 `agent hello`、`agent close` 与 60s 定时清扫里调用；实测重启 4 次后稳定在 `total=3 (1 online + 2 offline)`。
      ② **会话选择器"一片白色"**：`select` 是 `background:transparent`，浏览器给原生下拉浮层画白底，而选项文字继承 `--ink(#fff)` → 白底白字全看不见。
      修法：给 `select option` 明确的 `background:#11151c; color:var(--ink)`（含 `:checked`），会话 `select` 本身改为不透明 `var(--surface-2)`；顺带把选择器改成**默认只列在线会话** + "显示已断开的会话"开关 + "（已隐藏 N 个）"提示，选中的会话被隐藏时自动回落到"最新在线"。
      · 验证：`tools/verify_v35_sessions.sh`（pruner 单测 4 项 + 选择器标记/配色 5 项 + 实际离线会话上限）PASS；浏览器实测计算样式：`select` 背景 `rgb(21,25,34)`、`option` 背景 `rgb(27,32,42)`、文字白色，列表只剩「（最新在线）+ 1 条在线」并提示"已隐藏 2 个"。
- [x] **模块 W 可选后端：eCapture（eBPF 抓 TLS 明文，2026-09-16 真机验证）**：官方发布固定版本 + 官方 checksum 里的 sha256（`tools/ecapture_versions.json` / `tools/fetch_ecapture.sh`），
      运行器 `tools/ecapture_capture.sh`：`--preflight-only` 打印 root/内核/`CONFIG_BPF_SYSCALL`/`CONFIG_UPROBES`/BTF 能力并给判定，运行后按输出里的 `probe started successfully` 给结论（失败打印首条错误），产出落 `captures/ecapture/`。
      · 关键更正：**内核 BTF 不是必需**（本机 5.10 / `CONFIG_DEBUG_INFO_BTF=n`，初版预检把 BTF 当硬门槛 → 实测 OpenSSL probe 正常启动后改为"提示"），真正的能力信号是 probe 是否启动。
      · 验收 `tools/verify_v34_ecapture.sh` 真机 PASS：官方二进制 → 预检 supported → 对 sandbox 起 TLS probe → **用 MCP `net_capture` 驱动一次真实 HTTPS** → eCapture 抓到请求明文 `ADH_NET_MARKER_v1` + 响应明文 `ADH_NET_RESPONSE_v1`。
        对比证据：同一次请求里 agent 自己的 GOT hook 是 `hooked={"write":0,"read":0}`，eCapture 仍抓到两者 —— 两者是**互补边界**（uprobe vs GOT）。
      · 门槛：root + aarch64 内核 ≥5.5 + eBPF；内核不支持时验收 SKIP 并给出确切原因。
- [x] **沙盒定位澄清：只做"可手动点击的插件测试宿主"（2026-09-16）**：删掉了沙盒 App 里的"观测控制台"（LAN 地址探测 / `/health` 轮询 / 剪贴板与浏览器动作）—— 控制台是 Web UI 与 ADH Manager 的职责；
      保留并明确「状态 / 加解密 / 网络·文件 / 脱壳 / 日志」五个**可点击**标签页，用于手动点测各能力切片；启动初始化（mock dex、模拟注入 `System.loadLibrary`、AdhSecurity 提供者、低频加密流）不变。
      · 中途试过把它改写成"正常小店 App"（商品→下单→支付→订单→我的），经确认**回退**：手动点测更方便，测试宿主形态更合适；插件按类名触发的入口（JavaCrypto/Network/CorrelatedFlow/FileIO/Detection/HookTarget）保持原样。
      · 顺手把 `tools/verify_v33_backends.sh` 的 MCP 会话级分类改为"会话中途消失 → SKIP"（此前会把 `error: command timeout` 当 FAIL 假红），矩阵本身仍必须可达。
      · 验证：全量 `verify_all` 通过（设备 + host），沙盒 APK 重新构建并安装。
- [x] **MCP 面收口：后端矩阵与"进程内真实注入路径"进 MCP（2026-09-16）**：新增 `backends` MCP 工具，与 REST `GET /api/backends` **同源**（共用 `daemon/src/backends.ts`，不做第二套逻辑）；
      带 `session` 参数时按 agent 自己的 /proc/self/maps 判定该进程里**真实存在**的注入路径：`zygisk` / `xposed_module` / `frida_gadget` / `self_load`。
      · 真机实测（MCP 驱动，非 HTTP 手测）：`compat_probe` 取足迹 → `load_library` 把 Frida Gadget dlopen 进 sandbox → `backends(session)` 从 `["adhd_agent","self_load"]` 变为 `["adhd_agent","frida_gadget","self_load"]`（模块数 533→535）。
      · 验收：`tools/verify_v33_backends.sh` 增加 MCP 断言（`tools/list` 含 `backends`、MCP 矩阵与 HTTP 逐字节一致、在线会话分类含 `adhd_agent`）；host 三条（v10_webui / v10_mcp / v33）全绿。
      · 说明：这类能力以前只能靠我手工 curl/HTTP 验证 —— 现在"AI 客户端看到的"和"控制台看到的"是同一份真相。
- [x] **模块 W：注入中心收口 —— 可选后端矩阵进 Web 控制台（2026-09-15）**：主机侧新增只读 `GET /api/backends`：会话按 `entry` 分类（`start` = 注入器路径、`jni_onload` = 自加载/Gadget/Xposed），
      并给出**主机侧真实**的 Frida Gadget 状态（固定版本清单 + 本地缓存版本/ABI/字节数 + 加载命令模板）；Zygisk/Xposed 两项如实标注"设备侧由 ADH Manager → Device Daemon 驱动"。
      Web 控制台设置里新增"注入后端"页：会话列表 + 每个会话的"检测注入方式"按钮（拉 `/api/modules` 按 agent/Gadget 的实际映射路径判别 Zygisk / Xposed 模块 / Gadget / 应用自加载），Gadget 命令一键复制。
      · 验收：`tools/verify_v33_backends.sh`（host，17 项断言：接口形状、**缓存条目与磁盘逐字节核对**、固定版本与 manifest 一致、面板标记、内联脚本 `node --check` 全通过）；连同 `verify_v10_webui`/`verify_v10_mcp` 一起绿。
      · 说明：该提交同时带上 Web 控制台与 `routes_system.ts` 此前未提交的界面改动（与本次面板同一批文件交织）。
- [x] **模块 W：可选后端的控制面 —— ADH Manager/Device Daemon 驱动 Xposed（2026-09-15）**：框架状态与开关从"只能靠框架 CLI"变成 ADH 自己管 ——
      `device/daemon/.../XposedBackend.kt` 只调框架自己的 `/data/adb/lspd/cli`（不碰它的 sqlite 库），AIDL 协议 **v5** 新增 `getXposedStatus`/`setXposedEnabled`/`setXposedScope`；
      Manager 的 Scope 页新增卡片：启用/停用 + "把当前选择同步到 Xposed"，且保存作用域时若后端已启用会自动镜像 —— "哪些应用"仍然只在 Manager 一处配置。
      · 同一代码路径导出 root-only 一次性 CLI（`--xposed-status|--xposed-enable|--xposed-disable|--xposed-scope`）：运维/CI 不必开 UI、不必重启（把新 daemon APK 推进模块目录即可立即生效）。
      · 框架怪癖（已写进实现）：`scope set <module>` 不带参会抛 NPE（清 scope 必须逐条 `scope rm`）；`scope set` 会**隐式启用**模块，想保持关闭必须显式再关一次。
      · 验收：`tools/verify_v32_backend_control.sh` 真机 PASS（构建+推送 daemon APK → 设/清 scope、关/开模块，每步与框架 CLI 交叉核对，最后恢复测试前状态）；单元测试覆盖 v5 门槛、启用即镜像、保存即镜像、停用不镜像。
      · 注：该提交同时带上设备侧此前未提交的多模块工作（应用目录/图标/进程启停/Web UI 地址/启动图标）—— 它们与本次改动在 `RootScopeBinder`、`ScopeScreen`、`DaemonScopeRepository` 里交织，无法单独切开。
- [x] **模块 W 可选后端：LSPosed/Xposed 薄模块（2026-09-15，真机 aa165071 / Vector v2.2 3080）**：`injector/xposed/` 一个**薄加载器 APK**（`com.adh.xposed`），框架已加载进目标进程后把自带 `libadh_agent.so` 送进去；分析能力一行没搬进目标（红线不变），也**不 vendor 上游代码**（`api-stub/` 是自己写的 compile-only ABI 声明，dex 静态验证只有 `Lcom/adh/xposed/AdhXposedEntry;` 一个类定义）。
      · 设备事实 ①：Vector 给模块的 `nativeLibraryDirectories` 是 `base.apk!/lib/arm64-v8a` —— 所以 agent `.so` 必须**未压缩**留在 APK（`useLegacyPackaging=false` + `extractNativeLibs=false`）；先前用"安装时解压"布局时 `System.loadLibrary` 直接 `UnsatisfiedLinkError`（日志已留证），改成未压缩后一次通过。
      · 设备事实 ②：模块 dex 走 `InMemoryDexFile`，APK 不进 maps → APK 路径兜底只在解压式布局下有意义。
      · 设备事实 ③：`vector-cli scope set <module>` 空参数会抛 NPE 且不清 scope，清 scope 必须逐条 `scope rm`（`install_xposed.sh --disable` / 验收脚本都按这个来）。
      · 策略（slice 1）：只进 scope 内应用主进程；永不进 `android`/`com.android.*`/`com.google.android.gms`/模块自身；**只对 ADH 自己的测试宿主**（sandbox / Manager）写 marker，第三方目标不留文件。
      · 验收：`tools/verify_v31_xposed.sh` 真机 PASS（靶子 `com.adh.manager`，非自加载 agent 的 sandbox）：marker `ADH_XPOSED_OK ... agent=1`、框架日志 `Loading legacy module com.adh.xposed` → `Loading class com.adh.xposed.AdhXposedEntry`、Host daemon 拿到 `entry=jni_onload` 会话并真的能执行命令（模块枚举 533 条）；脚本结束**恢复测试前状态**（本机现为 disabled + 空 scope）。
      · 待办：ADH Manager/Device Daemon 驱动框架 scope、注入中心里的后端选择。
- [x] **修复：`verify_v27_zygisk.sh` 泄漏 Zygisk scope → 双 agent 抢 GOT 槽（2026-09-15）**：v27 把 `scope.json` 写成 `["com.adh.sandbox"]` 做 round-trip 后**不还原**，
      于是后续每个 device 脚本的 sandbox 里都同时存在**两份 agent**：`/data/app/.../lib/arm64/libadh_agent.so`（应用自己 `System.loadLibrary`，新构建，tag `ADH_AGENT`）
      + `/data/adb/modules/adh/libadh_agent.so`（Zygisk 注入，旧构建，tag `ADH_AGENT`），两份抢同一批 GOT 槽。日志实锤：`ADH_AGENT capture_start: evp=1 dig=1 …` 之后
      `ADH_AGENT capture_start: evp=0 …`，紧接 `crypto_hook_test: replaced=0 triggered=1 captures=0`。
      证据/验证：把 scope 清成空 allowlist 后进程里只剩 1 份 agent（maps 3 段而非 6 段），v04_crypto / v07 / v07_flow / v20_file / v26_cryptocoverage **全部转绿**。
      修法：v27 现在快照原 scope 并在退出时还原（`trap restore_scope EXIT`；原本无文件则留空 allowlist），不再把 sandbox 永久留在 Zygisk 注入里。
- [x] **模块 W 可选后端：Frida Gadget 直载 + 官方版本切换（2026-09-15，真机 aa165071）**：把"能不能加载 Frida JS hook"做成可选、可验收的独立路径 ——
      下一步：读 `agent/src/hook/got.c` 的匹配逻辑 + 在真机上确认槽在 patch 时刻的实际值（本轮未修，避免与 gadget 改动混在一起）。
      `tools/fetch_frida_gadget.sh`（只走官方 release，版本/ABI 可切换，压缩包 sha256 固定在 `tools/frida_gadget_versions.json`）
      + `tools/compile_frida_script.sh`（**Frida 17 起 Java/ObjC 语言桥不再内置在 runtime**：用 esbuild 把 hook 与 `frida-java-bridge` 打成单文件；
      经典 `Java.perform(...)` 自动注入 `globalThis.Java`，module 写法原样打包，已打包文件幂等直通；不用 `frida-compile` —— 其 CLI 依赖原生 `frida` 绑定，Windows 上需 MSVC）
      + `tools/load_frida_gadget.sh`（官方 so → 按需打包 → 落进 `<pkg>/code_cache`（app uid + selinux ctx）→ `/api/agent/load_so` dlopen →
      轮询 `/proc/<pid>/task` 等 `frida-gadget` 线程 → 可选 `--marker` 断言脚本真的跑了；`--watch` 用 `on_change: reload`，改脚本即热重载无需重启目标）。
      · 排掉的 4 个坑（均有证据）：① Gadget 由构造函数自启动、**没有入口符号**，`symbolFound:false` 是正常的（loader 现在只认 dlopen 成功）；
        ② 配置文件名必须是 `<soname>.config.so` 且与 so 同目录，否则静默回退默认 listen（无 listener、无脚本、无报错）；
        ③ `Java is not defined` = Frida 17 语言桥不在 runtime（官方 Gadget 文档明示），必须打包，否则脚本能跑但 Java hook 部分永远不执行；
        ④ 只等"线程起来"会假绿 —— 线程在配置解析之前就创建，必须用 `--marker` 这类端到端断言。
      · 验收：`tools/verify_v30_fridagadget.sh` 真机 PASS（官方 Gadget 17.18.0 arm64 → dlopen → 打包后的 Java hook 写 marker `ADH_FRIDA_GADGET_OK android=15`，目标进程存活）；
        实测开销：so 25,220,848 B、目标进程 +9 行 maps、+2 线程 —— 高开销后端，**默认关闭**，只有显式调用才启用。

- [x] **修复：`verify_v05_detect.sh` 转绿（2026-09-15）——两个独立缺陷叠加**：症状是 `/api/detect/watch` 恒返回 `hooked={"ptrace":0,"access":0,"prop":0} count=0`。
      缺陷 ①（真凶）：daemon 持久化的 `adhd-data/settings.json` 里还是旧名 `sysModule: "libadhdetect.so"`，而设备上的库早就是 `libadhdetect.so` ——
      agent 拿到的模块子串匹配不到任何已加载模块，**静默** 0 命中（`capture_start: sys[…] p=0 a=0 g=0`，日志里那个 `sys[libadhdetect.so]` 就是线索）。
      修法：`state.ts::mergeSettings` 加 legacy 迁移，只把这一段的确切旧值升级为 `libadhdetect.so`（其余模块名仍归操作者配置）。代码默认值本来就对，是持久化设置把它盖住了。
      缺陷 ②（即使模块名对了也不生效）：这三个符号在被 hook 时**还没被调用过**（sandbox 启动只做 `Detection.load()`，`Detection.run()` 由 agent 触发），
      PLT 槽仍是 resolver stub，而 `adh_got_replace` 只认"槽值 == 原函数地址" → 仍旧 0 命中。修法：把检测三件套的安装/还原（`capture_start` 的 sys 段、
      `capture_stop`、`adh_cmd_detect_watch` 安装+还原）改用现成的 `adh_got_replace_by_name`——从模块自己的 `.rela.plt`/`.rela.dyn`（含 APS2 打包 reloc）按符号名定位槽，槽解析与否都成立。
      证据：修复后 `hooked={"ptrace":1,"access":1,"prop":1}`、`count=4`（debug/root×2/prop 全部观测到），agent 日志 `detect_watch: hooked p=1 a=1 g=1 triggered=1 detections=4`；
      `tools/verify_v05_detect.sh` PASS，全量 `verify_all` 47/47。
- [x] **Web UI 重皮 —— 移植 IDH「2026 workbench」设计语言（2026-07-24）**：`daemon/public/index.html` 整体重设，对齐 IDH 参考界面。
      · 深墨蓝 token 体系（`--bg:#06070a`/`--surface`/`--blue:#78a9ff` + 分类色）+ Inter 字体；品牌头 brand-lockup + `Runtime Console` + 状态 pill；tabbar 计数胶囊（active 蓝底）。
      · 三实时 tab（加解密/系统/网络）共用**过滤工具栏**：分类/搜索/输入大小 min-max/清除 + 暂停(冻结)/下载本类(导出 JSON)/清空本类；`makeCapPanel` 接入 per-panel 过滤态。
      · 捕获行**分类色左边框**（digest 绿/hmac 蓝/对称 琥珀/非对称 紫/net 青/file 珊瑚）+ 分类胶囊；详情面板 cat-dot 标题 + 复制按钮 + IO 卡片（INPUT 蓝顶边 / OUTPUT 珊瑚顶边）+ **UTF-8/HEX/HexDump 三视图**（新增 `hexdump()` 偏移·十六进制·ascii）。
      · 文件/Dump/模态/设置全部套新样式；list-pane 可拖动分栏。**零后端/agent 改动**，所有 fetch/函数/面板 id/WS 处理不变。
      · 验证：headless(Playwright) 渲染**零 JS 错误** + 目视比对参考图一致；`verify_v10_webui.sh` 20/20 PASS（并修复该脚本一个潜伏 bug：`echo "$HTML"|grep -q` 在 `pipefail` 下遇 >64KB 页面因 grep 早退触发 echo SIGPIPE 误判 FAIL → 改 here-string `grep -q <<<"$HTML"`）。
- [x] **顶栏五 tab 重构 + agent 目录浏览（2026-07-24，commit 125f286）**：加解密/系统/网络/文件/Dump。
- [x] **v2.0** WS-D 协议重写（length-framed `[u32 len][u8 type][payload]`，去 8192 上限）**✅**
      + WS-C 环形缓冲/如实 dropped 上报 **✅ 完成并验证**（连续 push-drain 线程作为 WS-C 优化后续再上，见日志）
      + WS-C `cap_reset` 记账修复（丢弃环内记录计入 dropped，`emitted+backlog+dropped==seq` 恒成立）**✅**
- [x] **v2.1 原生 Signature/AEAD 覆盖扩展（GOT hook）+ WS-B 去 sandbox 耦合（2026-07-27）**
      · **WS-B 部分完成**：agent 常驻采集三类(crypto/file/sys)目标模块**全部参数化**、agent 零硬编码目标模块 **✅**；
      · **AEAD（GCM/ChaCha20-Poly1305）**：`EVP_AEAD_CTX_seal/open` 原生 hook 补上此前完全抓不到明文/密文的真实漏洞（Conscrypt 走一次性 API，不走 `EVP_CipherUpdate`）
      · **Signature（RSA/ECDSA）关键发现**：Conscrypt 的 `SHA256withECDSA` 实际不走 `ECDSA_sign/verify`，而是走 BoringSSL 通用的 `EVP_DigestSignInit/Update/Final` + `EVP_DigestVerifyInit/Update/Final`——这套 API 同时服务 JCA `Mac`(HMAC)，靠 `EVP_PKEY_id()`（稳定导出访问器，非内部结构体偏移）在 Init 时判定 HMAC vs 非对称密钥，结果缓存进有界 ctx→kind 表
      · 验证：`tools/verify_v26_cryptocoverage.sh`（新增）连续多次 fresh-restart 测试 PASS；`tools/verify_all.sh` 41/41 全绿
      · 修了一个验收脚本自身的竞态：`aeadDemo` 一次触发产出 3 条相关捕获（原生 GCM 密文/原生 ChaCha 密文/沙盒自带 AdhReport Java 富捕获），轮询一见到第一条就提前返回，导致偶发 `aeadMarker=false`——加 `settleTicks` 让轮询在断言满足后再多等几拍
- [x] **结构重构 Phase 1 — tools 测试库（2026-08-03）**：抽出 `tools/lib/verify_common.sh`（resolve_env/sandbox_alive/gate/grep_q/host_begin+chk+finish，here-string grep 修 SIGPIPE 假 FAIL）+ `tools/lib/env.sh`（SDK/NDK/CMAKE/NINJA/TOOLCHAIN/READELF/ROOT/ABI，build_agent+build_detect 共享）；33 个 verify 脚本转 source 库（node heredoc 全 verbatim，只换 shell boilerplate），三种 idiom（device-alive / device-host node-heredoc / host-chk）各保其形；`tools/MAP.md` 导航 + 加脚本配方。**verify_all 41/41 全绿**（两轮：首轮 v08_disasm/analyze 瞬时 flake，次轮 41/41）。v23 已从发布面移除，不再保留无法验证的静默排除项。已知预存 flake：v08 .so 重建路径 `readMem` short-read 早退（index.ts:663）→ Phase 2 dump.ts 抽取时处理。
- [x] **结构重构 Phase 2 — daemon 拆分（2026-08-03）**：`daemon/src/index.ts` 1585 行 → 拆成 `state.ts`/`service.ts`/`mcp.ts`/`index.ts`。**verify_all 41/41 全绿**。
- [x] **结构重构 Phase 3a — agent GOT/ELF hook 引擎拆分（2026-08-05）**：新增 `agent/src/hook/got.c` + `got.h`，把 ELF relocation/APS2 解析、GOT slot 替换、内存符号解析和 `gothook_selftest` 从 bootstrap 收口为内部窄接口；按 `wc -l`，`agent_main.c` 2655 → 2179 行。新增 `agent/src/MAP.md`，并修正 AGENTS/CLAUDE 中“MAP pending / single TU”的过期导航。**`tools/build_agent.sh` NDK 编译、链接、双导出检查通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP（Host 全绿）**。指定测试机 `13f54a46` 当前未连接（仅出现两台未指定的同型号设备），故 `verify_v04_gothook.sh` 运行时验收诚实标 PENDING，未擅自安装到其他设备。
- [x] **结构重构 Phase 3b — agent capture/JNI runtime 拆分（2026-08-05）**：新增 `capture/capture.c` + 窄命令接口，封装 crypto/TLS/file/system wrapper、bounded ring、Java reporter、persistent/one-shot/inline capture 与 detection watch；新增 `runtime/jni.c`，统一 JavaVM 发现、线程 attach/detach 和 app ClassLoader。`agent_main.c` 2179 → **967 行**，不再持有 capture 的锁、ring、trampoline 或 JavaVM 全局。**`tools/build_agent.sh` 通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP（Host 全绿）**；device capture/inline/detection acceptance 仍因指定机离线 PENDING。
- [x] **结构重构 Phase 3c — agent trigger/trace runtime 拆分（2026-08-05）**：新增 `runtime/actions.c`，收口安全黑名单触发与显式 `.so` 加载；新增 `trace/commands.c` + `qbdi_trace.h`，封装 GOT 函数调用记录、QBDI 命令响应和对应有界状态。命令名与 JSON schema 不变，`agent_main.c` **978 → 784 行**，只保留调用。拆分时修复既有 `trace_run` 16 KiB 缓冲无法容纳 256 条最坏记录的风险，改为可由固定上限证明足够的 128 KiB。**`tools/build_agent.sh` NDK 编译/链接/三入口导出通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP**；v10/v14/v18 设备验收因指定机离线 PENDING。
- [x] **结构重构 Phase 3d — agent object/ART inspection 拆分（2026-08-05）**：新增 `runtime/inspection.c`，收口 live-object 字段检查/无参调用、JNI probe 与兼容性实测；新增 `runtime/art.c`，保留 ClassLoader cookie 枚举、TBI untag、DEX 035–041/cdex 结构判定和完整容器范围计算。命令名、响应 schema 与 SDK 35/36 解析策略不变，`agent_main.c` **784 → 366 行**，现只负责 hello/report、RPC 分发和 lifecycle；Phase 3 capability-domain 拆分完成，并清除拆分后遗留的 socket/`dlfcn`/`fcntl` 等无用头文件。**`tools/build_agent.sh` NDK 编译/链接/三入口导出通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP**；`verify_v03.sh` 的设备侧 JNI/ART 验收因指定机离线 PENDING。
- [x] **Daemon 依赖漂移核查（2026-08-05）**：`npm ls --depth=0` 无 extraneous；评审点名的 `pkijs`/`asn1js` 是已声明 devDependency `selfsigned` 的传递依赖，`tsyringe` 来自其 `@peculiar/x509` 链。`package-lock.json` 与安装树一致，**不是未声明遗留依赖，不做错误清理**。
- [x] **ADH 命名收口（2026-08-05）**：模拟注入宿主 `com.idh.sandbox` → **`com.adh.sandbox`**，Java helper 同步为 `com.adh.agent`，`AdhSecurity/AdhReport`，native JNI 名、daemon sandbox defaults、device scope 单测、协议示例和 35 个 shell 验收脚本全部同步。新增对外主入口 **`adh_agent_start`**，Zygisk 只解析它；rich reporter 只认 `adh.reporter.class`。门禁：除固定哈希历史 probe dex `com.idh.probe` 外，当前源码/脚本 `com.idh.sandbox|com.idh.agent` = 0。验证：agent + detect + sandbox APK 构建通过（APK=`com.adh.sandbox`），daemon smoke PASS，device `:core:test` PASS，Zygisk zip 重建成功，`verify_all.sh` **16 PASS / 0 FAIL / 28 SKIP**；指定设备仍离线，迁移后的 device acceptance 待补。
- [x] **结构重构 Phase 4 — daemon HTTP 领域拆分（2026-08-05）**：新增 `config.ts`、`http/router.ts` 与 system/runtime/analysis 三个 route domain，保持原路由顺序、method/prefix 匹配和响应 schema；`index.ts` **808 → 132 行**，只剩 agent TCP frame decode、HTTP/WS server lifecycle 和 boot。`daemon/test/smoke.ts` 同步改为 `ADH_*` 端口变量。验证使用独立 `18760/18761` 启动本次源码，fresh smoke、dashboard、MCP doc 均 PASS；同一临时实例上 `verify_all.sh` **16 PASS / 0 FAIL / 28 SKIP**，测试后进程已终止。
- [x] **结构维护 Phase 5 — 遗留债务收尾（2026-08-05）**：把 v0.2–v1.0 的 559 行旧状态/会话日志完整迁入非权威 `docs/archive/PROGRESS_V0.2_V1.0.md`，当前 `PROGRESS.md` 从 655 行降至约 100 行且只保留现状与路线；归档内容与迁移前 Git 版本逐行 diff 一致。剩余 shell/MJS 入口统一为 `ADH_HTTP_PORT`/`ADH_AGENT_PORT`/`ADH_TLS_PORT`/`ADH_SERIAL`/`ADH_SDK`/`ADH_LLVM_BIN`，sandbox Gradle 展示名收口为 ADH；三份 HTTP route 文件末尾格式清理。依赖树复核仍无 extraneous，最终 `agent_main.c=366`、`daemon/src/index.ts=132`。验证：Node `--check`、Git Bash `bash -n`、`git diff --check`、sandbox `:app:assembleDebug`、`npm ls --depth=0` 全通过；独立端口实例执行 `verify_all.sh` **16 PASS / 0 FAIL / 28 SKIP**，SKIP 均因指定设备 `13f54a46` 离线，未使用其他设备。
- [x] **ADH Daemon 品牌化 + 模块 W Zygisk/Manager 首版（2026-08-03）**：
      · 对外统一称 **Host ADH Daemon**（npm `adhd`）；`ADH_*` 为唯一环境变量前缀；`adhd` 为唯一 daemon 名。
      · `injector/zygisk/` Magisk Zygisk 模块：按 `/data/adb/adh/scope.json` 白名单 `dlopen` + `adh_agent_start`；`tools/build_zygisk.sh` → `adh-zygisk.zip`。
      · `tools/verify_v27_zygisk.sh`：无 Magisk/未刷模块 → SKIP；有模块则 scope 往返 PASS。
      · Gadget 等可选后端按需启用。
- [x] **设备侧架构奠基（对标 Vector 形态，2026-08-03）**：
      · 新建 `device/` 多模块：`:core`（ScopeConfig/AdhPaths/ScopeJson 单一真相 + 单测）+ `:daemon`（`IAdhScopeService` AIDL + ScopeService 骨架）+ `:manager`（Jetpack Compose 壳，FileScopeRepository / DaemonScopeRepository 预留）。
      · 工具链锁定 Gradle 8.9 + AGP 8.7.3 + Kotlin 2.0.21 + Compose BOM（与 sandbox 同级；不追 AGP 9）。
      · 旧 `injector/manager` ViewBinding 工程退役为 DEPRECATED stub。
      · 验收：`device/gradlew :core:test :daemon:assembleDebug :manager:assembleDebug` BUILD SUCCESSFUL。
- [x] **组合安装包 + Zygisk Next ABI/Manager 状态修复 v0.2.2（2026-08-04，参考 Vector）**：
      · `tools/build_bundle.sh` 生成 Magisk 可直接安装的版本化 `adh-bundle-vX.Y.Z.zip`；内含 Zygisk 模块与同版本 `manager.apk`，安装前验证 `manager.apk.sha256`，boot mode 自动安装。Magisk `action.sh` 可直接打开 Manager，未安装时用模块内 APK 修复安装。
      · 截图所示 Zygisk Next “ADH 无法加载”的根因已定位：旧 `zygisk.hpp` 把入口导出成 C++ 符号 `_Z19zygisk_module_entry...`，而加载器要求原始 C 符号 `zygisk_module_entry`。注册宏现使用 `extern "C"` + default visibility；构建同时强制验证 `zygisk_module_entry` 与 `zygisk_companion_entry`，缺失即失败。
      · 模块真实加载状态改由 Zygisk root companion 写 `/data/adb/adh/zygisk_loaded`，避开模块回调的 SELinux 权限限制；`post-fs-data.sh` 每次启动清理旧标记，`service.sh` 只把 `module.prop` 描述更新为“运行中”或“未加载，请检查 Zygisk”。作者固定为 `decrypthub.com`，不再把内部路径和开发说明放进用户可见描述。
      · Manager 采用 Vector 同类的紧凑 Compose 信息层级，但保持 ADH 独立 APK/作用域边界：首页只显示模块运行状态、注入范围和版本；默认中文，英文系统使用 `values-en`，主题跟随系统深浅色与 Material You。
      · `v0.2.1` 真机重启后，KernelSU 模块页已显示 ADH“状态：运行中”，且 `/data/adb/adh/zygisk_loaded` 存在，证明 Zygisk ABI/companion 修复生效。Manager 仍显示“未安装”的根因是 `com.adh.manager` 未获 KernelSU 超级用户授权：应用命名空间中 `/system/bin/su` 不可见；旧 UI 把该失败吞掉并错误映射为模块不存在。
      · `v0.2.2` 将 Root 可用性纳入 `ModuleStatus`，明确显示“需要 Root 权限”，作用域页在未授权时不再加载空配置；首页和作用域页返回前台自动重检，首页另有刷新按钮。新增 Manager 单测覆盖“无 Root”和“已安装且已加载”两条确定性路径。
      · 模块与 Manager 同步为 `v0.2.2 / versionCode=6`。最终 ZIP 完整性、Manager SHA-256、APK v2 签名、APK 版本及两个 Zygisk C 导出均验证通过；已只推送到 Pixel 6 Pro `1A281FDEE003ZV:/sdcard/adh-bundle-v0.2.2.zip`（SHA-256 `76577c323a3cfc4f105f29d4913285f2a194459a30b2e6dd3a2679c6f97cd5fb`），未安装、未刷入、未重启。
      · 只采用 Vector 的版本化打包、完整性校验、Action 入口和 UI 信息层级，不采用其依赖 system_server hook/root daemon 的 `com.android.shell` 寄生 Manager。
- [x] **v0.3.0 Root Device Daemon 权限边界（2026-08-04）**：
      · `device/:daemon` 从同进程 Service 骨架改为模块以 root `app_process` 启动的独立 APK；只提供 scope 读写与模块状态 AIDL，不含 HTTP/MCP/DB/分析。
      · `IAdhScopeService` 契约移至 `:core`；Manager 删除 `FileScopeRepository` 和全部 `su`/`/data/adb` 访问，只使用 `DaemonScopeRepository`。UI 状态由“需要 Root 授权”改为“Device Daemon 未连接”。
      · Binder 由 daemon 通过 Manager 的 ContentProvider 交接；Provider 只接受 UID 0 且校验 descriptor。daemon 每次事务校验调用 UID、`com.adh.manager` 包归属及构建时固定的 Manager SHA-256 签名证书，作用域写入使用 fsync + 原子替换。
      · `build_zygisk.sh` 先构建 Manager、用 `apksigner` 提取并严格校验 64 位证书摘要，再编入 `daemon.apk`；模块打包 `daemon.apk` + `device-daemon`，`service.sh` 在私有 mount namespace 启动它。
      · 验收：`:core:test`、`:daemon:testDebugUnitTest`、`:daemon:assembleDebug`、`:manager:testDebugUnitTest`、`:manager:assembleDebug` 全绿；`adh-bundle-v0.3.0.zip` 构建成功，含 14 个预期文件，Manager `versionCode=7/versionName=0.3.0`、APK v2 签名有效，daemon 内嵌证书摘要与 Manager 实际证书一致。
      · 已推送到原对话同一台 Pixel 6 Pro `1A281FDEE003ZV:/sdcard/adh-bundle-v0.3.0.zip`，本机与设备 SHA-256 均为 `7bcc9783696d14a15ababb6b71f57f9fd8d1198b6c1caa0b1be18a49ca937be8`；设备上的旧 `v0.2.2` 包已删除，只保留 `v0.3.0`。
      · **真机运行时 PENDING**：按本轮约束未安装、未启动、未重启设备，因此尚未声称 `app_process → Binder 交接 → scope 往返` 在 ColorOS/KernelSU 上通过；首次安装测试必须读取 `device_daemon.log`、ready marker 并做确定性 scope 往返。
- [x] **v0.3.1 Device Daemon / Manager Android 16 修复（2026-08-04）**：Pixel 6 Pro `1A281FDEE003ZV` 首次运行抓到 daemon 在开机早期调用 `ActivityManager.getRunningAppProcesses()` 时，系统 `IActivityManager` 尚未就绪并抛 NPE（PID 1460）；Manager 的全量应用查询又因不必要的 `GET_META_DATA` 产生超大 `ParceledListSlice` 并显示“无法读取应用列表”。daemon 改为直接扫描 root 可读的 `/proc/*/cmdline`，以 `getContentProviderExternal()` + Android 12+ `IContentProvider.call(AttributionSource, authority, method, arg, extras)` 向独立 Manager 安全交接 Binder；Manager 使用 flags=0 枚举应用，并分别记录 scope 与 package query 异常。
      · 热验证：临时 v0.3.1 daemon 以 root/su 域持续运行（PID 11579），ready/PID marker 存在；Manager v0.3.1 显示“ADH 运行中 / Zygisk 已加载 ADH”，应用列表可见。
      · 确定性 scope 往返：只选 `com.adh.sandbox` 保存后 `/data/adb/adh/scope.json` 精确包含该单包；立即取消并再次保存后 packages 恢复为空。
      · 回归与交付：`:core:test`、`:daemon:testDebugUnitTest`、`:daemon:assembleDebug`、`:manager:testDebugUnitTest`、`:manager:assembleDebug` 全绿；`adh-bundle-v0.3.1.zip` 含 14 个预期文件，Manager `versionCode=8/versionName=0.3.1`、APK v2 签名、内置 SHA 与 daemon 固定证书摘要均通过。已推送到 `1A281FDEE003ZV:/sdcard/adh-bundle-v0.3.1.zip`，本机与设备 SHA-256 均为 `3c72f8e1bc77cfa11a4d18c1b759d6ab3ba58a0f369e98f2b9c230bc928ff4bf`；旧 v0.3.0 包已删除。
- [x] **Manager 显示 Host Web UI 地址（2026-08-04）**：Manager 直接经 `http://127.0.0.1:8760/health`（adb reverse）读取 Host ADH Daemon 上报地址，首页优先显示 `web.lan[0]`、无 LAN 时回退 `web.local`，并提供复制与浏览器打开按钮；Device Daemon/AIDL 不承载 HTTP。新增 LAN 优先与 local 回退单测，`:manager:testDebugUnitTest :manager:assembleDebug --rerun-tasks` 全绿。Pixel 6 Pro `1A281FDEE003ZV` 真机显示 `Web UI 在线 / http://192.168.100.11:8760`，UIAutomator 确认全部文案与按钮可见；点击打开后 Chrome 收到精确 `ACTION_VIEW dat=http://192.168.100.11:8760`。
- [x] **v2.2 WS-A native inline 后端（Dobby by-address，2026-08-04）**：
      · Dobby 独立提供 arm64 函数入口 hook；模块名/符号名/触发类与方法均由 Host ADH Daemon 命令传入，agent 零 sandbox 硬编码。
      · sandbox `libadhdetect.so` 增加 BoringSSL `EVP_CipherUpdate` 同 ABI 的静态链接 mock，JNI 直接调用、没有可替换 GOT slot；agent inline wrapper 捕获 `ADH_INLINE_CRYPTO_v1` 并通过 original trampoline 返回 `1`。
      · Dobby 1.2 的 `Destroy → Hook` 重装路径在 ColorOS A15 触发 `CodePatch+84` SIGSEGV；改为产品实际需要的常驻 hook + 命令窗口 active gate，同目标幂等复用。`tools/verify_v28_inlinehook.sh` 同进程连续两次均 PASS（首轮 installed=true，次轮 false，均 1 条 marker）。
      · 真机：OnePlus PGP110 / Android 15 / SDK 35 / arm64，serial `aa165071`；agent、native mock、sandbox APK 构建成功；`tools/verify_all.sh` 全部 43 个条目退出 0（允许脚本定义的环境 SKIP）。
- [x] **v2.3 WS-F 持久索引 + 深解析 + 反射（2026-08-04）**：
      · Host ADH Daemon 新增 `daemon/src/dex_index.ts`，使用 Node 24 `node:sqlite` 将 dex 按 SHA/大小/parser version 持久化到 `adhd-data/dex-index.sqlite`；保存 strings/classes/methods/fields、invoke callers、string callers、field readers/writers 与 `Class.forName` reflection edges。
      · `dex.ts` 增加 proto/descriptor/参数解析、字段访问点和保守的寄存器常量传播；寄存器被覆盖或 code_item 越界时不猜测，统计 `skipped` 并 fail-loud。
      · REST：`POST /api/dex/index`、`/api/dex/index/search`、`/api/dex/index/reflections`；MCP：`dex_index`、`dex_index_search`、`dex_reflections`。
      · sandbox 新增 `ReflectionProbe.load()`，多 dex 验收 `tools/verify_v29_dexindex.sh`：四个 dex 共 59,719 个方法、0 skipped；重复索引缓存最大 3.9ms；`ReflectionProbe.load → Class.forName → Lcom/adh/sandbox/JavaCrypto;` caller/descriptor 经 REST + MCP 均 PASS。已加入 `verify_all.sh`。
- [x] **真机刷入通道 `tools/flash_device.sh`（2026-09-14）**：KernelSU (`ksud module install`) / Magisk 自动识别。当前连接机 OnePlus PGP110 `aa165071`（SukiSU Ultra + Zygisk Next 1.4.2）已刷入 **ADH v0.3.1** 并重启：模块描述「状态：运行中」，`zygisk_loaded` 与 `device_daemon_ready` 均在，`com.adh.manager` 已安装。后续代码更新重复 `bash tools/flash_device.sh --reboot`。`verify_v27_zygisk` 同步认 KernelSU。
- [x] **Web UI 顶栏访问地址只显示一条；品牌改为乌鸦 logo（2026-09-14）**：`#access` 局域网优先，不再并排「LAN · 本机 127.0.0.1」。顶栏去掉字母 A / 双行产品名，只留乌鸦标 + `ADH`；`/raven.svg` 同时作 favicon。
- [x] **应用列表改由 root Device Daemon 枚举 + Web UI 公众号/MCP（2026-09-14）**：
      · 根因：Manager 自己 `getInstalledApplications` 在 Android 11+/ColorOS 上对侧载包不可见，且可能 TransactionTooLarge →「无法读取应用列表」。LSPosed 形态下列表由特权守护进程提供，注入范围仍是 `/data/adb/adh/scope.json`。
      · AIDL protocol v2 增加 `listApplications()`（compact JSON `[{p,l,s}]`）；Device Daemon 用 uid=0 `ActivityThread.systemMain()` 系统上下文枚举，失败则 `cmd package list packages`。Manager 删除 `QUERY_ALL_PACKAGES`，目录失败时仍展示 scope.json 已选包。
      · Web UI 对齐 iOS：顶栏「公众号」+ `/wechat-follow.png`；MCP 模态直接展示 Host ADH Daemon 的 HTTP MCP 端点与 JSON-RPC 示例，`/api/mcp/config` 同步。
- [x] **Host 对外 8088 + 按包名切 App（2026-09-14）**：用户可见 HTTP/WS/MCP 默认 **8088**（对齐 iOS `idh`），agent TCP 仍 **8761**。`http://<LAN>:8088/<package>` 钉该 App 的 Web / `POST /<package>/mcp`。HTTP 仍只在 Host，不进 agent / Device Daemon。Manager 探测 `127.0.0.1:8088/health`（adb reverse），展示优先 LAN。真机 `aa165071` 沙盒 `com.adh.sandbox` 模拟注入在线：加解密 / 系统观测 / TLS 抓包 / 文件管理器 / 文件 I/O hook 均 PASS。
- [x] **注入范围显示 App 图标（2026-09-14）**：Manager 进程没有包可见性，`getApplicationIcon` 全是空占位。协议 v3 增加 `getApplicationIconPng`，由 uid=0 Device Daemon 按包返回 PNG；列表仍用 compact catalog，图标按可见行懒加载。
- [x] **Web UI 对齐 iOS workbench 整页（2026-09-14）**：进程收进顶栏下拉（去掉第二进程条）；tab 计数不再用胶囊；筛选默认折叠；捕获最新在上，滚离顶部时出「跳到最新」；详情左侧色条 + 悬停复制；Dump 默认只列本应用模块、下载在右列。MCP / 设置 / 公众号保留。续扫：Dump 始终隐藏 APK/JAR（不再被 `/data/app` 误放进本应用列表）；主 tab 选择器不再误伤设置侧栏；加解密列表补第三行 preview；覆盖率/配置 JSON 去掉填色框。
- [x] **Manager 终止/重启目标应用（2026-09-14）**：注入范围每行溢出菜单「终止进程 / 重新启动」。协议 v4 `controlPackage` 由 uid=0 Device Daemon 调 `ActivityManager.forceStopPackage`（失败则 `cmd activity force-stop` / `start`），供 Zygisk 改 scope 后冷启动再注入。Manager 不调用 `su`/`am`。拒绝 Manager / Device Daemon / System UI / `android` / HardExcludes。模块与 Manager `v0.3.2 / versionCode=9`。
- [x] **真机 Zygisk 注入链路修复 v0.3.3 + Sentry 验收（2026-09-15）**：
      · 根因：`postAppSpecialize` 调 `getModuleDir()` 死锁；KernelSU 未自动应用模块 `sepolicy.rule`，zygote 读不了 `adb_data_file` 上的 scope；early inject 时 `/proc/self/cmdline` 仍是 `zygote64`。
      · 修复：`preAppSpecialize` 用 `getModuleDir()` + `openat` 取 agent fd、post 只做 `android_dlopen_ext`；新增 `adh_agent_set_package` 由 companion 注入真实包名；模块加 `sepolicy.rule` + `post-fs-data.sh` ksud live patch；`onLoad` 设 `DLCLOSE_MODULE_LIBRARY` 卸载 companion。
      · 真机 Sentry `anti.rusda` v1.7.1 冷启动 3/3：agent online `entry=start`；agent maps=3、companion maps=0、anonExec=0、anonNamed=0、memfd=2（ART JIT）、rwx=0。
      · Sentry 自身检测 3/3：Memory Signatures clean、Maps detection clean；Frida threads/ports、Ptrace、Debugger 全过；安全分数 96，与未注入基线一致。
- [x] **注入足迹基线 + release 收口（2026-09-15，WS-J 首切片）**：`compat_probe` 新增 bootstrap 基线/当前 `execMappings`、`anonExecMappings`、`anonNamedExecMappings`、`memfdExecMappings`、`rwxMappings`、`agentExecMappings`、`zygiskExecMappings` 与 delta；`verify_v05_detect` 校验字段形状、agent 映射存在且 `rwx=0`。
      · release `libadh_agent.so` strip（debug copy 留本地），`.dynsym` 经 version script 只保留 `JNI_OnLoad` / `adh_agent_set_package` / `adh_agent_start` / `adh_agent_start`；debug 13.34MB → release 590KB。
      · 静态结论：基础注入与 GOT hook 不分配匿名可执行段；已知匿名 `x` 生产者是 Dobby inline trampoline（Dobby 自身缓存，`DobbyDestroy` 不释放）与 QBDI trace code cache。QBDI 结束已 `dlclose`。真机 Sentry 验收见上。
- [x] v2.4 WS-E 脱壳二代 + try/catch（v95/v96 已完成）；**cdex/041 不进排期**（2026-10-01，需真实样本）
- [x] v2.5 WS-G Capstone（v48）；WS-H：QBDI **降级为可选后端**（起不来按 `SKIP:optional-dependency`），真实调用点插桩改由 `native_hook` 承接（2026-10-01）
- [~] v2.6 WS-I 确定性关联（**未做**：当前是 `flow.ts` 的 tid+时间窗关联，带 caveat 自述）；WS-J 反检测动态面（首切片已落地；**TRACEME 中和在 2026-10-01 失去唯一控制面**，恢复需显式 opt-in）
- [~] 贯穿 WS-K 架构拆分（进行中）；**多架构不做**（2026-10-01 决议）

---

## 历史归档

v0.2–v1.0 的阶段状态与逐轮日志已移至 [`archive/PROGRESS_V0.2_V1.0.md`](archive/PROGRESS_V0.2_V1.0.md)。归档仅供追溯，不是当前计划或待办来源。
