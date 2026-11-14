# Skill: 运行时调用图优先（Callgraph-First）

> 这个 Skill 解决一类反复出现的失败：**不知道该在哪个地址下断点，于是逐个猜，逐个 0 命中。**
> 适用场景：逆向一个不熟悉的 native 目标、追一条不知道经过哪些函数的计算链、判断某段代码到底有没有被执行。

## 核心原则

**先要调用图，再要断点。** `root_watch` 的每个事件里都带 `chain[]`——内核采集的运行时调用栈。
这是**免费**的：你为了别的目的下断点时，它已经一起给了。不用它，就等于放弃手边最可靠的证据。

## 为什么这条重要

目标的栈帧可能被主动破坏。实测遇到过函数入口连写 8 组：

```asm
mov x10, sp ; subs x10, x10, #0x10 ; mov sp, x10
mov x11, sp ; subs x11, x11, #0x10 ; mov sp, x11
...（连续 8 组）
```

这是**栈指针混淆**：基于 `x29` 的帧链遍历会失效，`native_backtrace` 会返回空或错乱的帧。
但**内核 unwind 仍然有效**，`chain[]` 不受影响。所以在这种目标上，`chain` 是唯一可靠的调用图来源。

## 标准流程

### 1. 拿一个已验证的热点地址

不要用"反汇编里看起来像函数入口"的地址。要来自实测：

- `br x8` / `blr` 这类派发指令的实际跳转目标
- `native_backtrace` 返回的帧
- 已有的 `chain[]` 里的某一帧

### 2. 下执行断点，不附加任何额外采集

```json
{"action":"start","session":"$session","tid":"$tid","addr":"$entry","width":4,"mode":"x",
 "durationMs":5000,"maxEvents":128,"stackBytes":0}
```

`tid` 必须是**真正执行工作的线程**。Java 驱动的目标用 `java_call` 调 `android.os.Process.myTid` 取；
`native_call` 的 worker 是短命的，不是持久的执行线程。

### 3. 读事件，看 `chain`

```json
{"action":"read","id":"$runId","afterSeq":0,"limit":8,"registers":true}
```

每个事件形如：

```json
{"seq":1,"bp":0,"ip":"0x...","pid":...,"tid":...,
 "chain":["0x...","0x...","0x..."],   // ← 这就是调用图
 "chainTruncated":false,
 "regs":[...33 个...],
 "stack":{"addr":"0x...","requested":1024,"got":1024}}
```

把 `chain` 里每个地址映射到模块区间（用 `memory_maps` 拿区间），得到 `模块名+偏移`。

### 4. 先确认调用图稳定，再信任它

同一个操作触发两次，`chain` 应该一致。**不一致说明你采样到的是不同的工作，不是同一条调用路径。**

### 5. 用 `chain` 的下一帧作为新锚点，逐层向外

```json
{"action":"start","session":"$session","tid":"$tid","addr":"$pc","width":4,"mode":"x",...}
```

入口 → 它的调用者 → 再上一层。遇到跨模块或运行时边界就停。

## 关键：`chain` 里是返回地址，不是函数入口

**这是最容易踩的坑。** `chain` 的每一帧是 `bl` 之后的下一条指令地址（返回地址），
不是被调用函数的入口。直接拿它下断点，命中率接近 0。

正确做法：**从返回地址往前找函数序言**。

```
候选序言（ARM64）：
  sub  sp, sp, #imm
  stp  x29, x30, [sp, #imm]
  add  x29, sp, #imm
```

往前扫最多几百字节，第一个满足「`sub sp` 紧跟 `stp x29, x30`」的地址就是函数入口。

**另一个容易犯的错：把绝对地址当偏移。**
`chain` 里是绝对地址（如 `0x6f9b5427f0`）。若 VM 段基址是 `0x6f9b510000`，
真实偏移是 `0x327f0`，不是 `0x427f0`。用错会断到 +4MB 外。

## 判读规则（都是踩过的坑）

| 现象 | 含义 | 不要下的结论 |
|---|---|---|
| `chain` 只有 1 帧 | 内核无法继续 unwind | 不是"没有调用者" |
| 两次触发 `chain` 不同 | 采到了不同的工作 | 不是"调用图不稳定" |
| 断点 0 命中 | 地址错 / 工作不在这个线程 | **不是**"这段代码不存在" |
| `chain` 跨到 `boot.oat` / `*.vdex` | 调用来自 ART 管理的代码 | 不是 native 库内部调用 |

## 一个真实例子

追一个 Android VM 的派发点时，静态反汇编能看到的只有 VM 内部的一层。用 `chain` 一次就拿到完整五层：

```
VM+0x17328   ← br x8 派发
VM+0x16980   ← 解释器主循环
VM+0xc7cc    ← JNI 包装（按返回类型有 10 个几乎相同的副本）
boot.oat+0xd6c
base.vdex+0xca26ccd
```

512 个事件全部一致。这直接说明了 VM 是通过 ART 的 vdex 代码被调用的，
而不是从某个 native 库直接调进来——这个事实靠静态反汇编要花很久才能确认。

## 什么时候不该用这个 Skill

- 已经知道确切的目标函数 → 直接 `native_hook` / `native_look`
- 目标是 Java 方法 → `java_hook` / `java_trace`，不是 native 调用图
- 需要指令级语义 → `trace_session`（QBDI），不是调用图

## 配套工具

| 工具 | 用途 |
|---|---|
| `analysis_guide(topic="callgraph")` | 本流程的机器可读版本，含模板和失败分支 |
| `root_watch` | 提供 `chain[]`；同时可下最多 4 个断点、读最多 4 个内存窗口 |
| `memory_maps` | 把 `chain` 地址映射成模块+偏移 |
| `native_backtrace` | 栈未混淆时可用；混淆时改用 `chain` |
| `runtime_diagnostics` | 确认线程身份，列出可用的 TID 候选 |

## 一句话

**断点前先问：这条链我已经有了吗？** `root_watch` 的 `chain` 几乎总是已经回答过了。