# 交接文档 —— 接手 ADH 开发的 Agent 先读这一份

> 写给**下一个接手本项目的 Agent**。读完这份再动手，能少踩一整轮的坑。
> 交叉引用（不重复内容）：规格 `REQUIREMENTS.md` / 路线 `DEVELOPMENT_PLAN.md` / 当下进度 `PROGRESS.md` /
> 功能状态 `FEATURE_STATUS.md` / 实战记录 `CASE_STUDIES.md` / 硬规则 `CLAUDE.md`（**自动加载，先读它**）。
> 本文件只放三样：**环境真相**、**不在其它文档里的坑**、**在没有设备的前提下该做什么**。
> 写于 2026-09-29，基于 HEAD `633e793`。

---

## 0. 一句话状态

`libadh_agent.so` + Host ADH Daemon + `adh` CLI + 5 个可选后端都已实现，**host 侧门禁 36/36 全绿**；
**device 侧 82 个脚本当前一个都跑不了**——原因见 §1，且**不是代码问题**。
加解密、脱壳、抓包三条线各自的"能力地图"见 §5 的待办表。

---

## 1. 环境真相（最重要的一节，先读完再决定做什么）

### 1.1 连着的那台手机**不属于你**，而且**没有 root**

`adb devices` 里的 `a22fecdd` 是 **PGP110 / Android 15 (SDK 35) / arm64-v8a**，实测证据：

| 检查 | 命令 | 结果 |
|---|---|---|
| 身份 | `adb -s a22fecdd shell getprop ro.product.model` | `PGP110`（与旧文档里的 `aa165071` **不是同一台**，那台已不在） |
| 无 root | `adb -s a22fecdd shell 'id'` | `uid=2000(shell)`，非 root |
| 无 su | `adb -s a22fecdd shell 'which su'` | `NO su in PATH` |
| 无 Magisk | `adb -s a22fecdd shell 'ls /data/adb'` | `Permission denied` |

**它是用户日常在用的手机。** 这意味着：

- ❌ **不许**刷任何东西（`tools/flash_device.sh` 会刷 Zygisk/Magisk 模块 —— **绝对不要跑**）
- ❌ **不许**往里装东西（`install_apk_root` 用 `su + pm install`，**没有 su 必然失败**；改用 `adb install` 也是往用户手机上装 App，**不要做**）
- ❌ **不许**用 `am force-stop` / `am start` 去起停沙盒（`verify_all.sh` 的 device 分支就会这么干）
- ⚠️ `tools/dev_up.sh` 会对**当前连着的设备**执行 `adb reverse`（在用户手机上建两条反向隧道）。做 host-only 的活时**不要**跑它，直接 `cd daemon && node src/index.ts` 起 daemon 即可。

### 1.2 所以：**device 侧的 82 个脚本现在全是死的，而且会挂**

沙盒 App **根本没装**（`adb shell pm list packages | grep adh` → 空；`am start -n com.adh.sandbox/.MainActivity`
→ `Activity class does not exist`）。于是 `verify_all.sh` 一旦把 `adb get-state` 认成 `device`，就会去跑 82 个
device 脚本，每个都 `am force-stop`+`am start`+`sleep 4` 然后**等一个永远不会连上来的 agent**——上一轮实测
**卡了一个多小时**，要靠手工 kill 收场。

**因此：现在不要跑 `tools/verify_all.sh` 全量。** 跑 host 子集（§2.2）。

### 1.3 有一条不碰用户手机的路：模拟器（**尚未验证，先查两个阻塞点**）

这台机器上**有** AVD：`Pixel_6_Pro`，系统镜像 `android-37.1 / x86_64`。

```bash
$ANDROID_SDK_ROOT/emulator/emulator.exe -list-avds      # → Pixel_6_Pro
$ANDROID_SDK_ROOT/emulator/emulator.exe -avd Pixel_6_Pro -no-snapshot -no-audio &
adb -s emulator-5554 shell getprop ro.product.cpu.abi   # 看 ABI
adb root                                                # 非 Play 镜像可 root
```

**两个必须先解决的阻塞点，别假设它能用**：

1. **ABI**：镜像是 `x86_64`，而 agent 只交付 `arm64-v8a`（`tools/lib/env.sh` 的 `ABI="${ABI:-arm64-v8a}"`）。
   要么确认 agent/Dobby 在 x86_64 下**能编译且能跑**（这是个真问题，`agent/src/runtime/art.c` 有按 API 分级的
   结构体布局，某些地方可能是 AArch64 假设），要么换一个 arm64-v8a 镜像（Windows x86 宿主上跑 arm64 镜像会极慢，
   且不一定有货）。
2. **API 级别**：镜像是 **37.1**，而 ART 结构解析器**只验证到 SDK 35（主）/ 36（次）**。
   跑起来大概率在 `art_dexfiles` 那步失败——那本身是一个**有价值的发现**（解析器需要覆盖 37），
   但别把它当成"模拟器这条路的失败"，先判断是实现问题还是覆盖率问题。

**如果这两条任一走不通**：老老实实做 host-only（§2.2 + §5 里标了 host 的项），这已经是能交付的一大块。

### 1.4 参考仓库（本轮的靶子来源）

- `https://github.com/CYRUS-STUDIO/CyReverse` —— **教学性质的逆向示例代码**（不是样本集），
  104 篇文章的配套源码，含加壳/脱壳/反调试/抓包/魔改算法。
- 本机 clone（我在 2026-09-29 拉的，**在仓库外**）：`C:\Users\diiho\AppData\Local\Temp\cyreverse`
  （临时目录，可能被系统清掉；要重拉就 `git clone --depth 1`）。
- 有用的四份变异实现（都在 `app/src/main/cpp/`）：`md5_change_constant.cpp`、`sha1_change_constant.cpp`、
  `custom_base64_alphabet.cpp`、`dynamic_base64_alphabet.cpp`、`custom_crc32_table.cpp`。
- 抽取壳样本：`app/src/main/java/com/cyrus/example/shell/DexExtract.kt` + `hook/CyrusStudioHook.kt`
  + `app/src/main/cpp/cyrus_studio_hook.cpp`，资产 `app/src/main/assets/classes3{,_extracted}.dex`。
- ⚠️ **顶层没有 LICENSE**（= 保留所有权利）。**不许把它的源码拷进本仓库**。可以"照原理自己写 + 拿它当外部靶子
  （在仓库外自己 build）"，本仓库已按这个口径做了 `fixtures/crypto-variants/`（洁净室代码 + 相同常量值）。

---

## 2. 怎么干活

### 2.1 循环（与 `CLAUDE.md` 一致，这里只说没有设备时的落地方式）

**Explore → Plan → Implement → Verify → 更新 `docs/PROGRESS.md` → commit**，一个切片一个闭环。
**没有 pass/fail 信号就不算做完**——这是本项目最硬的一条，见 §3.1。

### 2.2 唯一还能跑的验收（host 子集）

```bash
cd daemon && node src/index.ts &      # 起 daemon（不要跑 dev_up.sh，它会动用户手机）
cd .. && for s in $(grep -oE '"verify_[^"]+\.sh:host"' tools/verify_all.sh | tr -d '"' | sed 's/:host//'); do
  bash "tools/$s" >/tmp/vr.log 2>&1 && echo "PASS $s" || { echo "FAIL $s"; tail -5 /tmp/vr.log; }
done
```
2026-09-29 实测：**36/36 PASS**（含新增的 `verify_v101_crypto_variants.sh`）。

### 2.3 加一项能力的标准动作（四件套，缺一不可）

1. 实现（`.so` / daemon `.ts` / CLI 子命令）
2. **验收脚本** `tools/verify_v1XX_*.sh`（照 `tools/MAP.md` 的配方）
3. **注册进 `tools/verify_all.sh` 的 `SCRIPTS`**（`:host` 或 `:device`）——不注册 = 永远不会跑
4. 文档同步：`tools/MAP.md` + 对应层的 `MAP.md` + `docs/PROGRESS.md` +（若新增 MCP 工具）`docs/mcp-tools.md`；
   改 `CLAUDE.md` 必须**同步 `AGENTS.md`**（两者除标题行外必须一致）

### 2.4 目标解析：用 `adh` CLI，别手搓

```bash
SID="$(cd daemon && node src/cli.ts target --package com.adh.sandbox --quiet)"   # exit 3 = 没 agent
```
"找在线 agent → 按 connectedAt 取最新 → 拿 sessionId"这段曾经被抄进 **76 个** verify 脚本。
现在只有一份实现（`daemon/src/cli.ts`）。`tools/MAP.md` 的"新增验收脚本"第 7 步写了用法。

---

## 3. 坑（这一轮踩到的，其它文档里没有）

### 3.1 门禁会绿着撒谎——这是本项目最重要的一条经验

2026-09-26 那次真机脱壳暴露：**79 个 device 脚本全跑在沙盒自加载路径上**，而那条路径**结构上不可能**产生
"memfd 加载的 agent"或"拒绝 `/proc/self/mem` 的目标"。于是 `art_dexfiles`/Java hook/整条读内存链路在真机上
**整组死掉，门禁却全绿**。修法不是改一个功能，是**断言注入路径上的能力**（`verify_v98`）+ 给读内存加强制直读
（`verify_v97` 覆盖全部读命令）。

**你接手后的第一条纪律**：任何新验收都要问"它跑的路径和真实路径是同一条吗？"
**能证明测试有牙齿的做法**（本项目期望你这么干）：把被测能力临时破坏掉，断言测试**必须**红。
`verify_v98` 是这样验的（把 JavaVM 查找改成 `return NULL` → 断言 FAIL），`verify_v101` 也内置了
"旧扫描对两个库返回同一组名字"这条**证明旧层看不见**的断言。

### 3.2 靶子必须**编译**，不能是测试自己拼的 buffer

`verify_v101` 第一版 13 条单测全绿，但**编译靶子当场证伪**：MD5 的 16 字节 init 是 SHA1 20 字节 init 的**前缀**，
任何同时含 SHA1 的镜像都会让"MD5 init 在不在"答 yes → 变异库被误判成标准 MD5。合成 buffer 从不同时含两份 init，
**真实 .so 通常两份都有**。参见 `fixtures/crypto-variants/` + `tools/build_crypto_variants.sh`。

### 3.3 本仓库的 TypeScript 是 **strip-only**，没有构建步骤

node 24 直接跑 `.ts`，**不支持 TS 的 parameter property**（`constructor(readonly x: T)` 直接语法错）。
其它 TS 独有语法同理慎用。

### 3.4 "接受但被忽略的 flag" 比没有这个 flag 更糟

`xls-probe`（另一个项目）的 `--proxy` 注册在公共参数里、只有 `signcode` 一个子命令消费，于是 `face --proxy …`
**静默忽略**——而那条命令存在的意义就是"换出口"。ADH 现在有两道守卫：`daemon/test/cli_args.test.ts`
（声明了就必须有人消费）+ `verify_v100`（每个 flag 必须有**可观测效果**）。加 flag 时别破坏它们。

### 3.5 超时/退出这类"看起来对"的地方，一律量一遍

`adh` CLI 的两个真问题都是量出来的：`fetch` + `AbortSignal` 在 2s 中止但**进程又活了 8.7s**（undici 的待决
connect 句柄在 Windows 上不可取消）；换 `node:http` 后 `req.setTimeout` 只约束 socket **空闲**、不约束 connect，
于是 `--timeout 2` 的错误在 **5106ms** 才出现而文案写着 2 秒。现在是自己的墙钟定时器（2090ms 实测），
**并且 `verify_v100` 断言这个界**，防止回退成谎话。

### 3.6 其它小而致命

- `echo "$OUT" | grep -q` 在 `pipefail` 下会因 **SIGPIPE** 假失败（>64KB 载荷必踩）；用 `verify_grep_q` 或 here-string。
- Windows 上杀进程用 **PowerShell `Stop-Process`**，`taskkill /F` 在 `MSYS_NO_PATHCONV` 下会被吞掉（静默不生效 → 假绿）。
- 单引号 TS 字符串里**一个撇号**能让 daemon 起不来，而 `node --check` 看不出来（正因如此才有 `verify_v71`）。
- 本仓库**禁止提交目标数据**（`captures/`、`dumps/`、`adhd-data/` 已在 `.gitignore`）；写文档要脱敏。

---

## 4. 架构红线（别越）

`libadh_agent.so`（目标进程内，只采集/执行）→ Host ADH Daemon（HTTP/MCP/分析）→ Device（作用域/进程控制）→ Web UI。
**永远不要**把 HTTP/MCP/数据库/dex 索引/Capstone 放进 agent `.so` 或 Device 层。模块 X（手机自动化）已退役，**不要恢复**。

---

## 5. 待办（按"无设备、无 root 也能交付"排序）

### A. 立刻可做（纯 host，有明确验收）

| # | 事项 | 验收信号 |
|---|---|---|
| A1 | **变异识别的第二步**：运行时生成的码表（`out[i ^ (len%64)] = std[i]`）与"连锚点一起换"的变异（自定义 S-box / 自造轮函数）。现在的静态常量法对这两类**注定看不见**，`limits` 已如实自述。落点：用**指令结构**（已有的 `trace_digest`/QBDI 摘要是原料）识别"轮函数形状/移位表/循环边界"。 | 对参考仓库的 `dynamic_base64_alphabet` 与一个自造 S-box 的靶子，**在只给反汇编/指令流的条件下**能报出"这是一种 base64/分组密码结构"，且对普通代码负对照不误报 |
| A2 | **二代抽取壳的 host 半段**：把 `verify_v13_recover.sh` 的合成样本升级成**真实形态的 fixture**（用参考仓库的 6 字节方法体抽取形态：`1A 00 87 00 11 00` = `const-string v0` + `return-object v0`，抽取 = 把这 6 字节清零），把"覆盖率 → 恢复 → 重建 → 再测覆盖率"串成一个**可断言恢复率**的闭环。 | 恢复率是**具体数字**（不是"部分"），且被抽方法重建后与原文 sha 一致；解不动的显式 `unresolvable` 计入分母 |
| A3 | **门禁的变异测试化**：现在"破坏能力 → 断言测试必须红"是手工做的。做成机制：每个守卫声明"拿掉哪个能力时你必须失败"，门禁自动跑负对照。 | 门禁能自动报出"这条守卫没有牙齿" |
| A4 | **`adh` CLI 的第二片**：`adh watch`（事件流）+ `adh hooks`（钩子装卸），并**迁移**若干 verify 脚本改用 CLI 解析目标（先迁 3-5 个，每批都跑门禁）。 | 迁移后的脚本行数显著下降且全绿；`--quiet` 给出 session id |
| A5 | **agent 侧 `agent_inventory` + `unhook_all`**：现在只有逐钩子 `unhook`，没有"现在挂着什么"的清单和"全部卸掉"的动作（代价我踩过：一个没卸掉的 `strlen` 钩子让后面的断言失败，只能重启进程收场）。⚠️ 改 agent 需要 `build_agent.sh`，**但验证只能在 host 侧做单测 + 等有设备时补真机**。 | CLI `target` 能打出常驻钩子清单；`unhook_all` 后清单为空 |

### B. 需要设备（**现在做不了，写清楚留给以后**）

| # | 事项 | 为什么现在做不了 |
|---|---|---|
| B1 | `adh target`/`unpack` 的端到端（上轮 `verify_v100` 的 device 半段） | 需要在线 agent；用户手机不装沙盒 |
| B2 | 二代抽取壳的**还原点**（hook ART `ClassLinker::LoadMethod` 在方法体解密瞬间抓 CodeItem） | 需要真机；参考仓库给的就是这个还原点（mangled 名在 `cyrus_studio_hook.cpp`）。注意本机 ROM 的 `libart.so` 被裁过，符号可能不在——**这是首要待查项** |
| B3 | `mprotect` 读 PROT_NONE（SO 脱壳：很多壳把 ELF 头设成 PROT_NONE 再 dump） | agent 内部**有** `mprotect`（hook 机制里用），但**没有对外命令**；需要一个只读用途的改页 op |
| B4 | 抓包两块缺口：**QUIC/HTTP3**（明文捕获建立在 TLS/SSL 库边界 + EVP 边界上，QUIC 不走 `SSL_write/read`）、**WebView JS 桥**（参考仓库有 `webshell_bridge.cpp` + `bridge.js`） | 需要真机抓包验证 |
| B5 | 反检测靶场：把参考仓库那套 Frida/调试/反抓包检测（`fridadetector/core/checks/*`、`anti_debug.c`、`SniffDetector.kt`）当**负对照**跑 `stealth` | 需要真机；这是 `verify_v69` 思路的加强版 |

### C. 需要用户拍板（不要自己决定）

- **产品口径冲突**：用户希望"横扫所有脱壳/加解密/抓包"，而 `REQUIREMENTS.md §15.5` 写死"不承诺把每种壳还原成
  可读 Java 源码、不承诺 VMP 完整语义还原"。按 `CLAUDE.md`，两份说法必须合一（**先问，再改文档**）。
  建议口径：**覆盖所有场景类型都有对应工具与流程（不保证每个壳 100% 还原），恢复率如实上报**。
- `DEVELOPMENT_PLAN.md §6.9.5` 的发布范围收口 10 项（除模块 X 外）逐项待确认。
- agent TCP `8761` 无鉴权的信任模型（加 token / 只绑 127.0.0.1 / 维持现状）。
- 是否**允许在用户的手机上装沙盒**（若允许，82 个 device 脚本立刻复活；若不允许，走 §1.3 的模拟器路）。

---

## 6. 不要做的事（红线清单）

1. **不要动用户那台手机**：不刷、不装、不起停 App、不 mock 位置；`dev_up.sh` 会建 adb reverse，host-only 时别跑。
2. **不要跑全量 `verify_all.sh`**（会把 82 个 device 脚本拖起来挂住）。
3. **不要拷贝参考仓库的代码**（无 LICENSE）。
4. **不要提交目标数据**（`captures/`、`dumps/`、`adhd-data/`）。
5. **不要恢复模块 X**（手机自动化），也不要给 Device 层加分析能力。
6. **不要在 agent `.so` 里加 HTTP/MCP/DB/重分析**。
7. **不要把"看起来对"当成通过**——没有 pass/fail 信号的改动不算做完，宁可标 `SKIP` 也不要虚报 PASS。

---

## 7. 接手前自检（跑一遍，确认环境与本文一致）

```bash
git log --oneline -1                                  # 期望起点：633e793 之后
adb devices                                           # 期望：一台 a22fecdd device（用户手机，别动）
adb -s a22fecdd shell 'id; which su'                  # 期望：uid=2000(shell) + NO su  ← 无 root
adb -s a22fecdd shell pm list packages | grep -c adh  # 期望：0（沙盒没装 → device 半段全灭）
$ANDROID_SDK_ROOT/emulator/emulator.exe -list-avds     # 期望：Pixel_6_Pro
cd daemon && node --test test/*.test.ts 2>&1 | tail -3 # 期望：全部 pass
bash tools/verify_v101_crypto_variants.sh              # 期望：RESULT:PASS（host，无需设备）
```

任何一条与本文不符（例如设备换了、root 了、沙盒装上了），**先更新本文档再按新情况推进**。
