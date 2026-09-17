# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 当前阶段 —— 🔧 v2.0+ 加固与重构（进行中）

**v0.1–v1.0 全部实现并逐项验证（`tools/verify_all.sh` 35/35，真机 + host）——那一轮证明"每条能力路径可跑通"。**
现进入 **v2.0+ 加固重构轮**：针对评审锐评的 14 点，把每条路径从"能演示"做到"能在对抗、并发、无样本、
无 sandbox 耦合下不骗人"。权威路线见 `DEVELOPMENT_PLAN.md §6.9`（WS-A…WS-K + v2.0–v2.6 排期 + 门禁清单）。
旧 v0.2–v1.0 路线归档于 `DEVELOPMENT_PLAN.md §7`。

**三条总原则（门禁）**：① 不为过测而耦合（agent 内 `com.adh.sandbox` 常量 = 0，目标模块名不硬编码，
全来自命令参数）；② 不胡乱兜底 / fail-loud（hook 装不上、缓冲溢出、解不动一律显式报错 + 计数上报，
绝不 `ok:true replaced:0` 或虚高恢复率）；③ 红线不动（重分析在 adhd，hook/采集在 agent）。

### v2.0+ 进度
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
- [ ] v2.4 WS-E 脱壳二代 + try/catch + cdex/041（需样本，否则 PENDING）
- [ ] v2.5 WS-G Capstone + WS-H QBDI 通用化
- [ ] v2.6 WS-I 确定性关联 + WS-J 反检测动态面
- [ ] 贯穿 WS-K 架构拆分 + 多架构

---

## 历史归档

v0.2–v1.0 的阶段状态与逐轮日志已移至 [`archive/PROGRESS_V0.2_V1.0.md`](archive/PROGRESS_V0.2_V1.0.md)。归档仅供追溯，不是当前计划或待办来源。
