# ADH 手机自动化 · 接入指南（面向使用者）

> 规格与红线以 `docs/REQUIREMENTS.md §31` 为准，工具清单见 `docs/mcp-tools.md`，逐次验收证据见 `docs/PROGRESS.md`。
> 这份文档只讲"装好之后怎么开、怎么用、出问题怎么查"。

## 1. 前置条件

| 需要什么 | 说明 |
|---|---|
| ADH 模块已刷入 | Zygisk 模块 + Manager（手机侧）+ Device Daemon（root）。bundle 见 `injector/zygisk/dist/adh-bundle-vX.Y.Z.zip` |
| Manager 已安装 | 承载可选的 `AdhAutomationAccessibilityService`（自动化执行面） |
| Host ADH Daemon 在跑 | `cd daemon && node src/index.ts`（HTTP/WS `8088`，agent `8761`，自动化桥 `8763`） |
| `adb reverse` 已建立 | `bash tools/dev_up.sh` 会一次性设好 8761/8763/8088 三条隧道 |

> 只走 USB/局域网时，**三个端口都要 reverse**，否则手机侧的 agent 与自动化桥都回不来。

## 2. 打开自动化（默认关闭）

1. 手机打开 **ADH Manager → 首页 → 自动化** 开关（一键）。
   - 打开：写入 opt-in marker `/data/adb/adh/automation.enabled` 并启用无障碍服务；设备侧 5s 自愈循环会在系统/OEM 清理后自动补回。
   - 关闭：同时移除 marker 与服务条目，之后自愈不会擅自重开。
2. Host 侧打开开关（默认 `false`，关闭时 `phone_*` 不出现在 `tools/list`）：

```bash
curl -s -X POST http://127.0.0.1:8088/api/config \
  -H 'content-type: application/json' \
  -d '{"automation":{"enabled":true,"screenshot":true,"packages":["com.example.app"],"maxNodes":300}}'
```

3. **包名 allowlist**：AI 只能驱动列表内的 App（Host 与设备侧各自校验一次）。允许的常见系统面：`com.android.systemui`（通知栏/快捷开关）、`com.android.launcher`（桌面/抽屉）。**默认不包含**任何第三方业务 App，需要你显式加入。

自检：

```bash
curl -s http://127.0.0.1:8088/api/automation/status   # enabled / bridge.connected / device caps
```

## 3. 接入 MCP 客户端

- 普通端点：`http://<host>:8088/mcp`（JSON-RPC 2.0）
- 固定到某个 App 的端点：`http://<host>:8088/<package>/mcp`（后续调用不必再传 session 相关参数）

手工验证一次：

```bash
curl -s http://127.0.0.1:8088/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -s http://127.0.0.1:8088/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"phone_observe","arguments":{"mode":"text","maxNodes":40}}}'
```

把同一个 URL 填进任意支持 MCP 的客户端即可；`GET /api/mcp/config` 会返回当前建议端点与示例提问（`quickAsks`）。

## 4. AI 操控的推荐套路

```
phone_observe {mode:"text"}         # 省上下文的紧凑屏幕视图（含 snapshotId 与 ref）
  → phone_find {textContains:"登录"} # 只取需要的节点
  → phone_act {action:"tap", snapshotId, ref}   # 用 ref 点，不靠坐标
  → phone_wait {stable:true, stableMs:600}      # 等界面稳定，再用它返回的 ref 继续
```

- **等界面**：`phone_wait` 支持四类条件——选择器/前台包、`stable:true`（屏幕签名连续不变）、agent 信号（`captureCategory` / `agentEvent`）、以及 scroll-until-found（`scrollMode:"gesture"` 用真滑动，翻页器/自绘列表必需）。
- **竞态**：动作与等待是两次调用时，用 `phone_act` 返回的 `cursorBefore` 传给 `phone_wait` 的 `afterCaptureId`/`afterEventSeq`，信号不会漏。
- **一次调用多步**：`phone_task` 的步骤可用 `{{id.path}}` 引用前序结果（例如把 `find` 拿到的 `ref` 直接喂给 `act`），步骤还支持 `retries`/`stopOnError`。
- **沉淀流程**：`phone_skill` 保存命名配方（可声明 `params`，运行时用 `inputs` 传值），下次一条 `run` 复现；配方与 `phone_task` 同级、不可嵌套、无 shell。
- **输入**：`phone_act {action:"set_text", resourceId|ref|editable, text}`；`submit:true` 会再按一次键盘动作键（搜索/发送/完成），回 `submitted:true`。
- **启动与浮窗**：`phone_app open` 会等前台真正切换（冷启动最多 12s，中途重发一次启动意图），返回 `verified`/`foreground`/`relaunched`。ColorOS 把部分系统设置子页做成浮窗（例如 `com.oplus.battery`）时，启动会落在浮窗后面 —— 此时接口自动按一次返回键再重发启动，并在结果里标 `dismissedBlockingPackage`；只有系统包会被当作浮窗，第三方应用永远不会被自动返回键打扰。
- **被拒绝的包名**：操控落到允许名单外的界面时（ColorOS 的设置页分散在 `com.oplus.battery` 等独立包里），工具会明确报 `blocked_package`，Host 记住这个包名，Web「设置 → 手机自动化」会出现一行「被拒绝的包名」+ 一键添加；加进名单后 AI 可以立刻继续。Host 只记包名，不记页面内容。
- **手势保真**：tap/swipe 返回 `changed`（窗口文本签名是否真的变化）。有些 Compose 界面（SukiSU Ultra、Vector/LSPosed 管理器）接受无障碍手势但界面不动 —— 此时 `phone_act` 会自动用同坐标走 root 注入重试一次并标注 `fallback:"root"`；也可以显式要求 `inputMode:"root"`（Device Daemon v9），或直接 `{action:"input", mode:"tap|swipe"}`。
- **看图**：`phone_observe {mode:"text", includeScreenshot:true}` 一次给文本 + JPEG。

## 5. 读通知（可选，需要你在系统里授权一次）

Android 15 不再把通知正文放进无障碍事件，所以这一项走独立的 `NotificationListenerService`：

1. 手机 **ADH Manager → 首页 → 通知读取** 卡片点右侧齿轮 → 在系统"通知使用权"里打开 **ADH Manager**（卡片会显示当前是否已授权）。
2. Host 侧打开开关（默认关，属于独立隐私开关）——Web 控制台 **设置 → 手机自动化 → 「允许 AI 读取通知」**，或等价地：

   ```bash
   curl -s -X POST http://127.0.0.1:8088/api/config -H 'content-type: application/json' \
     -d '{"automation":{"notifications":true}}'
   ```

3. 之后：

   ```json
   {"name":"phone_notifications","arguments":{"limit":10}}
   {"name":"phone_notifications","arguments":{"limit":10,"sinceMs":1750000000000}}
   ```

设备侧缓冲只在内存、最多 30 条、不落盘；未授权时工具报 `notification_access_not_granted`，开关关闭时报 `notifications_disabled`。通知栏本身仍可用 `phone_act {action:"global", key:"notifications"}` + `phone_observe` 读取（会扰动屏幕）。

**等通知（推荐用法）**：把"点发送"和"等验证码"串起来，不用轮询：

```json
{ "name": "phone_wait", "arguments": { "notificationContains": "验证码", "timeoutMs": 20000 } }
```

命中返回 `{matched:true, kind:"notification", item:{package,title,text,ts,key}}`；也可以先读取 `phone_notifications` 拿到 `ts`，再用 `sinceMs` 增量轮询。

## 6. 安全边界（默认值，别改错）

- 自动化**默认关闭**；关闭时 `phone_*` 工具根本不暴露。
- **双层 allowlist**：Host 设置 + 设备侧再次校验，MCP 参数绕不过去。
- 系统弹窗/权限页/支付页**默认不自动授权**；弹窗所在包不在 allowlist 时，接口会 fail-loud 报出包名（例如 ColorOS 的 `com.oplus.securitypermission`）。
- skills 不新增任何权限，不携带 shell，不进版本库；文件被篡改时丢弃条目而不是执行。
- 不复用注入 scope；自动化面与"注入/分析"面相互独立。

## 7. 排障速查

| 现象 | 含义与处理 |
|---|---|
| `automation_disabled` | Host 开关没开（`/api/config` 的 `automation.enabled`） |
| `no automation device connected` | 无障碍服务被系统关掉，或 `adb reverse tcp:8763` 断了；先看 `/api/automation/status` 的 `bridge` |
| `command_timeout: device did not answer …` | 目标窗口被冻结/无响应（设备侧 10s 硬截止）。**通道仍然可用**：重试，或对该 App 执行 `phone_app {action:"restart"}` |
| `selector_not_found` / `stale_ref` | 报错里已附**当前屏幕**的紧凑文本视图，照着改选择器或重新 `phone_find` |
| `phone_app open` 报了 `verified:false` 且 `warning` 指向某个系统包 | OEM 跨应用确认框拦住了启动：手动确认、把该包加入 allowlist、或刷入含协议 v6+ 的新模块包（当前为 v0.3.8）走 root `open` |
| `blocked_package: … is not in the automation allowlist` | 目标包不在 allowlist（前台包或要打开的目标包） |

诊断入口（验收用，不进产品 MCP 面）：`POST /api/automation/selftest?op=status`，以及设备侧故障注入 `POST /api/automation/selftest?op=selftest_sleep&ms=20000`。

## 8. 验收脚本

```bash
bash tools/verify_v36_automation.sh        # 控件树/文本视图/动作/等待/技能/提交/通知栏…
bash tools/verify_v37_agent_reconnect.sh   # Host 重启后 agent 自行重连（同进程新会话）
bash tools/verify_v38_automation_watchdog.sh  # 命令卡死 → 10s 回 command_timeout，通道存活
bash tools/verify_v39_notifications.sh     # 通知读取（脚本借用授权并在结束时还原）
bash tools/verify_all.sh                   # 全量回归（设备/沙盒缺席时对应项 SKIP）
```
