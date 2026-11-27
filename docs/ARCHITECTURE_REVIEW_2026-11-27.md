# ADH 架构与收尾审查（2026-11-27）

## 结论

**不需要推倒 Host／Device／Agent 分层，但连接生命周期和数据可靠性还没有达到“拔插即用、长期抓取”的产品完成度。** 本轮从用户的双机拔插故障逆向走查主要使用链路，复现并修复4类连接缺陷；另列出数据、状态、旧代码与文档的收尾项。并非每个 Hook、ROM、机型、LAN 路径的全量功能／安全审计。

源码基线：`7b4894ac6dcdf061678a79f93560c18f2fa5da08`。本轮不改手机载荷、不重启手机、不清空历史。当前仅一台手机物理在线；双设备的断连／重新枚举竞态由生产路由＋模拟 ADB 协议夹具验证，**不冒充双机物理拔插实测**。

## 1. 当前架构与身份模型

```text
浏览器 / CLI / MCP
        │ 明确设备 + APP；写操作带 revision / epoch / operationId
        ▼
Host ADH Daemon：路由、任务协调、作用域、分析、文件通道、持久化
  ├─ Device RPC（USB / 已配对 LAN）→ Device Daemon → scope / 进程控制 / 能力
  ├─ 显式 ADB 兼容通道（本轮修复为按 serial 选择）→ 文件 / 清单 / 部分 root 能力
  └─ 每设备 Agent 路由租约 → 目标 APP 内 libadh_agent.so
                               │ 有界内存环形缓冲 / 原始采集
                               ▼
                    Host drain / 归属校验 / 规范化
                               │
                   RAM + SQLite 归档 + 旧 JSONL
                               │ WebSocket / 游标 HTTP
                               ▼
                   浏览器 IndexedDB + 虚拟列表
```

| 标识 | 职责 | 不应混用 |
|---|---|---|
| `deviceId` + 设备身份指纹 | 设备域的持久身份及 USB/LAN 认证 | 不能用临时 ADB ID 冒充 |
| `serial` | 明确选择 ADB 设备 | 不是目标进程身份，也不是设备公钥认证 |
| `transportId` | ADB 当前连接代际 | 不能当长期缓存，本次4→9就是反例 |
| `leaseId` / `bootId` | Host拥有的监听、路由、手机启动代际 | 变化就让旧会话失效，不复用旧证明 |
| `sessionId` + PID / UID / starttime | APP 的一个具体进程 | 同包、同PID、不同手机也不能混用 |

应继续保持 Agent 只采集／执行，Device 只管设备域，Host 做分析和存储；应统一的是**连接生命周期和状态来源**，不是把三层合成巨型服务。

## 2. 已复现并修复的连接缺陷

| 编号 | 严重度 | 原因／真实影响 | 本轮结果 |
|---|---|---|---|
| C1 | P1 | `deviceAdbPrefix` 从 Agent 租约取旧 `transportId`，文件、应用清单、图标等复用它；物理手机在线也会报找不到4 | 改为显式稳定serial；无设备或与当前请求矛盾时拒绝。Agent命令仍保留租约／启动／进程证明，不放宽为任意设备 |
| C2 | P1 | `track-devices` 只广播刷新UI，旧监听／租约没回收，也不随已选设备重新枚举而恢复 | `reconcileKnown` 串行合并新名册，只重建之前明确选择过的设备；拔掉B不动仍在原代际的A；不自动接入陌生C，不重放APP／Hook写操作 |
| C3 | P1 | A的归属验证探测B时，B在“枚举→探测”间拔掉，B的异常直接使A失败 | 有界重读名册。B仍在线却读不了就继续拒绝；B换代后映射到A监听仍拒绝，不能用吞异常破坏归属安全 |
| C4 | P1 | RPC池的旧连接关闭回调直接按serial删条目，能误删正在建立的新连接；并发connect重复建通道 | 共享同一次连接任务，旧回调只能删除自己持有的缓存条目；实际生产代码夹具复现旧连接迟到关闭／并发连接 |

对应源码：[设备选择与RPC池](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/device_bridge.ts)、[Agent路由生命周期](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/usb_agent_routes.ts)、[插拔事件入口](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/index.ts)、[文件错误说明](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/sandbox_fs.ts)。

### 当前现场结果

- 原接口：同一设备／APP／目录，HTTP **502**，原文为 `host:transport-id:4: no device with transport id '4'`。
- 修复运行版：同一请求 HTTP **200**、`ok:true`、返回4个目录项；设备当前连接ID为9。
- Demo的Agent在Host重新连上；只是Host保留数据重启，未重启手机、未重新安装APK、未启动其他APP。
- 相关5个测试文件共 **80通过 / 0失败**，Host类型检查通过。单独14项新生命周期用例有原版／修改版／回滚对照，见既有验证账本；没有跑全量设备测试。

## 3. 尚未收尾的部分（不能说已修复）

| 编号 | 类型／优先级 | 证据与影响 | 建议下一步 |
|---|---|---|---|
| D1 | **已确认缺陷 / P1** | [restoreHostState](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/state.ts) 对 `events.jsonl` 整文件读入再取末5000行。当前文件约981MB；本轮启动日志实际报Node字符串上限，旧事件回放从空起步 | 先做有界尾读／流式恢复，再加轮转；保留旧文件，不以清数据解决。事件回放与SQLite捕获归档要分开说明 |
| D2 | **已观察的数据完整性缺口 / P1** | 本轮Agent重连后的首批健康日志出现累计 `dropped=329585, seq=536027, complete:false`。这是该Agent累计计数，不能说这些都是本轮新丢的。内存有界但没有完整的断线持久化保障 | 明确采集连续性／丢失区间；分离控制与大量数据的调度，量化断线缓冲预算。若要求长时间离线不丢，需独立设计手机端有界落盘与确认游标，不能只无限加内存 |
| D3 | **代码层性能风险 / P2，未做新压力测** | [CaptureHistory.page](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/capture_history.ts) 同步SQLite每页COUNT、LIKE包含搜索、读取完整body JSON再解析；[旧JSONL](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/capture_persist.ts) 与事件/RAM/SQLite多份数据共存。当前SQLite约1.46GB | 用同一数据样本量化P50/P95、事件循环阻塞与积压；优先元数据／正文拆读、增量计数、批量落盘和索引，必要时Worker。不要先上微服务或消息队列 |
| D4 | **状态与生命周期未完全收敛 / P2** | [device_bridge](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/device_bridge.ts) 与 [Devices](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/devices.ts) 分别维护连接池／注册表；`deviceRpcLive` 把连接中也计为live，ADB在线与Agent在线又是两回事 | 一个生命周期协调入口，状态明确为发现／连接中／设备域就绪／APP未运行／采集中／离线；保持USB进程证明与设备密钥认证的信任级别差异 |
| D5 | **能力边界不齐 / P2** | [设备能力声明](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/device/daemon/src/main/java/com/adh/daemon/device/DeviceOperations.kt) 明确fs、Agent路由、bulk等未迁移；[scope RPC兼容逻辑](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/scope_list.ts) 仍在RPC不可用时走ADB。[文件路由](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/http/routes_runtime.ts) 的Agent／root选择也是另一条策略 | 做实际能力矩阵，声明来源和不可用原因；不能承诺USB/LAN全能力等价，更不能把所有失败都偷偷提权／自动重试 |
| D6 | **产品行为待收敛 / P2** | [refreshDevices](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/panel/src/store.ts) 在当前设备从列表消失时可能自动选另一台；当前异步列表与文件组件有目标／请求代际隔离，这是正确的，但自动切目标是否符合用户预期仍需产品裁定 | 倾向保留“已断开”的选中上下文，明确提示重连，别悄悄换分析对象；此项本轮未改，不能与首次启动自动选择混为一谈 |
| D7 | **遗留代码／文档／门禁 / P2–P3** | 仍有两个脏worktree。入口index保留已搬走处理器的未用import；FEATURE_STATUS旧版本／日期／计数与现行native-capture/3不一致；旧网络复制命名断言在改动前也失败 | 逐文件／逐hunk对账后收敛，不整仓合并、reset或清目录。同步“当前能力真相表”与实际UI断言，别降低语义测试标准 |
| D8 | **明确未完成能力 / P3，可不新增** | [FLOW_CAVEAT](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/flow.ts) 只有线程＋时间窗口共现，不是内容哈希证明；[MCP说明](X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/daemon/src/mcp.ts) 仍提旧EVP抓取路径 | 更新描述，保持限制可见；按用户“简单、宁缺毋滥”的方向，先把采集／检索／导出做稳，不为了完整清单继续加冷门Hook |

### 旧代码哪些保留、哪些该收掉

- **保留**：历史EVP／Native记录的解码与展示。它们不是仍在运行的Hook；删掉会让已有日志变得不可读。
- **保留**：设备／APP／进程作用域、CAS/epoch、unknown不重试、路由归属与指针所有权校验。不能为了“简化”删掉真正的安全边界。
- **应收敛**：重复连接生命周期、同状态多来源、已迁移后的入口残留import、旧说明和与现行UI脱节的断言。
- **不自动删除**：脏worktree、用户归档、旧事件文件、未确认归属的转发；先生成差异和恢复依据。

## 4. Worktree核对

本轮现场快照仅用于这次审查，后续必须重查：

- `X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/.tmp/daemon-main`：HEAD为main祖先=True，未提交6项。
  - `daemon/public/index.html`：工作文件与当前main不同，不能认定已合入。
  - `daemon/src/http/routes_runtime.ts`：工作文件与当前main不同，不能认定已合入。
  - `daemon/src/service.ts`：工作文件与当前main不同，不能认定已合入。
  - `panel/src/components/CapturePanel.vue`：工作文件与当前main不同，不能认定已合入。
  - `daemon/src/maps_view.ts`：工作文件与当前main相同（仍需核对索引／用途，不能直接删）。
  - `daemon/test/maps_view.test.ts`：工作文件与当前main相同（仍需核对索引／用途，不能直接删）。

- `X:/Project/github/DecryptHub-all/ADH/AndroidDecryptHub/.tmp/fix-copy-buttons`：HEAD为main祖先=True，未提交3项。
  - `panel/src/components/CapDetail.vue`：工作文件与当前main不同，不能认定已合入。
  - `panel/src/components/ExchangeDetail.vue`：工作文件与当前main不同，不能认定已合入。
  - `panel/src/style.css`：工作文件与当前main不同，不能认定已合入。

没有在本轮删除、搬移或提交这两个工作树的内容；没有把主目录可提交当作整个项目已经收尾。

## 5. 建议收尾顺序与验收

1. **连接基本盘（本轮已做）**：单机／双机，拔非当前设备，拔当前设备，换transportId，同serial重连，ADB连接代际整体重置，名册更新交叠，旧连接迟到关闭，陌生设备不自动接管，冲突作用域拒绝，仍在线的探测失败／路由别名继续拒绝。
2. **数据可靠性（下一优先级）**：修旧事件有界恢复；抓取断线30s/5min、峰值／磁盘慢／空间不足、Host退出后恢复。验收看记录ID连续性、丢失区间和真实磁盘数据，不看“页面有数字”。测试只写隔离目录，不对用户数据跑清理。
3. **即时性与状态统一**：相同样本1万／10万／更大规模，测首条可见延迟、滚动补页P95、控制命令延迟、内存／磁盘；先用测量定方案。设备状态分别验收，不把Agent未启动显示成手机离线。
4. **最后做旧逻辑收口**：只合并已确定重复的实现，逐个处理两个脏工作树和旧断言／说明。保持目前官网主题和工具栏，不再顺手扩大UI范围。

**验收边界**：80项是本轮相关自动化，不是全产品通过。当前手机实际验证只覆盖恢复连接和自己的沙盒读取；没有对第二台手机做物理拔插、没有对其他APP做采集或生命周期操作，也没声称LAN-only、所有算法、所有机型都测完。
