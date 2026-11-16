# P3：设备域、稳定身份与 USB RPC（2026-11-16）

设备控制从传输中拆出：手机现有 Device Daemon 的 `DeviceOperations` 由签名校验后的 Binder 与 USB RPC 共用，Host 的 `Devices` 管理经过验证的安装身份、能力和连接。AI 默认拥有规划和执行权；不需要固定 recipe 或每次人工确认。人类的修改、暂停与接管继续由 P1/P2 的操作协调器约束。

本轮在 `feat/adh-p3-device-domain-20261116` 独立 worktree 开发并验证，不发布、不部署、不替换当前进程或静态资源，不执行任何真实 ADB 命令，不调整现有 reverse/forward，不关联或迁移正在运行的 target session。

## 模块与边界

| 模块 | 职责 |
|---|---|
| `device/:core` 的 `DeviceRpc` | `adh.device/1`、方法效果表、帧编解码；AIDL v19 在末尾追加身份/能力/作用域快照及 CAS 方法，保留旧 transaction 顺序 |
| `device/:daemon` 的 `AndroidDeviceBackend` | 模块、应用、作用域、进程、证书与 Host 地址业务；Binder 不再复制这些实现 |
| `device/…/device/DeviceOperations` | 单写入锁、持久 revision、操作意图去重、预先落盘、未知隔离；Manager 旧写入也推进同一 revision |
| `DeviceIdentity` / `DeviceFiles` | 明确初始化、持久 UUID/身份密钥、USB 凭据；原子替换、文件/目录 fsync；损坏不重建 |
| `DeviceRpcSession` / `LocalDeviceRpcServer` | 与传输无关的 dispatcher；当前适配 Android abstract UDS，限制 peer UID、帧和工作线程 |
| `daemon/src/device_protocol.ts` | 同一协议的 Node codec、签名校验、有界 pending、超时与断线，不重连或重放 |
| `daemon/src/transport/adb_device.ts` | 显式发现、固定 transport、可信 USB bootstrap、创建与清理自己拥有的 forward |
| `daemon/src/devices.ts` / `device_host.ts` | 持久设备清单、临时连接、身份去重、代际失效与显式能力调用 |
| MCP `devices` / REST `/api/devices` | 同一操作分类和执行器；公共 Python CLI 的 `call` / `run` 无需增加第二套业务逻辑 |

手机不增加 HTTP、MCP、数据库或逆向分析。设备操作日志是有界 JSON 协调记录；采集、索引、反汇编、任务工作流仍在 Host/Harness。进程 RPC 仅提供现有第三方应用控制，不恢复已退役的 UI 自动化。

## 身份与可信建立

- `deviceId` 是首次初始化时生成的安装 UUID，与 RSA-2048 身份密钥共同保存在 `/data/adb/adh/device-rpc/identity.json`。目录 0700、文件 0600；不使用 ADB serial、Android ID、型号、目标 PID 或 session ID 代替设备身份。
- `/data/adb/adh/device-rpc/usb-access.json` 只含 schema、deviceId、公钥 SHA-256 指纹与随机 USB token，不含私钥。Host 通过明确选择的已授权 root ADB transport 读取；token 只在本次内存握手使用，不写入 Host 设备缓存、任务或输出。
- `bootId` 来自内核 boot_id；每次 Device Daemon 启动另生成 `daemonInstanceId`。主机要求每次写入带上已观察的两种代际；重启不会把旧指令重新绑定到新实例。
- hello 的 RSA/SHA-256 签名覆盖客户端 nonce、请求 ID、协议、设备/代际、信息与能力。Host 验证签名和 bootstrap 指纹，再对照已保存的 deviceId→指纹，不静默覆盖身份。
- 多条 USB/ADB 连接可以合并为一个设备；有多条活连接时必须给 connectionId，不自动选路或故障切换。相同身份同时声明不同活 boot/daemon 代际会被拒绝。断线后保留清理句柄，便于显式断开并核对 forward。

这是安装身份，不是硬件证明。离线复制整份身份目录的两个系统不能仅凭公钥区分；在线代际冲突可检测。删除安装身份会成为新设备，Host 不通过 serial 自动合并。身份或日志损坏必须人工核对备份，不能自动删除后继续执行。

## 传输与协议

设备端只监听 `localabstract:adh_device_rpc_v1`，检查 peer UID 为 root/shell，并验证 USB token。手机不开放 TCP/LAN 监听。Android 的 [LocalSocket](https://developer.android.com/reference/android/net/LocalSocket) 提供 peer credentials 和读超时接口；本机只完成编译与 JVM 协议测试，未把 Android socket/SELinux 行为当作已通过的真机结论。

Host 显式执行 `adb devices -l`，保留 device/offline/unauthorized 状态。连接会重新核对发现结果，用 `-t transport_id` 固定设备；旧 adb 不返回 transport_id 时才使用发现到的精确 `-s serial`。创建方式是 `forward --no-rebind tcp:0 localabstract:adh_device_rpc_v1`，符合 [AOSP adb 命令约定](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/commandline.cpp)。不会调用 reverse、remove-all、kill-server、安装或重启。

清理时重新检查原 transport，以及 serial/本地端口/远端 socket 三者完全匹配的映射；只移除自己创建的映射。原 transport 消失或映射已被替换时，留下不属于自己的映射并报告清理未确认。Host 正常缓存恢复不会发现、连接设备或自动清理任何映射；Host 进程异常退出可能留下自己的 forward，需要之后明确核对。

帧为 `[4 字节大端长度][UTF-8 JSON]`，上限 1 MiB。它与原 target agent 协议不同。请求示意：

```json
{
  "protocol": "adh.device/1",
  "id": "unique-request-id",
  "method": "scope.patch",
  "target": {
    "deviceId": "observed-installation-uuid",
    "bootId": "observed-kernel-uuid",
    "daemonInstanceId": "observed-daemon-uuid"
  },
  "params": {"scopeRevision": "observed-sha256", "add": ["com.example.fixture"]},
  "meta": {"operationId": "host-operation-uuid", "expectedRevision": 7, "actor": "ai", "budgetMs": 10000}
}
```

实际 UUID/哈希必须来自观察，示例字符串不能直接执行。响应以相同 id 返回 `{protocol,id,ok,result}` 或 `{protocol,id,ok:false,error:{code,message,uncertain}}`。方法效果由静态表与签名能力共同决定，不能用调用者的 `status` 或 `read` 字段把写入伪装成读取。新传输只需提供经过认证的流，复用 codec、dispatcher、身份及业务方法；P4 还必须实现配对、TLS、撤销和连接权限，不能把 USB token 直接当成公网认证方案。

## 能力、状态与副作用

| 方法 | 效果 | 前提/返回 |
|---|---|---|
| `device.info` / `device.capabilities` / `device.state` | 读取 | 身份、代际、设备信息、方法表、stateRevision；无目标进程也可查询 |
| `module.status` | 读取 | 模块存在/加载标记/版本 |
| `scope.get` | 读取 | 完整 document、原文 SHA-256 scopeRevision、stateRevision |
| `applications.list` / `processes.list` | 读取 | 分页与 nextOffset；进程返回 PID/UID/starttimeTicks、不完整状态 |
| `certificates.list` / `host.get` | 读取 | 当前证书及 pendingReboot、Host endpoint |
| `operations.get` | 读取 | 设备端按 Host operationId 查询持久实际结果；不重发执行 |
| `scope.patch` | 写入 | scopeRevision CAS，只改 packages，保留完整策略/未知字段，不重启目标 |
| `scope.replace` | 写入 | scopeRevision CAS；规范化已知策略键，保留并合并扩展字段；不自动注入/重启 |
| `process.control` | 写入 | 明确第三方包、open/stop/restart、expectedProcesses 的 PID/UID/starttimeTicks 集合；调用前复查，不声称有内核原子 CAS |
| `certificates.put` / `certificates.delete` | 写入 | 有界 CA 字节/受限文件名；标记需重启，不远程重启 |
| `host.set` | 写入 | 合法 endpoint，原子保存；现有目标不会因此自动重连 |
| `operations.resolve` | 写入 | 已认证人类、明确未知操作 ID 与 acknowledge；保留原 unknown 历史 |

每个 RPC 写入同时要求：Host `_operation.expectedRevision/controlEpoch/hostEpoch`、`device:<UUID>` 资源、已观察 boot/daemon 代际，以及 `expectedDeviceRevision`。作用域另要求 scopeRevision。结构非法在设备业务派发前拒绝；磁盘 reservation 未持久化不派发。已派发后结果持久化失败返回未知并关闭后续写入，重启从预留记录恢复 unknown，绝不重放。

Device Daemon 的全局单写入锁协调 Binder/RPC。旧 Manager 不强制升级 UI，每次旧写也推进设备 revision，因而旧 AI 指令会失效；新增 AIDL CAS 供后续 Manager 编辑器采用。外部旧 Host/直接 ADB 文件写入不经过该锁，scopeRevision 可发现检查前的变化，不能承诺与任意外部文件写入之间有原子事务。

设备日志限 1024 条/2 MiB，不自动删除历史；单结果超过 32 KiB 保存省略摘要、大小和哈希。达到限制拒绝新写入，本轮没有在线归档 API。人工维护需要先安排隔离/停止对应新实例并核对备份，不能在当前分析现场删除日志。只读查询仍可使用。

Host 以 `device:<UUID>` 作为独立控制范围；两个已验证设备可并行。原 agent session 仍没有可验证设备归属，因此旧 target 与新设备写入保守互斥；其中一边被人类持有或有未知副作用时，AI 不能从另一边绕过。不会根据“当前只有一台 ADB 设备”推断归属。工作台可从该设备操作的任务详情选择“查看此范围控制权”，继续查看副作用、接管或交还 AI。

## 公共入口与 AI 工作流

1. `devices action=list` 读取 Host 缓存，明确 lastKnown/online；不会进行 ADB 操作。`discover` 才显式发现传输。
2. `operations action=snapshot tool=devices arguments={action:connect,serial,transportId}` 得到 Host 版本，然后提交 connect。现有公共 CLI 可使用 `adh run devices --arguments '<JSON>'` 自动走相同 snapshot/submit；连接不是注入或重启。
3. 用返回的 deviceId 查询 `info`、`capabilities`、`device.state` 和 `scope.get`。读取失效/缺能力时先诊断，不能偷偷回退 ADB 或切换另一连接。
4. 给 `adh run devices --arguments '<JSON>'` 的 arguments 填 action=call、deviceId、method、params、bootId、daemonInstanceId、expectedDeviceRevision。Host `run` 只负责 Host 状态版本，不替调用者刷新设备版本或重写意图。
5. 用任务/操作 ID 读取结果，超时或断线后用设备 `operations.get` 查询实际执行，不重发原命令。设备预算最多 60 秒，预算在设备等待锁后也会检查；执行中的 Android 调用不能保证被取消。

REST 的 GET/POST `/api/devices` 接收同一 action/参数，写入携带 `X-Adh-Operation`；MCP/CLI 参数使用 `_operation`。operator 身份只来自 Host 凭据，RPC meta 从执行上下文产生，调用参数不能伪造 actor。相同幂等意图键跨 REST/MCP 取回同一 Host 操作，不再执行。

未知处理：先观察设备 `operations.get`、scope/进程事实及 Host 副作用，再由人类显式核对 Host unknown；设备日志若也有 unresolved unknown，继续由人类在设备资源持有状态下调用 `operations.resolve`。两层历史均保留；核对不等于宣布原调用成功。已派发请求超时后不故障切换、不自动重试，也不声称目标已取消。

## 验证与未验证项

```powershell
cd device
.\gradlew.bat --offline :core:testDebugUnitTest :daemon:testDebugUnitTest :manager:testDebugUnitTest :daemon:assembleDebug :manager:compileDebugKotlin :daemon:writeDeviceRpcFixtureClasspath -PadhManagerCertSha256=<64-hex-test-pin>
cd ../daemon
$env:ADH_CLI_SOURCE='<adh-cli repo>/src'
npm run typecheck
npm test
cd ..
node tools/generate_mcp_docs.mjs --check
```

本轮用全零测试 pin，仅生成隔离构建产物，不可发布/安装。JVM classpath 清单是忽略的 build 产物；测试探测不到它时明确 skip，绝不转用真机。完整验收前先构建清单；本轮跨语言用例确实执行，未 skip。

- Host 完整回归 **538 passed / 0 failed / 0 skipped**，含生产 Kotlin/Node codec、签名握手、双设备隔离、USB 别名去重、旧 boot 拒绝、Host 代际失效、凭据错误清理、超时后设备结果查询、MCP/REST/公共 Python CLI 同资源与 CAS、人类接管。
- Android JVM **61 passed / 0 failed / 0 skipped**：core 22、daemon 11（含设备域 10）、Manager 28；Device Daemon debug APK 构建、Manager Kotlin 编译通过。包含共享 Binder/RPC 服务的 revision/去重、磁盘失败、崩溃 unknown、作用域策略与帧限制。
- ADB 适配器由本机 loopback 代理模拟，设备域/编解码/持久化运行生产 Kotlin 实现；未测试 Android UDS 的真机 SELinux 可达性、真实证书挂载、真实第三方应用启停、旧 Manager Binder 的实机调用。
- LAN/TLS/配对撤销、bulk、agent 本地路由和旧 ADB-only 诊断/helper/fs 迁移均明确未实施。原审计附录 P3 的 agent 本地 UDS/fd/SELinux 原型仍待专用设备验证，不能把本轮构建和 JVM 信号当成该原型通过。

当前在线服务与原工作目录保持原状；交付的是已验证并提交的源码，不是当前分析实例升级。
