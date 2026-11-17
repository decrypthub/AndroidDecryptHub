# P4：LAN、配对、TLS、授权撤销与断线对账（2026-11-16）

P4 在 P3 的安装身份和 `adh.device/1` 上增加 TLS 流。USB 和 LAN 进入同一个 dispatcher、设备业务服务、持久 revision 与操作日志，不建立第二套分析流程。AI 继续默认自主执行；人类凭据、接管、暂停和版本冲突仍由同一 Host 协调器处理。

源码在 `feat/adh-p4-lan-20261116` 独立 worktree，基于 P3 `258e69a`。本轮没有部署到当前实例，没有启动正式 index、执行真实 ADB、重设 reverse/forward、安装 APK、启停目标或重启当前分析服务。

LAN 需要配套 P4 Host/Device，不能只替换一端或静态页面。P4 Host 可以查询旧设备已广告的子集；P3 Host 的严格能力校验可能拒绝 P4 新能力，需要明确升级。现有 Binder transaction 顺序/v19 与 target agent 协议不变；本轮不安排现场升级。

## 模块与信任边界

| 模块 | 实现 |
|---|---|
| Device `DeviceTls` | 用安装 RSA 密钥签发独立 TLS 证书，公共 JCA/JSSE API；不使用 Android 不支持的 sun.security.x509，不安装系统 CA |
| Device `DeviceNetwork` | 默认关闭、显式配置的 TLS listener，持久配置恢复、实际 listening/port/startupError、有限连接/线程、撤销后关闭流 |
| Device `DevicePairings` | 有界持久 grant、公钥/权限、撤销 tombstone；授权存储失败关闭后续认证，不丢弃损坏文件 |
| `DeviceRpcSession` / `DeviceOperations` | USB token 和 LAN 客户端证明分别认证，复用帧、业务、代际/CAS、去重与日志；权限在域锁内、每次派发前检查 |
| Host `device_client_identity.ts` | 显式配对时生成本机 RSA 客户端密钥；完整写入后排他发布，多个 Host 不能相互覆盖；损坏不自动重建 |
| Host `transport/device_transport.ts` / `lan_device.ts` | 统一认证连接接口、TLS 身份固定、挑战证明；无 ADB 调用或自动重连/重放 |
| Host `Devices` / `device_host` | USB/LAN 合并同一 deviceId，显式连接选择、配对/采用已观察 grant、对账证据落盘；公共 MCP/REST/CLI 入口共用 |
| Host `operations` / `task_store` / 工作台 | 窄范围连接恢复/安全收缩、多个 unknown、对账历史、版本确认失效与结果下载 |

手机仍只有设备控制和有界协调记录，没有 HTTP/MCP、数据库、反汇编、索引或 AI 工作流。设备 TLS 证书、Host 客户端证明、Manager APK 签名和用户导入的系统 CA 是四种不同用途，不互相替代。

## 配对与 TLS

采用 **可信 USB 首次登记**，不是未认证网络上的自动信任：

1. 通过 P3 的已验证 USB 连接，Host 获得稳定 deviceId/身份公钥指纹。USB bootstrap token 只用于本地 UDS，LAN 拒绝 usb-token 认证。
2. `devices action=pair` 生成/读取 Host 私钥，并将公钥和明确权限提交到设备的 `pairings.grant`。返回 grantId、clientId、公有权限；私钥不进入工具参数、任务、设备缓存或响应。默认 `read,write`，需要远程管理时显式加入 `manage`。
3. 设备 `lan.configure` 显式开启数字地址和端口，生产默认端口 8762；出厂配置 enabled=false。测试只在 127.0.0.1 随机端口运行。保存 enabled=true 后，新 Device Daemon 启动会恢复它；失败报告 LAN_START_FAILED/listening=false，USB 仍可查询。
4. Host `connect transport=lan` 指定已配对 deviceId 和数字 address/port。首次成功后保存“已验证过的端点”；以后可以省略地址/端口，仍然需要明确 connect，不在启动时自动拨号。

TLS 只允许 1.2/1.3，使用 TLS 1.3 AEAD 或 ECDHE-RSA 的 GCM/ChaCha20 套件。Host 对自签安装证书不使用公网 CA/主机名信任，必须在发送任何 RPC 或客户端证明前检查 **SPKI SHA-256 固定值、自签验证及证书有效期**。错误设备、明文或身份变化都会失败，不退回无 TLS。原理依据见 [JSSE 参考](https://docs.oracle.com/en/java/javase/17/security/java-secure-socket-extension-jsse-reference-guide.html) 与 [Node TLS API](https://nodejs.org/api/tls.html)；TLS 证书不会因为用户在系统证书页导入了别的 CA 而被信任。

TLS 建立后先执行 `device.challenge`，设备每条流只发一个 256-bit 随机挑战。Host 用自己的 RSA 私钥签署以下 JSON 数组的 UTF-8 字节，作为 device.hello 的 client-signature：

```text
["adh.device/1", "lan-auth/1", deviceId, bootId, daemonInstanceId,
 serverChallenge, clientNonce, helloRequestId, clientId, grantId]
```

设备检查 grant 有效性、clientId、公钥签名及整条挑战。原 P3 的设备签名 hello 仍绑定 nonce、代际与能力。旧挑战或另一个 grant 的证明不能重放；初始认证限时，空闲连接也有读超时。它是服务端 TLS 身份认证加应用层公钥认证，不声称采用 mTLS 客户端证书。

设备身份仍是安装身份，不是硬件证明。复制整个安装私钥目录无法凭本协议证明属于另一件硬件；P3 的双活代际冲突拒绝继续保留。

## 权限与撤销

| 权限 | 能力 |
|---|---|
| `read` | 身份/信息/状态、普通能力、模块、作用域、应用/进程/证书/Host 地址、操作结果与对账 |
| `write` | scope patch/replace、第三方进程控制、CA 保存/删除、Host 地址修改；仍需 Host 和设备状态版本 |
| `manage` | 配对清单/授权/撤销、LAN 配置及设备 unknown 人工核对；不自动获得 write |

每个 grant 至少需要 read。USB 是经 root bootstrap 验证的管理通道；LAN 的签名能力表按 grant 过滤，未授权方法列入 deniedMethods。Host 返回 PERMISSION_DENIED，设备在同一个域锁内再次检查，不能靠旧 hello、旧 connectionId 或重放操作 ID 绕过授权。

`pairings.revoke` 必须给明确 grantId。先持久保存 revokedAt，再关闭该 grant 的既有流；之后的认证和派发均拒绝。撤销记录保留，重启不会恢复授权。再次登记同一个客户端需要新 grantId；不把旧撤销记录改回有效。不承诺撤回已经派发的方法或中途取消 Android 系统调用。

从当前 LAN 流撤销自己，或关闭当前 LAN listener，会先切断响应：Host 保持 unknown，不能伪造“已收到成功确认”。可以从另一条仍获授权的连接/USB 查询设备操作记录。配对响应或 Host 保存未确认时，同样先查询；`devices pair grantId=<已观察 ID>` 会经已验证 USB 检查该 grant 确实属于本机密钥且未撤销，再保存 Host 登记，不重复授权。

权限以设备为准。Host 清单里的 pairing 是**缓存登记**，不证明当前仍获授权；每次 LAN 请求都会重新检查。遗失或损坏 Host 私钥不会自动换一把密钥继续连接，必须通过可信路径重新登记。设备 pairings 上限 256 条/512 KiB，包含撤销历史，无自动清理或在线归档。

## USB/LAN 能力对等矩阵

下表针对新设备 RPC，权限足够时两条传输调用同一实现。

| 能力 | USB | LAN | 证据/限制 |
|---|---|---|---|
| 设备/模块/应用/进程查询 | 支持 | 支持 | 无目标 agent 也可查询；进程完整性按实际返回 |
| scope get/patch/replace | 支持 | 支持 | 相同 scopeRevision、设备 revision、完整策略保留；不自动重启 |
| 第三方进程 open/stop/restart | 支持 | 支持 | 相同 PID/UID/starttimeTicks 检查；实机 Android 效果本轮未测 |
| 用户 CA 列表/保存/删除 | 支持 | 支持 | 同一业务、pendingReboot；不远程重启；实机挂载未测 |
| Host endpoint | 支持 | 支持 | 原子保存，不强制现有目标重连 |
| operations get/reconcile/resolve | 支持 | 支持 | resolve 仍需人类身份；LAN 还需 manage |
| LAN 配置、grant 管理/撤销 | 支持 | 支持 | LAN 需 manage；Host pair 简化入口要求可信 USB |
| agent Hook/内存/主动调用/trace/dump | unsupported | unsupported | 旧 agent 通道未迁入设备身份域 |
| runtime diagnostics/fs/root helper | unsupported | unsupported | 旧 ADB-only 路径未迁移，不伪装 LAN 能力 |
| bulk、自动路由/重试、广播发现、无 USB 首次配对 | unsupported | unsupported | 不制造部分成功或隐式替代 |

同一 deviceId 的 USB/LAN 只占一个设备条目，连接各有 connectionId。多条活连接必须显式选择；任何写入都不因某条连接断开而自动换路。新 Device Daemon 不改变旧 target agent 的归属，旧 session 仍是 legacy/unverified。

`devices call` 未知方法返回 UNSUPPORTED_METHOD，未安装的已知能力返回 CAPABILITY_UNSUPPORTED。给旧 MCP/REST 能力附 deviceId、connectionId 或 transport=lan 会返回 UNSUPPORTED_DEVICE_ROUTING，避免旧工具忽略设备选择后继续走 ADB。调用旧 session 的既有工具仍是明确的 legacy 路径，不能据此宣称设备域 LAN 对等。

`discover transport=lan` 只列已经验证过的端点，明确标记 last-known/not-probed，不扫描网络、不宣称在线。list 也是缓存视图；connect 和 live info 才建立/查询认证连接。

## 断线、超时与对账

P3 的持久 operationId reservation、内容指纹、代际和 revision 保留：同一设备操作 ID 不能重新派发另一份意图；重启将 running 恢复为 unknown。LAN 不增加自动重试、写入重放或 exactly-once 的虚假保证。reservation 后、业务前崩溃也可能留下 unknown；这不证明一定执行过。

- `devices action=reconcile operationIds=[...]` 先核对 Host 操作确实属于所选设备，再以设备只读 `operations.reconcile` 查询，最多 100 个 ID。结果集合必须精确对应请求；错误设备或不合规结果不附加证据。
- 对账作为 Host analysis 操作保存结果，并把每条设备证据附到原操作。最近 8 次索引持久保存，旧文件不自动删除；遵循原结果 8 MiB 省略策略。更新任务元数据版本，**不修改原终态、不解除隔离、不恢复任务**。
- 设备返回 succeeded/failed/unknown 或 found=false。found=false 明确不是“证明未发送”，更不是自动重试许可。新 boot 上仍可读取旧 boot 的持久记录。
- 网络中断后的 connect/disconnect 使用静态 connectionOnly 分类：仍受 Host CAS、人类控制和串行协调约束，但允许在 unknown 下恢复查询通道；该上下文禁止派发设备修改。
- 撤销授权、明确 enabled=false 的 LAN 关闭属于 securityOnly 收缩，可在 unknown 下执行；上下文拒绝把它换成启用 LAN 或其他写入，设备也单独执行相同限制。普通写入仍被隔离，不允许通过伪造请求标记绕过。
- 同一范围可能因原操作和自身撤销出现多个 unknown。Host 保留全部 ID，新的 unknown 推进控制版本；人工核对必须基于当前版本、覆盖已显示的全部未知操作，仍在等待的 Host handler 不能解除隔离。核对保留每条原 unknown，任务只变为暂停，不自动重放或恢复。

工作台增加缓存设备范围选择、多未知记录入口、对账证据预览/下载；版本变化清除已勾选的人工确认。证据作为纯文本显示，目标字符串不解释为 HTML。

## 公共调用顺序

所有写入继续用 Host `_operation.expectedRevision/controlEpoch/hostEpoch`，由现有 `adh run` 获取 Host snapshot/submit；设备 bootId、daemonInstanceId、expectedDeviceRevision 必须来自本次观察，不在提交时偷偷刷新旧意图。

1. `devices discover transport=adb`，再 `connect transport=adb serial=... transportId=...`。
2. 查询 device.state，`call method=lan.configure params={enabled:true,address:"0.0.0.0",port:8762}`。
3. 查询新 stateRevision，`pair deviceId=... connectionId=<USB> permissions=["read","write","manage"]`。需要最小权限时仅给所需项。
4. `connect transport=lan deviceId=... address=<手机局域网 IP> port=8762`。如 USB 仍在线，后续调用明确 LAN connectionId；准备好后可断开自己的 USB RPC 连接，再拔 USB。不会改变原分析通道的 reverse。
5. 断线后明确恢复连接，`reconcile deviceId=... connectionId=... operationIds=[<Host ID>]`；核对实际设备结果与工作台证据后，由人类决定解除隔离和下一步。

可以用 `adh run devices --arguments '<JSON>'` 提交 connect/pair/call；list/info/capabilities 用现有 call。对账同样可用 run（Host analysis）或 MCP/REST。REST `/api/devices` 使用相同 action/参数及 X-Adh-Operation；没有新 CLI 业务实现或客户端包发布。

Host 新增私有 `ADH_DATA_DIR/device-client.json`，设备新增 `device-rpc/pairings.json`、`lan.json`、`tls-certificate.der.b64`，沿用 P3 root 目录及原子文件策略。POSIX 私有文件为 0600；Windows 依赖现有数据目录 ACL。备份/迁移时保留客户端与安装密钥，不将私钥复制进日志、工单或源码。

## 隔离验收与剩余限制

构建/验收命令沿用 [P3_DEVICE_DOMAIN.md](P3_DEVICE_DOMAIN.md) 的离线 Gradle 任务、classpath 清单和 npm launcher，必须**先完成构建再启动 JVM Host 测试**，Windows 正在使用的 classpath JAR 不能同时替换。测试只用合成 backend、临时数据目录和 loopback TLS，完全禁用真实设备操作。

- Host 类型检查通过；完整 **547 passed / 0 failed / 0 skipped**，P3 基线 538 + P4 新增 9。真实 Node↔生产 Kotlin TLS 流验证配对、通道能力/身份一致、禁 ADB 后独立运行、只读权限、既有连接撤销及重启持久化、错误证书/明文/重放拒绝、响应丢失和设备中途退出后的对账与派发计数为 1，以及 MCP/REST/真实公共 Python CLI 路径、旧路由拒绝、Host 并发密钥创建。
- Android JVM **66 passed / 0 failed / 0 skipped**：core 22、daemon 16、Manager 28；Device Daemon debug 构建、Manager Kotlin 编译通过。只使用全零隔离测试 pin，产物不发布/安装。
- ego-browser 随机端口验收并查看截图：对账保持原 unknown，HTML 作为纯文本，下载完整已保存证据，多未知分别展示，控制版本改变清除确认，人工核对及交还不自动恢复任务。浏览器和本轮 fixture 已关闭。

**未验证**：Android JSSE/provider、UDS/SELinux/防火墙的真机可达性、真实无线链路、真实 Binder/应用启停/系统 CA 效果。本轮不能替代专用测试设备的发布前验收。Android/API 差异导致 TLS 无法启动时明确返回实际未监听状态，不放宽身份校验或退到明文。无网络配对 UI/广播发现、证书在线轮换、grant/日志在线归档、bulk 与 agent/ADB-only 能力迁移；以上保持明确 unsupported，后续按单项证据推进。

未更改当前分析服务或真机；交付的是隔离验证过的源码提交。
