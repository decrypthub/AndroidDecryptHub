# P5 Android 沙盒验收与修复（2026-11-16）

首轮独立验收 **7 PASS / 0 FAIL**；最后一轮 capture/绑定验收与沙盒阶段收口见本文末节。设备为 PGP110、Android 15 / API 35、arm64-v8a、KernelSU，SELinux 保持 enforcing。使用独立 worktree，未安装或替换生产 Zygisk 模块、Manager、Device Daemon，未重启现有服务。

后续用户授权手机重启后，已完成[真实 Zygisk 调用链的隔离真机验收](P5_ZYGISK_ACCEPTANCE.md)。本文“不重启”与“正式链未验证”均是当轮 self-load 沙盒的历史边界，不代表后续验收没有执行。默认生产部署/升级继续未验证。

## 实测证据与边界

| 项目 | 实测结果 |
| --- | --- |
| Android 安装绑定 | 正式 `AndroidHookBinding` 验证 PackageManager UID、版本、APK signer、源文件信息、实际 Agent SHA 和 release 导出，支持状态为 true |
| 早期 GOT 命中 | 新包 `com.adh.p5sandbox` 先加载测试 so 和 Agent，调用正式 early-plan 导出，再调用测试 so 的 getpid，最后才启动 Agent 通道。回执 attempted=confirmed=1、installed=1、Hook ID=1；正式 native status 的 hits=1，返回值仍为该进程 PID |
| 缓存过期 | 真正等待秒级 TTL 到期，正式 root broker 返回 0 bytes；新沙盒进程无 early receipt、无 Hook |
| 绑定失效 | 实际把同一测试 APK 从 versionCode 1 更新至 2，Android APK 路径和版本变化；旧缓存不再交付，新进程无 Hook |
| 授权撤销 | 通过真实 LAN TLS 1.3 和配对 grant 暂存缓存，先证明确能命中；再经 USB 撤销该 grant，后续 broker 返回 0 bytes，新进程无 Hook |
| 显式缓存撤销 | CAS 撤销后，后续 broker 返回 0 bytes，新进程无 Hook |
| 旧配置回滚 | 自有 scope 的未知/退役字段保留。并发新增包后回滚被 STALE_SCOPE 拒绝；显式恢复本测试的迁移后版本后，再回滚，实际文件 SHA-256 与原始文本逐字节一致 |

“早期”在本验收中只代表 **真实 Android 沙盒 self-load 后、Agent 连接 Host 前**。测试调用正式 Agent 消费函数，broker 使用正式 root LocalSocket 服务，缓存/任务/RPC/配对/TLS 都走正式实现。沙盒只提供可确定的调用顺序和 getpid 触发器，不充当另一套 Hook 实现。

以下仍未验证：

- 正式 Zygisk 模块在 pre/post-specialize 中获取并投递缓存的整条路径、SELinux 对该 companion 的实际许可与时序；本次没有刷模块或重启手机。
- `.init_array` 前、Java 类加载前的命中保证；这些也不属于当前缓存协议承诺。
- 整机重启、生产模块更新、真实业务 App、Java/inline 早期步骤。后两种步骤当前明确 unsupported。
- 其他 ROM、所有算法/模块/布尔组合。本轮补齐七族代表性真实探针、UID 与 Agent 替换反例，见末节；这不代表穷举覆盖。

## 发现并修复的问题

1. **GOT 安装参数错误。** early consumer 把 errno 默认值传成 -1，正式 native primitive 只接受 0..4095。真实沙盒因此拒绝安装，之前只覆盖编码/解析骨架的测试没有发现。现改为 0，并在部分失败回执里保留有界、JSON 转义后的原生原因；正例由真实调用和 hits 证明。
2. **Android LAN 签名转义差异。** Android `org.json` 会转义 `/`，而 JVM 夹具和 Host `JSON.stringify` 的挑战文本不同。新 `DeviceRpc.lanProof` 固定线上的紧凑 JSON 字节，覆盖斜杠、反斜杠、控制字符、Unicode 和孤立 surrogate；不改变已有持久操作 hash。真实 Android TLS 配对认证和撤销已通过。
3. **enforcing 下 USB forward 被拒绝。** 内核审计明确记录 adbd → su Unix socket 的 connectto 拒绝。增加显式 `devices connect transport=adb usbMode=stdio`：root byte relay 连接同一个 UDS，仍使用 `adh.device/1`、同一个 bootstrap token、签名身份、设备代次、任务和去重账本。默认 forward 保留；无自动回退、重试、放宽 SELinux 或新增网络监听。

stdio 通过 `adb shell -T` 保持双向原始流。连接前只读检查 su 帮助；仅在实现明确提供 `--no-wrapper` 时选择 KernelSU `-W`。Android relay 使用原始 FileDescriptor，而非会被 app_process 重定向到 logcat 的 System.out；LocalSocket 在连接后才设超时。首轮 bootstrap 的 stdioVersion=1 只增加传输能力标记（最终轮升级为2，见末节），保留原身份和凭据；旧设备未声明时返回 unsupported。

## 隔离设施与复现

- `device/p5sandbox` 是 opt-in Gradle 模块，只有 `-PadhP5Sandbox=true` 才加入。self-load 入口使用新包名和前台 Service，不启动 Activity；后续真实 Zygisk 入口另用自身 Activity 保持前台/常亮，适用本轮用户的手机操作授权。
- `device/daemon/src/p5Fixture` 只有同一 opt-in 属性启用时编入测试 APK；不进入普通 bundle。它运行独立 root 进程，不发布 Binder，不使用 AndroidDeviceBackend，不能调生产启停/证书/宿主设置。
- 每次创建 `/data/local/tmp/adh-p5-<随机值>`、独立数据和 UDS 名；身份/授权/迁移账本在 root 私有 domain 目录。Host 使用独立数据、18088/18761。正式 8088/8761 映射不改写。
- 专用 Agent 构建把默认连接端口编为 18761；运行前核对 CMakeCache 和 APK 内实际 Agent SHA，防止新沙盒误连正式 Host。`build_agent.sh` 拒绝把自定义端口 Agent 用 `--deploy` 推出。
- `tools/verify_p5_device.ts` 显式接收 serial、transportId、构建资产目录、新输出目录。拒绝已有同名包和已占用端口；不默认选第一台设备。测试开始与结束核对原会话 ID/PID/进程代次、原 root daemon 与业务 PID、模块/配置哈希及 ADB reverse 映射。失败也记录 unknown，不把设备账本的晚到成功改称已确认成功。
- 测试只停止/卸载自身新包、关闭自身 Host/连接和 root fixture、删除自己建立的 reverse 映射；私有原始报告与失败诊断留在工作区外的 `.tmp`，不提交。设备 UUID 目录保留以便检查，其中无业务采集数据；不自动清理生产目录。

构建顺序（示例在 Windows Git Bash / PowerShell 中按现有 SDK 路径执行）：

1. `ADH_AGENT_CONNECT_PORT=18761 bash tools/build_agent.sh`，独立产物位于 `agent/build-isolated-18761/`，自动暂存到 `device/p5sandbox/src/main/jniLibs/arm64-v8a/`；不会覆盖正常端口的 canonical 产物。
2. `device/gradlew --offline -PadhP5Sandbox=true :daemon:assembleDebug :p5sandbox:assembleDebug`。保存 daemon.apk 与 versionCode 1 的 sandbox-v1.apk；再用 `-PadhP5SandboxVersion=2` 构建并保存 sandbox-v2.apk。只保存到自有资产目录，不刷模块。
3. `node tools/verify_p5_device.ts SERIAL TRANSPORT_ID PRIVATE_ASSETS NEW_PRIVATE_OUTPUT`。资产文件名是 daemon.apk、sandbox-v1.apk、sandbox-v2.apk。必须确保 SERIAL 是获准的专用 root 机；脚本不对日常机执行安装。

Host 自动回归通过 `tools/verify_v132_p5_stdio.sh` 注册到既有 host gates，覆盖真实 Kotlin dispatcher 的 stdio 认证、长二进制帧和旧能力拒绝。真机脚本保留为显式入口，避免 verify_all 自动重启共享沙盒的行为破坏现场。

最终原始报告在本机工作区外 `.tmp/adh-p5-android-run-24/report.json`，包含 7 个真实用例和 sceneUnchanged=true；run-23 同样为 7/7。此前失败报告保留，没有计为通过。它是本次有日期的验收证据，不能替代下次运行时重新选择设备和检查现场。

收口回归：Host typecheck 和 **558/558** 通过；Android JVM **70/70**（core23、daemon18、Manager29）；普通及 opt-in Android 构建通过，普通 APK 的 DEX 确认不含 P5 fixture、包含生产 stdio relay。原生正常/隔离端口构建、v132、94 项 MCP 注册及生成文档检查通过。

## 最后一轮：capture_start 与缓存绑定（2026-11-16）

在 `feat/adh-p5-final-sandbox-20261116`、基座 f7d726e 上补齐限定范围。仍为独立 Android self-load 沙盒，正式 Zygisk 模块和现有服务没有更新。七族逐一启用、每次执行全部七族探针，加全禁用对照、UID 变化、Agent 替换，共 10 个范围内用例，另加 stdio/2 的 256 次真实往返回归，总计 11 项。

| 捕获族 | 实际触发与捕获证据 |
| --- | --- |
| digest | AndroidOpenSSL SHA-256；EVP_DigestUpdate 中匹配本轮唯一明文 |
| hmac | HmacSHA256；HMAC_Update 中匹配唯一明文 |
| symmetric | AES/CBC/PKCS5Padding 加解密往返；EVP_CipherUpdate 匹配明文 |
| asymmetric | SHA256withECDSA 签名/验签；本机走 EVP_DSignUpdate_asym，匹配签名输入；同时观察 Final/Verify 回调 |
| tls | 仅连接独立 Root 域的临时 loopback TLS 端口；SSL_write 匹配本轮请求，SSL_read 返回 AUTH_FAILED，无授权或业务操作 |
| aead | AES/GCM/NoPadding 加解密往返；EVP_AEAD_seal_pt/open_pt 匹配明文 |
| system | 独立 libp5target.so 调用 access 检查不存在的唯一路径；命中 access 记录，无系统修改 |

每个新进程先预热真实系统 JCA provider，再应用早期缓存，在 **Agent 启动/连接之前**执行全部探针；测试回执验证运算往返/签名验签成功。匹配记录按精确 session 和唯一标记读取，检查完整窗口、累计 dropped/jdropped=0、backlog=0、complete=true。所有被禁用族的专用 GOT 安装计数均不大于 0，且对应探针没有记录；全禁用时安装总数为 0、记录为空，early 状态如实为 partial-or-failed，不把 unconditional ok:true 算作安装成功。

DigestSign Init/Update/Final/Verify 是 HMAC 与非对称族共用的导入：任一族启用时可为其安装共享基础 Hook，不能把共享槽描述成“另一个族绝无物理 Hook”。本轮要求并实测的是禁用族专用 Hook 不安装、共享回调不产生禁用族记录；两族均关闭时共享槽也不安装。

首轮发现仅 HMAC 启用仍泄出 ECDSA DigestSign 记录，修复 `capture.c` 四个共享数据回调的实际族资格判断，保持原调用和返回值。Agent hello 新增有界 `lastCaptureInstall`，保留最后一条 capture_start 的原始安装计数（非成功判定），相应扩大有界 status/hello 缓冲区。该字段不代表此前所有 capture 步骤或完整 Hook 清单。

缓存反例分两层验：

- **UID**：有效缓存先证实 GOT getpid 安装/命中；保存旧 wire，卸载/重装相同测试 APK，确认 OS 分配新 UID、Agent hash 不变。正式 broker 拒发（0 bytes）；把旧 wire 送入新进程，正式 Agent 依据实际 getuid 拒绝，native Hook 数为 0。重装也会改变 APK 源路径，因此不声称 Root 层仅 UID 一项变化；Agent wire 层的包名/Agent hash/有效期不变。
- **Agent 文件**：新缓存先证实命中，仅在已停止的自身测试包提取目录替换 libadh_agent.so（有效 ELF 追加测试尾标，机器码/ABI 不变），不更新 APK。AndroidHookBinding 确认 UID、版本、signer、APK 元数据完全相同，只有真实 Agent SHA 改变且 earlySupported 仍为 true。broker 拒发；加载新文件并重新取其实际 SHA 后消费旧 wire，被拒且无 native Hook。测试包 JNI 不信任启动参数提供的 hash。

复现：按前节构建隔离端口 Agent 和 opt-in APK，资产只需 `daemon.apk`、`sandbox-v1.apk`。执行 `node tools/verify_p5_device.ts SERIAL TRANSPORT_ID PRIVATE_ASSETS NEW_PRIVATE_OUTPUT final`。显式 `final` 模式复用同一隔离前置检查、正式 MCP/共享执行器和清理；默认模式仍为之前 7 项。测试只读采样自身 Host 的累计 ring 元数据，不读取生产捕获内容。

原始报告保存在本机聚合工作区外的 `.tmp/adh-p5-final-run-*`，不提交原始捕获、APK、so 或私有身份。run-01 复现串族失败；run-02 修复后 10/10 且 sceneUnchanged=true；run-03/04/05/06 的后续 RPC 超时均保留 unknown，不重发、不计为通过；Root 私有账本显示执行已完成，主线程栈显示等待下一个请求。run-07 为新增夹具断言字段取错，已修正，也不计为通过。

### 最终收口

另一个实际缺陷是本机 **Windows ADB shell 的 stdout 文本转换**：即使 `shell -T`、KernelSU `-W`，实际回包帧头 `00 00 09 0a` 会变成 `00 00 09 0d 0a`；用测试 wire 中原有 CRLF 做只读对照，exec-out 保持原字节、shell 多出 CR，`-x` 也不解决。帧长度被破坏导致 Host 等待缺失字节，业务已完成却只能报告 unknown。该结论来自自身测试流，不推断所有 ADB/平台均相同；[ADB 源码的 shell 输出与 exec-out 路径](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/commandline.cpp)也分开处理这些路径。

修复为显式 `stdioVersion=2`：两端对完整、有界的 adh.device/1 原帧做 Base64 行封装，读端只容许行尾 CRLF/LF，验证长度、规范 Base64、非 ASCII/半帧/超限并拒绝异常。USB 认证、签名身份、CAS、任务账本与错误状态不变。旧/缺失 stdioVersion=1 明确 unsupported，不自动降级、重连或重放。设备只升级能力标记，保留原身份与凭据；本次只在自身 fixture 进程运行新代码，未修改现有生产 bootstrap。JVM 互操作回归通过正式 Kotlin codec，并在 Host 端模拟 Windows LF 扩张；额外覆盖 1 MiB 上限和碎片/控制字节。

**最终实测**：run-08 与 run-09 各 **11 PASS / 0 FAIL / 0 UNKNOWN**；两轮 `sceneUnchanged=true`、`cleanupVerified=true`。自有 root fixture 退出、包已卸载、18088/18761 已释放，自有映射已移除；原在线会话/进程代次、业务/root daemon PID、模块/配置 SHA 和原映射前后一致。原始报告为本机聚合目录 `.tmp/adh-p5-final-run-08/report.json` 与 run-09 同路径，均在 git 仓外。所有失败记录保留。

Host 类型检查和 **560/560**（0 skip），Android JVM **73/73**（core26、daemon18、Manager29，0 skip）；默认/隔离 Agent 构建、普通/opt-in Device APK、v132、94 项 MCP 注册与生成文档检查完成。**P5 沙盒阶段在约定范围内收口**。仍未验证正式 Zygisk pre/post-specialize 全链、整机重启/生产升级、其他 ROM/真实业务 App，以及全部算法/模块/布尔组合；Java/inline 早期步骤继续 unsupported。self-load before-agent-start 的通过不替代这些验证。
