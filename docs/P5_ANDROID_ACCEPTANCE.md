# P5 Android 沙盒验收与修复（2026-11-16）

最终独立验收 **7 PASS / 0 FAIL**。设备为 PGP110、Android 15 / API 35、arm64-v8a、KernelSU，SELinux 保持 enforcing。使用独立 worktree，未安装或替换生产 Zygisk 模块、Manager、Device Daemon，未重启现有服务。

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
- 早期 `capture_start` 各捕获族、独立 UID 变更和 Agent 二进制替换的真机反例；本次真实绑定失效反例是 APK v1→v2。
- 真机的早期 `capture_start` 捕获族、单独替换 Agent 二进制或更换 UID、其他 ROM。此次早期命中正例是 GOT getpid，绑定失效反例是实际 APK 升级；不把它扩写成所有组合均已通过。

## 发现并修复的问题

1. **GOT 安装参数错误。** early consumer 把 errno 默认值传成 -1，正式 native primitive 只接受 0..4095。真实沙盒因此拒绝安装，之前只覆盖编码/解析骨架的测试没有发现。现改为 0，并在部分失败回执里保留有界、JSON 转义后的原生原因；正例由真实调用和 hits 证明。
2. **Android LAN 签名转义差异。** Android `org.json` 会转义 `/`，而 JVM 夹具和 Host `JSON.stringify` 的挑战文本不同。新 `DeviceRpc.lanProof` 固定线上的紧凑 JSON 字节，覆盖斜杠、反斜杠、控制字符、Unicode 和孤立 surrogate；不改变已有持久操作 hash。真实 Android TLS 配对认证和撤销已通过。
3. **enforcing 下 USB forward 被拒绝。** 内核审计明确记录 adbd → su Unix socket 的 connectto 拒绝。增加显式 `devices connect transport=adb usbMode=stdio`：root byte relay 连接同一个 UDS，仍使用 `adh.device/1`、同一个 bootstrap token、签名身份、设备代次、任务和去重账本。默认 forward 保留；无自动回退、重试、放宽 SELinux 或新增网络监听。

stdio 通过 `adb shell -T` 保持双向原始流。连接前只读检查 su 帮助；仅在实现明确提供 `--no-wrapper` 时选择 KernelSU `-W`。Android relay 使用原始 FileDescriptor，而非会被 app_process 重定向到 logcat 的 System.out；LocalSocket 在连接后才设超时。新 bootstrap 的 stdioVersion=1 只增加传输能力标记，保留原身份和凭据；旧设备未声明时返回 unsupported。

## 隔离设施与复现

- `device/p5sandbox` 是 opt-in Gradle 模块，只有 `-PadhP5Sandbox=true` 才加入。使用新包名和前台 Service，没有 Activity，不抢占原分析 App 的界面。
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
