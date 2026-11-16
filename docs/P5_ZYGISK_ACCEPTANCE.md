# P5：真实 Zygisk 投递链隔离验收（2026-11-16）

最终 **6 PASS / 0 FAIL**，`cleanupVerified=true`、`originalHostAndFilesUnchanged=true`。设备为用户本轮明确授权可重启的 aa165071，PGP110 / Android 15 API35 / arm64-v8a / KernelSU，Zygisk Next 1.5.2，SELinux 保持 enforcing。使用独立 `feat/adh-p5-zygisk-e2e-20261116` worktree，基座 efe8e78。

这是**真实 Zygisk 回调、companion、Root broker、Agent 消费与命中链路**的实测；不是测试 App 主动 dlopen Agent。默认生产目录的部署/升级仍未进行。此前 self-load 沙盒结果保留于 [P5_ANDROID_ACCEPTANCE.md](P5_ANDROID_ACCEPTANCE.md)。

## 验收范围和证据

| 项目 | 实测与判定 |
| --- | --- |
| companion 获取 | 系统启动真实加载临时 Zygisk 模块，框架调用正式 companion。正式 Root EarlyPlanBroker 校验 root peer，读取正式 HookPlanCache。companion 审计包含包名、实际目标 UID、非零 wire 长度；没有测试端代推 wire |
| post-specialize 应用 | 正式 pre 回调经 getModuleDir/openat 保留 Agent FD，post 回调复制为 memfd、计算实际加载内容 SHA、调用 adh_agent_apply_early_v1，再启动 Agent。目标 UID 与 PackageManager、Agent hello 一致；自身 App 调试文件保留 result=1、before_agent_start=1 的 post 审计 |
| Application 首次测试调用 | 测试包不调用 bootstrap/early export、不自行加载 Agent；Application.onCreate 内用 System.nanoTime 夹住 android.system.Os.getpid。libjavacore.so/getpid 的 NATIVE_HOOK 事件须属于本次 session、Hook ID、主线程，tsNs 落入该窗口；原返回 PID 与服务 PID 一致。状态还要求 GOT slotCurrent= replacement，不能只凭历史 hits |
| TTL 过期 | 真正等待缓存过期，实际 companion 返回 0 bytes；新进程 earlyPlan=null，native Hook 数为0 |
| 显式撤销 | CAS revoke 后实际 companion 返回0，新进程无早期 Hook |
| UID 变化 | 相同测试 APK 卸载/重装，实际 UID 改变而 Agent SHA 不变；旧缓存不再交付，新进程无 Hook。重装同时改变 APK 源路径，不声称 Root 层只有 UID 一项变化 |
| Agent 文件替换 | 仅替换临时模块的 Agent 文件（有效 ELF 追加测试尾标），APK/UID/版本/signer/源文件元数据不变、earlySupported仍true，只有 Agent SHA 改变。真实模块 FD/memfd 路径仍加载新 Agent，旧缓存被拒、无 Hook |
| broker 不可用 | 有效缓存先证实命中，再正常关闭自身 Root fixture；实际 companion 交付0 bytes，新 Agent 不启用默认 Hook |

六个用例中，第一个合并验证投递、应用与首次调用命中；后五个分别验证五类拒绝。正例在绑定反例之前重新执行，避免把“一直没加载成功”误算成拒绝成功。`earlyPlan` 仍是 Agent 自报历史回执，不因此成为已认证的设备/session 绑定。

`/proc/self/maps` 中的 jit-cache 字样只是辅助事实，ART 自己也使用同名 memfd；它不能单独证明 Agent 已加载。上述通过依赖实际 Agent hello、companion/post 回执、精确调用窗口内的 Hook 事件和当前 GOT 值。

## 隔离和副作用

- 临时模块 ID 为 `adh_p5_<12hex>`，只有 Zygisk so 和隔离端口 Agent，无生产 installer/action/service/post-fs-data 脚本。状态目录 `/data/adb/adh-p5-<12hex>`、broker `adh_p5_<12hex>_early`、Root RPC/数据及 Host 18088/18761 均独立；作用域只含 com.adh.p5sandbox。
- `injector/zygisk/fixture` 编译**同一个 main.cpp**，只覆盖状态目录和 broker 名称。默认构建继续使用 `/data/adb/adh`、`adh_early_plans_v1`，与 Device/core 契约不变；默认目标也编译并核对真实 ELF 中的契约字符串。最终在原构建目录重建的测试 so 与实测 so 逐字节一致。
- 手机重启是本轮用户的新授权，明确不同于此前“不得重启手机”的沙盒限制。每轮加载和卸载各重启一次；这会终止手机原进程，不承诺保留其内存现场。首次操作前原 Host 没有在线 Agent；电脑端现有 Host 从未被重启。
- 清理卸载自身测试包、关闭自身 Host/Root fixture、核对 nonce 所有权后删除自身临时模块，再重启手机确保卸载生效。入口只支持保留既有 TCP reverse，其他类型在设备写入前拒绝。原有 TCP reverse 映射按原端点恢复，冲突时不覆盖。原 scope、host.endpoint、Agent、Zygisk so、daemon.apk、module.prop 共六个文件 SHA 前后一致；原 Host PID/启动时间及映射一致，隔离端口释放。
- 私有 nonce 诊断目录保留，Root domain 权限仍为私有。APK/so、捕获、内存地址、任务身份和原始报告均不提交。全程未关闭 SELinux、未改系统冻结策略、未对真实业务包执行启动/force-stop。

## 发现的问题和修正

1. **临时模块文件标签。** 单纯 mkdir/cp 得到 adb_data_file，无法照搬正常模块加载假设。夹具按原模块实际上下文设置自身目录的 system_file、so 的 system_lib_file；不扩大 SELinux allow。首轮未收到 Agent hello，不计通过。
2. **日志和探针不能冒充命中证明。** 本 ROM 的该阶段 logcat 为空；夹具预备自身 cache 目录，使用已有显式调试文件通道保存 post 审计。增加 companion 的 bytes/UID 和 post 的结果/实际 UID 元数据，不记录缓存正文。最初 libandroid_runtime.so/getpid 的 GOT 后续值已被覆盖，不能凭早期历史 hits 宣称 Application 仍命中；后续使用预载的 libjavacore.so，并增加当前槽值与精确时间窗口断言。覆盖的具体 ROM/其他模块成因未定位，不自动重装 Hook。
3. **后台冻结导致采集未确认。** run-03/04 中，Agent hello/status 已收到，但 capture_drain 超时。自身进程所有线程的内核栈均为 do_freezer_trap，不能归因为 Agent 死锁或缺少命中。夹具增加仅自身的前台 ProbeActivity、常亮窗口，继续由 Service 产出回执；不解冻真实目标、不改全局策略。debuggerd 对冻结进程超时的记录保留。

最终 run-05 六项全部通过；run-01/02 不通过，run-03/04 部分项目通过、后续捕获未确认，全部保留，均未计为整轮成功。原始报告位于本机聚合工作区 `.tmp/adh-p5-zygisk-run-05/report.json`，不在 Git 仓内。此前失败报告也在同级私有目录。

## 复现与回归

先构建 `ADH_AGENT_CONNECT_PORT=18761 bash tools/build_agent.sh`，再用 `device/gradlew --offline -PadhP5Sandbox=true :daemon:assembleDebug :p5sandbox:assembleDebug` 保存 daemon.apk、sandbox-v1.apk 至私有资产目录。显式运行：

```text
node tools/verify_p5_zygisk.ts SERIAL PRIVATE_ASSETS NEW_PRIVATE_OUTPUT --allow-device-reboot
```

入口拒绝缺失重启 opt-in、日常机 a22fecdd、已有测试包、占用端口或原作用域包含测试包。测试模块由 build_p5_zygisk.sh 在私有输出目录构建，该构建脚本自身不调用 ADB。运行需要 root、可重启且可启动测试包的设备，并预先确认允许前台测试窗口；不使用 dev_up/verify_all 或 kill-server。

回归实测：Host 类型检查、**561/561**（0 skip）；Android JVM **73/73**（core26/daemon18/Manager29，0 skip）；默认/隔离 Agent、默认契约/隔离 Zygisk、普通/opt-in APK 构建；94项 MCP registry 与文档检查通过。新增入口拒绝回归验证没有 opt-in 或选中日常机时，在创建输出状态、调用 ADB 之前拒绝。

## 保留的未验证项

- 默认生产命名空间的部署/升级、生产 Device Daemon 启动与配对状态迁移，没有替换原模块或 Manager。
- 其他 ROM、架构、Root/Zygisk 实现、真实业务 App 和热升级；本机结果不外推。
- `.init_array` 前、任意 Java 类加载前、任意模块仍未加载时的 Hook 保证；Java/inline early 当前仍 unsupported。
- 正式 Zygisk 链路中的 capture_start 七族和所有算法/模块组合、LAN grant 撤销；此前 self-load/Root broker 的通过不能外推为这些组合已经实测。

本轮收口的是此设备、隔离命名空间下的正式 Zygisk 调用链和上述六项结果。
