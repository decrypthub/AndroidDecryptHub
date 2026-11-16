# P5：Host Hook 方案、早期缓存与可逆迁移

后续已有真实 Android 沙盒验收与修复，见 [P5_ANDROID_ACCEPTANCE.md](P5_ANDROID_ACCEPTANCE.md)。原文下面的“未验证”是初次实现快照；后续已完成[真实 Zygisk 调用链的隔离真机验收](P5_ZYGISK_ACCEPTANCE.md)，默认生产命名空间部署/升级仍未进行。

2026-11-16。Host 是方案与流程的权威；手机保留设备执行、验证缓存、状态和撤销入口。AI 默认持有控制，人类通过同一操作层查看、编辑和接管。P5 没有部署到现有手机，也没有重启现有 Host。

## 模块与统一入口

| 模块 | 职责 |
| --- | --- |
| `daemon/src/hook_plans.ts` | 严格方案校验、不可变版本、库 CAS、预检、顺序执行、逐步回执、观察和有限撤销 |
| `hook_plan_host.ts`、`http/routes_hook_plans.ts`、MCP `hook_plans` | 统一 action dispatcher；复用 P1 持久任务、目标代次、幂等键、版本、控制权及 unknown |
| `public/hook-plans-panel.js` | `/workbench` 和现场内嵌面板共用 JSON 编辑器、版本准备、任务提交及按意图键查询 |
| `device/.../HookPlanCache.kt` | 持久缓存与迁移账本、APK/Agent 绑定、TTL、授权与 scope 再校验 |
| `AndroidHookBinding.kt`、`EarlyPlanBroker.kt` | 包身份、Agent SHA/导出 ABI 检查；仅 root 可访问的本地有界缓存接口 |
| `core/EarlyPlanWire.kt`、`agent/src/bootstrap/early_wire.h` | Kotlin 编码与 native 验证同一受限指令格式、内容 SHA、目标与过期检查 |
| `agent/src/bootstrap/early_plan.cpp`、`injector/zygisk/jni/main.cpp` | Zygisk 获取缓存并绑定加载文件；Agent 先执行缓存，再启动 Host 通道，hello 带结果 |
| Manager `HookConfigScreen`、Binder v20 | 固定 Hook 编辑器改为旧策略快照、缓存状态与停止未来缓存；作用域改走包列表 CAS |

MCP：`hook_plans`。REST：`GET/POST /api/hook-plans`。发布版 Python CLI 已有的 `adh call hook_plans --arguments ...`（查询）与 `adh run hook_plans --arguments ...`（持久写入）直接复用此工具，无第二套方案解释器。`daemon/src/cli.ts` 继续承担原有专用命令；通用方案入口使用 Python CLI。

可用 actions：

- 查询：`list/get/validate/preflight/run/observe`、`early-prepare/early-status/migration-preview`。
- 写入：`put/import-legacy/apply/undo`、`early-stage/early-revoke/migration-apply/migration-rollback`。

写入一律要求 P1 `_operation` 的当前状态版本与控制代次，建议持久 `taskId` 和 `idempotencyKey`。AI 不自动夺取人类控制，也不刷新旧版本重发失败指令。面板“读取提交版本”冻结当前参数和状态，修改草稿后必须重新读取；未知 HTTP 提交保留意图键，只查询记录。

## 方案与版本

```json
{
  "schemaVersion": 1,
  "id": "observe-example",
  "title": "观察示例模块",
  "package": "com.example.app",
  "families": {
    "digest": true, "hmac": true, "symmetric": false,
    "asymmetric": false, "tls": false, "aead": false, "system": false
  },
  "steps": [{
    "id": "got-read", "tool": "native_hook",
    "arguments": {"action": "hook", "mode": "got", "module": "libexample.so", "symbol": "read"}
  }]
}
```

所有七个 family 必须显式指定，表示后续捕获安装的资格；不会自行安装这些 family。程序支持已有 `native_hook`、`java_hook`（hook/hookAll）、`jni_onload`（hook）、`module_watch`（start）和 `capture_start` 原语，步骤参数以当前 MCP schema 校验，不可覆盖 session、device 或授权上下文。最多 32 步、128 KiB，每步可选 `waitMs`（0..600000），等待受任务预算和检查点约束。没有手机端任意脚本求值器。

`capture_start` 必须写明三个模块参数。空 `cryptoModule` 是显式全模块扫描；空 file/sys 是不启用该模块组。省略参数的旧原语仍可使用旧模板；完整方案不从旧设置偷取模块值。

`put` 使用 `expectedLibraryRevision`，返回不可变 SHA-256 digest。Host 数据位于 `hook-plans/library.json`、`versions/<digest>.json`、`runs/<operationId>.json`。构造或导入模块不会建库、清理历史或自动安装；损坏的索引/版本拒绝读取，不自动重建。库头写入失败时可能留下孤立不可变版本，重新观察版本后再做新意图。

保存不等于应用。`apply` 必须显式给出 digest 和在线 session；预检校验包名、进程代次和 `capture_policy` 等运行时能力。先记录 run，再读取/设置明确 family 策略，再调用现有原语。每步保存真实回执；Java 批次部分安装不会成为整套成功。具名捕获的部分符号不存在按原语返回 partial，完整性保留在回执中。

超时/取消由 P1 协调器返回事实状态：已派发命令不能收回，没有自动重试或推断成功。`run.state` 是历史记录，`run/observe` 同时返回权威 Operation；Host 崩溃后的 running 文件不能覆盖 Operation 的 unknown。断线对账延续 P4，仅附加设备账本证据，不重放。

撤销仅支持可核验的单个 native/Java Hook ID；先读当前状态并核对归属与策略。partial/unknown 运行、批次、watch 和持久 capture 集合返回 UNSUPPORTED_UNDO。历史捕获回执不能证明当前集合仍属于本方案，需核对后显式 capture_stop；不会退化为 unhook-all 或声称恢复原捕获集合。

## 早期缓存的实际边界

阶段是 **post-specialize / before-agent-start**，不是 `.init_array` 之前、不是 pre-specialize，也不是 Java 类加载前保证。支持 1..16 步的具名模块 `capture_start` 和只观测的 GOT `native_hook`；拒绝等待、Java、inline、改参数/返回值、主动调用或重放。该边界只覆盖此缓存格式，完整实时方案仍保留已有原语自由度。

早期 hello 的 `lastCaptureInstall` 仅记录最后一条 capture_start 的有界原始计数，不把 ok:true 当作成功，也不是所有步骤的 Hook 清单。专用导入按 family 决定布防；HMAC/非对称共用 DigestSign 槽，回调还按实际上下文的族资格过滤事件。禁用族不能借共享 Hook 输出数据。七族真实沙盒、全禁用和 UID/Agent 替换证据见 [P5_ANDROID_ACCEPTANCE.md](P5_ANDROID_ACCEPTANCE.md)。

流程：

1. `migration-preview` 返回完整原 scope 原文及 hash；`import-legacy` 生成 Host 方案版本。
2. `migration-apply` 显式标记该包的 authority 为 `host-plans/1`，保留完整旧数据与备份，不扩大注入范围，也不装 Hook。
3. `early-prepare` 读取新鲜绑定、`cacheRevision` 与支持状态。绑定包含包名、UID、versionCode、APK signer、base/split APK 文件路径/大小/inode/mtime、Agent SHA-256 及 ELF 导出 `adh_agent_apply_early_v1`。
4. `early-stage` 指定 digest、原 prepare binding、`expectedCacheRevision`、秒级 `expiresAt` 和 `offline:"keep-until-expiry"`。必须同时携带 P3/P4 的 deviceId、connectionId、bootId、daemonInstanceId、expectedDeviceRevision。TTL 为 1..86400 秒。新库版本不会替换已暂存 digest，需再次显式 stage。
5. USB 和 LAN 调用同一 DeviceOperations。LAN stage/revoke/迁移要求 `manage` 权限，缓存记录来源 grant，消费前重新检查授权。未迁移设备方法返回 unsupported，不转旧 ADB 命令。
6. root broker 为新进程检查 scope、authority、UID、绑定、有效期、来源授权和 wire SHA；Zygisk 校验 root peer，并对实际加载的 Agent 文件取 SHA。Agent 再验二进制内容、包/UID/Agent SHA/TTL，在同一进程最多消费一次，第一步未确认安装即停止后续步骤。

缓存文件是 root 私有的有界 JSON（2 MiB，不自动清理），本地 socket 无 HTTP/MCP 或设备分析逻辑。内容 SHA 用于完整性；授权来自既有 root 信任边界和 P4 的 TLS/权限，不把 SHA 称为签名或硬件证明。APK 元数据绑定不宣称完整 APK 内容测量；信任 Android 包管理器与 root 存储。

`early-status` 的 `validated-cache` 仅说明暂存验证通过，`applied:null`。Agent hello 的 `earlyPlan` 列出 attempted/confirmed/每步 installed/Hook ID，明确 `agent-reported`。GOT 缺失或安装失败返回 partial-or-failed，不因为 RPC 被接受而报成功。旧 target 通道仍未绑定设备身份；不得据此升级成已验证设备会话。

`early-revoke` 只阻止未来获取缓存，不卸载现有进程 Hook；已经交付给正在启动进程的包不能追回，仍受其原 TTL 限制。授权撤销同样在后续 broker 获取时生效。不会为了刷新 APK、安装新库或换进程而自动启停 App。broker 超时、旧 Agent、模块尚未载入均失败关闭；没有重试安装或恢复默认固定 Hook。

## 旧配置迁移与回滚

迁移保留旧 scope **精确原文字节**、beforeHash、预期 afterHash、migrationId 和阶段；先持久 prepared，再 CAS 写 scope，再记 migrated。Unknown/retired/未来字段保留。Host `import-legacy` 把 scope/settings 完整快照放入版本 metadata，将旧 family/捕获模块与兼容的启动 native Hook 转成显式步骤；输出过滤和已退役的 bypass 只存档，不冒充迁移后已执行。

`migration-rollback` 需要 migrationId 和原迁移后的 scopeRevision，重新校验备份与当前 scope，逐字节恢复 beforeRaw，并撤销未来缓存。后续哪怕是别的包的 scope 修改也会触发冲突；保留现场，由 AI/人类基于最新文档决定新的修复意图，不强行覆盖。迁移/回滚持久化中断保留 prepared/unknown 证据，不自动修复或重跑。

P5 的新 injector 默认 family 全关闭，完整策略由显式实时计划或已验证缓存提供。旧 policy、startup、模块模板和 autoDumpDex 数据仍保存；hello、重连、settings.enabled 不再按旧默认值布防或自动 dump。回滚恢复配置数据，不会自动恢复已退役的自动执行路径；如需回退软件版本，先完成受保护的配置回滚并保留备份，再另行部署旧版本。

手机固定 family 编辑器已移除。Manager 显示旧快照与 Host 指引、缓存 digest/state，并可 CAS 撤销未来缓存；旧 Binder 不支持时明确不可用。v20 包列表提交走 scope/state 双版本，不再用默认 family 值覆盖已迁移策略。完整 JSON 方案编辑与流程决定在 Host 面板、CLI、MCP 完成。

## 隔离验证

Host 测试入口 `node test/run.mjs` 为每个测试进程分配临时数据。新增测试覆盖方案 CAS/不可变版本/原语回执/旧能力拒绝/人类接管/撤销冲突、公共 MCP/REST/Python CLI、真实 Kotlin RPC 缓存/迁移账本，以及 Kotlin wire → 生产 C++ 解析/执行骨架（含 SHA oracle、篡改/UID/Agent/TTL 拒绝）。Manager/core/daemon 用离线 Gradle JVM 测试和 debug assemble 验证；Agent 和 Zygisk 用 NDK 构建，不 deploy。

浏览器 QA 用 `test/fixtures/p5_workbench.ts` 的随机 loopback 端口，禁止 fixture 内调用 ADB/子进程，复用正式页面和 handler。真机 PackageManager/SELinux/root socket、实际加载时序与 Hook 命中仍需后续独立冷启动验收；本次为保护现场没有执行这些步骤。编译通过与缓存字节验证不冒充真机早期命中证明。
# 本次隔离验收记录

基座为 P4 `fa98813`，工作分支 `feat/adh-p5-hook-plans-20261116`。未部署产物。

| 验证 | 结果 |
| --- | --- |
| Host typecheck 与完整测试（含已发布 Python CLI 源码路径） | PASS，557/557，0 skip |
| 离线 Android JVM：core / daemon / Manager | PASS，22 / 18 / 29，0 skip |
| Device Daemon、Manager debug assemble | PASS，仅隔离构建 |
| NDK Agent、Zygisk | PASS；实际 release `.dynsym` 和设备验证器确认早期导出，内部辅助符号未导出 |
| MCP 注册表、生成文档、diff whitespace | PASS，94 tools |
| 随机端口正式面板浏览器验收 | PASS：保存不应用、并发冲突保留草稿、不重发、任务结果与副作用入口 |
| 现场保护 | 原仓、P2/P3/P4 worktree、adh-cli 无新增改动；8088 原 PID 与启动时间保持不变；临时面板已关闭 |

补充边界：自动 `undo` 拒绝 partial/unknown 运行和持久 capture 集合，避免仅凭历史 Host 回执误停后来替换的集合。单 Hook 撤销仍要求当前进程、ID、模块/符号、策略核验；不支持的归属明确返回 `UNSUPPORTED_UNDO`。早期方案 digest 使用 Host 原规范文本及设备语义比对，避免 Kotlin/JavaScript 对 Unicode 和浮点 JSON 序列化差异造成误判。
