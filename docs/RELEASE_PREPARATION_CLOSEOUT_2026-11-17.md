# 发布准备收尾（2026-11-17）

按用户要求先收尾，停在可审查的源码提交。**不是 ADH 1.0.0 正式发布，也不是全部目标完成**。
P0–P5 已集成、CLI 0.2.0 已发布；正式 Zygisk 15/15 是其文档指定构建的实测。
本轮 Agent 又有修改，不能继承那份结果作为新候选版全链验收。

## 已落地

- APK 安装不再隐式调用 `refresh_agent_so`。显式部署拒绝日常机、缺失序列号/构建、
  无法读取模块版本和模块/Agent 版本不一致；跨版本使用配套 bundle。
- v01/v02 把指定端口的 Agent 实际打进沙盒 APK；自定义端口不覆盖默认 8761 构建。
  可选 QBDI 存在时一并打包；这不等于其运行门禁通过。
- runner 的 host 模式不发现设备、不启动服务；full 模式先核对设备和服务归属。
  停进程必须有 `ADH_VERIFY_OWNED_ROOT` 证据，每条验收保留独立日志。
- 历史 stdin 验收客户端通过测试专用 fetch 适配器先读状态版本，再发一次意图。
  不重试冲突/超时、不刷新显式旧版本、不增加 operator 权限；普通产品进程不拦截。
- 夹具缺失保持 SKIP；显式 FAIL 即使退出 0、后面输出 SKIP，仍作为失败。
  v102 的 scope 固定 Hook 策略已被 P5 Host 方案替代，明确退役 SKIP，不能记 PASS。
- GOT 值匹配仅扫描 linker 已加载 ELF 的 GLOB_DAT/JUMP_SLOT 重定位槽；验证失败不再
  退回任意数据扫描。按页安全读取候选值，以原子所有权检查写入。
  这是针对 DEX/APK/文件尾页 SIGBUS 的防护；全模块扫描的超时仍未解决。
- 准备统一 1.0.0 源码版本及一致性检查；未发布、未默认升级。

## 实测与未验证

| 验证 | 结果及边界 |
| --- | --- |
| Host 类型检查 | 通过 |
| Host 全测复核 | 566/566，0 skip；其后新增 runner 判定测试，定向共6/6通过 |
| 原生 GOT 夹具 | 9/9，清理通过；直接链接生产 got.c/mem_read.c，新增非 ELF 文件尾页防 SIGBUS 用例，原八项所有权/RELRO 也通过 |
| 新 Agent 编译及沙盒装载 | v01通过，40/40 maps匹配；JNI自加载，不是Zygisk路径 |
| 新候选全模块 capture_start | FAIL：COMMAND_TIMEOUT，保留 unknown；沙盒存活，不自动重放、不声称已取消 |
| Android JVM | 版本准备时73/73，0 skip；不替代第二台真机/ROM |
| 正式 Zygisk 扩展 | 历史指定构建15/15，见[P5_ZYGISK_EXTENDED_ACCEPTANCE.md](P5_ZYGISK_EXTENDED_ACCEPTANCE.md)；新GOT修改后未重跑 |
| 新候选 GOT hook/selftest RPC | 未验证；“重启沙盒并自测”组合命令被自动审批以 `blocked by policy` 拒绝，未执行，后续只做资源清理 |
| 源码版本、Shell语法、diff空白检查 | 通过；不代表发布门禁通过 |

首轮 Host 有一项 `device_lan_entrypoints` 失败（缺失操作结果），定向及全测复核均通过。
原因尚未定位，原 `host-tests.txt` 保留，不解释成确定的 CLI 路径问题。

私有证据：聚合工作区 `.tmp/adh-got-closeout-20261117-02/`。更早全量尝试保留于
`.tmp/adh-default-upgrade-backup-20261117/verification/full-gates*`：前三轮中止，第四轮
执行期间 runner 被修改，末尾 EOF，**没有有效全量总结**；不杜撰全量 PASS 数。

## 仍阻塞发布

| 项目 | 事实与下一步 |
| --- | --- |
| capture_start 全模块扫描 | 原 SIGBUS 栈在 GOT 任意文件扫描；新候选存活但仍超时。定位耗时并以新进程验证真实命中，保留 unknown 历史 |
| 大 DEX 请求 | 沙盒 classes.dex 9,604,000 B，base64 超过现有8 MiB JSON上限；需要有界的按路由大产物处理，兼顾准备请求与MCP |
| 回归脚本/夹具 | QBDI及native fixture缺失；v117–119部分负例/组合约束、v99硬编码captures目录、v19设置和v35面板断言等仍失败；区分旧断言与产品缺陷后修复复验 |
| 未知任务 | v72超时、CLI unpack因UNKNOWN_EXECUTION拒绝等保留历史；不自动确认、清空或重放未知副作用 |
| 默认升级与发布 | 重建产物，完成默认命名空间升级/状态保留/回滚、USB/LAN及正式缓存全链验收，再发Release；当前未升级、未发布 |
| 其他原任务 | GOT所有权丢失后的卸载RPC、实际覆盖写入方、第二个真实环境、得物dhw独立算法均未完成，见[AI_FIRST_REMAINING.md](AI_FIRST_REMAINING.md) |

## 现场与保留物

旧 `install_apk_root` 曾把候选 Agent 附带写入正式模块。发现后已用核验备份恢复，再次比较
scope、host.endpoint、Agent、Zygisk、daemon.apk、module.prop 六个SHA，全部等于 expanded-02
原基线。不能写成“从未改动正式模块”。默认模块/Manager仍0.8.0，未启停得物或日常机，未重启手机。

收尾已停止自有18088/18761 Host、8762 TLS夹具及com.adh.sandbox，移除自有三个reverse，
保留原8088/8761 reverse；五个相关Host端口均无监听，符合本轮开始时默认Host未运行的状态。
测试沙盒APK保留为隔离端口构建；私有Host操作日志/unknown记录及回滚备份保留。

早于最新GOT修改的候选ZIP已移入私有备份 `verification/unverified-artifacts/`，加`.unverified`
后缀；源码dist不留可误发的旧候选包。备份、捕获、二进制不进Git、不上传Release。
