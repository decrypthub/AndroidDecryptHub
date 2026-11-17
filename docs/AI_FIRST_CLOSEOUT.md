# ADH P0–P5 收尾索引（2026-11-17）

后续推进：正式Zygisk原六项、capture_start七族/全部禁用、真实LAN grant撤销已在新Agent上
完整15/15实测，清理和原环境保护通过；见[P5_ZYGISK_EXTENDED_ACCEPTANCE.md](P5_ZYGISK_EXTENDED_ACCEPTANCE.md)。
以下历史“正式链扩展覆盖尚未实测”条目已由这次指定探针覆盖更新，全部算法/模块组合仍未验证。

收尾补丁：独立 `feat/adh-completion-20261117` 分支补上 GOT 卸载所有权保护，
原生恢复夹具8/8、清理通过；详情与未重跑边界见 [NATIVE_GOT_CLOSEOUT.md](NATIVE_GOT_CLOSEOUT.md)。
它没有解决下表的 GOT 覆盖成因，也没有推进默认部署或发布；下文 e58f2ba 仍指既有正式链验收基准。
本次补丁回归：Agent 默认构建、Host 类型检查、Host561/561（0 skip，含配套CLI源码路径）、
Android JVM73/73（0 skip）、原生Hook选择门禁和94项MCP registry检查均通过。

## 原阶段收尾记录（50b4cda）

约定的实现与隔离验收已完成，最新代码基准为 e58f2ba（2026-11-16）。本次收尾只核对状态、补齐交付索引并执行 Host 文档回归；没有重跑真机验收、安装/重启手机或启停现有服务。

## 交付位置

AndroidDecryptHub 的完整提交链位于 `feat/adh-p5-zygisk-e2e-20261116`，已核对其包含下表全部前序提交；各阶段独立 worktree 保留。配套 adh-cli 为 f086459，分支 `feat/adh-p1-operations-20261116`。本会话没有执行合并、推送、发布或默认环境部署，原 AndroidDecryptHub 工作区仍在 P1 分支；不能把最新隔离分支等同于已上线版本。

| 阶段 | 已交付 | 提交与详情 |
| --- | --- | --- |
| P0 | 作用域策略保留、统一设置应用、初始化/数据清理拆分 | 7f71626，[P0_HOST_STATE.md](P0_HOST_STATE.md) |
| P1 | 共用操作层、持久任务、版本与控制权、超时/取消状态 | be80e29；CLI f086459，[P1_OPERATIONS.md](P1_OPERATIONS.md) |
| P2 | 人类任务工作台、配置冲突、暂停/恢复、接管/交还 | 91be0f5，[P2_WORKBENCH.md](P2_WORKBENCH.md) |
| P3 | 设备域、稳定身份、发现/能力、统一 USB RPC | 258e69a，[P3_DEVICE_DOMAIN.md](P3_DEVICE_DOMAIN.md) |
| P4 | LAN TLS、配对/撤销、断线对账、未迁能力 unsupported | fa98813，[P4_LAN_AUTH.md](P4_LAN_AUTH.md) |
| P5 | Host Hook 方案、经验证的早期缓存、可逆迁移 | de9d134，[P5_HOOK_PLANS.md](P5_HOOK_PLANS.md) |
| P5 沙盒 | Android 绑定、七族代表性捕获/禁用、UID/Agent 失效、stdio/2 | f7d726e、efe8e78，[P5_ANDROID_ACCEPTANCE.md](P5_ANDROID_ACCEPTANCE.md) |
| P5 正式链 | 真实 Zygisk callbacks/companion/post-specialize、首次调用命中及拒绝 | e58f2ba，[P5_ZYGISK_ACCEPTANCE.md](P5_ZYGISK_ACCEPTANCE.md) |

最近一次已执行验收：self-load 沙盒最终两轮各11/11；真实 Zygisk 隔离命名空间6/6；Host561/561、Android JVM73/73，均无skip，94项MCP门禁通过。各自日期、原始报告入口和严格边界以对应验收文档为准，不用本索引覆盖失败历史。

## 本轮可关闭的事项

- 约定范围内没有待提交的实现修复；测试代码、验收脚本、问题修正和进度记录均已提交。
- 收尾只读核对确认：临时 Zygisk 模块、测试包、自建测试进程无运行残留，隔离端口已释放；原 TCP reverse 映射保留。
- 私有原始报告、失败/unknown 历史和诊断目录按既有约定保留，不重放、不清空、不提交。源码 worktree 保留以便审阅和集成。

## 后续事项，未计为本轮完成

| 事项 | 当前边界 |
| --- | --- |
| 分支集成与发布 | 尚未执行，需同时考虑 AndroidDecryptHub 与配套 adh-cli；未发布新的默认运行版本 |
| 默认生产部署/升级 | 未替换原模块、Manager 或生产 Device Daemon；其启动、配对状态迁移仍未验收 |
| 正式链扩展覆盖 | capture_start 七族、LAN grant 撤销、全部算法/模块组合尚未通过正式 Zygisk 链复测 |
| 其他环境 | 其他 ROM/Root/Zygisk/架构、真实业务 App、热升级等未验证 |
| 设备 RPC 未迁能力 | Hook/内存/Trace/dump 等未迁能力仍明确 unsupported，不能外推为所有分析功能已完成 USB/LAN 对等 |
| 早期时序限制 | 不承诺 init_array 前、任意 Java 类加载前或目标模块尚未加载时命中；Java/inline early 仍 unsupported |
| GOT 覆盖成因 | 本 ROM 的 libandroid_runtime/getpid 槽后续被覆盖，具体 runtime/其他模块成因未定位；已有审计与限制记录，不自动重装。正式通过使用预载 libjavacore，并验证当前槽及首次调用事件 |
| 原业务算法目标 | 本轮交付的是工具改造与验收，没有交付或验证得物 dhw 的纯算法还原；工具测试通过不能当作业务算法已还原 |

本轮到此收尾，不继续扩大真机验证或推进部署。
