# AI 自主分析改造：剩余工作跟踪（2026-11-17）

用户要求继续完成剩余工作。阶段收尾不等于全部目标完成；以下按当前代码、外部运行状态和
实际报告更新。P0–P5历史提交入口见[AI_FIRST_CLOSEOUT.md](AI_FIRST_CLOSEOUT.md)。

阶段收尾已提交d0e2e47，后续继续修复发布阻塞。全模块capture_start扫描已定位并通过
[针对性实测](CAPTURE_SCAN_ACCEPTANCE_2026-11-17.md)；大DEX输入/持久结果和10条相关门禁也已
[修复实测](LARGE_ARTIFACT_ACCEPTANCE_2026-11-17.md)，完整发布回归仍待处理。
1.0.0是准备中的源码版本，未发布或默认升级。

| 工作 | 当前状态 | 完成所需证据 |
| --- | --- | --- |
| 正式Zygisk扩展 | 已实测完成指定代表性范围 | 七族单启用、全部禁用、LAN grant撤销及原六项，共15/15；expanded-02清理和原环境保护通过，见[P5_ZYGISK_EXTENDED_ACCEPTANCE.md](P5_ZYGISK_EXTENDED_ACCEPTANCE.md) |
| GOT卸载保护 | 底层恢复函数完成；状态链已复测 | 原生11/11，含尾页、全模块安装/恢复及APS2；此前指定构建全链slotOwned/首次调用通过。失去所有权后的卸载RPC集成未验证 |
| ADH与adh-cli分支集成 | 已完成 | [ADH PR1](https://github.com/decrypthub/AndroidDecryptHub/pull/1)合并为fe2d2c2；[CLI PR2](https://github.com/decrypthub/adh-cli/pull/2)合并为f394dc8。两者远端PR检查成功，保留原提交历史；原工作区仍未切换/覆盖 |
| CLI与桌面组件发布 | 已完成 | [PyPI0.2.0](https://pypi.org/project/android-decrypt-hub/0.2.0/)、[CLI Release](https://github.com/decrypthub/adh-cli/releases/tag/v0.2.0)、[组件Release](https://github.com/decrypthub/adh-cli/releases/tag/decrypthub-v0.2.0)均已发布于f394dc8；源码14/14、隔离wheel运行时13/13、build/twine检查、公开PyPI下载导入及组件逐文件SHA核对通过。未升级本机全局安装 |
| ADH打包与发布 | 未完成 | 一致且递增的版本、默认产物构建、发布门禁、可下载Release与对应提交；不发布opt-in测试APK或捕获数据 |
| 默认设备环境升级 | 未完成 | 原模块/Manager/Root状态可恢复备份；默认目录启动、身份/配对状态保留、USB/LAN共用RPC、正式缓存投递的实际结果；独立设备授权仍只适用aa165071 |
| GOT覆盖成因 | 未定位 | 实际覆盖写入方或等价强证据；不能用其他Zygisk实现源码类比就声称已定位本机Zygisk Next |
| 其他环境覆盖 | 未验证 | 第二个实际ROM/Root/架构环境的独立报告；当前仅一台API35 arm64设备，不能用JVM或同ROM多用户冒充另一环境 |
| 得物dhw纯算法 | 未交付 | 同次请求输入/输出配对、多样本逐字节对拍、独立可运行实现和已知边界；不得把工具验收或只列参数当作算法还原 |

仍是既定产品边界：未迁移设备RPC明确unsupported；Java/inline early仍unsupported；不承诺
init_array前或未加载模块的提前Hook。它们不能被文档换名为“已支持”，也不要求伪造不存在的验证。
各算法/模块组合只按实际指定样本记录，代表性七族通过不外推为所有组合。

P0–P5实现已进入远端main。后续ADH发布准备位于同一独立worktree的`release/adh-ai-first-1.0.0`，
基座fe2d2c2；CLI发布提交f394dc8，独立worktree为`release/adh-cli-0.2.0`。
原AndroidDecryptHub工作区仍在P1分支；本次未升级默认部署。旧辅助函数曾附带替换正式Agent，
已从核验备份恢复，原六文件SHA再次核对相等。隔离进程已停止，测试APK/私有备份及unknown记录保留。
运行态会变化，
下一步必须重新检查；这些不是可复用的固定环境前提。
