# GOT 卸载所有权收尾（2026-11-17）

后续RPC实测：`verify_v61_got_by_name.sh`已在专用沙盒真实Agent中完成安装/命中后，
用独立memory_write意图把GOT槽改为合成外来值（期间不调用该槽），状态转ownership-lost，
卸载返回ownership lost/持久操作failed，槽仍是外来值、上下文仍保留。随后先读取确认仍为
自己的合成值，再恢复原值，以新意图卸载；活动Hook为0，探针仍返回30且没有新增Hook事件。
这是模拟外来写入，不是定位libandroid_runtime/getpid的实际覆盖方。
日志在聚合工作区私有`.tmp/adh-capture-timeout-20261117-01/got-ownership-rpc.txt`，
底层夹具最新11/11（含APS2），见[捕获扫描验收](CAPTURE_SCAN_ACCEPTANCE_2026-11-17.md)。
下文未验证标记保留为早期收尾时点的历史记录。

后续：含本补丁的Agent已通过正式Zygisk扩展15/15，包含当前GOT槽所有权与首次调用证据。
见[P5_ZYGISK_EXTENDED_ACCEPTANCE.md](P5_ZYGISK_EXTENDED_ACCEPTANCE.md)；
本页后文“未重跑”指原收尾时点，GOT卸载冲突RPC仍未由后续全链触发。

收尾审查发现：原生 GOT Hook 卸载先检查是否为 original，否则直接写回旧 original。
若槽已被 runtime、人类或另一个工具改写，这会覆盖对方的新值。这里修复的是卸载的
所有权检查，**没有定位**此前 libandroid_runtime/getpid 后续被覆盖的具体成因。

## 修复行为

- `got.c` 提供生产共用的原子 compare/exchange 恢复：当前值为本 Hook replacement 才写回 original；
  已为 original 时幂等通过；其他值拒绝且不写入。不使用“先检查再无条件写入”。
- 保留 RELRO 原页权限。不可读、未映射、未对齐或保护操作失败，返回未确认，保留 stub。
- `native_hook` 的 GOT 卸载冲突返回 `not-unhooked: GOT ownership lost`，保持失败状态，
  不自动重装 Hook、不重试写入、不承诺已卸载或已回收资源。
- 活跃 GOT 状态增加 `slotOwned`（true/false/null），`verdict` 在失去当前槽时为 `ownership-lost`，
  不可读时为 `slot-unreadable`。历史 hits 保留，但不再单凭历史次数输出 fired。
  字段描述读取时的快照，不是对其他线程后续写入的承诺。

## 本轮实测

在 aa165071（PGP110 / API35 / arm64-v8a）独立、短命的 shell 原生进程中，
`agent/test/got_restore.c` **直接链接本次生产 got.c**，8/8 通过：
可写页自有值恢复、可写页他人值不变、只读页恢复及权限恢复、已恢复幂等、
只读页他人值及权限不变、空/未对齐地址拒绝、不可读页拒绝、已解除映射地址拒绝。
测试程序使用合成指针数据，没有调用这些指针。

原始输出和报告保留于聚合工作区私有目录 `.tmp/adh-got-restore-20261117-01/`；
`cleanupVerified=true`，自己的 UUID 目录和文件已清理。没有启停 Host、修改 reverse、
安装测试包或 Zygisk 模块、重启手机，未启停真实业务 App。
收尾时再次比较原 scope、host.endpoint、Agent、Zygisk、daemon.apk、module.prop 六个文件，
SHA 与此前 Zygisk run-05 的原环境基线一致；原8088/8761 reverse保留，四个Host/隔离端口无监听。

本次 Agent 默认构建和 Host 类型检查通过；Host561/561、Android JVM73/73，均0 skip；
原生Hook选择门禁和94项MCP registry检查通过。Host回归显式指定配套adh-cli的src路径，
前两次因路径缺失跳过的1项保留日志，未当作完整通过。
此前真实 Zygisk 6/6 和 self-load 11/11 是各自文档所列旧提交/构建的历史实测，
**没有用本次修改后的 Agent 重跑整套 Zygisk、Hook 命中或卸载 RPC 集成验收**。
本轮原生夹具结果不替代这些未重跑项目。

复现：先 `bash tools/build_got_restore_fixture.sh`，再显式运行
`node tools/verify_got_restore.ts TEST_SERIAL agent/build/adh-got-restore NEW_PRIVATE_OUTPUT`。
仅对获准的独立测试设备执行；缺少设备/构建条件时保留未验证，不回退到业务目标。
