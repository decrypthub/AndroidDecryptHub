# 工具沙盒收尾（2026-11-17）

按用户最新范围，仅完善 ADH；不分析第三方 App，不继续 dhw。代码在独立
`release/adh-ai-first-1.0.0` worktree 中验证，手机只使用授权的 `aa165071`
及自有 `com.adh.sandbox` / 短生命周期原生夹具。Host 使用独立数据、捕获目录和
18088/18761；没有运行默认指向第三方 App 的验收脚本。

## 修复与实测

| 路径 | 改动与实际结果 |
| --- | --- |
| `agent/src/trace/qbdi_trace.c` | 原 Hook 内回放直接使用命中 SP，guest 局部栈写入破坏真实 Hook 返回帧，沙盒实测 SIGBUS；现始终使用 256 KiB 私有栈，已知 SP 上方复制最多 128 KiB−64 字节，按范围重定位 FP，未对齐 SP/越过快照的 FP 在执行前拒绝。输出明确 `stack.mode/copied/truncated`、`execution:replay` 与 `contextComplete:false` |
| 同上，写监视 | 栈监视范围映射到私有栈，事件地址换算为逻辑源地址，`addressSpace:replay-stack` 明确属于回放；堆监视仍为 `target`。跨快照边界拒绝，不把回放写入说成真实栈写入 |
| 原生生产 tracer 夹具 | 4/4：真实源栈保护字未改、私有栈写监视地址/值正确、未对齐 SP 拒绝、FP 越界拒绝；临时二进制/QBDI 目录清理确认。`verify_v133_qbdi_stack.sh` 可复跑，日常机在设置前拒绝 |
| v117/v118/v119 | 真实 Agent RPC 全部 PASS：sites 与 inline trampoline 追踪、关闭后无 trace、调用仍 30；负偏移与绝对窗口精确字节；堆写监视精确地址/指令/值、绝对监视、移除后无旧 watch。修复负例助手错误地抛弃预期拒绝，并显式 drain，不依赖 P5 已取消的 hello 自动布防 |
| v51 | QBDI 参数真机 PASS：非法整数拒绝，`adh_add_target(20,22)` 返回 84，有实际指令；无参夹具返回 30 |
| v22 | 显式 `capture_start`，19/19 安装；20,000 次 AES 压测 PASS。最终采样 `seq=20007, emitted=899, backlog=0, dropped=19108`，三者严格相等；`agentResidual/agentLost/daemonLost=0`。Java 另报 `jdropped=19333`，如实 `complete:false`，不宣称无丢包。结束 stop/drain 确认 |
| `operation_registry.ts` | 旧 `/api/data/clear` 与 maintenance 同属全局 Host 设置维护；继续走版本与控制权门禁，不再误按目标会话路由；有对应资源断言 |
| v19/v99 | 隔离 Host 配置修改/落盘/导入/拒绝/按自有字段恢复通过；重启后的无来源旧产物与带 sidecar 来源产物均通过，来源不匹配/丢失/悬空路径均 0。拒绝无归属 Host，不清除旧 unknown 历史 |
| 人类面板 / v35 | 当前应用摘要补回离线会话开关、隐藏数量与 PID/会话列表。v35 PASS；ego-browser 注入页面本地合成的在线/离线会话，实测默认隐藏、勾选显示、取消后隐藏，并查看截图确认布局；没有向 Host 写入合成会话 |
| 测试隔离 | 全套失败曾暴露 PID 复用导致旧测试设备账本被再次加载；launcher 增加每轮 UUID，保留每进程独立目录，路径解析仍纯函数。LAN 用例按明确 deviceId 选授权，禁止依赖列表第一项 |

最新沙盒 Agent SHA256：
`5fec733594fded8f3583f3180be52fc43a7f0bcbc573feef5346a276231a6b55`。
最新 `npm run typecheck` 通过，指定配套 CLI 源码后 `npm test` **574/574，0 fail，0 skip**。
之前失败日志保留，未以删除旧账本或清空 unknown 获得绿灯。

## 复跑入口与边界

原生独立路径不需要 Host、APK、作用域或 reverse：先 `bash tools/build_qbdi_stack_fixture.sh`，
再显式设置测试序列号运行 `bash tools/verify_v133_qbdi_stack.sh`。Node 校验器要求新输出目录，
只清理 UUID 命名的自有两个文件及空目录。

旧 stdin 验收在隔离 Host 上需要 `tools/lib/verify_fetch.mjs` 的版本观察适配；它只为新意图
读取版本，不放宽产品鉴权、不重试冲突或 unknown。Host 单测通过 `daemon/test/run.mjs`
运行，配套 CLI 用 `ADH_CLI_SOURCE` 指向 0.2.0 源码。

私有原始证据位于工作区 `.tmp/adh-gate-focused-20261117-01/`；包含首轮 tombstone、
修复后门禁日志、Host 全套失败/成功日志及合成会话截图，不提交二进制/捕获/运行账本。

私有栈不是完整进程快照：其他寄存器/栈内指针仍可能指向真实堆或调用者内存，FPR/标志上下文
仍不完整；Hook 内追踪仍会回放一次后执行真实调用，副作用函数不能因此被视为安全双执行。
这轮没有验证任意函数、所有栈指针别名/深递归、其他 ROM/Root，亦未重跑最新 Agent 的正式
companion/post-specialize 全链。历史 Zygisk 15/15 只归属于其原构建。

本轮定向收尾通过，不等于发布门禁全绿。完整旧门禁、v72 原未定因问题、最新构建正式 Zygisk
复核、1.0.0 正式打包/发布/默认升级仍单独跟踪；源码版本不能当作已发布版本。

收工只停止本 worktree 归属的隔离 Host/TLS 夹具与 Sandbox，移除本轮 18088/18761/8762
reverse；原 8088/8761 reverse 保留。实测清理后默认与隔离端口均无监听、Sandbox 已停，
原 scope/endpoint/Agent/Zygisk/daemon.apk/module.prop 六文件 SHA 与原基线相同。
测试 APK 和私有证据保留，未清空历史捕获或 unknown。
