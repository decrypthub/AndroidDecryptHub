# 两级 Hook 管理

Host、Web 和 MCP 共用 `capture_controls`。它不是记录过滤，也不从命中次数推断是否安装。

## 操作语义

- `get`：只读配置、实际 Native / Java 方法目录、进程代和控制版本。Java 未发现时目录明确未就绪。
- `discover`：明确请求 Java 重载目录，不启用观测；属于受版本围栏约束的目标操作。
- `save`：按 `serial + package` 保存草稿，校验配置版本。离线使用明确标记的历史目录；不存地址或运行时句柄，不自动重连应用。
- `apply`：指定一个已核验的在线 session，带配置 `expectedRevision`、刚读到的 `runtimeToken` 及 Host `_operation` 版本。先排空、停止、设置精确选择及家族策略，再启动并逐项读回。共享方法取启用功能所选集合的并集；必要依赖单独标注。已有 Hook 计划持有的会话拒绝覆盖。

父级是独立总闸，关闭后保存子项选择；重新打开不会自动选择新增方法。Java 停用是软停用观测，底层 LSPlant 补丁可保留；Native 只恢复仍由本采集器持有的 GOT 槽位。

状态区分保存待应用、完整应用、部分失败和未知。未知写入不重放、不自动撤回；保留逐步回执并由既有操作账本隔离。超时不能等同于失败：本轮真实设备曾进入系统 freezer，所有线程的 wchan 为 `do_freezer_trap`，测试改用自有前台宿主验证，没有修改系统 freezer 策略。

## 接口

HTTP：`GET/POST /api/capture/controls`；MCP：`capture_controls`。参数为 `action, serial, package, session, expectedRevision, runtimeToken, config, confirmRisk`。写入还需要既有 `_operation` 元数据。`get` 返回目标控制快照和 `saveControl`（Host 配置写入快照），不能拿一个资源的版本替代另一个。

`config.schemaVersion=1`；`features` 包含 digest、hmac、symmetric、asymmetric、tls、aead、system、file，各自有独立 `enabled` 和稳定方法 ID 数组 `methods`。`modules` 指定 crypto/file/system 的 Native 模块范围；crypto 留空意味着扫描已加载模块，Native 应用须明确确认风险。

## 本轮实现与仍缺的范围

Web 设置收敛为 Hook 管理 / 显示过滤 / 界面偏好 / 高级。Hook 管理采用固定目录快照、功能/方法两栏、进程选择、合并应用、跨目标草稿保留/放弃、只读刷新后的明确版本采用。显示过滤不再展示记录数，旧“由命中记录生成的 Hook 状态”入口已撤下；分析范围保留在高级。

真实 ART 双重载测试暴露原安装器会拦截 SIGSEGV 并跨 JNI 长跳转；该机制已移除。ART 的 Dobby 适配器改用完整绝对跳转，且串行保护 Dobby 的全局 near 选项，普通 Native hook 保留原偏好。改动后，两台授权手机的同 Host 自加载路径通过精确 digest、设备隔离及共享 HTTP 版本围栏实测；A 机另通过 Native access、父级停用及子项保留、第二重载安装与三轮启停，B 机原 digest 同时保留。实际 Web 另验证了 A 机双重载独立启停、父级停用与恢复、跨功能搜索和移动布局。此结论只覆盖已执行路径，不是所有 ROM 的通用证明。

Manager 当前设备域用户路径、全部算法/工具与真实注入矩阵、最终无上下文独立体验、旧逻辑收尾及最终交付尚未完成，不得以本文件替代最终验收。

预览复验的 9 项功能检查通过，但严格现场前后比较失败：原 `com.adh.sandbox` 的 TCP session 从 s_2zgr 变为 s_3lcx，PID 28885 / starttime 53704094 未变。两机 scope/endpoint/module 哈希、原 reverse 均相同，自有包与上传清理完成。报告保留 FAIL，不将功能成功冒充整个现场检查通过；此前无浏览器的修正版双机 9/9 报告严格现场比较通过。
