# 设备、会话与记录归属

本轮实现以 `AgentSession.deviceBinding` 固定 Agent 连接的 ADB 串号、transport_id、独立 Host 监听端口、设备 boot_id 及 PID/UID/starttime。设备 Agent 端口与 Host 监听端口不再必须同号。Host 使用 5037 协议，不启动 adb 子进程。

## 边界

- 这是受信本机 ADB 路由及 root procfs 核对，不是 DeviceRpc 的密钥认证，也不能对抗恶意本机 ADB server。Windows 的 devpath 为 unknown 时，依据已有 Windows ADB roster 分类，并在绑定中标注 `linkEvidence: windows-adb-roster`，不伪称来自 USB 硬件认证。
- 已有其他入口占用的 Agent reverse 不覆盖。空映射使用 no-rebind；只迁移本进程确实持有的旧监听。关闭时核对映射、启动身份，只移除自己的映射。ADB 不提供跨外部写入者的 CAS，前后核对不等于原子 CAS。
- 未验证旧入口可以保持可见和排空已有记录，不自动安装新 Hook。未知来源历史不按当前手机或当前会话补归属；需要后续显式旧历史入口。
- 浏览器请求通过 `x-adh-device-serial` / `x-adh-package` 固定目标，异步执行沿用同一请求作用域。同包名来自多设备时，省略目标会拒绝，而不是猜第一条。传输只接收本会话对应的 cmdResult。
- 新捕获带不可变来源；分页、详情、导出、删除和内存/磁盘保留按来源隔离。未知历史保留为独立桶。设备范围的事件/产物清理暂时明确拒绝，不用全局删除冒充设备清理。
- 页面切设备即切数据身份；晚到的应用/记录请求不能覆盖下一台手机。其他设备的 WebSocket 记录不会挤掉当前记录。设备命名可跨标签共享，当前选择不通过 Host 全局变量共享。

## 已执行验证（不是最终产品验收）

- 定向测试覆盖同包名双手机、异步作用域、跨会话拒绝、PID 代际、路由别名/变更、原始数据保留、真实 store/API 代码、5037 服务名及伪造 cmdResult。
- 两台授权真机在同一个 Host 模块进程中使用独立反向通道，自加载相同隔离测试包。逐设备核对实际 Agent SHA、PID、UID/starttime，分别启用一个真实 JCA digest 重载，核对不同标记的 SHA-256 输入输出。停止一台不停止另一台。测试结束移除自有包/上传/映射，原有 Host 会话、scope/module/endpoint 哈希及 reverse 前后相同。
- 真机测试只证明这条自加载路径，不代表 Zygisk、全部算法、Web/Manager 或完整功能矩阵通过。

## 后续仍须完成

HTTP 全入口与设备列表的最终整合、按设备持久化的 Hook 配置事务、Web/Manager 两级设置、真实 UI 体验、完整双设备矩阵、无上下文子 Agent 独立体验及修复，最后再收拢旧逻辑。不得把本轮基础测试当成任务书已全部完成。
