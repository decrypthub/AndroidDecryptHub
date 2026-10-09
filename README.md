# AndroidDecryptHub

中文 | [English](README.en.md)

AndroidDecryptHub（**ADH**）是面向**授权 Android 运行时逆向分析**的开源工具。轻量 agent 注入目标进程，负责 hook、采集、trace 和 dump；电脑上的 Host ADH Daemon（`adhd`）负责存储、DEX 索引、反汇编、Web 查看器与 MCP 接口。iOS 对应项目是 [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub)。

本仓是**源码快照**，没有附带可安装的 Release。当前官方注入路径为 **Zygisk**；Frida Gadget、Xposed 和 eCapture 是开发或实验后端。交付架构仅支持 `arm64-v8a`，ART 结构解析主要在 Android SDK 35 验证、SDK 36 次级验证。不同 ROM、加固方式和调用路径需要逐项验证，工具不会保证所有目标都能脱壳或捕获全部事件。

## 功能

- Java、JNI 与 native hook；GOT、inline、调用点和函数指针槽位等后端。
- 加解密、TLS 明文、文件与系统行为的持续捕获；丢弃和截断会在结果中报告。
- 内存搜索与 dump、ART DEX 枚举、SO 重建、DEX 修复与方法体恢复。
- 持久 DEX 索引、搜索、xref、反射线索、Capstone 反汇编和算法特征识别。
- Web 只读查看器、REST/MCP 接口，以及 `adh doctor`、`adh target`、`adh unpack` 命令。

现有 crypto↔TLS 关联基于**同线程和时间窗共现**，不能证明两条记录对应同一份数据；内容关系的确定性关联尚未实现。QBDI 为可选后端。完整 MCP 工具清单见 [docs/mcp-tools.md](docs/mcp-tools.md)。

## 结构

```text
目标 App    libadh_agent.so       hook / capture / trace / dump
手机侧      Zygisk + ADH Manager  注入范围、模块状态、目标进程控制
电脑侧      adhd                  HTTP / WebSocket / MCP / DB / 分析
浏览器      Web 查看器             观察、搜索、导出
```

目标进程中的 agent 不运行 HTTP、数据库或重型分析。通信协议见 [proto/PROTOCOL.md](proto/PROTOCOL.md)。

## 构建与试用

需要 Android SDK（compileSdk 36）、NDK `28.2.13676358`、CMake、JDK 17、Node.js 24，以及一台用于设备验收的**专用、已 root 的 arm64 Android 测试机**。构建脚本支持 Windows/Git Bash 与 Linux；设置 `ANDROID_SDK_ROOT`、`ANDROID_NDK_HOME` 后，按 [构建说明](docs/BUILDING.md)执行。

```bash
bash tools/fetch_dobby.sh
bash tools/fetch_lsplant.sh   # 可选：Java method hook 后端
bash tools/build_agent.sh
bash tools/build_bundle.sh
```

在电脑上启动 Host ADH Daemon：

```bash
cd daemon
npm ci
npm start
```

默认 HTTP/WebSocket/MCP 端口为 `8088`，agent TCP 端口为 `8761`。CLI 示例：

```bash
cd daemon
node src/cli.ts doctor
node src/cli.ts target --help
node src/cli.ts unpack --help
```

Host 单元测试：`cd daemon && node --test test/*.test.ts`。设备验收由 `tools/verify_all.sh` 驱动，会操作当前连接的手机；**只在明确指定的专用测试设备上运行**。

## 使用与安全边界

仅分析自己拥有或获得授权的 App。ADH 不提供法律取证所需的证据保全保证，也不授权传播从目标提取的内容。捕获的密钥、明文和 dump 必须留在私有环境；`captures/`、`dumps/` 与 `adhd-data/` 已被 Git 忽略。

**当前 Host HTTP `8088` 与 agent TCP `8761` 均监听所有网卡，尚无身份认证。**只在可信网络或隔离环境中运行，不要暴露到公网。详见 [安全边界](docs/SECURITY.md)。

## 许可证

本仓自有源码采用 [MIT](LICENSE)，与 iOS 项目一致。构建时获取的第三方依赖仍受各自许可证约束，尤其是 LGPL-3.0 的 LSPlant；见 [NOTICE](NOTICE)。
