# Android DecryptHub

Android DecryptHub（ADH）是一套 Android 运行时分析工具。它把一个轻量程序注入到你勾选的应用里，观察这个应用在运行时做了什么：网络、加密、Java 方法、native 函数、内存和 DEX。重的分析放在电脑上，不放进目标应用。

在电脑的任务工作台编辑 Hook 方案。MCP `hook_plans`、Python CLI `adh call/run hook_plans` 和工作台共用执行层，分别报告保存、暂存与实际安装的状态。迁移与兼容边界见 [P5_HOOK_PLANS.md](docs/P5_HOOK_PLANS.md)。

P5 后续已完成真实 Android 独立沙盒验收，并在正式 Zygisk 回调/companion/post-specialize 的隔离命名空间中完成七族代表性捕获、全部禁用、LAN 授权撤销及 UID/Agent/过期等拒绝，共15/15。详见[正式链验收与未验证边界](docs/P5_ZYGISK_EXTENDED_ACCEPTANCE.md)；默认模块/Manager/生产 RootDaemon 的部署升级仍待验证。

## 能做什么

**只影响勾选的应用。** 在手机上的 ADH Manager 里勾选注入范围并保存，然后重新打开该应用。主进程和 `:core` 这类子进程都会注入。没勾选的应用不会注入。

**用代理看 HTTPS。** 手机负责系统 CA 管理；Java trust-manager bypass 由 Host 显式执行 `java_hook action=bypass`。native 的 `SSL_read` / `SSL_write` 明文由显式捕获方案控制。注入与连接本身不会自动安装这些 Hook。

**记录 Java 加密。** Host 可显式执行 `java_hook action=crypto`，或用方案中的 Java 方法步骤观察这些接口；原来的方法照常执行：

| 接口 | 记下什么 |
| --- | --- |
| `javax.crypto.Cipher` | `init`、`doFinal`。包括 AES（CBC、GCM 等）和走 `Cipher` 的 RSA 加解密 |
| `javax.crypto.Mac` | `init`、`doFinal`。例如 HmacSHA256 |
| `java.security.MessageDigest` | `digest`。例如 MD5、SHA-256 |
| `java.security.Signature` | `initSign`、`initVerify`、`sign`、`verify`。例如 SHA256withRSA |

每条记录按接口能力包含算法名、操作、密钥、IV、输入和输出。方案中的 family 控制后续 native 捕获安装资格；Manager 保留旧配置快照和缓存撤销入口，编辑方案在 Host 完成。Java 原语的覆盖边界以工具返回和实际事件为准。

这些情况记不到，或只能记到一部分：

- 数据是分片 `update()` 再空参收尾时，输出还在，输入不在。
- 结果写进调用方自己缓冲区的重载，输入还在，输出不在。
- 密钥放在 Android Keystore 里时，`getEncoded()` 为空，密钥字段就是空的。
- `Cipher.wrap` / `unwrap`、密钥协商、PBKDF2 / HKDF 没有钩。
- 应用自己实现的算法，以及直接调用 `libcrypto` 的路径，不走上面这四个接口。native OpenSSL / BoringSSL 要在电脑上开始采集才会装。

**继续往下看实现。** 同一个注入进程里还可以：

- Hook Java 方法、JNI 和 native 函数（GOT、inline、调用点、函数指针槽）。
- 搜索和导出内存，枚举已加载的 DEX，修复并重建 DEX，反汇编 so。
- 在电脑上做 DEX 索引、搜索、引用关系和算法特征识别。
- 用浏览器查看采集结果，或通过 MCP 让分析程序直接查询。工具清单见 [docs/mcp-tools.md](docs/mcp-tools.md)。

## 环境

- 一台已 root、并开启 Zygisk 的手机（KernelSU 或 Magisk）。正式支持的 ABI 是 **arm64-v8a**。
- 一台运行 Host ADH Daemon 的电脑。设备管理支持 USB 和已配对的 LAN。
- 从源码构建时还需要 Android SDK、NDK `28.2.13676358`、CMake、JDK 17 和 Node.js 24。脚本在 Git Bash 或 Linux 下运行。

## 快速开始

### 1. 核对旧配置

升级前备份原 Host 数据目录（默认是旧工作目录里的 `adhd-data/`）和手机上的 `/data/adb/adh/`。手机备份包含应用范围 `scope.json`、Host 地址 `host.endpoint` 及已有的设备身份和配对资料，请私下保存。旧 Host 使用外置采集目录时，同时保留原 `ADH_CAPTURES_DIR`。

用同一版本的 Host、模块和 ADH Manager，就地更新并保留应用数据。Manager 的签名须与已安装版本一致。切换 Host 工作目录时，将 `ADH_DATA_DIR` 指向原目录。启动后在 ADH Manager 核对应用范围，在任务工作台点击「快速开始 → 查看 Host 配置」对照备份。方案编辑的入口是工作台「Hook 方案」。源码安装见[构建指南](docs/BUILDING.md)，保留目录的细节见 [P0 存储说明](docs/P0_HOST_STATE.md#初始化与存储)。

### 2. 确认设备连接

在电脑上运行以下命令启动配套 Host ADH Daemon。

```bash
cd daemon
npm ci
npm start
```

用配套 `adh` CLI 发现 USB 设备，将返回的 `serial`、`transportId` 填入连接命令，然后用 `adh tasks get` 查看连接操作状态。示例用电脑上的默认 Host 地址。

```bash
adh call devices --arguments '{"action":"discover","transport":"adb"}' --endpoint http://127.0.0.1:8088
adh run devices --arguments '{"action":"connect","transport":"adb","serial":"SERIAL","transportId":"TRANSPORT_ID"}' --endpoint http://127.0.0.1:8088
adh tasks get OPERATION_ID --endpoint http://127.0.0.1:8088
```

连接操作显示 `succeeded` 后，打开 Host 地址下的 `/workbench?view=quick-start`，点击「检查设备连接」。有多条在线连接时，选定要核对的那条。已有配对的设备也可按 [LAN 说明](docs/P4_LAN_AUTH.md#公共调用顺序)连接。

### 3. 读取首条诊断结果

点击「读取诊断结果」，核对回执中的设备 ID、连接 ID、设备型号和状态版本。这个页面可在观察模式下使用。设备断开后，重新检查连接再读一次。先在隔离沙盒做一遍，可以看到带「隔离沙盒」来源标记的 `JVM fixture` 回执。

### 在隔离沙盒复验

准备 Node.js 24、JDK 17、Android SDK 和 Git Bash（Windows）。在仓库执行以下命令。Windows 使用 Git Bash 的 `./gradlew` 或 PowerShell 的 `.\gradlew.bat`。

```bash
cd device
./gradlew :daemon:writeDeviceRpcFixtureClasspath
cd ../daemon
npm ci
node test/fixtures/upgrade_quick_start.ts
```

脚本在临时目录放入 0.6.0 格式的旧配置，执行安装包共用的范围初始化，再通过 Host 的实际 HTTP 路由及 JVM 设备沙盒验证旧值、身份连接和诊断回执。给最后一条命令加 `--serve`，打开终端输出的 `QUICK_START_URL` 可以走同一套工作台步骤。输入 `stop` 可关闭沙盒并清理临时文件。沙盒使用回环连接，默认安装包在 Android 上的部署和升级另行验收。

## MCP 客户端

用我们已开源的 `adh` CLI 接 AI 客户端（PyPI 包 `android-decrypt-hub`，源码 [decrypthub/adh-cli](https://github.com/decrypthub/adh-cli)）：

```bash
pip install android-decrypt-hub
adh connect 127.0.0.1:8088      # 按包固定：adh connect 127.0.0.1:8088/<包名>
```

客户端的 MCP 配置（`adh mcp` 把 Host 的 `POST /mcp` 转成 stdio，客户端只认这个）：

```json
{
  "mcpServers": {
    "adh": {
      "command": "adh",
      "args": ["mcp"]
    }
  }
}
```

网页顶栏的 MCP 面板就是这三段，地址按当前页面生成。

## 各部分怎么分工

| 位置 | 做什么 |
| --- | --- |
| 目标应用里的 `libadh_agent.so` | hook、采集、trace、dump。不做网页、数据库和反汇编 |
| 手机上的 Zygisk 模块和 ADH Manager | 决定注入哪些应用，查看模块状态，停止或重启目标进程 |
| 电脑上的 Host ADH Daemon（`adhd`） | 保存记录，做 DEX 索引和反汇编，提供网页和 MCP |

默认端口：网页和 MCP 是 `8088`，手机上的 agent 连接电脑用 `8761`。可以用 `ADH_HTTP_PORT` 和 `ADH_AGENT_PORT` 改。

**这两个端口目前没有登录验证，并且监听所有网卡。** 只在你信任的网络里开，不要暴露到公网。

## 在 KernelSU 或 Magisk 里更新

模块信息里有一条 `updateJson`。KernelSU、KernelSU Next 和 Magisk 会读取这个地址。远端的 `versionCode` 比手机上已安装的更高时，模块页面会出现更新。点更新会安装新的 zip，并在安装脚本里重新安装附带的 ADH Manager。已经勾选的注入范围留在 `/data/adb/adh/scope.json`，不会被清空。更新后重启手机。

没有 `updateJson` 的旧模块使用管理器里的「从本地安装」。按[快速开始](#快速开始)备份并核对旧配置。

## 许可证

本仓库自己的代码使用 [MIT](LICENSE)。构建时拉取的第三方组件仍使用各自的许可证，其中 LSPlant 是 LGPL-3.0。见 [NOTICE](NOTICE)。
