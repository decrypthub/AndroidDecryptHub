# Android DecryptHub

Android DecryptHub（ADH）是一套 Android 运行时分析工具。它把一个轻量程序注入到你勾选的应用里，观察这个应用在运行时做了什么：网络、加密、Java 方法、native 函数、内存和 DEX。重的分析放在电脑上，不放进目标应用。

## 能做什么

**只影响勾选的应用。** 在手机上的 ADH Manager 里勾选注入范围并保存，然后重新打开该应用。主进程和 `:core` 这类子进程都会注入。没勾选的应用不会注入。

**用代理看 HTTPS。** 应用被注入之后，Java 侧的证书校验会放行。配合你自己的抓包代理（系统代理或 VPN），可以看到这个应用发出的 HTTPS。native 的 `SSL_read` / `SSL_write` 明文是另一项，要在电脑上开始采集才会装，Manager 里的「TLS 明文」开关管的是这一项。

**记录 Java 加密。** 注入后自动观察这些接口，原来的方法照常执行：

| 接口 | 记下什么 |
| --- | --- |
| `javax.crypto.Cipher` | `init`、`doFinal`。包括 AES（CBC、GCM 等）和走 `Cipher` 的 RSA 加解密 |
| `javax.crypto.Mac` | `init`、`doFinal`。例如 HmacSHA256 |
| `java.security.MessageDigest` | `digest`。例如 MD5、SHA-256 |
| `java.security.Signature` | `initSign`、`initVerify`、`sign`、`verify`。例如 SHA256withRSA |

每条记录包含算法名、操作（加密、解密、摘要、签名等）、密钥、IV、输入和输出。Manager 里可以按应用关掉某一族（摘要、HMAC、对称、非对称、AEAD）；关掉的族不会安装钩子。保存后要重启该应用。RSA 加解密跟着「对称」或 AEAD，RSA 签名跟着「非对称」。

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
- 一台运行 Host ADH Daemon 的电脑。手机通过 `adb reverse` 连到这台电脑。
- 从源码构建时还需要 Android SDK、NDK `28.2.13676358`、CMake、JDK 17 和 Node.js 24。脚本在 Git Bash 或 Linux 下运行。

## 安装和使用

1. 构建安装包并刷入手机，然后重启，让 Zygisk 和手机侧服务起来：

   ```bash
   bash tools/fetch_dobby.sh
   bash tools/fetch_lsplant.sh
   bash tools/build_bundle.sh
   bash tools/flash_device.sh --reboot
   ```

   也可以在 root 管理器里选择「从本地安装」，安装 `injector/zygisk/dist/` 下的 bundle zip，然后重启。

2. 打开 **ADH Manager**。在「注入范围」勾选要分析的应用，需要的话再调整该应用的 Hook 配置，保存。

3. 重新打开目标应用。

4. 在电脑上启动守护进程，并把端口转到手机：

   ```bash
   bash tools/dev_up.sh
   ```

   这条命令会启动 Host ADH Daemon，并设置 `adb reverse`。也可以自己启动：

   ```bash
   cd daemon
   npm ci
   npm start
   adb reverse tcp:8088 tcp:8088
   adb reverse tcp:8761 tcp:8761
   ```

5. 用浏览器打开 `http://<电脑的局域网地址>:8088/<应用包名>`。Web 界面用来查看和搜索，不在网页里改目标。

抓包时，先让抓包工具在手机上生效，再操作已经注入的应用。算法记录在应用进程里产生，电脑上的守护进程连上之后才会出现在采集结果里。

命令行可以检查连通和导出 DEX：

```bash
cd daemon
node src/cli.ts doctor
node src/cli.ts target --help
node src/cli.ts unpack --help
```

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

现在手机上如果装的是还没有 `updateJson` 的旧模块，管理器不会出现这个更新按钮。需要手动刷入一次 v0.3.14，之后的版本就可以在管理器里更新。

## 许可证

本仓库自己的代码使用 [MIT](LICENSE)。构建时拉取的第三方组件仍使用各自的许可证，其中 LSPlant 是 LGPL-3.0。见 [NOTICE](NOTICE)。
