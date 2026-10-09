# 交接文档 —— 接手 ADH 开发的 Agent 先读这一份

> 写给**下一个接手本项目的 Agent**。你大概率在**另一台机器**上，并且用户会给你**一台能刷模块、有 root 的手机**。
> 交叉引用（不重复内容）：规格 `REQUIREMENTS.md` / 路线 `DEVELOPMENT_PLAN.md` / 当下进度 `PROGRESS.md` /
> 功能状态 `FEATURE_STATUS.md` / 实战记录 `CASE_STUDIES.md` / 硬规则 `CLAUDE.md`（**自动加载，先读它**）。
> 本文件只放三样：**环境真相（按档案分）**、**不在其它文档里的坑**、**接着做什么**。
> 写于 2026-09-29，基于 HEAD `34f8ecc`。

---

## 0. 一句话状态

`libadh_agent.so` + Host ADH Daemon + `adh` CLI 都已实现；注入后端**只有 Zygisk 是官方路径**（另有 Gadget/Xposed/eCapture 三个实验后端）。**门禁已全量跑过**：
2026-10-01 在 Linux 接管机上（设备 `aa165071`，agent 换成本机构建的 `78d9d20f…`）见 `FEATURE_STATUS §2.1`；
上上轮 2026-09-29（二）**103 PASS / 11 FAIL / 4 SKIP**
（host 36 = 29/5/2，device 82 = 74/6/2）。**11 条 FAIL 没有一条能归到产品代码**：7 条是本机缺
Windows 工具链/依赖、2 条是**门禁自己的断言缺陷**、2 条是文档已登记的偶发。**device 半段是健康的**
（赛前预测的 4 条环境噪声全部命中，无意外红）。逐条见 `PROGRESS.md` 2026-09-29（二）。
加解密/脱壳/抓包三条线的能力地图见 §5——**下一步最该做的是 §5 第一梯队第 1b 条：把那 9 条环境项治掉**，
否则门禁在这台机器上会一直带着已知噪声。

---

## 1. 环境真相 —— **先确认你在哪一组，两组结论相反**

### 1.0 先跑这个（30 秒定性）

```bash
adb devices                                  # 拿到 serial
adb -s <serial> shell 'id; which su'         # 有 uid=0 / 有 su → 你是 B 组
adb -s <serial> shell getprop ro.build.version.sdk   # 记下 API level（见 §1.3，这决定第一件事做什么）
```

**A 组（原始 Windows 工作站 + 用户日常机）**：没有 root，**那台手机不要碰**。
**B 组（你接管的机器 + 用户给你的可刷机）**：root 与刷模块全部可用，**走常规路径**。

### 1.1 A 组：原始工作站那一台（仅在你在它上面干活时适用）

`a22fecdd` / PGP110 / **Android 15（SDK 35）** / arm64-v8a，实测（2026-09-29）：

| 检查 | 命令 | 结果 |
|---|---|---|
| 无 root | `adb shell id` | `uid=2000(shell)`，非 root |
| 无 su | `adb shell which su` | 无 |
| 无 Magisk | `adb shell ls /data/adb` | `Permission denied` |
| 沙盒没装 | `adb shell pm list packages \| grep adh` | 空 |

**它是用户日常在用的手机。** 因此：❌ 不许刷（`tools/flash_device.sh`）、❌ 不许装（`install_apk_root` 用
`su + pm install`，没有 su 必然失败；改用 `adb install` 也是往用户手机上装 App，不要做）、❌ 不许用
`am force-stop`/`am start` 起停沙盒。⚠️ `tools/dev_up.sh` 会对**当前连着的设备**执行 `adb reverse`
（在用户手机上建两条反向隧道）——host-only 的活直接 `cd daemon && node src/index.ts`，别跑它。

**结果**：82 个 device 脚本既起不了沙盒也连不上 agent，会**失败或挂住**（上一轮实测挂了一个多小时，
要手工 kill 收场）。所以**在 A 组不要跑全量 `tools/verify_all.sh`**，只跑 host 子集（§2.2）。

### 1.2 B 组：你接管的机器（**预期的主场景**）

用户会给你**一台能刷模块、有 root 的手机**。于是常规路径全部可用：

> ⚠️ **先读 §1.5**：2026-10-09 已补齐 SDK 36 和 Gradle 8.9 wrapper 缓存，公开快照的 Agent、APK 与 Zygisk bundle 均能在本机编译；但新 Release 没有刷入真机。私有 SMB 工作树的 wrapper 没有可执行位，构建脚本改用 `bash ./gradlew`。

- `tools/fetch_qbdi.sh` / `fetch_dobby.sh` / `fetch_lsplant.sh`（一次性第三方拉取，进 `agent/third_party/`）
- `tools/build_agent.sh` / `build_detect.sh` / `build_zygisk.sh` / `build_bundle.sh`
- `tools/flash_device.sh --reboot`（KernelSU/Magisk 刷入 Zygisk 模块；多设备时 `export ANDROID_SERIAL=<serial>`）
- `install_apk_root`（`su` + `pm install`）装沙盒
- `tools/verify_all.sh` **全量**（**117 脚本 = 36 host + 81 device**，2026-10-01 起 eCapture 那条移出闸门）——这才是设计的常规门禁

**你要做的第一件事：把设备事实记录到本文档 §1.3 的表里**（机型 / API / ABI / root 方式 / serial）。
后面所有人（包括下一个 agent）都靠这张表判断 ART 解析器覆盖面与可用后端。

### 1.3 设备选型的硬约束（**先看这条再决定从哪开始**）

- **ART 结构级 dex 解析器目前只验证到 SDK 35（主）/ 36（次）**。它是靠 per-API-level 的结构体布局
  （`agent/src/runtime/art.c`）+ 宿主侧 DEX 解析实现的。
  **如果你拿到的手机不是 SDK 35/36，第一条任务就是补解析器覆盖**，症状会是 `art_dexfiles` 失败或
  返回 0——**别把它当成"工具坏了"**，那是覆盖率问题，而且它本身是一个有价值的结果。
- **agent ABI 只交付 `arm64-v8a`**（`tools/lib/env.sh` 的 `ABI="${ABI:-arm64-v8a}"`）。手机必须是 arm64。
  **这是已确认的产品边界（2026-10-01 决议），不是暂时没做**：armeabi-v7a 与 x86_64 都不做，
  重新考虑的条件只有"出现必须支持的真实 32 位目标"。
- 本项目的参考设备是 OnePlus PGP110，其 ColorOS ROM **`libart.so` 被裁得很厉害**——所以
  原生 inline hook 后端用的是验证过的 Dobby，而**按符号名 hook 某些 ART 内部函数可能找不到符号**
  （二代还原点会遇到这个问题，见 §5 B2）。
- 模拟器不推荐替代真机：本项目验的东西（Zygisk 注入、memfd 加载、真实加固目标）在模拟器上多半
  不成立或不可信。**模拟器只在"手边没有真机时"当勉强替代**，且要先解决两个阻塞点：镜像是 x86_64
  vs agent 只交付 arm64-v8a（**这个阻塞点是永久的**——多架构已决议不做）；镜像是 API 37 vs 解析器只覆盖 35/36。

#### 1.3.1 已记录设备事实

> 每换一台机器/手机，**先更新这张表再推进**。

| 机器档案 | serial | 机型 / ROM | Android / SDK | ABI | root | 实测日期 |
|---|---|---|---|---|---|---|
| **B 组 · Linux 接管机**（工作树是 SMB 共享 `//Russell.lan/X`，见 §1.5） | `aa165071` | OnePlus PGP110（`OP5551L1`，`PGP110_15.0.0.1901(CN01)`） | 15 / **35** | arm64-v8a | **KernelSU**（`su` → `uid=0(root)`） | 2026-09-29 |
| A 组 · 原始 Windows 工作站（日常机，**不可动**） | `a22fecdd` | OnePlus PGP110 | 15 / 35 | arm64-v8a | **无** | 2026-09-29 |

`aa165071` 这个 serial **就是 2026-09-23 那次 113 PASS / 0 FAIL / 0 SKIP 全量门禁的同一台机器**——
所以它是"已知全绿"的参考设备，不是新设备。

> ⚠️ **2026-10-01 更新**：设备上的 agent 已从 `82e0cfb5…` 换成**本机构建的 `78d9d20f…`**（删掉 9 条沙盒耦合命令后的产物）。
> Manager / Device Daemon / Zygisk companion 三个 APK 未变，**不需要重刷模块**。

**接管当天实测：设备上刷的包与本仓 HEAD 逐字节一致，不需要重刷。**（2026-09-29，HEAD `c273ef4`）：

| 文件 | 设备路径 | sha256（设备 == 本仓构建产物） |
|---|---|---|
| agent | `/data/adb/modules/adh/libadh_agent.so` | **`78d9d20f…`**（2026-10-01 更新）== `agent/build/libadh_agent.so`；同值也写进沙盒 `…/lib/arm64/libadh_agent.so` |
| Manager | `/data/adb/modules/adh/manager.apk` | `e0b2a83d…` == `device/manager/build/…/manager-debug.apk` |
| Device Daemon | `/data/adb/modules/adh/daemon.apk` | `87c2df98…` == `device/daemon/build/…/daemon-debug.apk` |
| 沙盒 | `com.adh.sandbox`（`lastUpdateTime` 2026-09-27 00:13:07） | 与本仓 `sandbox-app/…/app-debug.apk` 同一次构建 |

因此 `FEATURE_STATUS.md` 里"当前源码需要重建 release bundle 后再发布/刷机"是**过时结论**，已订正。

### 1.4 参考仓库（靶子来源，与机器无关）

- `https://github.com/CYRUS-STUDIO/CyReverse` —— **教学性质的逆向示例代码**（不是加壳样本集），
  104 篇文章的配套源码：加壳/脱壳/反调试/抓包/魔改算法都有。
- 本仓库已按它做了 `fixtures/crypto-variants/`（洁净室代码 + 相同常量值）。
- 有用的原件（若你要重新拉：`git clone --depth 1` 到仓库外）：
  - 变异算法：`app/src/main/cpp/{md5_change_constant,sha1_change_constant,custom_base64_alphabet,dynamic_base64_alphabet,custom_crc32_table}.cpp`
  - 抽取壳：`app/src/main/java/com/cyrus/example/shell/DexExtract.kt` + `hook/CyrusStudioHook.kt`
    + `app/src/main/cpp/cyrus_studio_hook.cpp`；资产 `app/src/main/assets/classes3{,_extracted}.dex`
- ⚠️ **顶层没有 LICENSE**（= 保留所有权利）。**不许把它的源码拷进本仓库**。可以"照原理自己写 + 拿它当
  外部靶子（在仓库外自己 build）"。

### 1.5 接管机的工具链真相（**2026-09-29 新增；2026-10-01 订正 —— 先读这条**）

> **2026-10-09 最新补记**：Android SDK `/home/r/Android/Sdk` 已安装 platform 36；NDK `/home/r/tools/android-ndk-r29`、Gradle 8.9 wrapper 缓存、CMake/Ninja/Java 21 可用。从公开快照 `/home/r/AndroidDecryptHub-public` 实测 `ANDROID_SDK_ROOT=/home/r/Android/Sdk ANDROID_NDK_HOME=/home/r/tools/android-ndk-r29 bash tools/build_agent.sh`、`bash tools/build_bundle.sh` 均成功，`device :core:test :daemon:assembleDebug :manager:assembleDebug` 成功。**下面标记“缺 gradle / 不可构建 APK”的段落是 2026-10-01 历史事实，不再是当前限制。** 私有 SMB 树的 Gradle wrapper 是 664，使用 `bash ./gradlew`；不要把公开快照的构建通过误记为私有树的一次独立构建通过。新 ZIP 尚未刷入设备。

§1.2 假设"B 组机器上常规路径全部可用"。实测：**接管机是一台 Linux，不是 Windows**，`su`/刷机/装 APK 都能做。
**2026-10-09 已从公开快照在本机成功构建 agent `.so`、APK 与 Zygisk bundle。**

- ✅ **能跑**：Host ADH Daemon、`adh` CLI、`tools/verify_*:host` 全部 host 脚本（node 直接跑 `.ts`）。
- ✅ **agent `.so` 能在本地重建**：本机有 CMake/Ninja 与 NDK `/home/r/tools/android-ndk-r29`。
  `tools/build_agent.sh` 已有 Linux fallback，并会避开 Windows 生成的 CMake cache；在本地盘上的公开快照实测成功。命令：
  `ANDROID_SDK_ROOT=/home/r/Android/Sdk ANDROID_NDK_HOME=/home/r/tools/android-ndk-r29 bash tools/build_agent.sh`。
- ✅ **APK / Zygisk bundle 能在本机编译**：`/home/r/Android/Sdk` 有 platform 36，Gradle 8.9 wrapper 已缓存；
  公开快照的 `device :core:test :daemon:assembleDebug :manager:assembleDebug` 与 `bash tools/build_bundle.sh` 成功。
  私有 SMB 工作树尚未独立重跑构建，且 wrapper 文件没有可执行位；调用 wrapper 时使用 `bash ./gradlew`。
- **不重打 APK 也能把新 agent 送上设备（2026-10-01 实测）**：沙盒的 native 库是**解压式安装**，
  `adb push` 新 `.so` → `su -c 'cp … /data/app/*/com.adh.sandbox*/lib/arm64/libadh_agent.so'`
  + `chcon u:object_r:apk_data_file:s0` → `am force-stop` / `am start` 即可（Zygisk 那条路同时换
  `/data/adb/modules/adh/libadh_agent.so`）。**改了 agent 源码就要走这一步**，否则设备上跑的还是旧 `.so`
  而门禁会绿着撒谎（§3.1）。前提是**沙盒夹具本身一行都不改**——那是要重打 APK 的。
- 私有树 `agent/build/` 与 `device/*/build/` 是**共享树上的旧产物**，部分 cache 仍有 Windows 路径。
  Agent 脚本检测 Windows cache 后另开 Linux 构建目录；SMB I/O 较慢，发布重建优先使用本地盘上的公开快照。
- 其它实测偏差：
  - `node` 是 **v22.23.2**（本文档/`CLAUDE.md` 写 v24）。strip-only TS 仍可跑（`adh --help` 正常），
    但别依赖 node 24 独有行为。
  - 工作树挂在 **SMB2**（`//Russell.lan/X`），I/O 是这台机器的主要成本：daemon **冷启动 ~33s**
    （从磁盘重新哈希恢复 290 个工件 / 1304 MiB），单个 host 验收脚本 **40–80s**。
    进程卡在 `D` 状态（`folio_wait_bit_common`）是**正常现象，不是死锁**，等它读完。
  - `sudo` 免密可用。`/etc/udev/rules.d/51-android.rules` 原先**只有 Google `18d1` 一条**，
    因此 OPPO/OnePlus（`22d9`）报 `no permissions`——已补 `22d9` 规则并
    `sudo udevadm control --reload-rules` + `udevadm trigger`（无需重新插拔）。
  - ⚠️ **多设备时 `dev_up.sh` 会挑错设备**：它用 `adb devices | awk 'NR==2{print $1}'` 取第一台，
    而接管机上 `NR==2` 是那台**未授权**的 Google 机（`1A281FDEE003ZV unauthorized`），
    于是 `adb reverse` 静默落在错的设备上、OPPO 上没有隧道、device 脚本连不上 agent。
    **跑 `dev_up.sh`（以及 `flash_device.sh`、`verify_all.sh`）前一律先 `export ANDROID_SERIAL=aa165071`。**
    注意 `verify_all.sh` 里 `am force-stop`/`am start` 也**不带 `-s`**，所以更依赖这个变量（它由 adb 自己认，
    一处 export 全覆盖）。
  - ⚠️ **`tools/frida/node_modules/` 是跨 OS 的坑**：共享树里那份是 **Windows 装的**，
    带的是 `@esbuild/win32-x64`，于是 `verify_v30_fridagadget.sh` 在 Linux 上 `bundle failed`（`loader rc=1`）。
    反过来在 Linux 上 `npm install` 也可能顶掉 Windows 那份。**这类依赖不该跟着 SMB 树走。**
  - ⚠️ **`adhd-data/` 不该放网络盘 —— 这台机器上它已经害过事，必须改（2026-09-30 实测）**：
    `dex-index.sqlite` 被**两台机器同时在写**（同一个 SMB 共享树），库直接损坏——daemon 报
    `SQLITE_CORRUPT`（"database disk image is malformed"），4 个 dex 里 **3 个分类失败**；
    更离谱的是**在 Linux 上连改名都做不到**（`mv` → "设备或资源 busy"，因为**另一端还开着它**），
    这正是"两个写者"的直接证据。
    **`export ADH_DATA_DIR=/home/r/adh-data`（本地盘）再启动 daemon**，实测同一个索引从
    "3/4 失败"变成 **4/4 分类、1 秒完成**，且 `verify_v29_dexindex` 的 `queryMs` 从 **466ms 掉到 1.72ms**。
    ⚠️ **注意 `dev_up.sh` 启动 daemon 时不会替你设这个变量**——必须自己 export
    （`verify_all.sh` 会调 `dev_up.sh`，所以跑门禁前也要 export）。
    `state.ts:123` 读 `ADH_DATA_DIR`（默认仍是仓库内 `adhd-data/`，单机使用不受影响）。
    `dex_index.ts` 另有 `ADH_SQLITE_JOURNAL` 逃生阀（默认仍 `WAL`，**未改默认值**——见那里的注释：
    并发写者才是实测到的真因，改日志模式没被测出能防住任何东西）。
  - ⚠️ **`v07` / `v07_flow` / `v34_ecapture` 起的 TLS 测试服务器在 Linux 上杀不掉**：
    它们的清理用 `powershell.exe` + `taskkill`，在这台机器上是 **no-op**，于是
    `daemon/tls_test_server.mjs` 会残留（实测抓到一个活了 23 小时的）。副作用不只是脏：
    **下一轮 v07 可能是在跟这个陈旧服务器对话而通过**。跑完门禁记得查一下有没有残留。
  - ⚠️ **共享树上任何文件都不可能可执行**（2026-09-30 实测，影响面很广）：
    CIFS 挂载参数是 `nounix,file_mode=0664,dir_mode=0775`——**服务端不存 Unix 权限位**，
    客户端把**所有**文件强制成 `0664`。于是 `chmod +x` 看起来成功、`ls` 仍是 `-rw-rw-r--`。
    症状是"找不到/权限错"，例如 `npm install` 装好的 esbuild 报
    `spawn …/@esbuild/linux-x64/bin/esbuild EACCES`。
    **凡是需要从这棵树里 *执行* 东西的，都要先把可执行文件拷到本地盘**——
    `tools/compile_frida_script.sh` 已经这么做了（拷到 `~/.cache/adh/` 并设 `ESBUILD_BINARY_PATH`）。
  - **本机已经有一个可用的 Linux NDK**：`/home/r/tools/android-ndk-r29`（含 `clang` / `jni.h` / llvm 工具）。
    `tools/lib/env.sh` 现在会自动解析 `ADH_NDK_BIN`/`CLANG`/`JNI_H`（先看 `ANDROID_NDK_HOME`，再看配置的 `$NDK`，
    再扫 `~/tools/android-ndk-*`、`~/Android/Sdk/ndk/*`、`/opt/android-ndk-*`）。
    **`$NDK` 本身刻意不动**（它驱动 Windows 构建路径），所以这台机器上 `$NDK` 仍指向 Windows 路径、
    而 `$CLANG`/`$JNI_H` 指向本地 r29——这是有意的。`llvm-objdump`/`llvm-readelf` 装了 apt 的 `llvm`（21.x），
    与 NDK 自带那份输出格式一致。**`verify_v01` 仍缺构建链（`cmake`/`ninja`/`gradle` + Android SDK），
    那是"要不要在这台机器上做完整构建"的环境决策，不是路径 bug。**

---

## 2. 怎么干活

### 2.1 循环（与 `CLAUDE.md` 一致）

**Explore → Plan → Implement → Verify → 更新 `docs/PROGRESS.md` → commit**，一个切片一个闭环。
**没有 pass/fail 信号就不算做完**——这是本项目最硬的一条，见 §3.1。

### 2.2 门禁

- **B 组（有可刷机）**：`bash tools/dev_up.sh` 然后 `bash tools/verify_all.sh` 全量。device 脚本自己会
  启停沙盒；SKIP 是"前置缺失"，不是通过（见 §3.1）。
  ⚠️ 多设备时先 `export ANDROID_SERIAL=<serial>`——`dev_up.sh` 用 `adb devices | awk 'NR==2{print $1}'`
  选设备，会挑中第一台（可能是未授权的那台），`adb reverse` 就静默落在错的设备上（§1.5）。
- **A 组（无 root）**：只跑 host 子集。**下面的 recipe 会把 SKIP 当 PASS**（SKIP 一般 `exit 0`），
  所以**必须再按 `RESULT:` 句柄复核一遍**：

```bash
cd daemon && node src/index.ts &      # 不要跑 dev_up.sh，它会动用户手机
cd .. && for s in $(grep -oE '"verify_[^"]+\.sh:host"' tools/verify_all.sh | tr -d '"' | sed 's/:host//'); do
  bash "tools/$s" >/tmp/vr_$s.log 2>&1
  if   grep -q 'RESULT:SKIP' /tmp/vr_$s.log; then echo "SKIP $s"
  elif grep -q 'RESULT:FAIL' /tmp/vr_$s.log; then echo "FAIL $s"; tail -5 /tmp/vr_$s.log
  elif grep -q 'RESULT:PASS' /tmp/vr_$s.log; then echo "PASS $s"
  else echo "?    $s (no RESULT sentinel — 看日志里的 ✅/❌ 行)"; fi
done
```

**2026-09-29（二）在 Linux 接管机上的基准：29 PASS / 5 FAIL / 2 SKIP**，逐条原因见 `PROGRESS.md`
同一天那一节。**别把这次的 5 个 FAIL 当成"代码坏了"**——3 个是缺 Windows 路径下的 LLVM 工具，
1 个是门禁自身的断言缺陷，1 个是 SMB 上的 SQLite 结构性超时。

### 2.3 新机器接管顺序（照 `CLAUDE.md` 的复现顺序，这里补齐容易漏的）

1. 工具链：**node 24**（daemon 直接跑 `.ts`，无构建步骤；实测 node 22 也能跑，但 v101 的 reporter 断言会咬人）；
   Android SDK + **NDK `28.2.13676358`** + `cmake/3.22.1`；`ANDROID_SDK_ROOT` / `ANDROID_NDK_HOME` 按需覆盖
   （`tools/lib/env.sh` 读它们，但它把 `windows-x86_64` 与 `.exe` **写死了**，见 §1.5）。
   **如果这台机器不构建（只跑门禁），这一步可以跳过**——只要 `agent/build/` 与 `device/*/build/` 里的产物
   跟 HEAD 一致即可（用 §1.3.1 的 sha256 对照法自证）。
2. `bash tools/fetch_qbdi.sh` → `fetch_dobby.sh` →（可选）`fetch_lsplant.sh`
3. `bash tools/build_agent.sh` → `build_detect.sh`
4. **先跑 host 子集（§2.2）**，按 `RESULT:` 句柄看真实数字（别只看退出码）→ 再 `dev_up.sh` + 装沙盒 + 全量门禁。
   这能把"环境没搭好"和"代码坏了"分开。
5. 记录设备事实到 §1.3.1 的**已记录设备事实**表（机型 / API / ABI / root 方式 / serial），
   并用 sha256 对照确认"设备上刷的 == 本仓构建的"。
6. 本项目**没有 CI**：门禁就是唯一信号，别指望别的东西告诉你有没有坏。

### 2.4 加一项能力的标准动作（四件套，缺一不可）

1. 实现（`.so` / daemon `.ts` / CLI 子命令）
2. **验收脚本** `tools/verify_v1XX_*.sh`（照 `tools/MAP.md` 的配方）
3. **注册进 `tools/verify_all.sh` 的 `SCRIPTS`**（`:host` 或 `:device`）——不注册 = 永远不会跑
4. 文档同步：`tools/MAP.md` + 对应层 `MAP.md` + `docs/PROGRESS.md` +（若新增 MCP 工具）`docs/mcp-tools.md`；
   改 `CLAUDE.md` 必须**同步 `AGENTS.md`**（两者除标题行外必须一致）

### 2.5 目标解析：用 `adh` CLI，别手搓

```bash
SID="$(cd daemon && node src/cli.ts target --package com.adh.sandbox --quiet)"   # exit 3 = 没 agent
```

"找在线 agent → 按 `connectedAt` 取最新 → 拿 sessionId"这段曾被抄进 **76 个** verify 脚本；
现在只有一份实现（`daemon/src/cli.ts`）。`tools/MAP.md` 的"新增验收脚本"第 7 步写了用法。
`adh doctor` 会直接告诉你**手机上刷的 agent 版本 vs 本仓源码版本**是否一致（不一致就该重刷）。

---

## 3. 坑（其它文档里没有的）

### 3.1 门禁会绿着撒谎——本项目最重要的一条经验

2026-09-26 真机脱壳暴露：**79 个 device 脚本全跑在沙盒自加载路径上**，而那条路径**结构上不可能**产生
"memfd 加载的 agent"或"拒绝 `/proc/self/mem` 的目标"。于是 `art_dexfiles`/Java hook/整条读内存链路在
真机上**整组死掉，门禁却全绿**。修法不是改功能，是**断言注入路径上的能力**（`verify_v98`）+ 给读内存加
强制直读并覆盖**全部**读命令（`verify_v97`）。

**你的第一条纪律**：任何新验收都要问"它跑的路径和真实路径是同一条吗？"

> ⚠️ **2026-10-01 实测的同类坑（已修）**：`verify_v02.sh` 会 `install_apk_root` 重装沙盒 APK，
> 而 **APK 里自带一份 agent** —— 重装会把热替换进去的新 `.so` 覆盖回旧版，于是**其后所有 device
> 脚本都在验旧 agent**（实测差了三个版本）。现在 `install_apk_root` 装完会调用 `refresh_agent_so()`
> 把 `agent/build/libadh_agent.so` 推回沙盒与模块目录并打印 sha。**改 agent 源码后仍然必须闭环：
> 重建 → 部署 → 确认设备 hash == 本仓 hash**。
**证明测试有牙齿的做法**（期望你这么干）：把被测能力临时破坏掉，断言测试**必须**红。
`verify_v98` 就是这么验的（JavaVM 查找改成 `return NULL` → 必须 FAIL）；`verify_v101` 内置了一条
"旧扫描对两个库返回同一组算法名"的断言，**用度量证明旧层看不见**。

### 3.2 靶子必须**编译**，不能是测试自己拼的 buffer

`verify_v101` 第一版 13 条单测全绿，但**编译靶子当场证伪**：MD5 的 16 字节 init 是 SHA1 20 字节 init 的
**前缀**，任何同时含 SHA1 的镜像都会让"MD5 init 在不在"答 yes → 变异库被误判成标准 MD5。合成 buffer 从不同时
含两份 init，**真实 .so 通常两份都有**。见 `fixtures/crypto-variants/` + `tools/build_crypto_variants.sh`。

### 3.3 本仓库的 TypeScript 是 **strip-only**，没有构建步骤

node 24 直接跑 `.ts`，**不支持 TS 的 parameter property**（`constructor(readonly x: T)` 直接语法错）。
其它 TS 独有语法同理慎用。

### 3.4 "接受但被忽略的 flag" 比没有这个 flag 更糟

另一个项目的 CLI 把 `--proxy` 注册在公共参数里、却只有 `signcode` 一个子命令消费，于是 `face --proxy …`
**静默忽略**——而那条命令存在的意义就是"换出口"。ADH 现在有两道守卫：`daemon/test/cli_args.test.ts`
（声明了就必须有人消费）+ `verify_v100`（每个 flag 必须有**可观测效果**）。加 flag 时别破坏它们。

### 3.5 超时/退出这类"看起来对"的地方，一律量一遍

`adh` CLI 的两个真问题都是量出来的：`fetch` + `AbortSignal` 在 2s 中止但**进程又活了 8.7s**（undici 的待决
connect 句柄在 Windows 上不可取消）；换 `node:http` 后 `req.setTimeout` 只约束 socket **空闲**、不约束 connect，
于是 `--timeout 2` 的错误在 **5106ms** 才出现而文案写着 2 秒。现在用自己的墙钟定时器（2090ms 实测），
**并且 `verify_v100` 断言这个界**，防止回退成谎话。

### 3.6 Windows / Git Bash 特定的坑（换到 Linux/macOS 可能不适用）

- `echo "$OUT" | grep -q` 在 `pipefail` 下会因 **SIGPIPE** 假失败（>64KB 载荷必踩）；用 `verify_grep_q` 或 here-string。
- 杀进程用 **PowerShell `Stop-Process`**；`taskkill /F` 在 `MSYS_NO_PATHCONV` 下会被吞掉（静默不生效 → 假绿）。
- `tools/lib/env.sh` 用 `cygpath -m` 把 `ROOT` 转成 Windows 形式给 NDK 工具看；WSL 走 `wsl_env.sh`。
- Windows 的 python 读不了 MSYS 的 `/tmp`（要传数据用 stdin 或 heredoc）。

### 3.7 其它小而致命

- 单引号 TS 字符串里**一个撇号**能让 daemon 起不来，而 `node --check` 看不出来（正因如此才有 `verify_v71`）。
- 本仓库**禁止提交目标数据**（`captures/`、`dumps/`、`adhd-data/` 已在 `.gitignore`）；写文档要脱敏。

---

## 4. 架构红线（别越）

`libadh_agent.so`（目标进程内，只采集/执行）→ Host ADH Daemon（HTTP/MCP/分析）→ Device（作用域/进程控制）→ Web UI。
**永远不要**把 HTTP/MCP/数据库/dex 索引/Capstone 放进 agent `.so` 或 Device 层。
模块 X（手机自动化）已退役，**不要恢复**（`CLAUDE.md` 有明确禁令）。

---

## 5. 接着做什么（按"取证价值 + 可验收性"排序，每项带验收信号）

### 第一梯队（有可刷机就立刻能做，收益最大）

| # | 事项 | 验收信号 |
|---|---|---|
| **1** | ~~**先跑一遍全量门禁**，把 device 侧的真实状态量出来~~ ✅ **2026-09-29（二）已跑**：**103 PASS / 11 FAIL / 4 SKIP**（host 29/5/2，device 74/6/2）。11 条 FAIL **没有一条归到产品代码**：7 条环境、2 条门禁自身缺陷、2 条文档已登记的偶发。**device 半段是健康的**——赛前预测的 4 条环境噪声全部命中，无意外红。详见 `PROGRESS.md` 同日第 7 条。 | 已完成；下一步是把那 9 条环境项治掉（见下） |
| **1b** | **治掉让门禁变哑的环境项**（本轮新暴露的、收益最直接的一类）：~~② **修 `v99`/`v100`/`v101`/`v15_dumpall` 的 `^ℹ fail 0$` 断言**，并补 `v99`/`v15_dumpall` 漏掉的 `exit 1`~~ ✅ **2026-09-29（二）已修**：收成一处实现 `verify_unit_pass`（`tools/lib/verify_common.sh`，解析两种 reporter + 剥 ANSI + 要求 `rc==0` + **`min_pass` 下限**防静默空跑），四个调用点全部改完，**并按 §3.1 做了 5 项齿检**（含"塞必然失败的用例必须红"与"用例删光必须红"）。`v101` 假红 → 如实 SKIP；`v99` 假绿 → 真实结果；`v15_dumpall` device 段全绿；`v100` **22 checks/0 problems 转绿**。详见 `PROGRESS.md` 同日第 9 条。<br>**剩下 1 项待做（2026-10-01 部分解决）**：`verify_v01` / `verify_v32` 仍需要 **gradle**（重打沙盒 APK / 模块 APK）——
agent `.so` 本机已能构建（§1.5），卡住它们的只剩 gradle，
那是"要不要在这台机器上做完整构建"的环境决策，不是路径 bug。（①②③④ **均已在本轮完成**——
①④ 见下；②③ 见 2026-09-29（二）与 2026-09-30 的提交。） | ① 完成后 `v02_so`/`v08_disasm`/`v08_analyze`/`v26_footprint`/`v30` 全部转 PASS，
`v90` 由 SKIP 转**真跑**（228 索引逐条对照 jni.h），`v101` 由 SKIP 转**真跑**（clang 编译靶子 + 11 项断言）|
| **2** | ~~**`adh target` / `adh unpack` 的端到端**~~ ✅ **2026-09-29（二）已随 `v100` 转绿一并验证**：`v100` 真机 **22 checks / 0 problems**，含 `target` 报出唯一 agent + 活体事实、"`unpack` 分类每个 DexFile"、"`--out` 每个真 dex 落盘且字节数与报告一致"。`FEATURE_STATUS` 里"真机端到端尚未验证"已作废。 | 已完成 ✅ |
| **3** | **二代抽取壳闭环**：fixture（按参考仓库形态：抽取 = 把 `PluginClass.getString()` 的 6 字节方法体 `1A 00 87 00 11 00` 清零）+ **还原点**（hook `art::ClassLinker::LoadMethod`，在方法体解密瞬间抓 CodeItem；参考仓库的 mangled 名在 `cyrus_studio_hook.cpp`）+ 把"覆盖率 → 受控触发 → 恢复 → 重建 → 再测覆盖率"串成 **可断言恢复率**的闭环 | 恢复率是**具体数字**；被抽方法重建后与原文 sha 一致；解不动的显式 `unresolvable` 计入分母。**注意**：本机 ROM 的 `libart.so` 被裁过，先确认 `LoadMethod` 符号在不在——不在就得换落点 |
| **4** | **`mprotect` 读 PROT_NONE**：很多壳把 ELF 头设成 `PROT_NONE`；agent 内部**有** `mprotect`（hook 机制里用）但**没有对外命令**。加一个只读用途的改页 op。 | 对一个被 `PROT_NONE` 的 ELF 头能读出并重建（`so_unpack` 的经典场景） |

### 第二梯队（能力补全）

| # | 事项 | 验收信号 |
|---|---|---|
| **5** | **变异识别的第二步**：运行时生成的码表（`out[i ^ (len%64)] = std[i]`）与"连锚点一起换"的变异（自定义 S-box / 自造轮函数）。静态常量法对这两类**注定看不见**，`crypto_variants.ts` 的 `limits` 已如实自述。落点：**指令结构**（`trace_digest`/QBDI 摘要已是原料）。 | 对 `dynamic_base64_alphabet` 与一个自造 S-box 的靶子，在只给反汇编/指令流的条件下能报出"这是 base64/分组密码结构"，且对普通代码负对照不误报 |
| **6** | **抓包两块缺口**：**QUIC/HTTP3**（明文捕获建立在 TLS/SSL 库边界 + EVP 边界上，QUIC 不走 `SSL_write/read`）、**WebView JS 桥**（参考仓库有 `webshell_bridge.cpp` + `bridge.js`） | 对 Cronet 请求拿得到请求语义；JS 桥调用可枚举 |
| **7** | **反检测靶场**：把参考仓库那套 Frida/调试/反抓包检测（`fridadetector/core/checks/*`、`anti_debug.c`、`SniffDetector.kt`）当**负对照**跑 `stealth` | stealth 前后这些检测的判定翻转（`verify_v69` 思路的加强版） |

### 第三梯队（工程 hygiene，收益立刻可见）

| # | 事项 | 验收信号 |
|---|---|---|
| **8** | **`adh` CLI 第二片**：`adh watch`（事件流）+ `adh hooks`（钩子装卸），并**迁移**若干 verify 脚本改用 CLI 解析目标（先迁 3-5 个，每批都跑门禁） | 迁移后脚本行数显著下降且全绿 |
| **9** | **agent 侧 `agent_inventory` + `unhook_all`**：现在只有逐钩子 `unhook`，没有"现在挂着什么"的清单和"全部卸掉"的动作（代价踩过：一个没卸掉的 `strlen` 钩子让后续断言失败，只能重启进程收场） | CLI `target` 能打出常驻钩子清单；`unhook_all` 后清单为空 |
| **10** | **门禁的变异测试化**：现在"破坏能力 → 断言测试必须红"是手工做的。做成机制：每个守卫声明"拿掉哪个能力时你必须失败"，门禁自动跑负对照。 | 门禁能自动报出"这条守卫没有牙齿" |

### 需要用户拍板（**不要自己决定**）

### 已拍板（2026-10-01，不要再问一遍）

- **产品口径**：覆盖所有场景类型都有对应工具与流程，**不保证每个壳 100% 还原，恢复率如实上报**
  （已并入 `REQUIREMENTS.md §15.5`）。
- **发布范围收口 10 项**：全部照建议执行，已并入 `DEVELOPMENT_PLAN.md §6.9.1/§6.9.2/§6.10`（§6.9.5 已删除，不要再引用它）。
  要点：arm64-only；QBDI/Frida Gadget/eCapture 降级、Xposed 标社区实验、官方路径只剩 Zygisk；
  全量 syscall 拦截不做；cdex/041 样本驱动不进排期；Web UI 冻结为只读查看器；
  **9 个沙盒耦合命令真删**（2026-10-01 完成，能力改由 `capture_start/capture_stop` + `java_call` + `native_hook` 提供）。
- **agent TCP 8761 无鉴权的信任模型**：**仍未决**，见 `REQUIREMENTS.md §20.1`。

---

## 6. 不要做的事（红线清单）

1. **若你在 A 组机器上**（原始工作站 + 用户日常机）：不刷、不装、不起停 App；`dev_up.sh` 会建 adb reverse，
   host-only 时别跑；不要跑全量 `verify_all.sh`。
2. **不要拷贝参考仓库的代码**（无 LICENSE）。
3. **不要提交目标数据**（`captures/`、`dumps/`、`adhd-data/`）。
4. **不要恢复模块 X**（手机自动化），也不要给 Device 层加分析能力。
5. **不要在 agent `.so` 里加 HTTP/MCP/DB/重分析**。
6. **不要把"看起来对"当成通过**——没有 pass/fail 信号的改动不算做完，宁可标 `SKIP` 也不要虚报 PASS。

---

## 7. 接手自检（跑一遍，确认环境与本文一致）

```bash
git log --oneline -1                                   # 期望起点：34f8ecc 之后
node --version                                         # 期望：v24.x（实测 v22.23.2 也可用）
adb devices                                            # 记下 serial 与个数（多设备先 export ANDROID_SERIAL）
adb -s <serial> shell 'id; which su'                   # uid=0/有 su → B 组（可刷机）；否则见 §1.1
adb -s <serial> shell getprop ro.build.version.sdk     # 35/36 → 解析器可直接用；否则先补覆盖（§1.3）
adb -s <serial> shell getprop ro.product.cpu.abi       # 必须是 arm64-v8a
cd daemon && node --test test/*.test.ts 2>&1 | tail -3 # 期望：全部 pass
bash tools/verify_v101_crypto_variants.sh              # ⚠️ 见下方注；不是"无需设备就一定 PASS"
cd .. && export ANDROID_SERIAL=<serial> && bash tools/dev_up.sh && bash tools/verify_all.sh
                                                       # B 组：全量；A 组改用 §2.2 的 host 子集
```

> ⚠️ **`verify_v101` 在 node 22 上会假红**：它的第 1 步 `grep -qE '^ℹ fail 0$'` 匹配的是 node
> **spec reporter** 的标记，而脚本用命令替换取输出 = **管道 = 非 TTY**，node 会走 **TAP reporter**
> 打印 `# fail 0` —— 断言**永远不成立**。单元测试本身 13/13 全过。同类写法还在 `verify_v99` /
> `verify_v15_dumpall` / `verify_v100` 里，**改之前先知道这是断言缺陷、不是被测代码坏了**。

任何一条与本文不符（设备换了 / 没有 root / API 不是 35-36 / 沙盒没装），**先更新 §1.3.1 的表再推进**——
这张表是后面所有人的判断依据。**接管机本身换了也要更新 §1.5**（构建链 / node 版本 / I/O 特性）。
