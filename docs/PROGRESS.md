# PROGRESS — 跨会话进度看板

> 这是"我们现在在哪"的唯一真相。每个会话开始先读它，结束前更新它。
> 详细规格见 `REQUIREMENTS.md`，路线与架构见 `DEVELOPMENT_PLAN.md`。

## 当前阶段 —— 🔧 v2.0+ 加固与重构（进行中）

**v0.1–v1.0 全部实现并逐项验证（`tools/verify_all.sh` 35/35，真机 + host）——那一轮证明"每条能力路径可跑通"。**
现进入 **v2.0+ 加固重构轮**：针对评审锐评的 14 点，把每条路径从"能演示"做到"能在对抗、并发、无样本、
无 sandbox 耦合下不骗人"。权威路线见 `DEVELOPMENT_PLAN.md §6.9`（WS-A…WS-K + v2.0–v2.6 排期 + 门禁清单）。
旧 v0.2–v1.0 路线归档于 `DEVELOPMENT_PLAN.md §7`。

**三条总原则（门禁）**：① 不为过测而耦合（agent 内 `com.adh.sandbox` 常量 = 0，目标模块名不硬编码，
全来自命令参数）；② 不胡乱兜底 / fail-loud（hook 装不上、缓冲溢出、解不动一律显式报错 + 计数上报，
绝不 `ok:true replaced:0` 或虚高恢复率）；③ 红线不动（重分析在 idhd，hook/采集在 agent）。

### v2.0+ 进度

- [x] **Web UI 重皮 —— 移植 IDH「2026 workbench」设计语言（2026-07-24）**：`daemon/public/index.html` 整体重设，对齐 IDH 参考界面。
      · 深墨蓝 token 体系（`--bg:#06070a`/`--surface`/`--blue:#78a9ff` + 分类色）+ Inter 字体；品牌头 brand-lockup + `Runtime Console` + 状态 pill；tabbar 计数胶囊（active 蓝底）。
      · 三实时 tab（加解密/系统/网络）共用**过滤工具栏**：分类/搜索/输入大小 min-max/清除 + 暂停(冻结)/下载本类(导出 JSON)/清空本类；`makeCapPanel` 接入 per-panel 过滤态。
      · 捕获行**分类色左边框**（digest 绿/hmac 蓝/对称 琥珀/非对称 紫/net 青/file 珊瑚）+ 分类胶囊；详情面板 cat-dot 标题 + 复制按钮 + IO 卡片（INPUT 蓝顶边 / OUTPUT 珊瑚顶边）+ **UTF-8/HEX/HexDump 三视图**（新增 `hexdump()` 偏移·十六进制·ascii）。
      · 文件/Dump/模态/设置全部套新样式；list-pane 可拖动分栏。**零后端/agent 改动**，所有 fetch/函数/面板 id/WS 处理不变。
      · 验证：headless(Playwright) 渲染**零 JS 错误** + 目视比对参考图一致；`verify_v10_webui.sh` 20/20 PASS（并修复该脚本一个潜伏 bug：`echo "$HTML"|grep -q` 在 `pipefail` 下遇 >64KB 页面因 grep 早退触发 echo SIGPIPE 误判 FAIL → 改 here-string `grep -q <<<"$HTML"`）。
- [x] **顶栏五 tab 重构 + agent 目录浏览（2026-07-24，commit 125f286）**：加解密/系统/网络/文件/Dump。
- [x] **v2.0** WS-D 协议重写（length-framed `[u32 len][u8 type][payload]`，去 8192 上限）**✅**
      + WS-C 环形缓冲/如实 dropped 上报 **✅ 完成并验证**（连续 push-drain 线程作为 WS-C 优化后续再上，见日志）
      + WS-C `cap_reset` 记账修复（丢弃环内记录计入 dropped，`emitted+backlog+dropped==seq` 恒成立）**✅**
- [x] **v2.1 原生 Signature/KDF/AEAD 覆盖扩展（GOT hook，替代原 LSPlant 路线的 P0 缺口）+ WS-B 去 sandbox 耦合（2026-07-27）**
      · **WS-B 部分完成**：agent 常驻采集三类(crypto/file/sys)目标模块**全部参数化**、agent 零硬编码目标模块 **✅**；
        LSPlant 在测试机 13f54a46(ColorOS/A15 stripped libart) **根本性阻塞**（44 个所需 ART 符号缺 30 个/68%），
        同 ROM 上 ShadowHook inline 后端 `shadowhook_init` 同样失败（INIT_LINKER/errno12）——系统性 ROM 限制，需 stock/Pixel 验证；
        按 C 端产品方向（2026-07-27 决策）LSPlant 降级为非当前路线，国密 SM2/SM3/SM4 与隐私分析面板标 PENDING
      · **AEAD（GCM/ChaCha20-Poly1305）**：`EVP_AEAD_CTX_seal/open` 原生 hook 补上此前完全抓不到明文/密文的真实漏洞（Conscrypt 走一次性 API，不走 `EVP_CipherUpdate`）
      · **Signature（RSA/ECDSA）关键发现**：Conscrypt 的 `SHA256withECDSA` 实际不走 `ECDSA_sign/verify`，而是走 BoringSSL 通用的 `EVP_DigestSignInit/Update/Final` + `EVP_DigestVerifyInit/Update/Final`——这套 API 同时服务 JCA `Mac`(HMAC)，靠 `EVP_PKEY_id()`（稳定导出访问器，非内部结构体偏移）在 Init 时判定 HMAC vs 非对称密钥，结果缓存进有界 ctx→kind 表
      · **KDF（PBKDF2/HKDF/scrypt）原生一次性捕获仍是 PENDING**：`PKCS5_PBKDF2_HMAC`/`HKDF` 根本不被 `libjavacrypto.so` 导入（`llvm-readelf --dyn-syms` 确认），`EVP_PBE_scrypt` 虽可 hook 但无 Android JCA provider 调用它——Android 自己的 `PBKDF2WithHmacSHA256` 是纯 Java 迭代 `Mac.doFinal`，无原生一次性 KDF 调用可拦截；不伪造覆盖，诚实标 PENDING
      · 验证：`tools/verify_v26_cryptocoverage.sh`（新增）连续多次 fresh-restart 测试 PASS；`tools/verify_all.sh` 41/41 全绿
      · 修了一个验收脚本自身的竞态：`aeadDemo` 一次触发产出 3 条相关捕获（原生 GCM 密文/原生 ChaCha 密文/沙盒自带 IdhReport Java 富捕获），轮询一见到第一条就提前返回，导致偶发 `aeadMarker=false`——加 `settleTicks` 让轮询在断言满足后再多等几拍
- [x] **结构重构 Phase 1 — tools 测试库（2026-08-03）**：抽出 `tools/lib/verify_common.sh`（resolve_env/sandbox_alive/gate/grep_q/host_begin+chk+finish，here-string grep 修 SIGPIPE 假 FAIL）+ `tools/lib/env.sh`（SDK/NDK/CMAKE/NINJA/TOOLCHAIN/READELF/ROOT/ABI，build_agent+build_detect 共享）；33 个 verify 脚本转 source 库（node heredoc 全 verbatim，只换 shell boilerplate），三种 idiom（device-alive / device-host node-heredoc / host-chk）各保其形；`tools/MAP.md` 导航 + 加脚本配方。**verify_all 41/41 全绿**（两轮：首轮 v08_disasm/analyze 瞬时 flake，次轮 41/41）。v23 故意排除（LSPlant 在本 ROM 阻断）——把静默排除显式化注释而非加回（fail-loud，避免未来 AI 误"修"致每次红）。已知预存 flake：v08 .so 重建路径 `readMem` short-read 早退（index.ts:663）→ Phase 2 dump.ts 抽取时处理。
- [x] **结构重构 Phase 2 — daemon 拆分（2026-08-03）**：`daemon/src/index.ts` 1585 行 → 拆成 `state.ts`/`service.ts`/`mcp.ts`/`index.ts`。**verify_all 41/41 全绿**。
- [x] **结构重构 Phase 3a — agent GOT/ELF hook 引擎拆分（2026-08-05）**：新增 `agent/src/hook/got.c` + `got.h`，把 ELF relocation/APS2 解析、GOT slot 替换、内存符号解析和 `gothook_selftest` 从 bootstrap 收口为内部窄接口；按 `wc -l`，`agent_main.c` 2655 → 2179 行。新增 `agent/src/MAP.md`，并修正 AGENTS/CLAUDE 中“MAP pending / single TU”的过期导航。**`tools/build_agent.sh` NDK 编译、链接、双导出检查通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP（Host 全绿）**。指定测试机 `13f54a46` 当前未连接（仅出现两台未指定的同型号设备），故 `verify_v04_gothook.sh` 运行时验收诚实标 PENDING，未擅自安装到其他设备。
- [x] **结构重构 Phase 3b — agent capture/JNI runtime 拆分（2026-08-05）**：新增 `capture/capture.c` + 窄命令接口，封装 crypto/TLS/file/system wrapper、bounded ring、Java reporter、persistent/one-shot/inline capture 与 detection watch；新增 `runtime/jni.c`，统一 JavaVM 发现、线程 attach/detach 和 app ClassLoader。`agent_main.c` 2179 → **967 行**，不再持有 capture 的锁、ring、trampoline 或 JavaVM 全局。**`tools/build_agent.sh` 通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP（Host 全绿）**；device capture/inline/detection acceptance 仍因指定机离线 PENDING。
- [x] **结构重构 Phase 3c — agent trigger/trace runtime 拆分（2026-08-05）**：新增 `runtime/actions.c`，收口安全黑名单触发与显式 `.so` 加载；新增 `trace/commands.c` + `qbdi_trace.h`，封装 GOT 函数调用记录、QBDI 命令响应和对应有界状态。命令名与 JSON schema 不变，`agent_main.c` **978 → 784 行**，只保留调用。拆分时修复既有 `trace_run` 16 KiB 缓冲无法容纳 256 条最坏记录的风险，改为可由固定上限证明足够的 128 KiB。**`tools/build_agent.sh` NDK 编译/链接/三入口导出通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP**；v10/v14/v18 设备验收因指定机离线 PENDING。
- [x] **结构重构 Phase 3d — agent object/ART inspection 拆分（2026-08-05）**：新增 `runtime/inspection.c`，收口 live-object 字段检查/无参调用、JNI probe 与兼容性实测；新增 `runtime/art.c`，保留 ClassLoader cookie 枚举、TBI untag、DEX 035–041/cdex 结构判定和完整容器范围计算。命令名、响应 schema 与 SDK 35/36 解析策略不变，`agent_main.c` **784 → 366 行**，现只负责 hello/report、LSPlant 自测、RPC 分发和 lifecycle；Phase 3 capability-domain 拆分完成，并清除拆分后遗留的 socket/`dlfcn`/`fcntl` 等无用头文件。**`tools/build_agent.sh` NDK 编译/链接/三入口导出通过；`verify_all.sh` 16 PASS / 0 FAIL / 28 SKIP**；`verify_v03.sh` 的设备侧 JNI/ART 验收因指定机离线 PENDING。
- [x] **Daemon 依赖漂移核查（2026-08-05）**：`npm ls --depth=0` 无 extraneous；评审点名的 `pkijs`/`asn1js` 是已声明 devDependency `selfsigned` 的传递依赖，`tsyringe` 来自其 `@peculiar/x509` 链。`package-lock.json` 与安装树一致，**不是未声明遗留依赖，不做错误清理**。
- [x] **ADH 命名收口（2026-08-05）**：模拟注入宿主 `com.idh.sandbox` → **`com.adh.sandbox`**，Java helper 同步为 `com.adh.agent`，`IdhSecurity/IdhReport` → `AdhSecurity/AdhReport`，native JNI 名、daemon sandbox defaults、device scope 单测、协议示例和 35 个 shell 验收脚本全部同步。新增对外主入口 **`adh_agent_start`**，Zygisk 优先解析它并回退 legacy `idh_agent_start`；rich reporter 主属性改为 `adh.reporter.class` 并保留旧 key 回退。门禁：除固定哈希历史 probe dex `com.idh.probe` 外，当前源码/脚本 `com.idh.sandbox|com.idh.agent` = 0。验证：agent + detect + sandbox APK 构建通过（APK=`com.adh.sandbox`），daemon smoke PASS，device `:core:test` PASS，Zygisk zip 重建成功，`verify_all.sh` **16 PASS / 0 FAIL / 28 SKIP**；指定设备仍离线，迁移后的 device acceptance 待补。
- [x] **ADH Daemon 品牌化 + 模块 W Zygisk/Manager 首版（2026-08-03）**：
      · 对外统一称 **Host ADH Daemon**（npm `adhd`）；`ADH_*` env 别名；遗留 `idhd`/`idh_*`/`IDH_*` 保留。
      · `injector/zygisk/` Magisk Zygisk 模块：按 `/data/adb/adh/scope.json` 白名单 `dlopen` + `idh_agent_start`；`tools/build_zygisk.sh` → `adh-zygisk.zip`。
      · `tools/verify_v27_zygisk.sh`：无 Magisk/未刷模块 → SKIP；有模块则 scope 往返 PASS。
      · Gadget/重打包仍延后。
- [x] **设备侧架构奠基（对标 Vector 形态，2026-08-03）**：
      · 新建 `device/` 多模块：`:core`（ScopeConfig/AdhPaths/ScopeJson 单一真相 + 单测）+ `:daemon`（`IAdhScopeService` AIDL + ScopeService 骨架）+ `:manager`（Jetpack Compose 壳，FileScopeRepository / DaemonScopeRepository 预留）。
      · 工具链锁定 Gradle 8.9 + AGP 8.7.3 + Kotlin 2.0.21 + Compose BOM（与 sandbox 同级；不追 AGP 9）。
      · 旧 `injector/manager` ViewBinding 工程退役为 DEPRECATED stub。
      · 验收：`device/gradlew :core:test :daemon:assembleDebug :manager:assembleDebug` BUILD SUCCESSFUL。
- [x] **组合安装包 + Zygisk Next ABI/Manager 状态修复 v0.2.2（2026-08-04，参考 Vector）**：
      · `tools/build_bundle.sh` 生成 Magisk 可直接安装的版本化 `adh-bundle-vX.Y.Z.zip`；内含 Zygisk 模块与同版本 `manager.apk`，安装前验证 `manager.apk.sha256`，boot mode 自动安装。Magisk `action.sh` 可直接打开 Manager，未安装时用模块内 APK 修复安装。
      · 截图所示 Zygisk Next “ADH 无法加载”的根因已定位：旧 `zygisk.hpp` 把入口导出成 C++ 符号 `_Z19zygisk_module_entry...`，而加载器要求原始 C 符号 `zygisk_module_entry`。注册宏现使用 `extern "C"` + default visibility；构建同时强制验证 `zygisk_module_entry` 与 `zygisk_companion_entry`，缺失即失败。
      · 模块真实加载状态改由 Zygisk root companion 写 `/data/adb/adh/zygisk_loaded`，避开模块回调的 SELinux 权限限制；`post-fs-data.sh` 每次启动清理旧标记，`service.sh` 只把 `module.prop` 描述更新为“运行中”或“未加载，请检查 Zygisk”。作者固定为 `decrypthub.com`，不再把内部路径和开发说明放进用户可见描述。
      · Manager 采用 Vector 同类的紧凑 Compose 信息层级，但保持 ADH 独立 APK/作用域边界：首页只显示模块运行状态、注入范围和版本；默认中文，英文系统使用 `values-en`，主题跟随系统深浅色与 Material You。
      · `v0.2.1` 真机重启后，KernelSU 模块页已显示 ADH“状态：运行中”，且 `/data/adb/adh/zygisk_loaded` 存在，证明 Zygisk ABI/companion 修复生效。Manager 仍显示“未安装”的根因是 `com.adh.manager` 未获 KernelSU 超级用户授权：应用命名空间中 `/system/bin/su` 不可见；旧 UI 把该失败吞掉并错误映射为模块不存在。
      · `v0.2.2` 将 Root 可用性纳入 `ModuleStatus`，明确显示“需要 Root 权限”，作用域页在未授权时不再加载空配置；首页和作用域页返回前台自动重检，首页另有刷新按钮。新增 Manager 单测覆盖“无 Root”和“已安装且已加载”两条确定性路径。
      · 模块与 Manager 同步为 `v0.2.2 / versionCode=6`。最终 ZIP 完整性、Manager SHA-256、APK v2 签名、APK 版本及两个 Zygisk C 导出均验证通过；已只推送到 Pixel 6 Pro `1A281FDEE003ZV:/sdcard/adh-bundle-v0.2.2.zip`（SHA-256 `76577c323a3cfc4f105f29d4913285f2a194459a30b2e6dd3a2679c6f97cd5fb`），未安装、未刷入、未重启。
      · 只采用 Vector 的版本化打包、完整性校验、Action 入口和 UI 信息层级，不采用其依赖 system_server hook/root daemon 的 `com.android.shell` 寄生 Manager。
- [x] **v0.3.0 Root Device Daemon 权限边界（2026-08-04）**：
      · `device/:daemon` 从同进程 Service 骨架改为模块以 root `app_process` 启动的独立 APK；只提供 scope 读写与模块状态 AIDL，不含 HTTP/MCP/DB/分析。
      · `IAdhScopeService` 契约移至 `:core`；Manager 删除 `FileScopeRepository` 和全部 `su`/`/data/adb` 访问，只使用 `DaemonScopeRepository`。UI 状态由“需要 Root 授权”改为“Device Daemon 未连接”。
      · Binder 由 daemon 通过 Manager 的 ContentProvider 交接；Provider 只接受 UID 0 且校验 descriptor。daemon 每次事务校验调用 UID、`com.adh.manager` 包归属及构建时固定的 Manager SHA-256 签名证书，作用域写入使用 fsync + 原子替换。
      · `build_zygisk.sh` 先构建 Manager、用 `apksigner` 提取并严格校验 64 位证书摘要，再编入 `daemon.apk`；模块打包 `daemon.apk` + `device-daemon`，`service.sh` 在私有 mount namespace 启动它。
      · 验收：`:core:test`、`:daemon:testDebugUnitTest`、`:daemon:assembleDebug`、`:manager:testDebugUnitTest`、`:manager:assembleDebug` 全绿；`adh-bundle-v0.3.0.zip` 构建成功，含 14 个预期文件，Manager `versionCode=7/versionName=0.3.0`、APK v2 签名有效，daemon 内嵌证书摘要与 Manager 实际证书一致。
      · 已推送到原对话同一台 Pixel 6 Pro `1A281FDEE003ZV:/sdcard/adh-bundle-v0.3.0.zip`，本机与设备 SHA-256 均为 `7bcc9783696d14a15ababb6b71f57f9fd8d1198b6c1caa0b1be18a49ca937be8`；设备上的旧 `v0.2.2` 包已删除，只保留 `v0.3.0`。
      · **真机运行时 PENDING**：按本轮约束未安装、未启动、未重启设备，因此尚未声称 `app_process → Binder 交接 → scope 往返` 在 ColorOS/KernelSU 上通过；首次安装测试必须读取 `device_daemon.log`、ready marker 并做确定性 scope 往返。
- [x] **v0.3.1 Device Daemon / Manager Android 16 修复（2026-08-04）**：Pixel 6 Pro `1A281FDEE003ZV` 首次运行抓到 daemon 在开机早期调用 `ActivityManager.getRunningAppProcesses()` 时，系统 `IActivityManager` 尚未就绪并抛 NPE（PID 1460）；Manager 的全量应用查询又因不必要的 `GET_META_DATA` 产生超大 `ParceledListSlice` 并显示“无法读取应用列表”。daemon 改为直接扫描 root 可读的 `/proc/*/cmdline`，以 `getContentProviderExternal()` + Android 12+ `IContentProvider.call(AttributionSource, authority, method, arg, extras)` 向独立 Manager 安全交接 Binder；Manager 使用 flags=0 枚举应用，并分别记录 scope 与 package query 异常。
      · 热验证：临时 v0.3.1 daemon 以 root/su 域持续运行（PID 11579），ready/PID marker 存在；Manager v0.3.1 显示“ADH 运行中 / Zygisk 已加载 ADH”，应用列表可见。
      · 确定性 scope 往返：只选 `com.idh.sandbox` 保存后 `/data/adb/adh/scope.json` 精确包含该单包；立即取消并再次保存后 packages 恢复为空。
      · 回归与交付：`:core:test`、`:daemon:testDebugUnitTest`、`:daemon:assembleDebug`、`:manager:testDebugUnitTest`、`:manager:assembleDebug` 全绿；`adh-bundle-v0.3.1.zip` 含 14 个预期文件，Manager `versionCode=8/versionName=0.3.1`、APK v2 签名、内置 SHA 与 daemon 固定证书摘要均通过。已推送到 `1A281FDEE003ZV:/sdcard/adh-bundle-v0.3.1.zip`，本机与设备 SHA-256 均为 `3c72f8e1bc77cfa11a4d18c1b759d6ab3ba58a0f369e98f2b9c230bc928ff4bf`；旧 v0.3.0 包已删除。
- [x] **Manager 显示 Host Web UI 地址（2026-08-04）**：Manager 直接经 `http://127.0.0.1:8760/health`（adb reverse）读取 Host ADH Daemon 上报地址，首页优先显示 `web.lan[0]`、无 LAN 时回退 `web.local`，并提供复制与浏览器打开按钮；Device Daemon/AIDL 不承载 HTTP。新增 LAN 优先与 local 回退单测，`:manager:testDebugUnitTest :manager:assembleDebug --rerun-tasks` 全绿。Pixel 6 Pro `1A281FDEE003ZV` 真机显示 `Web UI 在线 / http://192.168.100.11:8760`，UIAutomator 确认全部文案与按钮可见；点击打开后 Chrome 收到精确 `ACTION_VIEW dat=http://192.168.100.11:8760`。
- [x] **v2.2 WS-A native inline 后端（Dobby by-address，2026-08-04）**：
      · Dobby 从 LSPlant 条件中解耦，独立提供 arm64 函数入口 hook；模块名/符号名/触发类与方法均由 Host ADH Daemon 命令传入，agent 零 sandbox 硬编码。
      · sandbox `libidhdetect.so` 增加 BoringSSL `EVP_CipherUpdate` 同 ABI 的静态链接 mock，JNI 直接调用、没有可替换 GOT slot；agent inline wrapper 捕获 `IDH_INLINE_CRYPTO_v1` 并通过 original trampoline 返回 `1`。
      · Dobby 1.2 的 `Destroy → Hook` 重装路径在 ColorOS A15 触发 `CodePatch+84` SIGSEGV；改为产品实际需要的常驻 hook + 命令窗口 active gate，同目标幂等复用。`tools/verify_v28_inlinehook.sh` 同进程连续两次均 PASS（首轮 installed=true，次轮 false，均 1 条 marker）。
      · 真机：OnePlus PGP110 / Android 15 / SDK 35 / arm64，serial `aa165071`；agent、native mock、sandbox APK 构建成功；`tools/verify_all.sh` 全部 43 个条目退出 0（允许脚本定义的环境 SKIP）。
- [x] **v2.3 WS-F 持久索引 + 深解析 + 反射（2026-08-04）**：
      · Host ADH Daemon 新增 `daemon/src/dex_index.ts`，使用 Node 24 `node:sqlite` 将 dex 按 SHA/大小/parser version 持久化到 `idhd-data/dex-index.sqlite`；保存 strings/classes/methods/fields、invoke callers、string callers、field readers/writers 与 `Class.forName` reflection edges。
      · `dex.ts` 增加 proto/descriptor/参数解析、字段访问点和保守的寄存器常量传播；寄存器被覆盖或 code_item 越界时不猜测，统计 `skipped` 并 fail-loud。
      · REST：`POST /api/dex/index`、`/api/dex/index/search`、`/api/dex/index/reflections`；MCP：`dex_index`、`dex_index_search`、`dex_reflections`。
      · sandbox 新增 `ReflectionProbe.load()`，多 dex 验收 `tools/verify_v29_dexindex.sh`：四个 dex 共 59,719 个方法、0 skipped；重复索引缓存最大 3.9ms；`ReflectionProbe.load → Class.forName → Lcom/idh/sandbox/JavaCrypto;` caller/descriptor 经 REST + MCP 均 PASS。已加入 `verify_all.sh`。
- [ ] v2.4 WS-E 脱壳二代 + try/catch + cdex/041（需样本，否则 PENDING）
- [ ] v2.5 WS-G Capstone + WS-H QBDI 通用化
- [ ] v2.6 WS-I 确定性关联 + WS-J 反检测动态面
- [ ] 贯穿 WS-K 架构拆分 + 多架构/多进程

---

## 历史阶段 —— ✅ v0.2 – v1.0 全部实现并逐项验证（归档）

**v0.2 – v1.0 全部实现并逐项验证：`tools/verify_all.sh` = 26/26 PASS（真机 Pixel 6 Pro / host）。无 Blocked。循环已停（cron 已删）。**

完整取证流水线（模块 A–V + idhd 分析 + MCP + Web），全部真机/host 验证：
模拟注入 → maps/内存 dump（so 重组、dex 修复）→ **ART 结构级真实 dex 捕获** →
**明文边界 AES 捕获 + TLS 明文捕获 + 网络↔crypto 关联** → 反分析观测(+中和) + 抗干扰诊断 →
活体对象自省 → dex 搜索/xref/方法体恢复 → 原生反汇编/分析/常量扫描/svc 扫描 →
**函数级 trace + QBDI 指令级动态 trace** → 25 MCP tool（AI 可编程操控）+ Web 控制台（含 Events）+
会话录制/回放 + 诊断导出 + 文档（architecture/threat-model/mcp-tools）。

**QBDI 已解除并完成**：GitHub API 被墙但 release 直链可下；`tools/fetch_qbdi.sh` 拉 v0.12.1
arm64 预编译，agent 运行时 dlopen libQBDI.so，指令级 trace idh_trace_target 得 retval=30 + 64 条指令。

### 交付物（可复现）

- `libidh_agent.so`（C/NDK，双入口，纯采集）、`idhd`（Node/TS，REST+WS+MCP+分析）、
  Web 控制台、`sandbox-app`（模拟注入 + 各 mock 目标）、26 个验收脚本、`fetch_qbdi.sh`。
- QBDI 依赖非 git（third_party/qbdi + libQBDI.so 已 gitignore）；`bash tools/fetch_qbdi.sh` 重新拉取。
- 新机复现：fetch_qbdi → build_agent → build_detect → dev_up → verify_all。

## 技术栈（已定）

- idhd = **Node.js + TypeScript**（node 24 直接跑 .ts，无构建步骤）；deps: `ws`
- agent = **C + NDK 28.2 + SDK cmake 3.22.1 + ninja**，ABI arm64-v8a
- sandbox = **AGP 8.7.3 / Gradle 8.9 / Kotlin 2.0.21 / compileSdk 36**，Java 21(jbr)
- 通信 v0：NDJSON over TCP，agent 经 `adb reverse tcp:8761` 连 host idhd
- 端口：idhd HTTP/WS `8760`，agent TCP `8761`

## 已完成

- [x] 需求定稿（模块 A–W）折叠进 REQUIREMENTS/DEVELOPMENT_PLAN；一份方案
- [x] git、`.gitignore`、`CLAUDE.md`、`PROGRESS.md`；设备就绪
- [x] **v0.1 端到端验证**（3 commits）：idhd(HTTP/WS/TCP registry+dashboard)、
      agent .so 双入口(JNI_OnLoad+idh_agent_start)、sandbox 模拟注入、
      agent 注册 + maps 采样全部与内核 `/proc/<pid>/maps` verbatim 一致
- [x] 可复现验收脚本 `tools/build_agent.sh` + `tools/verify_v01.sh`（exit 0 = PASS）

## 范围指令（最高优先级，循环每轮必读）

- **目标：先把 `libidh_agent.so` 的全部功能实现并自测通过**（模块 A–V 的 agent 侧能力）。
- **验证一律走模拟注入**（sandbox `dlopen` 加载 agent）—— 它执行的就是 agent 的同一套代码路径，`.so` 全功能都能在此自测，无需真实注入。
- **Zygisk + 设备多模块底座（模块 W）已落地**：`injector/zygisk` + `device/`（`:core`/`:daemon`/`:manager` Compose）。Gadget/重打包仍延后。功能验证仍以 sandbox 模拟注入为主；`verify_v27_zygisk` 在未刷模块时 SKIP。
- 因此 v0.1 已建立的 sandbox 模拟注入回路 = 后续所有版本的验证台。缺哪个测试 Activity 就往 sandbox-app 里加。

## 自动续跑循环（已启用）

- 已启用 durable cron `4b2458ac`（每 ~10 分钟空闲时唤醒），指令：读本文件 → `bash tools/dev_up.sh` → 做下一个可验证增量 → 构建 → 验证 → 仅验证通过才 commit → 更新本文件。
- 每次迭代先跑 `tools/dev_up.sh`（幂等拉起 idhd + adb reverse + 检测设备）。
- 设备离线时只做 host 侧工作（idhd/web/dex 解析/协议/sandbox 代码），设备验证标 PENDING，不伪造验证。
- 停止：删除该 cron（CronDelete 4b2458ac）或在本文件写明 v0.2–v1.0 全部完成。

## 进行中

- [ ] v1.0 — **MCP Server + Web 控制台已完成并验证**；仅剩 QBDI 指令级 trace（高风险，最后）
- [x] v0.9 — 完成并验证：native 常量扫描 + direct syscall + **Method Body Recovery(L.7)**
- [ ] v0.8 Dex 索引 + Native Browser — **完成并验证**（搜索+xref+disasm+analyze）
- [ ] v0.3 ART 结构级捕获 — **核心已完成并验证**，剩恢复状态标记/多 resolver 为后续

### v0.9 完成补充：direct syscall

- [x] **Direct syscall 扫描**（E.9 L1）：解析 ELF program header，扫 PF_X 段找 `svc #0`(0xd4000001) 热点。`POST /api/native/syscall_scan`。sandbox-native 加内联 svc 直连 gettid

### v1.0 进展

- [x] **MCP Server**（Streamable HTTP / JSON-RPC）：`POST /mcp` — initialize/tools/list/tools/call，**19 个 tool** 包装 Service 层（进程/内存/ART/crypto/net/detect/object/dex/native 全套）。AI 客户端可编程操控。host 验证

### v1.0 已完成并验证（verify_all.sh 22/22 PASS）

- [x] **MCP Server**（19 tools，JSON-RPC，AI 可编程操控）
- [x] **Web 控制台**（daemon/public/index.html）：Dashboard/Capture/Dumps/Dex/Native/MCP 多面板，
      WS 实时 agent + session 选择器，一键跑各捕获/分析，调现成 REST/MCP API
- [x] Method Body Recovery(L.7 被动)：`POST /api/dex/method_code` 提取方法运行时 code_item

### v1.0 Trace 层已完成并验证

- [x] **函数级 trace（I.2）第一公民**：`GET /api/trace/run` — 通用 4 参 wrapper hook 任意原生符号，
      记录 args+tid+ts，**并把指针参数解析成字符串预览**（如 access("/system/xbin/su")）。suite 覆盖
- [x] 静态反汇编（llvm-objdump）+ 二进制分析（v0.8）作为静态指令视图

## Blocked

- （无）—— QBDI 已解除并完成（见「当前阶段」）。

### v0.8 完成补充：invoke-xref

- [x] **Dex invoke-xref**（K.2）：Dalvik 指令宽度表 + payload 处理 + 一致性校验（walk 必须精确落在 insns_size）。
      21820 个真实方法 0.00% desync。`POST /api/dex/xref`——查"谁调用了某加密 API"（Cipher.doFinal ← JavaCrypto.run）

### v0.9 进展

- [x] **native crypto 常量扫描**（H.4）：AES S-box/inv、Base64 表、SHA-256 init+K、MD5/SHA-1 init、TEA delta 字节签名。
      `POST /api/native/crypto_const`。对付静态链接+strip 符号的原生加密（EVP 符号 hook 落空时用常量定位）

### v0.9 待做

- [ ] Method Body Recovery（L.7）：被动恢复（执行前后 code_item 对比）+ 受控触发；需 ART 抽取壳 mock
- [ ] Direct syscall coverage（E.9）：扫可执行段 svc 指令热点 + DBI 观测

### v0.7 完成并全部验证（网络监控 + 关联）

- [x] TLS 明文捕获（SSL_write/SSL_read GOT hook，绕过 TLS/pinning）
- [x] **网络↔crypto 关联（取证闭环）**：capture 加 tid+ts_ns；flow_watch 同时 hook EVP+SSL_write，
      触发"加密→发送"流；idhd 按同线程+时间窗关联，输出"明文 IDH_CORRELATE_v1 → 承载其密文的请求"。
      `GET /api/flow/watch`，Δ~33ms 命中

### v0.8 已完成并验证（verify_all.sh 16/16 PASS）

- [x] **Dex 搜索索引**（K.2/K.3）：searchDex() 搜 string/class/method；`POST /api/dex/search`
- [x] **原生反汇编**：llvm-objdump -d（NDK 自带，无额外依赖）按符号/地址范围反汇编 ELF .so → 结构化 {addr,bytes,mnemonic,text}；`POST /api/native/disasm`
- [x] **原生二进制分析**：llvm-readelf dyn-syms(exports/imports)+NEEDED + 字符串提取；`POST /api/native/analyze {q?}`
- 说明：llvm-mc 未随 NDK；无 section 的内存镜像 raw-binary 反汇编留作增强（objdump -d 需 section/symbol，对拉取的文件型 .so 完美工作）

### v0.8 待做

- [ ] invoke-xref：解析 code_item 字节码（需 Dalvik 指令宽度表 + payload 处理），method→callers
- [ ] Web Native Browser / Dex Browser UI（并入 v1.0 Web 收尾）

### v0.7 已完成并验证（verify_all.sh 12/12 PASS）

- [x] **网络 TLS 明文捕获**：GOT-hook Conscrypt(libjavacrypto) 的 SSL_write/SSL_read，
      在 TLS 边界读明文——请求(含 X-Idh-Marker)在 SSL_write、响应(IDH_NET_RESPONSE_v1)在 SSL_read。
      **绕过 TLS 与 pinning**。`GET /api/net/hook_test`
- [x] 自包含测试栈：`daemon/tls_test_server.mjs`（本地 HTTPS 自签名，经 adb reverse，无需外网）+ sandbox Network.kt（全信任客户端）
- [x] **修复严重构建隐患**：build_agent.sh 曾用 >/dev/null 吞掉编译错误 → 本轮多次跑的是**旧 .so**。
      现已 forward-declare load_app_class + build_agent 编译失败即报错退出

### v0.7 待做 —— 网络↔crypto 关联（取证闭环第二半）

- [ ] 给捕获事件加 thread id + 时间戳，把网络明文与 crypto 明文按线程/时间窗关联（correlate_request）
- [ ] 当前 capture buffer 是 pull 式；关联需要统一事件流（可先在 idhd 侧按序聚合 net+crypto 捕获）

### v0.6 完成并全部验证（verify_all.sh 11/11 PASS）

- [x] **T 活体对象字段读取**：反射经静态字段到达对象，枚举其声明字段（name + String.valueOf）。
      `POST /api/object/inspect {className,field}` — 验证读到 HeapProbe.sConfig 的 token/count/note
- [x] **T 低风险方法调用**：无参 getter/toString 反射调用。`POST /api/object/invoke {className,field,method}`
      — getToken() → IDH_TOKEN_abc123
- [x] sandbox 增 HeapProbe（已知字段值的 Config 对象）

### v0.6 后续增强（推迟，非阻塞）

- [ ] **完整堆实例枚举（Java.choose）**：需 JVMTI（jvmti.h 不在 NDK，要 vendor 头或声明结构）或 ART 堆遍历（art::gc::Heap::VisitObjects，偏移相关）。当前经静态字段/hook 引用到达对象。
- [ ] byte[]/数组/集合字段的 hex/摘要展示；堆内 String/byte[] 搜索；与 hook 事件联动展开参数对象

### v0.5 完成并全部验证（verify_all.sh 10/10 PASS）

- [x] **V 反分析行为观测**：GOT-hook 目标原生检测调用（libidhdetect：ptrace/access/__system_property_get），
      观测到目标"用了哪些检测"——debug(ptrace TRACEME) + root(su 路径) + prop(ro.debuggable)，
      并**中和 PTRACE_TRACEME**（观测 V + 抗调试 S 附赠）。`GET /api/detect/watch`
- [x] **S 抗干扰诊断**：`compat_probe` 自评——TracerPid、seccomp、后端可用性(gotHook/jniReflect/artDexCapture/memRead)、
      maps/module 计数、dlopen 受限标记。`GET /api/compat/probe`
- [x] sandbox 增 libidhdetect.so（原生检测 mock）+ Detection.kt；tools/build_detect.sh

### v0.5 后续增强（推迟）

- [ ] 更多检测类别：签名检测(PackageManager，需 Java hook)、模拟器检测、frida/xposed 痕迹扫描
- [ ] 行为分叉标注（检测命中后目标是否改走分支）；Anti-Analysis Radar Web 页

### v0.4 完成并全部验证（verify_all.sh 9/9 PASS）

- [x] 静态通道：DEX 解析器 + crypto 静态扫描
- [x] **GOT/PLT hook 引擎**（E.8.1）：intercept + trampoline，单槽 RELRO 定位
- [x] **动态通道 = #1 卖点**：原生 EVP GOT hook 在**明文边界**抓到 AES 明文 `IDH_CRYPTO_PLAINTEXT_v1`（加密前），trampoline 不崩
  - `resolve_sym()`：解析已加载模块内存 dynsym（绕过 dlopen namespace 限制）
  - `crypto_probe`：定位 EVP 指针在哪个模块 GOT（实测 libjavacrypto.so=Conscrypt JCE 路径）
  - `crypto_hook_test`：装 hook → JNI 反射触发 JavaCrypto.run() → 返回捕获明文
  - **经验**：Conscrypt 经 GOT 调系统 libcrypto EVP（可 hook）；系统 libcrypto 不可 dlopen（namespace）→ 内存 dynsym 解析；"libcrypto.so" 子串会误配 cronet 版 → 精确 basename

### v0.4 后续增强（推迟，非阻塞）

- [ ] HMAC/Digest 捕获（EVP_DigestUpdate/HMAC_Update，GOT 已确认可 hook）；key/iv 捕获（hook EVP_CipherInit）
- [ ] 明文事件异步流到 idhd（当前是 pull 式 capture buffer）→ Algorithm Session 视图（H.1）
- [ ] 纯 Java 自实现加密（不走 BoringSSL）需 Java 层 hook（LSPlant，留待引擎稳定）

### v0.4 已完成并验证（verify_all.sh 7/7 PASS）

- [x] **DEX 解析器** `daemon/src/dex.ts`（header/string_ids/type_ids/method_ids/class_defs、uleb128、MUTF-8）——同时是 v0.5 基础
- [x] **crypto 静态扫描（H.2）** `POST /api/dex/parse` + `/api/dex/crypto_scan`：找 javax/crypto 方法引用 + 算法字符串
- [x] sandbox JavaCrypto（AES/CBC + HmacSHA256，已知 key/iv/明文）——静态引用 + 未来动态 hook 目标
- [x] verify_v04_dexparse（host-only，多 dex 聚合）：probe dex 解析正确；app 中命中 Cipher.doFinal/Mac/AES-CBC/HmacSHA256

### v0.4 动态通道进展

- [x] **GOT/PLT hook 引擎（E.8.1）已完成并验证**（verify_v04_gothook，suite 8/8）：`got_replace()` 扫描模块非 exec 段（含 RELRO）找已解析函数指针→mprotect→换 wrapper→trampoline 调原函数。self-test hook agent 自己的 close() 命中且不崩。
  - **关键经验（写死在代码注释）**：① 必须扫到 RELRO(r--) 段——真正的 .got.plt 槽在那；只扫 writable 会命中 .data 副本导致 wrapper 不触发。② 只能 hook **第一个（真实）槽**；把重复副本也改掉会破坏原函数自身调用路径→trampoline 时死锁。
- [ ] **下一步 v0.4(dyn-2)：用 GOT 引擎 hook BoringSSL EVP，抓明文**
  - 目标：`libcrypto.so` 的 `EVP_EncryptUpdate/EVP_DecryptUpdate/EVP_CipherUpdate`（Android JCE 默认 Conscrypt→BoringSSL）。
  - 定位调用方模块：Conscrypt native（libjavacrypto.so 或 boot image）——先用 `got_replace` 在哪个模块能命中 EVP 指针需实测；或对所有已加载模块尝试。
  - wrapper 签名 `int EVP_CipherUpdate(ctx, out, *outl, in, inl)`：记录 in/inl（明文/密文）→ 发事件给 idhd → 调原函数。
  - 验证：sandbox JavaCrypto.run() 跑 AES，断言捕获的明文含 "IDH_CRYPTO_PLAINTEXT_v1"。
  - 备选：若 Conscrypt 不经 GOT 调 EVP（静态内联），改 hook 导出符号地址的 inline hook，或 Java 层 LSPlant。

**（历史决策）为什么先不做 LSPlant**：Java method hook 需内联 hook 后端 + backup method 重建（版本相关、易崩）；改走更安全的原生 EVP GOT hook，引擎已就绪。

**更安全的计划（下一个增量）——原生 BoringSSL EVP 的 PLT/GOT hook（E.8.1）**：
- Android JCE 默认走 Conscrypt → BoringSSL `libcrypto.so` 的 `EVP_CipherUpdate/EVP_EncryptUpdate/EVP_DecryptUpdate` 等。
- GOT hook = 只改函数指针（安全，可 trampoline 调原函数），无需内联/指令重定位/backup method。
- agent：枚举已加载模块，解析各自 .dynamic→DT_JMPREL/DT_SYMTAB/DT_STRTAB，匹配 EVP_* 符号的 GOT 槽，mprotect 可写→换指针→我方 wrapper 记录 in/inlen（明文）后调原函数。
- 先在**受控目标**验证 GOT hook 机制（hook agent 自己对某 libc 函数的调用，断言 wrapper 命中），再上 EVP。
- 验证：sandbox JavaCrypto.run() 跑 AES，hook 抓到的明文 == "IDH_CRYPTO_PLAINTEXT_v1"。
- 备选/补充：Java 层 hook（LSPlant）留待引擎稳定后，用于纯 Java 自实现加密（不走 BoringSSL）的场景。

### v0.3 已完成并验证（verify_all.sh 6/6 PASS）

- [x] agent JNI 反射基础（cache JavaVM + attach 原生线程 + Build.VERSION 读取）`GET /api/jni/probe`
- [x] **ART 结构级 dex 枚举** `GET /api/art/dexfiles`：ClassLoader→pathList→dexElements→dexFile→mCookie(long[])→art::DexFile*→scavenge begin_（指向 dex/cdex magic 的成员）→自描述 header 读 size。**不做 magic 扫描、不硬编码 ART 偏移**。关键：Android tagged pointer（top-byte TBI）需 untag 后再 pread。
- [x] **结构级 dump** `POST /api/art/dump`：对 InMemoryDexClassLoader 的已知 728B dex，sha256 与 d8 原始输出**字节级一致**；正确归属 ClassLoader 类型
- [x] sandbox 增 DynamicDex（InMemoryDexClassLoader 加载已知 dex + 设为 context loader）

### v0.3 剩余（推迟，非阻塞）

- [ ] 恢复状态标记（已恢复/仍为空）、多 Android API level resolver 兜底、与 magic scan 交叉校验、失败时结构探测报告
- [ ] 抽取壳场景（方法体运行时解密）——属 v0.9 Method Body Recovery

### v0.2 Dump Engine — 完成并全部验证（tools/verify_all.sh 5/5 PASS）

- [x] idhd↔agent 命令通道（`cmd`/`cmdResult`，pending-promise + 超时；每 session socket）
- [x] 按需全量 maps `GET /api/process/maps`（前 40 与内核 verbatim 一致）
- [x] `memory.read` `POST /api/memory/read`（/proc/self/mem pread + base64；读到真实 ELF 头）
- [x] dex/ELF magic 扫描 `GET /api/memory/scan_magic`（dex/cdex/elf/zip/oat/vdex 全命中）
- [x] `memory.search` `POST /api/memory/search`（hex/text）
- [x] region dump + sha256 去重 `POST /api/memory/dump` + `/api/dumps[/download]`（mock dex 字节级 sha256 校验）
- [x] **so 重组** `GET /api/modules` + `POST /api/module/dump`（SoFixer-lite：PT_LOAD 按 vaddr 重排，保留 PT_DYNAMIC；重建 libidh_agent.so 有效可分析）
- [x] **dex header 修复** `POST /api/dex/repair`（file_size/checksum/signature；对真实 5MB dex 字节级还原）
- [x] 主回归脚本 `tools/verify_all.sh`（设备缺席时 device 脚本 SKIP 不 FAIL）

### v0.2 未做（推迟，非阻塞）

- [ ] Web：Memory Explorer / Dump Center 页面（并入 v1.0 Web 收尾，或 v0.3 后穿插）

## v1.0 打磨已完成（本轮）

- [x] **MCP 工具补齐到 25**（+memory_dump/flow_correlate/object_invoke/trace_function/dex_method_code/dex_repair）——每个能力都可被 AI 调用
- [x] **诊断导出** `GET /api/export/report`（仅元数据，无 key/明文）+ `GET /api/mcp/doc`
- [x] **文档**：docs/architecture.md（as-built）、docs/threat-model.md、docs/mcp-tools.md（自动生成）

## 下一步

**无。项目按路线图完成（v0.2–v1.0 全绿，26/26）。自动续跑循环已停（durable cron 已删除）。**
后续若要扩展：模块 U 非标运行时识别（Flutter/Unity/RN）、真实 Zygisk/gadget 注入器（模块 W，用户手测）、
更多 sandbox 对抗场景。均为增强，非路线图必需。

## 下一步（v0.2 Dump Engine）

1. 协议扩展：idhd→agent 命令通道（cmd/cmdResult），大 payload 走 base64/后续 shm
2. agent：按需返回**完整 maps**、`memory.read(start,size)`、region dump、dex magic scan
3. idhd：`/api/process/maps`、`/api/memory/read`、`/api/memory/dump`、`/api/memory/scan_magic`；dump 落盘 + sha256 去重（DexIdentity）
4. Web：Memory Explorer 最小页
5. 验收：AntiDumpMock/DynamicDex（sandbox 需补这些 Activity）dump hash 对照；`tools/verify_v02.sh`

## 验收信号（每个版本必须可 pass/fail）

- v0.1：agent 连上 idhd；maps 条目数与 `adb shell cat /proc/<pid>/maps` 一致；Dashboard 显示在线
- 后续版本验收标准见 `DEVELOPMENT_PLAN.md` §11 测试策略

## 未决 / 待办提醒

- 构建工具链选型（NDK/CMake for agent；idhd 语言：C++/Rust/Go 待定）在 v0.1 敲定后回填 `CLAUDE.md` 的 build 命令
- ART 结构 resolver 需覆盖 SDK 36（设备版本）优先

## 会话日志（倒序，简短）

- 2026-07-27（产品方向决策 + v2.1 重新定scope：LSPlant 降级，原生 Signature/KDF/AEAD 覆盖扩展）：
  用户明确产品方向——ADH 是 **C 端产品**，"不兼容就不要做，必须大部分设备都可用，不做小众功能"。
  据此重新审视 §6.9.4 P0（国密+Signature+KDF，原计划整体绑 LSPlant）：LSPlant 在测试机 13f54a46
  （OnePlus PGP110/ColorOS/A15，代表性消费级 ROM）上因 `libart.so` 缺失 44 个所需 ART 符号中的
  30 个（68%）根本性阻塞，同 ROM ShadowHook inline 后端同样失败——系统性 ROM 限制，非集成 bug，
  正是"不兼容就不做"的典型例子。**决策**：把 P0 里能靠原生 GOT hook 解决的部分（RSA/ECDSA
  Signature、PBKDF2/HKDF/scrypt、GCM/ChaCha20-Poly1305 AEAD）与 LSPlant 依赖切割，用已证明
  ROM-independent 的 GOT hook 引擎补齐（9 个新符号：EVP_PKEY_sign/verify/encrypt/decrypt、
  PKCS5_PBKDF2_HMAC/HKDF/EVP_PBE_scrypt、EVP_AEAD_CTX_seal/open）；国密 SM2/SM3/SM4（无原生
  BoringSSL 等价物，走 BouncyCastle 纯 Java 或厂商私有原生库，两条路都到不了 LSPlant 之外的方案）
  与隐私分析面板（纯 Java-only API，同样只能靠 LSPlant）明确标 **PENDING**，不伪造覆盖、不再占用
  当前验收门禁。**意外发现**：Conscrypt 的 AES/GCM、ChaCha20-Poly1305 走 BoringSSL 独立的
  `EVP_AEAD_CTX_seal/open` 一次性 API，完全不经过既有 `EVP_CipherUpdate` hook——即现有对称 hook
  此前**完全抓不到 GCM/ChaCha20-Poly1305 的明文/密文**，此增量顺带修复。`EC_POINT_mul` 明确排除
  （ECDSA 内部多次调用，非一次性 API 边界，高频噪音无取证价值）。详见
  `docs/DEVELOPMENT_PLAN.md` §6.9.1/§6.9.2/§6.9.4 与执行计划。

- 2026-07-24 (WS-B crypto 去硬编码 + WS-C cap_reset 记账修复，agent 零硬编码目标模块)：接上一条 39/39
  绿基线，做真正的功能增量。**WS-B**：agent 的 crypto/TLS 常驻 hook 此前把模块名写死成 `"libjavacrypto.so"`
  （安装 6 处 + 还原 6 处）——这是常驻采集路径上**最后一处硬编码目标模块**（file/sys 类早已参数化）。改成
  `capture_start` 新增 `cryptoModule` 参数→`g_crypto_mod`，安装/还原全用它；**agent 内不再 bake 任何模块名**
  （门禁① 对 crypto 类达成）。默认值放 idhd `settings.capture.cryptoModule`，随 `captureModules()` 下发。
  **踩坑（真机诊断）**：先把默认设为 `''`＝扫全部文件型模块（想覆盖 cronet 自带 BoringSSL / 改名库），结果
  **app 一收 capture_start 就崩**（HELLO→MAPS→2s 后 CLOSE）——`""` 广扫会 hook 到 framework/boot 模块里
  **app 启动期就在主线程跑的 crypto 调用**，破坏系统内部路径。改回安全默认 `libjavacrypto.so`（Conscrypt，
  每个 App 的 JCE/TLS 路径、与框架隔离）；`''` 广扫**降级为高级 opt-in**并注明会拖垮启动。真正的通用性收益是
  **operator 可按目标把 crypto hook 指到任意单模块**（`libcronet.so`/改名库，稳定，一次一个），而非焊死 Conscrypt。
  配套加固 `got_replace`：广扫时**跳过非文件型映射**（路径非 `/` 开头的匿名/`[stack]`/JIT 区——那里没有 GOT/reloc
  槽，避免 `""` 误改巧合数据字）；具名调用零影响。**WS-C**：诊断 v22 时揪出一个既有 latent bug——`cap_reset()`
  清空环形缓冲时**丢弃环内未 drain 的记录却不计入 dropped**，导致某次 capture_stop/probe 撞上非空环后
  `emitted+backlog+dropped==seq` **永久漏 N**（真机稳定复现 off-by-1，30 个采样全差 1）。修：cap_reset 把丢弃的
  `g_ring_count` 计入 `g_cap_dropped`（WS-C“没有一条静默消失”）。硬信号：v22 稳定态 `accountedFor==seq`
  （20030==20030）、`accounted=true`；crypto 明文照常（v04 `replaced=1 ascii="IDH_CRYPTO_PLAINTEXT_v1"`）；
  **`verify_all` = 39/39 PASS**（agent 重建+重装真机 13f54a46 + host 全绿）。
  **未做（诚实边界）**：`''` 全模块广扫在本 ROM 不稳（框架 crypto 主线程），未验证可用——留作需要时按单模块指定；
  非 Conscrypt 目标的实测需真实样本（sandbox 只走 Conscrypt）。

- 2026-07-24 (测试机切到 13f54a46 + 恢复 verify_all 39/39 全绿 + 修 2 个真 bug)：用户指定测试机为
  **`13f54a46`（OnePlus PGP110，Android 15 / SDK 35，arm64-v8a，root）**，非旧记录的 Pixel 6 Pro。
  项目已从 `…/Desktop/ADH` 迁到 `…/桌面文件备份3/ADH`（非 ASCII 路径），新机首跑基线 **10/39 红**——
  逐条 root-cause，**6 个纯环境**（① `agent/build` 的 CMakeCache 指向旧 Desktop 路径→`rm -rf` 重配；
  ② sandbox APK 从未在本机构建，7 个 host dex 测试报 "APK missing"→`gradlew assembleDebug`；③ AGP 因
  非 ASCII 路径拒构建→`gradle.properties` 加 `android.overridePathCheck=true`；④ `/tmp/base.dex` 在 APK 缺席
  时被建成 0 字节空文件、`[ -f ]` 判存在跳过重解压→v12/v13 一直吃空 dex）；**2 个真代码修复**：
  (a) **`/api/trace/run` 漏了 `withCaptureSuspended`**——常驻采集已 hook 住 `access` 的 GOT 槽，一次性
  `trace_run` 再找原始 `access` 得 `replaced=0`；其余 6 个一次性探针都包了挂起，唯独它没有→补上，v10_trace
  转绿（`replaced=1 calls=2` 两条 su 路径同线程）。(b) **`/api/native/analyze` 导出列表 cap=500 太小**——
  LSPlant 把 agent .so 撑到 **756 个导出**，`idh_agent_start`(dynsym #702) 被截在 500 之后丢失，v08_analyze
  假失败；cap 提到 20000 + 加 `truncated` 标记（fail-loud）。**脚本健壮性**：v12/v13 `[ -f ]`→`[ -s ]`（判非空
  才复用缓存）；**v03 去掉硬编码 `sdk_int===36`**，改成对齐设备 `getprop ro.build.version.sdk`（SDK 35/36 通用）。
  **CLAUDE.md/AGENTS.md**：填了此前 TBD 的 Commands 段（build/test/lint 全量命令）；测试机段改为 13f54a46 +
  **多台同型号 PGP110 在线须 `export ANDROID_SERIAL=13f54a46`** + **本 ColorOS ROM 的 libart.so 重度 strip
  →LSPlant(WS-A) 在此机根本性阻塞,需 stock/Pixel 验证**。硬信号：**`tools/verify_all.sh` = 39/39 PASS
  fail=0 skip=0**（真机 13f54a46 + host 全绿）。下一步：crypto/TLS 常驻 hook 去 `libjavacrypto.so` 硬编码
  （加 `cryptoModule` 参数,默认扫全部文件型模块,覆盖 cronet/改名 BoringSSL）。


- 2026-07-14 (v2.1 WS-A · LSPlant 集成——**编译通过 + 后端加载，卡在 ROM ART 符号**)：为国密/Signature/KDF
  + 隐私面板铺 ART 方法级 hook 地基。三个侦察 subagent 产出（LSPlant 配方 / 加密 hook 表 / 隐私 hook 表）后落地
  **完整集成**：`tools/fetch_lsplant.sh`（LSPlant **v6.4** + DexBuilder + parallel_hashmap；master 用 C++23 modules
  需 CMake 3.28 不兼容我们的 3.22.1）；inline hooker 选型踩坑记录——**ShadowHook** 预编译 .so 装上但
  `shadowhook_init` 报 `INIT_LINKER`(errno12)、其引擎在本 ColorOS ROM 不可用；**Dobby master** 源码腐烂编不过
  （`ProcessRuntime.cc` 引用已删字段 + .asm/头缺失）；最终用 **Dobby 预编译静态库** `io.github.vvb2060.ndk:dobby:1.2`
  （正是 LSPlant 自测用的后端，`libdobby.a` 静态链入、自包含、按地址 hook、无 .so/JNI_OnLoad/linker 监控）。
  CMake 扩 `C→C CXX`+C++20+`-DANDROID_STL=c++_static`；新增 `java_lsplant.cpp/.h`（C-ABI 壳，`lsplant::Init/Hook/UnHook`）；
  `resolve_sym` 重构出 `resolve_sym_ex`+`idh_resolve_sym[_prefix]` C 包装供 ART 符号解析；agent 加 `java_hook_test` 命令、
  daemon `/api/java/hook_test`、沙盒 `HookTarget.kt`+`com.idh.agent.MethodHook.java`（LSPlant 回调）、`verify_v23_javahook.sh`。
  **agent 编译通过（13.4MB 自包含 .so），Dobby 后端加载不崩，既有能力零回归**（v04_crypto/v11/v20 全 PASS）。
  **硬阻塞（fail-loud，未伪装通过）**：`lsplant::Init` 失败——LSPlant 需 ART 符号 `GetMethodShorty`
  （内部链接 `_ZN3artL15GetMethodShorty...`），本机 `libart.so` **dynsym 2822 个符号里 0 个含 Shorty**（ColorOS/
  Android15 stripped 掉了）。v6.4 无兜底；支持 A15/16 的新 LSPlant 又要 C++23。**下一步（择一）**：① cherry-pick 新
  LSPlant 的无符号 shorty 解析进 v6.4；② 换能导出该符号的 ROM/设备（如 CLAUDE.md 记录的 Pixel 6 Pro）验证；
  ③ 用 JNI 反射（getParameterTypes/getReturnType）在 C++ 侧自算 shorty 替换 LSPlant 的 GetMethodShorty 依赖。
  `verify_v23` **暂不入 verify_all**（已知阻塞，避免把套件染红），待解阻塞后纳入。
  **续（同日深挖，确认是 ROM 问题非集成缺陷）**：按"改成不依赖该符号"落地——`idh_compute_shorty`（JNI 反射
  从 reflect Method 自算 shorty：返回类型+参数类型→V/Z/B/C/S/I/J/F/D/L）替换 `GetMethodShorty`，patch 进
  `art_method.hpp`（fetch 脚本可复现）；**GetMethodShorty 已解**（log 实测"computing shorty via JNI reflection"）。
  又把 `SetEntryPointsToInterpreter`+`art_quick_*` 反优化入口改为非致命（只 `Deoptimize()` 用、Hook 不用），
  越过 ClassLinker::Init。**但继续撞墙**：`JitCodeCache::GarbageCollectCache` 等也被 strip。**量化定论**：
  本机 `libart.so` dynsym 里 **LSPlant 需要的 44 个 mangled ART 符号有 30 个被 strip 掉**（ColorOS/A15 激进裁剪，
  68% 缺失），JIT code cache / 真正的方法替换 trampoline 无符号无解。**结论：集成正确（编译/加载/shorty 回退均通），
  但此 ROM 从根本上不兼容 LSPlant v6.4**——LSPlant 在 Pixel/AOSP（导出完整符号集）上开发验证。**下一步：换
  CLAUDE.md 记录的 Pixel 6 Pro(SDK36) 验证**（stock 导出这些符号），或继续 30 符号的逐个无符号化（高成本、部分无解）。

- 2026-07-14 (二轮审计 P1 · got_replace 交叉验证重定位槽)：审计的内存损坏隐患——`got_replace` 旧逻辑
  在模块非 exec 段扫任一 `*word==orig` 就改（大混淆 so 里巧合等值的数据字会被写成 wrapper → 崩）。修复：
  新增 `module_base_of`/`reloc_slots`（解析模块 `.rela.plt`(DT_JMPREL/DT_PLTRELSZ) + `.rela.dyn`(DT_RELA/DT_RELASZ)
  的 `Elf64_Rela.r_offset` → 绝对 GOT 槽地址集）+ `slot_in_set`。`got_replace` 现只改**确属重定位槽**的匹配
  （`*slot==orig` 且地址在 reloc 集内）；reloc 解析失败/截断时**回退到旧的值匹配并 log 告警**（不破坏现有能力）。
  硬信号：v04_gothook(自测 close)/v04_crypto(EVP)/v07(SSL_rw)/v20_file(open/__read_chk/__write_chk) **全 PASS**——
  证明交叉验证能找到真实槽（所有 hook 照常命中），同时对巧合数据字免疫。
  **未做（下一步）**：wrapper SIGSEGV 隔离 handler；国密/Signature/KDF 与隐私面板需 LSPlant（WS-A，v2.1）。
- 2026-07-14 (二轮审计 P0 · 前端主操作去 sandbox 硬编码)：审计最坑新手的一处——"一键脱壳"前端写死
  `triggerAllPrefix:'com.idh.sandbox.'` + `triggerClasses:['com.idh.sandbox.TriggerProbe']`，对真实 App 点它
  **静默空转还显示"会话完成"**。修复：① 后端 `runUnpackSession` 的 `triggerAllPrefix` **缺省改为连上来的目标进程
  包名**（`sessions.get(sid).package`，agent hello 已知）——沙盒/真实目标都自动生效；② 前端 `unpackRun` 去掉写死的
  sandbox 前缀/类/方法（改为 `triggerAllPrefix:val('unpack-pkg')||undefined`，级别 3 无 method = 只加载类、对真实目标安全），
  加"目标包名前缀"输入框（留空=自动）；③ TLS 明文/关联取证/反分析雷达/一次性抓明文四个按钮**明确标注"(沙盒)"**
  并加说明（它们经 agent 反射触发 sandbox 测试类，真实目标由「加解密·实时」常驻 hook 被动采集）。硬信号：
  served HTML 里 **`com.idh.sandbox` 计数归 0**；不传前缀直接调 `/api/unpack/run` 自动用 `com.idh.sandbox`
  枚举触发 28 类、4 dex；回归 verify_v10_webui/v15_session/v17_deepunpack 全 PASS。
  **未做（下一步大件）**：agent 侧 `net_hook_test/flow_watch/detect_watch/crypto_hook_test` 仍写死 sandbox 类
  （属 WS-B agent 去耦合）；国密/Signature/KDF 与隐私面板需 LSPlant（WS-A，v2.1）。
- 2026-07-14 (二轮审计 P0/P1 · 采集热路径不阻塞目标线程)：把二轮审计（四维 + P0/P1/P2）折进
  `DEVELOPMENT_PLAN §6.9.4`（三大欠账：国密/非对称/KDF、隐私分析 0→1、前端去 sandbox 化）。
  本轮落地两处 agent 热路径安全修复（自包含、真机验证）：
  ① **`capture()` 改非阻塞**——**移除目标加密/TLS 线程里的 `usleep` 背压**（旧：ring 满等 3×150µs 再丢，
  给目标注入可测延迟 = 时序反调试面 + ANR），改为 `pthread_mutex_trylock`：锁忙/环满即原子计数丢弃、
  **绝不阻塞/睡眠目标线程**；`g_cap_seq`/`g_cap_dropped` 全部 `__atomic_*`；`nReport`（Java 富采集，同在目标线程）
  同样改 trylock。② **`trace_preview` 缓存 `/proc/self/mem` fd**（旧：wrapper 热路径每次 open/close，fd 压力），
  一次性 CAS 打开、不再关闭。硬信号：`verify_v22` 不变式 `emitted+backlog+dropped==seq` 仍恒成立，且
  **`seq=41289`（比旧 20017 更高）——正因目标线程不再被 usleep 拖住、burst 跑得更快**，dropped=21063 如实上报；
  `verify_v10_trace` 缓存 fd 后仍解析出 `access("/system/xbin/su")`。回归：v04_crypto/v07/v07_flow/v11/v20 全 PASS
  （v20 批量里偶发 flake，单跑 PASS：open 路径 + write/read marker + 校验OK）。
  **未做（大件，下一步）**：got_replace 交叉验证重定位槽、SIGSEGV 隔离；国密/Signature/KDF 与隐私面板需 LSPlant（WS-A，v2.1）；
  前端"一键脱壳"去 sandbox 硬编码（P0，触及 Web UI）。
- 2026-07-14 (v2.0 WS-C · 采集环形缓冲 + 如实 dropped)：把 native 采集从定长 `g_caps[64]`
  （满即**静默丢**）换成 **`CAP_RING=1024` 环形缓冲 + 有界阻塞背压**（producer 最多等
  `3×150µs` 再丢）+ **诚实计数**：`g_cap_seq`(每次 capture 尝试)、`g_cap_dropped`+首/末丢弃时间戳，
  Java 富路径 `g_jcaps[96]` 加 `g_jcap_dropped`。不变式 **`emitted + backlog + dropped == seq`** 恒成立
  （没有任何一条静默消失）。`capture_drain` 改为按批 pop（可增长缓冲，顺带修掉旧固定 64KB 缓冲对满环的
  潜在溢出），带回 seq/dropped/backlog/complete。daemon：`capStats`/`captureHealth` 聚合，
  drain tick 循环把 backlog 拉空，`/api/captures` 与 `configStats` 带 `complete/dropped/seq/backlog/accountedFor`，
  首次丢弃 log 红字（fail-loud）。**验收 `verify_v22_capture.sh`（真机 PASS）**：外部触发
  `BurstProbe.run()`（20000 次 AES，**类名由 idhd 传参、agent 零知识 = WS-B 干净**）→ 观测
  `seq=20017 emitted=14775 dropped=5242 jdropped=17126 complete=false`，**每个采样点 accountedFor==seq**——
  旧实现只会显示 ~64 条、dropped=0 却静默丢 ~19936。app 未崩。回归：**verify_all 全绿**（除已知
  verify_v03 的 SDK35≠36 设备断言，与本改动无关）。
  **诚实边界（未做，非潦草）**：WS-C 计划里的"drain 线程经 `FRAME_CAPTURE`(0x02) 连续 push + idhd 落盘"
  本轮**未做**——保留 pull-drain（idhd 轮询 `capture_drain`，命中 backlog 时连拉直到清空）以最小化对既有
  35 脚本采集路径的回归风险；帧类型 `0x02` 与 `g_send_lock` 已就位。连续 push + 落盘直通留作 WS-C 下一步。
- 2026-07-14 (v2.0 WS-D · length-framed 协议)：把 agent↔idhd 线协议从 NDJSON 换成
  **`[u32 len BE][u8 type][payload]`**（`FRAME_JSON=0x01`；`0x02` 采集批留给 WS-C）。
  agent：`send_frame`/`send_line`（加 `g_send_lock` 为 WS-C drain 线程前置）+ `read_full` 按长读整帧，
  `command_loop` **去掉 8192 单行缓冲 + memchr 分行**，改按 `len` malloc 读整帧；帧长 > `FRAME_MAX_IN`(16MiB)
  或未知 type → **关连接/跳过并 log（fail-loud，不重同步损坏流）**。daemon：`frameJson()` + `sock.on('data')`
  改 Buffer 帧解析（`FRAME_MAX`=64MiB 超限 destroy），`sendCmd`/ack/pong 全走帧。`proto/PROTOCOL.md` 重写为帧规范。
  **验收 `verify_v21_frame.sh`（真机 PASS）**：A) 1MB `pad` 命令帧 + `tail` 哨兵置于第 8192 位之后，
  `recvBytes=1048669 tailOk notTruncated`——证明命令方向越过旧 8192 上限完整送达；B) 16MB region dump
  字节级 sha256 一致（1MB 分片 dump vs 256KB 分片重读 = `2ec725abde…` 完全相同）——证明响应方向多 MB
  跨不同帧边界零截断/零损坏。回归：**旧 35 脚本中除 verify_v03 全 PASS**，协议改动零回归。
  **注**：`verify_v03` 唯一失败项是它硬编码 `sdk_int===36`，而本轮设备 `13f54a46`=PGP110=**SDK 35**
  （非 CLAUDE.md 记录的 Pixel 6 Pro/SDK36）；其 ART 结构 dump 本身**字节级 PASS**（sha 命中 + probe 找到），
  纯属设备版本断言不匹配，与 WS-D 无关——**待用户确认换回 Pixel 6 Pro 或放宽该断言**。下一步 WS-C 环形缓冲。

- 2026-07-14 (v2.0+ 加固重构立项 · 折叠一份计划)：应用户"锐评 14 点 + 重构方案"，把 **WS-A…WS-K
  工作流 + v2.0–v2.6 排期 + 三条总原则 + 不胡乱兜底门禁清单**折叠进 `DEVELOPMENT_PLAN.md §6.9`
  （当前权威路线），旧 v0.1–v1.0 路线归档到 §7（标注已完成 35/35，不再续写）。本文件"当前阶段"从
  "项目完成"改为"v2.0+ 加固重构进行中"。**核心转向**：从"每条路径能演示"→"能在对抗/并发/无样本/
  无 sandbox 耦合下不骗人"。三门禁：① agent 零 sandbox 耦合（`grep com.idh.sandbox agent/`=0、
  目标模块名不硬编码、全走命令参数）；② fail-loud（装不上/溢出/解不动显式报错+计数，禁止
  `ok:true replaced:0`/虚高恢复率）；③ 红线不动（重分析 idhd、hook/采集 agent）。
  先开 **v2.0**（WS-D length-framed 协议去 8192 上限 + WS-C 环形缓冲/落盘/如实 dropped 上报）——
  风险最低、是后面所有采集能力的地基。

- 2026-07-14 (sandbox App Material Design 重构 + 真实文件 I/O hook)：应用户要求"完全重构为 Material Design，
  加 HTTPS 请求发送、文件读写，作插件功能全测试 demo"。范围二选一经用户确认：**只改 sandbox-app，daemon Web UI 不动**；
  文件 I/O 能力必须是**真实 agent 侧原生 hook**，不是装饰性按钮。
  ① **sandbox-app 全量 Material Components 重写**（`MainActivity.kt`：Material3 Dark 主题、`MaterialCardView`/`MaterialButton`，
  中文分区卡片：控制台/加解密测试/网络文件I/O/脱壳触发/测试日志），新增 `themes.xml`/`colors.xml`。
  ② **`Network.kt`/`CorrelatedFlow.kt` HTTPS 发送 + `FileIO.kt` 真实文件读写**（写 `IDH_FILE_MARKER_v1` 到
  app 私有路径、读回校验），供 agent hook 触发对象。
  ③ **agent 文件 I/O GOT hook**（`cmd_file_probe` 扫描 open/openat/read/write/close 落在哪个模块的 GOT；
  `cmd_file_hook_test` 装 hook→JNI 反射触发 `FileIO.run()`→还原→报告捕获）。
  **关键坑（现场真机诊断，非猜测）**：libopenjdk.so 虽然静态导入 open/read/write/close/syscall（`readelf --dyn-syms` 证实），
  但真实 `java.io.FileInputStream/FileOutputStream` 走的是 **libjavacore.so**（libcore Linux.cpp JNI 层），且该模块对
  read/write 分别导入的是 bionic FORTIFY_SOURCE 变体 `__read_chk(fd,buf,count,buflen)` 和 `__write_chk`（不同版本节
  `LIBC_N` vs `LIBC`，`readelf -sW` 才能看全名，截断输出会把它当成 `writev`/`syscall` 误诊）——挂 `open`/`close`（明符号）
  + `__read_chk`/`__write_chk` 才是正确 hook 点；曾错误尝试 `syscall()` 级 hook（因怀疑 libcore 走 raw syscall）和
  `writev` hook，两者都装得上但零捕获，静态 dynsym 比对后定位到真正符号才修好。
  硬信号：`open` 捕获真实路径 `/data/data/com.idh.sandbox/files/idh_file_test.txt`，`write`/`read` 各捕获
  55B `IDH_FILE_MARKER_v1 订单号=... 金额=...` 明文，四条捕获顺序 open→write→open→read 与代码逻辑完全对应。
  新增 `verify_v20_file.sh`（真机断言 open 路径 + write/read marker 字节），已入 `verify_all.sh`。
  遗留小问题（非阻塞）：`close` hook 装上但 `closeHits` 恒为 0（IoBridge 的 close 路径未進一步深挖，不影响已确认的
  open/write/read 核心取证信号）。设备侧本轮用 `13f54a46`(PGP110/SDK35)，非 CLAUDE.md 记录的 Pixel 6 Pro——待与用户确认。
- 2026-07-11 (设置/MCP/配置导入导出，对齐 IDH 交互)：**把 IDH 的「头部按钮→模态」范式引入 ADH**。
  熟读 `.ref/ios-decrypt-helper/web/index.html` 的 set-shell/set-switch/配置JSON编辑器/openMcp。
  后端 `daemon/src/index.ts`：新增 `settings`（持久化 `idhd-data/settings.json`）+ `mergeSettings` 板块合并；
  端点 `GET/POST /api/config`、`GET /api/settings/export`、`POST /api/settings/import`、`POST /api/data/clear`；
  `/api/mcp/config` 加 `cli`(claude mcp add 等价命令)；captures 用 `pushCapture`（家族过滤 idhd 侧 + retain 上限）替换硬编码 1000；
  autoDumpDex/capture_start 受 settings 控制。前端：头部 `MCP`/`设置` 按钮→两个模态；设置三页(捕获开关+家族过滤+容量 / 数据统计+清空+导出 / 配置JSON 重载·复制·下载·从文件载入·保存并应用)；toast；
  主 tab 精简为 加解密/一键脱壳（MCP 移入模态，去掉 p-mcp tab）。**刻意不做** IDH 的伪装/绕过页（反检测，超范围）。
  真机验证：捕获经新路径正常流入、**家族过滤 live 生效**（关 digest 后新捕获无 digest）、config 回读+落盘。
  新增 `verify_v19_settings.sh`(15 检查) 入 verify_all，扩 verify_v10_webui。**verify_all 35/35。**
- 2026-07-11 (UI 简化：便捷性)：**沙盒 App 屏 + Web 面板双双简化，去冗余、可手动触发测试。**
  App(`MainActivity`)：删掉重复的两块 URL + 长段用法说明，收成 1 个最优地址(局域网优先·点按复制)+连通点；
  新增手动触发区（全部算法/AES/RSA/SHA-256/HMAC/加载DEX/触发脱壳类/HTTPS/关联流）+ 自动加密流开关 + 屏内测试日志；
  `JavaCrypto` 抽出 `MENU`/`oneAes/oneRsa/oneSha256/oneHmac/runAllOnce` + 可停的 `startLiveDriver/stopLive/liveRunning`。
  Web(`index.html`)：8 tab → 3 主 tab（🔓加解密·实时 / 📦一键脱壳 / 🤖AI·MCP）对齐三轴，专家 5 工具收进「⋯ 高级」折叠默认隐藏；
  脱壳页「🚀 一键脱壳」为唯一主操作、手动 Dump/快照恢复进 `<details>`；MCP 页加「📋 复制 MCP 配置」(读 `/api/mcp/config`)+quickAsks。
  真机验证：APK 装上无崩溃、live 流转、health ok=true agents=7、captures=130 流入面板。**verify_all 34/34。**
  **补：去掉全部 emoji 图标**（硬性规则，见记忆 no-emoji-icons）——App/Web 所有标题/按钮/tab/日志改纯文字。
  **补：Web 视觉重做成 IDH 样式**——正文改系统无衬线字体（等宽仅留代码/hex），换 GitHub 暗色配色
  (#0d1117/#161b22/#30363d，绿色 monospace 标题、橙色激活 tab、蓝色强调)，明文/密文详情用 IDH 的 io-card
  (kv/in/out 三色卡片)。参考 `.ref/ios-decrypt-helper/web/index.html`。旧 catppuccin 配色清空。
- 2026-07-11 (加载任意 so / frida-gadget)：agent 是目标进程内原生码 → 可 `dlopen` 任意 .so。
  `cmd_load_so(path, symbol?)` + `POST /api/agent/load_so` + MCP `load_library`。frida-gadget script 模式 dlopen 后自动跑 js。
  `tools/load_frida_gadget.sh`（root 推 gadget+config+js 到 code_cache、chcon、触发 load_so）。
  `verify_v18`（真机按绝对路径 dlopen libidhdetect.so + 符号解析）。**verify_all 34/34。**
  坑记录：app 进程默认只能从 nativeLibraryDir 执行 .so，任意路径受 SELinux exec 限制；设备 root 可 chcon/setenforce 绕过（内网测试可接受）。
- 2026-07-11 (逆向能力三轴延伸)：按重心定案——只做逆向能力，不做鉴权/防检测（内网测试）。
  **轴1 通用性**：`crypto_identify`（`/api/crypto/identify` + MCP）把捕获聚合成"App 用了哪些算法/密钥/IV"的白话报告，
  覆盖对称/**非对称RSA**/摘要/HMAC；Java 拦截 Provider + demo 加 RSA-2048。`verify_v16`（真机报告 11 算法 7 带密钥）。
  **轴3 灵活性**：MCP **25→34 工具**（crypto_identify/live_captures/capture_detail/dex_coverage/unpack_run/dex_recover/trigger/qbdi_trace/net_correlate），
  `/api/mcp/config` 一键配置（粘进 Claude/Cursor 即用）+ quickAsks 给不会逆向的同事。unpack 抽成 `runUnpackSession` REST/MCP 共用。
  **轴2 便捷性**：`unpack_run` 加 `triggerAllPrefix` —— 按包名从 dump 的 dex 枚举**全部类**主动加载(Level 1)，
  最大化回填型抽取壳的恢复机会，**无需刷 AOSP**。`verify_v17`（真机枚举加载 23 类 + 恢复重建）。
  **verify_all 33/33。** 排障：设备多次 offline，`adb reconnect` 恢复。
- 2026-07-10 (P3 会话编排收官)：把 P0–P2 串成一次操作。`POST /api/unpack/run`：
  **T0 快照(每 DexFile)→coverage→主动触发→T1 快照→按 begin 配对 recover+重建**，输出每 dex 前后恢复率 + 可下载重建 dex。
  面板「一键脱壳会话」；`verify_v15_session`（device）：五阶段贯通、T0/T1 各 4 dex、触发 safeCompute 生效、前后覆盖率、重建可解析。**verify_all 31/31。**
  **诚实边界（未做，非潦草）**：① cdex→标准dex、② DEX 041 逻辑拆分——设备是 dex-038，无真实 cdex/041 样本，
  041 容器"取全范围"已修(P0)但逻辑切分需样本；③ 分离缓冲/擦除型抽取壳需 backend C(壳恢复函数 hook)/D(ArtMethod，版本敏感)。
  这三项要么依赖真实样本、要么依赖脆弱 ART 内部结构，**不verify 就不发**。脱壳主线（一级整体 + 二级回填型 + 触发 + 会话）已闭环。
- 2026-07-10 (P2 主动分级触发)：invoke 只是"给捕获器制造触发机会"的触发源，不是恢复本身（触发→再快照→recover）。
  ① **agent `cmd_trigger`**：Level 1 加载类（壳可能在 class-load 时恢复）、Level 3 反射调用**安全 static 无参**方法；
     安全策略黑名单（exit/exec/delete/pay/lifecycle…），异常隔离，单类单方法（批次/进度由 idhd 编排）。
  ② `/api/unpack/trigger?session&class&method&level`。
  ③ sandbox `TriggerProbe`：safeCompute()(安全)/deleteAll()(黑名单)。
  ④ `verify_v14_trigger`：safeCompute 被调用(IDH_TRIGGER_OK) + deleteAll 按黑名单跳过 + 类可加载。**verify_all 30/30。**
  ⚠️ 排障记录：30+ 次 app 重启把 **adb reverse 返回路径(host→device)搞卡死**（hello 通、命令不通，HEAD 代码也复现）——
     `adb reboot` 复位后恢复。属环境问题，非代码。教训：频繁重启 app 时留意 adb reverse 退化，必要时重启 adb/设备。
- 2026-07-10 (P1 第二代恢复闭环)：按评审 P1 做"被动恢复"——**从恢复镜像捕获 CodeItem，不假设执行回填原 DEX**。
  ① `codeItemOf/recoverFromSnapshots`（dex.ts）：对 base 的 BASE_EMPTY 方法，从 restored 快照提取 code_item 生成 captures，再 `rebuildStandardDex`。
  ② `stripMethodCode`：同长度冗余-uleb 把 code_off 置 0，模拟抽取（不移位）。
  ③ `/api/dex/recover {baseSha,restoredSha}`（+ `/api/dex/strip` 测试工具）：真实设备流程=对同一 dex 先后 dump 两次(T0 抽取态/T1 运行后)做差异恢复，**无需新 agent 代码**（快照就是 art dump）。
  ④ 面板「脱壳」加"快照恢复"入口（base/restored sha → 恢复重建 + 下载）。
  ⑤ `verify_v13_recover`（host）：真实 classes.dex 抽取一个方法→从恢复镜像捕获→重建→**字节码字节级一致**。**verify_all 29/29。**
  覆盖范围诚实：处理"回填型"抽取壳；分离缓冲/执行后擦除型需 backend C(壳恢复函数 hook)/D(ArtMethod)，属下一档。P2=主动分级触发（类加载/初始化/安全调用）。
- 2026-07-10 (脱壳架构轮·采纳评审设计)：按评审给的正确设计做**脱壳地基**（先 CodeItem 捕获器+方法索引+重建器，不做 invoke-all）。
  纠正两个判断：① 第二代核心是"在壳恢复方法体的瞬间抓完整 CodeItem"，不能假设执行会回填原 DEX；② `begin+file_size` 对 DEX 041 container/cdex 会截断。
  ① **agent resolver 升级**（修 SDK36 截断 bug）：识别 035–041 + cdex，DEX 041 按 `container_size` 取全物理容器（begin=container_begin），严格校验 endian/header_size/越界，返回富视图 format/version/logical/dataBegin/dataSize/confidence。
  ② **方法索引 + 恢复率报告**（`analyzeCoverage`，`/api/dex/coverage`）：per-method 状态（native/abstract/BASE_PRESENT/BASE_EMPTY），恢复率只按具体 Java 方法算。真机 app dex：total=22586 concreteJava=21740 present=21740 recovery=100%（未加固→100%，诚实）。
  ③ **结构化标准 DEX 重建器**（`rebuildStandardDex`，`/api/dex/rebuild`）：按 method_idx 追加 CodeItem + 重写受影响类的 class_data + patch class_data_off（不做 uleb 原位改写）+ 修 file_size/data_size/SHA-1/Adler32。
  ④ 面板「脱壳」页加覆盖率报告（恢复率进度条 + 缺失方法清单）。
  ⑤ `verify_v12_rebuild`（host）：真实 classes.dex → 覆盖率 → 注入一个 code_item 重建 → **重建 dex 可解析 + 该方法字节码字节级一致（26B MATCH）**。**verify_all 28/28。**
  下一轮（P1）：运行时 CodeItem 捕获后端（解释器/自然执行捕获点）+ 抽取壳模拟场景做硬信号；再 P2 主动分级触发。
- 2026-07-10 (Java 层 hook 轮·参考 iOS 数据模型)：把加解密从"只有类别"升级到 iOS 级富审计。
  参考 iOS log_store 记录模型（algorithm/operation/key/iv/input/output/callstack/分类），做 **Android 自己的方案**：
  ① **Java 层拦截 Provider `IdhSecurity`**：插到最高优先级的 JCE Provider，包住 Cipher/Mac/MessageDigest 的 SPI，
     委托真实 AndroidOpenSSL 计算、在 Java API 边界采集 **算法全名 + Key + IV + 明文 + 密文**，覆盖纯 Java 加密。
  ② **agent JNI 富采集**：`Java_com_idh_sandbox_IdhReport_nReport`（JNI 名字绑定，无需 RegisterNatives）→ g_jcaps 富缓冲；
     capture_drain 增 `jcaptures`（algo/op/key/iv/in/out）。native EVP 层保留作显式指定 provider 绕过时的兜底。
  ③ **idhd 去重**：Java 富记录为准，按输入明文丢弃 native 回声（同明文 2s 窗）；`/api/captures` 带 source+key/iv/out。
  ④ **面板主从详情**：来源(Java/Native) + 算法 + 操作 + 🔑Key + IV + 明文(UTF-8) + 🔒密文。
  硬信号：`DESede/CBC/PKCS5Padding encrypt key=24B iv=8B ct=48B 明文=IDH_LIVE_..订单金额=191.00元`；10 个精确算法名全覆盖。
  **verify_v11 升级为富字段断言（算法+Key+IV+明文+密文），verify_all 27/27。**
  （下一步：把 IdhSecurity 从 sandbox 挪到 agent 注入的 dex，做到任意目标；或上 LSPlant 做不可绕过的方法级 hook。）
- 2026-07-10 (加密面铺开轮)：只抓 AES 太单薄——按 IDH 覆盖完整加密面。
  ① **agent 常驻 hook 扩到全套**：EVP_CipherUpdate(对称) + EVP_DigestUpdate(摘要) + HMAC_Update/EVP_DigestSignUpdate(HMAC) + SSL_read/write(TLS)；capture_stop 对称还原。
  ② **demo 跑全套算法**（每 2s 轮转）：AES-CBC/CTR/GCM、DESede、MD5/SHA-1/SHA-256/SHA-512、HmacSHA256/HmacSHA1。
  ③ **面板分类**：对称/摘要/HMAC/TLS 四类 pill；明文 UTF-8 解码（中文可读）。
  ④ 新验收 `verify_v11_capture.sh`（对称+摘要+HMAC 三类都自动捕获 + 明文含 IDH_LIVE_ + DEX 可下载）。
  硬信号：`cats=对称加解密|摘要 Digest|HMAC`，明文 `IDH_LIVE_0009_HmacSHA1_订单金额=163.00元`。**verify_all 27/27**。
- 2026-07-10 (面板产品化轮·参考 iOS 数据流)：把 Web 从"接口调试器"改成**可操作观测面板**。
  参考 `.ref/ios-decrypt-helper`（hook 常驻→log store→Web 轮询主从列表；dump 面板直接下载）。
  ① **agent 常驻采集**：`capture_start`（常驻装 EVP+SSL hook，不还原）/`capture_drain`（返回并清空累积）/`capture_stop`（还原）。
  ② **idhd 自动流水线**：agent 连上即 `capture_start` + 每 1.5s `capture_drain` 入库/广播；自动 `art_dexfiles`→逐个 dump（可下载）。
  新端点 `/api/captures`(列表)/`/api/captures/:id`(明文 UTF-8 解码，中文可读)。
  ③ **sandbox App 加实时加解密驱动**（每 2.5s 滚动明文"订单金额=…元"），面板打开即自动填充。
  ④ **Web 重写为中文面板**：默认「加解密」主从实时列表（自动填充、点开看明文/密文/线程/时间）、「脱壳(DEX)」一键 Dump+下载、进程信息栏、其余功能中文化；调试台保留。
  ⑤ **冲突修复**：常驻 hook/drain 与一次性 probe 端点(crypto/net/flow)争用同一 GOT 槽+缓冲 → idhd `withCaptureSuspended` 在这三端点期间挂起常驻采集（暂停 drain+capture_stop→跑→capture_start）。
  硬信号：`/api/captures total>0 on=true`，明文 `IDH_LIVE_0003_订单金额=121.00元`；`/api/dumps` 4 个 dex-auto。**verify_all 26/26**。
- 2026-07-10 (可用性闭环轮·参考 iOS)：把"怎么打开观测控制台"按产品做闭环，参考 `.ref/ios-decrypt-helper`
  （其 `http_server.m` getifaddrs 取局域网 IP、fail-loud 明示"仅本地可访问"、悬浮窗 URL 点击复制）。
  ① **idhd 探测宿主机局域网 IP**（`os.networkInterfaces`，过滤 vEthernet/WSL/docker 等虚拟网卡，优先 192.168./10./172.16-31.），
  `/health` 增 `web:{port,local,lan[]}`，启动横幅打印 local/LAN（无 LAN 则 fail-loud）。实测 `http://192.168.100.11:8760`。
  ② **Web 顶栏显示访问地址**（LAN 优先，点击复制）。
  ③ **`dev_up.sh` 增 `adb reverse tcp:8760`**——手机浏览器与电脑用同一个 `127.0.0.1:8760`（经隧道）。
  ④ **sandbox App 主界面重做**：显示可复制的局域网地址 + 本机地址 + "在手机浏览器打开"按钮 + **活体在线指示**
  （轮询 idhd `/health`：绿=控制台在线并显示 agents 数，红=提示去电脑 `dev_up.sh`）。
  ⑤ **Web 控制台加 Debug 面板**：monkeypatch fetch 统一记录每个 REST/MCP 请求 + WS 事件（方法/状态/耗时）。
  闭环硬信号：设备侧 App 经反向隧道读到 `health: ok=true agents=2 lan='http://192.168.100.11:8760'`。**verify_all 仍 26/26。**
- 2026-07-10 (评审硬化轮)：应大佬评审，修 agent 侧 3 处正确性/隐蔽性缺陷并各自加验证——
  ① **`got_replace` hook 后恢复原页保护 + 写屏障**：RELRO(r--) 槽改写后 `__atomic_thread_fence` 发布再 `mprotect` 回 r--，不再残留 rw-（削弱 RELRO / 完整性自检诱饵）。selftest 实测 `origPerms=r--p slotPerms=r--p protRestored=true`，验证脚本纳入通过条件。
  ② **`resolve_sym` 用 DT_HASH(nchain)/DT_GNU_HASH 求 dynsym 数**，节区相邻反推降为兜底——不再依赖 `.dynstr` 紧邻 `.dynsym` 的非标准布局。
  ③ **`got_replace` 泛化为跨全部 caller 模块**（每模块仍只改第一个真实 RELRO 槽，避免 trampoline 死锁），单 caller 场景行为不变。**verify_all 仍 26/26**，1 次提交。
- 2026-07-10 (loop#18)：**QBDI 指令级动态 trace 完成——项目收官**。release 直链绕过 API 封锁拉到 v0.12.1 arm64 预编译；agent dlopen libQBDI.so，trace idh_trace_target 得 retval=30 + 64 条指令。**verify_all 26/26，v0.2–v1.0 全部完成。循环停止（删 cron）。** 2 次提交。
- 2026-07-10 (loop#17)：v1.0 会话录制/回放（事件持久化到 idhd-data/events.jsonl，重启 idhd 后回放验证）+ Web Events tab。suite 25/25，3 次提交。**功能完成，仅剩 QBDI(Blocked)；无实质自动化待办。**
- 2026-07-10 (loop#16)：v1.0 打磨——MCP 补齐到 25 tools + 诊断导出(/api/export/report, 仅元数据) + 生成 docs（architecture/threat-model/mcp-tools）。suite 24/24，3 次提交。除 QBDI(Blocked) 外功能全部完成并验证。
- 2026-07-10 (loop#15)：v1.0 函数级 trace 第一公民（通用 trace_run，任意原生符号，args+tid+ts+指针→字符串预览，access("/system/xbin/su")）。suite 23/23，4 次提交。**QBDI 指令级 trace 记为 Blocked**（网络受限拉不到预编译 + 重集成风险）；剩 v1.0 打磨项（导出/回放/文档/MCP 补齐）。
- 2026-07-10 (loop#14)：v0.9 完成——Method Body Recovery(L.7 被动，提取方法 code_item)。v1.0——**Web 控制台**（多面板，调全套 API）。suite 22/22，4 次提交。**功能核心全部完成，仅剩 QBDI 指令级 trace**（高风险，最后做）。
- 2026-07-10 (loop#13)：v0.9 收尾——direct syscall 扫描(E.9，svc #0 热点)。v1.0 大件——**MCP Server（19 tools，JSON-RPC，AI 可编程操控）**。suite 20/20，3 次提交。剩 Web UI + Method Body Recovery + QBDI。
- 2026-07-10 (loop#12)：v0.8 收尾——dex invoke-xref（指令宽度表，21820 方法 0% desync，Cipher.doFinal←JavaCrypto.run）。v0.9 起步——native crypto 常量扫描(H.4：AES S-box/Base64/SHA/MD5/TEA)。suite 18/18，2 次提交。
- 2026-07-10 (loop#11)：v0.8 核心完成——原生反汇编(llvm-objdump)+ 原生二进制分析(llvm-readelf: exports/imports/NEEDED/strings)。NDK 自带工具，无额外依赖。suite 16/16，2 次提交。invoke-xref + Web UI 待做。
- 2026-07-10 (loop#10)：v0.7 完成——网络↔crypto 关联（取证闭环：明文 IDH_CORRELATE_v1 关联到承载其密文的 TLS 请求，同线程 Δ~33ms）。v0.8 起步——dex 搜索索引(string/class/method)。suite 14/14，2 次提交。
- 2026-07-10 (loop#9)：v0.7 网络 TLS 明文捕获完成——GOT-hook Conscrypt SSL_write/SSL_read，抓到请求(X-Idh-Marker)+响应明文，绕过 TLS。自建本地 HTTPS 测试栈(selfsigned v5 async cert 坑)。**修复 build_agent 吞编译错误导致跑旧 .so 的严重隐患**。suite 12/12，1 次提交。关联(network↔crypto)待做。
- 2026-07-10 (loop#8)：v0.6 完成——Runtime Object Inspector（反射读活体对象字段 + 无参方法调用）。经静态字段到达对象，读到 token/count/note，getToken() 调用成功。完整 Java.choose 堆枚举推迟（需 JVMTI/ART 堆遍历）。suite 11/11，2 次提交。
- 2026-07-10 (loop#7)：v0.5 完成——V 反分析行为观测（GOT-hook 目标原生 ptrace/access/prop 检测，抓到防御地图 + 中和 TRACEME）+ S 抗干扰诊断（compat_probe）。sandbox 加 libidhdetect.so。suite 10/10，3 次提交。
- 2026-07-10 (loop#6)：**v0.4 完成——#1 卖点明文边界 crypto 捕获验证通过**。原生 EVP GOT hook 在 libjavacrypto(Conscrypt) 抓到 AES 明文 "IDH_CRYPTO_PLAINTEXT_v1"（加密前）。含 resolve_sym 内存 dynsym 解析、crypto_probe 定位、JNI 反射触发。suite 9/9。2 次提交。
- 2026-07-10 (loop#5)：v0.4 动态通道地基——原生 GOT/PLT hook 引擎(E.8.1)完成并真机验证（hook agent 自身 close，intercept+trampoline 不崩）。深挖两个 bug：RELRO 槽定位、单槽 hook（多槽 trampoline 死锁）。suite 8/8，1 次提交。下一步用引擎 hook EVP 抓明文。
- 2026-07-10 (loop#4)：v0.4 静态 crypto 通道——DEX 解析器(dex.ts) + crypto 静态扫描，host 验证（probe dex 解析 + 多 dex 命中 Cipher/Mac/AES/HmacSHA256）。sandbox 加 JavaCrypto。动态 hook 通道有意推迟到专门回合（改走更安全的原生 EVP GOT hook，计划已记录）。suite 7/7。1 次提交。
- 2026-07-10 (loop#3)：v0.3 ART 结构级 dex 捕获完成——JNI 反射基础 + ClassLoader cookie→art::DexFile*→begin_ 枚举（untag tagged pointer）+ 结构级 dump 对已知 InMemoryDex 字节级 sha256 校验。现场 root-cause 两个 bug（tagged pointer pread EFAULT、响应缓冲截断丢 newline）。2 次提交，suite 6/6。
- 2026-07-10 (loop#2)：v0.2 完成——so 重组（SoFixer-lite，重建 libidh_agent.so 有效）+ dex header 修复（真实 5MB dex 字节级还原）+ 主回归 verify_all.sh 5/5。3 次提交。
- 2026-07-10 (loop#1)：v0.2 Dump Engine 核心完成——命令通道 + maps/read/scan_magic/search/dump+dedup，全部真机验证（dump 对 mock dex 字节级 sha256 校验）。3 次提交。
- 2026-07-10：需求定稿、通用化、注入方案敲定（Zygisk root 版 + gadget/重打包 非 root 版）、加入"反分析行为观测(V)"、基建搭建。v0.1 端到端验证。
