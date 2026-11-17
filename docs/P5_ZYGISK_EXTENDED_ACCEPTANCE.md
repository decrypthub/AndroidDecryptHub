# P5 正式 Zygisk 扩展验收（2026-11-17）

最终 **15 PASS / 0 FAIL**，`cleanupVerified=true`、`originalHostAndFilesUnchanged=true`。
使用独立 `feat/adh-completion-20261117`，Agent 源码基准为0ad72ef，包含GOT卸载所有权修复。
测试夹具和脚本为本次提交。设备仍为获准可重启的aa165071、PGP110 / API35 / arm64-v8a /
KernelSU / Zygisk Next1.5.2，SELinux enforcing。

正式默认命名空间的部署/升级尚未进行；本次临时模块使用同一Zygisk main.cpp、真实框架回调、
companion、Root broker、缓存校验与Agent消费路径，状态目录/broker/Host端口独立，作用域仅测试包。
加载和卸载各重启一次；默认生产目录六个文件SHA及原reverse映射前后一致。
本轮开始及结束时原8088 Host均未监听，没有为满足夹具前提而启动或重启原服务。

## 正式捕获链的八项实测

每个新进程只启用一个捕获族，七族代表性探针仍全部运行；最后再全部禁用。
cache经真实companion交付，Agent在post-specialize、start之前执行capture_start，
探针在Application.onCreate内发起，不由App加载Agent或调用early export，不做启用前warmup。
此ROM的libjavacrypto/libssl/libjavacore已由Zygote预载；未声明未加载模块也能提前Hook。

| 启用族 | 代表性输入与实际事件 | 本族标记命中 |
| --- | --- | --- |
| digest | SHA-256 / EVP_DigestUpdate | 1 |
| hmac | HmacSHA256 / HMAC_Update或EVP_DigestSignUpdate | 1 |
| symmetric | AES-CBC / EVP_CipherUpdate | 1 |
| asymmetric | SHA256withECDSA / 签名原文或ECDSA_sign_digest的已计算摘要 | 1 |
| tls | 测试包→私有Root loopback TLS / SSL_write中的唯一标记 | 1 |
| aead | AES-GCM / AEAD原文 | 2 |
| system | android.system.Os.access / access唯一路径 | 1 |
| 全部禁用 | 七种探针仍全部成功 | 0，整个会话捕获数也为0 |

每项还验证：启用族实际安装计数>0，其他族未布防；共享DigestSign符号仅在HMAC/签名需要时布防；
其他族唯一标记命中为0。命中必须属于本次session，在本次Application探针起止nanoTime窗口内，
并匹配实际执行TID。TLS在Application创建并等待的自身工作线程运行，其TID单独记录；
其他显式探针在主线程。所有会话窗口完整读取，dropped/jdropped/backlog均0，complete=true。
这里的“0”针对禁用族的指定探针标记；不声称启用族不会捕获其他初始化流量。
全部禁用时安装confirmed=0、回执为partial-or-failed，不把零安装包装成applied。

## 其余七项实测

- 原正式链六项重跑：投递/应用/首次GOT调用窗口命中；真实TTL到期；显式缓存撤销；
  卸载重装产生实际UID变化；仅临时模块Agent文件字节/SHA变化；Root broker不可用。
  所有拒绝都经真实companion，新进程earlyPlan=null、native Hook数0；绑定反例前有成功正例。
- 新增真实Wi-Fi LAN授权撤销：USB配对后，经实际TLS连接staging，缓存sourceGrant匹配该grant，
  先证明正式Zygisk命中；USB撤销grant后，已有进程同一GOT的slotOwned仍true，未自动卸载或重装；
  再冷启测试包，真实companion拒绝旧缓存，earlyPlan=null、无Hook。

LAN撤销验证的是未来缓存投递，不承诺撤销会回滚已经运行的进程。
GOT正例还验证最新Agent的slotOwned=true及当前slot=replacement，不能只凭历史hits。
GOT卸载冲突RPC仍未由本轮触发；其底层恢复函数8/8实测保留于[NATIVE_GOT_CLOSEOUT.md](NATIVE_GOT_CLOSEOUT.md)。

## 失败历史、清理与回归

首轮expanded-01前三项通过，捕获项因测试Application在主线程进行网络请求，触发
NetworkOnMainThreadException而失败；读取自身崩溃记录确认，未归因为Agent捕获问题。
修复为测试App自己的线程，未修改系统或业务App线程策略。首轮cleanupVerified=false还来自
夹具把被signal终止的Host之exitCode=null误判为未退出；修复为同时检查exitCode/signalCode。
模块/测试包已卸载，端口释放及原文件一致的事实独立核对，未倒改首轮结果。

清理改为各步骤分别记录失败并继续其他独立步骤，防止卸载包失败跳过自身模块清理；
nonce所有权、原Host无在线会话与原进程身份检查仍约束模块删除/重启，不靠忽略异常变绿。
原Host可以不存在；若存在则必须可查询、无在线会话，且重启前再次核对身份。

最终expanded-02报告和逐族窗口证据保留在聚合工作区私有
`.tmp/adh-p5-zygisk-expanded-02/`；失败报告保留在expanded-01，APK/so/捕获均不提交。
回归：默认与隔离Agent构建、opt-in APK构建、Host类型检查、Host561/561（0 skip，显式CLI源码路径）、
入口拒绝门禁通过。此前Android JVM73/73仍为相同生产Kotlin代码的实测，本轮未重跑JVM套件。

仍未验证：默认模块/Manager/生产RootDaemon部署与升级、其他ROM/Root/架构、真实业务App、
全部算法/模块组合、热升级、init_array之前的保证。Java/inline early仍明确unsupported。
此前libandroid_runtime/getpid被后续覆盖的具体成因也未由本轮定位。
