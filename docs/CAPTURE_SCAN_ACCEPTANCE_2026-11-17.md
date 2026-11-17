# 全模块捕获扫描修复与隔离实测（2026-11-17）

后续已解决[发布准备收尾](RELEASE_PREPARATION_CLOSEOUT_2026-11-17.md)中全模块扫描的超时。
仍不是正式Release验收通过；默认模块未升级，新Agent未重跑正式Zygisk15项。

## 原因与改动

修复前在独立Host18088/18761和沙盒进程14203再次得到COMMAND_TIMEOUT。
运行中debuggerd快照的Agent Build ID为`c806ca95ae137244f3823d3fa734cd592f40005c`，
命令线程栈经配套debug产物符号化为`sscanf → module_base_of:170 → adh_got_replace:268
→ adh_cmd_capture_start:980 → command_loop:843`。逐文件映射重新读取整张maps，再按各符号重复，
导致ART大量映射下的重复扫描。没有用提高命令超时作为修复。

- 使用当前映射地址的linker身份取得image base，不按basename反复扫描maps。按image base区分
  同一APK路径中的不同image；非linker映射仍拒绝，不恢复任意数据扫描。
- RELRO映射可能始于PT_LOAD前的填充区，`dladdr(start)`无结果时，仅复用同一路径已验证的base；
  读写仍限于该image的真实重定位槽，不能据此扫描任意数据。
- 按名称替换的空模块名恢复“全部模块”语义；严格的`adh_got_unique_slot`仍要求明确模块，
  不扩大其匹配范围。
- 值匹配加入DT_ANDROID_RELA/APS2的GLOB_DAT/JUMP_SLOT槽枚举；SLEB/组大小/表截断/容量超限
  拒绝，不用值碰撞回退。每image最多262144个槽，packed迭代上限为该数的16倍。
- v26不再依赖hello自动布防，而是显式发出capture_start。v20同时明确crypto和file调用模块，
  保留部分安装明细和真实文件读写断言。

## 实测范围

设备为获准的aa165071，PGP110/API35/arm64-v8a。仅更新com.adh.sandbox测试APK，
未重启手机、未启停得物、未修改默认模块/Manager。以下为沙盒JNI自加载路径。

Agent Build ID：`f6e82e54a5067ac18adb4069fff0d2ae7f79ddde`。
SHA256：`5c1871a0d50a524d723ce0e578824291d9b9413d8f3171bb9fa35cff3c879a0b`。
源文件固化于本报告所在提交；正式发布前仍须从该提交重建完整bundle。

| 验收 | 实际结果 |
| --- | --- |
| 原生生产GOT夹具 | 11/11，自己的UUID执行目录清理通过；原八项所有权/RELRO、非ELF文件尾页、全模块getpid安装/调用/值恢复、实际APS2 GLOB_DAT值安装/恢复 |
| v01新Agent装载 | 40/40 maps采样匹配，进程19265 |
| v04 crypto全模块 | 19/19，测试明文命中；首次修复后完整脚本约3127ms；此脚本接受Java报告通道，不能单独证明原生EVP命中 |
| v26签名/AEAD | 显式libjavacrypto.so；evp=1、aead.seal=1；签名2、AEAD3，两个预期标记命中；AEAD允许产品Java去重后的记录，不外推为每种原生算法独立命中 |
| v07 TLS | 19/19；真实SSL_write请求标记与SSL_read响应标记都命中 |
| v20文件 | 22/26，open/readChk/writeChk已安装；实际文件路径、写入和读回标记都命中。openat/read/write/syscall不导入仍保持0、partial，不改成完全安装 |
| Host | 567/567，0 skip，类型检查通过 |
| 默认环境保护 | scope、endpoint、Agent、Zygisk、daemon.apk、module.prop六个SHA仍等于原基线；只启动自己的隔离Host/TLS进程 |

私有证据在聚合工作区`.tmp/adh-capture-timeout-20261117-01/`：`capture-before.txt`、
`during-capture.txt`、`crypto-final.txt`、`native-crypto-final.txt`、`tls-final.txt`、
`file-explicit.txt`、`host-tests.txt`以及原生夹具最终报告`got-packed-01/report.json`和
`native-final-c676141076/report.json`，两者均11/11、`cleanupVerified:true`。
中间失败报告保留，不作为通过证据。

原生夹具的前几次失败分别暴露了RELRO遗漏，或在发现APS2缺口时尚未完成值恢复。
早期capture超时的操作保持unknown，未自动resolve或重放。补充多项冷启动验收的组合命令曾被
自动审批以`blocked by policy`拒绝，未执行；改为在已确认运行的同一测试进程中逐项执行
明确的capture意图。真实Zygisk路径、其他ROM和所有权丢失后的卸载RPC仍按剩余清单未验证。
