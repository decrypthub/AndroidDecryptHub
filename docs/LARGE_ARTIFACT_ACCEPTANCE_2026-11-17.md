# 大产物输入与持久结果验收（2026-11-17）

解决发布准备中9,604,000 B沙盒DEX被8 MiB JSON限制拒绝，以及剥离结果被任务层省略后
当作完整结果返回的两处缺陷。只使用独立worktree和自有Host18088/18761，未升级默认模块。

## 最终行为

- `http/request_body.ts`统一按入口分类：指定DEX/ELF分析请求、对应MCP工具、operations
  snapshot/submit及REST prepare/submit可接收最多64 MiB JSON；包括包固定MCP入口。
  普通配置/控制请求仍拒绝超过8 MiB的body。MCP/操作信封需要先读取才能分类，临时读取
  上限仍为64 MiB，分类后超限控制请求不会分派。不依赖Content-Length，chunked同样有界。
- 413不再被router/operations捕获后改成403/409。顶层错误响应使用生产共用的
  `http/response_error.ts`：不再保留超限数据，最多排空一秒，再回复413并关闭。
  测试证明未结束的上传也不会一直占住响应；直接销毁连接造成ECONNRESET的旧行为已修复。
- 持久结果文件上限由8 MiB改为64 MiB（包含HTTP envelope），保持在私有results目录，
  不塞进账本。进程重启后仍能通过HTTP/MCP完整读取，不只在原调用栈中临时保留。
- 超过结果上限，以及历史已经省略的结果，仍保留omitted/bytes/sha256；接口明确返回
  RESULT_OMITTED（HTTP422），不伪装成原工具成功数据。原任务执行状态保留；unknown仍是
  UNKNOWN_EXECUTION/504，不自动确认、不自动重放。丢失的旧输出不能靠本补丁恢复。
- 没有修改状态版本、权限、幂等、未知副作用隔离规则，也没有清空历史任务或捕获。

## 证据

Host类型检查和全套测试572/572、0 skip；随后扩展大信封测试覆盖MCP/REST持久submit，
对应5项定向测试全部通过。测试使用生产router/错误响应，覆盖大于8 MiB的真实JSON、
普通/包固定MCP、REST、prepare/submit、配置控制拒绝、64 MiB绝对上限、未结束上传，
以及9 MiB结果跨Operations重建后的内容哈希与旧omitted状态。

从本机沙盒APK提取的9,604,000 B DEX（纯测试产物）通过以下原有门禁：

| 路径 | 实际结果 |
| --- | --- |
| v02 dexrepair | 修复header/checksum/signature、存储与按SHA下载通过 |
| v04 dexparse | 解析与密码常量扫描通过 |
| v08 dexsearch | 类/方法/字符串命中通过 |
| v08 xref | 方法调用图通过，46954个方法体、desyncRate=0 |
| v09 methodcode | 测试方法体恢复通过 |
| v95 trycatch | 完整99 B code_item及tries逐字节一致；截断捕获仍422拒绝 |
| v96 map | map_list重定位/自检/截断及file_size负例通过 |
| v12 rebuild | 标准DEX重建与相应验证通过 |
| v13 recover | 剥离一个方法后从恢复镜像补回，原字节一致 |
| v29 dexindex | 持久索引、调用关系、反射和MCP路径通过 |

第一轮v95/v13在输入限制已修复后仍失败，才定位到原任务结果8 MiB省略；保留失败日志。
上述10项为针对性路径，并非完整发布门禁已经通过，也不证明超过64 MiB的内联输入受支持。
不重复已成功的真实设备捕获测试来证明Host JSON改动。

私有日志位于聚合工作区`.tmp/adh-capture-timeout-20261117-01/`：`dexrepair-large.txt`、
各`verify_v*.large.txt`、v95/v13的`*.full-result.txt`、`result-host-tests.txt`、
`result-typecheck.txt`。没有把DEX、捕获、私有操作结果或凭据提交入仓。

后续仍需完整发布门禁、默认升级/回滚、GOT所有权丢失卸载RPC、覆盖写入方、第二真实环境
与得物dhw纯算法；不能用本页替代那些验收。
