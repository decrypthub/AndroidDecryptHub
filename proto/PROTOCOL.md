# ADH Agent ↔ ADH Daemon 协议 v2（length-framed）

传输：TCP。设备侧 agent 经 `adb reverse tcp:8761 tcp:8761` 连 host `127.0.0.1:8761`。
**v2.0 (WS-D) 起：所有消息一律 length-framed**，取代 v0 的 NDJSON。控制/事件/命令/结果均为
`FRAME_JSON`（payload 为一个 JSON 对象）；二进制/批量帧类型保留给后续（WS-C 采集批、分片 dump）。

## 帧格式

```text
┌────────────┬────────┬───────────────────────┐
│ u32 len BE │ u8 type│  payload （len 字节）  │
└────────────┴────────┴───────────────────────┘
```

- `len`：**payload 字节数**（不含 5 字节头）。大端序（网络序）。
- `type`：帧类型。
- payload：`type` 决定其含义。

### 帧类型

| 值 | 名称 | payload | 方向 |
|----|------|---------|------|
| `0x01` | `FRAME_JSON` | 一个 UTF-8 JSON 对象（下方所有 `t` 消息） | 双向 |
| `0x02` | `FRAME_CAPTURE` | 采集批（WS-C，保留） | agent → Host ADH Daemon |

### 上限与 fail-loud（不胡乱兜底）

- agent 入站（命令）payload 上限 `FRAME_MAX_IN = 16 MiB`；超出 → **关连接并上报**，不尝试重同步一条已损坏的流。
- Host ADH Daemon 入站（响应）payload 上限 `FRAME_MAX = 64 MiB`；超出 → **destroy socket 并 log**。
- 未知 `type` → 跳过该帧并 log（不静默）。
- **取消** v0 的 8192 字节单行命令上限与"超长行丢弃"——命令/响应按 `len` 精确读取，任意大小完整送达。
- 大 payload（dump/read）当前走多帧分片（`read` 每帧 ≤ 1 MiB base64）；大 region dump 的
  memfd/ashmem 共享内存传输仍是后续工作。

## 端口

- adhd HTTP + WebSocket：`8088`（对外称 **ADH Daemon**；npm 包名 `adhd`；与 iOS `idh` 同端口）
- ADH Daemon Agent TCP：`8761`

## agent → Host ADH Daemon（均为 `FRAME_JSON`）

```jsonc
// 注册（连接后第一帧）
{"t":"hello","agentVer":"0.2.0","pid":1234,"uid":10234,
 "package":"com.adh.sandbox","process":"com.adh.sandbox",
 "abi":"arm64-v8a","android":"16","sdk":36,"entry":"jni_onload|start"}

// maps 快照
{"t":"maps","count":812,"regions":[
  {"start":"7f...","end":"7f...","perms":"r-xp","offset":"0","dev":"fd:00","inode":123,"path":"/system/lib64/libc.so"}
]}

// 心跳
{"t":"ping","ts":170...}

// 命令结果（对每个 Host ADH Daemon 下发的 cmd）
{"t":"cmdResult","id":"c_ab12","op":"read","ok":true, ...}
```

## Host ADH Daemon → agent（均为 `FRAME_JSON`）

```jsonc
{"t":"ack","sessionId":"s_ab12"}   // 收到 hello 后回
{"t":"pong"}                        // 回 ping
{"t":"cmd","id":"c_ab12","op":"maps", ...}   // 命令；op 决定其余字段
```

命令 `op` 一览见 `agent_main.c` 的 `command_loop` 分发表（maps/read/scan_magic/search/
crypto_*/capture_*/trigger/art_dexfiles/file_probe/load_so/qbdi_trace/object_*/
compat_probe/frame_echo/ping…）。**注意（2026-10-01）**：`*_hook_test` / `flow_watch` /
`detect_watch` / `trace_run` / `jni_probe` / `crypto_probe` / `inline_crypto_test` 这些
"一次性触发"op 已删除，协议里不再有它们。

### `frame_echo`（WS-D 协议自测，无目标知识）

Host ADH Daemon `GET /api/debug/frame_echo?session=&kb=N` → 下发一个带 `pad`(N KiB)+`tail` 哨兵的命令帧；
agent 回 `{recvBytes, tail, padLen}`。`tail` 置于 `pad` 之后（越过旧 8192 位），只有当入站
framing 完整送达整帧时 `tail` 才非空。验收：`tools/verify_v21_frame.sh`。

## 会话身份

- Host ADH Daemon 为每个连接分配 `sessionId`；同 pid 重连视为同一逻辑目标，保留历史。
- 事件持久化到 `adhd-data/events.jsonl`。
