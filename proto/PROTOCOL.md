# IDH Agent ↔ idhd 协议 v0

传输：TCP，换行分隔 JSON（NDJSON）。设备侧 agent 经 `adb reverse tcp:8761 tcp:8761` 连 host `127.0.0.1:8761`。
后续大 payload（dex/so/region）改走独立二进制通道；v0 只走控制/事件 JSON。

## 端口

- idhd HTTP + WebSocket：`8760`
- idhd Agent TCP：`8761`

## agent → idhd

```jsonc
// 注册（连接后第一条）
{"t":"hello","agentVer":"0.1.0","pid":1234,"uid":10234,
 "package":"com.idh.sandbox","process":"com.idh.sandbox",
 "abi":"arm64-v8a","android":"16","sdk":36,"entry":"jni_onload|start"}

// maps 快照
{"t":"maps","count":812,"regions":[
  {"start":"7f...","end":"7f...","perms":"r-xp","offset":"0","dev":"fd:00","inode":123,"path":"/system/lib64/libc.so"}
]}

// 心跳
{"t":"ping","ts":170...}
```

## idhd → agent

```jsonc
{"t":"ack","sessionId":"s_ab12"}   // 收到 hello 后回
{"t":"pong"}
// v0.2+ 追加命令：dump/read/hook...
```

## 会话身份

- idhd 为每个连接分配 `sessionId`；同 pid 重连视为同一逻辑目标，保留历史。
- v0.1 内存态；v0.2 起持久化到 SQLite。
