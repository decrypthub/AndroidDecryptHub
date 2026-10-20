# 已退役：模块 X（手机自动化）与 Xposed 后端

> 非权威历史快照。产品边界以 `REQUIREMENTS.md` / `FEATURE_STATUS.md` / `CLAUDE.md` 为准。
> 从 `docs/PROGRESS.md` 抽出，避免接手 Agent 把退役能力当成待办。

## 模块 X（Android UI 自动化）

- **决议**：退役。AI 与手机交互用 `adb`，不经 Manager Accessibility / `phone_*` MCP。
- **已删**：Manager AccessibilityService / 通知监听、Device Daemon 输入/电源/音量/剪贴板桥、Host `automation.ts`、`phone_*` MCP、相关 Web 入口与验收脚本。
- **保留**：注入 scope、模块状态、目标进程启停、Host HTTP/WS/MCP 分析面。

## Xposed 后端（2026-10-11）

- **决议**：不做自带 Xposed 加载器；用户若需要可自装 LSPosed。整段删除，不留实验后端表述。
- **已删**：`injector/xposed/`、相关 build/install/verify 脚本、Device/Manager 的 Xposed 控制面与 AIDL、`/api/backends` 的 xposed 键、agent 注释里的 Xposed 加载路径。
- **保留**：Zygisk（官方注入）、Frida Gadget / eCapture（实验脚本，非发布物）、LSPlant（Java hook 引擎）。

更细的删除清单与门禁数字变化见 git 历史中 `PROGRESS.md` 的 2026-10-11 / 2026-09-23 条目。
