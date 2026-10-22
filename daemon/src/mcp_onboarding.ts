// MCP onboarding — the text behind "how do I connect an AI client?".
//
// The product's MCP entry point is the published `adh` CLI (PyPI `android-decrypt-hub`, source
// `decrypthub/adh-cli`), not the HTTP endpoint. `adh connect <host>` saves this daemon; `adh mcp`
// turns `POST /mcp` into stdio, which is what Cursor / Claude Desktop / Claude Code actually speak.
// Its README is explicit: do not put the HTTP `/mcp` into a client directly.
//
// This panel used to show the endpoint, the package-pinned endpoint and a `tools/list` JSON-RPC
// body — i.e. exactly what that README warns about — and a first version of this module replaced it
// with HTTP `--transport` commands, which is still the wrong transport. So the guide is now:
//
//   1. install the CLI, 2. `adh connect <this daemon>`, 3. register `adh mcp` as a stdio server.
//
// One implementation lives here; the Web panel renders it. Anything daemon-specific (the address,
// the pinned form) is derived from the request's own Host, so a LAN browser and a loopback shell
// each get an address that actually works. `adh-cli` 0.1.2 is the released CLI this text targets.

export const MCP_SERVER_NAME = 'adh';
export const CLI_NAME = 'adh';
export const CLI_PYPI_PACKAGE = 'android-decrypt-hub';

export type McpClientId = 'claude' | 'codex' | 'vscode' | 'cursor' | 'json';

export interface McpClientSpec {
  id: McpClientId;
  /** Human label for the Web chips. */
  label: string;
  /** The command is a multi-line document (currently only the generic JSON block). */
  multiline: boolean;
  /** One line shown under the command; state the side effect, not marketing. */
  note: string;
}

export interface McpClientCommand extends McpClientSpec {
  command: string;
}

export interface McpOnboarding {
  note: string;
  /** Install line for the CLI (the `pipx` alternative lives in the panel's hint). */
  install: string;
  /** `adh connect <host[:port][/package]>` for the address this payload was built for. */
  connect: string;
  endpoint: string;
  /** `/mcp` of `<base>/<package>/mcp`, or null when the payload is already pinned. */
  pinnedEndpoint: string | null;
  /** The CLI form of pinning, or null when the payload is already pinned. */
  connectPinned: string | null;
  tools: number;
  verify: string;
  clients: McpClientCommand[];
}

export const MCP_CLIENTS: McpClientSpec[] = [
  {
    id: 'claude', label: 'Claude Code', multiline: false,
    note: '写入用户级配置（所有项目可用）；-- 之后是 stdio 命令，由 adh 转发到 Host',
  },
  {
    id: 'codex', label: 'Codex', multiline: false,
    note: 'Codex CLI 的 stdio 注册；-- 之后是命令，不需要 --url',
  },
  {
    id: 'vscode', label: 'VS Code', multiline: false,
    note: '写入 VS Code 的用户级 MCP 配置；在装了 code 命令的终端里运行一次',
  },
  {
    id: 'cursor', label: 'Cursor', multiline: false,
    note: '需要 Cursor 的 shell 命令（命令面板 → Install \'cursor\' command）；也可直接编辑 mcp.json',
  },
  {
    id: 'json', label: 'JSON', multiline: true,
    note: '通用 mcpServers 片段：command 是 adh，args 是 ["mcp"]（cmd.exe 用这个）',
  },
];

/** `base` is `http(s)://host[:port]` with no trailing slash. A pinned package lives under the same
 *  server as the Web UI (`/<package>/mcp`), which is what makes the endpoint app-scoped. */
export function mcpEndpoint(base: string, pkg?: string): string {
  const root = base.replace(/\/+$/, '');
  return pkg ? `${root}/${pkg}/mcp` : `${root}/mcp`;
}

/** `adh connect` takes `host[:port][/package]` (scheme optional); `adh-cli` turns the path into
 *  `/<package>/mcp`, so pinning is a property of the saved connection, not of the command. */
export function adhConnectTarget(base: string, pkg?: string): string {
  const hostPort = base.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  return pkg ? `${hostPort}/${pkg}` : hostPort;
}

/** The stdio server definition every JSON-config client uses. `adh mcp` reads the saved address and
 *  streams JSON-RPC on stdout — no HTTP URL, no per-client transport differences. */
function serverJson(): string {
  return JSON.stringify({ name: MCP_SERVER_NAME, command: CLI_NAME, args: ['mcp'] });
}

export function mcpClientCommand(spec: McpClientSpec): string {
  switch (spec.id) {
    case 'claude':
      // --scope user: a device tool is useful from every project, not only the cwd one.
      return `claude mcp add --scope user ${MCP_SERVER_NAME} -- ${CLI_NAME} mcp`;
    case 'codex':
      return `codex mcp add ${MCP_SERVER_NAME} -- ${CLI_NAME} mcp`;
    case 'vscode':
      return `code --add-mcp '${serverJson()}'`;
    case 'cursor':
      return `cursor --add-mcp '${serverJson()}'`;
    case 'json':
      // Pretty-printed but compact on purpose: the panel shows this block inline, and a
      // nine-line output pushed the rest of the guide below the fold for no extra meaning.
      return `{\n  "mcpServers": {\n    "${MCP_SERVER_NAME}": { "command": "${CLI_NAME}", "args": ["mcp"] }\n  }\n}`;
  }
}

export function mcpOnboarding(base: string, opts: { package?: string; tools?: number } = {}): McpOnboarding {
  const pkg = opts.package?.trim() || undefined;
  const root = base.replace(/\/+$/, '');
  return {
    note: 'MCP 没有鉴权，只连可信网络。客户端里只配 `adh mcp` 这条 stdio 命令——不要把 HTTP /mcp 直接填进客户端。',
    install: `python -m pip install -U ${CLI_PYPI_PACKAGE}`,
    connect: `${CLI_NAME} connect ${adhConnectTarget(root, pkg)}`,
    endpoint: mcpEndpoint(root, pkg),
    // A pinned payload already IS the pinned form; printing "<package>" again would be noise.
    pinnedEndpoint: pkg ? null : `${root}/<package>/mcp`,
    connectPinned: pkg ? null : `${CLI_NAME} connect ${adhConnectTarget(root)}/<package>`,
    tools: opts.tools ?? 0,
    verify: '`adh devices` 显示 online 后，让客户端调用 capabilities：能看到 agent 的能力面就说明通了。',
    clients: MCP_CLIENTS.map((spec) => ({ ...spec, command: mcpClientCommand(spec) })),
  };
}

/** Package names only — the value goes into a URL path and is echoed back to the operator. */
export function isValidPackage(pkg: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_.]*$/.test(pkg) && !pkg.includes('..');
}

/**
 * The base URL a client on THIS network can reach. The request's Host header is the truth for the
 * browser (that is the address that just worked, LAN or loopback); without it we fall back to the
 * daemon's own view. Returning null for anything that is not a bare host[:port] keeps a spoofed Host
 * from turning the guide into an arbitrary-URL printer.
 */
export function baseFromHost(host?: string | null): string | null {
  const value = String(host ?? '').trim();
  if (!value) return null;
  const split = /^([^:]+|\[[0-9A-Fa-f:]+\])(?::([0-9]{1,5}))?$/.exec(value);
  if (!split) return null;
  const [, hostname, port] = split;
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?$/.test(hostname) && !/^\[[0-9A-Fa-f:]+\]$/.test(hostname)) return null;
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return null;
  return `http://${value}`;
}
