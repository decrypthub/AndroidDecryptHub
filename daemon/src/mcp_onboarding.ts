// MCP onboarding — the text behind "how do I connect an AI client?".
//
// Before this module the Web modal showed three raw artifacts (the endpoint, a package-pinned
// endpoint, and a `tools/list` JSON-RPC body) and left the operator to translate them into a client
// config by hand. That is an API dump, not an install guide: the thing that actually has to happen is
// "run one command that registers this daemon with the client you use". The guide therefore starts
// from our own CLI (`adh mcp`), and the command lines it prints are built HERE — one implementation
// shared by the CLI (which renders them, see cli.ts `mcp`) and the Web modal (which shows them), so
// the page and the terminal cannot drift apart.
//
// Two properties are deliberate:
//   * every `command` is meant to be pasted as-is (the client's own CLI, not a config snippet), which
//     is why the JSON argument for `code`/`cursor` is single-quoted: that form works in PowerShell and
//     in bash/zsh (the screenshot-era modal sent people to hand-edit JSON instead);
//   * `bin` is the executable the CLI checks on PATH to say "you have this client" — it is metadata,
//     so detection stays on the side that runs the command (a daemon on another machine cannot know).
//
// The list is intentionally short: one entry per client we can name a real command for. `json` is the
// escape hatch for everything else (and for cmd.exe, where single quotes are not quoting).

export const MCP_SERVER_NAME = 'adh';

export type McpClientId = 'claude' | 'codex' | 'vscode' | 'cursor' | 'json';

export interface McpClientSpec {
  id: McpClientId;
  /** Human label for the Web chips. */
  label: string;
  /** Executable whose presence means "this client is installed". null = no CLI to register with. */
  bin: string | null;
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
  /** The command the guide starts from. */
  guide: string;
  endpoint: string;
  /** `/mcp` of `<base>/<package>/mcp`, or null when the payload is already pinned. */
  pinnedEndpoint: string | null;
  tools: number;
  verify: string;
  clients: McpClientCommand[];
}

export const MCP_CLIENTS: McpClientSpec[] = [
  {
    id: 'claude', label: 'Claude Code', bin: 'claude', multiline: false,
    note: '写入用户级配置（所有项目可用）；去掉 --scope user 则只对当前项目生效',
  },
  {
    id: 'codex', label: 'Codex', bin: 'codex', multiline: false,
    note: 'Codex CLI 内置注册，--url 指向 Streamable HTTP 端点',
  },
  {
    id: 'vscode', label: 'VS Code', bin: 'code', multiline: false,
    note: '写入 VS Code 的用户级 MCP 配置；在装了 code 命令的终端里运行一次',
  },
  {
    id: 'cursor', label: 'Cursor', bin: 'cursor', multiline: false,
    note: '需要 Cursor 的 shell 命令（命令面板 → Install \'cursor\' command）',
  },
  {
    id: 'json', label: 'JSON', bin: null, multiline: true,
    note: '通用 mcpServers 片段：手工粘进任意客户端的配置文件（cmd.exe 用这个）',
  },
];

/** `base` is `http(s)://host[:port]` with no trailing slash. A pinned package lives under the same
 *  server as the Web UI (`/<package>/mcp`), which is what makes the endpoint app-scoped. */
export function mcpEndpoint(base: string, pkg?: string): string {
  const root = base.replace(/\/+$/, '');
  return pkg ? `${root}/${pkg}/mcp` : `${root}/mcp`;
}

/** The one JSON object every HTTP-capable client understands for this server. */
function serverJson(url: string): string {
  return JSON.stringify({ name: MCP_SERVER_NAME, type: 'http', url });
}

export function mcpClientCommand(spec: McpClientSpec, url: string): string {
  switch (spec.id) {
    case 'claude':
      // --scope user: a device-tool server is useful from every project, not only the cwd one.
      return `claude mcp add --transport http --scope user ${MCP_SERVER_NAME} ${url}`;
    case 'codex':
      return `codex mcp add ${MCP_SERVER_NAME} --url ${url}`;
    case 'vscode':
      return `code --add-mcp '${serverJson(url)}'`;
    case 'cursor':
      return `cursor --add-mcp '${serverJson(url)}'`;
    case 'json':
      return JSON.stringify({ mcpServers: { [MCP_SERVER_NAME]: { type: 'http', url } } }, null, 2);
  }
}

export function mcpOnboarding(base: string, opts: { package?: string; tools?: number } = {}): McpOnboarding {
  const pkg = opts.package?.trim() || undefined;
  const endpoint = mcpEndpoint(base, pkg);
  const root = base.replace(/\/+$/, '');
  return {
    note: '仅限可信网络：MCP 没有鉴权，不要把 8088 暴露到公网。接入命令由 `adh mcp` 生成，与命令行同源。',
    guide: 'adh mcp',
    endpoint,
    // A pinned payload already IS the pinned endpoint; printing "<package>" again would be noise.
    pinnedEndpoint: pkg ? null : `${root}/<package>/mcp`,
    tools: opts.tools ?? 0,
    verify: '接好后让客户端调用 capabilities：能看到 agent 的能力面就说明通了。',
    clients: MCP_CLIENTS.map((spec) => ({ ...spec, command: mcpClientCommand(spec, endpoint) })),
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
