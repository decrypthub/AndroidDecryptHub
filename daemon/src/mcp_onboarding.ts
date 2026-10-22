// MCP onboarding — the text behind "how do I connect an AI client?".
//
// The product's MCP entry point is the published `adh` CLI (PyPI `android-decrypt-hub`, source
// `decrypthub/adh-cli`), not the HTTP endpoint: `adh connect <host>` saves this daemon, `adh mcp`
// turns `POST /mcp` into stdio, which is what the clients speak. Its README says plainly not to put
// the HTTP `/mcp` into a client.
//
// The panel is deliberately three blocks long — install / connect / config — matching the iOS
// counterpart's panel. An earlier version listed five per-client commands and an endpoint section;
// the operator does not need to be taught how a client is configured, they need the JSON.
//
// Values that depend on the live daemon (the address, the pinned form) come from the request's own
// Host, so a LAN browser and a loopback shell each get an address that works.

export const MCP_SERVER_NAME = 'adh';
export const CLI_NAME = 'adh';
export const CLI_PYPI_PACKAGE = 'android-decrypt-hub';

export interface McpOnboarding {
  /** Footer line. Deliberately one sentence: MCP has no auth. */
  note: string;
  install: string;
  connect: string;
  /** The `mcpServers` block for the client config, pretty-printed like the iOS panel's. */
  config: string;
}

/** `adh connect` takes `host[:port][/package]` (scheme optional); `adh-cli` turns the path into
 *  `/<package>/mcp`, so pinning is a property of the saved connection, not of the command. */
export function adhConnectTarget(base: string, pkg?: string): string {
  const hostPort = base.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  return pkg ? `${hostPort}/${pkg}` : hostPort;
}

/** The client config. `args` stays on one line on purpose — this is the block people paste. */
export function adhClientConfig(): string {
  return `{
  "mcpServers": {
    "${MCP_SERVER_NAME}": {
      "command": "${CLI_NAME}",
      "args": ["mcp"]
    }
  }
}`;
}

export function mcpOnboarding(base: string, opts: { package?: string } = {}): McpOnboarding {
  const pkg = opts.package?.trim() || undefined;
  return {
    note: '仅限可信网络',
    install: `pip install ${CLI_PYPI_PACKAGE}`,
    connect: `${CLI_NAME} connect ${adhConnectTarget(base, pkg)}`,
    config: adhClientConfig(),
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
