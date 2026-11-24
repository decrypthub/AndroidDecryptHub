// First path segment is an Android package when it looks like one and is not a reserved route.
// Host stays one HTTP server; `/com.example.app` pins the Web UI / MCP to that app's session.

const RESERVED = new Set([
  'api', 'mcp', 'health', 'ws', 'index.html', 'wechat-follow.png', 'favicon.ico',
  'raven.svg', 'raven.png',
]);

export function packageFromPath(pathname: string): string | null {
  const seg = decodeURIComponent((pathname.replace(/^\//, '').split('/')[0] || ''));
  if (!seg || RESERVED.has(seg) || !seg.includes('.')) return null;
  if (!/^[A-Za-z][\w]*(\.[\w]+)+$/.test(seg)) return null;
  return seg;
}
