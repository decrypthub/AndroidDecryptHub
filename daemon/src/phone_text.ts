// Plain-text rendering of a phone observation.
//
// The JSON tree is verbose (each node repeats className/package/flags), which burns the AI's
// context on every observe. This renders the same tree as terse lines an AI can read directly,
// while refs stay usable for phone_act.

export interface ScreenTextOptions { maxNodes?: number; maxTextLength?: number }

const DEFAULT_MAX_NODES = 60;
const DEFAULT_MAX_TEXT = 60;

function clip(value: unknown, max: number): string {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text.length > max ? text.slice(0, max - 1) + '…' : text;
}

export function renderScreenText(result: any, options: ScreenTextOptions = {}): string {
  const maxNodes = Math.max(1, Math.min(400, Number(options.maxNodes ?? DEFAULT_MAX_NODES)));
  const maxText = Math.max(8, Math.min(200, Number(options.maxTextLength ?? DEFAULT_MAX_TEXT)));
  const screen = result?.screen ?? {};
  const nodes: any[] = Array.isArray(result?.nodes) ? result.nodes : [];
  const lines: string[] = [];

  const header = [
    `screen: ${result?.activePackage ?? '?'}`,
    screen.width && screen.height ? `${screen.width}x${screen.height}` : null,
    screen.rotation != null ? `rot=${screen.rotation}` : null,
    `snapshot=${result?.snapshotId ?? '-'}`,
    `nodes=${nodes.length}${result?.truncated ? '+' : ''}`,
    result?.mode ? `mode=${result.mode}` : null,
    result?.cursor ? `cursor=${result.cursor.eventSeq}/${result.cursor.captureId}` : null,
  ].filter(Boolean);
  lines.push(header.join('  '));

  if (result?.screenshot?.mimeType) lines.push(`screenshot: ${result.screenshot.mimeType} ${result.screenshot.bytes ?? '?'}B`);
  if (Array.isArray(result?.warnings) && result.warnings.length) lines.push(`warnings: ${result.warnings.join('; ')}`);
  if (!nodes.length) lines.push('(no nodes)');

  for (const node of nodes.slice(0, maxNodes)) {
    const bits: string[] = [`[${node?.ref ?? '?'}]`, clip(node?.className ?? '', 28).split('.').pop() || 'Node'];
    const label = node?.text ?? node?.hint;
    if (label) bits.push(JSON.stringify(clip(label, maxText)));
    if (node?.contentDescription && node.contentDescription !== label) bits.push(`desc=${JSON.stringify(clip(node.contentDescription, maxText))}`);
    const id = String(node?.resourceId ?? '');
    if (id) bits.push(`id=${clip(id.split('/').pop(), 32)}`);
    if (Array.isArray(node?.bounds) && node.bounds.length === 4) bits.push(`@${node.bounds.join(',')}`);
    // Only non-default state is worth printing: most actionable nodes are clickable/enabled,
    // and every action they support is already listed below.
    const flags = ['editable', 'scrollable', 'selected', 'checked'].filter((key) => node?.[key] === true);
    if (node?.enabled === false) flags.push('disabled');
    if (flags.length) bits.push(`(${flags.join(',')})`);
    const actions = Array.isArray(node?.actions) ? node.actions.filter((action: string) => action !== 'click') : [];
    if (actions.length) bits.push(`actions=${actions.join('/')}`);
    lines.push(bits.join(' '));
  }
  if (nodes.length > maxNodes) lines.push(`… ${nodes.length - maxNodes} more nodes (raise maxNodes to see them)`);
  return lines.join('\n');
}
