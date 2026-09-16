// Screen signature + settling logic for phone_wait's stability mode.
//
// An AI loop that acts on a freshly launched or freshly switched screen keeps reading half-rendered
// trees ("nav bar not there yet"). Waiting for a selector is not always possible — the AI wants
// "this screen has stopped changing" — so the wait loop samples a signature until it holds still.

import { createHash } from 'node:crypto';

export function screenSignature(tree: any): string {
  const nodes: any[] = Array.isArray(tree?.nodes) ? tree.nodes : [];
  const parts: string[] = [String(tree?.activePackage ?? ''), String(tree?.activity ?? ''), String(nodes.length)];
  for (const node of nodes) {
    const label = [node?.text, node?.hint, node?.contentDescription].map((value) => String(value ?? '')).join('\u0001');
    const bounds = Array.isArray(node?.bounds) ? node.bounds.join(',') : '';
    parts.push([String(node?.className ?? ''), label, bounds, String(node?.checked ?? ''), String(node?.selected ?? ''), String(node?.enabled ?? '')].join('|'));
  }
  return createHash('sha1').update(parts.join('\n')).digest('hex').slice(0, 16);
}

export interface SettleSample { signature: string; changedAt: number }

export function isSettled(sample: SettleSample, now: number, stableMs: number): boolean {
  return now - sample.changedAt >= stableMs;
}

export function noteSample(previous: SettleSample | null, signature: string, now: number): SettleSample {
  if (previous && previous.signature === signature) return previous;
  return { signature, changedAt: now };
}
