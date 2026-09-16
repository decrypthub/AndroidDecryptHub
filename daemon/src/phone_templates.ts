// Step-output templating for phone_task / phone_skill.
//
// A task step often needs something an earlier step discovered: the ref of the node just found,
// the snapshotId that ref belongs to, an index in a parsed result. Without templating the AI has
// to make separate MCP calls (and refs expire between them). Syntax:
//
//   {{stepId}}              -> that step's whole result
//   {{stepId.path.to.0}}    -> a value inside it (arrays use numeric keys)
//
// Only earlier steps that carry an id can be referenced. Missing steps and missing paths throw,
// so a typo surfaces as a failed step instead of a silently wrong action.

const FULL = /^\{\{\s*([A-Za-z0-9_.-]+?)\s*\}\}$/;
const EMBEDDED = /\{\{\s*([A-Za-z0-9_.-]+?)\s*\}\}/g;

export function readPath(root: any, path: string): { found: boolean; value?: any } {
  let current = root;
  for (const key of (path || '').split('.').filter(Boolean)) {
    if (current == null) return { found: false };
    if (Array.isArray(current)) {
      const index = Number(key);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return { found: false };
      current = current[index];
      continue;
    }
    if (typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, key)) return { found: false };
    current = current[key];
  }
  return { found: true, value: current };
}

function lookup(expr: string, outputs: Record<string, any>): any {
  const dot = expr.indexOf('.');
  const stepId = dot < 0 ? expr : expr.slice(0, dot);
  const path = dot < 0 ? '' : expr.slice(dot + 1);
  if (!(stepId in outputs)) {
    throw new Error(`template_unknown_step: '${stepId}' has no result yet — reference an earlier step by id`);
  }
  if (!path) return outputs[stepId];
  const { found, value } = readPath(outputs[stepId], path);
  if (!found) throw new Error(`template_path_missing: '${expr}' is not present in step '${stepId}'`);
  return value;
}

function stringify(value: any): string {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export function resolveTemplates(value: any, outputs: Record<string, any>): any {
  if (typeof value === 'string') {
    const full = FULL.exec(value);
    if (full) return lookup(full[1], outputs);          // whole-string form keeps the raw type
    return value.replace(EMBEDDED, (_match, expr) => stringify(lookup(expr, outputs)));
  }
  if (Array.isArray(value)) return value.map((item) => resolveTemplates(item, outputs));
  if (value && typeof value === 'object') {
    const out: Record<string, any> = {};
    for (const [key, item] of Object.entries(value)) out[key] = resolveTemplates(item, outputs);
    return out;
  }
  return value;
}
