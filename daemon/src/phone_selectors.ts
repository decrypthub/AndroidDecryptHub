// Selector derivation for the phone automation tools.
//
// Kept pure and separate from mcp.ts so the argument-vs-selector rules are unit-testable: the
// same JSON field can be a target (resourceId) or a payload (set_text's text), and mixing the
// two silently produces a selector that can never match.

export const SELECTOR_KEYS = ['text', 'textContains', 'resourceId', 'contentDescription', 'contentDescriptionContains', 'clickable', 'editable', 'scrollable'];

export function selectorFrom(args: any, excludeKeys: string[] = []): any {
  const selector: any = { ...(args?.selector ?? {}) };
  for (const key of SELECTOR_KEYS) {
    if (excludeKeys.includes(key)) continue;
    if (args?.[key] !== undefined && args?.[key] !== null) selector[key] = args[key];
  }
  return selector;
}

// set_text carries its payload in `text`. Reading that same argument as a selector would demand a
// node whose CURRENT text already equals the value we are about to write, so the field could never
// be resolved (`selector_not_found` on every attempt). Exclude it from the implicit selector;
// an explicit selector:{text:...} is still honoured.
export function implicitSelectorFor(action: string | undefined, args: any): any {
  return selectorFrom(args, action === 'set_text' ? ['text'] : []);
}
