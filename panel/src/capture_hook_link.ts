import type {Cap} from './api';
/** Resolve only an exact reported Native symbol in the actual control catalog.
 * Java rich captures currently omit overload identity, so they must not guess a method. */
export function captureHookMethod(c: Cap, methods: any[]): any | null {
  if (!c.deviceBinding?.serial || !c.package || c.source !== 'native' || typeof c.func !== 'string') return null;
  const found = methods.filter(m => m.backend === 'native' && m.symbol === c.func && m.id === 'native.' + c.func);
  return found.length === 1 ? found[0] : null;
}
