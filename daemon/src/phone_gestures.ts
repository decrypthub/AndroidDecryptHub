// Gesture geometry for phone_wait's scroll-until-found.
//
// ACTION_SCROLL only works on widgets that implement it. Pagers (the launcher's home pages,
// custom horizontal lists, some WebViews) reject it outright — they only respond to a real
// swipe. These helpers keep that geometry in one place so the wait loop stays readable.

export type ScrollAxis = 'vertical' | 'horizontal';

export interface SwipePath { x: number; y: number; x2: number; y2: number }

// Fractions of the screen; forward = content moves forward (swipe up for a list, left for a pager).
export function swipePath(axis: ScrollAxis, forward: boolean): SwipePath {
  if (axis === 'horizontal') return forward ? { x: 0.82, y: 0.5, x2: 0.18, y2: 0.5 } : { x: 0.18, y: 0.5, x2: 0.82, y2: 0.5 };
  return forward ? { x: 0.5, y: 0.75, x2: 0.5, y2: 0.3 } : { x: 0.5, y: 0.3, x2: 0.5, y2: 0.75 };
}

export function normalizeAxis(value: unknown): ScrollAxis {
  return String(value ?? '').toLowerCase() === 'horizontal' ? 'horizontal' : 'vertical';
}
