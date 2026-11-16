import { restoreHostState } from './state.ts';

/** Called by the executable before listeners start. Never prunes or configures a device. */
export function initializeHost() {
  return restoreHostState();
}
