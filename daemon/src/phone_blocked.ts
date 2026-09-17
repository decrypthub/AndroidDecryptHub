// Recently-noticed-but-blocked automation packages.
//
// The allowlist is the product's privacy boundary: nothing gets touched without an explicit
// entry. The cost is that the operator only learns which package they forgot at the moment an
// AI hits the wall — and on ColorOS the settings pages are scattered across packages
// (com.android.settings -> com.oplus.battery). This module records the package names that were
// refused (never the page content) so the settings panel can offer a one-click "add to
// allowlist" affordance instead of a dead end.
//
// Host-only, in-memory, bounded; the name also comes from the device error string, which is
// produced by the device's own allowlist check.

export interface BlockedPackageNotice {
  package: string;
  count: number;
  firstSeenAt: number;
  lastSeenAt: number;
  /** Monotonic insertion/refresh order; Date.now() collides inside one millisecond. */
  order: number;
}

const MAX_NOTICES = 8;
const notices = new Map<string, BlockedPackageNotice>();
let sequence = 0;

/** Records an allowlist refusal. Returns false when the name does not look like a package. */
export function recordBlockedPackage(packageName: unknown): boolean {
  const name = String(packageName ?? '').trim();
  // Deliberately conservative: a package id is dot-separated words, nothing else.
  if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(name) || name.length > 120) return false;
  const now = Date.now();
  const order = ++sequence;
  const notice = notices.get(name);
  if (notice) {
    notice.count++;
    notice.lastSeenAt = now;
    notice.order = order;
  } else {
    notices.set(name, { package: name, count: 1, firstSeenAt: now, lastSeenAt: now, order });
  }
  while (notices.size > MAX_NOTICES) {
    let oldest: string | null = null;
    let oldestOrder = Infinity;
    for (const [key, value] of notices) {
      if (value.order < oldestOrder) {
        oldestOrder = value.order;
        oldest = key;
      }
    }
    if (!oldest) break;
    notices.delete(oldest);
  }
  return true;
}

/** Newest first. */
export function blockedPackageNotices(): BlockedPackageNotice[] {
  return [...notices.values()].sort((a, b) => b.order - a.order);
}

export function clearBlockedPackages(): void {
  notices.clear();
}
