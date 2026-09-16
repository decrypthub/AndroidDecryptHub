// Verification helpers for phone_app open.
//
// On some OEM ROMs the accessibility `open` fallback is intercepted by a system confirmation
// dialog: the launch call "succeeds" but the requested app never reaches the foreground. The AI
// must be told that plainly instead of being handed an optimistic ok.

const BLOCKED = /active package ([\w.]+) is not in the automation allowlist/;

export function blockedPackageFromError(message: unknown): string | null {
  const match = BLOCKED.exec(String(message ?? ''));
  return match ? match[1] : null;
}

export function openOutcomeHint(requested: string, foreground: string | null, blocked: boolean): string {
  if (foreground === requested) return '';
  if (blocked && foreground) {
    return `open_blocked_by_system_dialog: '${foreground}' is in front (OEM cross-app confirmation). Confirm it on the phone, add '${foreground}' to the automation allowlist, or flash the v0.3.7 bundle so the root Device Daemon opens the app directly.`;
  }
  if (!foreground) return 'open_unverified: the foreground package could not be read (is the automation bridge connected?)';
  return `open_unverified: foreground is '${foreground}', not '${requested}'`;
}
