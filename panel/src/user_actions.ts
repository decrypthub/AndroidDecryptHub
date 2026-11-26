/** User-initiated actions. A browser acknowledgement is not proof that a file reached disk. */
export async function copyText(text: string): Promise<void> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // LAN HTTP does not expose Clipboard API. Use the synchronous user-gesture fallback,
  // respecting its boolean result and restoring focus/selection; never silently succeed.
  if (typeof document === 'undefined' || !document.body || typeof document.execCommand !== 'function')
    throw new Error('当前环境不支持复制');
  const active = document.activeElement as HTMLElement | null;
  const selection = document.getSelection();
  const ranges = selection ? Array.from({length: selection.rangeCount}, (_, i) => selection.getRangeAt(i).cloneRange()) : [];
  const field = document.createElement('textarea');
  field.value = text; field.setAttribute('readonly', '');
  field.style.cssText = 'position:fixed;left:-9999px;top:0';
  document.body.appendChild(field);
  try {
    field.select();
    if (!document.execCommand('copy')) throw new Error('浏览器拒绝复制');
  } finally {
    field.remove(); active?.focus({preventScroll:true});
    if (selection) { selection.removeAllRanges(); for (const range of ranges) selection.addRange(range); }
  }
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  let link: HTMLAnchorElement | undefined;
  try { link = document.createElement('a'); link.href = url; link.download = filename; document.body.appendChild(link); link.click(); }
  finally { link?.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
}
