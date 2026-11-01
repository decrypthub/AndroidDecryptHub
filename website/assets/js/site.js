(() => {
  "use strict";

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const targets = document.querySelectorAll("[data-reveal]");

  if (reduced || !("IntersectionObserver" in window)) {
    targets.forEach((el) => el.classList.add("is-in"));
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -6% 0px", threshold: 0 }
    );
    targets.forEach((el) => io.observe(el));
  }

  const copyText = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await Promise.race([
          navigator.clipboard.writeText(text),
          new Promise((_, reject) => window.setTimeout(() => reject(new Error("timeout")), 800)),
        ]);
        return true;
      } catch {
        /* fall through to the selection route */
      }
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  };

  for (const button of document.querySelectorAll("[data-copy]")) {
    button.setAttribute("aria-live", "polite");
    button.addEventListener("click", async () => {
      const host = button.closest(".code-block, .code-mini");
      const code = host && host.querySelector("code");
      if (!code) return;
      const original = button.textContent;
      const ok = await copyText(code.textContent);
      if (ok) {
        button.textContent = "已复制";
        button.classList.add("done");
      } else {
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        button.textContent = "按 Ctrl+C";
      }
      window.setTimeout(() => {
        button.textContent = original;
        button.classList.remove("done");
      }, 1800);
    });
  }
})();
