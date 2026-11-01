"""Subset and self-host the faces the page uses.

Reads every character in index.html, site.css and site.js, then writes:

    assets/fonts/sans-400.woff2    body
    assets/fonts/sans-500.woff2    labels, buttons
    assets/fonts/sans-600.woff2    display and headings
    assets/fonts/mono-400.woff2    code and data

Run it again after changing copy, otherwise new characters fall back to the
system font. The summary line reports how many requested characters the source
font lacks.

    python website/tools/build_fonts.py
"""

from __future__ import annotations

from pathlib import Path

from fontTools.subset import Options, Subsetter
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
OUT = ROOT / "assets" / "fonts"

SANS_SRC = CACHE / "NotoSansSC.ttf"
MONO_SRC = CACHE / "JetBrainsMono.ttf"

ALWAYS = (
    "".join(chr(c) for c in range(0x20, 0x7F))
    + "，。、；：「」『』（）《》！？·…“”‘’→"
)


def source_text() -> str:
    text = []
    for name in ("index.html", "assets/css/site.css", "assets/js/site.js"):
        text.append((ROOT / name).read_text(encoding="utf-8"))
    return "".join(text)


def subset_font(src: Path, out: Path, chars: str, weight: int | None = None) -> tuple[int, int]:
    font = TTFont(str(src))
    if weight is not None:
        font = instantiateVariableFont(font, {"wght": weight}, inplace=True)

    have = set(font.getBestCmap().keys())
    missing = sorted({ch for ch in chars if ord(ch) not in have})

    opts = Options()
    opts.flavor = "woff2"
    opts.layout_features = ["*"]
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    opts.drop_tables += ["DSIG"]

    subsetter = Subsetter(options=opts)
    subsetter.populate(text=chars)
    subsetter.subset(font)

    font.flavor = "woff2"
    out.parent.mkdir(parents=True, exist_ok=True)
    font.save(str(out))
    return len(font.getBestCmap()), len(missing)


def main() -> None:
    chars = "".join(sorted(set(source_text()) | set(ALWAYS)))
    chars = "".join(ch for ch in chars if ord(ch) >= 0x20)
    print(f"requested characters: {len(chars)}")

    jobs = [
        (SANS_SRC, OUT / "sans-400.woff2", chars, 400),
        (SANS_SRC, OUT / "sans-500.woff2", chars, 500),
        (SANS_SRC, OUT / "sans-600.woff2", chars, 600),
        (MONO_SRC, OUT / "mono-400.woff2", "".join(chr(c) for c in range(0x20, 0x7F)) + "·", None),
    ]
    for src, out, text, weight in jobs:
        glyphs, missing = subset_font(src, out, text, weight)
        kb = out.stat().st_size / 1024
        note = f", {missing} chars not in source" if missing else ""
        print(f"{out.name:18s} {kb:7.1f} KB  {glyphs:5d} glyphs{note}")


if __name__ == "__main__":
    main()
