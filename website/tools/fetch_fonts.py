"""Download the upstream fonts into .cache/ (one time, then offline).

    python website/tools/fetch_fonts.py

Noto Sans SC and JetBrains Mono are both SIL Open Font License.
"""

from __future__ import annotations

from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"

FONTS = {
    "NotoSansSC.ttf": "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf",
    "JetBrainsMono.ttf": "https://raw.githubusercontent.com/google/fonts/main/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf",
}


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    for name, url in FONTS.items():
        out = CACHE / name
        if out.exists():
            print(f"{name:20s} cached ({out.stat().st_size / 1024 / 1024:.1f} MB)")
            continue
        print(f"{name:20s} downloading")
        with urlopen(url, timeout=180) as res:
            out.write_bytes(res.read())
        print(f"{name:20s} {out.stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
