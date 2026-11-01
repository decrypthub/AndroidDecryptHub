"""Generate the 1200x630 share card.

    python website/tools/gen_assets.py

White canvas, bold grotesque headline, one green signal, and the same dark
product surface the page uses.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
OUT = ROOT / "assets" / "img"

SANS = CACHE / "NotoSansSC.ttf"
MONO = CACHE / "JetBrainsMono.ttf"

WHITE = (255, 255, 255)
INK = (13, 13, 13)
BODY = (53, 55, 64)
MUTED = (110, 110, 128)
FAINT = (142, 142, 160)
LINE = (229, 229, 229)
GREEN = (16, 163, 127)
DARK = (13, 13, 13)
DARK_2 = (23, 23, 23)
DARK_LINE = (42, 42, 42)
ON_DARK = (236, 236, 241)
ON_DARK_MUTED = (142, 142, 160)


def face(size: int, weight: int | None = None) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype(str(SANS), size)
    if weight is not None:
        try:
            f.set_variation_by_axes([weight])
        except Exception:
            pass
    return f


def mono(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(MONO), size)


def tracked(draw, xy, text, font, fill, tracking=0.0):
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += font.getlength(ch) + tracking
    return x


def build() -> Image.Image:
    W, H = 1200, 630
    img = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(img)

    display = face(82, 600)
    sub = face(21, 400)
    word = face(18, 600)
    small = face(13, 500)
    mono_md = mono(12)
    mono_sm = mono(10)

    # Masthead
    d.rectangle((64, 52, 73, 61), fill=INK)
    d.text((82, 45), "ADH", font=word, fill=INK)
    tracked(d, (W - 64 - 160, 52), "ANDROID RUNTIME", mono_sm, MUTED, 1.6)
    d.line((64, 88, W - 64, 88), fill=LINE, width=1)

    # Headline
    d.text((62, 138), "它只在运行时", font=display, fill=INK)
    d.text((62, 236), "说出真话。", font=display, fill=INK)

    # Subline
    d.text((64, 390), "轻量 agent 进入目标进程，密钥、方法、内存从运行时读出来。", font=sub, fill=BODY)
    d.text((64, 422), "索引、反汇编与数据库留在电脑上。", font=sub, fill=BODY)

    # Console
    x0, y0, x1, y1 = 700, 148, 1136, 452
    pw, ph = x1 - x0, y1 - y0
    panel = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    pd = ImageDraw.Draw(panel)
    pd.rounded_rectangle((0, 0, pw - 1, ph - 1), radius=12, fill=DARK + (255,), outline=DARK_LINE + (255,), width=1)
    pd.rectangle((0, 0, pw - 1, 38), fill=DARK_2 + (255,))
    pd.rounded_rectangle((0, 0, pw - 1, 12), radius=12, fill=DARK_2 + (255,))
    pd.line((0, 38, pw, 38), fill=DARK_LINE + (255,), width=1)
    pd.ellipse((14, 15, 21, 22), fill=GREEN + (255,))
    pd.text((29, 13), "adhd", font=mono_sm, fill=ON_DARK + (255,))
    pd.text((66, 14), "/ 127.0.0.1:8088", font=mono_sm, fill=(124, 124, 138, 255))
    pd.text((pw - 42, 14), "LIVE", font=mono_sm, fill=GREEN + (255,))

    pd.line((0, 68, pw, 68), fill=DARK_LINE + (255,), width=1)
    pd.text((14, 46), "com.example.app", font=mono_sm, fill=ON_DARK + (255,))
    pd.text((110, 46), ":core", font=mono_sm, fill=(124, 124, 138, 255))
    pd.line((14, 67, 96, 67), fill=GREEN + (255,), width=2)

    pd.text((14, 80), "captures 1,204", font=mono_sm, fill=(124, 124, 138, 255))
    pd.text((pw - 74, 80), "dropped 0", font=mono_sm, fill=(124, 124, 138, 255))
    pd.line((0, 98, pw, 98), fill=DARK_LINE + (255,), width=1)

    rows = [
        ("Cipher", "AES/CBC/PKCS5Padding", "ENCRYPT · key 16 B · iv 16 B"),
        ("Digest", "SHA-256", "digest · in 1.2 KB · out 32 B"),
    ]
    y = 108
    for tag, name, meta in rows:
        tw = int(pd.textlength(tag, font=mono_sm)) + 12
        pd.rounded_rectangle((14, y, 14 + tw, y + 15), radius=3, fill=(16, 163, 127, 36))
        pd.text((20, y + 2), tag, font=mono_sm, fill=GREEN + (255,))
        pd.text((14, y + 26), name, font=mono_md, fill=(245, 245, 245, 255))
        pd.text((14, y + 46), meta, font=mono_sm, fill=(142, 142, 160, 255))
        pd.line((14, y + 66, pw - 14, y + 66), fill=(35, 35, 35, 255), width=1)
        y += 80

    pd.text((14, y + 4), "ring 12%", font=mono_sm, fill=(124, 124, 138, 255))
    pd.text((pw - 52, y + 4), "jsonl", font=mono_sm, fill=(124, 124, 138, 255))
    img.paste(panel, (x0, y0), panel)

    # Footer
    d.line((64, 520, W - 64, 520), fill=LINE, width=1)
    tracked(d, (64, 540), "ADH / ANDROID DECRYPTHUB", mono_sm, MUTED, 1.2)
    d.text((W - 64 - small.getlength("运行时分析，留在本机"), 538), "运行时分析，留在本机", font=small, fill=MUTED)
    return img


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    card = build()
    out = OUT / "og.jpg"
    card.save(out, quality=90, optimize=True, progressive=True)
    print(f"{out.name}  {out.stat().st_size / 1024:.1f} KB  {card.size}")


if __name__ == "__main__":
    main()
