"""Génère un logo PNG simple pour InjectionHunter.

But:
- éviter d'avoir un fichier logo vide/non-image
- fournir un logo par défaut stable, sans dépendre d'assets externes

Le rendu est volontairement minimal: un bandeau + texte.
"""

from __future__ import annotations

from pathlib import Path


def ensure_injection_logo(path: str | Path) -> str:
    """Crée un PNG de logo si nécessaire, puis retourne son chemin (str)."""

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Si un fichier existe déjà et qu'il est non vide, on le garde.
    if p.exists() and p.is_file() and p.stat().st_size > 0:
        return str(p)

    # Génération d'un logo simple via Pillow.
    try:
        from PIL import Image, ImageDraw, ImageFont

        w, h = 1400, 420
        img = Image.new("RGB", (w, h), (10, 15, 30))
        draw = ImageDraw.Draw(img)

        # bandeau accent
        draw.rectangle([0, 0, w, 40], fill=(31, 95, 191))
        draw.rectangle([0, h - 24, w, h], fill=(31, 95, 191))

        title = "InjectionHunter"
        subtitle = "A05 – Injection (OWASP Top 10:2025)"

        # Polices: on prend la police par défaut si Arial indispo
        def _load_font(size: int):
            try:
                return ImageFont.truetype("arial.ttf", size)
            except Exception:
                return ImageFont.load_default()

        font_title = _load_font(92)
        font_sub = _load_font(46)

        # centrage approximatif (suffisant pour un logo)
        tw, th = draw.textbbox((0, 0), title, font=font_title)[2:]
        sw, sh = draw.textbbox((0, 0), subtitle, font=font_sub)[2:]

        x_title = (w - tw) // 2
        y_title = 120
        x_sub = (w - sw) // 2
        y_sub = y_title + th + 20

        draw.text((x_title, y_title), title, fill=(255, 255, 255), font=font_title)
        draw.text((x_sub, y_sub), subtitle, fill=(229, 231, 235), font=font_sub)

        img.save(str(p), format="PNG", optimize=True)
        return str(p)

    except Exception:
        # Dernier recours: créer un placeholder binaire très simple est risqué.
        # On préfère ne rien écrire.
        return str(p)
