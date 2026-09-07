"""assets/icons/*.svg (elle cizilmis, basit stroke ikonlar) icin tek bir
icon(name) fonksiyonu.

Desen, kullanicinin chameleon projesindeki `shared/ui_kit/icons.py`'den
alindi: Unicode glif/emoji YERINE gercek SVG kullanmanin gerekcesi de ayni --
chameleon'un kendi gecmisinde (docs/ogrenilenler.md) bulunmus bir ders:
emoji/glif ikonlar headless/bazi ortamlarda kutu (tofu) olarak render
olabiliyor, sistemin renkli emoji fontuna dusme garantisi yok. SVG'ler
`stroke="currentColor"` kullanir, Qt'ye vermeden once bu metin duzeyinde
istenen hex renkle degistirilir.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from triagechain.gui_qt import theme as t

_ASSETS_DIR = Path(__file__).resolve().parent / "assets" / "icons"
_cache: dict[tuple[str, str, int], QIcon] = {}


def icon(name: str, color: str | None = None, size: int = 20) -> QIcon:
    """`assets/icons/<name>.svg` dosyasini (uzantisiz isimle) yukler.

    color verilmezse guncel TEXT_MAIN kullanilir. Sonuc (isim, renk, boyut)
    anahtariyla onbelleklenir -- ayni ikon tekrar tekrar parse edilmez.
    """
    color = color or t.TEXT_MAIN
    key = (name, color, size)
    cached = _cache.get(key)
    if cached is not None:
        return cached

    path = _ASSETS_DIR / f"{name}.svg"
    if not path.is_file():
        return QIcon()

    svg_text = path.read_text(encoding="utf-8").replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(svg_text.encode("utf-8")))
    pixmap = QPixmap(QSize(size, size))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()

    result = QIcon(pixmap)
    _cache[key] = result
    return result
