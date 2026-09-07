"""Gomulu artefakt katalogu erisimi.

Katalog yolu tek bir fonksiyon uzerinden veriliyor: hem konfigurasyon
dogrulamasi hem de toplayici ayni fonksiyonu cagirdigi icin testlerde
tek noktadan sahte katalogla degistirilebiliyor.
"""

from __future__ import annotations

from pathlib import Path


def default_catalog_path() -> Path:
    """Pakete gomulu varsayilan hedef katalogunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "default_targets.yaml"
