"""Gomulu Hayabusa/YARA cagri sablonu katalogu erisimi.

Katalog yolu tek bir fonksiyon uzerinden veriliyor: tespit kosusu bu
fonksiyonu cagirdigi icin testlerde tek noktadan sahte sablonla
degistirilebiliyor (collection/catalog ve router/catalog ile ayni desen).
"""

from __future__ import annotations

from pathlib import Path


def default_catalog_path() -> Path:
    """Pakete gomulu varsayilan Hayabusa cagri sablonunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "hayabusa_args.yaml"


def default_yara_catalog_path() -> Path:
    """Pakete gomulu varsayilan YARA cagri sablonunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "yara_args.yaml"


def default_chainsaw_catalog_path() -> Path:
    """Pakete gomulu varsayilan Chainsaw cagri sablonunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "chainsaw_args.yaml"


def default_capa_catalog_path() -> Path:
    """Pakete gomulu varsayilan capa cagri sablonunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "capa_args.yaml"
