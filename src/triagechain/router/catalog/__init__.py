"""Gomulu arac esleme katalogu erisimi.

Katalog yolu tek bir fonksiyon uzerinden veriliyor: yonlendirici bu
fonksiyonu cagirdigi icin testlerde tek noktadan sahte eslemeyle
degistirilebiliyor (collection/catalog ile ayni desen).
"""

from __future__ import annotations

from pathlib import Path


def default_catalog_path() -> Path:
    """Pakete gomulu varsayilan arac esleme katalogunun yolunu dondurur."""
    return Path(__file__).resolve().parent / "tool_mapping.yaml"


def default_recmd_batch_path() -> Path:
    """Pakete gomulu varsayilan RECmd toplu (batch) dosyasinin yolunu dondurur.

    RECmd, `-f <hive>` ile cagrildiginda hangi anahtar/degerlerin cikarilacagini
    AYRICA bilmek ister; bunun standart yolu `--bn <toplu dosya>`. Gomulen dosya
    EricZimmerman/RECmd deposundaki MIT lisansli DFIRBatch.reb'in SABITLENMIS
    (pinned) bir surumudur - kaynak/surum/SHA-256 bilgisi icin bkz.
    recmd_batch/PROVENANCE.md. Kullanici isterse config'deki
    `router.recmd_batch_file` ile kendi dosyasini gosterebilir.
    """
    return Path(__file__).resolve().parent / "recmd_batch" / "DFIRBatch.reb"
