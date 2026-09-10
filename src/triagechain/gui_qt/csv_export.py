"""Tablo verisini CSV'ye yazmak icin TEK bir kucuk yardimci -- Oxygen
Forensic Detective'in tablo disa aktarma ozelliginden esinlenildi (bkz.
docs/aldigim_kararlar.md). Yeni bir bagimlilik EKLENMEDI: stdlib `csv`
modulu yeterli.

Hangi tablonun hangi sutunlari tasidigini BILMEZ -- cagiran taraf
(main_window.py) zaten o veriye sahip, satirlari kendi olusturur. Bu modul
sadece "bunlari diske UTF-8 BOM'lu CSV olarak yaz" isini yapar.
"""

from __future__ import annotations

import csv
from pathlib import Path


def write_rows_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    """Satirlari CSV olarak yazar.

    `utf-8-sig` (BOM'lu UTF-8) BILEREK kullanildi: Excel, BOM olmadan
    UTF-8 CSV'yi yanlis kod sayfasiyla aciyor -- Turkce karakterler (İ/ş/
    ğ/ü vb.) bozuk gorunuyor. BOM eklenince Excel dogru kod sayfasini
    kendiliginden taniyor.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)
