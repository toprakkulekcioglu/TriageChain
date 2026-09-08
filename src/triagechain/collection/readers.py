"""Kaynak dosyayi acma stratejileri.

Tek isi dogru acma yontemini secmek; boylece collector.py'de requires_vss
icin if/else dagilmiyor.
"""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Optional

from triagechain.collection.vss_snapshot import VssSnapshot
from triagechain.collection.winpath import to_long_path


def read_plain(path: Path) -> BinaryIO:
    """Kilitli olmayan dosyayi dogrudan acar."""
    return open(to_long_path(path), "rb")


def read_via_vss(path: Path, snapshot: VssSnapshot) -> BinaryIO:
    """Yolu once golge kopya karsiligina cevirip acar."""
    return open(snapshot.translate(path), "rb")


def open_source(path: Path, snapshot: Optional[VssSnapshot]) -> BinaryIO:
    """Golge kopya varsa onun uzerinden, yoksa dogrudan acar."""
    if snapshot is None:
        return read_plain(path)
    return read_via_vss(path, snapshot)
