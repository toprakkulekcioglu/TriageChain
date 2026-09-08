"""Dosya hash'leme. Guven acisindan kritik: sadece stdlib, hicbir hokkabazlik yok."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Union

from triagechain.collection.winpath import to_long_path

DEFAULT_CHUNK_SIZE = 1024 * 1024


def hash_file(
    path_or_stream: Union[str, Path, BinaryIO],
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Dosyayi/akisi sabit parcalar halinde okuyup kucuk harfli hex ozet dondurur."""
    digest = hashlib.new(algorithm)
    if hasattr(path_or_stream, "read"):
        _feed(path_or_stream, digest, chunk_size)
    else:
        with open(to_long_path(Path(path_or_stream)), "rb") as handle:
            _feed(handle, digest, chunk_size)
    return digest.hexdigest()


def _feed(stream: BinaryIO, digest, chunk_size: int) -> None:
    """Akisi parca parca okuyup ozete besler."""
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
