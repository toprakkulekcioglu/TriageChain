r"""Windows'un 260 karakter MAX_PATH sinirini asan \\?\ oneki yardimcisi.

Gercek bir MAX_PATH hatasi, gercek bir KAPE ice aktarma testinde (uzun
olay gunlugu kanal adlari + derin vaka klasoru) bulundu -- bkz.
aldigim_kararlar.md -> "Windows MAX_PATH duzeltmesi".
"""

import sys
from pathlib import Path

import pytest

from triagechain.collection.winpath import to_long_path

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="\\\\?\\ oneki Windows'a ozgu")


def test_absolute_path_gets_prefixed():
    result = to_long_path(Path(r"C:\Users\test\uzun\bir\yol\dosya.txt"))
    assert str(result) == r"\\?\C:\Users\test\uzun\bir\yol\dosya.txt"


def test_already_prefixed_path_is_not_double_prefixed():
    already = Path(r"\\?\C:\Users\test\dosya.txt")
    assert to_long_path(already) == already


def test_relative_path_is_returned_unchanged():
    # Onek SADECE mutlak yollarda gecerlidir -- goreli bir yolu \\?\ ile
    # sarmak onu bozardi (Win32 API mutlak bekler).
    relative = Path("goreli") / "dosya.txt"
    assert to_long_path(relative) == relative


def test_unc_path_gets_unc_prefix():
    unc = Path(r"\\sunucu\pay\dosya.txt")
    result = to_long_path(unc)
    assert str(result) == r"\\?\UNC\sunucu\pay\dosya.txt"
