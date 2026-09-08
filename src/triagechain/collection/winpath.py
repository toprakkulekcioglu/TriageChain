r"""Windows'un klasik 260 karakter MAX_PATH sinirini asmak icin tek fonksiyon.

Uzun dosya adli olay gunlugu kanallari (orn. "Microsoft-Windows-Device
Management-Enterprise-Diagnostics-Provider%4Operational.evtx") + derin vaka
klasor yapisi (output_dir/case_id/artifacts/<hedef>/<dosya>) kolayca 260
karakteri asabiliyor -- gercek bir KAPE ice aktarma testinde (bkz.
aldigim_kararlar.md -> "Ice aktarma modu") bulundu. "Enable Win32 long
paths" grup ilkesine/uygulama manifestosuna BAGIMLI olmayan tek tasinabilir
cozum, Win32 API'nin kendi \\?\ (extended-length path) onekidir.
"""

from __future__ import annotations

import sys
from pathlib import Path


def to_long_path(path: Path) -> Path:
    r"""Windows'ta MUTLAK bir yolu \\?\ onekiyle dondurur (MAX_PATH atlanir).

    Diger platformlarda (CI Linux) hicbir sey yapmaz -- onek Windows'a ozgu,
    baska bir yerde anlamsiz/zararli olurdu. Zaten onekli ya da UNC
    (\\sunucu\pay gibi) bir yol farkli ele alinir (UNC icin \\?\UNC\),
    goreli bir yol ise DOKUNULMADAN dondurulur (onek sadece mutlak
    yollarda gecerlidir).
    """
    if sys.platform != "win32":
        return path
    text = str(path)
    if text.startswith("\\\\?\\"):
        return path
    if text.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + text[2:])
    if not path.is_absolute():
        return path
    return Path("\\\\?\\" + text)
