"""Custody defterinin dosya katmani: sadece ekleme yapilan JSONL + surecler
arasi yazma kilidi.

`locked()` ayri bir `.lock` dosyasi uzerinden isletim sistemi seviyesinde
ozel (exclusive) bir kilit tutar -- Windows'ta `msvcrt.locking`, POSIX'te
`fcntl.flock` (ikisi de STDLIB, yeni bir bagimlilik DEGIL). Log dosyasinin
KENDISI degil, ayri bir `.lock` dosyasi kilitleniyor: boylece SALT-OKUNUR
islemler (read_lines/verify_chain) yazmayi hic beklemez, sadece YAZMA-YAZMA
carpismasi engellenir -- bir adli inceleme sirasinda dogrulamanin bir
yazicinin arkasinda beklemesi kabul edilemez.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Iterator

from triagechain.core.errors import CustodyLedgerError

try:
    import msvcrt
except ImportError:  # POSIX'te yok
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:  # Windows'ta yok
    fcntl = None  # type: ignore[assignment]


@contextlib.contextmanager
def locked(log_path: Path) -> Iterator[None]:
    """`log_path` icin surecler-arasi ozel kilit tutar (bkz. modul dokstring'i).

    Kilit olmadan, IKI ayri surec (orn. GUI + ayni anda calistirilan bir CLI
    komutu) `CustodyLedger.append_event()`'in `last_hash()` OKUMASI ile
    `append_line()` YAZMASI arasina girebilir -- ikisi de ayni prev_hash'i
    okuyup ekleyebilir, bu da zinciri CATALLAR (iki olay ayni prev_hash'e
    sahip olur, verify_chain sonraki olayda kirilma bildirir). Bu fonksiyon
    `append_event()`'in TAMAMINI (oku+yaz) atomik yapmak icin kullanilir.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = log_path.with_name(log_path.name + ".lock")

    with open(lock_path, "a+b") as lock_file:
        # msvcrt bos bir dosyanin 0. baytini kilitleyemiyor -- en az 1 bayt
        # gerekiyor, icerigin kendisi hicbir zaman okunmuyor/onemli degil.
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"0")
            lock_file.flush()

        if msvcrt is not None:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        elif fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        else:  # pragma: no cover - ne Windows ne POSIX, cok nadir bir platform
            yield


def append_line(log_path: Path, line: str) -> None:
    """Satiri deftere ekler ve diske yazildigindan emin olur.

    Kilitlenme sorumlulugu CAGIRANDA (bkz. CustodyLedger.append_event): bu
    fonksiyon kendi basina cagirilirsa (orn. testlerde) kilitsiz calisir.
    """
    log_path = Path(log_path)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # "a" modu: dosya tanimlayicisi her yazmada sonuna konumlanir, ustune yazilmaz.
        with open(log_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()
            # Adli kayit: surec cokse bile satir diskte kalmali.
            os.fsync(handle.fileno())
    except OSError as exc:
        raise CustodyLedgerError(f"Custody defterine yazilamadi: {log_path} ({exc})") from exc


def read_lines(log_path: Path) -> Iterator[str]:
    """Defterdeki bos olmayan satirlari sirayla dondurur.

    KASITLI OLARAK kilitsiz: okuma yazmayi hic beklememeli (bkz. modul
    dokstring'i). Bir yazma yarim kalmis olsa bile (fsync sonrasi tam satir
    ya hic yazilmis ya tam yazilmis olur) okuma engellenmez.
    """
    log_path = Path(log_path)
    try:
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield line
    except FileNotFoundError as exc:
        raise CustodyLedgerError(f"Custody defteri bulunamadi: {log_path}") from exc
    except OSError as exc:
        raise CustodyLedgerError(f"Custody defteri okunamadi: {log_path} ({exc})") from exc
