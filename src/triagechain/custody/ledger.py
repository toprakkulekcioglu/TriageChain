"""Hash zincirli chain-of-custody defteri.

Zincir semasi (docs/chain_of_custody.md ile birebir ayni):
  genesis_hash = sha256(case_id + "::TRIAGECHAIN_GENESIS")
  entry_hash   = sha256(prev_hash + kanonik_json(olay - entry_hash))
Kanonik JSON: anahtarlar sirali, ayiraclar (",", ":").
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from triagechain.core.errors import CustodyLedgerError
from triagechain.custody import storage
from triagechain.custody.models import CustodyEvent

GENESIS_SUFFIX = "::TRIAGECHAIN_GENESIS"


def genesis_hash(case_id: str) -> str:
    """Bir vakanin zincirini baslatan sabit hash."""
    return hashlib.sha256((case_id + GENESIS_SUFFIX).encode("utf-8")).hexdigest()


def compute_entry_hash(event: CustodyEvent) -> str:
    """Olayin entry_hash degerini prev_hash + kanonik gosterimden hesaplar."""
    return hashlib.sha256(
        event.prev_hash.encode("utf-8") + event.canonical_json_bytes()
    ).hexdigest()


def read_events(log_path: Path) -> Iterator[CustodyEvent]:
    """Defterdeki olaylari sirayla okur."""
    for index, line in enumerate(storage.read_lines(log_path), start=1):
        try:
            yield CustodyEvent.from_json_line(line)
        except (ValueError, KeyError) as exc:
            raise CustodyLedgerError(
                f"Custody defterinin {index}. satiri cozulemedi: {exc}"
            ) from exc


@dataclass
class VerificationResult:
    """verify_chain sonucu."""

    is_valid: bool
    total_events: int
    broken_at_event_id: Optional[str]
    message: str


class CustodyLedger:
    """Tek bir vakanin gozetim zinciri defteri."""

    def __init__(self, log_path: Path | str, case_id: str) -> None:
        self.log_path = Path(log_path)
        self.case_id = case_id

    def last_hash(self) -> str:
        """Son kaydin entry_hash'i; defter yoksa/bossa genesis hash."""
        if not self.log_path.exists():
            return genesis_hash(self.case_id)
        last: Optional[str] = None
        for line in storage.read_lines(self.log_path):
            last = line
        if last is None:
            return genesis_hash(self.case_id)
        return CustodyEvent.from_json_line(last).entry_hash

    def append_event(
        self, event_type: str, operator: str, payload: dict[str, Any]
    ) -> CustodyEvent:
        """Yeni olayi zincire ekler ve yazilan olayi dondurur.

        `storage.locked()` icinde: last_hash() OKUMASI ile append_line()
        YAZMASI tek bir atomik islem olarak calisir -- aksi halde birden
        fazla surec (orn. GUI + CLI ayni anda) ayni prev_hash'i okuyup
        zinciri CATALLAYABILIR (bkz. storage.py'nin kendi dokstring'i).
        """
        with storage.locked(self.log_path):
            event = CustodyEvent(
                event_id=str(uuid.uuid4()),
                timestamp_utc=datetime.now(timezone.utc),
                event_type=event_type,
                case_id=self.case_id,
                operator=operator,
                payload=dict(payload),
                prev_hash=self.last_hash(),
            )
            # entry_hash her zaman defter tarafindan hesaplanir, disaridan alinmaz.
            event.entry_hash = compute_entry_hash(event)
            storage.append_line(self.log_path, event.to_json_line())
        return event


def verify_chain(log_path: Path, case_id: str) -> VerificationResult:
    """Zinciri genesis'ten itibaren yeniden hesaplayarak dogrular.

    Ilk uyusmazlikta durur ve hangi olayda kirildigini bildirir.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise CustodyLedgerError(f"Custody defteri bulunamadi: {log_path}")

    expected_prev = genesis_hash(case_id)
    count = 0

    for index, line in enumerate(storage.read_lines(log_path), start=1):
        try:
            event = CustodyEvent.from_json_line(line)
        except (ValueError, KeyError) as exc:
            return VerificationResult(
                is_valid=False,
                total_events=count,
                broken_at_event_id=None,
                message=f"{index}. satir cozulemedi (bozuk JSON): {exc}",
            )
        count += 1

        if event.case_id != case_id:
            return VerificationResult(
                False, count, event.event_id,
                f"{index}. olay baska bir vakaya ait: {event.case_id!r} (beklenen {case_id!r}).",
            )
        if event.prev_hash != expected_prev:
            return VerificationResult(
                False, count, event.event_id,
                f"{index}. olayin prev_hash degeri onceki kaydin entry_hash'i ile uyusmuyor.",
            )
        recomputed = compute_entry_hash(event)
        if recomputed != event.entry_hash:
            return VerificationResult(
                False, count, event.event_id,
                f"{index}. olayin entry_hash degeri yeniden hesaplananla uyusmuyor "
                "(kayit degistirilmis olabilir).",
            )
        expected_prev = event.entry_hash

    return VerificationResult(
        is_valid=True,
        total_events=count,
        broken_at_event_id=None,
        message=f"Zincir saglam: {count} olay dogrulandi.",
    )
