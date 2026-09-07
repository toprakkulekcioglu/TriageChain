"""Chain-of-custody olay modeli ve kanonik serilestirme."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Kanonik JSON kurali: anahtarlar sirali, ayiraclar bosluksuz. Hash bu
# gosterim uzerinden alindigi icin kural degistirilirse tum zincir bozulur.
_JSON_SEPARATORS = (",", ":")


@dataclass
class CustodyEvent:
    """Deftere yazilan tek bir gozetim zinciri olayi."""

    event_id: str
    timestamp_utc: datetime
    event_type: str
    case_id: str
    operator: str
    payload: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    # entry_hash defter tarafindan hesaplanip atanir; burada varsayilani bos.
    entry_hash: str = ""

    def __post_init__(self) -> None:
        # tsa_token ileride zaman damgasi otoritesi entegrasyonu icin ayrildi;
        # su an her zaman var ve her zaman null.
        self.payload.setdefault("tsa_token", None)

    def to_hashable_dict(self) -> dict[str, Any]:
        """entry_hash HARIC tum alanlar (dairesellik olmasin diye)."""
        return {
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc.astimezone(timezone.utc).isoformat(),
            "event_type": self.event_type,
            "case_id": self.case_id,
            "operator": self.operator,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }

    def canonical_json_bytes(self) -> bytes:
        """Hash hesabinda kullanilan kanonik JSON gosterimi."""
        return json.dumps(
            self.to_hashable_dict(),
            sort_keys=True,
            separators=_JSON_SEPARATORS,
            ensure_ascii=False,
        ).encode("utf-8")

    def to_json_line(self) -> str:
        """Deftere yazilacak tek satirlik JSONL gosterimi (entry_hash dahil)."""
        data = self.to_hashable_dict()
        data["entry_hash"] = self.entry_hash
        return json.dumps(data, sort_keys=True, separators=_JSON_SEPARATORS, ensure_ascii=False)

    @classmethod
    def from_json_line(cls, line: str) -> "CustodyEvent":
        """JSONL satirini tekrar CustodyEvent'e cevirir."""
        data = json.loads(line)
        return cls(
            event_id=data["event_id"],
            timestamp_utc=datetime.fromisoformat(data["timestamp_utc"]),
            event_type=data["event_type"],
            case_id=data["case_id"],
            operator=data["operator"],
            payload=data.get("payload", {}),
            prev_hash=data["prev_hash"],
            entry_hash=data.get("entry_hash", ""),
        )
