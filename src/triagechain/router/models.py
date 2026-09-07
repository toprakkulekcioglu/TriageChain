"""Yonlendirme ciktisinin veri modelleri: islenmis artefakt kaydi ve manifest."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class ProcessedArtifact:
    """Bir dis arac tarafindan basariyla ayristirilmis tek bir artefakt."""

    artifact_type_id: str
    tool: str
    # Toplama manifestindeki dest_path; araca girdi olarak verilen dosya.
    source_path: str
    output_dir: str
    exit_code: int
    stdout_log_path: str
    stderr_log_path: str
    duration_seconds: float
    processed_at_utc: datetime


@dataclass
class RoutingManifest:
    """Bir yonlendirme kosusunun tam dokumu."""

    case_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime] = None
    manifest_version: str = "1.0"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    processed: list[ProcessedArtifact] = field(default_factory=list)
    # Atlananlar: arac konfigure edilmemis / arac yolu yok / tanimli rota yok.
    # Her ogede en az artifact_type_id, source_path ve message bulunur.
    skipped: list[dict[str, Any]] = field(default_factory=list)
    # Hatalar: sifirdan farkli cikis kodu, zaman asimi, cikti agaci disinda yol.
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Duz sozluge cevirir; datetime alanlari ISO-8601 metne donusur."""
        data = asdict(self)
        data["started_at_utc"] = _iso(self.started_at_utc)
        data["ended_at_utc"] = _iso(self.ended_at_utc)
        for item, raw in zip(self.processed, data["processed"]):
            raw["processed_at_utc"] = _iso(item.processed_at_utc)
        return data

    def to_json_file(self, path: Path) -> None:
        """Manifesti JSON olarak diske yazar."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "RoutingManifest":
        """Diskteki manifesti geri okur."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        processed = [
            ProcessedArtifact(
                **{**raw, "processed_at_utc": datetime.fromisoformat(raw["processed_at_utc"])}
            )
            for raw in data.get("processed", [])
        ]
        return cls(
            case_id=data["case_id"],
            started_at_utc=datetime.fromisoformat(data["started_at_utc"]),
            ended_at_utc=(
                datetime.fromisoformat(data["ended_at_utc"]) if data.get("ended_at_utc") else None
            ),
            manifest_version=data.get("manifest_version", "1.0"),
            run_id=data["run_id"],
            processed=processed,
            skipped=data.get("skipped", []),
            errors=data.get("errors", []),
        )


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Datetime'i UTC ISO-8601 metnine cevirir (None ise None)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()
