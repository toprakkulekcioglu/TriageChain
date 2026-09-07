"""Tespit ciktisinin veri modelleri: tekil bulgu ve tespit manifesti."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class Finding:
    """Bir Sigma kuralinin tek bir olay uzerinde urettigi tespit.

    Alanlarin tamami metindir: aracin CSV ciktisi en iyi caba ile ayristirilir,
    okunamayan/olmayan bir sutun bos kalir - tip donusumu zorlanmaz.
    """

    artifact_type_id: str
    # Taranan .evtx dosyasinin yolu (vakanin artifacts agacindaki kopyasi).
    source_path: str
    rule_title: str
    level: str
    timestamp: str
    computer: str
    channel: str
    event_id: str
    details: str
    # Sigma kurallarinin KENDI metadatasinda zaten var olan MITRE ATT&CK
    # teknik/taktik etiketleri (orn. "attack.t1055,attack.defense-evasion") --
    # Hayabusa bunlari CSV'ye tasiyorsa aynen yuzeye cikarilir, YENI bir veri
    # kaynagi/internet cagrisi DEGIL (bkz. detection/catalog/hayabusa_args.yaml).
    mitre_tags: str = ""


@dataclass
class DetectionManifest:
    """Bir tespit kosusunun tam dokumu."""

    case_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime] = None
    manifest_version: str = "1.0"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    findings: list[Finding] = field(default_factory=list)
    # Taranan her dosya icin bir ozet: source_path, output_csv_path,
    # finding_count, level_counts, duration_seconds ve varsa parse_warning.
    scanned: list[dict[str, Any]] = field(default_factory=list)
    # Atlananlar: arac konfigure edilmemis / arac yolu yok / taranacak .evtx yok.
    skipped: list[dict[str, Any]] = field(default_factory=list)
    # Hatalar: sifirdan farkli cikis kodu, zaman asimi, cikti agaci disinda yol.
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Duz sozluge cevirir; datetime alanlari ISO-8601 metne donusur."""
        data = asdict(self)
        data["started_at_utc"] = _iso(self.started_at_utc)
        data["ended_at_utc"] = _iso(self.ended_at_utc)
        return data

    def to_json_file(self, path: Path) -> None:
        """Manifesti JSON olarak diske yazar."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "DetectionManifest":
        """Diskteki manifesti geri okur."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            case_id=data["case_id"],
            started_at_utc=datetime.fromisoformat(data["started_at_utc"]),
            ended_at_utc=(
                datetime.fromisoformat(data["ended_at_utc"]) if data.get("ended_at_utc") else None
            ),
            manifest_version=data.get("manifest_version", "1.0"),
            run_id=data["run_id"],
            findings=[Finding(**raw) for raw in data.get("findings", [])],
            scanned=data.get("scanned", []),
            skipped=data.get("skipped", []),
            errors=data.get("errors", []),
        )


@dataclass
class YaraMatch:
    """Bir YARA kuralinin tek bir dosya uzerinde urettigi imza eslesmesi.

    Finding'den (Sigma/Hayabusa, olay-gunlugu temelli) BILEREK ayri bir tip:
    YARA statik dosya imzalamasi yapar, computer/channel/event_id gibi bir
    olay baglaminin karsiligi yok. Ortak nokta source_path -- iki motorun
    AYNI dosyayi isaretleyip isaretlemedigi buradan korele edilir (bkz.
    detection/correlation.py).
    """

    artifact_type_id: str
    source_path: str
    rule_name: str
    # Kuralin kendi tag'leri, virgulle ayrilmis (orn. "malware,mimikatz") --
    # Finding.mitre_tags ile ayni "metadata zaten var, aynen yuzeye cikar" fikri.
    tags: str = ""
    # Kuralin meta blogundaki anahtar/deger ciftleri, "k=v, k2=v2" biciminde.
    meta: str = ""


@dataclass
class YaraManifest:
    """Bir YARA tarama kosusunun tam dokumu -- DetectionManifest ile BIREBIR
    ayni yapi/serilestirme deseni (kasitli: iki motoru ogrenen biri ayni
    sekli bulsun)."""

    case_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime] = None
    manifest_version: str = "1.0"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    matches: list[YaraMatch] = field(default_factory=list)
    # Taranan her dosya icin ozet: source_path, match_count, duration_seconds.
    scanned: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["started_at_utc"] = _iso(self.started_at_utc)
        data["ended_at_utc"] = _iso(self.ended_at_utc)
        return data

    def to_json_file(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "YaraManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            case_id=data["case_id"],
            started_at_utc=datetime.fromisoformat(data["started_at_utc"]),
            ended_at_utc=(
                datetime.fromisoformat(data["ended_at_utc"]) if data.get("ended_at_utc") else None
            ),
            manifest_version=data.get("manifest_version", "1.0"),
            run_id=data["run_id"],
            matches=[YaraMatch(**raw) for raw in data.get("matches", [])],
            scanned=data.get("scanned", []),
            skipped=data.get("skipped", []),
            errors=data.get("errors", []),
        )


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Datetime'i UTC ISO-8601 metnine cevirir (None ise None)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()
