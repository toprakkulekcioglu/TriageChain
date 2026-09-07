"""Rapor ciktisinin veri modelleri: vaka ozeti, katman ozetleri ve zincir durumu.

Serilestirme deseni collection/router/detection manifestleriyle BIREBIR ayni
(`to_dict` + `to_json_file` + `from_json_file` + `_iso`), boylece dort dosya
ayni sekilde okunup yazilabiliyor.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from triagechain.detection.correlation import CorrelatedArtifact, EngineAgreement
from triagechain.detection.models import Finding, YaraMatch
from triagechain.reporting.timeline import TimelineEvent


@dataclass
class CollectionSummary:
    """manifest.json'dan cikarilan toplama ozeti."""

    run_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime]
    artifact_count: int
    error_count: int


@dataclass
class RoutingSummary:
    """routing_manifest.json'dan cikarilan yonlendirme ozeti."""

    run_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime]
    processed_count: int
    skipped_count: int
    error_count: int


@dataclass
class DetectionSummary:
    """detection_manifest.json'dan cikarilan tespit ozeti."""

    run_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime]
    scanned_count: int
    finding_count: int
    # Bulgu seviyesi (critical/high/...) -> o seviyedeki bulgu sayisi.
    level_counts: dict[str, int] = field(default_factory=dict)
    skipped_count: int = 0
    error_count: int = 0
    # Bulgularin kendisi de rapora kopyalanir: rapor tek basina okunabilir olmali.
    findings: list[Finding] = field(default_factory=list)


@dataclass
class YaraSummary:
    """yara_manifest.json'dan cikarilan YARA tarama ozeti -- DetectionSummary
    ile ayni desen."""

    run_id: str
    started_at_utc: datetime
    ended_at_utc: Optional[datetime]
    scanned_count: int
    match_count: int
    skipped_count: int = 0
    error_count: int = 0
    matches: list[YaraMatch] = field(default_factory=list)


@dataclass
class CustodyEventSummary:
    """Deftere yazilmis tek bir olayin rapora giren hali.

    prev_hash/entry_hash rapora alinmaz: zincirin gecerli olup olmadigi zaten
    ayrica (ChainStatus) yaziliyor, ham hash'ler raporu okunmaz hale getirirdi.
    Hash'lerin kendisi her zaman custody.jsonl'de duruyor.
    """

    event_id: str
    timestamp_utc: datetime
    event_type: str
    operator: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainStatus:
    """Raporun uretildigi ANDAKI verify_chain sonucu."""

    is_valid: bool
    total_events: int
    broken_at_event_id: Optional[str]
    message: str


@dataclass
class Report:
    """Bir vakanin tam raporu."""

    case_id: str
    operator: str
    description: str
    collection: CollectionSummary
    chain_status: ChainStatus
    manifest_version: str = "1.0"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_generated_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # None = ilgili komut (route/detect/yara-scan) bu vaka icin hic calistirilmamis.
    routing: Optional[RoutingSummary] = None
    detection: Optional[DetectionSummary] = None
    yara: Optional[YaraSummary] = None
    # Hayabusa ile AYNI DetectionSummary/Finding semasini kullanir -- ikinci,
    # BAGIMSIZ bir Sigma motoru (capraz dogrulama icin, bkz. correlation.py).
    chainsaw: Optional[DetectionSummary] = None
    # Hem Sigma/Hayabusa HEM YARA'nin isaretledigi dosyalar -- ikisi de
    # calismamissa ya da kesisim bossa bos liste (bkz. detection/correlation.py).
    correlated_artifacts: list[CorrelatedArtifact] = field(default_factory=list)
    # Hayabusa VE Chainsaw'in AYNI kurali AYNI dosyada bulduğu durumlar.
    engine_agreements: list[EngineAgreement] = field(default_factory=list)
    # YARA ile AYNI YaraSummary/YaraMatch semasini kullanir -- capa da (YARA
    # gibi) TEK bir dosyaya karsi calisip adlandirilmis kural eslesmeleri
    # uretir (bkz. detection/capa_runner.py). BILEREK risk hesabina
    # (reporting/executive.py) KATILMAZ: capa "yetenek" tespit eder, "kotu
    # amacli davranis" degil -- gercek, zararsiz bir .exe'de bile onlarca
    # capa kurali eslesir (bkz. aldigim_kararlar.md -> "capa entegrasyonu").
    capa: Optional[YaraSummary] = None
    # MFTECmd/RECmd/EvtxECmd/PECmd ciktilarindan birlestirilmis, kronolojik
    # zaman cizelgesi -- routing_manifest.json yoksa veya araclarin hicbiri
    # CSV uretmemisse bos liste (bkz. reporting/timeline.py).
    timeline: list[TimelineEvent] = field(default_factory=list)
    custody_events: list[CustodyEventSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Duz sozluge cevirir; datetime alanlari ISO-8601 metne donusur."""
        data = asdict(self)
        data["report_generated_at_utc"] = _iso(self.report_generated_at_utc)
        for key, summary in (
            ("collection", self.collection),
            ("routing", self.routing),
            ("detection", self.detection),
            ("yara", self.yara),
            ("chainsaw", self.chainsaw),
            ("capa", self.capa),
        ):
            if summary is not None:
                data[key]["started_at_utc"] = _iso(summary.started_at_utc)
                data[key]["ended_at_utc"] = _iso(summary.ended_at_utc)
        for event, raw in zip(self.custody_events, data["custody_events"]):
            raw["timestamp_utc"] = _iso(event.timestamp_utc)
        return data

    def to_json_file(self, path: Path) -> None:
        """Raporu JSON olarak diske yazar."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "Report":
        """Diskteki raporu geri okur."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        detection_raw = data.get("detection")
        detection = None
        if detection_raw is not None:
            findings = [Finding(**raw) for raw in detection_raw.pop("findings", [])]
            detection = DetectionSummary(**_with_times(detection_raw), findings=findings)

        yara_raw = data.get("yara")
        yara = None
        if yara_raw is not None:
            matches = [YaraMatch(**raw) for raw in yara_raw.pop("matches", [])]
            yara = YaraSummary(**_with_times(yara_raw), matches=matches)

        chainsaw_raw = data.get("chainsaw")
        chainsaw = None
        if chainsaw_raw is not None:
            findings = [Finding(**raw) for raw in chainsaw_raw.pop("findings", [])]
            chainsaw = DetectionSummary(**_with_times(chainsaw_raw), findings=findings)

        capa_raw = data.get("capa")
        capa = None
        if capa_raw is not None:
            matches = [YaraMatch(**raw) for raw in capa_raw.pop("matches", [])]
            capa = YaraSummary(**_with_times(capa_raw), matches=matches)

        return cls(
            case_id=data["case_id"],
            operator=data["operator"],
            description=data.get("description", ""),
            collection=CollectionSummary(**_with_times(data["collection"])),
            chain_status=ChainStatus(**data["chain_status"]),
            manifest_version=data.get("manifest_version", "1.0"),
            run_id=data["run_id"],
            report_generated_at_utc=datetime.fromisoformat(data["report_generated_at_utc"]),
            routing=(
                RoutingSummary(**_with_times(data["routing"]))
                if data.get("routing") is not None
                else None
            ),
            detection=detection,
            yara=yara,
            chainsaw=chainsaw,
            capa=capa,
            correlated_artifacts=[
                CorrelatedArtifact(**raw) for raw in data.get("correlated_artifacts", [])
            ],
            engine_agreements=[
                EngineAgreement(**raw) for raw in data.get("engine_agreements", [])
            ],
            timeline=[TimelineEvent(**raw) for raw in data.get("timeline", [])],
            custody_events=[
                CustodyEventSummary(
                    **{**raw, "timestamp_utc": datetime.fromisoformat(raw["timestamp_utc"])}
                )
                for raw in data.get("custody_events", [])
            ],
        )


def _with_times(raw: dict[str, Any]) -> dict[str, Any]:
    """Ozet sozlugundeki started/ended alanlarini datetime'a cevirir."""
    return {
        **raw,
        "started_at_utc": datetime.fromisoformat(raw["started_at_utc"]),
        "ended_at_utc": (
            datetime.fromisoformat(raw["ended_at_utc"]) if raw.get("ended_at_utc") else None
        ),
    }


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Datetime'i UTC ISO-8601 metnine cevirir (None ise None)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()
