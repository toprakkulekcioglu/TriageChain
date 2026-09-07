"""Rapor uretimi: diskteki manifestleri ve custody defterini tek bir Report'a toplar.

Bu katman dis program CALISTIRMAZ ve custody defterine YAZMAZ; yalnizca okur.
Rapor, zincirin uretim anindaki durumunun fotografidir - rapor uretimi kendi
basina bir olay yazsaydi, raporun icindeki olay listesi ve `verify_chain`
sonucu yazildigi anda eskimis olurdu (bkz. docs/aldigim_kararlar.md).
"""

from __future__ import annotations

import logging
from pathlib import Path

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectionManifest
from triagechain.config.loader import (
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_report_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ReportingError
from triagechain.custody.ledger import read_events, verify_chain
from triagechain.detection.correlation import correlate_findings, correlate_sigma_engines
from triagechain.detection.models import DetectionManifest, YaraManifest
from triagechain.reporting.models import (
    ChainStatus,
    CollectionSummary,
    CustodyEventSummary,
    DetectionSummary,
    Report,
    RoutingSummary,
    YaraSummary,
)
from triagechain.reporting.renderer import render_html
from triagechain.reporting.timeline import TimelineEvent, build_timeline
from triagechain.router.models import RoutingManifest

logger = logging.getLogger(__name__)


def build_report(config: TriageChainConfig) -> Report:
    """Vakanin ciktilarini okuyup raporu olusturur (diske yazmaz)."""
    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        # CLI bu durumu zaten kendi kontrol edip cikis kodu 2 ile duruyor; bu
        # kontrol dogrudan cagiran taraflar (GUI, testler) icin ham bir
        # FileNotFoundError yerine tipli hata dondurmek amaciyla var.
        raise ReportingError(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali."
        )
    collection = CollectionManifest.from_json_file(manifest_path)

    log_path = resolve_custody_log_path(config)
    # verify_chain defter yoksa CustodyLedgerError firlatir; bu olumcul ve
    # dogrusu da bu - manifest varken defterin olmamasi zincirin kaybi demektir.
    chain = verify_chain(log_path, config.case.case_id)

    detection_path = resolve_detection_manifest_path(config)
    yara_path = resolve_yara_manifest_path(config)
    chainsaw_path = resolve_chainsaw_manifest_path(config)
    correlated_artifacts = []
    engine_agreements = []
    if detection_path.exists() and yara_path.exists():
        # Korelasyon SADECE iki motor de calismissa anlamli -- biri eksikse
        # "kesisim" kavraminin kendisi bos/yanlis olurdu (bkz. testler).
        correlated_artifacts = correlate_findings(
            DetectionManifest.from_json_file(detection_path),
            YaraManifest.from_json_file(yara_path),
        )
    if detection_path.exists() and chainsaw_path.exists():
        engine_agreements = correlate_sigma_engines(
            DetectionManifest.from_json_file(detection_path),
            DetectionManifest.from_json_file(chainsaw_path),
        )

    return Report(
        case_id=config.case.case_id,
        operator=config.case.operator,
        description=config.case.description,
        collection=CollectionSummary(
            run_id=collection.run_id,
            started_at_utc=collection.started_at_utc,
            ended_at_utc=collection.ended_at_utc,
            artifact_count=len(collection.artifacts),
            error_count=len(collection.errors),
        ),
        chain_status=ChainStatus(
            is_valid=chain.is_valid,
            total_events=chain.total_events,
            broken_at_event_id=chain.broken_at_event_id,
            message=chain.message,
        ),
        routing=_routing_summary(config),
        detection=_detection_summary(config),
        yara=_yara_summary(config),
        chainsaw=_chainsaw_summary(config),
        capa=_capa_summary(config),
        correlated_artifacts=correlated_artifacts,
        engine_agreements=engine_agreements,
        timeline=_timeline(config),
        custody_events=[
            CustodyEventSummary(
                event_id=event.event_id,
                timestamp_utc=event.timestamp_utc,
                event_type=event.event_type,
                operator=event.operator,
                payload=event.payload,
            )
            for event in read_events(log_path)
        ],
    )


def write_report(config: TriageChainConfig, report: Report) -> tuple[Path, Path, Path]:
    """Raporu report.json + report.json.sha256 + report.html olarak yazar.

    sha256 yan dosyasi, raporun KENDISININ sonradan degisip degismedigini
    zincire bakmadan kontrol etmeye yarar; bu yuzden JSON yazildiktan SONRA,
    dosyanin gercek icerigi uzerinden hesaplanir.
    """
    json_path = resolve_report_path(config)
    sha_path = json_path.with_name(json_path.name + ".sha256")
    html_path = json_path.with_suffix(".html")

    try:
        report.to_json_file(json_path)
        # sha256sum ile dogrudan dogrulanabilsin diye "<hash>  <dosya>" bicimi.
        sha_path.write_text(
            f"{hash_file(json_path)}  {json_path.name}\n", encoding="utf-8"
        )
        html_path.write_text(render_html(report), encoding="utf-8")
    except OSError as exc:
        raise ReportingError(f"Rapor dosyalari yazilamadi: {json_path.parent} ({exc})") from exc

    return json_path, sha_path, html_path


def _timeline(config: TriageChainConfig) -> list[TimelineEvent]:
    """routing_manifest.json varsa MFTECmd/RECmd/EvtxECmd/PECmd ciktilarindan
    birlestirilmis zaman cizelgesini dondurur; yoksa bos liste (hata degil) --
    diger opsiyonel bolumlerle AYNI desen (bkz. reporting/timeline.py)."""
    path = resolve_routing_manifest_path(config)
    if not path.exists():
        logger.info("[report] Yonlendirme manifesti yok (%s), zaman cizelgesi bos kalacak.", path)
        return []
    return build_timeline(RoutingManifest.from_json_file(path))


def _routing_summary(config: TriageChainConfig) -> RoutingSummary | None:
    """routing_manifest.json varsa ozetini dondurur; yoksa None (hata degil)."""
    path = resolve_routing_manifest_path(config)
    if not path.exists():
        logger.info("[report] Yonlendirme manifesti yok (%s), bu bolum bos kalacak.", path)
        return None
    routing: RoutingManifest = RoutingManifest.from_json_file(path)
    return RoutingSummary(
        run_id=routing.run_id,
        started_at_utc=routing.started_at_utc,
        ended_at_utc=routing.ended_at_utc,
        processed_count=len(routing.processed),
        skipped_count=len(routing.skipped),
        error_count=len(routing.errors),
    )


def _yara_summary(config: TriageChainConfig) -> YaraSummary | None:
    """yara_manifest.json varsa ozetini dondurur; yoksa None (hata degil) --
    _detection_summary ile ayni desen."""
    return _yara_shaped_summary(resolve_yara_manifest_path(config), "YARA")


def _capa_summary(config: TriageChainConfig) -> YaraSummary | None:
    """capa_manifest.json varsa ozetini dondurur; yoksa None -- YARA ile AYNI
    YaraManifest/YaraMatch semasini kullanir (bkz. detection/capa_runner.py),
    bu yuzden AYNI ozetleme mantigini paylasir (bkz. _yara_shaped_summary)."""
    return _yara_shaped_summary(resolve_capa_manifest_path(config), "capa")


def _yara_shaped_summary(path: Path, label: str) -> YaraSummary | None:
    """YARA ve capa icin ortak ozetleme -- ikisi de ayni YaraManifest/
    YaraMatch semasini uretiyor (bkz. yukaridaki iki fonksiyon)."""
    if not path.exists():
        logger.info("[report] %s manifesti yok (%s), bu bolum bos kalacak.", label, path)
        return None
    yara_manifest: YaraManifest = YaraManifest.from_json_file(path)
    return YaraSummary(
        run_id=yara_manifest.run_id,
        started_at_utc=yara_manifest.started_at_utc,
        ended_at_utc=yara_manifest.ended_at_utc,
        scanned_count=len(yara_manifest.scanned),
        match_count=len(yara_manifest.matches),
        skipped_count=len(yara_manifest.skipped),
        error_count=len(yara_manifest.errors),
        matches=list(yara_manifest.matches),
    )


def _detection_summary(config: TriageChainConfig) -> DetectionSummary | None:
    """detection_manifest.json (Hayabusa) varsa ozetini dondurur; yoksa None."""
    return _sigma_engine_summary(resolve_detection_manifest_path(config), "Tespit (Hayabusa)")


def _chainsaw_summary(config: TriageChainConfig) -> DetectionSummary | None:
    """chainsaw_manifest.json varsa ozetini dondurur; yoksa None -- Hayabusa
    ile AYNI DetectionManifest/Finding semasini kullandigi icin AYNI ozetleme
    mantigini paylasir (bkz. _sigma_engine_summary)."""
    return _sigma_engine_summary(resolve_chainsaw_manifest_path(config), "Chainsaw")


def _sigma_engine_summary(path: Path, label: str) -> DetectionSummary | None:
    """Hem Hayabusa hem Chainsaw icin ortak ozetleme -- ikisi de ayni
    DetectionManifest/Finding semasini uretiyor (bkz. yukaridaki iki fonksiyon)."""
    if not path.exists():
        logger.info("[report] %s manifesti yok (%s), bu bolum bos kalacak.", label, path)
        return None
    detection: DetectionManifest = DetectionManifest.from_json_file(path)

    # Seviye dagilimi detection/runner.py ile ayni kurala gore: kucuk harf,
    # bos seviye "bilinmiyor" sayilir.
    level_counts: dict[str, int] = {}
    for finding in detection.findings:
        key = finding.level.lower() or "bilinmiyor"
        level_counts[key] = level_counts.get(key, 0) + 1

    return DetectionSummary(
        run_id=detection.run_id,
        started_at_utc=detection.started_at_utc,
        ended_at_utc=detection.ended_at_utc,
        scanned_count=len(detection.scanned),
        finding_count=len(detection.findings),
        level_counts=level_counts,
        skipped_count=len(detection.skipped),
        error_count=len(detection.errors),
        findings=list(detection.findings),
    )
