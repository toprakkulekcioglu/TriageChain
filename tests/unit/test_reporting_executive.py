"""Yonetici Raporu ozeti: risk seviyesi kurali sadece Report'taki gercek
sayilardan turer, hicbir sey uydurulmaz -- bkz. reporting/executive.py."""

from datetime import datetime, timezone

from triagechain.detection.correlation import CorrelatedArtifact, EngineAgreement
from triagechain.detection.models import Finding
from triagechain.reporting.executive import assess_risk, build_executive_summary
from triagechain.reporting.models import (
    ChainStatus,
    CollectionSummary,
    DetectionSummary,
    Report,
    YaraSummary,
)

NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _collection(artifact_count=5, error_count=0):
    return CollectionSummary(
        run_id="run-1", started_at_utc=NOW, ended_at_utc=NOW, artifact_count=artifact_count,
        error_count=error_count,
    )


def _chain(is_valid=True, message="zincir tutarli"):
    return ChainStatus(
        is_valid=is_valid, total_events=10, broken_at_event_id=None if is_valid else "evt-3",
        message=message,
    )


def _finding(level):
    return Finding(
        artifact_type_id="event_logs", source_path="C:/x.evtx", rule_title="Kural",
        level=level, timestamp="2026-06-07 22:00:00", computer="WS-01", channel="Security",
        event_id="4688", details="",
    )


def _detection(findings):
    return DetectionSummary(
        run_id="run-2", started_at_utc=NOW, ended_at_utc=NOW, scanned_count=1,
        finding_count=len(findings), level_counts={}, findings=list(findings),
    )


def _yara_summary(match_count):
    return YaraSummary(
        run_id="run-yara", started_at_utc=NOW, ended_at_utc=NOW, scanned_count=1,
        match_count=match_count,
    )


def _report(
    collection, chain_status, detection=None, yara=None, correlated=None,
    chainsaw=None, engine_agreements=None, capa=None,
):
    return Report(
        case_id="CASE-X", operator="e.demir", description="", collection=collection,
        chain_status=chain_status, detection=detection, yara=yara,
        correlated_artifacts=correlated or [], chainsaw=chainsaw,
        engine_agreements=engine_agreements or [], capa=capa,
    )


def test_gecersiz_zincir_her_zaman_kritik_dondurur():
    """Bulgu olmasa bile zincir bozuksa risk KRITIK olmali -- en ciddi sinyal."""
    report = _report(_collection(), _chain(is_valid=False, message="hash uyusmazligi"))
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "hash uyusmazligi" in reason


def test_yuksek_onemli_bulgu_yuksek_risk_dondurur():
    report = _report(
        _collection(), _chain(), _detection([_finding("critical"), _finding("low")])
    )
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "1" in reason


def test_sadece_dusuk_onemli_bulgu_orta_risk_dondurur():
    report = _report(_collection(), _chain(), _detection([_finding("low"), _finding("medium")]))
    level, _ = assess_risk(report)
    assert level == "Orta"


def test_bulgu_yok_ama_toplama_hatasi_var_dusuk_risk_dondurur():
    report = _report(_collection(error_count=2), _chain(), _detection([]))
    level, _ = assess_risk(report)
    assert level == "Düşük"


def test_hicbir_sorun_yoksa_bulgu_yok_dondurur():
    report = _report(_collection(), _chain(), detection=None)
    level, _ = assess_risk(report)
    assert level == "Bulgu Yok"


def test_capa_eslesmeleri_risk_seviyesini_ETKILEMEZ():
    """capa 'yetenek' tespit eder, kotu amacli davranis degil -- gercek,
    zararsiz bir .exe'de bile onlarca capa kurali eslesir (bkz. aldigim_
    kararlar.md -> 'capa entegrasyonu'). Bulgu/YARA/korelasyon yoksa capa
    tek basina risk seviyesini yukseltmemeli."""
    report = _report(_collection(), _chain(), detection=None, capa=_yara_summary(35))
    level, _ = assess_risk(report)
    assert level == "Bulgu Yok"

    summary = build_executive_summary(report)
    assert summary.risk_level == "Bulgu Yok"


def test_korelasyon_varsa_kritik_dondurur_bulgu_seviyesinden_bagimsiz():
    """Iki motor da ayni dosyayi isaretlerse -- yuksek onemli bulgu olmasa
    bile -- risk KRITIK olmali (bkz. assess_risk dokstring'i)."""
    report = _report(
        _collection(), _chain(),
        detection=_detection([_finding("low")]),
        yara=_yara_summary(1),
        correlated=[CorrelatedArtifact(source_path="C:/a.evtx")],
    )
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "1 dosya" in reason


def test_motor_ittifaki_varsa_kritik_dondurur_bulgu_seviyesinden_bagimsiz():
    """Hayabusa VE Chainsaw ayni kurali ayni dosyada bulursa -- yuksek onemli
    bulgu olmasa bile -- risk KRITIK olmali (bkz. assess_risk dokstring'i)."""
    report = _report(
        _collection(), _chain(),
        detection=_detection([_finding("low")]),
        chainsaw=_detection([_finding("low")]),
        engine_agreements=[EngineAgreement(source_path="C:/a.evtx", rule_title="Kural")],
    )
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "1 dosya" in reason


def test_chainsaw_yuksek_onemli_bulgu_tek_basina_yuksek_risk_dondurur():
    """Hayabusa hic calismamis olsa bile Chainsaw'in tek basina buldugu
    yuksek/kritik bulgu Yuksek risk demektir."""
    report = _report(
        _collection(), _chain(), detection=None,
        chainsaw=_detection([_finding("critical")]),
    )
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "1" in reason


def test_yara_eslesmesi_tek_basina_yuksek_risk_dondurur():
    """Sigma hic calismamis olsa bile bir YARA eslesmesi Yuksek risk demektir."""
    report = _report(_collection(), _chain(), detection=None, yara=_yara_summary(3))
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "3" in reason


def test_yonetici_ozeti_teknik_terim_icermeyen_bir_anlati_uretir():
    report = _report(
        _collection(artifact_count=7), _chain(), _detection([_finding("high")])
    )
    summary = build_executive_summary(report)

    assert summary.risk_level == "Yüksek"
    assert summary.artifact_count == 7
    assert summary.finding_count == 1
    assert summary.high_severity_count == 1
    assert summary.chain_is_valid is True
    assert "CASE-X" in summary.narrative
    assert "7 dosya" in summary.narrative
    # Teknik jargon ("manifest", "custody", "Sigma") yonetici ozetine sizmamali.
    for jargon in ("manifest", "custody", "Sigma", "run_id"):
        assert jargon not in summary.narrative


def test_ozet_chainsaw_bulgularini_hayabusa_ile_birlikte_sayar():
    """finding_count/high_severity_count Hayabusa VE Chainsaw'in toplami
    olmali -- ikisi de ayni DetectionSummary semasini kullaniyor."""
    report = _report(
        _collection(), _chain(),
        detection=_detection([_finding("high")]),
        chainsaw=_detection([_finding("critical"), _finding("low")]),
    )
    summary = build_executive_summary(report)

    assert summary.finding_count == 3
    assert summary.high_severity_count == 2


def test_ozet_motor_ittifakini_anlatiya_ekler():
    report = _report(
        _collection(), _chain(),
        detection=_detection([_finding("low")]), chainsaw=_detection([_finding("low")]),
        engine_agreements=[EngineAgreement(source_path="C:/a.evtx", rule_title="Kural")],
    )
    summary = build_executive_summary(report)

    assert summary.engine_agreement_count == 1
    assert "bağımsız davranışsal tarama motoru" in summary.narrative
