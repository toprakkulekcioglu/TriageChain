"""Rapor katmani: eksik/tam manifest senaryolari, sha256 yan dosyasi, kirik zincir.

Hicbir test dis program calistirmaz; manifestler dogrudan yazilir, custody
defteri gercek CustodyLedger ile uretilir.
"""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.loader import (
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ReportingError
from triagechain.custody.ledger import CustodyLedger, read_events
from triagechain.detection.models import DetectionManifest, Finding, YaraManifest, YaraMatch
from triagechain.reporting.builder import build_report, write_report
from triagechain.reporting.models import Report
from triagechain.router.models import ProcessedArtifact, RoutingManifest

CASE_ID = "CASE-TEST-REPORT"
OPERATOR = "test.operator"


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def config(tmp_path):
    """Rapor icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": OPERATOR, "description": "Rapor testi"},
        collection={
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
    )


def _write_collection(config) -> CollectionManifest:
    """Sahte bir toplama kosusu: iki custody olayi + manifest.json."""
    ledger = CustodyLedger(resolve_custody_log_path(config), CASE_ID)
    manifest = CollectionManifest(case_id=CASE_ID, started_at_utc=_now())
    ledger.append_event("case_opened", OPERATOR, {"run_id": manifest.run_id})

    dest = Path(config.collection.output_dir) / CASE_ID / "artifacts" / "prefetch" / "APP.pf"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"sahte artefakt")
    manifest.artifacts.append(
        CollectedArtifact(
            artifact_type_id="prefetch",
            source_path=r"C:\Windows\Prefetch\APP.pf",
            dest_path=str(dest),
            hash_value="0" * 64,
            hash_algorithm="sha256",
            size_bytes=14,
            collected_at_utc=_now(),
            collecting_user=OPERATOR,
            case_id=CASE_ID,
        )
    )
    manifest.errors.append({"artifact_type_id": "prefetch", "message": "MISSING.pf bulunamadi"})
    manifest.ended_at_utc = _now()
    ledger.append_event("case_closed", OPERATOR, {"run_id": manifest.run_id})
    manifest.to_json_file(resolve_manifest_path(config))
    return manifest


def _write_routing(config) -> RoutingManifest:
    """Sahte bir yonlendirme kosusu."""
    routing = RoutingManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch",
            tool="pecmd",
            source_path="APP.pf",
            output_dir="parsed/pecmd/prefetch",
            exit_code=0,
            stdout_log_path="APP.pf.stdout.log",
            stderr_log_path="APP.pf.stderr.log",
            duration_seconds=0.5,
            processed_at_utc=_now(),
        )
    )
    routing.skipped.append({"artifact_type_id": "mft", "message": "arac konfigure edilmemis"})
    routing.to_json_file(resolve_routing_manifest_path(config))
    return routing


def _write_detection(config) -> DetectionManifest:
    """Sahte bir tespit kosusu: iki farkli seviyede bulgu."""
    detection = DetectionManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    for title, level in (("Mimikatz Detected", "critical"), ("Failed Logon", "low")):
        detection.findings.append(
            Finding(
                artifact_type_id="event_logs",
                source_path="Security.evtx",
                rule_title=title,
                level=level,
                timestamp="2026-01-02 03:04:05.678 +03:00",
                computer="WS-01",
                channel="Security",
                event_id="4688",
                details="ayrinti",
            )
        )
    detection.scanned.append(
        {"source_path": "Security.evtx", "finding_count": 2, "level_counts": {}}
    )
    detection.to_json_file(resolve_detection_manifest_path(config))
    return detection


def _write_chainsaw(config, rule_title="Mimikatz Detected", source_path="Security.evtx") -> DetectionManifest:
    """Sahte bir Chainsaw kosusu -- Hayabusa ile AYNI DetectionManifest/Finding
    semasini kullanir (bkz. detection/chainsaw_runner.py)."""
    chainsaw = DetectionManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    chainsaw.findings.append(
        Finding(
            artifact_type_id="event_logs", source_path=source_path, rule_title=rule_title,
            level="critical", timestamp="2026-01-02 03:04:05.678 +03:00", computer="WS-01",
            channel="Security", event_id="4688", details="ayrinti",
        )
    )
    chainsaw.scanned.append({"source_path": source_path, "finding_count": 1, "level_counts": {}})
    chainsaw.to_json_file(resolve_chainsaw_manifest_path(config))
    return chainsaw


def _write_yara(config, matched_source_path=None) -> YaraManifest:
    """Sahte bir YARA kosusu. matched_source_path verilirse, o dosyayi
    isaretleyen bir eslesme eklenir (korelasyon testleri icin)."""
    yara_manifest = YaraManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    if matched_source_path:
        yara_manifest.matches.append(
            YaraMatch(
                artifact_type_id="event_logs", source_path=matched_source_path,
                rule_name="Mimikatz_Strings", tags="malware",
            )
        )
    yara_manifest.scanned.append({"source_path": matched_source_path or "x", "match_count": 1})
    yara_manifest.to_json_file(resolve_yara_manifest_path(config))
    return yara_manifest


def _write_capa(config, rule_name="link function at runtime on Windows", source_path="C:/supheli/ornek.exe"):
    """Sahte bir capa kosusu -- YARA ile AYNI YaraManifest/YaraMatch semasini
    kullanir (bkz. detection/capa_runner.py)."""
    capa_manifest = YaraManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    capa_manifest.matches.append(
        YaraMatch(
            artifact_type_id="suspicious_binary", source_path=source_path,
            rule_name=rule_name, tags="T1129", meta="namespace=linking/runtime-linking",
        )
    )
    capa_manifest.scanned.append({"source_path": source_path, "match_count": 1})
    capa_manifest.to_json_file(resolve_capa_manifest_path(config))
    return capa_manifest


def test_only_collection_leaves_other_sections_empty(config):
    """Sadece toplama varsa yonlendirme/tespit bolumleri 'henuz calistirilmadi' olmali."""
    collection = _write_collection(config)

    report = build_report(config)

    assert report.case_id == CASE_ID
    assert report.operator == OPERATOR
    assert report.description == "Rapor testi"
    assert report.collection.run_id == collection.run_id
    assert report.collection.artifact_count == 1
    assert report.collection.error_count == 1
    assert report.routing is None
    assert report.detection is None
    assert report.chain_status.is_valid
    assert [e.event_type for e in report.custody_events] == ["case_opened", "case_closed"]

    _, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    # Yonlendirme + tespit + Chainsaw + YARA + capa + watchlist hepsi henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 6
    assert "GEÇERLİ" in html


def test_routing_present_detection_missing(config):
    """Toplama + yonlendirme var, tespit yok."""
    _write_collection(config)
    routing = _write_routing(config)

    report = build_report(config)

    assert report.routing is not None
    assert report.routing.run_id == routing.run_id
    assert (report.routing.processed_count, report.routing.skipped_count) == (1, 1)
    assert report.detection is None

    _, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    # Tespit + Chainsaw + YARA + capa + watchlist henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 5


def test_all_three_layers_fill_findings_table(config):
    """Toplama + yonlendirme + tespit: bulgu tablosu ve seviye dagilimi dolmali."""
    _write_collection(config)
    _write_routing(config)
    _write_detection(config)

    report = build_report(config)

    assert report.detection is not None
    assert report.detection.scanned_count == 1
    assert report.detection.finding_count == 2
    assert report.detection.level_counts == {"critical": 1, "low": 1}

    json_path, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    # Bulgu tablosu: kural/seviye/zaman/bilgisayar
    assert "Mimikatz Detected" in html and "Failed Logon" in html
    assert "WS-01" in html and "2026-01-02 03:04:05.678 +03:00" in html
    # Yonlendirme + tespit calisti, Chainsaw + YARA + capa + watchlist henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 4
    # Rapor tek basina okunabilir olmali: bulgular JSON'a da kopyalanir.
    reloaded = Report.from_json_file(json_path)
    assert [f.rule_title for f in reloaded.detection.findings] == [
        "Mimikatz Detected", "Failed Logon"
    ]
    assert reloaded.run_id == report.run_id
    assert len(reloaded.custody_events) == len(report.custody_events)


def test_html_has_both_yonetici_and_uzman_sekmeleri(config):
    """report.html'de iki sekme de olmali; Yonetici sekmesi risk seviyesini,
    Uzman sekmesi teknik detayi (mevcut _detection_section) tasimali."""
    _write_collection(config)
    _write_detection(config)

    _, _, html_path = write_report(config, build_report(config))
    html = html_path.read_text(encoding="utf-8")

    assert "Yönetici Raporu" in html
    assert "Uzman Raporu" in html
    # Bir critical bulgu var -> risk Yuksek olmali (bkz. reporting/executive.py).
    assert "Risk Seviyesi: Yüksek" in html
    # Teknik detay (kural adi) SADECE uzman panelinde olmali, ama HTML tek
    # dosya oldugu icin string arama panel ayrimini test etmez -- en azindan
    # ikisinin de icerigi var mi kontrol ediliyor.
    assert "Mimikatz Detected" in html


def test_timeline_is_built_from_real_pecmd_csv_and_rendered_in_html(config):
    """routing_manifest.json'daki bir PECmd artefaktinin gercek Timeline
    CSV'si varsa, Report.timeline dolmali ve HTML'e islenmeli (bkz.
    reporting/timeline.py -- gercek PECmd 2026.5.0 ciktisindan alinan
    sutunlarla, aldigim_kararlar.md -> 'Birlesik zaman cizelgesi')."""
    _write_collection(config)
    routing = RoutingManifest(case_id=CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    output_dir = Path(config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8",
    )
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=_now(),
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(config))

    report = build_report(config)

    assert len(report.timeline) == 1
    assert report.timeline[0].tool == "pecmd"
    assert report.timeline[0].timestamp == "2019-06-05 19:23:00"

    json_path, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "Zaman çizelgesi" in html
    assert "NOTEPAD.EXE" in html

    reloaded = Report.from_json_file(json_path)
    assert reloaded.timeline[0].tool == "pecmd"


def test_yara_present_and_correlated_with_sigma_finding(config):
    """YARA VE Sigma ayni dosyayi isaretlerse Report.correlated_artifacts
    dolmali -- bkz. detection/correlation.py."""
    _write_collection(config)
    detection = _write_detection(config)
    matched_path = detection.findings[0].source_path
    _write_yara(config, matched_source_path=matched_path)

    report = build_report(config)

    assert report.yara is not None
    assert report.yara.match_count == 1
    assert len(report.correlated_artifacts) == 1
    assert report.correlated_artifacts[0].source_path == matched_path
    assert report.correlated_artifacts[0].yara_rule_names == ["Mimikatz_Strings"]

    json_path, _, _ = write_report(config, report)
    reloaded = Report.from_json_file(json_path)
    assert reloaded.yara.matches[0].rule_name == "Mimikatz_Strings"
    assert reloaded.correlated_artifacts[0].source_path == matched_path


def test_chainsaw_present_and_agrees_with_hayabusa(config):
    """Hayabusa VE Chainsaw AYNI kurali AYNI dosyada bulursa
    Report.engine_agreements dolmali -- bkz. detection/correlation.py."""
    _write_collection(config)
    detection = _write_detection(config)
    matched_path = detection.findings[0].source_path
    _write_chainsaw(config, rule_title=detection.findings[0].rule_title, source_path=matched_path)

    report = build_report(config)

    assert report.chainsaw is not None
    assert report.chainsaw.finding_count == 1
    assert len(report.engine_agreements) == 1
    assert report.engine_agreements[0].source_path == matched_path
    assert report.engine_agreements[0].rule_title == detection.findings[0].rule_title

    json_path, _, html_path = write_report(config, report)
    reloaded = Report.from_json_file(json_path)
    assert reloaded.chainsaw.findings[0].rule_title == detection.findings[0].rule_title
    assert reloaded.engine_agreements[0].source_path == matched_path

    html = html_path.read_text(encoding="utf-8")
    assert "Chainsaw özeti" in html
    assert "Motor ittifakı (Hayabusa + Chainsaw)" in html
    assert matched_path in html


def test_chainsaw_without_hayabusa_has_no_engine_agreement(config):
    """Sadece Chainsaw calismissa (Hayabusa yok) ittifak anlamsizdir, bos kalmali."""
    _write_collection(config)
    _write_chainsaw(config)

    report = build_report(config)

    assert report.chainsaw is not None
    assert report.detection is None
    assert report.engine_agreements == []


def test_yara_without_detection_has_no_correlation(config):
    """Sadece YARA calismissa (Sigma yok) korelasyon anlamsizdir, bos kalmali."""
    _write_collection(config)
    _write_yara(config, matched_source_path="C:/bir/dosya.evtx")

    report = build_report(config)

    assert report.yara is not None
    assert report.detection is None
    assert report.correlated_artifacts == []


def test_capa_present_and_rendered_without_affecting_correlation(config):
    """capa varsa Report.capa dolmali ve HTML'de gorunmeli; capa'nin YARA/
    Sigma korelasyonuna hic KATILMADIGI (bkz. aldigim_kararlar.md) ayrica
    dogrulanir -- capa tek basina calissa bile correlated_artifacts bos kalir."""
    _write_collection(config)
    capa_manifest = _write_capa(config)

    report = build_report(config)

    assert report.capa is not None
    assert report.capa.match_count == 1
    assert report.capa.matches[0].rule_name == capa_manifest.matches[0].rule_name
    assert report.correlated_artifacts == []

    json_path, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "capa tarama özeti" in html
    assert capa_manifest.matches[0].rule_name in html

    reloaded = Report.from_json_file(json_path)
    assert reloaded.capa.matches[0].rule_name == capa_manifest.matches[0].rule_name


def test_sha256_sidecar_matches_written_report(config):
    """report.json.sha256 GERCEKTEN report.json'un o anki iceriginin hash'i olmali."""
    _write_collection(config)

    json_path, sha_path, _ = write_report(config, build_report(config))

    digest, filename = sha_path.read_text(encoding="utf-8").split()
    assert filename == "report.json"
    assert digest == hashlib.sha256(json_path.read_bytes()).hexdigest()

    # Rapor sonradan degistirilirse yan dosya artik tutmaz.
    json_path.write_text("degistirildi", encoding="utf-8")
    assert digest != hashlib.sha256(json_path.read_bytes()).hexdigest()


def test_broken_chain_is_reported_as_invalid(config):
    """Elle degistirilmis bir custody satiri raporda GECERSIZ olarak gorunmeli."""
    _write_collection(config)
    log_path = resolve_custody_log_path(config)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    # Ikinci olayin operatoru degistiriliyor: JSON gecerli kalir, hash tutmaz.
    lines[1] = lines[1].replace(f'"operator":"{OPERATOR}"', '"operator":"saldirgan"')
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = build_report(config)

    assert report.chain_status.is_valid is False
    assert report.chain_status.broken_at_event_id is not None
    # Olay listesi yine de TAM: rapor zincirin kirildigini soyler, olaylari gizlemez.
    assert len(report.custody_events) == 2

    _, _, html_path = write_report(config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "GEÇERSİZ" in html and "GEÇERLİ" not in html


def test_build_report_without_manifest_raises_typed_error(config):
    """Toplama manifesti yoksa ham FileNotFoundError degil, tipli hata gelmeli."""
    with pytest.raises(ReportingError) as excinfo:
        build_report(config)
    assert "triagechain collect" in str(excinfo.value)


def test_report_generation_does_not_touch_the_ledger(config):
    """Rapor katmani salt-okunur: deftere yeni olay EKLEMEZ."""
    _write_collection(config)
    log_path = resolve_custody_log_path(config)
    before = log_path.read_bytes()

    write_report(config, build_report(config))

    assert log_path.read_bytes() == before
    assert len(list(read_events(log_path))) == 2


def test_cli_report_without_manifest_exits_with_code_2(tmp_path, capsys):
    """collect hic calistirilmamissa CLI net mesaj + cikis kodu 2 vermeli."""
    from triagechain.cli.main import main

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    data = {
        "case": {"case_id": CASE_ID, "operator": OPERATOR},
        "collection": {
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(output_dir),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    exit_code = main(["report", "--config", str(config_path)])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Toplama manifesti yok" in captured.err
    assert "triagechain collect" in captured.err
    assert not (output_dir / CASE_ID / "report.json").exists()
