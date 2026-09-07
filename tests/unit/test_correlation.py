"""Sigma/Hayabusa ve YARA ciktilarinin korelasyonu: sadece kume kesisimi,
hicbir puanlama yok -- bkz. detection/correlation.py."""

from datetime import datetime, timezone

from triagechain.detection.correlation import correlate_findings, correlate_sigma_engines
from triagechain.detection.models import DetectionManifest, Finding, YaraManifest, YaraMatch

NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _finding(source_path, rule_title="Kural"):
    return Finding(
        artifact_type_id="event_logs", source_path=source_path, rule_title=rule_title,
        level="high", timestamp="2026-06-07 22:00:00", computer="WS-01", channel="Security",
        event_id="4688", details="",
    )


def _match(source_path, rule_name="YaraKural"):
    return YaraMatch(artifact_type_id="event_logs", source_path=source_path, rule_name=rule_name)


def _detection(findings):
    return DetectionManifest(case_id="CASE-X", started_at_utc=NOW, findings=list(findings))


def _yara(matches):
    return YaraManifest(case_id="CASE-X", started_at_utc=NOW, matches=list(matches))


def test_ayni_dosyayi_isaretleyen_iki_motor_korele_edilir():
    detection = _detection([_finding("C:/a.evtx", "Suspicious PowerShell")])
    yara = _yara([_match("C:/a.evtx", "Mimikatz_Strings")])

    result = correlate_findings(detection, yara)

    assert len(result) == 1
    assert result[0].source_path == "C:/a.evtx"
    assert result[0].sigma_rule_titles == ["Suspicious PowerShell"]
    assert result[0].yara_rule_names == ["Mimikatz_Strings"]


def test_sadece_bir_motorun_isaretledigi_dosya_korele_EDILMEZ():
    """Sadece Sigma ya da sadece YARA bulmus dosyalar kesisimde olmamali --
    korelasyon sadece IKI motorun da ayni dosyada anlastigi durumu gosterir."""
    detection = _detection([_finding("C:/only-sigma.evtx")])
    yara = _yara([_match("C:/only-yara.evtx")])

    assert correlate_findings(detection, yara) == []


def test_ayni_dosyada_birden_fazla_kural_hepsi_listelenir():
    detection = _detection([_finding("C:/a.evtx", "Kural1"), _finding("C:/a.evtx", "Kural2")])
    yara = _yara([_match("C:/a.evtx", "YaraKural1")])

    result = correlate_findings(detection, yara)

    assert result[0].sigma_rule_titles == ["Kural1", "Kural2"]
    assert result[0].yara_rule_names == ["YaraKural1"]


def test_bos_manifestler_bos_liste_dondurur():
    assert correlate_findings(_detection([]), _yara([])) == []


def test_iki_sigma_motoru_ayni_kurali_ayni_dosyada_bulursa_ittifak():
    """Hayabusa ve Chainsaw AYNI kural setini kullandigi icin rule_title
    esitligi capraz dogrulama sayilir (bkz. correlate_sigma_engines)."""
    hayabusa = _detection([_finding("C:/a.evtx", "Suspicious PowerShell")])
    chainsaw = _detection([_finding("C:/a.evtx", "Suspicious PowerShell")])

    result = correlate_sigma_engines(hayabusa, chainsaw)

    assert len(result) == 1
    assert result[0].source_path == "C:/a.evtx"
    assert result[0].rule_title == "Suspicious PowerShell"


def test_farkli_kural_adlari_ittifak_SAYILMAZ():
    """Ayni dosyada ama FARKLI kurallar eslesirse -- iki motor ayni SEYI
    dogrulamamis demektir, ittifak olmamali."""
    hayabusa = _detection([_finding("C:/a.evtx", "Kural A")])
    chainsaw = _detection([_finding("C:/a.evtx", "Kural B")])

    assert correlate_sigma_engines(hayabusa, chainsaw) == []


def test_sonuc_source_path_sirasina_gore_deterministik():
    detection = _detection([_finding("C:/z.evtx"), _finding("C:/a.evtx")])
    yara = _yara([_match("C:/z.evtx"), _match("C:/a.evtx")])

    result = correlate_findings(detection, yara)

    assert [r.source_path for r in result] == ["C:/a.evtx", "C:/z.evtx"]
