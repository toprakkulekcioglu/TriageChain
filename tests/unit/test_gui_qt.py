"""PySide6 arayuzunun ekransiz (offscreen) testleri.

Gercek bir pencere ACILMAZ: QT_QPA_PLATFORM=offscreen ile Qt kendi sanal
ekranina cizer, testler yalnizca widget'larin DOGRU DEGERLERI tuttugunu
(.text(), satir sayisi vb.) dogrular -- goruntu karsilastirmasi yok.
"""

import os

# QApplication kurulmadan ONCE ayarlanmali, bu yuzden import'lardan once.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from datetime import datetime, timedelta, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

from triagechain.collection.models import CollectedArtifact, CollectionManifest  # noqa: E402
from triagechain.config.loader import (  # noqa: E402
    load_config,
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.custody.ledger import CustodyLedger  # noqa: E402
from triagechain.detection.models import (  # noqa: E402
    DetectionManifest,
    Finding,
    YaraManifest,
    YaraMatch,
)
from triagechain.reporting.builder import build_report, write_report  # noqa: E402
from triagechain.router.models import ProcessedArtifact, RoutingManifest  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from triagechain.gui_qt import i18n  # noqa: E402
from triagechain.gui_qt import theme as t  # noqa: E402
from triagechain.gui_qt.main_window import SIDEBAR_PAGES, TriageChainWindow  # noqa: E402

CASE_ID = "CASE-GUI-001"
START = datetime(2026, 6, 7, 22, 1, 0, tzinfo=timezone.utc)


def _event_name_at(window, row):
    """Olay adi hucresi artik duz bir QTableWidgetItem degil, ikon + ad/detay
    tasiyan bir widget (bkz. main_window._build_event_cell) -- adi bu yuzden
    objectName ile isaretlenmis QLabel'dan okunuyor."""
    cell = window.table.cellWidget(row, 0)
    return cell.findChild(QLabel, "event_name").text()


@pytest.fixture(scope="session")
def qt_app():
    """Tum testler icin tek bir QApplication (Qt ikincisine izin vermez)."""
    return QApplication.instance() or QApplication([])


@pytest.fixture
def config_path(tmp_path):
    """Gecerli ama hicbir ciktisi olmayan bir vaka konfigurasyonu."""
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "gui testi"},
        "collection": {
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def _write_fake_case(config_path, artifact_count=3, finding_count=2):
    """Diske sahte bir vaka yazar: manifest + gecerli custody defteri + bulgular."""
    config = load_config(config_path)

    artifacts = [
        CollectedArtifact(
            artifact_type_id="event_logs",
            source_path=f"C:/kaynak/log{i}.evtx",
            dest_path=f"C:/hedef/log{i}.evtx",
            hash_value="0" * 64,
            hash_algorithm="sha256",
            size_bytes=1024,
            collected_at_utc=START,
            collecting_user="test.operator",
            case_id=CASE_ID,
        )
        for i in range(artifact_count)
    ]
    manifest = CollectionManifest(
        case_id=CASE_ID,
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=2, seconds=5),
        artifacts=artifacts,
    )
    manifest.to_json_file(resolve_manifest_path(config))

    detection = DetectionManifest(
        case_id=CASE_ID,
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=1),
        findings=[
            Finding(
                artifact_type_id="event_logs",
                source_path="C:/hedef/log0.evtx",
                rule_title=f"Kural {i}",
                level="critical",
                timestamp="2026-06-07 22:03:00",
                computer="WS-01",
                channel="Security",
                event_id="4688",
                details="ornek",
            )
            for i in range(finding_count)
        ],
    )
    detection.to_json_file(resolve_detection_manifest_path(config))

    # Gercek defter: hash zinciri gercekten hesaplansin diye append_event.
    ledger = CustodyLedger(resolve_custody_log_path(config), CASE_ID)
    ledger.append_event("case_opened", "test.operator", {"aciklama": "gui testi"})
    for i in range(artifact_count):
        ledger.append_event("artifact_collected", "test.operator", {"index": i})
    ledger.append_event("case_closed", "test.operator", {"artifact_count": artifact_count})
    return config


def test_pencere_vaka_yuklenmeden_kuruluyor(qt_app, config_path):
    """Hicbir vaka yuklenmeden pencere+Dashboard cokmeden kurulmali."""
    window = TriageChainWindow()

    assert window.metric_files[1].text() == "—"
    assert window.metric_duration[1].text() == "—"
    assert window.metric_findings[1].text() == "—"
    assert window.chain_badge.text() == "Henüz vaka yüklenmedi"
    assert window.table.rowCount() == 0
    # Toplama disindaki uc aksiyon vaka yokken kapali olmali.
    assert not window.collect_button.isEnabled()
    assert not window.route_button.isEnabled()
    assert not window.detect_button.isEnabled()
    assert not window.yara_button.isEnabled()
    assert not window.chainsaw_button.isEnabled()
    assert not window.capa_button.isEnabled()
    assert not window.report_button.isEnabled()


def test_tum_sidebar_sayfalari_farkli_indekse_gidiyor(qt_app, config_path):
    """Yedi nav dugmesi de cokmeden, BIRBIRINDEN FARKLI bir sayfaya gitmeli.

    Yer tutucu sayfa artik yok -- 'Vakalar', 'Delil Zinciri', 'Raporlar',
    'Bulgular', 'Toplanan Dosyalar', 'Zaman Çizelgesi' hepsi gercek sayfa
    (bkz. asagidaki test_<sayfa_adi>_sayfasi_* testleri, her biri kendi
    verisini dogruluyor)."""
    window = TriageChainWindow()
    seen_indexes = {0}  # Dashboard zaten acik basliyor.
    for name in SIDEBAR_PAGES:
        window.nav_buttons[name].click()
        index = window.stack.currentIndex()
        assert index not in seen_indexes
        seen_indexes.add(index)
    window.nav_buttons["Dashboard"].click()
    assert window.stack.currentIndex() == 0


def test_toplanan_dosyalar_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["Toplanan Dosyalar"].click()
    assert window.stack.currentIndex() == 1
    assert window.files_table.rowCount() == 0
    assert "yüklenmedi" in window.files_subtitle.text()


def test_toplanan_dosyalar_sayfasi_gercek_veri(qt_app, config_path):
    """Yuklenen vakada her artefakt gercek diskteki manifestten satir olmali."""
    _write_fake_case(config_path, artifact_count=3)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.files_table.rowCount() == 3
    assert window.files_table.item(0, 1).text() == "1.0 KB"  # size_bytes=1024
    assert len(window.files_table.cellWidget(0, 3).text()) == 64  # tam hash
    assert window.files_footer.text() == "3 dosya toplandı, hepsi doğrulandı."


def test_delil_zinciri_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["Delil Zinciri"].click()
    assert window.stack.currentIndex() == 2
    assert window.custody_table.rowCount() == 0
    assert window.custody_badge.text() == "Henüz vaka yüklenmedi"


def test_delil_zinciri_sayfasi_tam_liste(qt_app, config_path):
    """Dashboard'un aksine 50 satirla sinirli olmamali -- TUM olaylar gorunmeli."""
    _write_fake_case(config_path, artifact_count=3)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    # 1 acilis + 3 toplama + 1 kapanis = 5 olay -- Dashboard'daki mini
    # tabloyla (window.table) AYNI sayida olmali, ikisi de ayni snapshot'tan.
    assert window.custody_table.rowCount() == 5 == window.table.rowCount()
    assert "Zincir Geçerli" in window.custody_badge.text()
    assert window.custody_table.cellWidget(0, 3).text() == "Doğrulandı"


def test_bulgular_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["Bulgular"].click()
    assert window.stack.currentIndex() == 3
    assert window.findings_table.rowCount() == 0
    assert "yüklenmedi" in window.findings_subtitle.text()


def test_bulgular_sayfasi_gercek_veri(qt_app, config_path):
    """Tespit manifestindeki HER bulgu (Dashboard'daki sayinin acilimi) satir olmali."""
    _write_fake_case(config_path, finding_count=2)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    # _write_fake_case butun bulgulari level="critical" yaziyor.
    assert window.findings_table.rowCount() == 2
    assert window.findings_table.cellWidget(0, 1).text() == "critical"
    assert window.findings_table.item(0, 2).text() == "2026-06-07 22:03:00"
    assert window.findings_subtitle.text() == f"{CASE_ID} · 2 bulgu"


def test_bulgular_sayfasi_yara_ve_korelasyon(qt_app, config_path):
    """YARA manifesti Sigma bulgusuyla AYNI dosyayi isaretlerse korelasyon
    notu gorunmeli -- bkz. detection/correlation.py."""
    config = _write_fake_case(config_path, finding_count=1)
    # _write_fake_case'in TUM bulgulari ayni source_path'i kullaniyor.
    matched_path = "C:/hedef/log0.evtx"
    yara_manifest = YaraManifest(case_id=CASE_ID, started_at_utc=START)
    yara_manifest.matches.append(
        YaraMatch(
            artifact_type_id="event_logs", source_path=matched_path,
            rule_name="Mimikatz_Strings", tags="malware,mimikatz",
        )
    )
    yara_manifest.to_json_file(resolve_yara_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert not window.yara_panel.isHidden()
    assert window.yara_empty_note.isHidden()
    assert window.yara_table.rowCount() == 1
    assert window.yara_table.item(0, 0).text() == "Mimikatz_Strings"
    assert not window.yara_correlation_note.isHidden()
    assert "1 dosya" in window.yara_correlation_note.text()


def test_bulgular_sayfasi_yara_calismamissa_bos_not_gosterir(qt_app, config_path):
    """YARA hic calismamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.yara_panel.isHidden()
    assert not window.yara_empty_note.isHidden()
    assert window.yara_correlation_note.isHidden()


def test_bulgular_sayfasi_chainsaw_ve_motor_ittifaki(qt_app, config_path):
    """Chainsaw manifesti Hayabusa bulgusuyla AYNI kurali AYNI dosyada
    bulursa ittifak notu gorunmeli -- bkz. detection/correlation.py."""
    config = _write_fake_case(config_path, finding_count=1)
    # _write_fake_case'in TUM bulgulari "Kural 0" adini ve ayni source_path'i kullaniyor.
    matched_path = "C:/hedef/log0.evtx"
    chainsaw_manifest = DetectionManifest(case_id=CASE_ID, started_at_utc=START)
    chainsaw_manifest.findings.append(
        Finding(
            artifact_type_id="event_logs", source_path=matched_path, rule_title="Kural 0",
            level="critical", timestamp="2026-06-07 22:03:00", computer="WS-01",
            channel="Security", event_id="4688", details="ornek",
        )
    )
    chainsaw_manifest.to_json_file(resolve_chainsaw_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert not window.chainsaw_panel.isHidden()
    assert window.chainsaw_empty_note.isHidden()
    assert window.chainsaw_table.rowCount() == 1
    assert window.chainsaw_table.cellWidget(0, 1).text() == "critical"
    assert not window.chainsaw_agreement_note.isHidden()
    assert "1 dosyada" in window.chainsaw_agreement_note.text()


def test_bulgular_sayfasi_chainsaw_calismamissa_bos_not_gosterir(qt_app, config_path):
    """Chainsaw hic calismamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.chainsaw_panel.isHidden()
    assert not window.chainsaw_empty_note.isHidden()
    assert window.chainsaw_agreement_note.isHidden()


def test_bulgular_sayfasi_capa_gercek_veri(qt_app, config_path):
    """capa manifesti varsa Bulgular sayfasindaki capa paneli dolmali --
    YARA ile AYNI YaraMatch semasini kullanir (bkz. detection/capa_runner.py)."""
    config = _write_fake_case(config_path, finding_count=1)
    capa_manifest = YaraManifest(case_id=CASE_ID, started_at_utc=START)
    capa_manifest.matches.append(
        YaraMatch(
            artifact_type_id="suspicious_binary", source_path="C:/supheli/ornek.exe",
            rule_name="link function at runtime on Windows", tags="T1129",
            meta="namespace=linking/runtime-linking",
        )
    )
    capa_manifest.to_json_file(resolve_capa_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert not window.capa_panel.isHidden()
    assert window.capa_empty_note.isHidden()
    assert window.capa_table.rowCount() == 1
    assert window.capa_table.item(0, 0).text() == "link function at runtime on Windows"
    assert window.capa_table.item(0, 1).text() == "T1129"


def test_bulgular_sayfasi_capa_calismamissa_bos_not_gosterir(qt_app, config_path):
    """capa hic calistirilmamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.capa_panel.isHidden()
    assert not window.capa_empty_note.isHidden()


def test_raporlar_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["Raporlar"].click()
    assert window.stack.currentIndex() == 4
    assert window.reports_card.isHidden()
    assert window.report_chain_badge.text() == "Henüz vaka yüklenmedi"


def test_raporlar_sayfasi_rapor_uretilmemis(qt_app, config_path):
    """Vaka yuklu ama 'Rapor Uret' hic calistirilmamissa bos not gorunmeli."""
    _write_fake_case(config_path)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.reports_card.isHidden()
    assert not window.reports_empty_note.isHidden()
    assert window.report_chain_badge.text() == "Henüz rapor yok"


def test_raporlar_sayfasi_gercek_veri(qt_app, config_path):
    """report.json'daki gercek alanlar (uydurulmamis) ekrana yansimali."""
    config = _write_fake_case(config_path, artifact_count=3, finding_count=2)
    report = build_report(config)
    write_report(config, report)

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert not window.reports_card.isHidden()
    assert window.reports_empty_note.isHidden()
    assert "Zincir Geçerli" in window.report_chain_badge.text()
    assert window.report_field_operator.text() == f"test.operator · {CASE_ID}"
    assert "3 dosya" in window.report_field_collection.text()
    assert "2 bulgu" in window.report_field_detection.text()
    assert window.report_field_routing.text() == "Bu vaka için henüz çalıştırılmadı"
    # _write_fake_case route calistirmiyor -- zaman cizelgesi de bos kalmali.
    assert "Henüz oluşturulmadı" in window.report_field_timeline.text()

    # Yonetici Raporu sekmesi: _write_fake_case TUM bulgulari "critical"
    # yazdigi icin risk seviyesi Yuksek olmali (bkz. reporting/executive.py).
    assert window.reports_tabs.tabText(0) == "Yönetici Raporu"
    assert window.reports_tabs.tabText(1) == "Uzman Raporu"
    assert "Risk Seviyesi: Yüksek" in window.exec_risk_level.text()
    assert window.exec_tile_artifacts.text() == "3"
    assert window.exec_tile_findings.text() == "2"
    assert window.exec_tile_high.text() == "2"
    assert window.exec_tile_chain.text() == "Doğrulandı"
    assert CASE_ID in window.exec_narrative.text()


def test_zaman_cizelgesi_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["Zaman Çizelgesi"].click()
    assert window.stack.currentIndex() == 6
    assert window.timeline_table.rowCount() == 0
    assert "yüklenmedi" in window.timeline_subtitle.text()


def test_zaman_cizelgesi_sayfasi_route_calismamissa_bos_not_gosterir(qt_app, config_path):
    """route hic calistirilmamissa (routing_manifest.json yok) panel bos-durum
    notu gostermeli -- gercek YARA/Chainsaw/capa panelleriyle AYNI desen."""
    _write_fake_case(config_path)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.timeline_table.isHidden()
    assert not window.timeline_empty_note.isHidden()


def test_zaman_cizelgesi_sayfasi_gercek_pecmd_verisiyle_dolar(qt_app, config_path):
    """routing_manifest.json'daki bir PECmd artefaktinin gercek Timeline
    CSV'si varsa tabloya yansimali -- gercek PECmd 2026.5.0 ciktisindan
    alinan sutunlarla (bkz. reporting/timeline.py, aldigim_kararlar.md)."""
    config = _write_fake_case(config_path)
    output_dir = Path(config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8",
    )
    routing = RoutingManifest(case_id=CASE_ID, started_at_utc=START, ended_at_utc=START)
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=START,
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert not window.timeline_table.isHidden()
    assert window.timeline_empty_note.isHidden()
    assert window.timeline_table.rowCount() == 1
    assert window.timeline_table.item(0, 0).text() == "2019-06-05 19:23:00"
    assert window.timeline_table.item(0, 1).text() == "Prefetch"
    assert "1 olay" in window.timeline_subtitle.text()


def test_yuklenen_vakada_metrikler_ve_defter_dogru(qt_app, config_path):
    """Sahte bir vaka yuklendiginde kartlar/tablo diskteki gercek veriyi gostermeli."""
    _write_fake_case(config_path)
    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.metric_files[1].text() == "3"
    assert window.metric_duration[1].text() == "02:05"   # 2 dk 5 sn
    assert window.metric_findings[1].text() == "2"
    assert "Zincir Geçerli" in window.chain_badge.text()

    # Delta metni + sparkline verisi GERCEK diskteki veriden turemeli --
    # uydurulmus bir sayi degil (bkz. read_snapshot()).
    # "~" oneki referans tasarimdaki kucuk trend isaretiyle ayni gorsel
    # dili tasir, sadece gosterim katmaninda eklenir (bkz. _refresh_metrics).
    assert window.metric_files[2].text() == "~ tümü doğrulandı"
    assert window.metric_files[3]._values == [1, 2, 3]
    assert window.metric_findings[2].text() == "~ 2 yüksek önem"  # ikisi de "critical"
    assert window.metric_findings[3]._values == [1, 2]
    # _write_fake_case hem toplama hem tespit manifesti yaziyor (yonlendirme
    # yok) -- ikisinin de suresi trend'e girmeli, en son BITEN (toplama,
    # 02:05 > tespitin 1 dakikasi) basliktaki metni belirlemeli.
    assert window.metric_duration[2].text() == "~ toplama+tarama"
    assert window.metric_duration[3]._values == [125.0, 60.0]

    # 1 acilis + 3 toplama + 1 kapanis = 5 olay
    assert window.table.rowCount() == 5
    assert _event_name_at(window, 0) == "Vaka Açıldı"
    assert _event_name_at(window, 1) == "Dosya Toplandı"
    assert _event_name_at(window, 4) == "Vaka Kapatıldı"
    # Hash tam gosterilmeli (64 karakter), kesilmemeli.
    assert len(window.table.cellWidget(0, 2).text()) == 64
    assert all(
        window.table.cellWidget(row, 3).text() == "Doğrulandı"
        for row in range(window.table.rowCount())
    )
    assert window.table_footer.text() == "5 olay gösteriliyor"

    # Manifest artik var: yonlendirme/tarama/rapor butonlari acilmali.
    assert window.route_button.isEnabled()
    assert window.detect_button.isEnabled()
    assert window.yara_button.isEnabled()
    assert window.chainsaw_button.isEnabled()
    assert window.capa_button.isEnabled()
    assert window.report_button.isEnabled()


def test_bozulan_zincirde_supheli_durumu_gorunuyor(qt_app, config_path):
    """Defter kasitli bozulursa kirilmadan sonraki satirlar 'Şüpheli' olmali."""
    config = _write_fake_case(config_path)
    log_path = resolve_custody_log_path(config)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    # 2. olayin operator alanini degistir -> entry_hash artik uyusmaz.
    lines[1] = lines[1].replace('"test.operator"', '"sahtekar"')
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert "GEÇERSİZ" in window.chain_badge.text()
    assert window.table.cellWidget(0, 3).text() == "Doğrulandı"
    assert window.table.cellWidget(1, 3).text() == "Şüpheli"
    assert window.table.cellWidget(4, 3).text() == "Şüpheli"


def _case_id_at(window, row):
    """Vakalar tablosundaki vaka kimligini objectName ile isaretlenmis
    QLabel'dan okur -- _event_name_at ile ayni desen."""
    cell = window.cases_table.cellWidget(row, 0)
    return cell.findChild(QLabel, "case_id_label").text()


def test_vakalar_sayfasi_vaka_yuklenmeden(qt_app, config_path):
    """Config yuklenmeden output_dir bilinmiyor -- liste bos kalmali, cokmemeli."""
    window = TriageChainWindow()
    window.nav_buttons["Vakalar"].click()
    assert window.stack.currentIndex() == 5
    assert window.cases_table.rowCount() == 0


def test_vakalar_sayfasi_kardes_vakalari_buluyor(qt_app, config_path):
    """Ayni output_dir altindaki BASKA bir vaka klasoru de listede gorunmeli,
    yuklu olan 'AKTIF' etiketiyle ayirt edilebilmeli."""
    config = _write_fake_case(config_path, artifact_count=3, finding_count=2)

    # Kardes vaka: sadece bir manifest.json'u olan, custody/tespit hic
    # calistirilmamis eksik bir vaka -- okunamayan alanlar cokmemeli.
    sibling_dir = Path(config.collection.output_dir) / "CASE-SIBLING-002"
    sibling_dir.mkdir(parents=True)
    sibling_manifest = CollectionManifest(
        case_id="CASE-SIBLING-002",
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=1),
        artifacts=[
            CollectedArtifact(
                artifact_type_id="event_logs",
                source_path="C:/kaynak/log0.evtx",
                dest_path="C:/hedef/log0.evtx",
                hash_value="1" * 64,
                hash_algorithm="sha256",
                size_bytes=2048,
                collected_at_utc=START,
                collecting_user="baska.operator",
                case_id="CASE-SIBLING-002",
            )
        ],
    )
    sibling_manifest.to_json_file(sibling_dir / "manifest.json")

    window = TriageChainWindow()
    window.load_config_file(config_path)

    assert window.cases_table.rowCount() == 2
    case_ids = {_case_id_at(window, row) for row in range(2)}
    assert case_ids == {CASE_ID, "CASE-SIBLING-002"}

    rows_by_id = {_case_id_at(window, row): row for row in range(2)}
    active_row = rows_by_id[CASE_ID]
    sibling_row = rows_by_id["CASE-SIBLING-002"]
    assert window.cases_table.item(active_row, 1).text() == "3"
    assert window.cases_table.cellWidget(active_row, 2).text() == "Geçerli · 5 olay"
    # Kardes vakada custody/tespit hic yok -- bu alanlar "—"/"Defter yok" kalmali.
    assert window.cases_table.item(sibling_row, 1).text() == "1"
    assert window.cases_table.cellWidget(sibling_row, 2).text() == "Defter yok"
    assert window.cases_table.item(sibling_row, 3).text() == "—"


def test_bozuk_konfigurasyon_ham_traceback_gostermiyor(qt_app, tmp_path):
    """Gecersiz bir YAML yuklenince sade bir durum mesaji gosterilmeli."""
    bad = tmp_path / "bozuk.yaml"
    bad.write_text("case: [bu bir sozluk degil]\n", encoding="utf-8")

    window = TriageChainWindow()
    window.load_config_file(bad)

    assert window.config is None
    message = window.status_label.text()
    assert "Traceback" not in message
    assert message.strip()
    # Vaka yuklenemedigi icin aksiyonlar kapali kalmali.
    assert not window.collect_button.isEnabled()


# -- Ayarlar sayfasi: tema + dil (canli gecis) -------------------------------
# t.set_mode/i18n.set_language SUREC GENELINDE PAYLASILAN modul durumu --
# her testten SONRA varsayilana (dark/tr) donduruluyor ki bu dosyadaki
# BASKA testler (hepsi varsayilan temayi/dili varsayiyor) bozulmasin.

@pytest.fixture(autouse=True)
def _reset_theme_and_language_after_test():
    yield
    t.set_mode("dark")
    i18n.set_language("tr")


def test_ayarlar_sayfasi_varsayilan_koyu_ve_turkce_gosterir(qt_app):
    window = TriageChainWindow()

    assert window.theme_dark_radio.isChecked()
    assert not window.theme_light_radio.isChecked()
    assert window.language_combo.currentData() == "tr"
    assert window.windowTitle() == "TriageChain Konsolu"


def test_acik_tema_radyosu_canli_gecis_yapiyor(qt_app):
    window = TriageChainWindow()
    window._show_settings()

    window.theme_light_radio.setChecked(True)

    assert t.get_mode() == "light"
    # _apply_theme() kabugu YENIDEN KURDUGU icin eski referanslar gecersiz --
    # widget'lar YENIDEN alinmali (bkz. main_window.py::_build_shell notu).
    assert window.stack.currentIndex() == 7  # Ayarlar sayfasinda kaldi
    assert window.theme_light_radio.isChecked()
    assert not window.theme_dark_radio.isChecked()


def test_koyu_temaya_geri_donus_calisiyor(qt_app):
    window = TriageChainWindow()
    window._show_settings()
    window.theme_light_radio.setChecked(True)

    window.theme_dark_radio.setChecked(True)

    assert t.get_mode() == "dark"
    assert window.theme_dark_radio.isChecked()


def test_dil_secimi_pencere_basligini_degistiriyor(qt_app):
    window = TriageChainWindow()
    window._show_settings()
    en_index = list(i18n.SUPPORTED_LANGUAGES.keys()).index("en")

    window.language_combo.setCurrentIndex(en_index)

    assert i18n.get_language() == "en"
    assert window.windowTitle() == "TriageChain Console"
    assert window.stack.currentIndex() == 7


def test_dil_acilir_listesi_kod_ve_ad_formatinda_ve_dogru_sirada(qt_app):
    window = TriageChainWindow()
    window._show_settings()

    labels = [window.language_combo.itemText(i) for i in range(window.language_combo.count())]

    assert labels[0] == "TR Türkçe"
    assert labels[1] == "EN English"
    assert labels[2].startswith("ES Español")
    assert labels[3].startswith("DE Deutsch")
    assert labels[4].startswith("PT Português")
    assert labels[5].startswith("FR Français")
    # Henuz cevrilmemis diller acikca isaretlenmeli, sessizce eksik
    # gosterilmemeli (kullaniciyi yanlis bilgilendirmemek icin).
    for label in labels[2:]:
        assert "çevrilmedi" in label


def test_tema_gecisi_dashboard_sayfasina_da_yansiyor(qt_app, config_path):
    """Sadece Ayarlar sayfasi degil, TUM kabuk yeniden kuruluyor mu?"""
    window = TriageChainWindow()
    window.load_config_file(config_path)
    window._show_settings()

    window.theme_light_radio.setChecked(True)

    assert t.get_mode() == "light"
    window._show_dashboard()
    # Kabuk yeniden kurulduktan sonra Dashboard verisi hala dogru --
    # _refresh() rebuild sonrasi tekrar cagriliyor.
    assert window.case_pill.text() == CASE_ID
