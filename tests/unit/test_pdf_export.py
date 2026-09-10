"""gui_qt/pdf_export.py'nin testleri.

test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen -- QTextDocument/
QPrinter QApplication gerektiriyor ama gercek bir pencere/yazici ACILMAZ,
PDF dogrudan diske yaziliyor (elle dogrulandi: gercek %PDF-1.4 imzali bir
dosya uretiyor, bkz. docs/aldigim_kararlar.md).

NOT: bu dosyayi offscreen platformda calistirinca konsolda "Windows fatal
exception: code 0x80040155" (COM REGDB_E_CLASSNOTREG) izi GORUNEBILIR --
bu ZARARSIZ ve testin GECMESINI ETKILEMEZ. Elle dogrulandi: AYNI kod
QT_QPA_PLATFORM AYARLANMADAN (gercek "windows" platformuyla, yani
paketlenmis uygulamanin GERCEKTE calistigi kosullarda) calistirilinca bu
iz HIC cikmiyor -- offscreen platform eklentisinin, gercek Windows
platformunun sagladigi bir yazici/font COM kaydini sahte-eksiksiz
saglamamasindan kaynaklaniyor, Qt bunu yakalayip PDF'i yine de dogru
uretiyor (bkz. docs/aldigim_kararlar.md).
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from datetime import datetime, timezone  # noqa: E402

import pytest  # noqa: E402

from triagechain.detection.models import Finding  # noqa: E402
from triagechain.reporting.executive import build_executive_summary  # noqa: E402
from triagechain.reporting.models import ChainStatus, CollectionSummary, DetectionSummary, Report  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from triagechain.gui_qt import pdf_export  # noqa: E402


@pytest.fixture(scope="session")
def qt_app():
    return QApplication.instance() or QApplication([])


def _make_report(**overrides) -> Report:
    defaults = dict(
        case_id="CASE-PDF-001",
        operator="yasar",
        description="",
        collection=CollectionSummary(
            run_id="r1", started_at_utc=datetime.now(timezone.utc), ended_at_utc=None,
            artifact_count=42, error_count=0,
        ),
        chain_status=ChainStatus(is_valid=True, total_events=5, broken_at_event_id=None, message="ok"),
    )
    defaults.update(overrides)
    return Report(**defaults)


def test_build_report_html_temel_alanlari_iceriyor(qt_app):
    report = _make_report()
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "CASE-PDF-001" in html
    assert "yasar" in html
    assert summary.risk_level in html


def test_build_report_html_kullanici_girdisini_kacirir(qt_app):
    """HTML enjeksiyonuna karsi -- operator/case_id gibi alanlar rapora
    dogrudan gomuluyor, kacirilmazsa bozuk/guvensiz bir PDF sablonu
    olusabilir."""
    report = _make_report(case_id="<script>evil</script>")
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "<script>evil</script>" not in html
    assert "&lt;script&gt;" in html


def test_build_report_html_bulgulari_listeler(qt_app):
    report = _make_report(
        detection=DetectionSummary(
            run_id="d1", started_at_utc=datetime.now(timezone.utc), ended_at_utc=None,
            scanned_count=3, finding_count=1,
            findings=[
                Finding(
                    artifact_type_id="event_logs", source_path="C:/case/Security.evtx",
                    rule_title="Şüpheli Oturum Açma", level="critical", timestamp="2026-06-07",
                    computer="WS-01", channel="Security", event_id="4625", details="",
                )
            ],
        )
    )
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "Şüpheli Oturum Açma" in html
    assert "Security.evtx" in html


def test_export_report_pdf_gercek_pdf_dosyasi_uretir(qt_app, tmp_path):
    report = _make_report()
    summary = build_executive_summary(report)
    out_path = tmp_path / "rapor.pdf"

    pdf_export.export_report_pdf(out_path, report, summary)

    assert out_path.is_file()
    assert out_path.stat().st_size > 0
    assert out_path.read_bytes().startswith(b"%PDF-")
