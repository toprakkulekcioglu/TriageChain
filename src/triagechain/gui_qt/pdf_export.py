"""Rapor ozetini PDF'e aktarma -- Oxygen Forensic Detective'in PDF disa
aktarma ozelliginden esinlenildi (bkz. docs/aldigim_kararlar.md). Yeni bir
bagimlilik EKLENMEDI: PySide6 zaten `QtPrintSupport`'u iceriyor
(`QTextDocument` -> `QPrinter`, gercek bir PDF uretir -- offscreen ortamda
da calistigi elle dogrulandi).

report.html'in (reporting/renderer.py) TAM CSS'ini/JS sekmelerini YENIDEN
URETMEYE CALISMAZ -- `QTextDocument`'in HTML/CSS destegi sinirli bir alt
kume (flexbox/grid/CSS degiskeni YOK). Bunun yerine sade, temel etiketlerle
(h1/h2/p/table, satir-ici stil) kendi kisa ozet sablonunu cizer; tam teknik
detay icin hala ayni vaka klasorundeki report.html referans kaliyor.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QPageLayout, QPageSize, QTextDocument
from PySide6.QtPrintSupport import QPrinter

from triagechain.reporting.executive import ExecutiveSummary
from triagechain.reporting.models import Report

# reporting/executive.RISK_LEVELS ve gui_qt/theme.RISK_COLORS ile AYNI
# anahtarlar/anlam -- PDF'in kendi ayri (yazdirilabilir, acik zeminli)
# renk degerleriyle, bkz. reporting/renderer.py'nin de kendi ayri acik-tema
# CSS paleti kullanmasiyla ayni gerekce.
_RISK_COLORS = {
    "Bulgu Yok": "#1A7F37", "Düşük": "#0969DA", "Orta": "#9A6700",
    "Yüksek": "#D1242F", "Kritik": "#D1242F",
}

# Bir PDF sayfasinin makul kalmasi icin bulgu tablosu bu sayidan sonra
# kesilir -- tam liste zaten CSV disa aktarmada ve report.html'de var.
_MAX_FINDINGS_IN_PDF = 100


def _field_row(label: str, value: str) -> str:
    return (
        f"<tr><td style='color:#656D76;padding:4px 10px 4px 0;'>{escape(label)}</td>"
        f"<td style='padding:4px 0;'>{escape(value)}</td></tr>"
    )


def build_report_html(report: Report, summary: ExecutiveSummary) -> str:
    """QTextDocument'in sinirli HTML/CSS alt kumesiyle uyumlu, sade bir
    ozet sayfasi uretir."""
    risk_color = _RISK_COLORS.get(summary.risk_level, "#656D76")

    rows = [
        _field_row("Vaka Kimliği", report.case_id),
        _field_row("Operatör", report.operator),
        _field_row(
            "Üretilme Zamanı (UTC)",
            report.report_generated_at_utc.strftime("%Y-%m-%d %H:%M:%S"),
        ),
        _field_row("İncelenen Dosya Sayısı", str(summary.artifact_count)),
        _field_row("Güvenlik Bulgusu Sayısı", str(summary.finding_count)),
        _field_row("Yüksek/Kritik Bulgu Sayısı", str(summary.high_severity_count)),
        _field_row("Kanıt Bütünlüğü", "Doğrulandı" if summary.chain_is_valid else "BOZULMUŞ"),
    ]
    if summary.yara_match_count:
        rows.append(_field_row("YARA Eşleşmesi", str(summary.yara_match_count)))
    if summary.correlated_count:
        rows.append(_field_row("Sigma + YARA Korelasyonu", str(summary.correlated_count)))
    if summary.engine_agreement_count:
        rows.append(
            _field_row("Hayabusa + Chainsaw Anlaşması", str(summary.engine_agreement_count))
        )

    findings_section = ""
    all_findings = list(report.detection.findings if report.detection else [])
    all_findings += list(report.chainsaw.findings if report.chainsaw else [])
    if all_findings:
        finding_rows = "".join(
            "<tr>"
            f"<td style='padding:4px 10px 4px 0;'>{escape(f.rule_title)}</td>"
            f"<td style='padding:4px 10px 4px 0;color:"
            f"{'#D1242F' if f.level.lower() in ('high', 'critical') else '#656D76'};'>"
            f"{escape(f.level)}</td>"
            f"<td style='padding:4px 0;'>{escape(f.source_path)}</td>"
            "</tr>"
            for f in all_findings[:_MAX_FINDINGS_IN_PDF]
        )
        more_note = (
            f"<p style='color:#656D76;font-size:10px;'>… ve "
            f"{len(all_findings) - _MAX_FINDINGS_IN_PDF} bulgu daha (tam liste için CSV dışa "
            "aktarmaya veya aynı vaka klasöründeki report.html'e bakın).</p>"
            if len(all_findings) > _MAX_FINDINGS_IN_PDF
            else ""
        )
        findings_section = f"""
        <h2 style='color:#1F2328;font-size:14px;margin-top:22px;'>Bulgular</h2>
        <table style='border-collapse:collapse;width:100%;font-size:11px;'>
        <tr style='color:#656D76;'><th align='left'>Kural</th><th align='left'>Seviye</th>
        <th align='left'>Dosya</th></tr>
        {finding_rows}
        </table>
        {more_note}
        """

    return f"""
    <div style='font-family:Helvetica;color:#1F2328;'>
    <h1 style='font-size:20px;margin-bottom:2px;'>TriageChain Raporu</h1>
    <p style='color:#656D76;font-size:11px;margin-top:0;'>
    Windows DFIR triage — hash zincirli gözetim kaydı
    </p>

    <table style='margin:14px 0;border:1px solid #D0D7DE;' cellpadding='10'>
    <tr><td>
    <div style='font-size:15px;font-weight:bold;color:{risk_color};'>
    Risk Seviyesi: {escape(summary.risk_level)}
    </div>
    <div style='font-size:11px;color:#656D76;padding-top:4px;'>{escape(summary.risk_reason)}</div>
    </td></tr>
    </table>

    <p style='font-size:12px;line-height:1.5;'>{escape(summary.narrative)}</p>

    <table style='margin-top:10px;font-size:12px;'>
    {''.join(rows)}
    </table>
    {findings_section}

    <p style='color:#8B949E;font-size:10px;margin-top:26px;'>
    Bu PDF, TriageChain'in ürettiği report.json/report.html'in kısa bir özetidir —
    tam teknik detay için aynı vaka klasöründeki report.html'e bakın.
    </p>
    </div>
    """


def export_report_pdf(path: Path, report: Report, summary: ExecutiveSummary) -> None:
    """Rapor ozetini PDF olarak diske yazar."""
    document = QTextDocument()
    document.setHtml(build_report_html(report, summary))

    printer = QPrinter(QPrinter.PrinterMode.HighResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(str(path))
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(18, 18, 18, 18), QPageLayout.Unit.Millimeter)
    document.print_(printer)
