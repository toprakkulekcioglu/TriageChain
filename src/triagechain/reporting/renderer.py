"""Report -> tek sayfa HTML.

Rapor olay yerinde, internetsiz bir makinede acilabilmek zorunda: harici
CDN/font/script/stil YOK, her sey bu dosyanin urettigi tek bir HTML'in icinde.
Disaridan gelen her metin (yol, kural adi, payload) `html.escape` ile
kacisliyor - manifest icerigi kullanicidan/dis araclardan geliyor, rapora ham
HTML olarak sizmamali.

CLI ciktisi ASCII kalirken buradaki metinler gercek Turkce karakterler
kullaniyor: HTML her zaman UTF-8 olarak tarayicida aciliyor, konsol kod
sayfasi sorunu burada yok.
"""

from __future__ import annotations

import base64
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from triagechain.reporting.executive import build_executive_summary
from triagechain.reporting.models import Report

# Rapor basligindaki logo -- base64 GOMULU (data: URI), harici bir dosya
# referansi DEGIL: report.html'in "tamamen offline acilabilmeli" kuralini
# bozmaz (bkz. modul dokstring'i). Dosya bulunamazsa (paketleme hatasi)
# sessizce atlanir, rapor logosuz ama yine dogru uretilir.
_LOGO_PATH = Path(__file__).resolve().parent / "assets" / "triagechain_logo_report.png"


def _logo_data_uri() -> str:
    try:
        raw = _LOGO_PATH.read_bytes()
    except OSError:
        return ""
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")

# Cok bulgulu bir vakada (binlerce Sigma bulgusu) HTML'i acilamaz hale
# getirmemek icin tabloya yalnizca ilk N bulgu yaziliyor; tamami her zaman
# report.json ve detection_manifest.json icinde duruyor.
HTML_FINDING_LIMIT = 500

# ExecutiveSummary.risk_level (bkz. reporting/executive.RISK_LEVELS) -> CSS
# sinif adindaki ASCII slug. Elle esleme, karakter karakter .replace()
# zincirinden daha guvenli (biri unutulursa acikca KeyError verir).
RISK_SLUGS = {
    "Bulgu Yok": "bulgu-yok",
    "Düşük": "dusuk",
    "Orta": "orta",
    "Yüksek": "yuksek",
    "Kritik": "kritik",
}

_CSS = """
:root { color-scheme: light; }
body { margin: 0; padding: 24px; background: #f4f5f7; color: #1c2024;
       font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; font-size: 14px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 10px; border-bottom: 2px solid #d5d8dd; padding-bottom: 6px; }
.sub { color: #5b6470; margin: 0 0 20px; }
.card { background: #fff; border: 1px solid #d5d8dd; border-radius: 6px; padding: 16px; }
.banner { border-radius: 6px; padding: 18px 20px; margin: 0 0 24px; color: #fff;
          font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
.banner.ok { background: #1f7a45; }
.banner.bad { background: #b3261e; }
.banner .detail { display: block; font-size: 13px; font-weight: 400; margin-top: 6px;
                  letter-spacing: 0; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { border: 1px solid #d5d8dd; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #eceef1; font-weight: 600; }
td.key { width: 220px; font-weight: 600; background: #f7f8f9; }
tr:nth-child(even) td { background: #fbfbfc; }
.empty { background: #fff8e1; border: 1px solid #e6d69a; border-radius: 6px;
         padding: 12px 14px; color: #6b5b17; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px;
         font-weight: 600; color: #fff; background: #6b7280; }
.badge.critical, .badge.high { background: #b3261e; }
.badge.medium { background: #b26a00; }
.badge.low, .badge.informational { background: #4b5563; }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 12px;
      font-family: Consolas, "Courier New", monospace; color: #333a42; }
footer { margin-top: 32px; color: #5b6470; font-size: 12px; }
.report-logo { display: block; height: 40px; margin: 0 0 12px; }

/* Sekmeler: saf CSS (radio + genel kardes secici), JS/kutuphane YOK -- rapor
   internetsiz bir makinede de tiklanabilir kalsin diye. */
.tab-input { position: absolute; opacity: 0; pointer-events: none; }
.tabbar { display: flex; gap: 4px; margin-bottom: 20px; border-bottom: 2px solid #d5d8dd; }
.tabbar label { padding: 9px 18px; cursor: pointer; color: #5b6470; font-weight: 600;
                border: 1px solid transparent; border-bottom: none; border-radius: 6px 6px 0 0;
                margin-bottom: -2px; }
.tab-panel { display: none; }
#tab-exec:checked ~ .panel-exec { display: block; }
#tab-expert:checked ~ .panel-expert { display: block; }
#tab-exec:checked ~ .tabbar label[for="tab-exec"],
#tab-expert:checked ~ .tabbar label[for="tab-expert"] {
    color: #1c2024; background: #fff; border-color: #d5d8dd; border-bottom-color: #fff;
}
.risk-banner { border-radius: 6px; padding: 20px 22px; margin: 0 0 20px; color: #fff; }
.risk-banner .level { font-size: 24px; font-weight: 700; letter-spacing: 0.5px; }
.risk-banner .reason { margin-top: 6px; font-size: 14px; opacity: 0.95; }
.risk-banner.risk-kritik, .risk-banner.risk-yuksek { background: #b3261e; }
.risk-banner.risk-orta { background: #b26a00; }
.risk-banner.risk-dusuk { background: #4b6b8a; }
.risk-banner.risk-bulgu-yok { background: #1f7a45; }
.narrative { font-size: 16px; line-height: 1.6; background: #fff; border: 1px solid #d5d8dd;
             border-radius: 6px; padding: 18px 20px; margin: 0 0 20px; }
.stat-grid { display: flex; gap: 14px; margin: 0 0 20px; flex-wrap: wrap; }
.stat-tile { flex: 1; min-width: 140px; background: #fff; border: 1px solid #d5d8dd;
             border-radius: 6px; padding: 14px 16px; }
.stat-tile .label { color: #5b6470; font-size: 12.5px; }
.stat-tile .value { font-size: 28px; font-weight: 700; margin-top: 4px; }

/* Kapak sayfasi -- resmi bir gozetim zinciri belgesi gibi yazdirilip elle
   imzalanabilsin diye bos imza satirlari (bkz. _cover_section). Sekmelerin
   DISINDA duruyor -- hangi sekme secili olursa olsun her zaman gorunur. */
.cover { margin: 0 0 24px; }
.sign-block { margin-top: 18px; display: flex; flex-direction: column; gap: 16px; }
.sign-row { display: flex; align-items: flex-end; gap: 10px; }
.sign-row .sign-label { flex: 0 0 190px; font-weight: 600; color: #1c2024; font-size: 13px; }
.sign-line { flex: 1; border-bottom: 1px solid #1c2024; height: 24px; }
@media print { .cover { page-break-after: always; } }
"""


def render_html(report: Report) -> str:
    """Raporu tek parca, tamamen offline acilabilen bir HTML'e cevirir.

    Iki sekme: Yonetici Raporu (teknik olmayan, risk seviyesi + duz metin
    ozet -- bkz. reporting/executive.py) ve Uzman Raporu (eskiden beri var
    olan teknik detay, degismedi). Sekme gecisi saf CSS'le yapiliyor, JS yok.
    """
    title = f"TriageChain Raporu - {report.case_id}"
    logo_uri = _logo_data_uri()
    logo_html = f'<img class="report-logo" src="{logo_uri}" alt="TriageChain">' if logo_uri else ""
    parts = [
        "<!DOCTYPE html>",
        '<html lang="tr"><head><meta charset="utf-8">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head><body>",
        logo_html,
        f"<h1>{_e(title)}</h1>",
        f'<p class="sub">Rapor üretim zamanı (UTC): {_e(_dt(report.report_generated_at_utc))}'
        f" &middot; rapor koşusu: {_e(report.run_id)}</p>",
        _cover_section(report),
        '<input type="radio" name="tabs" id="tab-exec" class="tab-input" checked>',
        '<input type="radio" name="tabs" id="tab-expert" class="tab-input">',
        '<div class="tabbar">'
        '<label for="tab-exec">Yönetici Raporu</label>'
        '<label for="tab-expert">Uzman Raporu</label>'
        "</div>",
        f'<div class="tab-panel panel-exec">{_executive_section(report)}</div>',
        '<div class="tab-panel panel-expert">'
        + _chain_banner(report)
        + _case_section(report)
        + _collection_section(report)
        + _routing_section(report)
        + _detection_section(report)
        + _chainsaw_section(report)
        + _yara_section(report)
        + _capa_section(report)
        + _watchlist_section(report)
        + _correlation_section(report)
        + _engine_agreements_section(report)
        + _timeline_section(report)
        + _custody_section(report)
        + "</div>",
        "<footer>TriageChain &middot; bu rapor otomatik üretildi; yanındaki "
        "<code>report.json.sha256</code> dosyası raporun kendisinin sonradan "
        "değişip değişmediğini gösterir.</footer>",
        "</body></html>",
    ]
    return "\n".join(parts)


def _cover_section(report: Report) -> str:
    """Kapak sayfasi -- vaka bilgisi + bos imza satirlari, raporun resmi bir
    gozetim zinciri belgesi gibi YAZDIRILIP ELLE imzalanabilmesi icin (bkz.
    aldigim_kararlar.md). Sekmelerin DISINDA duruyor: hangi sekme secili
    olursa olsun her zaman gorunur, `@media print`'te kendi sayfasinda kalir
    (`.cover { page-break-after: always; }`, bkz. yukaridaki CSS).

    Imza satirlari BILEREK BOS: `report.operator` toplama/tarama koşusunu
    calistiran KISI, ama bu raporu resmi olarak INCELEYEN/ONAYLAYAN kisi
    baska biri olabilir -- yanlis bir isim/imza uydurmak yerine analistin
    kendi elle doldurmasina birakiliyor."""
    status = report.chain_status
    chain_label = "GEÇERLİ" if status.is_valid else "GEÇERSİZ"
    rows = _kv_rows(
        [
            ("Vaka kimliği", report.case_id),
            ("Operatör", report.operator),
            ("Açıklama", report.description or "-"),
            ("Rapor üretim zamanı (UTC)", _dt(report.report_generated_at_utc)),
            ("Kanıt zinciri durumu", chain_label),
        ]
    )
    sign_rows = "".join(
        f'<div class="sign-row"><span class="sign-label">{_e(label)}</span>'
        '<span class="sign-line"></span></div>'
        for label in ("İnceleyen (Ad Soyad)", "İmza", "Tarih")
    )
    return (
        '<div class="card cover">'
        "<h2 style='margin-top:0;'>Vaka Kapak Sayfası</h2>"
        f"<table>{rows}</table>"
        f'<div class="sign-block">{sign_rows}</div>'
        "</div>"
    )


def _executive_section(report: Report) -> str:
    """Yonetici Raporu sekmesi: risk rozeti + duz metin ozet + birkac sayi.

    Teknik terim (manifest/custody/Sigma/run_id) KULLANILMAZ -- bkz.
    reporting/executive.py'nin kendi testleri."""
    summary = build_executive_summary(report)
    # CSS sinif adi icin ASCII slug -- Turkce karakterleri elle esliyoruz,
    # zincirlenmis .replace() bunlardan birini atlarsa (orn. 'ş') CSS'teki
    # .risk-* seciciyle sessizce uyusmazlik olusurdu.
    risk_slug = RISK_SLUGS[summary.risk_level]
    return (
        f'<div class="risk-banner risk-{_e(risk_slug)}">'
        f'<div class="level">Risk Seviyesi: {_e(summary.risk_level)}</div>'
        f'<div class="reason">{_e(summary.risk_reason)}</div>'
        "</div>"
        f'<div class="narrative">{_e(summary.narrative)}</div>'
        '<div class="stat-grid">'
        f'<div class="stat-tile"><div class="label">İncelenen dosya</div>'
        f'<div class="value">{summary.artifact_count}</div></div>'
        f'<div class="stat-tile"><div class="label">Güvenlik bulgusu</div>'
        f'<div class="value">{summary.finding_count}</div></div>'
        f'<div class="stat-tile"><div class="label">Yüksek/kritik bulgu</div>'
        f'<div class="value">{summary.high_severity_count}</div></div>'
        f'<div class="stat-tile"><div class="label">Hash listesi eşleşmesi</div>'
        f'<div class="value">{summary.watchlist_match_count}</div></div>'
        '<div class="stat-tile"><div class="label">Kanıt bütünlüğü</div>'
        f'<div class="value">{"Doğrulandı" if summary.chain_is_valid else "BOZULMUŞ"}</div>'
        "</div></div>"
    )


def _chain_banner(report: Report) -> str:
    """Büyük, renkli zincir durumu göstergesi."""
    status = report.chain_status
    css_class = "ok" if status.is_valid else "bad"
    label = "GEÇERLİ" if status.is_valid else "GEÇERSİZ"
    detail = f"{status.total_events} olay &middot; {_e(status.message)}"
    if status.broken_at_event_id:
        detail += f" &middot; kırılma olayı: {_e(status.broken_at_event_id)}"
    return (
        f'<div class="banner {css_class}">Zincir Durumu: {label}'
        f'<span class="detail">{detail}</span></div>'
    )


def _case_section(report: Report) -> str:
    """Vaka bilgisi kartı."""
    rows = _kv_rows(
        [
            ("Vaka kimliği", report.case_id),
            ("Operatör", report.operator),
            ("Açıklama", report.description or "-"),
            ("Rapor şeması", report.manifest_version),
        ]
    )
    return f"<h2>Vaka bilgisi</h2><table>{rows}</table>"


def _collection_section(report: Report) -> str:
    """Toplama özeti (manifest.json her zaman var, bu bölüm hiç boş kalmaz)."""
    summary = report.collection
    rows = _kv_rows(
        [
            ("Koşu (run_id)", summary.run_id),
            ("Başlangıç (UTC)", _dt(summary.started_at_utc)),
            ("Bitiş (UTC)", _dt(summary.ended_at_utc)),
            ("Toplanan artefakt", str(summary.artifact_count)),
            ("Alınamayan artefakt", str(summary.error_count)),
        ]
    )
    return f"<h2>Toplama özeti</h2><table>{rows}</table>"


def _routing_section(report: Report) -> str:
    """Yönlendirme özeti; komut hiç çalıştırılmadıysa açıklayıcı bir not."""
    summary = report.routing
    if summary is None:
        return (
            "<h2>Yönlendirme özeti</h2>"
            '<div class="empty">Yönlendirme henüz çalıştırılmadı '
            "(<code>triagechain route</code>).</div>"
        )
    rows = _kv_rows(
        [
            ("Koşu (run_id)", summary.run_id),
            ("Başlangıç (UTC)", _dt(summary.started_at_utc)),
            ("Bitiş (UTC)", _dt(summary.ended_at_utc)),
            ("İşlenen artefakt", str(summary.processed_count)),
            ("Atlanan artefakt", str(summary.skipped_count)),
            ("Hata veren artefakt", str(summary.error_count)),
        ]
    )
    return f"<h2>Yönlendirme özeti</h2><table>{rows}</table>"


def _detection_section(report: Report) -> str:
    """Hayabusa (Sigma) tespit özeti + seviye dağılımı + bulgular tablosu."""
    return _sigma_engine_section(
        report.detection, engine_label="Tespit", cli_hint="triagechain detect",
    )


def _chainsaw_section(report: Report) -> str:
    """Chainsaw (BAĞIMSIZ ikinci Sigma motoru) özeti + bulgular tablosu --
    Hayabusa ile AYNI DetectionSummary/Finding şemasını paylaştığı için AYNI
    render mantığını kullanır (bkz. _sigma_engine_section)."""
    return _sigma_engine_section(
        report.chainsaw, engine_label="Chainsaw", cli_hint="triagechain chainsaw-scan",
    )


def _sigma_engine_section(summary, engine_label: str, cli_hint: str) -> str:
    """Hem Hayabusa hem Chainsaw için ortak render -- ikisi de aynı
    DetectionSummary/Finding şemasını üretiyor (bkz. yukarıdaki iki fonksiyon)."""
    if summary is None:
        return (
            f"<h2>{_e(engine_label)} özeti</h2>"
            f'<div class="empty">{_e(engine_label)} henüz çalıştırılmadı '
            f"(<code>{_e(cli_hint)}</code>).</div>"
        )

    levels = ", ".join(f"{name}: {count}" for name, count in sorted(summary.level_counts.items()))
    rows = _kv_rows(
        [
            ("Koşu (run_id)", summary.run_id),
            ("Başlangıç (UTC)", _dt(summary.started_at_utc)),
            ("Bitiş (UTC)", _dt(summary.ended_at_utc)),
            ("Taranan dosya", str(summary.scanned_count)),
            ("Toplam bulgu", str(summary.finding_count)),
            ("Seviyeye göre dağılım", levels or "-"),
            ("Atlanan", str(summary.skipped_count)),
            ("Taranamayan dosya", str(summary.error_count)),
        ]
    )
    out = [f"<h2>{_e(engine_label)} özeti</h2><table>{rows}</table>"]

    if summary.findings:
        shown = summary.findings[:HTML_FINDING_LIMIT]
        body = "".join(
            "<tr>"
            f"<td>{_e(f.rule_title)}</td>"
            f'<td><span class="badge {_e(f.level.lower())}">{_e(f.level or "-")}</span></td>'
            f"<td>{_e(f.timestamp)}</td>"
            f"<td>{_e(f.computer)}</td>"
            f"<td>{_e(f.mitre_tags or '-')}</td>"
            "</tr>"
            for f in shown
        )
        out.append(
            f"<h2>{_e(engine_label)} bulguları</h2><table><tr><th>Kural</th><th>Seviye</th>"
            f"<th>Zaman</th><th>Bilgisayar</th><th>MITRE ATT&amp;CK</th></tr>{body}</table>"
        )
        if len(summary.findings) > len(shown):
            out.append(
                f'<p class="sub">{len(summary.findings)} bulgunun ilk {len(shown)} tanesi '
                "gösteriliyor; tamamı <code>report.json</code> içinde.</p>"
            )
    return "".join(out)


def _yara_section(report: Report) -> str:
    """YARA tarama özeti + eşleşme tablosu; hiç çalıştırılmadıysa açıklayıcı not."""
    return _yara_shaped_section(
        report.yara, engine_label="YARA", cli_hint="triagechain yara-scan",
        match_heading="YARA eşleşmeleri", match_label="eşleşme",
    )


def _capa_section(report: Report) -> str:
    """capa yetenek-analizi özeti + eşleşme tablosu -- YARA ile AYNI
    YaraSummary/YaraMatch şemasını paylaştığı için AYNI render mantığını
    kullanır (bkz. _yara_shaped_section). BİLEREK risk/korelasyon bölümlerine
    girmez: capa "yetenek" tespit eder, kötü amaçlı davranış değil (bkz.
    aldigim_kararlar.md -> "capa entegrasyonu")."""
    return _yara_shaped_section(
        report.capa, engine_label="capa", cli_hint="triagechain capa-scan",
        match_heading="capa yetenek eşleşmeleri", match_label="yetenek",
    )


def _watchlist_section(report: Report) -> str:
    """Hash listesi (watchlist/IOC) eşleştirme özeti + eşleşme tablosu -- YARA
    ile AYNI YaraSummary/YaraMatch şemasını paylaştığı için AYNI render
    mantığını kullanır (bkz. _yara_shaped_section). capa'nın AKSİNE bir
    eşleşme risk seviyesine DOĞRUDAN girer (bkz. reporting/executive.py)."""
    return _yara_shaped_section(
        report.watchlist, engine_label="Hash listesi (watchlist)",
        cli_hint="triagechain watchlist-check",
        match_heading="Hash listesi eşleşmeleri", match_label="eşleşme",
    )


def _yara_shaped_section(
    summary, engine_label: str, cli_hint: str, match_heading: str, match_label: str
) -> str:
    """YARA ve capa için ortak render -- ikisi de aynı YaraSummary/YaraMatch
    şemasını üretiyor (bkz. yukarıdaki iki fonksiyon)."""
    if summary is None:
        return (
            f"<h2>{_e(engine_label)} tarama özeti</h2>"
            f'<div class="empty">{_e(engine_label)} taraması henüz çalıştırılmadı '
            f"(<code>{_e(cli_hint)}</code>).</div>"
        )
    rows = _kv_rows(
        [
            ("Koşu (run_id)", summary.run_id),
            ("Başlangıç (UTC)", _dt(summary.started_at_utc)),
            ("Bitiş (UTC)", _dt(summary.ended_at_utc)),
            ("Taranan dosya", str(summary.scanned_count)),
            (f"Toplam {match_label}", str(summary.match_count)),
            ("Atlanan", str(summary.skipped_count)),
            ("Taranamayan dosya", str(summary.error_count)),
        ]
    )
    out = [f"<h2>{_e(engine_label)} tarama özeti</h2><table>{rows}</table>"]
    if summary.matches:
        shown = summary.matches[:HTML_FINDING_LIMIT]
        body = "".join(
            "<tr>"
            f"<td>{_e(m.rule_name)}</td>"
            f"<td>{_e(m.tags or '-')}</td>"
            f"<td>{_e(m.source_path)}</td>"
            "</tr>"
            for m in shown
        )
        out.append(
            f"<h2>{_e(match_heading)}</h2><table><tr><th>Kural</th><th>Etiketler</th>"
            f"<th>Dosya</th></tr>{body}</table>"
        )
    return "".join(out)


def _correlation_section(report: Report) -> str:
    """Hem Sigma/Hayabusa HEM YARA'nin isaretledigi dosyalar -- iki bagimsiz
    motorun ayni sonuca vardigi, daha guclu bir sinyal (bkz. correlation.py)."""
    if report.detection is None or report.yara is None:
        return ""
    if not report.correlated_artifacts:
        return (
            "<h2>Motor korelasyonu</h2>"
            '<div class="empty">Sigma/Hayabusa ve YARA aynı dosyayı işaretlemedi '
            "(kesişim boş).</div>"
        )
    body = "".join(
        "<tr>"
        f"<td>{_e(item.source_path)}</td>"
        f"<td>{_e(', '.join(item.sigma_rule_titles))}</td>"
        f"<td>{_e(', '.join(item.yara_rule_names))}</td>"
        "</tr>"
        for item in report.correlated_artifacts
    )
    return (
        "<h2>Motor korelasyonu</h2>"
        '<p class="sub">Bu dosyalar HEM Sigma/Hayabusa HEM YARA tarafından '
        "işaretlendi — bağımsız iki tekniğin aynı sonuca varması daha güçlü "
        "bir sinyaldir.</p>"
        "<table><tr><th>Dosya</th><th>Sigma kuralları</th>"
        f"<th>YARA kuralları</th></tr>{body}</table>"
    )


def _engine_agreements_section(report: Report) -> str:
    """Hayabusa VE Chainsaw'in AYNI kurali AYNI dosyada bulduğu durumlar --
    _correlation_section (Sigma+YARA) ile ayni desen, farkli veri kaynagi
    (bkz. detection/correlation.py -> correlate_sigma_engines)."""
    if report.detection is None or report.chainsaw is None:
        return ""
    if not report.engine_agreements:
        return (
            "<h2>Motor ittifakı (Hayabusa + Chainsaw)</h2>"
            '<div class="empty">İki Sigma motoru aynı kuralı aynı dosyada '
            "bulmadı (kesişim boş).</div>"
        )
    body = "".join(
        f"<tr><td>{_e(item.source_path)}</td><td>{_e(item.rule_title)}</td></tr>"
        for item in report.engine_agreements
    )
    return (
        "<h2>Motor ittifakı (Hayabusa + Chainsaw)</h2>"
        '<p class="sub">Bu dosyalarda İKİ BAĞIMSIZ Sigma motoru (Hayabusa ve '
        "Chainsaw) AYNI kuralı buldu — aynı kural setini kullanan iki farklı "
        "motorun anlaşması, tek motora göre daha güçlü bir doğrulamadır.</p>"
        f"<table><tr><th>Dosya</th><th>Kural</th></tr>{body}</table>"
    )


_TOOL_LABELS = {
    "mftecmd": "$MFT", "recmd": "Registry", "evtxecmd": "Olay Günlüğü", "pecmd": "Prefetch",
}


def _timeline_section(report: Report) -> str:
    """MFTECmd/RECmd/EvtxECmd/PECmd ciktilarindan birlestirilmis, kronolojik
    zaman cizelgesi -- Plaso'nun 'super zaman cizelgesi' fikrinin yeni bir dis
    arac gerektirmeyen hali (bkz. reporting/timeline.py)."""
    if not report.timeline:
        return (
            "<h2>Zaman çizelgesi</h2>"
            '<div class="empty">Zaman çizelgesi oluşturulamadı — '
            "<code>triagechain route</code> hiç çalışmamış olabilir ya da "
            "hiçbir araç CSV çıktısı üretmedi.</div>"
        )
    shown = report.timeline[:HTML_FINDING_LIMIT]
    body = "".join(
        "<tr>"
        f"<td>{_e(event.timestamp)}</td>"
        f"<td>{_e(_TOOL_LABELS.get(event.tool, event.tool))}</td>"
        f"<td>{_e(event.description)}</td>"
        f"<td>{_e(event.detail)}</td>"
        "</tr>"
        for event in shown
    )
    out = [
        "<h2>Zaman çizelgesi</h2>"
        '<p class="sub">$MFT, registry, olay günlüğü ve prefetch çıktılarından '
        "birleştirilmiş, kronolojik sıralı olaylar.</p>"
        "<table><tr><th>Zaman</th><th>Kaynak</th><th>Olay</th>"
        f"<th>Ayrıntı</th></tr>{body}</table>"
    ]
    if len(report.timeline) > len(shown):
        out.append(
            f'<p class="sub">{len(report.timeline)} olayın ilk {len(shown)} tanesi '
            "gösteriliyor; tamamı <code>report.json</code> içinde.</p>"
        )
    return "".join(out)


def _custody_section(report: Report) -> str:
    """Gözetim zincirinin TAM olay listesi (zaman sırasıyla)."""
    body = "".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td>{_e(_dt(event.timestamp_utc))}</td>"
        f"<td>{_e(event.event_type)}</td>"
        f"<td>{_e(event.operator)}</td>"
        f"<td><pre>{_e(json.dumps(event.payload, ensure_ascii=False, sort_keys=True))}</pre></td>"
        "</tr>"
        for index, event in enumerate(report.custody_events, start=1)
    )
    return (
        "<h2>Gözetim zinciri olayları</h2>"
        "<table><tr><th>#</th><th>Zaman (UTC)</th><th>Olay</th><th>Operatör</th>"
        f"<th>Yük (payload)</th></tr>{body}</table>"
    )


def _kv_rows(pairs: list[tuple[str, str]]) -> str:
    """Anahtar/deger satirlarini uretir."""
    return "".join(
        f'<tr><td class="key">{_e(key)}</td><td>{_e(value)}</td></tr>' for key, value in pairs
    )


def _dt(value: Optional[datetime]) -> str:
    """Datetime'i rapora yazilacak metne cevirir."""
    return value.isoformat() if value is not None else "-"


def _e(value: Any) -> str:
    """HTML kacisi; sayilar/None de guvenle metne cevrilir."""
    return html.escape(str(value), quote=True)
