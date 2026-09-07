"""Rapordan turetilen, teknik olmayan "Yonetici Raporu" ozeti.

Burada UYDURULAN hicbir sey yok: risk seviyesi, Report'un zaten tasidigi
gercek sayilardan (bulgu seviyeleri, zincir gecerliligi) DETERMINISTIK bir
kurala gore hesaplaniyor. Kural basit ve kasitli olarak muhafazakar (en
kotu sinyal kazanir) -- amac kesin bir "risk skoru" degil, teknik olmayan
bir okuyucunun raporu 5 saniyede tarayabilecegi bir ozet.
"""

from __future__ import annotations

from dataclasses import dataclass

from triagechain.reporting.models import Report

# Onem sirasi dusukten yuksege -- assess_risk() en kotu sinyali secer.
RISK_LEVELS = ("Bulgu Yok", "Düşük", "Orta", "Yüksek", "Kritik")


@dataclass
class ExecutiveSummary:
    """Yonetici Raporu sekmesinde gosterilecek her sey."""

    risk_level: str
    risk_reason: str
    narrative: str
    artifact_count: int
    finding_count: int
    high_severity_count: int
    chain_is_valid: bool
    yara_match_count: int
    correlated_count: int
    engine_agreement_count: int


def assess_risk(report: Report) -> tuple[str, str]:
    """(seviye, gerekce) dondurur -- sadece Report'taki gercek sayilardan.

    Kural (en kotu sinyal kazanir):
    1. Zincir GECERSIZ  -> Kritik (kanit butunlugu kaybi, bulgu sayisindan
       bagimsiz olarak en ciddi sinyal -- bkz. chain_of_custody.md).
    2. Korelasyon VAR (Sigma VE YARA ayni dosyayi isaretledi) VEYA motor
       ittifaki VAR (Hayabusa VE Chainsaw ayni kurali ayni dosyada buldu)
       -> Kritik (iki BAGIMSIZ teknigin/motorun ayni sonuca varmasi --
       bkz. correlation.py).
    3. >=1 high/critical Sigma bulgusu (Hayabusa VEYA Chainsaw) VEYA >=1
       YARA eslesmesi -> Yuksek (YARA statik imza eslesmesi kendi basina
       zaten spesifik bir gostergedir, Sigma'nin aksine "dusuk onemli" bir
       YARA kullanimi yaygin degil).
    4. >=1 bulgu (dusuk/orta Sigma, Hayabusa VEYA Chainsaw) -> Orta
    5. Hic bulgu yok ama toplama hatasi var -> Dusuk
    6. Hic bulgu/hata yok -> "Bulgu Yok"
    """
    if not report.chain_status.is_valid:
        return "Kritik", (
            f"Kanıt zincirinin bütünlüğü bozulmuş ({report.chain_status.message})."
        )

    if report.correlated_artifacts:
        n = len(report.correlated_artifacts)
        return "Kritik", (
            f"{n} dosya HEM davranışsal (Sigma) HEM imza tabanlı (YARA) "
            "tarama tarafından bağımsız olarak işaretlendi."
        )

    if report.engine_agreements:
        n = len(report.engine_agreements)
        return "Kritik", (
            f"{n} dosyada Hayabusa VE Chainsaw (iki bağımsız Sigma motoru) "
            "aynı kuralı bağımsız olarak doğruladı."
        )

    detection = report.detection
    chainsaw = report.chainsaw
    yara = report.yara
    high = 0
    total_findings = 0
    for summary in (detection, chainsaw):
        if summary is not None:
            high += sum(1 for f in summary.findings if f.level.lower() in ("high", "critical"))
            total_findings += summary.finding_count
    yara_match_count = yara.match_count if yara is not None else 0

    if high:
        return "Yüksek", f"{high} adet yüksek/kritik önemde güvenlik bulgusu tespit edildi."
    if yara_match_count:
        return "Yüksek", f"{yara_match_count} adet YARA imza eşleşmesi tespit edildi."
    if total_findings:
        return "Orta", f"{total_findings} adet düşük/orta önemde bulgu tespit edildi."

    if report.collection.error_count:
        return "Düşük", (
            f"Güvenlik bulgusu yok, ancak {report.collection.error_count} dosya alınamadı."
        )

    return "Bulgu Yok", "Toplanan veride herhangi bir güvenlik bulgusuna rastlanmadı."


def build_executive_summary(report: Report) -> ExecutiveSummary:
    """Report'tan, teknik terim icermeyen bir ozet cikarir."""
    risk_level, risk_reason = assess_risk(report)
    finding_count = 0
    high_severity_count = 0
    for summary in (report.detection, report.chainsaw):
        if summary is not None:
            finding_count += summary.finding_count
            high_severity_count += sum(
                1 for f in summary.findings if f.level.lower() in ("high", "critical")
            )
    yara_match_count = report.yara.match_count if report.yara is not None else 0
    correlated_count = len(report.correlated_artifacts)
    engine_agreement_count = len(report.engine_agreements)

    chain_phrase = (
        "kanıt zincirinin bütünlüğü doğrulandı"
        if report.chain_status.is_valid
        else "kanıt zincirinin bütünlüğünde bir bozulma tespit edildi"
    )
    if finding_count:
        finding_phrase = (
            f"{finding_count} güvenlik bulgusu tespit edildi "
            f"({high_severity_count} tanesi yüksek/kritik önemde)"
        )
    else:
        finding_phrase = "herhangi bir güvenlik bulgusuna rastlanmadı"

    narrative = (
        f'"{report.case_id}" vakası kapsamında {report.collection.artifact_count} dosya '
        f"incelendi, {finding_phrase} ve {chain_phrase}."
    )
    if yara_match_count:
        narrative += f" Ayrıca {yara_match_count} adet YARA imza eşleşmesi bulundu."
    if correlated_count:
        narrative += (
            f" Bunlardan {correlated_count} dosya hem davranışsal hem imza tabanlı "
            "taramada işaretlendi."
        )
    if engine_agreement_count:
        narrative += (
            f" {engine_agreement_count} dosyada iki bağımsız davranışsal tarama motoru "
            "aynı kuralı doğruladı."
        )

    return ExecutiveSummary(
        risk_level=risk_level,
        risk_reason=risk_reason,
        narrative=narrative,
        artifact_count=report.collection.artifact_count,
        finding_count=finding_count,
        high_severity_count=high_severity_count,
        chain_is_valid=report.chain_status.is_valid,
        yara_match_count=yara_match_count,
        correlated_count=correlated_count,
        engine_agreement_count=engine_agreement_count,
    )
