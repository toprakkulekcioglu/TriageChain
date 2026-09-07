"""Iki tespit motorunun (Sigma/Hayabusa ve YARA) ciktilarini korele eder.

Korelasyon fikri basit ve kasitli olarak alcak gonullu: iki motor da AYNI
dosyayi (source_path) isaretlemisse, bu dosya tek bir motorun isaretlediginden
daha guclu bir sinyaldir -- davranissal (Sigma, olay-gunlugu) ve statik
(YARA, imza) iki bagimsiz teknik ayni sonuca varmis demektir. Hicbir puanlama/
agirliklandirma YOK, sadece kume kesisimi -- bkz. testler.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from triagechain.detection.models import DetectionManifest, YaraManifest


@dataclass
class CorrelatedArtifact:
    """Hem Sigma/Hayabusa HEM YARA tarafindan isaretlenmis tek bir dosya."""

    source_path: str
    sigma_rule_titles: list[str] = field(default_factory=list)
    yara_rule_names: list[str] = field(default_factory=list)


def correlate_findings(
    detection: DetectionManifest, yara: YaraManifest
) -> list[CorrelatedArtifact]:
    """İki manifestteki source_path kesisimini dondurur, sonuc source_path'e
    gore sıralı (deterministik -- ayni girdi hep ayni sirayla cikar)."""
    sigma_by_path: dict[str, list[str]] = defaultdict(list)
    for finding in detection.findings:
        sigma_by_path[finding.source_path].append(finding.rule_title)

    yara_by_path: dict[str, list[str]] = defaultdict(list)
    for match in yara.matches:
        yara_by_path[match.source_path].append(match.rule_name)

    shared_paths = sorted(set(sigma_by_path) & set(yara_by_path))
    return [
        CorrelatedArtifact(
            source_path=path,
            sigma_rule_titles=sigma_by_path[path],
            yara_rule_names=yara_by_path[path],
        )
        for path in shared_paths
    ]


@dataclass
class EngineAgreement:
    """AYNI Sigma kuralinin, AYNI dosyada, IKI BAGIMSIZ motor (Hayabusa VE
    Chainsaw) tarafindan tespit edildigi durum -- gercek capraz dogrulama."""

    source_path: str
    rule_title: str


def correlate_sigma_engines(
    hayabusa: DetectionManifest, chainsaw: DetectionManifest
) -> list[EngineAgreement]:
    """Hayabusa ve Chainsaw'in AYNI (source_path, rule_title) ciftini
    isaretledigi durumlari dondurur -- ikisi de config.detection.rules_dir
    ile AYNI Sigma kural setini kullandigi icin `rule_title` esitligi
    (kuralin kendi `title:` alani) anlamli bir karsilastirma olculur.

    Sonuc (source_path, rule_title) ciftine gore sıralı -- deterministik."""
    hayabusa_pairs = {(f.source_path, f.rule_title) for f in hayabusa.findings}
    chainsaw_pairs = {(f.source_path, f.rule_title) for f in chainsaw.findings}
    shared = sorted(hayabusa_pairs & chainsaw_pairs)
    return [EngineAgreement(source_path=path, rule_title=title) for path, title in shared]
