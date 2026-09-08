"""Katalogtaki hedef kimliklerini yerel dosya sistemindeki somut yollara cevirir."""

from __future__ import annotations

import glob
import ntpath
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from triagechain.core.errors import ConfigError

# %SystemDrive% / %WinDir% gibi Windows tarzi ortam degiskeni kaliplari.
_ENV_PATTERN = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

# Windows disinda test edilebilmek icin bilinen degiskenlere makul varsayilanlar.
_ENV_FALLBACKS = {
    "SystemDrive": "C:",
    "WinDir": r"C:\Windows",
    "SystemRoot": r"C:\Windows",
}


@dataclass
class ResolvedTarget:
    """Bir katalog girdisinin, o makinede gercekten bulunan yollarla hali."""

    target_id: str
    category: str
    requires_vss: bool
    description: str
    # Bos liste gecerlidir: glob hicbir dosyaya uymamis olabilir. Bu durum
    # konfigurasyon hatasi degil, toplayicinin kaydedecegi bir artefakt hatasidir.
    paths: list[Path] = field(default_factory=list)


def load_catalog(catalog_path: Path) -> dict[str, dict]:
    """Katalog YAML'ini okuyup id -> girdi sozlugu dondurur."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Artefakt katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Artefakt katalogu gecerli YAML degil: {catalog_path} ({exc})") from exc

    entries = (raw or {}).get("targets") or []
    return {entry["id"]: entry for entry in entries}


def expand_pattern(pattern: str, source_root: Path | None = None) -> list[Path]:
    """Ortam degiskenlerini ve glob'lari acar, somut yol listesi dondurur.

    `source_root` verilmisse (bkz. `collection.source_root` -- daha once
    BASKA bir aracla (orn. KAPE) toplanmis, artik canli/kilitli OLMAYAN bir
    artefakt agacini "vaka" olarak ice aktarmak icin), her kalip -- ister
    `%SystemDrive%` degiskeni ister `C:\\Users\\*\\...` gibi sabit bir surucu
    harfiyle baslasin -- KENDI surucu harfi cikarilip `source_root` altina
    yeniden koklendiriliyor. Boylece katalogda TEK bir yol seti hem canli
    sistem hem ice aktarilmis bir kok icin calisiyor, iki ayri katalog
    gerekmiyor.
    """
    expanded = _ENV_PATTERN.sub(
        lambda m: os.environ.get(m.group(1), _ENV_FALLBACKS.get(m.group(1), m.group(0))),
        pattern,
    )
    if source_root is not None:
        # BILEREK os.path degil ntpath: katalog yollari HER ZAMAN Windows
        # sozdizimi (surucu harfi + ters bolu isareti) -- bu ayristirma
        # TriageChain'in kendisi hangi platformda CALISTIRILIYOR/TEST
        # EDILIYOR olursa olsun ayni sonucu vermeli (CI Linux'ta kosuyor,
        # os.path.splitdrive orada 'C:'yi surucu olarak TANIMAZ).
        _drive, rest = ntpath.splitdrive(expanded)
        segments = [s for s in re.split(r"[\\/]+", rest) if s]
        expanded = str(Path(source_root, *segments))
    if any(ch in expanded for ch in "*?["):
        # Glob: sifir veya daha fazla dosyaya acilabilir, sifir olmasi hata degil.
        return sorted(Path(p) for p in glob.glob(expanded))
    # Duz yol: dosya var mi diye bakmiyoruz. $MFT gibi kilitli dosyalar normal
    # erisimde gorunmez; erisilebilirlik karari toplama anina birakiliyor.
    return [Path(expanded)]


def resolve_targets(
    target_ids: list[str], catalog_path: Path, source_root: Path | None = None
) -> list[ResolvedTarget]:
    """Istenen hedef kimliklerini ResolvedTarget listesine cevirir.

    `source_root` bkz. `expand_pattern`. Ice aktarma modunda `requires_vss`
    ETIKETI KORUNUR (bulgu/rapor tarafinda hala "bu artefakt normalde kilitli
    olurdu" bilgisi anlamli) ama collector.py bu modda hicbir golge kopya
    ACMAZ -- ice aktarilan dosyalar zaten kilitli olmayan duz kopyalardir.
    """
    catalog = load_catalog(catalog_path)

    # Cagirana guvenmiyoruz: bilinmeyen kimlik burada da sert hata.
    unknown = [tid for tid in target_ids if tid not in catalog]
    if unknown:
        raise ConfigError(
            "Katalogda olmayan hedef kimlikleri: " + ", ".join(sorted(unknown))
        )

    resolved: list[ResolvedTarget] = []
    for target_id in target_ids:
        entry = catalog[target_id]
        paths: list[Path] = []
        for pattern in entry.get("paths", []):
            paths.extend(expand_pattern(pattern, source_root=source_root))
        resolved.append(
            ResolvedTarget(
                target_id=target_id,
                category=entry.get("category", ""),
                requires_vss=bool(entry.get("requires_vss", False)),
                description=entry.get("description", ""),
                paths=paths,
            )
        )
    return resolved
