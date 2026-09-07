"""Katalogtaki hedef kimliklerini yerel dosya sistemindeki somut yollara cevirir."""

from __future__ import annotations

import glob
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


def expand_pattern(pattern: str) -> list[Path]:
    """Ortam degiskenlerini ve glob'lari acar, somut yol listesi dondurur."""
    expanded = _ENV_PATTERN.sub(
        lambda m: os.environ.get(m.group(1), _ENV_FALLBACKS.get(m.group(1), m.group(0))),
        pattern,
    )
    if any(ch in expanded for ch in "*?["):
        # Glob: sifir veya daha fazla dosyaya acilabilir, sifir olmasi hata degil.
        return sorted(Path(p) for p in glob.glob(expanded))
    # Duz yol: dosya var mi diye bakmiyoruz. $MFT gibi kilitli dosyalar normal
    # erisimde gorunmez; erisilebilirlik karari toplama anina birakiliyor.
    return [Path(expanded)]


def resolve_targets(target_ids: list[str], catalog_path: Path) -> list[ResolvedTarget]:
    """Istenen hedef kimliklerini ResolvedTarget listesine cevirir."""
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
            paths.extend(expand_pattern(pattern))
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
