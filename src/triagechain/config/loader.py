"""YAML konfigurasyonunu okuyup dogrulanmis TriageChainConfig'e cevirir."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError


def _format_validation_error(exc: ValidationError) -> str:
    """Pydantic hatasini kullaniciya gosterilebilecek kisa metne cevirir."""
    parts = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err["loc"]) or "(kok)"
        parts.append(f"{field}: {err['msg']}")
    return "; ".join(parts)


def resolve_custody_log_path(config: TriageChainConfig) -> Path:
    """Custody defteri yolunu dondurur.

    Turetme mantigi TEK yerde, burada duruyor: hem CLI hem toplayici bu
    fonksiyonu cagirir, boylece 'log_path: null' durumunda iki tarafin farkli
    dosyaya yazma riski kalmaz.
    """
    if config.custody.log_path:
        return Path(config.custody.log_path)
    return Path(config.collection.output_dir) / config.case.case_id / "custody.jsonl"


def resolve_manifest_path(config: TriageChainConfig) -> Path:
    """Toplama manifestinin yolunu dondurur.

    resolve_custody_log_path ile ayni tek-kaynak mantigi: 'collect' bu yola
    yazar, 'route' ayni yoldan okur; iki tarafin ayrisma riski kalmaz.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "manifest.json"


def resolve_routing_manifest_path(config: TriageChainConfig) -> Path:
    """Yonlendirme manifestinin yolunu dondurur.

    resolve_manifest_path ile ayni tek-kaynak mantigi: 'route' bu yola yazar,
    raporlama katmani ayni yoldan okur.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "routing_manifest.json"


def resolve_detection_manifest_path(config: TriageChainConfig) -> Path:
    """Tespit manifestinin yolunu dondurur.

    resolve_manifest_path ile ayni tek-kaynak mantigi: tespit kosusu bu yola
    yazar, CLI ayni yolu ekrana basar, ileride raporlama katmani ayni yerden
    okur.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "detection_manifest.json"


def resolve_yara_manifest_path(config: TriageChainConfig) -> Path:
    """YARA tarama manifestinin yolunu dondurur -- resolve_detection_manifest_path
    ile ayni tek-kaynak mantigi, ayri bir dosya (iki motor birbirinin
    ciktisini EZMESIN diye)."""
    return Path(config.collection.output_dir) / config.case.case_id / "yara_manifest.json"


def resolve_chainsaw_manifest_path(config: TriageChainConfig) -> Path:
    """Chainsaw tarama manifestinin yolunu dondurur -- ayni tek-kaynak mantigi,
    Hayabusa'nin detection_manifest.json'undan AYRI bir dosya (iki bagimsiz
    Sigma motorunun ciktisi birbirini EZMESIN diye)."""
    return Path(config.collection.output_dir) / config.case.case_id / "chainsaw_manifest.json"


def resolve_capa_manifest_path(config: TriageChainConfig) -> Path:
    """capa yetenek-analizi manifestinin yolunu dondurur -- ayni tek-kaynak
    mantigi, diger tespit motorlarindan AYRI bir dosya."""
    return Path(config.collection.output_dir) / config.case.case_id / "capa_manifest.json"


def resolve_watchlist_manifest_path(config: TriageChainConfig) -> Path:
    """Hash listesi (watchlist/IOC) eslestirme manifestinin yolunu dondurur --
    ayni tek-kaynak mantigi, diger tespit motorlarindan AYRI bir dosya."""
    return Path(config.collection.output_dir) / config.case.case_id / "watchlist_manifest.json"


def resolve_report_path(config: TriageChainConfig) -> Path:
    """Makine-okur raporun (report.json) yolunu dondurur.

    Ayni tek-kaynak mantigi: HTML raporu ve sha256 yan dosyasi da bu yoldan
    turetilir (`.html` / `.json.sha256`), boylece uc dosya hep yan yana durur.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "report.json"


def resolve_tags_path(config: TriageChainConfig) -> Path:
    """Analistin bulgu isaretleme (tag/bookmark) notlarinin yolunu dondurur.

    Ayni tek-kaynak mantigi -- ama ONEMLI bir fark: bu dosya gozetim
    zincirinin (custody.jsonl) veya herhangi bir *_manifest.json'un PARCASI
    DEGIL. Isaretler analistin SUBJEKTIF notu -- delilin kendisi degil,
    delile dair bir yorum -- bu yuzden hash zincirine YAZILMAZ (zincir
    SADECE toplama/yonlendirme/tespit OLAYLARINI tasir) ve manifest
    dosyalarindan AYRI tutulur (manifestler her kosuda YENIDEN uretilir,
    isaretler bir kosudan digerine KALICI olmali). Bkz. gui_qt/tag_store.py.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "tags.json"


def resolve_case_note_path(config: TriageChainConfig) -> Path:
    """Vakanin GENELINE ait serbest metin notunun yolunu dondurur.

    resolve_tags_path ile AYNI gerekce (gozetim zincirine/manifestlere
    KARISMAZ, ayri ve kalici bir dosya) -- tek fark isaretlerin (tags.json)
    aksine bu TEK bir bulguya degil VAKANIN GENELINE ait. Bkz.
    gui_qt/case_note_store.py.
    """
    return Path(config.collection.output_dir) / config.case.case_id / "case_note.json"


def load_config(path: str | Path) -> TriageChainConfig:
    """Konfigurasyon dosyasini okur, dogrular ve model olarak dondurur."""
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Konfigurasyon dosyasi bulunamadi: {config_path}") from exc
    except OSError as exc:
        raise ConfigError(f"Konfigurasyon dosyasi okunamadi: {config_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Konfigurasyon gecerli YAML degil: {config_path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Konfigurasyonun kokunde bir sozluk bekleniyordu: {config_path}")

    try:
        config = TriageChainConfig(**raw)
    except ValidationError as exc:
        # Ham pydantic traceback'i kullaniciya sizdirmiyoruz, ozetliyoruz.
        raise ConfigError(
            f"Konfigurasyon gecersiz ({config_path}): {_format_validation_error(exc)}"
        ) from None

    _check_output_dir(Path(config.collection.output_dir))
    return config


def _check_output_dir(output_dir: Path) -> None:
    """Cikti dizininin ust dizini var ve yazilabilir olmali; dizinin kendisi yaratilabilir."""
    parent = output_dir.parent
    if not parent.is_dir():
        raise ConfigError(
            f"Cikti dizininin ust dizini yok: {parent}. Once bu dizini olusturun."
        )
    if not os.access(parent, os.W_OK):
        raise ConfigError(f"Cikti dizininin ust dizinine yazilamiyor: {parent}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"Cikti dizini olusturulamadi: {output_dir} ({exc})") from exc
