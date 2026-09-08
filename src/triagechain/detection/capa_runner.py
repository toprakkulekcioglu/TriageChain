"""capa tarama akisi: analistin gosterdigi supheli PE dosyasini(lari) capa ile
davranis/yetenek analizine tabi tutar.

Guvenlik kurallari detection/runner.py (Hayabusa) ve router/runner.py ile
BIREBIR ayni (docs/architecture.md):
  1. subprocess her zaman arguman LISTESI ile cagrilir; shell=True hicbir yerde
     kullanilmaz.
  2. Arac (capa.exe) yolu MUTLAK olmalidir (config semasinda dogrulanir);
     varligi kosu aninda kontrol edilir.
  3. Araca verilen her girdi yolu, vakanin kendi cikti agaci
     (<output_dir>/<case_id>/artifacts) altinda cozulmelidir.
  4. Her cagrinin zaman asimi vardir; asilirsa olumcul olmayan hata kaydedilir.

Digerlerinden FARKI: capa bir OLAY GUNLUGUNU (Hayabusa/Chainsaw) ya da HER
artefakti (YARA) degil, SADECE `collection.suspicious_binaries` ile analistin
ELLE gosterdigi yurutulebilir dosyalari tarar (artifact_type_id ==
SCANNED_ARTIFACT_TYPE, bkz. collection/collector.py -> SUSPICIOUS_BINARY_
TARGET_ID). Sonuc da zaman damgali bir "bulgu" degil, o dosyanin tasidigi
"yetenekler" (kural adi + namespace + varsa MITRE ATT&CK id'leri) listesidir
-- bu yuzden Finding/DetectionManifest DEGIL, YARA'nin YaraMatch/YaraManifest
semasini paylasir: capa da (YARA gibi) TEK bir dosyaya karsi calisip
adlandirilmis kural eslesmeleri uretir, olay-tabanli bir zaman/bilgisayar/
kanal baglami YOKTUR (bkz. aldigim_kararlar.md -> "capa entegrasyonu").

capa'nin Hayabusa/Chainsaw/YARA'dan onemli bir farki: gomulu (embedded) bir
varsayilan kural setiyle KUTUDAN CIKTIGI GIBI calisir -- `detection.
capa_rules_dir` SADECE bir override, zorunlu degildir. Bu yuzden "arac/kural
konfigure edilmemis" atlama mantigi SADECE capa_path icin gecerlidir.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.collection.winpath import to_long_path
from triagechain.config.loader import resolve_capa_manifest_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError, DetectionError
from triagechain.custody.ledger import CustodyLedger
from triagechain.detection import catalog as catalog_module
from triagechain.detection.models import YaraManifest, YaraMatch

logger = logging.getLogger(__name__)

STDERR_EXCERPT_LIMIT = 2000

# Sadece analistin elle gosterdigi supheli dosyalar taranir -- bkz.
# collection/collector.py -> SUSPICIOUS_BINARY_TARGET_ID (AYNI deger,
# artifact_type_id = target_id oldugu icin ikisi birbirine baglidir).
SCANNED_ARTIFACT_TYPE = "suspicious_binary"

# Kullanilan custody olay tipleri:
#   capa_started               - capa tarama kosusu basladi
#   capa_completed_for_artifact - bir dosya tarandi (dosya basina TEK ozet olay)
#   capa_skipped                - tarama atlandi (capa_path konfigure degil)
#   capa_error                  - arac sifirdan farkli kod dondurdu, zaman
#                                 asimina ugradi ya da girdi yolu agac disinda kaldi
#   capa_completed               - tarama kosusu bitti (manifest sha256'si ile)


@dataclass
class CapaProfile:
    """capa_args.yaml icindeki cagri sablonu (rules_dir HARIC -- kosullu
    oldugu icin _scan_artifact tarafindan koda, veri olarak DEGIL, eklenir)."""

    args: list[str]
    json_fields: dict[str, str] = field(default_factory=dict)


def load_capa_profile(catalog_path: Path) -> CapaProfile:
    """capa cagri sablonu YAML'ini okur (diger *_runner.py'lerle ayni desen)."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"capa sablon katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"capa sablon katalogu gecerli YAML degil: {catalog_path} ({exc})"
        ) from exc

    raw = raw or {}
    return CapaProfile(
        args=list(raw.get("args") or []),
        json_fields=dict(raw.get("json_fields") or {}),
    )


def run_capa_scan(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> YaraManifest:
    """Toplanmis supheli PE dosyalarini capa ile tarar ve yetenekleri dondurur."""
    operator = config.case.operator
    case_id = config.case.case_id
    case_dir = Path(config.collection.output_dir) / case_id
    artifacts_root = (case_dir / "artifacts").resolve()

    capa_manifest = YaraManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))
    targets = [a for a in manifest.artifacts if a.artifact_type_id == SCANNED_ARTIFACT_TYPE]

    ledger.append_event(
        "capa_started",
        operator,
        {
            "run_id": capa_manifest.run_id,
            "collection_run_id": manifest.run_id,
            "artifact_count": len(targets),
            "output_dir": str(case_dir),
        },
    )

    unavailable = _tool_unavailable_reason(config)
    if unavailable is not None:
        _record_skip(capa_manifest, ledger, operator, unavailable, artifact_count=len(targets))
    else:
        profile = load_capa_profile(catalog_module.default_capa_catalog_path())
        for artifact in targets:
            _scan_artifact(
                artifact=artifact,
                profile=profile,
                config=config,
                case_dir=case_dir,
                artifacts_root=artifacts_root,
                operator=operator,
                capa_manifest=capa_manifest,
                ledger=ledger,
            )

    capa_manifest.ended_at_utc = datetime.now(timezone.utc)

    manifest_path = resolve_capa_manifest_path(config)
    try:
        capa_manifest.to_json_file(manifest_path)
    except OSError as exc:
        raise DetectionError(f"capa manifesti yazilamadi: {manifest_path} ({exc})") from exc

    ledger.append_event(
        "capa_completed",
        operator,
        {
            "run_id": capa_manifest.run_id,
            "scanned_count": len(capa_manifest.scanned),
            "match_count": len(capa_manifest.matches),
            "skipped_count": len(capa_manifest.skipped),
            "error_count": len(capa_manifest.errors),
            "capa_manifest_path": str(manifest_path),
            "capa_manifest_sha256": hash_file(manifest_path),
        },
    )
    return capa_manifest


def _tool_unavailable_reason(config: TriageChainConfig) -> Optional[str]:
    """capa calistirilamayacaksa nedenini dondurur; calistirilabiliyorsa None.

    capa_rules_dir BURADA kontrol EDILMEZ: capa gomulu varsayilan kurallarla
    zaten calisir, ozel bir kural klasoru ZORUNLU degildir (bkz. modul
    dokstring'i)."""
    detection_config = config.detection
    if not detection_config.capa_path:
        return "capa konfigure edilmemis (detection.capa_path bos)."
    if not Path(detection_config.capa_path).is_file():
        return f"capa yolu bulunamadi: {detection_config.capa_path}"
    if detection_config.capa_rules_dir and not Path(detection_config.capa_rules_dir).is_dir():
        return f"capa kural klasoru bulunamadi: {detection_config.capa_rules_dir}"
    return None


def _scan_artifact(
    artifact: CollectedArtifact,
    profile: CapaProfile,
    config: TriageChainConfig,
    case_dir: Path,
    artifacts_root: Path,
    operator: str,
    capa_manifest: YaraManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir supheli dosyayi capa ile tarar."""
    source_path = _contained_source_path(artifact.dest_path, artifacts_root)
    if source_path is None:
        _record_error(
            capa_manifest, ledger, operator, artifact,
            f"Girdi yolu vakanin cikti agaci disinda kaliyor ({artifact.dest_path}); "
            f"beklenen kok: {artifacts_root}. Manifest degistirilmis olabilir, "
            "capa calistirilmadi.",
        )
        return

    output_dir = case_dir / "detections" / "capa"
    try:
        to_long_path(output_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DetectionError(f"capa cikti dizini olusturulamadi: {output_dir} ({exc})") from exc

    base_args = [arg.format(input=str(source_path)) for arg in profile.args]
    # capa_rules_dir KOSULLU: ayarlanmamissa capa kendi gomulu kurallarini
    # kullanir, "-r" argumani hic eklenmez (bkz. modul dokstring'i).
    rules_args = (
        ["-r", str(config.detection.capa_rules_dir)] if config.detection.capa_rules_dir else []
    )
    argv = [str(config.detection.capa_path)] + rules_args + base_args

    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=config.detection.capa_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _record_error(
            capa_manifest, ledger, operator, artifact,
            f"capa {config.detection.capa_timeout_seconds} saniyede bitmedi, sonlandirildi.",
        )
        return
    duration = time.monotonic() - started

    stdout_log, stderr_log = _write_tool_logs(
        output_dir, source_path.name, result.stdout, result.stderr
    )

    if result.returncode != 0:
        _record_error(
            capa_manifest, ledger, operator, artifact,
            f"capa {result.returncode} koduyla cikti (desteklenmeyen dosya "
            "bicimi olabilir).",
            exit_code=result.returncode,
            stderr_excerpt=_decode(result.stderr)[:STDERR_EXCERPT_LIMIT],
            stdout_log_path=str(stdout_log),
            stderr_log_path=str(stderr_log),
        )
        return

    matches, warning = _parse_matches(_decode(result.stdout), artifact, source_path, profile)
    capa_manifest.matches.extend(matches)

    entry: dict[str, Any] = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": str(source_path),
        "stdout_log_path": str(stdout_log),
        "stderr_log_path": str(stderr_log),
        "match_count": len(matches),
        "duration_seconds": round(duration, 3),
    }
    if warning:
        entry["parse_warning"] = warning
    capa_manifest.scanned.append(entry)
    ledger.append_event("capa_completed_for_artifact", operator, dict(entry))


def _parse_matches(
    stdout: str, artifact: CollectedArtifact, source_path: Path, profile: CapaProfile
) -> tuple[list[YaraMatch], Optional[str]]:
    """capa'nin `-j` JSON ciktisini EN IYI CABA ile yetenek eslesmelerine cevirir.

    Ayristirma basarisiz olursa OLUMCUL DEGIL: bos eslesme listesi + uyari
    metni doner, ham stdout zaten stdout.log dosyasinda durur."""
    if not stdout.strip():
        return [], "capa bos cikti verdi."
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return [], f"capa ciktisi JSON olarak ayristirilamadi: {exc}"

    rules = data.get("rules")
    if not isinstance(rules, dict):
        return [], "capa ciktisinda beklenen 'rules' sozlugu yok."

    matches = [
        YaraMatch(
            artifact_type_id=artifact.artifact_type_id,
            source_path=str(source_path),
            rule_name=str(rule_name),
            tags=_attack_ids(rule_data, profile),
            meta=_namespace(rule_data, profile),
        )
        for rule_name, rule_data in rules.items()
        if isinstance(rule_data, dict)
    ]
    return matches, None


def _namespace(rule_data: dict, profile: CapaProfile) -> str:
    """capa kuralinin namespace'ini ('meta.namespace' yolundan) okur --
    YaraMatch.meta ile ayni 'k=v' bicimi (bkz. detection/models.py)."""
    path = profile.json_fields.get("namespace")
    if not path:
        return ""
    value: Any = rule_data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return ""
        value = value[part]
    return f"namespace={value}" if value else ""


def _attack_ids(rule_data: dict, profile: CapaProfile) -> str:
    """capa kuralinin MITRE ATT&CK id'lerini ('meta.attack' yolundan) okur.

    Chainsaw/Sigma'nin duz string listesinden (bkz. chainsaw_runner.py ->
    _field_text) FARKLI: capa'nin 'attack' alani birer SOZLUK listesidir
    (her biri kendi 'id' anahtarini tasir), bu yuzden genel nokta-yolu
    okuyucusu yerine capa'ya ozgu bu kucuk ayiklama gerekiyor."""
    path = profile.json_fields.get("attack_ids")
    if not path:
        return ""
    value: Any = rule_data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return ""
        value = value[part]
    if not isinstance(value, list):
        return ""
    ids = [str(item["id"]) for item in value if isinstance(item, dict) and item.get("id")]
    return ",".join(ids)


def _contained_source_path(dest_path: str, artifacts_root: Path) -> Optional[Path]:
    """detection/runner.py'deki ayni adli fonksiyonla birebir ayni kural."""
    try:
        resolved = Path(dest_path).resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(artifacts_root) else None


def _write_tool_logs(
    output_dir: Path, filename: str, stdout: Optional[bytes], stderr: Optional[bytes]
) -> tuple[Path, Path]:
    """detection/runner.py'deki ayni adli fonksiyonla birebir ayni kural."""
    stdout_log = output_dir / f"{filename}.stdout.log"
    stderr_log = output_dir / f"{filename}.stderr.log"
    to_long_path(stdout_log).write_text(_decode(stdout), encoding="utf-8")
    to_long_path(stderr_log).write_text(_decode(stderr), encoding="utf-8")
    return stdout_log, stderr_log


def _decode(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def _record_skip(
    capa_manifest: YaraManifest,
    ledger: CustodyLedger,
    operator: str,
    message: str,
    artifact_count: int,
) -> None:
    logger.info("[capa] %s", message)
    entry = {"message": message, "artifact_count": artifact_count}
    capa_manifest.skipped.append(entry)
    ledger.append_event("capa_skipped", operator, dict(entry))


def _record_error(
    capa_manifest: YaraManifest,
    ledger: CustodyLedger,
    operator: str,
    artifact: CollectedArtifact,
    message: str,
    **extra: Any,
) -> None:
    logger.warning("[%s] %s", artifact.artifact_type_id, message)
    entry = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": artifact.dest_path,
        "message": message,
        **extra,
    }
    capa_manifest.errors.append(entry)
    ledger.append_event("capa_error", operator, dict(entry))
