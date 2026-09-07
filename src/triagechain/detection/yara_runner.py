"""YARA tarama akisi: her toplanan artefakti sec, dogrula, YARA'yi calistir, eslesmeleri cikar.

Guvenlik kurallari detection/runner.py (Hayabusa) ve router/runner.py ile
BIREBIR ayni (docs/architecture.md):
  1. subprocess her zaman arguman LISTESI ile cagrilir; shell=True hicbir yerde
     kullanilmaz.
  2. Arac (yara64.exe) ve kural dosyasi yollari MUTLAK olmalidir (config
     semasinda dogrulanir); varliklari kosu aninda kontrol edilir.
  3. Araca verilen her girdi yolu, vakanin kendi cikti agaci
     (<output_dir>/<case_id>/artifacts) altinda cozulmelidir.
  4. Her cagrinin zaman asimi vardir; asilirsa olumcul olmayan hata kaydedilir.

Hayabusa'dan FARKI: Hayabusa yalnizca .evtx tarar ve bir CSV dosyasina yazar;
YARA butun artefakt turlerini (statik imza taramasi herhangi bir dosya
formatinda anlamli) tarar ve sonucu DOGRUDAN stdout'a yazar -- ayri bir
cikti dosyasi yok, cagri sablonu bu yuzden daha basit (bkz.
detection/catalog/yara_args.yaml basindaki NOT, gercek ikiliye karsi
DOGRULANDI).
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.loader import resolve_yara_manifest_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError, DetectionError
from triagechain.custody.ledger import CustodyLedger
from triagechain.detection import catalog as catalog_module
from triagechain.detection.models import YaraManifest, YaraMatch

logger = logging.getLogger(__name__)

STDERR_EXCERPT_LIMIT = 2000

# Kullanilan custody olay tipleri:
#   yara_started               - YARA tarama kosusu basladi
#   yara_completed_for_artifact - bir dosya tarandi (dosya basina TEK ozet olay)
#   yara_skipped                - tarama atlandi (arac/kural konfigure degil)
#   yara_error                  - arac sifirdan farkli kod dondurdu, zaman
#                                 asimina ugradi ya da girdi yolu agac disinda kaldi
#   yara_completed               - tarama kosusu bitti (manifest sha256'si ile)


@dataclass
class YaraProfile:
    """yara_args.yaml icindeki cagri sablonu ve stdout satir deseni."""

    args: list[str]
    line_pattern: str = r'^(\S+)\s+\[([^\]]*)\]\s+\[([^\]]*)\]\s+(.+)$'


def load_yara_profile(catalog_path: Path) -> YaraProfile:
    """YARA cagri sablonu YAML'ini okur (detection.load_profile ile ayni desen)."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"YARA sablon katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"YARA sablon katalogu gecerli YAML degil: {catalog_path} ({exc})"
        ) from exc

    raw = raw or {}
    return YaraProfile(
        args=list(raw.get("args") or []),
        line_pattern=raw.get("line_pattern") or YaraProfile.line_pattern,
    )


def run_yara_scan(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> YaraManifest:
    """Toplanmis HER artefakti YARA ile tarar ve eslesmeleri dondurur.

    Hayabusa'nin aksine tek bir artefakt turuyle sinirli degil: YARA statik
    imza taramasi herhangi bir dosya formatinda anlamli (MFT kaydi, registry
    kovani, prefetch, event log -- hepsi taranir).
    """
    operator = config.case.operator
    case_id = config.case.case_id
    case_dir = Path(config.collection.output_dir) / case_id
    artifacts_root = (case_dir / "artifacts").resolve()

    yara_manifest = YaraManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))
    targets = list(manifest.artifacts)

    started_payload: dict[str, Any] = {
        "run_id": yara_manifest.run_id,
        "collection_run_id": manifest.run_id,
        "artifact_count": len(targets),
        "output_dir": str(case_dir),
    }
    started_payload.update(_rules_file_fingerprint(config.detection.yara_rules_file))
    ledger.append_event("yara_started", operator, started_payload)

    unavailable = _tool_unavailable_reason(config)
    if unavailable is not None:
        _record_skip(yara_manifest, ledger, operator, unavailable, artifact_count=len(targets))
    else:
        profile = load_yara_profile(catalog_module.default_yara_catalog_path())
        for artifact in targets:
            _scan_artifact(
                artifact=artifact,
                profile=profile,
                config=config,
                case_dir=case_dir,
                artifacts_root=artifacts_root,
                operator=operator,
                yara_manifest=yara_manifest,
                ledger=ledger,
            )

    yara_manifest.ended_at_utc = datetime.now(timezone.utc)

    manifest_path = resolve_yara_manifest_path(config)
    try:
        yara_manifest.to_json_file(manifest_path)
    except OSError as exc:
        raise DetectionError(f"YARA manifesti yazilamadi: {manifest_path} ({exc})") from exc

    ledger.append_event(
        "yara_completed",
        operator,
        {
            "run_id": yara_manifest.run_id,
            "scanned_count": len(yara_manifest.scanned),
            "match_count": len(yara_manifest.matches),
            "skipped_count": len(yara_manifest.skipped),
            "error_count": len(yara_manifest.errors),
            "yara_manifest_path": str(manifest_path),
            "yara_manifest_sha256": hash_file(manifest_path),
        },
    )
    return yara_manifest


def _rules_file_fingerprint(rules_file: Optional[str]) -> dict[str, Any]:
    """Kullanilan YARA kural dosyasinin sha256'si -- Hayabusa'nin kural KLASORU
    parmak izinden (_rules_fingerprint, detection/runner.py) daha basit:
    burada TEK bir dosya oldugu icin dogrudan icerigi hash'lenebiliyor."""
    if not rules_file or not Path(rules_file).is_file():
        return {}
    return {
        "yara_rules_file": str(rules_file),
        "yara_rules_sha256": hash_file(Path(rules_file)),
    }


def _tool_unavailable_reason(config: TriageChainConfig) -> Optional[str]:
    """YARA calistirilamayacaksa nedenini dondurur; calistirilabiliyorsa None."""
    detection_config = config.detection
    if not detection_config.yara_path:
        return "YARA konfigure edilmemis (detection.yara_path bos)."
    if not detection_config.yara_rules_file:
        return "YARA kural dosyasi konfigure edilmemis (detection.yara_rules_file bos)."
    if not Path(detection_config.yara_path).is_file():
        return f"YARA yolu bulunamadi: {detection_config.yara_path}"
    if not Path(detection_config.yara_rules_file).is_file():
        return f"YARA kural dosyasi bulunamadi: {detection_config.yara_rules_file}"
    return None


def _scan_artifact(
    artifact: CollectedArtifact,
    profile: YaraProfile,
    config: TriageChainConfig,
    case_dir: Path,
    artifacts_root: Path,
    operator: str,
    yara_manifest: YaraManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir artefakti YARA ile tarar."""
    source_path = _contained_source_path(artifact.dest_path, artifacts_root)
    if source_path is None:
        _record_error(
            yara_manifest, ledger, operator, artifact,
            f"Girdi yolu vakanin cikti agaci disinda kaliyor ({artifact.dest_path}); "
            f"beklenen kok: {artifacts_root}. Manifest degistirilmis olabilir, "
            "YARA calistirilmadi.",
        )
        return

    output_dir = case_dir / "detections" / "yara"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DetectionError(f"YARA cikti dizini olusturulamadi: {output_dir} ({exc})") from exc

    argv = [str(config.detection.yara_path)] + [
        arg.format(rules_file=str(config.detection.yara_rules_file), input=str(source_path))
        for arg in profile.args
    ]

    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=config.detection.yara_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _record_error(
            yara_manifest, ledger, operator, artifact,
            f"YARA {config.detection.yara_timeout_seconds} saniyede bitmedi, sonlandirildi.",
        )
        return
    duration = time.monotonic() - started

    stdout_log, stderr_log = _write_tool_logs(
        output_dir, source_path.name, result.stdout, result.stderr
    )

    if result.returncode != 0:
        _record_error(
            yara_manifest, ledger, operator, artifact,
            f"YARA {result.returncode} koduyla cikti (kural dosyasi derlenemedi olabilir).",
            exit_code=result.returncode,
            stderr_excerpt=_decode(result.stderr)[:STDERR_EXCERPT_LIMIT],
            stdout_log_path=str(stdout_log),
            stderr_log_path=str(stderr_log),
        )
        return

    matches = _parse_matches(_decode(result.stdout), artifact, source_path, profile)
    yara_manifest.matches.extend(matches)

    entry: dict[str, Any] = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": str(source_path),
        "stdout_log_path": str(stdout_log),
        "stderr_log_path": str(stderr_log),
        "match_count": len(matches),
        "duration_seconds": round(duration, 3),
    }
    yara_manifest.scanned.append(entry)
    ledger.append_event("yara_completed_for_artifact", operator, dict(entry))


def _parse_matches(
    stdout: str, artifact: CollectedArtifact, source_path: Path, profile: YaraProfile
) -> list[YaraMatch]:
    """YARA stdout'unu (bkz. yara_args.yaml basindaki gercek-ikiliyle dogrulanmis
    format notu) EN IYI CABA ile eslesmelere cevirir.

    Eslesme yoksa (bos stdout) bu bir hata DEGILDIR -- bkz. modul dokstring'i.
    Bir satir desene uymuyorsa o satir sessizce atlanir (ozetlemeyi cokertmez)."""
    pattern = re.compile(profile.line_pattern)
    matches: list[YaraMatch] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        found = pattern.match(line)
        if not found:
            continue
        rule_name, tags, meta, _file_path = found.groups()
        matches.append(
            YaraMatch(
                artifact_type_id=artifact.artifact_type_id,
                source_path=str(source_path),
                rule_name=rule_name,
                tags=tags,
                meta=meta,
            )
        )
    return matches


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
    stdout_log.write_text(_decode(stdout), encoding="utf-8")
    stderr_log.write_text(_decode(stderr), encoding="utf-8")
    return stdout_log, stderr_log


def _decode(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def _record_skip(
    yara_manifest: YaraManifest,
    ledger: CustodyLedger,
    operator: str,
    message: str,
    artifact_count: int,
) -> None:
    logger.info("[yara] %s", message)
    entry = {"message": message, "artifact_count": artifact_count}
    yara_manifest.skipped.append(entry)
    ledger.append_event("yara_skipped", operator, dict(entry))


def _record_error(
    yara_manifest: YaraManifest,
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
    yara_manifest.errors.append(entry)
    ledger.append_event("yara_error", operator, dict(entry))
