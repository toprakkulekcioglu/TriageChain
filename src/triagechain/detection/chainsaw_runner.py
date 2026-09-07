"""Chainsaw tarama akisi: .evtx sec, dogrula, Chainsaw'i calistir, bulgulari cikar.

Guvenlik kurallari detection/runner.py (Hayabusa) ile BIREBIR ayni
(docs/architecture.md): subprocess her zaman arguman LISTESI ile cagrilir,
shell=True hicbir yerde yok, yollar mutlak olmali, her girdi vakanin cikti
agaci altinda cozulmeli, her cagrinin zaman asimi var.

Hayabusa ile FARKI degil, KASITLI ORTAK NOKTASI: Chainsaw da Sigma kurali
calistiran bir motor -- `detection.rules_dir`'i (Hayabusa ile AYNI klasor)
kullanir. Amaç iki BAĞIMSIZ motoru AYNI kural setiyle calistirip sonuclarin
ortusup ortusmedigini gormek (gercek capraz dogrulama, bkz.
docs/aldigim_kararlar.md -> "Chainsaw entegrasyonu"). Hayabusa'dan tek
gercek farki: Chainsaw sonucu JSON dosyasina yazar (CSV degil) ve ayrica
bir "mapping" dosyasina ihtiyac duyar (Sigma alanlarini .evtx alanlarina
eslemek icin, kendi ikilisiyle birlikte gelir).
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
from triagechain.config.loader import resolve_chainsaw_manifest_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError, DetectionError
from triagechain.custody.ledger import CustodyLedger
from triagechain.detection import catalog as catalog_module
from triagechain.detection.models import DetectionManifest, Finding

logger = logging.getLogger(__name__)

# Hayabusa ile AYNI kisit: Chainsaw'in bu entegrasyonu da yalnizca .evtx
# tarar (Chainsaw'in kendisi baska formatlari da destekler, ama burada
# amac capraz dogrulama oldugu icin Hayabusa'nin taradigi TIPLE sinirli).
SCANNED_ARTIFACT_TYPE = "event_logs"

STDERR_EXCERPT_LIMIT = 2000

# Kullanilan custody olay tipleri:
#   chainsaw_started               - Chainsaw tarama kosusu basladi
#   chainsaw_completed_for_artifact - bir .evtx tarandi (dosya basina TEK ozet olay)
#   chainsaw_skipped                - tarama atlandi
#   chainsaw_error                  - arac sifirdan farkli kod dondurdu, zaman
#                                     asimina ugradi ya da girdi yolu agac disinda kaldi
#   chainsaw_completed               - tarama kosusu bitti (manifest sha256'si ile)


@dataclass
class ChainsawProfile:
    """chainsaw_args.yaml icindeki cagri sablonu ve JSON alan eslemesi."""

    args: list[str]
    output_filename: str
    json_fields: dict[str, str] = field(default_factory=dict)


def load_chainsaw_profile(catalog_path: Path) -> ChainsawProfile:
    """Chainsaw cagri sablonu YAML'ini okur (detection.load_profile ile ayni desen)."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Chainsaw sablon katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Chainsaw sablon katalogu gecerli YAML degil: {catalog_path} ({exc})"
        ) from exc

    raw = raw or {}
    return ChainsawProfile(
        args=list(raw.get("args") or []),
        output_filename=raw.get("output_filename") or "{stem}.chainsaw.json",
        json_fields={
            key: str(value) for key, value in (raw.get("json_fields") or {}).items()
        },
    )


def run_chainsaw_detection(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> DetectionManifest:
    """Toplanmis .evtx dosyalarini Chainsaw ile tarar ve bulgulari dondurur.

    Hayabusa'nin DetectionManifest'iyle AYNI tip donuyor (Finding semasi
    birebir ayni) ama AYRI bir dosyaya yazilir -- iki motorun ciktisi
    birbirini ezmesin diye.
    """
    operator = config.case.operator
    case_id = config.case.case_id
    case_dir = Path(config.collection.output_dir) / case_id
    artifacts_root = (case_dir / "artifacts").resolve()

    detection = DetectionManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))
    targets = [a for a in manifest.artifacts if a.artifact_type_id == SCANNED_ARTIFACT_TYPE]

    ledger.append_event(
        "chainsaw_started",
        operator,
        {
            "run_id": detection.run_id,
            "collection_run_id": manifest.run_id,
            "artifact_count": len(targets),
            "output_dir": str(case_dir),
        },
    )

    unavailable = _tool_unavailable_reason(config)
    if unavailable is not None:
        _record_skip(detection, ledger, operator, unavailable, artifact_count=len(targets))
    else:
        profile = load_chainsaw_profile(catalog_module.default_chainsaw_catalog_path())
        for artifact in targets:
            _scan_artifact(
                artifact=artifact,
                profile=profile,
                config=config,
                case_dir=case_dir,
                artifacts_root=artifacts_root,
                operator=operator,
                detection=detection,
                ledger=ledger,
            )

    detection.ended_at_utc = datetime.now(timezone.utc)

    manifest_path = resolve_chainsaw_manifest_path(config)
    try:
        detection.to_json_file(manifest_path)
    except OSError as exc:
        raise DetectionError(f"Chainsaw manifesti yazilamadi: {manifest_path} ({exc})") from exc

    ledger.append_event(
        "chainsaw_completed",
        operator,
        {
            "run_id": detection.run_id,
            "scanned_count": len(detection.scanned),
            "finding_count": len(detection.findings),
            "skipped_count": len(detection.skipped),
            "error_count": len(detection.errors),
            "chainsaw_manifest_path": str(manifest_path),
            "chainsaw_manifest_sha256": hash_file(manifest_path),
        },
    )
    return detection


def _tool_unavailable_reason(config: TriageChainConfig) -> Optional[str]:
    """Chainsaw calistirilamayacaksa nedenini dondurur; calistirilabiliyorsa None."""
    detection_config = config.detection
    if not detection_config.chainsaw_path:
        return "Chainsaw konfigure edilmemis (detection.chainsaw_path bos)."
    if not detection_config.rules_dir:
        return "Sigma kural klasoru konfigure edilmemis (detection.rules_dir bos)."
    if not detection_config.chainsaw_mapping_file:
        return "Chainsaw esleme dosyasi konfigure edilmemis (detection.chainsaw_mapping_file bos)."
    if not Path(detection_config.chainsaw_path).is_file():
        return f"Chainsaw yolu bulunamadi: {detection_config.chainsaw_path}"
    if not Path(detection_config.rules_dir).is_dir():
        return f"Sigma kural klasoru bulunamadi: {detection_config.rules_dir}"
    if not Path(detection_config.chainsaw_mapping_file).is_file():
        return f"Chainsaw esleme dosyasi bulunamadi: {detection_config.chainsaw_mapping_file}"
    return None


def _scan_artifact(
    artifact: CollectedArtifact,
    profile: ChainsawProfile,
    config: TriageChainConfig,
    case_dir: Path,
    artifacts_root: Path,
    operator: str,
    detection: DetectionManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir .evtx dosyasini Chainsaw ile tarar."""
    source_path = _contained_source_path(artifact.dest_path, artifacts_root)
    if source_path is None:
        _record_error(
            detection, ledger, operator, artifact,
            f"Girdi yolu vakanin cikti agaci disinda kaliyor ({artifact.dest_path}); "
            f"beklenen kok: {artifacts_root}. Manifest degistirilmis olabilir, "
            "Chainsaw calistirilmadi.",
        )
        return

    output_dir = case_dir / "detections" / "chainsaw"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DetectionError(f"Tespit cikti dizini olusturulamadi: {output_dir} ({exc})") from exc

    output_json = output_dir / profile.output_filename.format(stem=source_path.name)
    argv = [str(config.detection.chainsaw_path)] + [
        arg.format(
            input=str(source_path),
            rules_dir=str(config.detection.rules_dir),
            mapping_file=str(config.detection.chainsaw_mapping_file),
            output_json=str(output_json),
        )
        for arg in profile.args
    ]

    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=config.detection.chainsaw_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _record_error(
            detection, ledger, operator, artifact,
            f"Chainsaw {config.detection.chainsaw_timeout_seconds} saniyede bitmedi, "
            "sonlandirildi.",
        )
        return
    duration = time.monotonic() - started

    stdout_log, stderr_log = _write_tool_logs(
        output_dir, source_path.name, result.stdout, result.stderr
    )

    if result.returncode != 0:
        _record_error(
            detection, ledger, operator, artifact,
            f"Chainsaw {result.returncode} koduyla cikti.",
            exit_code=result.returncode,
            stderr_excerpt=_decode(result.stderr)[:STDERR_EXCERPT_LIMIT],
            stdout_log_path=str(stdout_log),
            stderr_log_path=str(stderr_log),
        )
        return

    findings, warning = _parse_findings(output_json, artifact, source_path, profile)
    detection.findings.extend(findings)

    level_counts: dict[str, int] = {}
    for finding in findings:
        key = finding.level.lower() or "bilinmiyor"
        level_counts[key] = level_counts.get(key, 0) + 1

    entry: dict[str, Any] = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": str(source_path),
        "output_json_path": str(output_json),
        "stdout_log_path": str(stdout_log),
        "stderr_log_path": str(stderr_log),
        "finding_count": len(findings),
        "level_counts": level_counts,
        "duration_seconds": round(duration, 3),
    }
    if warning:
        entry["parse_warning"] = warning
    detection.scanned.append(entry)
    ledger.append_event("chainsaw_completed_for_artifact", operator, dict(entry))


def _parse_findings(
    output_json: Path,
    artifact: CollectedArtifact,
    source_path: Path,
    profile: ChainsawProfile,
) -> tuple[list[Finding], Optional[str]]:
    """Chainsaw JSON'unu EN IYI CABA ile bulgulara cevirir.

    Ayristirma basarisiz olursa OLUMCUL DEGIL: bos bulgu listesi + uyari
    metni doner, ham JSON zaten diskte durur (detection/runner.py'nin CSV
    icin yaptigi ayni sey)."""
    if not output_json.is_file():
        return [], f"Chainsaw cikti dosyasi olusmadi: {output_json}"

    try:
        raw_text = output_json.read_text(encoding="utf-8-sig")
        if not raw_text.strip():
            # Esleme yoksa (0 bulgu) Chainsaw bos bir dosya yazar -- hata degil.
            return [], None
        records = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"Chainsaw ciktisi okunamadi ({output_json}): {exc}"

    if not isinstance(records, list):
        return [], f"Chainsaw ciktisi beklenmeyen bicimde ({output_json}): liste degil."

    findings = [
        Finding(
            artifact_type_id=artifact.artifact_type_id,
            source_path=str(source_path),
            rule_title=_field_text(record, profile, "rule_title"),
            level=_field_text(record, profile, "level"),
            timestamp=_field_text(record, profile, "timestamp"),
            computer=_field_text(record, profile, "computer"),
            channel=_field_text(record, profile, "channel"),
            event_id=_field_text(record, profile, "event_id"),
            details="",
            mitre_tags=_field_text(record, profile, "mitre_tags"),
        )
        for record in records
        if isinstance(record, dict)
    ]
    return findings, None


def _field_text(record: dict, profile: ChainsawProfile, field_name: str) -> str:
    """Bir alani nokta-ayirilmis JSON yolundan okur; yol yoksa/gecersizse bos
    metin doner (best-effort, Hayabusa'nin _cell() ile ayni ilke)."""
    path = profile.json_fields.get(field_name)
    if not path:
        return ""
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return ""
        value = value[part]
    if value is None:
        return ""
    if isinstance(value, list):
        # Sadece mitre_tags icin gecerli: Sigma tags listesi.
        return ",".join(str(item) for item in value)
    return str(value)


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
    detection: DetectionManifest,
    ledger: CustodyLedger,
    operator: str,
    message: str,
    artifact_count: int,
) -> None:
    logger.info("[chainsaw] %s", message)
    entry = {"message": message, "artifact_count": artifact_count}
    detection.skipped.append(entry)
    ledger.append_event("chainsaw_skipped", operator, dict(entry))


def _record_error(
    detection: DetectionManifest,
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
    detection.errors.append(entry)
    ledger.append_event("chainsaw_error", operator, dict(entry))
