"""Tespit akisinin orkestrasyonu: .evtx sec, dogrula, Hayabusa'yi calistir, bulgulari cikar.

Guvenlik kurallari router/runner.py ile BIREBIR ayni (docs/architecture.md):
  1. subprocess her zaman arguman LISTESI ile cagrilir; shell=True hicbir yerde
     kullanilmaz.
  2. Arac (hayabusa) ve kural klasoru yollari MUTLAK olmalidir (config
     semasinda dogrulanir); varliklari kosu aninda kontrol edilir.
  3. Araca verilen her girdi yolu, vakanin kendi cikti agaci
     (<output_dir>/<case_id>/artifacts) altinda cozulmelidir. Elle duzenlenmis
     bir manifest.json baska bir yeri gosteriyorsa hicbir sey calistirilmaz.
  4. Her cagrinin zaman asimi vardir; asilirsa olumcul olmayan hata kaydedilir.
"""

from __future__ import annotations

import csv
import hashlib
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
from triagechain.config.loader import resolve_detection_manifest_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError, DetectionError
from triagechain.custody.ledger import CustodyLedger
from triagechain.detection import catalog as catalog_module
from triagechain.detection.models import DetectionManifest, Finding

logger = logging.getLogger(__name__)

# Yalnizca bu tipteki artefaktlar taranir: Hayabusa bir Windows olay gunlugu
# (.evtx) tarayicisidir, registry kovani ya da prefetch okumaz.
SCANNED_ARTIFACT_TYPE = "event_logs"

# Custody olay kaydina yazilan stderr ozutunun ust siniri (router ile ayni).
STDERR_EXCERPT_LIMIT = 2000

# Kullanilan custody olay tipleri:
#   detection_started               - tespit kosusu basladi
#   detection_completed_for_artifact- bir .evtx tarandi (dosya basina TEK ozet olay)
#   detection_skipped               - tarama atlandi (arac/kural konfigure degil ya da bulunamadi)
#   detection_error                 - arac sifirdan farkli kod dondurdu, zaman asimina
#                                     ugradi ya da girdi yolu agac disinda kaldi (olumcul degil)
#   detection_completed             - tespit kosusu bitti (manifest sha256'si ile)


@dataclass
class HayabusaProfile:
    """hayabusa_args.yaml icindeki cagri sablonu ve CSV sutun eslemesi."""

    args: list[str]
    output_filename: str
    # Finding alani -> denenecek CSV baslik adaylari.
    csv_columns: dict[str, list[str]] = field(default_factory=dict)


def load_profile(catalog_path: Path) -> HayabusaProfile:
    """Hayabusa cagri sablonu YAML'ini okur (router.load_routes ile ayni desen)."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Hayabusa sablon katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Hayabusa sablon katalogu gecerli YAML degil: {catalog_path} ({exc})"
        ) from exc

    raw = raw or {}
    return HayabusaProfile(
        args=list(raw.get("args") or []),
        output_filename=raw.get("output_filename") or "{stem}.hayabusa.csv",
        csv_columns={key: list(values) for key, values in (raw.get("csv_columns") or {}).items()},
    )


def run_detection(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> DetectionManifest:
    """Toplanmis .evtx dosyalarini Hayabusa ile tarar ve bulgulari dondurur."""
    operator = config.case.operator
    case_id = config.case.case_id
    case_dir = Path(config.collection.output_dir) / case_id
    # Karsilastirma icin tek referans nokta: her girdi yolu bunun altinda olmali.
    artifacts_root = (case_dir / "artifacts").resolve()

    detection = DetectionManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))
    targets = [a for a in manifest.artifacts if a.artifact_type_id == SCANNED_ARTIFACT_TYPE]

    started_payload: dict[str, Any] = {
        "run_id": detection.run_id,
        "collection_run_id": manifest.run_id,
        "artifact_count": len(targets),
        "output_dir": str(case_dir),
    }
    started_payload.update(_rules_fingerprint(config.detection.rules_dir))
    ledger.append_event("detection_started", operator, started_payload)

    # Arac/kural kullanilabilirligi kosu basina BIR KEZ kontrol edilir: router'in
    # aksine burada tum artefaktlar tek bir araca gider, dolayisiyla dosya
    # basina ayni atlama kaydini tekrarlamak deftere gurultuden baska bir sey
    # eklemez.
    unavailable = _tool_unavailable_reason(config)
    if unavailable is not None:
        _record_skip(detection, ledger, operator, unavailable, artifact_count=len(targets))
    else:
        profile = load_profile(catalog_module.default_catalog_path())
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

    # Manifest deftere yazilmadan ONCE diske yazilir: kapanis olayina bu
    # dosyanin sha256'si islenir, boylece detayli bulgular sonradan
    # degistirilirse zincir uzerinden fark edilir.
    manifest_path = resolve_detection_manifest_path(config)
    try:
        detection.to_json_file(manifest_path)
    except OSError as exc:
        raise DetectionError(
            f"Tespit manifesti yazilamadi: {manifest_path} ({exc})"
        ) from exc

    ledger.append_event(
        "detection_completed",
        operator,
        {
            "run_id": detection.run_id,
            "scanned_count": len(detection.scanned),
            "finding_count": len(detection.findings),
            "skipped_count": len(detection.skipped),
            "error_count": len(detection.errors),
            "detection_manifest_path": str(manifest_path),
            "detection_manifest_sha256": hash_file(manifest_path),
        },
    )
    return detection


def _rules_fingerprint(rules_dir: Optional[str]) -> dict[str, Any]:
    """Kullanilan Sigma kural setinin "parmak izini" custody yuku icin uretir.

    Metodoloji izlenebilirligi: bir bulgu sorgulandiginda "hangi kural seti bunu
    uretti" sorusu deftere bakilarak cevaplanabilmeli. Router'daki toplu dosya
    tek bir dosya oldugu icin dogrudan hash'lenebiliyor; kural klasoru ise
    binlerce dosya icerebilir, hepsinin icerigini hash'lemek her kosuya
    gereksiz bir maliyet eklerdi.

    Bu yuzden parmak izi YAPISALDIR: klasordeki tum dosyalarin (goreli yol,
    boyut) ciftlerinin SIRALI listesinden tek bir sha256 hesaplanir.

    SINIRLAMA (bilincli tradeoff): dosya EKLENMESI, CIKARILMASI, yeniden
    adlandirilmasi ve BOYUT degisikligi yakalanir; bir kural dosyasinin icerigi
    AYNI BOYUTTA kalacak sekilde degistirilirse bu parmak izi bunu YAKALAMAZ.

    Kural klasoru hic tanimli degilse ya da diskte yoksa bos sozluk doner
    (uydurma bir deger yazmaktansa alanin hic olmamasi tercih edildi); bu
    durumda kosu zaten `detection_skipped` ile atlanacak ve nedeni deftere
    ayrica yazilacak.
    """
    if not rules_dir or not Path(rules_dir).is_dir():
        return {}

    root = Path(rules_dir)
    entries = sorted(
        (path.relative_to(root).as_posix(), path.stat().st_size)
        for path in root.rglob("*")
        if path.is_file()
    )
    digest = hashlib.sha256()
    for relative_path, size in entries:
        digest.update(f"{relative_path}\0{size}\n".encode("utf-8"))
    return {
        "rules_dir": str(rules_dir),
        "rules_file_count": len(entries),
        "rules_fingerprint_sha256": digest.hexdigest(),
    }


def _tool_unavailable_reason(config: TriageChainConfig) -> Optional[str]:
    """Hayabusa calistirilamayacaksa nedenini dondurur; calistirilabiliyorsa None."""
    detection_config = config.detection
    if not detection_config.hayabusa_path:
        return "Hayabusa konfigure edilmemis (detection.hayabusa_path bos)."
    if not detection_config.rules_dir:
        return "Sigma kural klasoru konfigure edilmemis (detection.rules_dir bos)."
    if not Path(detection_config.hayabusa_path).is_file():
        return f"Hayabusa yolu bulunamadi: {detection_config.hayabusa_path}"
    if not Path(detection_config.rules_dir).is_dir():
        return f"Sigma kural klasoru bulunamadi: {detection_config.rules_dir}"
    return None


def _scan_artifact(
    artifact: CollectedArtifact,
    profile: HayabusaProfile,
    config: TriageChainConfig,
    case_dir: Path,
    artifacts_root: Path,
    operator: str,
    detection: DetectionManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir .evtx dosyasini Hayabusa ile tarar."""
    source_path = _contained_source_path(artifact.dest_path, artifacts_root)
    if source_path is None:
        # Manifest verisine kor korune guvenilmez: agac disindaki bir yol
        # icin hicbir sey CALISTIRILMAZ.
        _record_error(
            detection, ledger, operator, artifact,
            f"Girdi yolu vakanin cikti agaci disinda kaliyor ({artifact.dest_path}); "
            f"beklenen kok: {artifacts_root}. Manifest degistirilmis olabilir, "
            "Hayabusa calistirilmadi.",
        )
        return

    output_dir = case_dir / "detections" / "hayabusa"
    try:
        to_long_path(output_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DetectionError(
            f"Tespit cikti dizini olusturulamadi: {output_dir} ({exc})"
        ) from exc

    output_csv = output_dir / profile.output_filename.format(stem=source_path.name)
    argv = [str(config.detection.hayabusa_path)] + [
        arg.format(
            input=str(source_path),
            rules_dir=str(config.detection.rules_dir),
            output_csv=str(output_csv),
        )
        for arg in profile.args
    ]

    started = time.monotonic()
    try:
        # shell=True YOK: argumanlar liste olarak gecer, kabuk devreye girmez.
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=config.detection.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _record_error(
            detection, ledger, operator, artifact,
            f"Hayabusa {config.detection.timeout_seconds} saniyede bitmedi, sonlandirildi.",
        )
        return
    duration = time.monotonic() - started

    stdout_log, stderr_log = _write_tool_logs(
        output_dir, source_path.name, result.stdout, result.stderr
    )

    if result.returncode != 0:
        _record_error(
            detection, ledger, operator, artifact,
            f"Hayabusa {result.returncode} koduyla cikti.",
            exit_code=result.returncode,
            stderr_excerpt=_decode(result.stderr)[:STDERR_EXCERPT_LIMIT],
            stdout_log_path=str(stdout_log),
            stderr_log_path=str(stderr_log),
        )
        return

    findings, warning = _parse_findings(output_csv, artifact, source_path, profile)
    detection.findings.extend(findings)

    level_counts: dict[str, int] = {}
    for finding in findings:
        key = finding.level.lower() or "bilinmiyor"
        level_counts[key] = level_counts.get(key, 0) + 1

    # Custody'ye bulgu basina degil, DOSYA basina tek ozet olay yazilir;
    # detayli bulgular yalnizca detection_manifest.json'da durur.
    entry: dict[str, Any] = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": str(source_path),
        "output_csv_path": str(output_csv),
        "stdout_log_path": str(stdout_log),
        "stderr_log_path": str(stderr_log),
        "finding_count": len(findings),
        "level_counts": level_counts,
        "duration_seconds": round(duration, 3),
    }
    if warning:
        entry["parse_warning"] = warning
    detection.scanned.append(entry)
    ledger.append_event("detection_completed_for_artifact", operator, dict(entry))


def _parse_findings(
    output_csv: Path,
    artifact: CollectedArtifact,
    source_path: Path,
    profile: HayabusaProfile,
) -> tuple[list[Finding], Optional[str]]:
    """Hayabusa CSV'sini EN IYI CABA ile bulgulara cevirir.

    Ayristirma basarisiz olursa bu OLUMCUL DEGILDIR: bos bulgu listesi ve bir
    uyari metni doner. Ham CSV zaten diskte durdugu icin veri kaybolmaz,
    sadece manifeste yapilandirilmis olarak giremez.
    """
    if not to_long_path(output_csv).is_file():
        return [], f"Hayabusa cikti dosyasi olusmadi: {output_csv}"

    try:
        with open(
            to_long_path(output_csv), "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return [], f"Hayabusa cikti dosyasi bos ya da basliksiz: {output_csv}"
            # Baslik eslemesi bir kez cozulur: normalize edilmis baslik -> gercek baslik.
            headers = {_normalize(name): name for name in reader.fieldnames if name}
            column_map = {
                field_name: next(
                    (headers[_normalize(c)] for c in candidates if _normalize(c) in headers),
                    None,
                )
                for field_name, candidates in profile.csv_columns.items()
            }
            if not any(column_map.values()):
                return [], (
                    f"Hayabusa CSV basliklari taninmadi ({output_csv}); "
                    "ham dosya diskte, bulgular ayristirilamadi."
                )
            findings = [
                Finding(
                    artifact_type_id=artifact.artifact_type_id,
                    source_path=str(source_path),
                    rule_title=_cell(row, column_map, "rule_title"),
                    level=_cell(row, column_map, "level"),
                    timestamp=_cell(row, column_map, "timestamp"),
                    computer=_cell(row, column_map, "computer"),
                    channel=_cell(row, column_map, "channel"),
                    event_id=_cell(row, column_map, "event_id"),
                    details=_cell(row, column_map, "details"),
                    mitre_tags=_cell(row, column_map, "mitre_tags"),
                )
                for row in reader
            ]
    except (OSError, csv.Error) as exc:
        return [], f"Hayabusa ciktisi okunamadi ({output_csv}): {exc}"

    return findings, None


def _normalize(header: str) -> str:
    """Baslik karsilastirmasini buyuk/kucuk harf ve bosluklardan bagimsiz yapar."""
    return header.strip().lower().replace(" ", "").replace("_", "")


def _cell(row: dict[str, Any], column_map: dict[str, Optional[str]], field_name: str) -> str:
    """Satirdan bir alani okur; sutun yoksa/bossa bos metin dondurur."""
    column = column_map.get(field_name)
    if column is None:
        return ""
    return (row.get(column) or "").strip()


def _contained_source_path(dest_path: str, artifacts_root: Path) -> Optional[Path]:
    """Girdi yolunu cozer; vakanin artefakt kokunun altindaysa dondurur, degilse None.

    router/runner.py'deki ayni adli fonksiyonla birebir ayni kural: cozumleme
    (`resolve`) sembolik baglantilari ve `..` parcalarini duzlestirdigi icin
    kontrol yol metnine degil gercek hedefe uygulanir.
    """
    try:
        resolved = Path(dest_path).resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(artifacts_root) else None


def _write_tool_logs(
    output_dir: Path, filename: str, stdout: Optional[bytes], stderr: Optional[bytes]
) -> tuple[Path, Path]:
    """Aracin stdout/stderr ciktisini diske yazar ve iki log yolunu dondurur."""
    stdout_log = output_dir / f"{filename}.stdout.log"
    stderr_log = output_dir / f"{filename}.stderr.log"
    to_long_path(stdout_log).write_text(_decode(stdout), encoding="utf-8")
    to_long_path(stderr_log).write_text(_decode(stderr), encoding="utf-8")
    return stdout_log, stderr_log


def _decode(raw: Optional[bytes]) -> str:
    """Arac ciktisini metne cevirir; cozulemeyen baytlar kaybedilmez, isaretlenir."""
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
    """Tum tespit kosusunun atlandigini hem manifeste hem deftere yazar."""
    logger.info("[detection] %s", message)
    entry = {"message": message, "artifact_count": artifact_count}
    detection.skipped.append(entry)
    ledger.append_event("detection_skipped", operator, dict(entry))


def _record_error(
    detection: DetectionManifest,
    ledger: CustodyLedger,
    operator: str,
    artifact: CollectedArtifact,
    message: str,
    **extra: Any,
) -> None:
    """Olumcul olmayan bir tarama hatasini hem manifeste hem deftere yazar."""
    logger.warning("[%s] %s", artifact.artifact_type_id, message)
    entry = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": artifact.dest_path,
        "message": message,
        **extra,
    }
    detection.errors.append(entry)
    ledger.append_event("detection_error", operator, dict(entry))
