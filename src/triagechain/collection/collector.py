"""Toplama akisinin orkestrasyonu: sec, oku, kopyala, dogrula, deftere yaz."""

from __future__ import annotations

import getpass
import hashlib
import logging
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from triagechain.collection import catalog as catalog_module
from triagechain.collection.hashing import DEFAULT_CHUNK_SIZE, hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.collection.readers import open_source
from triagechain.collection.selector import ResolvedTarget, resolve_targets
from triagechain.collection.vss_snapshot import VssSnapshot
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import CollectionError, IntegrityError
from triagechain.custody.ledger import CustodyLedger

logger = logging.getLogger(__name__)

# Kullanilan custody olay tipleri:
#   case_opened      - kosu basladi
#   artifact_collected - bir dosya basariyla alindi ve hash'i dogrulandi
#   collection_error - tek bir artefakt alinamadi (olumcul degil, kosu devam eder)
#   integrity_error  - yazilan dosyanin hash'i tutmadi (olumcul, kosu durur)
#   case_closed      - kosu bitti


def run_collection(config: TriageChainConfig, ledger: CustodyLedger) -> CollectionManifest:
    """Konfigurasyondaki hedefleri toplar ve manifesti dondurur."""
    operator = config.case.operator
    case_id = config.case.case_id
    algorithm = config.collection.hash_algorithm
    case_dir = Path(config.collection.output_dir) / case_id
    artifacts_root = case_dir / "artifacts"

    manifest = CollectionManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))

    ledger.append_event(
        "case_opened",
        operator,
        {
            "run_id": manifest.run_id,
            "targets": list(config.collection.targets),
            "output_dir": str(case_dir),
            "hash_algorithm": algorithm,
        },
    )

    targets = resolve_targets(
        list(config.collection.targets), catalog_module.default_catalog_path()
    )

    with ExitStack() as stack:
        snapshot = _open_snapshot_if_needed(targets, manifest, ledger, operator, stack)
        for target in targets:
            _collect_target(
                target=target,
                snapshot=snapshot,
                artifacts_root=artifacts_root,
                algorithm=algorithm,
                case_id=case_id,
                operator=operator,
                manifest=manifest,
                ledger=ledger,
            )
        _collect_additional_volumes(
            config=config,
            artifacts_root=artifacts_root,
            algorithm=algorithm,
            case_id=case_id,
            operator=operator,
            manifest=manifest,
            ledger=ledger,
            stack=stack,
        )
        _collect_suspicious_binaries(
            config=config,
            artifacts_root=artifacts_root,
            algorithm=algorithm,
            case_id=case_id,
            operator=operator,
            manifest=manifest,
            ledger=ledger,
        )

    manifest.ended_at_utc = datetime.now(timezone.utc)
    ledger.append_event(
        "case_closed",
        operator,
        {
            "run_id": manifest.run_id,
            "artifact_count": len(manifest.artifacts),
            "error_count": len(manifest.errors),
        },
    )
    return manifest


def _open_snapshot_if_needed(
    targets: list[ResolvedTarget],
    manifest: CollectionManifest,
    ledger: CustodyLedger,
    operator: str,
    stack: ExitStack,
) -> Optional[VssSnapshot]:
    """VSS gerektiren hedef varsa golge kopya acar.

    Golge kopya olusturulamazsa (or. yonetici degiliz) tum kosuyu iptal etmek
    yerine VSS gerektiren hedefleri hatali isaretleyip digerlerine devam ederiz.
    """
    if not any(target.requires_vss and target.paths for target in targets):
        return None
    try:
        return stack.enter_context(VssSnapshot())
    except CollectionError as exc:
        logger.error("Golge kopya acilamadi: %s", exc)
        for target in targets:
            if target.requires_vss:
                _record_error(
                    manifest, ledger, operator, target.target_id,
                    f"Golge kopya acilamadigi icin atlandi: {exc}",
                )
                target.paths = []
        return None


def _collect_additional_volumes(
    config: TriageChainConfig,
    artifacts_root: Path,
    algorithm: str,
    case_id: str,
    operator: str,
    manifest: CollectionManifest,
    ledger: CustodyLedger,
    stack: ExitStack,
) -> None:
    """`collection.additional_volumes`'daki HER birimin `$MFT`'sini toplar.

    Sistem diski disindaki bir birimin kendi golge kopyasi gerekir --
    `_open_snapshot_if_needed`'in actigi tek (C:) anlik goruntuyle
    ILGISIZ, her ek birim icin AYRI bir `VssSnapshot(volume=...)` acilir.
    Var olan `_collect_target`'i (hash/kopyala/dogrula/deftere yaz mantigi
    ayni) AYNEN yeniden kullanmak icin elle bir `ResolvedTarget` kuruluyor.
    """
    for volume in config.collection.additional_volumes:
        letter = volume.rstrip(":").lower()
        target = ResolvedTarget(
            target_id=f"mft_{letter}",
            category="filesystem",
            requires_vss=True,
            description=f"{volume} biriminin NTFS Master File Table'i (ek disk).",
            paths=[Path(f"{volume}\\$MFT")],
        )
        try:
            snapshot = stack.enter_context(VssSnapshot(volume=volume))
        except CollectionError as exc:
            logger.error("Ek birim %s icin golge kopya acilamadi: %s", volume, exc)
            _record_error(
                manifest, ledger, operator, target.target_id,
                f"Golge kopya acilamadigi icin atlandi: {exc}",
            )
            continue
        _collect_target(
            target=target,
            snapshot=snapshot,
            artifacts_root=artifacts_root,
            algorithm=algorithm,
            case_id=case_id,
            operator=operator,
            manifest=manifest,
            ledger=ledger,
        )


SUSPICIOUS_BINARY_TARGET_ID = "suspicious_binary"


def _collect_suspicious_binaries(
    config: TriageChainConfig,
    artifacts_root: Path,
    algorithm: str,
    case_id: str,
    operator: str,
    manifest: CollectionManifest,
    ledger: CustodyLedger,
) -> None:
    """`collection.suspicious_binaries`'daki HER dosyayi toplar.

    additional_volumes'un aksine VSS gerektirmez (analistin gosterdigi dosya
    genelde kilitli degildir) ve tumu AYNI `target_id` ("suspicious_binary")
    altinda tek bir hedef olarak toplanir -- boylece capa (bkz. detection/
    capa_runner.py) hangi artefaktlari tarayacagini artifact_type_id ile tek
    bir sabit degere karsi filtreleyebiliyor (birden fazla dosya varsa bile
    tek bir ResolvedTarget'in `paths` listesinde tutuluyor, Hayabusa'nin/
    Chainsaw'in event_logs filtresiyle AYNI desen).
    """
    paths = [Path(p) for p in config.collection.suspicious_binaries]
    if not paths:
        return
    target = ResolvedTarget(
        target_id=SUSPICIOUS_BINARY_TARGET_ID,
        category="executable",
        requires_vss=False,
        description="Analistin supheli bulup elle gosterdigi yurutulebilir dosya(lar).",
        paths=paths,
    )
    _collect_target(
        target=target,
        snapshot=None,
        artifacts_root=artifacts_root,
        algorithm=algorithm,
        case_id=case_id,
        operator=operator,
        manifest=manifest,
        ledger=ledger,
    )


def _collect_target(
    target: ResolvedTarget,
    snapshot: Optional[VssSnapshot],
    artifacts_root: Path,
    algorithm: str,
    case_id: str,
    operator: str,
    manifest: CollectionManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir hedefin tum dosyalarini toplar."""
    if not target.paths:
        _record_error(
            manifest, ledger, operator, target.target_id,
            "Hedefe uyan dosya bulunamadi (glob hicbir seye acilmadi).",
        )
        return

    target_dir = artifacts_root / target.target_id
    for source in target.paths:
        try:
            dest = _unique_dest(target_dir, source.name)
            with open_source(source, snapshot if target.requires_vss else None) as stream:
                streamed_hash, size = _copy_and_hash(stream, dest, algorithm)

            # Yazilan dosya tekrar hash'lenir: kismi/bozuk yazma buradan yakalanir.
            written_hash = hash_file(dest, algorithm)
            if written_hash != streamed_hash:
                ledger.append_event(
                    "integrity_error",
                    operator,
                    {
                        "artifact_type_id": target.target_id,
                        "source_path": str(source),
                        "dest_path": str(dest),
                        "expected_hash": streamed_hash,
                        "actual_hash": written_hash,
                    },
                )
                raise IntegrityError(
                    f"Hash uyusmuyor: {dest}. Okunan {streamed_hash}, yazilan {written_hash}. "
                    "Kopya bozuk; kosu durduruldu."
                )

            artifact = CollectedArtifact(
                artifact_type_id=target.target_id,
                source_path=str(source),
                dest_path=str(dest),
                hash_value=streamed_hash,
                hash_algorithm=algorithm,
                size_bytes=size,
                collected_at_utc=datetime.now(timezone.utc),
                collecting_user=getpass.getuser(),
                case_id=case_id,
            )
            manifest.artifacts.append(artifact)
            ledger.append_event(
                "artifact_collected",
                operator,
                {
                    "artifact_type_id": artifact.artifact_type_id,
                    "source_path": artifact.source_path,
                    "dest_path": artifact.dest_path,
                    "hash_algorithm": artifact.hash_algorithm,
                    "hash_value": artifact.hash_value,
                    "size_bytes": artifact.size_bytes,
                    "collecting_user": artifact.collecting_user,
                },
            )
        except (OSError, CollectionError) as exc:
            # Dosya yok / erisim reddedildi gibi durumlar beklenen hatalar:
            # kaydet ve sonraki hedefe gec.
            _record_error(
                manifest, ledger, operator, target.target_id,
                f"{source} alinamadi: {exc}",
            )


def _copy_and_hash(stream: BinaryIO, dest: Path, algorithm: str) -> tuple[str, int]:
    """Akisi hedefe kopyalarken ayni anda hash'ler; (hash, boyut) dondurur."""
    digest = hashlib.new(algorithm)
    size = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        while True:
            chunk = stream.read(DEFAULT_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            out.write(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _unique_dest(target_dir: Path, filename: str) -> Path:
    """Ayni isimli dosyalarin (or. her kullanicinin NTUSER.DAT'i) ustune yazilmasini onler."""
    candidate = target_dir / filename
    counter = 1
    while candidate.exists():
        candidate = target_dir / f"{filename}.{counter}"
        counter += 1
    return candidate


def _record_error(
    manifest: CollectionManifest,
    ledger: CustodyLedger,
    operator: str,
    artifact_type_id: str,
    message: str,
) -> None:
    """Olumcul olmayan bir toplama hatasini hem manifeste hem deftere yazar."""
    logger.warning("[%s] %s", artifact_type_id, message)
    manifest.errors.append({"artifact_type_id": artifact_type_id, "message": message})
    ledger.append_event(
        "collection_error", operator,
        {"artifact_type_id": artifact_type_id, "message": message},
    )
