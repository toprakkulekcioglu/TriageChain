"""Hash listesi (watchlist/IOC) eslestirme akisi: toplanan HER artefaktin
zaten hesaplanmis hash'i (CollectedArtifact.hash_value), analistin verdigi
bilinen-kotu hash listesiyle karsilastirilir.

Diger uc tespit motorundan (Hayabusa/Chainsaw/YARA/capa) TEMEL mimari farki:
bu motor hicbir DIS ARAC/subprocess CAGIRMAZ -- toplama sirasinda zaten
hesaplanmis hash'lere karsi SAF PYTHON sozluk karsilastirmasi yapar. Bu yuzden
detection/runner.py, yara_runner.py, capa_runner.py'nin sahip oldugu
subprocess guvenlik kurallari (mutlak arac yolu, zaman asimi, stdout/stderr
log dosyalari, "artefakt basina hata" durumu) burada YOK -- karsilastirma
kendiliginden basarisiz olamaz, sadece "hash listesi dosyasi okunamadi" gibi
TEK bir global atlama nedeni olabilir.

YARA ile paylastigi ortak nokta: HER artefakt turu taranir (capa'nin aksine
sadece suphe binary'lerle sinirli degil). Bu yuzden Finding/DetectionManifest
DEGIL, capa'nin da kullandigi YaraMatch/YaraManifest semasi yeniden
kullanilir (bkz. aldigim_kararlar.md -> "reused-schema" deseni): bir eslesme
zaman/bilgisayar/kanal baglami tasimayan, adlandirilmis bir kural
(bu durumda "watchlist:<etiket>") eslesmesidir -- capa'nin yetenek
eslesmeleriyle AYNI sekil.

Performans nedeniyle (binlerce artefakt, sifir maliyetli karsilastirma)
YARA/capa'nin aksine artefakt basina custody olayi YAZILMAZ -- sadece tek bir
watchlist_started/watchlist_completed cifti (diger motorlarla ayni desen).
Bu bilincli bir sapma: artefakt basina olay, gercek bir dis arac cagrisinin
denetim izini tutmak icindir; burada boyle bir cagri yok, kaydedilecek yeni
bir "olay" da yok -- sonuc zaten watchlist_manifest.json'da tam olarak duruyor.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.loader import resolve_watchlist_manifest_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import DetectionError
from triagechain.custody.ledger import CustodyLedger
from triagechain.detection.models import YaraManifest, YaraMatch

logger = logging.getLogger(__name__)

# Kullanilan custody olay tipleri:
#   watchlist_started   - hash listesi kosusu basladi
#   watchlist_skipped    - kosu atlandi (dosya konfigure degil/bulunamadi/okunamadi)
#   watchlist_completed  - kosu bitti (manifest sha256'si ile)


def load_watchlist(path: Path) -> dict[str, str]:
    """Hash listesi dosyasini okur -> {kucuk_harf_hash: etiket}.

    Bicim: satir basina bir girdi, `hash` ya da `hash,etiket` ya da
    `hash etiket` (virgul veya bosluk ile ayrilmis). `#` ile baslayan ve bos
    satirlar yok sayilir. Hash'ler kucuk harfe normalize edilir (buyuk/kucuk
    harf duyarsiz eslesme icin -- bkz. GUI arama ozelligiyle ayni karar).
    Etiket verilmemisse hash'in kendisi etiket olarak kullanilir."""
    hashes: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            hash_part, _, label_part = line.partition(",")
        else:
            parts = line.split(None, 1)
            hash_part = parts[0]
            label_part = parts[1] if len(parts) > 1 else ""
        hash_value = hash_part.strip().lower()
        label = label_part.strip()
        if hash_value:
            hashes[hash_value] = label or hash_value
    return hashes


def run_watchlist_check(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> YaraManifest:
    """Toplanmis HER artefaktin hash'ini hash listesiyle karsilastirir."""
    operator = config.case.operator
    case_id = config.case.case_id

    watchlist_manifest = YaraManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))
    targets = list(manifest.artifacts)

    ledger.append_event(
        "watchlist_started",
        operator,
        {
            "run_id": watchlist_manifest.run_id,
            "collection_run_id": manifest.run_id,
            "artifact_count": len(targets),
        },
    )

    unavailable = _unavailable_reason(config)
    if unavailable is not None:
        _record_skip(watchlist_manifest, ledger, operator, unavailable, artifact_count=len(targets))
    else:
        hashes_path = Path(config.detection.watchlist_hashes_file)  # type: ignore[arg-type]
        try:
            watchlist = load_watchlist(hashes_path)
        except OSError as exc:
            _record_skip(
                watchlist_manifest, ledger, operator,
                f"Hash listesi okunamadi: {hashes_path} ({exc})",
                artifact_count=len(targets),
            )
        else:
            for artifact in targets:
                _check_artifact(artifact, watchlist, watchlist_manifest)

    watchlist_manifest.ended_at_utc = datetime.now(timezone.utc)

    manifest_path = resolve_watchlist_manifest_path(config)
    try:
        watchlist_manifest.to_json_file(manifest_path)
    except OSError as exc:
        raise DetectionError(
            f"Hash listesi manifesti yazilamadi: {manifest_path} ({exc})"
        ) from exc

    ledger.append_event(
        "watchlist_completed",
        operator,
        {
            "run_id": watchlist_manifest.run_id,
            "scanned_count": len(watchlist_manifest.scanned),
            "match_count": len(watchlist_manifest.matches),
            "skipped_count": len(watchlist_manifest.skipped),
            "watchlist_manifest_path": str(manifest_path),
            "watchlist_manifest_sha256": hash_file(manifest_path),
        },
    )
    return watchlist_manifest


def _unavailable_reason(config: TriageChainConfig) -> Optional[str]:
    """Hash listesi kontrolu calistirilamayacaksa nedenini dondurur."""
    hashes_file = config.detection.watchlist_hashes_file
    if not hashes_file:
        return "Hash listesi konfigure edilmemis (detection.watchlist_hashes_file bos)."
    if not Path(hashes_file).is_file():
        return f"Hash listesi dosyasi bulunamadi: {hashes_file}"
    return None


def _check_artifact(
    artifact: CollectedArtifact, watchlist: dict[str, str], watchlist_manifest: YaraManifest
) -> None:
    """Tek bir artefaktin hash'ini hash listesiyle karsilastirir (dis arac
    cagrisi YOK -- bkz. modul dokstring'i)."""
    hash_value = artifact.hash_value.lower()
    label = watchlist.get(hash_value)
    if label is not None:
        watchlist_manifest.matches.append(
            YaraMatch(
                artifact_type_id=artifact.artifact_type_id,
                source_path=artifact.dest_path,
                rule_name=f"watchlist:{label}",
                tags="watchlist",
                meta=f"hash_algorithm={artifact.hash_algorithm}",
            )
        )
    watchlist_manifest.scanned.append(
        {
            "artifact_type_id": artifact.artifact_type_id,
            "source_path": artifact.dest_path,
            "match_count": 1 if label is not None else 0,
        }
    )


def _record_skip(
    watchlist_manifest: YaraManifest,
    ledger: CustodyLedger,
    operator: str,
    message: str,
    artifact_count: int,
) -> None:
    logger.info("[watchlist] %s", message)
    entry = {"message": message, "artifact_count": artifact_count}
    watchlist_manifest.skipped.append(entry)
    ledger.append_event("watchlist_skipped", operator, dict(entry))
