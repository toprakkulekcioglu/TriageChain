"""Yonlendirme akisinin orkestrasyonu: esle, dogrula, araci calistir, deftere yaz.

Guvenlik kurallari (docs/architecture.md ile birebir ayni):
  1. subprocess her zaman arguman LISTESI ile cagrilir; shell=True hicbir yerde
     kullanilmaz, boylece kabuk metakarakteri enjeksiyonu tamamen ortadan kalkar.
  2. Arac calistirilabilirlerinin yolu MUTLAK olmalidir (config semasinda
     dogrulanir); goreli yol hangi ikilinin calistigini belirsizlestirir.
  3. Araca verilen her girdi yolu, vakanin kendi cikti agaci
     (<output_dir>/<case_id>/artifacts) altinda cozulmelidir. Elle duzenlenmis
     bir manifest.json baska bir yeri gosteriyorsa hicbir sey calistirilmaz.
  4. Her cagrinin zaman asimi vardir; asilirsa olumcul olmayan hata kaydedilir.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.collection.winpath import to_long_path
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import ConfigError, RouterError
from triagechain.custody.ledger import CustodyLedger
from triagechain.router import catalog as catalog_module
from triagechain.router.models import ProcessedArtifact, RoutingManifest

logger = logging.getLogger(__name__)

# Custody olay kaydina yazilan stderr ozutunun ust siniri: defter satirlari
# okunabilir kalmali, arac cikmazsa megabaytlarca metin basabilir.
STDERR_EXCERPT_LIMIT = 2000

# Registry kovanlarinin islem (transaction) log dosyalari: bunlar TEK BASINA
# bir arac girdisi degildir, ana kovanla AYNI dizinde durup RECmd gibi
# araclar tarafindan kendiliginden (otomatik) bulunup "replay" edilir. Gercek
# bir makinede test edilirken kesfedildi: bu dosyalar registry_* hedefiyle
# birlikte toplaniyor (bkz. collection/catalog/default_targets.yaml) ama
# yonlendirmeye kendi basina asla girmemeli - girerse RECmd'e tek basina bir
# .LOG dosyasi verilmis olur, bu da anlamsiz/hatali bir cagridir.
_HIVE_TRANSACTION_LOG_SUFFIXES = (".log1", ".log2")

# tool_mapping.yaml'da bir rotanin RECmd tarzi bir toplu (batch) dosyasina
# ihtiyac duydugunu belirten yer tutucu. Rotanin hangi araca gittigine degil,
# sablonun bu yer tutucuyu KULLANIP kullanmadigina bakiliyor - esleme kod
# degil veri oldugu icin karar da veride kalmali.
_BATCH_FILE_PLACEHOLDER = "{batch_file}"

# Kullanilan custody olay tipleri:
#   routing_started    - yonlendirme kosusu basladi
#   artifact_processed - bir artefakt bir dis arac tarafindan basariyla ayristirildi
#   processing_skipped - artefakt atlandi (tanimli arac yok / arac konfigure degil / bulunamadi)
#   processing_error   - arac sifirdan farkli kod dondurdu, zaman asimina ugradi
#                        ya da girdi yolu cikti agacinin disinda kaldi (olumcul degil)
#   routing_completed  - yonlendirme kosusu bitti


@dataclass
class ToolRoute:
    """tool_mapping.yaml icindeki tek bir rota tanimi."""

    tool: str
    args: list[str]


def load_routes(catalog_path: Path) -> dict[str, ToolRoute]:
    """Arac esleme YAML'ini okuyup artifact_type_id -> rota sozlugu dondurur."""
    try:
        raw = yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Arac esleme katalogu okunamadi: {catalog_path} ({exc})") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Arac esleme katalogu gecerli YAML degil: {catalog_path} ({exc})"
        ) from exc

    routes = (raw or {}).get("routes") or {}
    return {
        artifact_type_id: ToolRoute(tool=entry["tool"], args=list(entry["args"]))
        for artifact_type_id, entry in routes.items()
    }


def run_router(
    config: TriageChainConfig, manifest: CollectionManifest, ledger: CustodyLedger
) -> RoutingManifest:
    """Toplanmis artefaktlari ilgili ayristirma araclarina yonlendirir."""
    operator = config.case.operator
    case_id = config.case.case_id
    case_dir = Path(config.collection.output_dir) / case_id
    # Karsilastirma icin tek referans nokta: her girdi yolu bunun altinda olmali.
    artifacts_root = (case_dir / "artifacts").resolve()

    routing = RoutingManifest(case_id=case_id, started_at_utc=datetime.now(timezone.utc))

    ledger.append_event(
        "routing_started",
        operator,
        {
            "run_id": routing.run_id,
            "collection_run_id": manifest.run_id,
            "artifact_count": len(manifest.artifacts),
            "output_dir": str(case_dir),
        },
    )

    routes = load_routes(catalog_module.default_catalog_path())

    for artifact in manifest.artifacts:
        _route_artifact(
            artifact=artifact,
            routes=routes,
            config=config,
            case_dir=case_dir,
            artifacts_root=artifacts_root,
            operator=operator,
            routing=routing,
            ledger=ledger,
        )

    routing.ended_at_utc = datetime.now(timezone.utc)
    ledger.append_event(
        "routing_completed",
        operator,
        {
            "run_id": routing.run_id,
            "processed_count": len(routing.processed),
            "skipped_count": len(routing.skipped),
            "error_count": len(routing.errors),
        },
    )
    return routing


def _route_artifact(
    artifact: CollectedArtifact,
    routes: dict[str, ToolRoute],
    config: TriageChainConfig,
    case_dir: Path,
    artifacts_root: Path,
    operator: str,
    routing: RoutingManifest,
    ledger: CustodyLedger,
) -> None:
    """Tek bir toplanmis artefakti ilgili araca yonlendirir."""
    if Path(artifact.dest_path).suffix.lower() in _HIVE_TRANSACTION_LOG_SUFFIXES:
        # Bu bir kovan islem logu: tek basina islenmez, ana kovanin yaninda
        # durup o calistirilirken dolayli olarak kullanilir.
        _record_skip(
            routing, ledger, operator, artifact,
            "Kovan islem log dosyasi; tek basina islenmez, ana kovan "
            "calistirilirken ayni dizinde bulunup kendiliginden kullanilir.",
        )
        return

    route = routes.get(artifact.artifact_type_id)
    if route is None:
        # Her toplama hedefinin bir ayristiricisi olmak zorunda degil; bu bir
        # hata degil ama sessiz de gecilmez, ciktida gorunur.
        _record_skip(
            routing, ledger, operator, artifact,
            "Bu artefakt tipi icin tanimli bir arac yok.",
        )
        return

    source_path = _contained_source_path(artifact.dest_path, artifacts_root)
    if source_path is None:
        # Manifest verisine kor korune guvenilmez: agac disindaki bir yol
        # icin hicbir sey CALISTIRILMAZ.
        _record_error(
            routing, ledger, operator, artifact,
            f"Girdi yolu vakanin cikti agaci disinda kaliyor ({artifact.dest_path}); "
            f"beklenen kok: {artifacts_root}. Manifest degistirilmis olabilir, "
            "hicbir arac calistirilmadi.",
        )
        return

    exe_path = config.router.tools.get(route.tool)
    if exe_path is None:
        _record_skip(
            routing, ledger, operator, artifact,
            f"'{route.tool}' araci konfigure edilmemis (router.tools icinde yok).",
        )
        return
    if not Path(exe_path).is_file():
        _record_skip(
            routing, ledger, operator, artifact,
            f"'{route.tool}' araci yolu bulunamadi: {exe_path}",
        )
        return

    # Toplu (batch) dosyasi: sadece sablonunda {batch_file} gecen rotalar icin
    # gerekir (bugun yalnizca RECmd). Yol ASLA manifest/artefakt verisinden
    # gelmez - ya config'den (mutlak oldugu semada dogrulanmis) ya da pakete
    # gomulu varsayilandan gelir.
    batch_path: Optional[Path] = None
    if any(_BATCH_FILE_PLACEHOLDER in arg for arg in route.args):
        batch_path = (
            Path(config.router.recmd_batch_file)
            if config.router.recmd_batch_file
            else catalog_module.default_recmd_batch_path()
        )
        # Varlik kontrolu config yukleme aninda degil, tam burada: aracin
        # kendisi bulunamadigindaki ile AYNI netlikte bir atlama, olumcul degil.
        if not batch_path.is_file():
            _record_skip(
                routing, ledger, operator, artifact,
                f"RECmd toplu dosyasi bulunamadi: {batch_path}",
            )
            return

    output_dir = case_dir / "parsed" / route.tool / artifact.artifact_type_id
    # Cikti dizini acilamiyorsa (disk dolu, izin yok, yolun bir parcasi aslinda
    # bir dosya) devam etmenin anlami yok: bu olumcul sayilir. Ham OSError
    # kullaniciya cikmaz, custody katmanindaki gibi tipli bir hataya sarilir.
    try:
        to_long_path(output_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RouterError(
            f"Ayristirma cikti dizini olusturulamadi: {output_dir} ({exc})"
        ) from exc

    # batch_file anahtari her rotaya veriliyor; sablonda kullanilmayan bir
    # keyword argumani str.format'ta zaten sorun degil. Her deger argv'de TEK
    # bir eleman olarak duruyor (shell=True yok).
    argv = [str(exe_path)] + [
        arg.format(
            input=str(source_path),
            output_dir=str(output_dir),
            batch_file=str(batch_path),
        )
        for arg in route.args
    ]

    started = time.monotonic()
    try:
        # shell=True YOK: argumanlar liste olarak gecer, kabuk devreye girmez.
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=config.router.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _record_error(
            routing, ledger, operator, artifact,
            f"'{route.tool}' araci {config.router.timeout_seconds} saniyede bitmedi, "
            "sonlandirildi.",
            tool=route.tool,
        )
        return
    duration = time.monotonic() - started

    stdout_log, stderr_log = _write_tool_logs(
        output_dir, source_path.name, result.stdout, result.stderr
    )

    if result.returncode != 0:
        excerpt = _decode(result.stderr)[:STDERR_EXCERPT_LIMIT]
        _record_error(
            routing, ledger, operator, artifact,
            f"'{route.tool}' araci {result.returncode} koduyla cikti.",
            tool=route.tool,
            exit_code=result.returncode,
            stderr_excerpt=excerpt,
            stdout_log_path=str(stdout_log),
            stderr_log_path=str(stderr_log),
        )
        return

    processed = ProcessedArtifact(
        artifact_type_id=artifact.artifact_type_id,
        tool=route.tool,
        source_path=str(source_path),
        output_dir=str(output_dir),
        exit_code=result.returncode,
        stdout_log_path=str(stdout_log),
        stderr_log_path=str(stderr_log),
        duration_seconds=round(duration, 3),
        processed_at_utc=datetime.now(timezone.utc),
    )
    routing.processed.append(processed)
    payload: dict[str, Any] = {
        "artifact_type_id": processed.artifact_type_id,
        "tool": processed.tool,
        "source_path": processed.source_path,
        "output_dir": processed.output_dir,
        "exit_code": processed.exit_code,
        "stdout_log_path": processed.stdout_log_path,
        "stderr_log_path": processed.stderr_log_path,
        "duration_seconds": processed.duration_seconds,
    }
    if batch_path is not None:
        # Metodoloji izlenebilirligi: "bu ciktiyi tam olarak hangi kural seti
        # uretti" sorusu, kod okunmadan defterden cevaplanabilsin diye kullanilan
        # toplu dosyanin yolu ve SHA-256'si olaya isleniyor. Diger araclarda
        # (mftecmd/evtxecmd/pecmd) ayri bir kural dosyasi kavrami yok, bu yuzden
        # bu iki alan yalnizca burada var.
        payload["recmd_batch_path"] = str(batch_path)
        payload["recmd_batch_sha256"] = hash_file(batch_path)
    ledger.append_event("artifact_processed", operator, payload)


def _contained_source_path(dest_path: str, artifacts_root: Path) -> Optional[Path]:
    """Girdi yolunu cozer; vakanin artefakt kokunun altindaysa dondurur, degilse None.

    Cozumleme (`resolve`) sembolik baglantilari ve `..` parcalarini duzlestirdigi
    icin, kontrol yol metnine degil gercek hedefe uygulanir.
    """
    try:
        resolved = Path(dest_path).resolve()
    except OSError:
        # Cozulemeyen yol (or. gecersiz surucu) guvenli sayilmaz.
        return None
    return resolved if resolved.is_relative_to(artifacts_root) else None


def _write_tool_logs(
    output_dir: Path, filename: str, stdout: Optional[bytes], stderr: Optional[bytes]
) -> tuple[Path, Path]:
    """Aracin stdout/stderr ciktisini diske yazar ve iki log yolunu dondurur.

    Denetim izi: "dis arac gercekte ne yapti" sorusunun cevabi burada durur.
    """
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
    routing: RoutingManifest,
    ledger: CustodyLedger,
    operator: str,
    artifact: CollectedArtifact,
    message: str,
) -> None:
    """Islenmeyen bir artefakti hem manifeste hem deftere yazar."""
    logger.info("[%s] %s", artifact.artifact_type_id, message)
    entry = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": artifact.dest_path,
        "message": message,
    }
    routing.skipped.append(entry)
    ledger.append_event("processing_skipped", operator, dict(entry))


def _record_error(
    routing: RoutingManifest,
    ledger: CustodyLedger,
    operator: str,
    artifact: CollectedArtifact,
    message: str,
    **extra: Any,
) -> None:
    """Olumcul olmayan bir isleme hatasini hem manifeste hem deftere yazar."""
    logger.warning("[%s] %s", artifact.artifact_type_id, message)
    entry = {
        "artifact_type_id": artifact.artifact_type_id,
        "source_path": artifact.dest_path,
        "message": message,
        **extra,
    }
    routing.errors.append(entry)
    ledger.append_event("processing_error", operator, dict(entry))
