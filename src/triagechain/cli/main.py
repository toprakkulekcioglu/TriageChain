"""TriageChain komut satiri arayuzu (yalnizca stdlib argparse)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from triagechain.__about__ import __version__
from triagechain.collection.collector import run_collection
from triagechain.collection.models import CollectionManifest
from triagechain.config.loader import (
    load_config,
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_routing_manifest_path,
    resolve_watchlist_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.core.errors import (
    ConfigError,
    CustodyLedgerError,
    DetectionError,
    IntegrityError,
    ReportingError,
    RouterError,
)
from triagechain.custody.ledger import CustodyLedger, verify_chain
from triagechain.detection.capa_runner import run_capa_scan
from triagechain.detection.chainsaw_runner import run_chainsaw_detection
from triagechain.detection.runner import run_detection
from triagechain.detection.watchlist_runner import run_watchlist_check
from triagechain.detection.yara_runner import run_yara_scan
from triagechain.reporting.builder import build_report, write_report
from triagechain.router.runner import run_router


def build_parser() -> argparse.ArgumentParser:
    """Alt komutlariyla birlikte argparse ayristiricisini kurar."""
    parser = argparse.ArgumentParser(
        prog="triagechain",
        description="DFIR delil toplama ve chain-of-custody araci.",
    )
    parser.add_argument("--version", action="version", version=f"TriageChain {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser("collect", help="Konfigurasyondaki hedefleri topla.")
    collect.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    route = subparsers.add_parser(
        "route", help="Toplanmis artefaktlari ayristirma araclarina yonlendir."
    )
    route.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    detect = subparsers.add_parser(
        "detect", help="Toplanmis olay gunluklerini Hayabusa/Sigma ile tara."
    )
    detect.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    yara_scan = subparsers.add_parser(
        "yara-scan", help="Toplanmis HER artefakti YARA imza kurallariyla tara."
    )
    yara_scan.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    chainsaw_scan = subparsers.add_parser(
        "chainsaw-scan",
        help="Toplanmis olay gunluklerini Chainsaw ile tara (Hayabusa ile capraz dogrulama icin).",
    )
    chainsaw_scan.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    capa_scan = subparsers.add_parser(
        "capa-scan",
        help="collection.suspicious_binaries'daki supheli dosyalari capa ile davranis/yetenek analizine tabi tut.",
    )
    capa_scan.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    watchlist_check = subparsers.add_parser(
        "watchlist-check",
        help="Toplanmis HER artefaktin hash'ini bilinen-kotu hash listesiyle (IOC) karsilastir.",
    )
    watchlist_check.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    report = subparsers.add_parser(
        "report", help="Vakanin tum ciktilarini tek bir rapora (JSON + HTML) topla."
    )
    report.add_argument("--config", required=True, help="YAML konfigurasyon dosyasi yolu.")

    verify = subparsers.add_parser(
        "verify-custody", help="Bir custody defterinin hash zincirini dogrula."
    )
    verify.add_argument("--log", required=True, help="custody.jsonl dosyasinin yolu.")
    verify.add_argument("--case-id", required=True, help="Defterin ait oldugu vaka kimligi.")

    return parser


def _cmd_collect(args: argparse.Namespace) -> int:
    """collect alt komutu."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    manifest = run_collection(config, ledger)

    # Yol turetme tek yerde: 'route' ayni fonksiyonla ayni dosyayi bulur.
    manifest_path = resolve_manifest_path(config)
    manifest.to_json_file(manifest_path)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {manifest.run_id}")
    print(f"Toplanan      : {len(manifest.artifacts)} dosya")
    print(f"Hata          : {len(manifest.errors)} artefakt alinamadi")
    for err in manifest.errors:
        print(f"  - [{err['artifact_type_id']}] {err['message']}")
    print(f"Manifest      : {manifest_path}")
    print(f"Custody log   : {log_path}")
    # Artefakt bazinda hatalar olumcul degil, kosu basarili sayilir.
    return 0


def _cmd_route(args: argparse.Namespace) -> int:
    """route alt komutu."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    # Yonlendirme olaylari toplamanin yazdigi AYNI deftere eklenir: vaka
    # basina tek bir zincir olur, ayri bir log dosyasi acilmaz.
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    routing = run_router(config, manifest, ledger)

    # Yol turetme tek yerde: rapor katmani ayni fonksiyonla ayni dosyayi bulur.
    routing_path = resolve_routing_manifest_path(config)
    routing.to_json_file(routing_path)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {routing.run_id}")
    print(f"Islenen       : {len(routing.processed)} artefakt")
    for item in routing.processed:
        print(f"  - [{item.artifact_type_id}] {item.tool} -> {item.output_dir}")
    print(f"Atlanan       : {len(routing.skipped)} artefakt")
    for item in routing.skipped:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"Hata          : {len(routing.errors)} artefakt islenemedi")
    for item in routing.errors:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"Yonlendirme   : {routing_path}")
    print(f"Custody log   : {log_path}")
    # Artefakt bazinda atlama/hata olumcul degil, kosu basarili sayilir.
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    """detect alt komutu."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    # Tespit olaylari da ayni deftere eklenir: vaka basina tek bir zincir.
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    # Manifesti diske yazan taraf tespit kosusunun kendisidir (kapanis olayina
    # dosyanin sha256'sini islemesi gerekiyor), CLI yalnizca sonucu ozetler.
    detection = run_detection(config, manifest, ledger)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {detection.run_id}")
    print(f"Taranan       : {len(detection.scanned)} olay gunlugu")
    for item in detection.scanned:
        print(f"  - {Path(item['source_path']).name}: {item['finding_count']} bulgu "
              f"{item['level_counts'] or ''}")
        if item.get("parse_warning"):
            print(f"    uyari: {item['parse_warning']}")
    print(f"Bulgu         : {len(detection.findings)} tespit")
    print(f"Atlanan       : {len(detection.skipped)}")
    for item in detection.skipped:
        print(f"  - {item['message']}")
    print(f"Hata          : {len(detection.errors)} dosya taranamadi")
    for item in detection.errors:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"Tespit        : {resolve_detection_manifest_path(config)}")
    print(f"Custody log   : {log_path}")
    # Dosya bazinda atlama/hata olumcul degil, kosu basarili sayilir.
    return 0


def _cmd_yara_scan(args: argparse.Namespace) -> int:
    """yara-scan alt komutu -- _cmd_detect ile ayni yapi, ayri manifest/olaylar."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    yara_manifest = run_yara_scan(config, manifest, ledger)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {yara_manifest.run_id}")
    print(f"Taranan       : {len(yara_manifest.scanned)} dosya")
    for item in yara_manifest.scanned:
        print(f"  - {Path(item['source_path']).name}: {item['match_count']} eslesme")
    print(f"Eslesme       : {len(yara_manifest.matches)} imza eslesmesi")
    print(f"Atlanan       : {len(yara_manifest.skipped)}")
    for item in yara_manifest.skipped:
        print(f"  - {item['message']}")
    print(f"Hata          : {len(yara_manifest.errors)} dosya taranamadi")
    for item in yara_manifest.errors:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"YARA manifest : {resolve_yara_manifest_path(config)}")
    print(f"Custody log   : {log_path}")
    return 0


def _cmd_chainsaw_scan(args: argparse.Namespace) -> int:
    """chainsaw-scan alt komutu -- _cmd_yara_scan ile ayni yapi."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    detection = run_chainsaw_detection(config, manifest, ledger)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {detection.run_id}")
    print(f"Taranan       : {len(detection.scanned)} olay gunlugu")
    for item in detection.scanned:
        print(f"  - {Path(item['source_path']).name}: {item['finding_count']} bulgu "
              f"{item['level_counts'] or ''}")
    print(f"Bulgu         : {len(detection.findings)} tespit")
    print(f"Atlanan       : {len(detection.skipped)}")
    for item in detection.skipped:
        print(f"  - {item['message']}")
    print(f"Hata          : {len(detection.errors)} dosya taranamadi")
    for item in detection.errors:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"Chainsaw manifest : {resolve_chainsaw_manifest_path(config)}")
    print(f"Custody log   : {log_path}")
    return 0


def _cmd_capa_scan(args: argparse.Namespace) -> int:
    """capa-scan alt komutu -- _cmd_yara_scan ile ayni yapi, capa SADECE
    collection.suspicious_binaries'daki dosyalari tarar (bkz. capa_runner.py)."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    capa_manifest = run_capa_scan(config, manifest, ledger)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {capa_manifest.run_id}")
    print(f"Taranan       : {len(capa_manifest.scanned)} dosya")
    for item in capa_manifest.scanned:
        print(f"  - {Path(item['source_path']).name}: {item['match_count']} yetenek")
    print(f"Eslesme       : {len(capa_manifest.matches)} yetenek eslesmesi")
    print(f"Atlanan       : {len(capa_manifest.skipped)}")
    for item in capa_manifest.skipped:
        print(f"  - {item['message']}")
    print(f"Hata          : {len(capa_manifest.errors)} dosya taranamadi")
    for item in capa_manifest.errors:
        print(f"  - [{item['artifact_type_id']}] {item['message']}")
    print(f"capa manifest : {resolve_capa_manifest_path(config)}")
    print(f"Custody log   : {log_path}")
    return 0


def _cmd_watchlist_check(args: argparse.Namespace) -> int:
    """watchlist-check alt komutu -- _cmd_yara_scan ile ayni yapi, ama dis
    arac cagirmaz (bkz. watchlist_runner.py modul dokstring'i)."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2
    manifest = CollectionManifest.from_json_file(manifest_path)

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, config.case.case_id)

    watchlist_manifest = run_watchlist_check(config, manifest, ledger)

    print(f"Vaka          : {config.case.case_id}")
    print(f"Kosu (run_id) : {watchlist_manifest.run_id}")
    print(f"Taranan       : {len(watchlist_manifest.scanned)} dosya")
    print(f"Eslesme       : {len(watchlist_manifest.matches)} hash listesi eslesmesi")
    for item in watchlist_manifest.matches:
        print(f"  - {item.rule_name}: {Path(item.source_path).name}")
    print(f"Atlanan       : {len(watchlist_manifest.skipped)}")
    for item in watchlist_manifest.skipped:
        print(f"  - {item['message']}")
    print(f"Watchlist manifest : {resolve_watchlist_manifest_path(config)}")
    print(f"Custody log   : {log_path}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """report alt komutu."""
    config = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    manifest_path = resolve_manifest_path(config)
    if not manifest_path.exists():
        print(
            f"Toplama manifesti yok ({manifest_path}); once 'triagechain collect' calistirilmali.",
            file=sys.stderr,
        )
        return 2

    # Rapor katmani deftere YAZMAZ: yazsaydi rapordaki olay listesi ve zincir
    # sonucu yazildigi anda eskimis olurdu.
    report = build_report(config)
    json_path, sha_path, html_path = write_report(config, report)

    print(f"Vaka          : {report.case_id}")
    print(f"Kosu (run_id) : {report.run_id}")
    print(f"Toplama       : {report.collection.artifact_count} artefakt, "
          f"{report.collection.error_count} hata")
    if report.routing is None:
        print("Yonlendirme   : henuz calistirilmadi")
    else:
        print(f"Yonlendirme   : {report.routing.processed_count} islenen, "
              f"{report.routing.skipped_count} atlanan, {report.routing.error_count} hata")
    if report.detection is None:
        print("Tespit        : henuz calistirilmadi")
    else:
        print(f"Tespit        : {report.detection.scanned_count} dosya, "
              f"{report.detection.finding_count} bulgu {report.detection.level_counts or ''}")
    print(f"Custody olayi : {len(report.custody_events)}")
    print(f"Zincir durumu : {'GECERLI' if report.chain_status.is_valid else 'GECERSIZ'} "
          f"({report.chain_status.message})")
    print(f"Rapor (JSON)  : {json_path}")
    print(f"Rapor (HTML)  : {html_path}")
    print(f"Rapor sha256  : {sha_path}")
    # Kirik bir zincir raporu gecersiz kilmaz, rapor onu BILDIRMEK icin var;
    # ama cikis kodu bunu sessizce basarili gostermemeli.
    return 0 if report.chain_status.is_valid else 1


def _cmd_verify_custody(args: argparse.Namespace) -> int:
    """verify-custody alt komutu."""
    log_path = Path(args.log)
    if not log_path.exists():
        print(f"Custody defteri bulunamadi: {log_path}", file=sys.stderr)
        return 2

    result = verify_chain(log_path, args.case_id)
    print(f"Defter    : {log_path}")
    print(f"Vaka      : {args.case_id}")
    print(f"Olay      : {result.total_events}")
    print(f"Durum     : {'GECERLI' if result.is_valid else 'GECERSIZ'}")
    print(f"Aciklama  : {result.message}")
    if result.broken_at_event_id:
        print(f"Kirilma   : {result.broken_at_event_id} numarali olayda")
    return 0 if result.is_valid else 1


def main(argv: list[str] | None = None) -> int:
    """Giris noktasi; hata tiplerini anlasilir mesaj + cikis koduna cevirir."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == "collect":
            return _cmd_collect(args)
        if args.command == "route":
            return _cmd_route(args)
        if args.command == "detect":
            return _cmd_detect(args)
        if args.command == "yara-scan":
            return _cmd_yara_scan(args)
        if args.command == "chainsaw-scan":
            return _cmd_chainsaw_scan(args)
        if args.command == "capa-scan":
            return _cmd_capa_scan(args)
        if args.command == "watchlist-check":
            return _cmd_watchlist_check(args)
        if args.command == "report":
            return _cmd_report(args)
        return _cmd_verify_custody(args)
    except ConfigError as exc:
        print(f"Konfigurasyon sorunu: {exc}", file=sys.stderr)
        return 1
    except IntegrityError as exc:
        print(f"Butunluk ihlali, toplama durduruldu: {exc}", file=sys.stderr)
        return 1
    except CustodyLedgerError as exc:
        print(f"Chain-of-custody sorunu: {exc}", file=sys.stderr)
        return 1
    except RouterError as exc:
        print(f"Yonlendirme sorunu: {exc}", file=sys.stderr)
        return 1
    except DetectionError as exc:
        print(f"Tespit sorunu: {exc}", file=sys.stderr)
        return 1
    except ReportingError as exc:
        print(f"Raporlama sorunu: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
