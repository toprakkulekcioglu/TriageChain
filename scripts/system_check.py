r"""TriageChain "sistem testleri" -- GERCEK araclara/GERCEK veriye karsi,
pytest'in BILEREK mock'ladigi seyleri GERCEKTEN calistirir.

NEDEN AYRI BIR DOSYA (pytest'in tests/unit veya tests/integration'ina
DEGIL): o iki klasor CI'da (ubuntu-latest) da calisir, bu yuzden GERCEK
Windows araclarina (Hayabusa, EZ Tools, 7-Zip, RAR) ya da bu makinedeki
gercek vaka verisine/derlenmis .exe'ye hic BAGIMLI OLAMAZLAR -- hepsi
mock'lanir (bkz. tests/integration/*.py'deki `unittest.mock.patch`
cagrilari). Bu script'in kontrolleri TAM TERSI bir amaca hizmet eder:
BILEREK gercek arac/gercek veri/gercek .exe kullanir, SADECE bu Windows
gelistirme makinesinde ELLE calistirilir -- pytest'e/CI'ya HIC dahil
EDILMEZ (dosya adi `test_` ile BASLAMIYOR, boylece pytest bunu hic
TOPLAMAZ).

Bu dosya, oturum boyunca elle yazilip atilan tek seferlik dogrulama
scriptlerinin (gercek KAPE toplama/yonlendirme, sihirbazin gercek arsivle
davranisi, gercek PDF uretimi, derlenmis .exe'nin gercekten acilmasi vb.)
KALICI, BUYUYEN karsiligidir.

KULLANIM:
    python scripts/system_check.py                # hepsini calistirir
    python scripts/system_check.py --list          # kontrolleri listeler
    python scripts/system_check.py <isim> [<isim2> ...]   # sadece secilenler

YENI BIR KONTROL EKLEMEK ICIN: asagiya `check_` ile baslayan yeni bir
fonksiyon ekle (imzasi `def check_xxx() -> None`, basarisizlikta
`AssertionError`/herhangi bir Exception firlatir). Otomatik olarak
listeye/kosuya dahil olur -- baska HICBIR yeri degistirmen gerekmez.
Gerekli gercek arac/veri bu makinede yoksa `raise SkipCheck("neden")`
ile ACIKCA atla; testi sessizce gecmis gibi GOSTERME.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

# QApplication kurulmadan ONCE ayarlanmali -- tests/unit'teki ayni desen.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

# Bu makinede durduklari BILINEN, kalici gercek yollar -- bkz.
# docs/aldigim_kararlar.md'deki ilgili karar kayitlari (ne zaman/nasil
# durduklari orada da aciklaniyor).
REAL_KAPE_ROOT = Path(r"C:\Users\yasar\Desktop\TriageChain-Vaka-Verileri\final-lab-kape")
REAL_TOOLS_ROOT = Path(r"C:\Users\yasar\Desktop\TriageChain-Tools")
REAL_RAR_ARCHIVE = Path(r"C:\Downloads\Telegram Desktop\final lab some kape analiz.rar")
PACKAGED_EXE = REPO_ROOT / "dist" / "TriageChainKonsolu.exe"


class SkipCheck(Exception):
    """Bir kontrolun bu makinede GEREKLI gercek arac/veri olmadigi icin
    calistirilamadigini ACIKCA belirtir -- sessizce PASS gibi gosterilmez."""


# ---------------------------------------------------------------------------
# Toplama / ice aktarma modu -- gercek KAPE verisine karsi
# ---------------------------------------------------------------------------
def check_import_mode_collect_real_kape_data() -> None:
    """collection.source_root ile gercek bir KAPE --zip ciktisini toplar.
    Bilinen dogru sonuc: 384/384 dosya, 0 hata (bkz. aldigim_kararlar.md)."""
    if not REAL_KAPE_ROOT.is_dir():
        raise SkipCheck(f"gercek KAPE verisi yok: {REAL_KAPE_ROOT}")

    from triagechain.collection.collector import run_collection
    from triagechain.config.schema import TriageChainConfig
    from triagechain.custody.ledger import CustodyLedger

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "output"
        config = TriageChainConfig(
            case={"case_id": "SYSCHECK-USER", "operator": "system_check"},
            collection={
                "targets": [
                    "mft", "registry_system", "registry_sam", "registry_security",
                    "registry_software", "registry_ntuser", "registry_usrclass",
                    "event_logs", "prefetch",
                ],
                "output_dir": str(output_dir),
                "source_root": str(REAL_KAPE_ROOT / "2026-06-07T220139_user" / "C"),
            },
        )
        ledger = CustodyLedger(output_dir / "SYSCHECK-USER" / "custody.jsonl", "SYSCHECK-USER")
        manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 384, f"384 dosya beklendi, {len(manifest.artifacts)} geldi"
    assert len(manifest.errors) == 0, f"0 hata beklendi, {manifest.errors}"


def check_route_real_ez_tools() -> None:
    """Gercek KAPE verisini toplayip GERCEK MFTECmd/RECmd/EvtxECmd/PECmd'ye
    yonlendirir. Bilinen dogru sonuc: 8 atlanan (registry .LOG1/.LOG2, tek
    basina islenmez), 0 hata."""
    if not REAL_KAPE_ROOT.is_dir():
        raise SkipCheck(f"gercek KAPE verisi yok: {REAL_KAPE_ROOT}")
    required_tools = ["MFTECmd", "RECmd", "EvtxECmd", "PECmd"]
    missing = [name for name in required_tools if not (REAL_TOOLS_ROOT / name).is_dir()]
    if missing:
        raise SkipCheck(f"gercek EZ Tools eksik: {missing} ({REAL_TOOLS_ROOT})")

    from triagechain.collection.collector import run_collection
    from triagechain.config.schema import TriageChainConfig
    from triagechain.custody.ledger import CustodyLedger
    from triagechain.router.runner import run_router

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "output"
        config = TriageChainConfig(
            case={"case_id": "SYSCHECK-ROUTE", "operator": "system_check"},
            collection={
                "targets": [
                    "mft", "registry_system", "registry_sam", "registry_security",
                    "registry_software", "registry_ntuser", "registry_usrclass",
                    "event_logs", "prefetch",
                ],
                "output_dir": str(output_dir),
                "source_root": str(REAL_KAPE_ROOT / "2026-06-07T220139_user" / "C"),
            },
            router={
                "tools": {
                    "mftecmd": str(REAL_TOOLS_ROOT / "MFTECmd" / "MFTECmd.exe"),
                    "recmd": str(REAL_TOOLS_ROOT / "RECmd" / "RECmd.exe"),
                    "evtxecmd": str(REAL_TOOLS_ROOT / "EvtxECmd" / "EvtxECmd.exe"),
                    "pecmd": str(REAL_TOOLS_ROOT / "PECmd" / "PECmd.exe"),
                },
            },
        )
        ledger = CustodyLedger(output_dir / "SYSCHECK-ROUTE" / "custody.jsonl", "SYSCHECK-ROUTE")
        manifest = run_collection(config, ledger)
        assert len(manifest.errors) == 0
        manifest.to_json_file(output_dir / "SYSCHECK-ROUTE" / "manifest.json")

        routing = run_router(config, manifest, ledger)

    assert len(routing.errors) == 0, f"0 yonlendirme hatasi beklendi, {routing.errors}"
    assert len(routing.skipped) == 8, f"8 atlanan beklendi, {len(routing.skipped)}"


# ---------------------------------------------------------------------------
# Tespit -- hash listesi (watchlist), gercek toplanmis dosyanin GERCEK hash'ine
# ---------------------------------------------------------------------------
def check_watchlist_matching_real_hash() -> None:
    """Gercek KAPE verisini toplar, toplanan dosyalardan BIRININ GERCEK
    hash_value'sunu bir watchlist dosyasina yazar, sonra watchlist_runner'in
    o dosyayi GERCEKTEN eslestirdigini dogrular (mock/sahte hash DEGIL --
    pytest'teki testler zaten sahte hash'lerle bu mantigi kapsiyor, burada
    amac uctan uca gercek bir CollectedArtifact.hash_value'nun dogru
    hesaplanip dogru karsilastirildigini gormek)."""
    if not REAL_KAPE_ROOT.is_dir():
        raise SkipCheck(f"gercek KAPE verisi yok: {REAL_KAPE_ROOT}")

    from triagechain.collection.collector import run_collection
    from triagechain.config.schema import TriageChainConfig
    from triagechain.custody.ledger import CustodyLedger
    from triagechain.detection.watchlist_runner import run_watchlist_check

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "output"
        hashes_file = Path(tmp) / "watchlist.txt"

        base_config = TriageChainConfig(
            case={"case_id": "SYSCHECK-WATCHLIST", "operator": "system_check"},
            collection={
                "targets": ["mft"],
                "output_dir": str(output_dir),
                "source_root": str(REAL_KAPE_ROOT / "2026-06-07T220139_user" / "C"),
            },
        )
        ledger = CustodyLedger(
            output_dir / "SYSCHECK-WATCHLIST" / "custody.jsonl", "SYSCHECK-WATCHLIST"
        )
        manifest = run_collection(base_config, ledger)
        assert manifest.artifacts, "toplama hic artefakt uretmedi"
        target = manifest.artifacts[0]

        hashes_file.write_text(f"{target.hash_value},SYSCHECK gercek dosya\n", encoding="utf-8")
        config = TriageChainConfig(
            case=base_config.case, collection=base_config.collection,
            detection={"watchlist_hashes_file": str(hashes_file)},
        )

        watchlist_manifest = run_watchlist_check(config, manifest, ledger)

    assert len(watchlist_manifest.matches) == 1, (
        f"1 eslesme beklendi, {len(watchlist_manifest.matches)} geldi"
    )
    assert watchlist_manifest.matches[0].source_path == target.dest_path
    assert len(watchlist_manifest.scanned) == len(manifest.artifacts)


# ---------------------------------------------------------------------------
# "Yeni Vaka Oluştur" sihirbazi -- gercek arsiv/gercek veri
# ---------------------------------------------------------------------------
def check_wizard_batch_creation_matches_real_kape_layout() -> None:
    """Gercek KAPE kokune (3 makine) karsi calistirilinca, ELLE yazilmis
    referans config'lerle BIREBIR ayni source_root'lari uretmeli."""
    if not REAL_KAPE_ROOT.is_dir():
        raise SkipCheck(f"gercek KAPE verisi yok: {REAL_KAPE_ROOT}")

    from triagechain.gui_qt.case_wizard import detect_machine_roots, resolve_drive_root

    machine_roots = detect_machine_roots(REAL_KAPE_ROOT)
    names = sorted(p.name for p in machine_roots)
    assert names == [
        "2026-06-07T220139_user", "2026-06-07T222136_server", "2026-06-08T082103_domain",
    ], f"3 gercek makine beklendi, {names} bulundu"

    for machine_root in machine_roots:
        resolved = resolve_drive_root(machine_root)
        assert resolved.name == "C", f"{machine_root.name} icin 'C' surucu kokunun altinda degil"


def check_rar_extraction_and_nested_zip_flow() -> None:
    """Kullanicinin gercek .rar dosyasi -- ic ice DOGRUDAN uc makine .zip'i
    tasiyor (klasor DEGIL). extract_archive + _extract_nested_zips + toplu
    mod tespiti uctan uca dogru calismali (bkz. aldigim_kararlar.md)."""
    if not REAL_RAR_ARCHIVE.is_file():
        raise SkipCheck(f"gercek .rar dosyasi yok: {REAL_RAR_ARCHIVE}")
    from triagechain.gui_qt.case_wizard import find_seven_zip
    if find_seven_zip() is None:
        raise SkipCheck("7-Zip bulunamadi (RAR cikartma icin gerekli)")

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841
    from triagechain.gui_qt.case_wizard import NewCaseDialog, detect_machine_roots

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "cikarilan"
        dialog = NewCaseDialog()
        error = None
        try:
            from triagechain.gui_qt.case_wizard import extract_archive
            error = extract_archive(REAL_RAR_ARCHIVE, dest)
            assert error is None, f"RAR cikartma hatasi: {error}"
            ok = dialog._extract_nested_zips(dest)
            assert ok, "ic ice zip cikartma basarisiz"
            machine_roots = detect_machine_roots(dest)
            assert len(machine_roots) == 3, f"3 makine beklendi, {len(machine_roots)} bulundu"
        finally:
            dialog.deleteLater()


def check_autodetect_tools_finds_real_ez_tools() -> None:
    """Gercek arac klasorune karsi -- 4 EZ Tools + Hayabusa yolu/kural
    klasoru bulunmali."""
    if not REAL_TOOLS_ROOT.is_dir():
        raise SkipCheck(f"gercek arac klasoru yok: {REAL_TOOLS_ROOT}")

    from triagechain.gui_qt.case_wizard import autodetect_tools

    found = autodetect_tools(REAL_TOOLS_ROOT)
    for name in ("mftecmd", "recmd", "evtxecmd", "pecmd"):
        assert name in found["router_tools"], f"{name} bulunamadi"
    assert "hayabusa_path" in found["detection"], "Hayabusa bulunamadi"


# ---------------------------------------------------------------------------
# Disa aktarma -- gercek dosya uretimi
# ---------------------------------------------------------------------------
def check_pdf_export_produces_valid_pdf() -> None:
    """QtPrintSupport ile gercek bir PDF uretir -- %PDF- imzali, bos degil."""
    from datetime import datetime, timezone

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841

    from triagechain.gui_qt import pdf_export
    from triagechain.reporting.executive import build_executive_summary
    from triagechain.reporting.models import ChainStatus, CollectionSummary, Report

    report = Report(
        case_id="SYSCHECK-PDF", operator="system_check", description="",
        collection=CollectionSummary(
            run_id="r1", started_at_utc=datetime.now(timezone.utc), ended_at_utc=None,
            artifact_count=10, error_count=0,
        ),
        chain_status=ChainStatus(is_valid=True, total_events=3, broken_at_event_id=None, message="ok"),
    )
    summary = build_executive_summary(report)

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "ozet.pdf"
        pdf_export.export_report_pdf(out_path, report, summary)
        assert out_path.is_file()
        data = out_path.read_bytes()
        assert data.startswith(b"%PDF-"), "gecerli bir PDF imzasi yok"
        assert len(data) > 500, "PDF supheli kucuk"


# ---------------------------------------------------------------------------
# Arayuz -- tam pencere render + derlenmis .exe
# ---------------------------------------------------------------------------
def check_theme_toggle_full_window_render() -> None:
    """Tam pencereyi kurup acik/koyu arasinda gecis yapar -- gercek
    QWidget.grab() cagirir, exception firlamamali ve piksel uretmeli."""
    from PySide6.QtWidgets import QApplication

    from triagechain.gui_qt import theme as t

    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    t.load_embedded_fonts()
    app.setStyleSheet(t.base_stylesheet())

    from triagechain.gui_qt.main_window import TriageChainWindow

    window = TriageChainWindow()
    window.resize(1180, 760)
    window.show()
    app.processEvents()

    dark_pixmap = window.grab()
    assert dark_pixmap.width() > 0 and dark_pixmap.height() > 0

    window._show_settings()
    window.theme_light_radio.setChecked(True)
    app.processEvents()
    assert t.get_mode() == "light"

    light_pixmap = window.grab()
    assert light_pixmap.width() > 0 and light_pixmap.height() > 0

    t.set_mode("dark")  # sonraki kontrolleri etkilememesi icin geri al
    window.deleteLater()


def check_packaged_exe_launches() -> None:
    """dist/TriageChainKonsolu.exe gercekten acilip birkaç saniye ayakta
    kalabiliyor mu -- PyInstaller'in eksik bir gizli import'u kacirdigi
    (orn. QtPrintSupport) durumlarda bu genelde hemen cokerdi."""
    if not PACKAGED_EXE.is_file():
        raise SkipCheck(f"derlenmis exe yok: {PACKAGED_EXE} (once PyInstaller calistirin)")
    import subprocess

    proc = subprocess.Popen([str(PACKAGED_EXE)])
    try:
        time.sleep(3)
        assert proc.poll() is None, "exe 3 saniye icinde kendiliginden kapandi (cokme?)"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Kosucu -- yukaridaki check_* fonksiyonlarini otomatik bulur/calistirir
# ---------------------------------------------------------------------------
def _discover_checks() -> dict[str, callable]:
    module = sys.modules[__name__]
    return {
        name: fn for name, fn in vars(module).items()
        if name.startswith("check_") and callable(fn)
    }


def main(argv: list[str]) -> int:
    checks = _discover_checks()

    if "--list" in argv:
        for name in sorted(checks):
            print(name)
        return 0

    selected = [a for a in argv if not a.startswith("-")]
    names = selected or sorted(checks)
    unknown = [n for n in names if n not in checks]
    if unknown:
        print(f"Bilinmeyen kontrol(ler): {unknown}", file=sys.stderr)
        return 2

    passed, failed, skipped = 0, 0, 0
    for name in names:
        print(f"— {name} ...", end=" ", flush=True)
        try:
            checks[name]()
        except SkipCheck as exc:
            print(f"ATLANDI ({exc})")
            skipped += 1
        except Exception:  # noqa: BLE001 -- kullanıcıya tam iz gösterilmeli
            print("BAŞARISIZ")
            traceback.print_exc()
            failed += 1
        else:
            print("GEÇTİ")
            passed += 1

    print(f"\n{passed} geçti, {failed} başarısız, {skipped} atlandı "
          f"(toplam {len(names)})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
