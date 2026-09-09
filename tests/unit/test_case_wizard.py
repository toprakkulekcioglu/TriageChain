"""Yeni Vaka sihirbazinin (case_wizard.py) ekransiz testleri.

test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen, gercek pencere
acilmaz. Dosya/klasor secim diyaloglari (QFileDialog) hicbir testte
TETIKLENMEZ -- diyalog sonrasi cagirilacak ic metotlar (_set_source_root,
_on_create) dogrudan cagrilir, boylece testler headless CI'da da calisir.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

from triagechain.config.loader import load_config  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import zipfile  # noqa: E402

from triagechain.gui_qt import case_wizard  # noqa: E402
from triagechain.gui_qt.case_wizard import (  # noqa: E402
    NewCaseDialog,
    autodetect_tools,
    derive_case_suffix,
    detect_machine_roots,
    extract_archive,
    resolve_drive_root,
)


@pytest.fixture(scope="session")
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def dialog(qt_app):
    return NewCaseDialog()


# -- Saf yardimci fonksiyonlar (Qt gerektirmez) ------------------------------

def test_derive_case_suffix_zaman_damgasini_atar():
    assert derive_case_suffix("2026-06-07T220139_user") == "USER"


def test_derive_case_suffix_desen_uymayan_adin_tamamini_kullanir():
    assert derive_case_suffix("sunucu_verisi") == "SUNUCU_VERISI"


def test_derive_case_suffix_bos_kalirsa_yedek_deger_doner():
    assert derive_case_suffix("---") == "VAKA"


def test_detect_machine_roots_gizli_klasoru_atlar(tmp_path):
    (tmp_path / "makine_a").mkdir()
    (tmp_path / "makine_b").mkdir()
    (tmp_path / ".gizli").mkdir()
    (tmp_path / "dosya.txt").write_text("x")
    found = detect_machine_roots(tmp_path)
    assert [p.name for p in found] == ["makine_a", "makine_b"]


def test_resolve_drive_root_tek_harfli_klasoru_bulur(tmp_path):
    (tmp_path / "C").mkdir()
    assert resolve_drive_root(tmp_path) == tmp_path / "C"


def test_resolve_drive_root_surucu_klasoru_yoksa_kendini_doner(tmp_path):
    (tmp_path / "Windows").mkdir()
    assert resolve_drive_root(tmp_path) == tmp_path


def test_autodetect_tools_bilinen_isimleri_bulur(tmp_path):
    (tmp_path / "MFTECmd").mkdir()
    (tmp_path / "MFTECmd" / "MFTECmd.exe").write_bytes(b"")
    (tmp_path / "hayabusa-4.0.0").mkdir()
    (tmp_path / "hayabusa-4.0.0" / "hayabusa-4.0.0-win-x64.exe").write_bytes(b"")
    (tmp_path / "hayabusa-4.0.0" / "rules").mkdir()

    found = autodetect_tools(tmp_path)
    assert found["router_tools"]["mftecmd"] == str(tmp_path / "MFTECmd" / "MFTECmd.exe")
    assert found["detection"]["hayabusa_path"] == str(
        tmp_path / "hayabusa-4.0.0" / "hayabusa-4.0.0-win-x64.exe"
    )
    assert found["detection"]["rules_dir"] == str(tmp_path / "hayabusa-4.0.0" / "rules")


def test_autodetect_tools_hicbir_sey_bulamazsa_bos_sozluk_doner(tmp_path):
    found = autodetect_tools(tmp_path)
    assert found == {"router_tools": {}, "detection": {}}


def _make_zip(zip_path: Path, files: dict[str, str]) -> None:
    with zipfile.ZipFile(zip_path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


# -- Arsiv cikartma (extract_archive / _extract_nested_zips) ----------------
# find_seven_zip() bu gelistirme makinesinde GERCEK bir 7-Zip bulabiliyor --
# 7z hem .zip'i hem .rar/.7z'i actigi icin normal (gecerli) bir .zip'te iki
# yol da (7z VEYA stdlib zipfile) ayni sonucu vermeli; "7z yok" davranisi
# ayrica monkeypatch ile zorlanarak test ediliyor (CI'da gercekten 7z
# bulunmuyor, o yuzden CI zaten hep bu ikinci yolu test ediyor).

def test_extract_archive_gecerli_zip_basariyla_acar(tmp_path):
    zip_path = tmp_path / "kaynak.zip"
    _make_zip(zip_path, {"C/marker.txt": "merhaba"})
    dest = tmp_path / "hedef"

    error = extract_archive(zip_path, dest)

    assert error is None
    assert (dest / "C" / "marker.txt").read_text(encoding="utf-8") == "merhaba"


def test_extract_archive_7z_yokken_zip_yine_stdlib_ile_acilir(tmp_path, monkeypatch):
    monkeypatch.setattr(case_wizard, "find_seven_zip", lambda: None)
    zip_path = tmp_path / "kaynak.zip"
    _make_zip(zip_path, {"C/marker.txt": "merhaba"})
    dest = tmp_path / "hedef"

    error = extract_archive(zip_path, dest)

    assert error is None
    assert (dest / "C" / "marker.txt").is_file()


def test_extract_archive_7z_yokken_rar_acikca_reddedilir(tmp_path, monkeypatch):
    monkeypatch.setattr(case_wizard, "find_seven_zip", lambda: None)
    fake_rar = tmp_path / "kaynak.rar"
    fake_rar.write_bytes(b"not a real rar")

    error = extract_archive(fake_rar, tmp_path / "hedef")

    assert error is not None
    assert "7-Zip" in error


def test_extract_archive_bozuk_zip_hata_doner(tmp_path, monkeypatch):
    monkeypatch.setattr(case_wizard, "find_seven_zip", lambda: None)
    bozuk = tmp_path / "bozuk.zip"
    bozuk.write_bytes(b"bu gecerli bir zip degil")

    error = extract_archive(bozuk, tmp_path / "hedef")

    assert error is not None


def test_extract_nested_zips_ic_ice_zip_dosyalarini_klasore_cikartir(dialog, tmp_path):
    """Gercek kullanici verisiyle bulunan durum: bir arsiv cikartildiginda
    kokte DOGRUDAN makine .zip dosyalari duruyor (klasor degil) -- bkz.
    case_wizard.py::_extract_nested_zips docstring'i."""
    dest = tmp_path / "cikarilan"
    dest.mkdir()
    _make_zip(dest / "2026-06-07T220139_user.zip", {"C/marker.txt": "user"})
    _make_zip(dest / "2026-06-07T222136_server.zip", {"C/marker.txt": "server"})

    ok = dialog._extract_nested_zips(dest)

    assert ok is True
    assert (dest / "2026-06-07T220139_user" / "C" / "marker.txt").read_text() == "user"
    assert (dest / "2026-06-07T222136_server" / "C" / "marker.txt").read_text() == "server"
    # Toplu mod bu noktada devreye girebilmeli:
    machine_roots = detect_machine_roots(dest)
    assert {p.name for p in machine_roots} >= {
        "2026-06-07T220139_user", "2026-06-07T222136_server",
    }


def test_extract_nested_zips_zip_yoksa_hicbir_sey_yapmaz(dialog, tmp_path):
    dest = tmp_path / "cikarilan"
    (dest / "C").mkdir(parents=True)

    ok = dialog._extract_nested_zips(dest)

    assert ok is True
    assert sorted(p.name for p in dest.iterdir()) == ["C"]


def test_extract_nested_zips_mevcut_hedefi_tekrar_cikartmaz(dialog, tmp_path):
    dest = tmp_path / "cikarilan"
    dest.mkdir()
    _make_zip(dest / "user.zip", {"C/marker.txt": "orijinal"})
    already = dest / "user"
    already.mkdir()
    (already / "farkli.txt").write_text("elle konulmus dosya")

    ok = dialog._extract_nested_zips(dest)

    assert ok is True
    assert (already / "farkli.txt").is_file()
    assert not (already / "C").exists()


# -- Arka planda cikartma (_ExtractionWorker / _start_extraction) -----------
# Gercek kullanici verisiyle bulunan hata: cikartma daha once GUI is
# parcacigini bloke ediyordu, buyuk arsivlerde Windows pencereyi "Yanit
# Vermiyor" gosteriyordu. Bu testler QFileDialog'a hic dokunmaz (_start_
# extraction dogrudan cagrilir) -- worker.wait() ile is parcacigi bitirilir,
# sonra processEvents() ile ana is parcacigina kuyruklanan sinyaller isletilir.

def test_extraction_arka_planda_calisir_ve_kaynak_kokunu_ayarlar(dialog, tmp_path, qt_app):
    source_zip = tmp_path / "kaynak.zip"
    _make_zip(source_zip, {"C/marker.txt": "veri"})
    dest = tmp_path / "hedef"

    dialog._start_extraction(source_zip, dest)

    assert dialog._pick_folder_btn.isEnabled() is False
    assert dialog._pick_archive_btn.isEnabled() is False
    assert dialog.create_btn.isEnabled() is False
    assert not dialog.extraction_progress.isHidden()

    assert dialog._extraction_worker.wait(5000)
    qt_app.processEvents()

    assert dialog._extraction_worker is None
    assert dialog._pick_folder_btn.isEnabled() is True
    assert dialog.create_btn.isEnabled() is True
    assert dialog.extraction_progress.isHidden()
    assert dialog._source_root == dest
    assert (dest / "C" / "marker.txt").read_text(encoding="utf-8") == "veri"


def test_extraction_hata_verirse_kontroller_geri_acilir(dialog, tmp_path, qt_app, monkeypatch):
    monkeypatch.setattr(case_wizard, "find_seven_zip", lambda: None)
    bozuk = tmp_path / "bozuk.zip"
    bozuk.write_bytes(b"gecersiz zip icerigi")
    dest = tmp_path / "hedef"

    dialog._start_extraction(bozuk, dest)
    assert dialog._extraction_worker.wait(5000)
    qt_app.processEvents()

    assert dialog._extraction_worker is None
    assert not dialog.error_label.isHidden()
    assert dialog._pick_folder_btn.isEnabled() is True
    assert dialog._source_root is None


def test_extraction_surerken_dialog_kapatilamaz(dialog, tmp_path, qt_app):
    source_zip = tmp_path / "kaynak.zip"
    _make_zip(source_zip, {"C/marker.txt": "veri"})
    dest = tmp_path / "hedef"
    dialog._start_extraction(source_zip, dest)

    rejected_calls = []
    dialog.rejected.connect(lambda: rejected_calls.append(True))
    dialog.reject()
    assert rejected_calls == []

    assert dialog._extraction_worker.wait(5000)
    qt_app.processEvents()

    dialog.reject()
    assert rejected_calls == [True]


def test_ic_ice_zipli_gercek_senaryo_arka_planda_toplu_moda_gecer(dialog, tmp_path, qt_app):
    """Gercek kullanici verisiyle bulunan tam senaryo: bir arsiv cikartilinca
    kokte DOGRUDAN makine .zip dosyalari duruyor -- worker bunlari da
    cikartip toplu modu tetiklemeli, hepsi tek is parcacigi calismasinda."""
    import io

    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.writestr("C/marker.txt", "user")

    outer_zip = tmp_path / "disari.zip"
    with zipfile.ZipFile(outer_zip, "w") as outer:
        outer.writestr("2026-06-07T220139_user.zip", inner_buffer.getvalue())

    dest = tmp_path / "hedef"
    dialog._start_extraction(outer_zip, dest)
    assert dialog._extraction_worker.wait(5000)
    qt_app.processEvents()

    assert dialog.error_label.isHidden()
    assert (dest / "2026-06-07T220139_user" / "C" / "marker.txt").read_text() == "user"


# -- Sihirbaz (Qt) ------------------------------------------------------------

def test_tekli_kaynak_gecerli_yaml_uretir(dialog, tmp_path):
    source = tmp_path / "kaynak" / "C"
    source.mkdir(parents=True)
    output_dir = tmp_path / "cikti"

    dialog.case_id_input.setText("TEK-VAKA")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = output_dir
    dialog._set_source_root(source.parent)

    dialog._on_create()

    assert dialog.error_label.isHidden()
    assert len(dialog.generated_config_paths) == 1
    config_path = dialog.generated_config_paths[0]
    assert config_path.name == "TEK-VAKA_config.generated.yaml"

    loaded = load_config(config_path)
    assert loaded.case.case_id == "TEK-VAKA"
    assert loaded.collection.source_root == str(source)


def test_canli_sistem_modunda_source_root_yazilmaz(dialog, tmp_path):
    output_dir = tmp_path / "cikti"
    dialog.case_id_input.setText("CANLI-VAKA")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = output_dir
    dialog.live_radio.setChecked(True)

    dialog._on_create()

    assert dialog.error_label.isHidden()
    raw = yaml.safe_load(dialog.generated_config_paths[0].read_text(encoding="utf-8"))
    assert "source_root" not in raw["collection"]


def test_toplu_mod_birden_fazla_makineyi_ayri_vaka_yapar(dialog, tmp_path):
    root = tmp_path / "kape_zip_koku"
    for name in ("2026-06-07T220139_user", "2026-06-07T222136_server"):
        (root / name / "C").mkdir(parents=True)
    output_dir = tmp_path / "cikti"

    dialog.case_id_input.setText("FINAL-LAB")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = output_dir
    dialog._set_source_root(root)

    assert len(dialog._batch_roots) == 2
    assert len(dialog._machine_checkboxes) == 2

    dialog._on_create()

    assert dialog.error_label.isHidden()
    case_ids = sorted(p.stem.removesuffix("_config.generated") for p in dialog.generated_config_paths)
    assert case_ids == ["FINAL-LAB-SERVER", "FINAL-LAB-USER"]

    for path in dialog.generated_config_paths:
        loaded = load_config(path)
        assert loaded.collection.source_root.endswith("\\C") or loaded.collection.source_root.endswith("/C")


def test_toplu_modda_secimi_kaldirilan_makine_uretilmez(dialog, tmp_path):
    root = tmp_path / "kape_zip_koku"
    for name in ("2026-06-07T220139_user", "2026-06-07T222136_server"):
        (root / name / "C").mkdir(parents=True)
    output_dir = tmp_path / "cikti"

    dialog.case_id_input.setText("FINAL-LAB")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = output_dir
    dialog._set_source_root(root)

    server_root = root / "2026-06-07T222136_server"
    dialog._machine_checkboxes[server_root].setChecked(False)

    dialog._on_create()

    assert dialog.error_label.isHidden()
    assert len(dialog.generated_config_paths) == 1
    assert "USER" in dialog.generated_config_paths[0].name


def test_tek_alt_klasorlu_kok_toplu_mod_saymaz(dialog, tmp_path):
    """Tek makine kok klasoru dogrudan 'C' klasorunu tasir -- bu 2. seviye
    alt klasor toplu mod icin 'birden fazla makine' SAYILMAMALI (bkz.
    resolve_drive_root ile ayni gerekce, case_wizard.py modul basi notu)."""
    source_root = tmp_path / "2026-06-07T220139_user"
    (source_root / "C").mkdir(parents=True)

    dialog._set_source_root(source_root)

    assert dialog._batch_roots == []


def test_bos_vaka_kimligi_hata_gosterir(dialog, tmp_path):
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = tmp_path / "cikti"
    dialog.live_radio.setChecked(True)

    dialog._on_create()

    assert not dialog.error_label.isHidden()
    assert dialog.generated_config_paths == []


def test_cikti_dizini_secilmeden_hata_gosterir(dialog):
    dialog.case_id_input.setText("VAKA-1")
    dialog.operator_input.setText("test.operator")
    dialog.live_radio.setChecked(True)

    dialog._on_create()

    assert not dialog.error_label.isHidden()
    assert "Çıktı dizini" in dialog.error_label.text()


def test_hicbir_artefakt_secili_degilse_hata_gosterir(dialog, tmp_path):
    dialog.case_id_input.setText("VAKA-1")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = tmp_path / "cikti"
    dialog.live_radio.setChecked(True)
    for box in dialog.target_checkboxes.values():
        box.setChecked(False)

    dialog._on_create()

    assert not dialog.error_label.isHidden()
    assert "artefakt" in dialog.error_label.text()


def test_ice_aktarma_modunda_kaynak_secilmezse_hata_gosterir(dialog, tmp_path):
    dialog.case_id_input.setText("VAKA-1")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = tmp_path / "cikti"
    dialog.import_radio.setChecked(True)

    dialog._on_create()

    assert not dialog.error_label.isHidden()
    assert "kaynak" in dialog.error_label.text().lower()


def test_arac_klasoru_otomatik_bulunanlari_konfigurasyona_yazar(dialog, tmp_path):
    tools_root = tmp_path / "araclar"
    (tools_root / "MFTECmd").mkdir(parents=True)
    (tools_root / "MFTECmd" / "MFTECmd.exe").write_bytes(b"")

    dialog._tools_root = tools_root
    dialog._autodetected = autodetect_tools(tools_root)

    dialog.case_id_input.setText("ARAC-VAKA")
    dialog.operator_input.setText("test.operator")
    dialog._output_dir = tmp_path / "cikti"
    dialog.live_radio.setChecked(True)

    dialog._on_create()

    assert dialog.error_label.isHidden()
    loaded = load_config(dialog.generated_config_paths[0])
    assert loaded.router.tools["mftecmd"] == str(tools_root / "MFTECmd" / "MFTECmd.exe")
