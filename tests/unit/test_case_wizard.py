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

from triagechain.gui_qt.case_wizard import (  # noqa: E402
    NewCaseDialog,
    autodetect_tools,
    derive_case_suffix,
    detect_machine_roots,
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
