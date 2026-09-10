"""TriageChain -- TUM pytest testleri TEK dosyada.

Kullanicinin istegi uzerine tests/unit/*.py + tests/integration/*.py
tek bir dosyada birlestirildi: yeni bir test eklenecegi zaman bu
dosyanin SONUNA eklenir, `pytest tests/test_all.py` (ya da sadece
`pytest`) TUMUNU tek seferde calistirir -- ayri ayri dosya
olusturup/calistirmaya gerek kalmaz.

Her bolum, orijinal kaynak dosyasindan (BIRE BIR ayni test/yardimci
kod, sadece CAKISAN isimler dosyaya-ozgu bir onekle yeniden
adlandirildi -- bkz. asagidaki bolum basliklari) tasindi. Orijinal
dosyalar SILINDI, boylece pytest ayni testi IKI KEZ toplamiyor.
"""

import os

# QApplication kurulmadan ONCE ayarlanmali (bazi bolumler PySide6
# kullaniyor) -- bu yuzden HER import'tan once, dosyanin en basinda.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.capa_runner import run_capa_scan
from triagechain.detection.models import YaraManifest
from triagechain.gui_qt import case_note_store
from pathlib import Path  # noqa: E402
import pytest  # noqa: E402
import yaml  # noqa: E402
from triagechain.config.loader import load_config  # noqa: E402
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
import pytest
from triagechain.detection.chainsaw_runner import run_chainsaw_detection
from triagechain.detection.models import DetectionManifest
import yaml
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.core.errors import ConfigError
from triagechain.detection.correlation import correlate_findings, correlate_sigma_engines
from triagechain.detection.models import DetectionManifest, Finding, YaraManifest, YaraMatch
import csv
from triagechain.gui_qt import csv_export
import threading
from triagechain.core.errors import CustodyLedgerError
from triagechain.custody.ledger import (
    CustodyLedger,
    genesis_hash,
    read_events,
    verify_chain,
)
from triagechain.detection import catalog as detection_catalog
from triagechain.detection.runner import SCANNED_ARTIFACT_TYPE, load_profile
from triagechain.core.errors import DetectionError
from triagechain.detection.runner import run_detection
from datetime import datetime, timedelta, timezone  # noqa: E402
from triagechain.collection.models import CollectedArtifact, CollectionManifest  # noqa: E402
from triagechain.config.loader import (  # noqa: E402
    load_config,
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.custody.ledger import CustodyLedger  # noqa: E402
from triagechain.detection.models import (  # noqa: E402
    DetectionManifest,
    Finding,
    YaraManifest,
    YaraMatch,
)
from triagechain.reporting.builder import build_report, write_report  # noqa: E402
from triagechain.router.models import ProcessedArtifact, RoutingManifest  # noqa: E402
from PySide6.QtWidgets import QApplication, QFileDialog, QLabel, QToolButton  # noqa: E402
from triagechain.gui_qt import i18n  # noqa: E402
from triagechain.gui_qt import tag_store  # noqa: E402
from triagechain.gui_qt import theme as t  # noqa: E402
from triagechain.gui_qt.main_window import SIDEBAR_PAGES, TriageChainWindow  # noqa: E402
from triagechain.collection.hashing import hash_file
from triagechain.gui_qt import i18n
from datetime import datetime, timezone  # noqa: E402
from triagechain.detection.models import Finding  # noqa: E402
from triagechain.reporting.executive import build_executive_summary  # noqa: E402
from triagechain.reporting.models import ChainStatus, CollectionSummary, DetectionSummary, Report  # noqa: E402
from triagechain.gui_qt import pdf_export  # noqa: E402
import hashlib
from triagechain.config.loader import (
    resolve_capa_manifest_path,
    resolve_chainsaw_manifest_path,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
    resolve_manifest_path,
    resolve_routing_manifest_path,
    resolve_yara_manifest_path,
)
from triagechain.core.errors import ReportingError
from triagechain.custody.ledger import CustodyLedger, read_events
from triagechain.reporting.builder import build_report, write_report
from triagechain.reporting.models import Report
from triagechain.router.models import ProcessedArtifact, RoutingManifest
from triagechain.detection.correlation import CorrelatedArtifact, EngineAgreement
from triagechain.detection.models import Finding
from triagechain.reporting.executive import assess_risk, build_executive_summary
from triagechain.reporting.models import (
    ChainStatus,
    CollectionSummary,
    DetectionSummary,
    Report,
    YaraSummary,
)
from triagechain.collection import catalog as collection_catalog
from triagechain.collection.selector import load_catalog
from triagechain.router import catalog as router_catalog
from triagechain.router.runner import load_routes
from triagechain.core.errors import RouterError
from triagechain.router.runner import run_router
from triagechain.collection.selector import expand_pattern, resolve_targets
from triagechain.detection.models import Finding, YaraMatch
from triagechain.gui_qt import tag_store
from triagechain.gui_qt import theme as t
from triagechain.reporting.timeline import build_timeline
import importlib
import sys
import time
from unittest.mock import MagicMock
from triagechain.core.errors import CollectionError
from triagechain.detection.watchlist_runner import load_watchlist, run_watchlist_check
from triagechain.gui_qt.widgets import MonoLabel  # noqa: E402
from triagechain.collection.winpath import to_long_path
from triagechain.detection.yara_runner import run_yara_scan
from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.collection.models import CollectionManifest
from triagechain.config.loader import (
    load_config,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
)
from triagechain.cli.main import main
from triagechain.custody.ledger import read_events
from triagechain.router.models import RoutingManifest
from triagechain.custody.ledger import CustodyLedger, verify_chain


# ============================================================================
# Kaynak: tests/unit/test_capa_runner.py
# ============================================================================
# capa tarama kosusu: basarili tarama, hata kodu, zaman asimi, atlama ve yol kontrolu.
#
# Hicbir test gercek bir capa ikilisi calistirmaz: subprocess.run her testte
# YAMALANDIGI YERDE (triagechain.detection.capa_runner.subprocess.run)
# unittest.mock ile degistirilir. FAKE_JSON_OUTPUT, gercek capa 9.4.0'in
# gercek bir PE dosyasina (notepad.exe) karsi urettigi --json ciktisinin
# sadelestirilmis ama GERCEK alan yollarini (meta.namespace, meta.attack[].id)
# koruyan bir kopyasidir (bkz. docs/aldigim_kararlar.md -> "capa entegrasyonu").
#



CAPA_RUNNER_CASE_ID = "CASE-TEST-CAPA"

# Gercek capa 9.4.0 ciktisinin (notepad.exe'ye karsi, `-j` ile) sadelestirilmis
# ama GERCEK alan yollarini koruyan bir kopyasi -- bkz. modul dokstring'i.
FAKE_JSON_OUTPUT = {
    "meta": {"sample": {"sha256": "3f5437198a9a9769d8f138a02544f93af8b53ef"}},
    "rules": {
        "link function at runtime on Windows": {
            "meta": {
                "namespace": "linking/runtime-linking",
                "attack": [
                    {
                        "parts": ["Execution", "Shared Modules"],
                        "tactic": "Execution",
                        "technique": "Shared Modules",
                        "subtechnique": "",
                        "id": "T1129",
                    }
                ],
            },
            "matches": [],
        },
        "create or open mutex on Windows": {
            "meta": {"namespace": "host-interaction/mutex", "attack": []},
            "matches": [],
        },
    },
}


def _capa_runner_make_config(tmp_path, capa_path=None, rules_dir=None, timeout=1800):
    return TriageChainConfig(
        case={"case_id": CAPA_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "capa_path": capa_path, "capa_rules_dir": rules_dir, "capa_timeout_seconds": timeout,
        },
    )


def _capa_runner_artifacts_root(config):
    return Path(config.collection.output_dir) / CAPA_RUNNER_CASE_ID / "artifacts"


def _capa_runner_make_artifact(
    config, artifact_type_id="suspicious_binary", filename="sample.exe", dest_path=None
):
    if dest_path is None:
        dest = _capa_runner_artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte pe")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\supheli\{filename}",
        dest_path=dest_path, hash_value="0" * 64, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=CAPA_RUNNER_CASE_ID,
    )


def _capa_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=CAPA_RUNNER_CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _capa_runner_fake_tool(tmp_path, name="capa.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _capa_runner_fake_rules_dir(tmp_path):
    rules = tmp_path / "capa-rules"
    rules.mkdir(parents=True, exist_ok=True)
    return str(rules)


def _capa_runner_configured(tmp_path, **kwargs):
    return _capa_runner_make_config(tmp_path, capa_path=_capa_runner_fake_tool(tmp_path), **kwargs)


def _capa_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CAPA_RUNNER_CASE_ID)


def _capa_runner_completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _writes_stdout(payload):
    """Sahte capa: JSON'u DOGRUDAN stdout'a yazip 0 ile doner (capa'nin -j
    davranisi -- Chainsaw'in -o dosyasindan FARKLI, bkz. capa_args.yaml)."""
    def side_effect(argv, **kwargs):
        return _capa_runner_completed(argv, stdout=json.dumps(payload).encode("utf-8"))
    return side_effect


def _capa_runner_assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_matches_with_real_field_shape(tmp_path):
    config = _capa_runner_configured(tmp_path)
    artifact = _capa_runner_make_artifact(config)
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout(FAKE_JSON_OUTPUT)
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([artifact]), ledger)

    assert len(capa_manifest.matches) == 2
    by_name = {m.rule_name: m for m in capa_manifest.matches}

    with_attack = by_name["link function at runtime on Windows"]
    assert with_attack.tags == "T1129"
    assert with_attack.meta == "namespace=linking/runtime-linking"
    assert with_attack.source_path == str(Path(artifact.dest_path).resolve())

    without_attack = by_name["create or open mutex on Windows"]
    assert without_attack.tags == ""
    assert without_attack.meta == "namespace=host-interaction/mutex"

    assert capa_manifest.errors == [] and capa_manifest.skipped == []

    argv = mock_run.call_args.args[0]
    assert argv[0] == config.detection.capa_path
    assert "-r" not in argv  # capa_rules_dir konfigure edilmemis -- gomulu kurallar kullanilir
    assert mock_run.call_args.kwargs["timeout"] == 1800
    _capa_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["capa_started", "capa_completed_for_artifact", "capa_completed"]
    assert verify_chain(ledger.log_path, CAPA_RUNNER_CASE_ID).is_valid


def test_custom_rules_dir_is_added_to_argv_when_configured(tmp_path):
    config = _capa_runner_configured(tmp_path, rules_dir=_capa_runner_fake_rules_dir(tmp_path))
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    argv = mock_run.call_args.args[0]
    assert "-r" in argv and config.detection.capa_rules_dir in argv


def test_no_matched_rules_is_empty_dict_not_an_error(tmp_path):
    config = _capa_runner_configured(tmp_path)
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    assert capa_manifest.matches == [] and capa_manifest.errors == []
    assert capa_manifest.scanned[0]["match_count"] == 0


def test_capa_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _capa_runner_configured(tmp_path)
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout(FAKE_JSON_OUTPUT)
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CAPA_RUNNER_CASE_ID / "capa_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "capa_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["capa_manifest_sha256"] == expected

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == capa_manifest.run_id
    assert len(reloaded.matches) == 2


def test_capa_runner_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _capa_runner_configured(tmp_path)
    failing = _capa_runner_make_artifact(config, filename="bad.exe")
    ok = _capa_runner_make_artifact(config, filename="good.exe")
    ledger = _capa_runner_ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if any("bad.exe" in part for part in argv):
            return _capa_runner_completed(argv, returncode=16, stderr=b"desteklenmeyen dosya bicimi")
        return _writes_stdout({"meta": {}, "rules": {}})(argv, **kwargs)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([failing, ok]), ledger)

    assert len(capa_manifest.errors) == 1
    assert capa_manifest.errors[0]["exit_code"] == 16
    assert capa_manifest.errors[0]["stderr_excerpt"] == "desteklenmeyen dosya bicimi"
    assert [Path(s["source_path"]).name for s in capa_manifest.scanned] == ["good.exe"]
    _capa_runner_assert_never_uses_shell(mock_run)


def test_capa_runner_timeout_is_a_non_fatal_error(tmp_path):
    config = _capa_runner_configured(tmp_path, timeout=5)
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["capa.exe"], timeout=5)
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    assert capa_manifest.scanned == [] and capa_manifest.matches == []
    assert len(capa_manifest.errors) == 1
    assert "5 saniyede bitmedi" in capa_manifest.errors[0]["message"]
    assert verify_chain(ledger.log_path, CAPA_RUNNER_CASE_ID).is_valid


def test_capa_runner_tool_not_configured_is_skipped(tmp_path):
    config = _capa_runner_make_config(tmp_path)
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "konfigure edilmemis" in capa_manifest.skipped[0]["message"]


def test_missing_rules_dir_is_skipped_even_though_it_is_optional(tmp_path):
    """capa_rules_dir SADECE ayarlandiginda kontrol edilir -- ayarlanip da
    diskte bulunamazsa (yanlis yazilmis bir yol) sessizce yok sayilmaz."""
    config = _capa_runner_configured(tmp_path, rules_dir=str(tmp_path / "olmayan-klasor"))
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([_capa_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural klasoru bulunamadi" in capa_manifest.skipped[0]["message"]


def test_capa_runner_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _capa_runner_configured(tmp_path)
    outside = tmp_path / "disari" / "sample.exe"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _capa_runner_make_artifact(config, dest_path=str(outside))
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _capa_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert "cikti agaci disinda" in capa_manifest.errors[0]["message"]


def test_cli_capa_scan_without_manifest_exits_with_code_2(tmp_path):
    """'capa-scan' da 'detect'/'yara-scan' ile ayni kural: once 'collect' calismali."""
    import yaml

    from triagechain.cli.main import main

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    data = {
        "case": {"case_id": CAPA_RUNNER_CASE_ID, "operator": "test.operator"},
        "collection": {
            "targets": ["event_logs"], "hash_algorithm": "sha256", "output_dir": str(output_dir),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    exit_code = main(["capa-scan", "--config", str(config_path)])

    assert exit_code == 2


def test_only_suspicious_binaries_are_scanned(tmp_path):
    """Hayabusa/Chainsaw'in 'sadece event_logs' kisitiyla ayni ilke: capa da
    SADECE analistin elle gosterdigi supheli dosyalari tarar."""
    config = _capa_runner_configured(tmp_path)
    binary = _capa_runner_make_artifact(config, artifact_type_id="suspicious_binary", filename="sample.exe")
    prefetch = _capa_runner_make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    ledger = _capa_runner_ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        run_capa_scan(config, _capa_runner_make_manifest([binary, prefetch]), ledger)

    assert mock_run.call_count == 1


# ============================================================================
# Kaynak: tests/unit/test_case_note_store.py
# ============================================================================
# gui_qt/case_note_store.py'nin testleri -- Qt gerektirmez.



def test_load_case_note_dosya_yoksa_none_doner(tmp_path):
    assert case_note_store.load_case_note(tmp_path / "yok.json") is None


def test_save_ve_load_round_trip(tmp_path):
    path = tmp_path / "case_note.json"
    saved = case_note_store.save_case_note(path, "Şüpheli IP: 10.0.0.5, takip edilecek.", "yasar")

    assert saved.text == "Şüpheli IP: 10.0.0.5, takip edilecek."
    assert saved.updated_by == "yasar"
    assert saved.updated_at_utc

    loaded = case_note_store.load_case_note(path)
    assert loaded is not None
    assert loaded.text == saved.text
    assert loaded.updated_by == "yasar"


def test_save_var_olan_notun_ustune_yazar(tmp_path):
    path = tmp_path / "case_note.json"
    case_note_store.save_case_note(path, "ilk not", "yasar")
    case_note_store.save_case_note(path, "güncellenmiş not", "yasar")

    loaded = case_note_store.load_case_note(path)
    assert loaded.text == "güncellenmiş not"


def test_load_case_note_bos_metin_none_doner(tmp_path):
    path = tmp_path / "case_note.json"
    case_note_store.save_case_note(path, "", "yasar")

    assert case_note_store.load_case_note(path) is None


def test_load_case_note_bozuk_dosyada_patlamiyor_none_doner(tmp_path):
    path = tmp_path / "case_note.json"
    path.write_text("gecerli json degil {{{", encoding="utf-8")

    assert case_note_store.load_case_note(path) is None


# ============================================================================
# Kaynak: tests/unit/test_case_wizard.py
# ============================================================================
# Yeni Vaka sihirbazinin (case_wizard.py) ekransiz testleri.
#
# test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen, gercek pencere
# acilmaz. Dosya/klasor secim diyaloglari (QFileDialog) hicbir testte
# TETIKLENMEZ -- diyalog sonrasi cagirilacak ic metotlar (_set_source_root,
# _on_create) dogrudan cagrilir, boylece testler headless CI'da da calisir.
#






pytest.importorskip("PySide6")





@pytest.fixture(scope="session")
def case_wizard_qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def dialog(case_wizard_qt_app):
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

def test_extraction_arka_planda_calisir_ve_kaynak_kokunu_ayarlar(dialog, tmp_path, case_wizard_qt_app):
    source_zip = tmp_path / "kaynak.zip"
    _make_zip(source_zip, {"C/marker.txt": "veri"})
    dest = tmp_path / "hedef"

    dialog._start_extraction(source_zip, dest)

    assert dialog._pick_folder_btn.isEnabled() is False
    assert dialog._pick_archive_btn.isEnabled() is False
    assert dialog.create_btn.isEnabled() is False
    assert not dialog.extraction_progress.isHidden()

    assert dialog._extraction_worker.wait(5000)
    case_wizard_qt_app.processEvents()

    assert dialog._extraction_worker is None
    assert dialog._pick_folder_btn.isEnabled() is True
    assert dialog.create_btn.isEnabled() is True
    assert dialog.extraction_progress.isHidden()
    assert dialog._source_root == dest
    assert (dest / "C" / "marker.txt").read_text(encoding="utf-8") == "veri"


def test_extraction_hata_verirse_kontroller_geri_acilir(dialog, tmp_path, case_wizard_qt_app, monkeypatch):
    monkeypatch.setattr(case_wizard, "find_seven_zip", lambda: None)
    bozuk = tmp_path / "bozuk.zip"
    bozuk.write_bytes(b"gecersiz zip icerigi")
    dest = tmp_path / "hedef"

    dialog._start_extraction(bozuk, dest)
    assert dialog._extraction_worker.wait(5000)
    case_wizard_qt_app.processEvents()

    assert dialog._extraction_worker is None
    assert not dialog.error_label.isHidden()
    assert dialog._pick_folder_btn.isEnabled() is True
    assert dialog._source_root is None


def test_extraction_surerken_dialog_kapatilamaz(dialog, tmp_path, case_wizard_qt_app):
    source_zip = tmp_path / "kaynak.zip"
    _make_zip(source_zip, {"C/marker.txt": "veri"})
    dest = tmp_path / "hedef"
    dialog._start_extraction(source_zip, dest)

    rejected_calls = []
    dialog.rejected.connect(lambda: rejected_calls.append(True))
    dialog.reject()
    assert rejected_calls == []

    assert dialog._extraction_worker.wait(5000)
    case_wizard_qt_app.processEvents()

    dialog.reject()
    assert rejected_calls == [True]


def test_ic_ice_zipli_gercek_senaryo_arka_planda_toplu_moda_gecer(dialog, tmp_path, case_wizard_qt_app):
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
    case_wizard_qt_app.processEvents()

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


# ============================================================================
# Kaynak: tests/unit/test_chainsaw_runner.py
# ============================================================================
# Chainsaw tarama kosusu: basarili tarama, hata kodu, zaman asimi, atlama
# ve yol kontrolu.
#
# Hicbir test gercek bir Chainsaw ikilisi calistirmaz: subprocess.run her
# testte YAMALANDIGI YERDE (triagechain.detection.chainsaw_runner.subprocess.run)
# unittest.mock ile degistirilir. FAKE_JSON, gercek chainsaw 2.16.5'in GERCEK
# SigmaHQ kurallariyla GERCEK bir EVTX-ATTACK-SAMPLES dosyasina karsi urettigi
# ciktinin BIREBIR bicimidir (bkz. docs/aldigim_kararlar.md) -- alan adlari
# (document.data.Event.System.*, tags) uydurulmadi.
#




CHAINSAW_RUNNER_CASE_ID = "CASE-TEST-CHAINSAW"

# Gercek chainsaw 2.16.5 ciktisinin (bir olay icin) sadelestirilmis ama
# GERCEK alan yollarini koruyan bir kopyasi.
FAKE_JSON_RECORD = {
    "group": "Sigma",
    "document": {
        "path": "placeholder",
        "data": {
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "MSEDGEWIN10",
                }
            }
        },
    },
    "name": "Potentially Suspicious Execution From Parent Process In Public Folder",
    "timestamp": "2020-10-23T21:57:36.014784+00:00",
    "level": "high",
    "tags": ["attack.execution", "attack.stealth", "attack.t1564", "attack.t1059"],
}


def _chainsaw_runner_make_config(tmp_path, chainsaw_path=None, rules_dir=None, mapping_file=None, timeout=600):
    return TriageChainConfig(
        case={"case_id": CHAINSAW_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "chainsaw_path": chainsaw_path, "rules_dir": rules_dir,
            "chainsaw_mapping_file": mapping_file, "chainsaw_timeout_seconds": timeout,
        },
    )


def _chainsaw_runner_artifacts_root(config):
    return Path(config.collection.output_dir) / CHAINSAW_RUNNER_CASE_ID / "artifacts"


def _chainsaw_runner_make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    if dest_path is None:
        dest = _chainsaw_runner_artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte evtx")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\kaynak\{filename}",
        dest_path=dest_path, hash_value="0" * 64, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=CHAINSAW_RUNNER_CASE_ID,
    )


def _chainsaw_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=CHAINSAW_RUNNER_CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _chainsaw_runner_fake_tool(tmp_path, name="chainsaw.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _chainsaw_runner_fake_rules_dir(tmp_path):
    rules = tmp_path / "sigma"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "ornek.yml").write_text("title: ornek", encoding="utf-8")
    return str(rules)


def _fake_mapping(tmp_path):
    mapping = tmp_path / "mapping.yml"
    mapping.write_text("name: sahte esleme", encoding="utf-8")
    return str(mapping)


def _chainsaw_runner_configured(tmp_path, **kwargs):
    return _chainsaw_runner_make_config(
        tmp_path, chainsaw_path=_chainsaw_runner_fake_tool(tmp_path), rules_dir=_chainsaw_runner_fake_rules_dir(tmp_path),
        mapping_file=_fake_mapping(tmp_path), **kwargs,
    )


def _chainsaw_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CHAINSAW_RUNNER_CASE_ID)


def _chainsaw_runner_completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _writes_json(records):
    """Sahte Chainsaw: -o ile verilen yola bir JSON listesi yazip 0 ile doner."""
    def side_effect(argv, **kwargs):
        out_path = Path(argv[argv.index("-o") + 1])
        out_path.write_text(json.dumps(records), encoding="utf-8")
        return _chainsaw_runner_completed(argv, stdout=b"[+] 1 Detections found\n")
    return side_effect


def _chainsaw_runner_assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_findings_with_real_field_shape(tmp_path):
    config = _chainsaw_runner_configured(tmp_path)
    artifact = _chainsaw_runner_make_artifact(config)
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([FAKE_JSON_RECORD])
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([artifact]), ledger)

    assert len(detection.findings) == 1
    f = detection.findings[0]
    assert f.rule_title == FAKE_JSON_RECORD["name"]
    assert f.level == "high"
    assert f.timestamp == FAKE_JSON_RECORD["timestamp"]
    assert f.computer == "MSEDGEWIN10"
    assert f.channel == "Microsoft-Windows-Sysmon/Operational"
    assert f.event_id == "1"
    assert f.mitre_tags == "attack.execution,attack.stealth,attack.t1564,attack.t1059"
    assert f.source_path == str(Path(artifact.dest_path).resolve())
    assert detection.errors == [] and detection.skipped == []

    argv = mock_run.call_args.args[0]
    assert argv[0] == config.detection.chainsaw_path
    assert "--sigma" in argv and config.detection.rules_dir in argv
    assert "--mapping" in argv and config.detection.chainsaw_mapping_file in argv
    assert mock_run.call_args.kwargs["timeout"] == 600
    _chainsaw_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["chainsaw_started", "chainsaw_completed_for_artifact", "chainsaw_completed"]
    assert verify_chain(ledger.log_path, CHAINSAW_RUNNER_CASE_ID).is_valid


def test_no_findings_is_empty_json_list_not_an_error(tmp_path):
    config = _chainsaw_runner_configured(tmp_path)
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([])
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([_chainsaw_runner_make_artifact(config)]), ledger)

    assert detection.findings == [] and detection.errors == []
    assert detection.scanned[0]["finding_count"] == 0


def test_chainsaw_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _chainsaw_runner_configured(tmp_path)
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([FAKE_JSON_RECORD])
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([_chainsaw_runner_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CHAINSAW_RUNNER_CASE_ID / "chainsaw_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "chainsaw_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["chainsaw_manifest_sha256"] == expected

    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 1


def test_chainsaw_runner_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _chainsaw_runner_configured(tmp_path)
    failing = _chainsaw_runner_make_artifact(config, filename="Bad.evtx")
    ok = _chainsaw_runner_make_artifact(config, filename="Good.evtx")
    ledger = _chainsaw_runner_ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if any("Bad.evtx" in part for part in argv):
            return _chainsaw_runner_completed(argv, returncode=1, stderr=b"kural yuklenemedi")
        return _writes_json([])(argv, **kwargs)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([failing, ok]), ledger)

    assert len(detection.errors) == 1
    assert detection.errors[0]["exit_code"] == 1
    assert detection.errors[0]["stderr_excerpt"] == "kural yuklenemedi"
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    _chainsaw_runner_assert_never_uses_shell(mock_run)


def test_chainsaw_runner_timeout_is_a_non_fatal_error(tmp_path):
    config = _chainsaw_runner_configured(tmp_path, timeout=5)
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["chainsaw.exe"], timeout=5)
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([_chainsaw_runner_make_artifact(config)]), ledger)

    assert detection.scanned == [] and detection.findings == []
    assert len(detection.errors) == 1
    assert "5 saniyede bitmedi" in detection.errors[0]["message"]
    assert verify_chain(ledger.log_path, CHAINSAW_RUNNER_CASE_ID).is_valid


def test_chainsaw_runner_tool_not_configured_is_skipped(tmp_path):
    config = _chainsaw_runner_make_config(tmp_path)
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([_chainsaw_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "konfigure edilmemis" in detection.skipped[0]["message"]


def test_mapping_file_not_configured_is_skipped(tmp_path):
    config = _chainsaw_runner_make_config(
        tmp_path, chainsaw_path=_chainsaw_runner_fake_tool(tmp_path), rules_dir=_chainsaw_runner_fake_rules_dir(tmp_path),
    )
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([_chainsaw_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "esleme dosyasi konfigure edilmemis" in detection.skipped[0]["message"]


def test_chainsaw_runner_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _chainsaw_runner_configured(tmp_path)
    outside = tmp_path / "disari" / "Security.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _chainsaw_runner_make_artifact(config, dest_path=str(outside))
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _chainsaw_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert "cikti agaci disinda" in detection.errors[0]["message"]


def test_only_event_logs_are_scanned(tmp_path):
    """Hayabusa ile ayni kisit: sadece event_logs taranir."""
    config = _chainsaw_runner_configured(tmp_path)
    evtx = _chainsaw_runner_make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx")
    prefetch = _chainsaw_runner_make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    ledger = _chainsaw_runner_ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([])
        run_chainsaw_detection(config, _chainsaw_runner_make_manifest([evtx, prefetch]), ledger)

    assert mock_run.call_count == 1


# ============================================================================
# Kaynak: tests/unit/test_config_loader.py
# ============================================================================
# Konfigurasyon yukleyicisi: gecerli dosya, bilinmeyen hedef, kotu vaka kimligi.




CONFIG_LOADER_FIXTURES = Path(__file__).resolve().parents[0] / "fixtures"


def _write_config(tmp_path, **overrides):
    """Ornek konfigurasyonu gecici dizine, istenen degisikliklerle yazar."""
    data = yaml.safe_load((CONFIG_LOADER_FIXTURES / "sample_config.yaml").read_text(encoding="utf-8"))
    data["collection"]["output_dir"] = str(tmp_path / "output")
    for section, values in overrides.items():
        data[section].update(values)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return config_path


def test_valid_config_parses(tmp_path):
    config = load_config(_write_config(tmp_path))

    assert config.case.case_id == "CASE-TEST-001"
    assert config.case.operator == "test.operator"
    assert config.collection.targets == ["event_logs", "prefetch"]
    assert config.collection.hash_algorithm == "sha256"
    assert config.logging.level == "INFO"
    # Cikti dizini yoksa yukleyici tarafindan olusturulur.
    assert Path(config.collection.output_dir).is_dir()


def test_custody_log_path_is_derived_when_null(tmp_path):
    config = load_config(_write_config(tmp_path))
    expected = Path(config.collection.output_dir) / "CASE-TEST-001" / "custody.jsonl"

    assert resolve_custody_log_path(config) == expected


def test_config_loader_unknown_target_id_raises_config_error(tmp_path):
    config_path = _write_config(tmp_path, collection={"targets": ["event_logs", "hayali_hedef"]})

    with pytest.raises(ConfigError) as exc_info:
        load_config(config_path)
    assert "hayali_hedef" in str(exc_info.value)


def test_unsafe_case_id_raises_config_error(tmp_path):
    config_path = _write_config(tmp_path, case={"case_id": "../kacis"})

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_missing_output_dir_parent_raises_config_error(tmp_path):
    config_path = _write_config(
        tmp_path, collection={"output_dir": str(tmp_path / "olmayan" / "output")}
    )

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "yok.yaml")


# ============================================================================
# Kaynak: tests/unit/test_correlation.py
# ============================================================================
# Sigma/Hayabusa ve YARA ciktilarinin korelasyonu: sadece kume kesisimi,
# hicbir puanlama yok -- bkz. detection/correlation.py.



CORRELATION_NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _correlation_finding(source_path, rule_title="Kural"):
    return Finding(
        artifact_type_id="event_logs", source_path=source_path, rule_title=rule_title,
        level="high", timestamp="2026-06-07 22:00:00", computer="WS-01", channel="Security",
        event_id="4688", details="",
    )


def _match(source_path, rule_name="YaraKural"):
    return YaraMatch(artifact_type_id="event_logs", source_path=source_path, rule_name=rule_name)


def _correlation_detection(findings):
    return DetectionManifest(case_id="CASE-X", started_at_utc=CORRELATION_NOW, findings=list(findings))


def _yara(matches):
    return YaraManifest(case_id="CASE-X", started_at_utc=CORRELATION_NOW, matches=list(matches))


def test_ayni_dosyayi_isaretleyen_iki_motor_korele_edilir():
    detection = _correlation_detection([_correlation_finding("C:/a.evtx", "Suspicious PowerShell")])
    yara = _yara([_match("C:/a.evtx", "Mimikatz_Strings")])

    result = correlate_findings(detection, yara)

    assert len(result) == 1
    assert result[0].source_path == "C:/a.evtx"
    assert result[0].sigma_rule_titles == ["Suspicious PowerShell"]
    assert result[0].yara_rule_names == ["Mimikatz_Strings"]


def test_sadece_bir_motorun_isaretledigi_dosya_korele_EDILMEZ():
    """Sadece Sigma ya da sadece YARA bulmus dosyalar kesisimde olmamali --
    korelasyon sadece IKI motorun da ayni dosyada anlastigi durumu gosterir."""
    detection = _correlation_detection([_correlation_finding("C:/only-sigma.evtx")])
    yara = _yara([_match("C:/only-yara.evtx")])

    assert correlate_findings(detection, yara) == []


def test_ayni_dosyada_birden_fazla_kural_hepsi_listelenir():
    detection = _correlation_detection([_correlation_finding("C:/a.evtx", "Kural1"), _correlation_finding("C:/a.evtx", "Kural2")])
    yara = _yara([_match("C:/a.evtx", "YaraKural1")])

    result = correlate_findings(detection, yara)

    assert result[0].sigma_rule_titles == ["Kural1", "Kural2"]
    assert result[0].yara_rule_names == ["YaraKural1"]


def test_bos_manifestler_bos_liste_dondurur():
    assert correlate_findings(_correlation_detection([]), _yara([])) == []


def test_iki_sigma_motoru_ayni_kurali_ayni_dosyada_bulursa_ittifak():
    """Hayabusa ve Chainsaw AYNI kural setini kullandigi icin rule_title
    esitligi capraz dogrulama sayilir (bkz. correlate_sigma_engines)."""
    hayabusa = _correlation_detection([_correlation_finding("C:/a.evtx", "Suspicious PowerShell")])
    chainsaw = _correlation_detection([_correlation_finding("C:/a.evtx", "Suspicious PowerShell")])

    result = correlate_sigma_engines(hayabusa, chainsaw)

    assert len(result) == 1
    assert result[0].source_path == "C:/a.evtx"
    assert result[0].rule_title == "Suspicious PowerShell"


def test_farkli_kural_adlari_ittifak_SAYILMAZ():
    """Ayni dosyada ama FARKLI kurallar eslesirse -- iki motor ayni SEYI
    dogrulamamis demektir, ittifak olmamali."""
    hayabusa = _correlation_detection([_correlation_finding("C:/a.evtx", "Kural A")])
    chainsaw = _correlation_detection([_correlation_finding("C:/a.evtx", "Kural B")])

    assert correlate_sigma_engines(hayabusa, chainsaw) == []


def test_sonuc_source_path_sirasina_gore_deterministik():
    detection = _correlation_detection([_correlation_finding("C:/z.evtx"), _correlation_finding("C:/a.evtx")])
    yara = _yara([_match("C:/z.evtx"), _match("C:/a.evtx")])

    result = correlate_findings(detection, yara)

    assert [r.source_path for r in result] == ["C:/a.evtx", "C:/z.evtx"]


# ============================================================================
# Kaynak: tests/unit/test_csv_export.py
# ============================================================================
# gui_qt/csv_export.py'nin testleri -- Qt gerektirmez.




def test_write_rows_csv_dosyayi_uretir_ve_basligi_yazar(tmp_path):
    path = tmp_path / "cikti.csv"
    csv_export.write_rows_csv(path, ["A", "B"], [["1", "2"], ["3", "4"]])

    assert path.is_file()
    with path.open(encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert rows == [["A", "B"], ["1", "2"], ["3", "4"]]


def test_write_rows_csv_turkce_karakterler_bom_ile_dogru_okunuyor(tmp_path):
    path = tmp_path / "turkce.csv"
    csv_export.write_rows_csv(path, ["BULGU"], [["Şüpheli Oturum Açma İşlemi"]])

    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM -- Excel uyumlulugu

    with path.open(encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert rows[1][0] == "Şüpheli Oturum Açma İşlemi"


def test_write_rows_csv_alt_klasoru_olusturur(tmp_path):
    path = tmp_path / "alt" / "klasor" / "cikti.csv"
    csv_export.write_rows_csv(path, ["A"], [["1"]])
    assert path.is_file()


def test_write_rows_csv_bos_satir_listesi_sadece_baslik_yazar(tmp_path):
    path = tmp_path / "bos.csv"
    csv_export.write_rows_csv(path, ["A", "B"], [])

    with path.open(encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    assert rows == [["A", "B"]]


# ============================================================================
# Kaynak: tests/unit/test_custody_ledger.py
# ============================================================================
# Custody defteri: zincir kurulumu, dogrulama ve kurcalama tespiti.




CUSTODY_LEDGER_CASE_ID = "CASE-TEST-001"


def _ledger_with_three_events(tmp_path):
    log_path = tmp_path / "custody.jsonl"
    ledger = CustodyLedger(log_path, CUSTODY_LEDGER_CASE_ID)
    ledger.append_event("case_opened", "test.operator", {"run_id": "r1"})
    ledger.append_event("artifact_collected", "test.operator", {"artifact_type_id": "demo"})
    ledger.append_event("case_closed", "test.operator", {"artifact_count": 1})
    return log_path, ledger


def test_chain_is_valid_after_three_appends(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)

    result = verify_chain(log_path, CUSTODY_LEDGER_CASE_ID)
    assert result.is_valid
    assert result.total_events == 3
    assert result.broken_at_event_id is None


def test_first_event_links_to_genesis_and_chain_is_linked(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)
    events = list(read_events(log_path))

    assert events[0].prev_hash == genesis_hash(CUSTODY_LEDGER_CASE_ID)
    assert events[1].prev_hash == events[0].entry_hash
    assert events[2].prev_hash == events[1].entry_hash
    # tsa_token her olayda var ve su an null.
    assert all(event.payload["tsa_token"] is None for event in events)


def test_tampered_line_is_detected_and_located(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)
    events = list(read_events(log_path))
    tampered_event_id = events[1].event_id

    # Ikinci satirin payload'ini diskte dogrudan degistiriyoruz (entry_hash aynen kaliyor).
    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["artifact_type_id"] = "sahte_artefakt"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(log_path, CUSTODY_LEDGER_CASE_ID)
    assert not result.is_valid
    assert result.broken_at_event_id == tampered_event_id
    assert "entry_hash" in result.message


def test_wrong_case_id_is_rejected(tmp_path):
    log_path, _ = _ledger_with_three_events(tmp_path)

    result = verify_chain(log_path, "CASE-BASKA-VAKA")
    assert not result.is_valid
    assert result.total_events == 1


def test_missing_log_raises_custody_error(tmp_path):
    with pytest.raises(CustodyLedgerError):
        verify_chain(tmp_path / "yok.jsonl", CUSTODY_LEDGER_CASE_ID)


def test_concurrent_writers_do_not_fork_the_chain(tmp_path):
    """Birden fazla 'surec' (burada: thread + AYRI CustodyLedger ornekleri,
    ayni dosyaya yazan gercek isletim sistemi kilidini test eder) ayni deftere
    ayni anda yazarsa zincir CATALLAMAMALI -- bkz. storage.locked() dokstring'i.

    Kilit olmadan bu test guvenilir sekilde basarisiz olurdu: iki thread ayni
    prev_hash'i okuyup ekleyebilir, verify_chain sonraki olayda kirilma
    bildirir. Her thread KENDI CustodyLedger'ini kullaniyor (gercek ayri
    surecleri simule etmek icin - paylasilan bir Python nesnesi/kilidi degil,
    dosya sistemi seviyesindeki kilit test ediliyor)."""
    log_path = tmp_path / "custody.jsonl"
    writer_count = 8
    events_per_writer = 10
    errors: list[Exception] = []

    def write_many(writer_index: int) -> None:
        ledger = CustodyLedger(log_path, CUSTODY_LEDGER_CASE_ID)
        try:
            for i in range(events_per_writer):
                ledger.append_event(
                    "artifact_collected", "test.operator",
                    {"writer": writer_index, "seq": i},
                )
        except Exception as exc:  # noqa: BLE001 - ana thread'de degerlendirilecek
            errors.append(exc)

    threads = [
        threading.Thread(target=write_many, args=(i,)) for i in range(writer_count)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    result = verify_chain(log_path, CUSTODY_LEDGER_CASE_ID)
    assert result.is_valid, result.message
    assert result.total_events == writer_count * events_per_writer


# ============================================================================
# Kaynak: tests/unit/test_detection_mapping.py
# ============================================================================
# Hayabusa cagri sablonu katalogu: yer tutucular ve CSV sutun eslemesi tutarli mi.


# Bir bulguyu (Finding) anlamli kilan, eslemede karsiligi bulunmasi ZORUNLU
# alanlar. Katalogdan biri dususe test kirilir.
REQUIRED_COLUMNS = {"timestamp", "rule_title", "level", "computer", "channel", "event_id"}


def test_arg_template_uses_all_placeholders():
    profile = load_profile(detection_catalog.default_catalog_path())
    joined = " ".join(profile.args)

    assert "{input}" in joined, "girdi yer tutucusu yok"
    assert "{rules_dir}" in joined, "kural klasoru yer tutucusu yok"
    assert "{output_csv}" in joined, "cikti yer tutucusu yok"
    # Sablonda calistirilabilirin kendisi durmaz; argv'nin basina kosu ekler.
    assert not any(arg.lower().endswith(".exe") for arg in profile.args)


def test_output_filename_is_derived_from_the_scanned_file():
    profile = load_profile(detection_catalog.default_catalog_path())

    # Ayni klasore yazilan ciktilar birbirinin ustune binmemeli.
    assert "{stem}" in profile.output_filename
    assert profile.output_filename.format(stem="Security.evtx").endswith(".csv")


def test_every_required_finding_field_has_column_candidates():
    profile = load_profile(detection_catalog.default_catalog_path())

    assert REQUIRED_COLUMNS <= set(profile.csv_columns)
    for field_name, candidates in profile.csv_columns.items():
        assert candidates, f"{field_name}: aday baslik listesi bos"


def test_scanned_artifact_type_matches_the_collection_catalog():
    # Taranan tip, toplama katalogundaki olay gunlugu hedefiyle ayni kimlik olmali;
    # yoksa tespit katmani hicbir dosya bulamaz.
    from triagechain.collection import catalog as collection_catalog
    from triagechain.collection.selector import load_catalog

    assert SCANNED_ARTIFACT_TYPE in load_catalog(collection_catalog.default_catalog_path())


# ============================================================================
# Kaynak: tests/unit/test_detection_runner.py
# ============================================================================
# Tespit kosusu: basarili tarama, hata kodu, zaman asimi, atlama ve yol kontrolu.
#
# Hicbir test gercek bir Hayabusa ikilisi calistirmaz: subprocess.run her testte
# YAMALANDIGI YERDE (triagechain.detection.runner.subprocess.run) unittest.mock
# ile degistirilir.
#




DETECTION_RUNNER_CASE_ID = "CASE-TEST-DETECT"

# Hayabusa'nin uretmesi beklenen CSV'nin sahtesi (basliklar hayabusa_args.yaml
# icindeki adaylarla eslesir).
DETECTION_RUNNER_FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Suspicious PowerShell,high,WS-01,Security,4104,Encoded komut\n"
    "2026-01-02 03:05:00.000 +03:00,Failed Logon,low,WS-01,Security,4625,Yanlis parola\n"
)


def _detection_runner_make_config(tmp_path, hayabusa_path=None, rules_dir=None, timeout_seconds=600):
    """Tespit icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": DETECTION_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "hayabusa_path": hayabusa_path,
            "rules_dir": rules_dir,
            "timeout_seconds": timeout_seconds,
        },
    )


def _detection_runner_artifacts_root(config):
    return Path(config.collection.output_dir) / DETECTION_RUNNER_CASE_ID / "artifacts"


def _detection_runner_make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    """Cikti agacinda gercek bir dosya olusturur ve manifest kaydini dondurur.

    dest_path verilirse dosya olusturulmaz; bu, agac disi yol testinde kullaniliyor.
    """
    if dest_path is None:
        dest = _detection_runner_artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte evtx")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id,
        source_path=rf"C:\Windows\System32\winevt\Logs\{filename}",
        dest_path=dest_path,
        hash_value="0" * 64,
        hash_algorithm="sha256",
        size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc),
        collecting_user="test.operator",
        case_id=DETECTION_RUNNER_CASE_ID,
    )


def _detection_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=DETECTION_RUNNER_CASE_ID,
        started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc),
        artifacts=list(artifacts),
    )


def _detection_runner_fake_tool(tmp_path, name="hayabusa.exe"):
    """Diskte gercekten var olan, mutlak yollu sahte bir arac dosyasi."""
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules(tmp_path):
    """Diskte var olan sahte bir Sigma kural klasoru."""
    rules = tmp_path / "sigma" / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "ornek.yml").write_text("title: ornek", encoding="utf-8")
    return str(rules)


def _detection_runner_configured(tmp_path, **kwargs):
    """Hem arac hem kural klasoru gercekten var olan konfigurasyon."""
    return _detection_runner_make_config(
        tmp_path, hayabusa_path=_detection_runner_fake_tool(tmp_path), rules_dir=_fake_rules(tmp_path), **kwargs
    )


def _detection_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", DETECTION_RUNNER_CASE_ID)


def _detection_runner_completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _writes_csv(content=DETECTION_RUNNER_FAKE_CSV):
    """Sahte Hayabusa: -o ile verilen yola bir CSV yazip 0 ile doner."""
    def side_effect(argv, **kwargs):
        Path(argv[argv.index("-o") + 1]).write_text(content, encoding="utf-8")
        return _detection_runner_completed(argv, stdout=b"tarama bitti\n")
    return side_effect


def _detection_runner_assert_never_uses_shell(mock_run):
    """Guvenlik kurali #1: hicbir cagri shell=True ile yapilmamali."""
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        # Ilk konumsal arguman her zaman arguman LISTESI olmali, tek metin degil.
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_findings_and_one_summary_event(tmp_path):
    config = _detection_runner_configured(tmp_path)
    artifact = _detection_runner_make_artifact(config)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _detection_runner_make_manifest([artifact]), ledger)

    assert len(detection.findings) == 2
    assert detection.errors == [] and detection.skipped == []
    assert detection.findings[0].rule_title == "Suspicious PowerShell"
    assert detection.findings[0].level == "high"
    assert detection.findings[0].event_id == "4104"
    assert detection.findings[0].source_path == str(Path(artifact.dest_path).resolve())

    # Dosya basina TEK ozet kayit: bulgu sayisi + seviye dagilimi.
    assert len(detection.scanned) == 1
    scanned = detection.scanned[0]
    assert scanned["finding_count"] == 2
    assert scanned["level_counts"] == {"high": 1, "low": 1}
    assert Path(scanned["output_csv_path"]).is_file()
    assert Path(scanned["stdout_log_path"]).read_text(encoding="utf-8") == "tarama bitti\n"

    # argv sablonu dogru dolduruldu mu?
    argv = mock_run.call_args.args[0]
    assert argv[0] == config.detection.hayabusa_path
    assert argv[argv.index("-f") + 1] == str(Path(artifact.dest_path).resolve())
    assert argv[argv.index("-r") + 1] == config.detection.rules_dir
    assert mock_run.call_args.kwargs["timeout"] == 600
    _detection_runner_assert_never_uses_shell(mock_run)

    # Custody: bulgu basina degil, dosya basina tek olay.
    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == [
        "detection_started", "detection_completed_for_artifact", "detection_completed",
    ]
    assert verify_chain(ledger.log_path, DETECTION_RUNNER_CASE_ID).is_valid


def test_mitre_attack_tags_are_surfaced_when_hayabusa_provides_them(tmp_path):
    """MitreTactics sutunu Hayabusa ciktisinda VARSA Finding.mitre_tags'e
    yansimali; bu yeni bir veri kaynagi degil, Sigma kuralinin kendi
    metadatasi -- sutun yoksa (DETECTION_RUNNER_FAKE_CSV'deki gibi) bos kalir, bu test o
    bos-kalma davranisini da dogas geregi kapsiyor (bkz. yukaridaki test)."""
    csv_with_mitre = (
        "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details,MitreTactics\n"
        "2026-01-02 03:04:05.678 +03:00,Suspicious PowerShell,high,WS-01,Security,"
        '4104,Encoded komut,"attack.t1059.001,attack.execution"\n'
    )
    config = _detection_runner_configured(tmp_path)
    artifact = _detection_runner_make_artifact(config)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv(csv_with_mitre)
        detection = run_detection(config, _detection_runner_make_manifest([artifact]), ledger)

    assert detection.findings[0].mitre_tags == "attack.t1059.001,attack.execution"


def test_mitre_attack_tags_are_empty_when_hayabusa_omits_them(tmp_path):
    """MitreTactics sutunu YOKSA (DETECTION_RUNNER_FAKE_CSV) alan bos kalmali, uydurulmamali."""
    config = _detection_runner_configured(tmp_path)
    artifact = _detection_runner_make_artifact(config)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _detection_runner_make_manifest([artifact]), ledger)

    assert detection.findings[0].mitre_tags == ""


def test_detection_manifest_is_written_and_its_hash_recorded(tmp_path):
    """Kapanis olayi, diske yazilan manifestin sha256'sini tasimali."""
    import hashlib

    config = _detection_runner_configured(tmp_path)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / DETECTION_RUNNER_CASE_ID / "detection_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "detection_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["detection_manifest_sha256"] == expected
    assert closing.payload["finding_count"] == 2

    # Manifest diskten geri okunabilmeli.
    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 2
    assert reloaded.ended_at_utc is not None


def test_detection_runner_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _detection_runner_configured(tmp_path)
    failing = _detection_runner_make_artifact(config, filename="Bad.evtx")
    ok = _detection_runner_make_artifact(config, filename="Good.evtx")
    ledger = _detection_runner_ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if "Bad.evtx" in argv[argv.index("-f") + 1]:
            return _detection_runner_completed(argv, returncode=3, stderr=b"kural yuklenemedi")
        return _writes_csv()(argv, **kwargs)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        # Hicbir istisna yukari sizmamali.
        detection = run_detection(config, _detection_runner_make_manifest([failing, ok]), ledger)

    assert len(detection.errors) == 1
    assert detection.errors[0]["exit_code"] == 3
    assert detection.errors[0]["stderr_excerpt"] == "kural yuklenemedi"
    # Kosu bir sonraki dosyayla devam etmis olmali.
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    assert mock_run.call_count == 2
    _detection_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_error") == 1
    assert event_types.count("detection_completed_for_artifact") == 1


def test_detection_runner_timeout_is_a_non_fatal_error(tmp_path):
    config = _detection_runner_configured(tmp_path, timeout_seconds=5)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["hayabusa.exe"], timeout=5)
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    assert detection.scanned == [] and detection.findings == []
    assert len(detection.errors) == 1
    assert "5 saniyede bitmedi" in detection.errors[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_error") == 1
    assert verify_chain(ledger.log_path, DETECTION_RUNNER_CASE_ID).is_valid


def test_detection_runner_tool_not_configured_is_skipped(tmp_path):
    # detection bolumu hic yazilmamis: hayabusa_path da rules_dir de None.
    config = _detection_runner_make_config(tmp_path)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert detection.findings == [] and detection.errors == []
    assert len(detection.skipped) == 1
    assert "konfigure edilmemis" in detection.skipped[0]["message"]
    assert detection.skipped[0]["artifact_count"] == 1

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_skipped") == 1


def test_rules_dir_not_configured_is_skipped(tmp_path):
    # Arac var ama kural klasoru bildirilmemis: kuralsiz tarama anlamsiz.
    config = _detection_runner_make_config(tmp_path, hayabusa_path=_detection_runner_fake_tool(tmp_path))
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert len(detection.skipped) == 1
    assert "kural klasoru konfigure edilmemis" in detection.skipped[0]["message"]


def test_detection_runner_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    # Yol mutlak (sema gecer) ama diskte boyle bir dosya yok.
    missing_exe = str(tmp_path / "olmayan" / "hayabusa.exe")
    config = _detection_runner_make_config(tmp_path, hayabusa_path=missing_exe, rules_dir=_fake_rules(tmp_path))
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    message = detection.skipped[0]["message"]
    # Iki durum birbirinden ayirt edilebilir olmali.
    assert "yolu bulunamadi" in message and missing_exe in message
    assert "konfigure edilmemis" not in message


def test_missing_rules_dir_on_disk_is_skipped(tmp_path):
    missing_rules = str(tmp_path / "olmayan" / "rules")
    config = _detection_runner_make_config(
        tmp_path, hayabusa_path=_detection_runner_fake_tool(tmp_path), rules_dir=missing_rules
    )
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural klasoru bulunamadi" in detection.skipped[0]["message"]


def test_only_event_log_artifacts_are_scanned(tmp_path):
    """Hayabusa bir .evtx tarayicisidir: prefetch/registry ona verilmez."""
    config = _detection_runner_configured(tmp_path)
    evtx = _detection_runner_make_artifact(config)
    prefetch = _detection_runner_make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    hive = _detection_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _detection_runner_make_manifest([prefetch, evtx, hive]), ledger)

    assert mock_run.call_count == 1
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Security.evtx"]
    # Taranmayan tipler "atlandi" olarak da kaydedilmez: bunlar zaten bu
    # katmanin isi degil, gurultu olurdu.
    assert detection.skipped == []

    started = [e for e in read_events(ledger.log_path) if e.event_type == "detection_started"][0]
    assert started.payload["artifact_count"] == 1


def test_detection_runner_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    """Guvenlik kurali #3: agac disindaki girdi icin hicbir sey CALISTIRILMAZ.

    Elle duzenlenmis / bozulmus bir manifest.json'i taklit eder.
    """
    config = _detection_runner_configured(tmp_path)
    # Vakanin artifacts kokunun kardesi: yol var ama agacin disinda.
    outside = tmp_path / "disarida" / "evil.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"kotu")
    tampered = _detection_runner_make_artifact(config, filename="evil.evtx", dest_path=str(outside))
    # '..' ile agactan cikmaya calisan ikinci bir kalip.
    traversal = _detection_runner_make_artifact(
        config,
        filename="traversal.evtx",
        dest_path=str(_detection_runner_artifacts_root(config) / "event_logs" / ".." / ".." / ".." / "escape.evtx"),
    )
    legit = _detection_runner_make_artifact(config, filename="Good.evtx")
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _detection_runner_make_manifest([tampered, traversal, legit]), ledger)

    # Iki bozuk girdi de hata olarak kaydedilmis olmali.
    rejected = {e["source_path"] for e in detection.errors}
    assert rejected == {tampered.dest_path, traversal.dest_path}
    for entry in detection.errors:
        assert "cikti agaci disinda" in entry["message"]

    # ...ve bu girdiler icin subprocess HIC cagrilmamis olmali.
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[argv.index("-f") + 1] == str(Path(legit.dest_path).resolve())
    assert str(outside) not in argv
    assert "escape.evtx" not in " ".join(argv)
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    _detection_runner_assert_never_uses_shell(mock_run)


def test_unparsable_output_is_not_fatal(tmp_path):
    """Ayristirma basarisiz olursa kosu devam eder: 0 bulgu + uyari kaydi."""
    config = _detection_runner_configured(tmp_path)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        # Arac 0 ile donuyor ama CSV yerine taninmayan bir sey yaziyor.
        mock_run.side_effect = _writes_csv("bu bir CSV degil\n")
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    assert detection.findings == []
    assert detection.errors == []
    scanned = detection.scanned[0]
    assert scanned["finding_count"] == 0
    assert "taninmadi" in scanned["parse_warning"]
    # Ham cikti diskte durmali: veri kaybolmuyor, sadece ayristirilamiyor.
    assert Path(scanned["output_csv_path"]).is_file()


def test_missing_output_file_is_not_fatal(tmp_path):
    """Arac 0 ile donup hic dosya yazmazsa da kosu devam eder."""
    config = _detection_runner_configured(tmp_path)
    ledger = _detection_runner_ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.return_value = _detection_runner_completed(["x"])
        detection = run_detection(config, _detection_runner_make_manifest([_detection_runner_make_artifact(config)]), ledger)

    assert detection.findings == []
    assert "olusmadi" in detection.scanned[0]["parse_warning"]


def test_output_dir_creation_failure_is_fatal_detection_error(tmp_path):
    """Cikti dizini olusturulamazsa (yolun bir parcasi aslinda bir dosya) bu
    olumcul sayilir ve tipli DetectionError olarak yukselir; ham OSError
    kullaniciya sizmaz."""
    config = _detection_runner_configured(tmp_path)
    artifact = _detection_runner_make_artifact(config)
    ledger = _detection_runner_ledger(tmp_path)

    # "detections" adinda bir DOSYA onceden var: alti icin dizin acilamaz.
    detections_as_file = Path(config.collection.output_dir) / DETECTION_RUNNER_CASE_ID / "detections"
    detections_as_file.parent.mkdir(parents=True, exist_ok=True)
    detections_as_file.write_text("bu bir dizin degil", encoding="utf-8")

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        with pytest.raises(DetectionError):
            run_detection(config, _detection_runner_make_manifest([artifact]), ledger)
        mock_run.assert_not_called()


def test_relative_tool_and_rules_paths_are_rejected_at_config_time():
    """Guvenlik kurali #2: goreli arac/kural yolu semada reddedilir."""
    for detection in ({"hayabusa_path": "hayabusa.exe"}, {"rules_dir": "rules"}):
        with pytest.raises(ValueError) as exc_info:
            TriageChainConfig(
                case={"case_id": DETECTION_RUNNER_CASE_ID, "operator": "test.operator"},
                collection={"targets": ["event_logs"], "output_dir": "."},
                detection=detection,
            )
        assert "mutlak yol" in str(exc_info.value)


def test_absolute_paths_do_not_need_to_exist_at_config_time(tmp_path):
    # Kullanici Hayabusa'yi kurmadan once konfigurasyonu yazmis olabilir.
    config = _detection_runner_make_config(
        tmp_path,
        hayabusa_path=str(tmp_path / "henuz" / "yok.exe"),
        rules_dir=str(tmp_path / "henuz" / "rules"),
    )

    assert config.detection.timeout_seconds == 600


def _started_payload(ledger):
    """Defterdeki detection_started olayinin yukunu dondurur."""
    events = [e for e in read_events(ledger.log_path) if e.event_type == "detection_started"]
    assert len(events) == 1
    return events[0].payload


def _run_and_get_started_payload(tmp_path, config, ledger):
    artifact = _detection_runner_make_artifact(config)
    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        run_detection(config, _detection_runner_make_manifest([artifact]), ledger)
    return _started_payload(ledger)


def test_detection_started_records_the_rule_set_fingerprint(tmp_path):
    """Metodoloji izlenebilirligi: "hangi kural seti bu bulgulari uretti"
    sorusu defterden cevaplanabilmeli."""
    config = _detection_runner_configured(tmp_path)
    payload = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path))

    assert payload["rules_dir"] == config.detection.rules_dir
    assert payload["rules_file_count"] == 1  # _fake_rules tek bir .yml yaziyor
    assert len(payload["rules_fingerprint_sha256"]) == 64
    # Mevcut alanlar (geriye donuk uyumluluk) korunmus olmali.
    assert {"run_id", "collection_run_id", "artifact_count", "output_dir"} <= set(payload)


def test_rule_set_fingerprint_is_stable_for_an_unchanged_directory(tmp_path):
    config = _detection_runner_configured(tmp_path)
    first = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path / "a"))
    second = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path / "b"))

    assert first["rules_fingerprint_sha256"] == second["rules_fingerprint_sha256"]


def test_rule_set_fingerprint_changes_when_a_rule_file_is_added_or_removed(tmp_path):
    """Parmak izi YAPISALDIR: dosya eklenmesi/cikarilmasi yakalanir (icerigi
    ayni boyutta degistirmek YAKALANMAZ - bilincli sinirlama, bkz.
    docs/chain_of_custody.md)."""
    config = _detection_runner_configured(tmp_path)
    rules = Path(config.detection.rules_dir)
    before = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path / "a"))

    yeni_kural = rules / "yeni_kural.yml"
    yeni_kural.write_text("title: yeni kural", encoding="utf-8")
    after_add = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path / "b"))

    assert after_add["rules_file_count"] == before["rules_file_count"] + 1
    assert after_add["rules_fingerprint_sha256"] != before["rules_fingerprint_sha256"]

    yeni_kural.unlink()
    after_remove = _run_and_get_started_payload(tmp_path, config, _detection_runner_ledger(tmp_path / "c"))

    # Dosya geri cikarilinca parmak izi ilk haline donmeli.
    assert after_remove["rules_fingerprint_sha256"] == before["rules_fingerprint_sha256"]


def test_fingerprint_fields_are_absent_when_the_rules_directory_is_missing(tmp_path):
    """Kural klasoru yoksa uydurma bir deger yazmaktansa alan HIC yazilmaz;
    kosunun neden atlandigi zaten detection_skipped olayinda duruyor."""
    config = _detection_runner_make_config(tmp_path, hayabusa_path=_detection_runner_fake_tool(tmp_path),
                          rules_dir=str(tmp_path / "olmayan" / "rules"))
    ledger = _detection_runner_ledger(tmp_path)
    payload = _run_and_get_started_payload(tmp_path, config, ledger)

    assert "rules_fingerprint_sha256" not in payload
    assert "rules_file_count" not in payload
    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_skipped") == 1


# ============================================================================
# Kaynak: tests/unit/test_gui_qt.py
# ============================================================================
# PySide6 arayuzunun ekransiz (offscreen) testleri.
#
# Gercek bir pencere ACILMAZ: QT_QPA_PLATFORM=offscreen ile Qt kendi sanal
# ekranina cizer, testler yalnizca widget'larin DOGRU DEGERLERI tuttugunu
# (.text(), satir sayisi vb.) dogrular -- goruntu karsilastirmasi yok.
#


# QApplication kurulmadan ONCE ayarlanmali, bu yuzden import'lardan once.




pytest.importorskip("PySide6")



GUI_QT_CASE_ID = "CASE-GUI-001"
START = datetime(2026, 6, 7, 22, 1, 0, tzinfo=timezone.utc)


def _event_name_at(window, row):
    """Olay adi hucresi artik duz bir QTableWidgetItem degil, ikon + ad/detay
    tasiyan bir widget (bkz. main_window._build_event_cell) -- adi bu yuzden
    objectName ile isaretlenmis QLabel'dan okunuyor."""
    cell = window.table.cellWidget(row, 0)
    return cell.findChild(QLabel, "event_name").text()


@pytest.fixture(scope="session")
def gui_qt_qt_app():
    """Tum testler icin tek bir QApplication (Qt ikincisine izin vermez)."""
    return QApplication.instance() or QApplication([])


@pytest.fixture
def gui_qt_config_path(tmp_path):
    """Gecerli ama hicbir ciktisi olmayan bir vaka konfigurasyonu."""
    data = {
        "case": {"case_id": GUI_QT_CASE_ID, "operator": "test.operator", "description": "gui testi"},
        "collection": {
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def _write_fake_case(gui_qt_config_path, artifact_count=3, finding_count=2):
    """Diske sahte bir vaka yazar: manifest + gecerli custody defteri + bulgular."""
    config = load_config(gui_qt_config_path)

    artifacts = [
        CollectedArtifact(
            artifact_type_id="event_logs",
            source_path=f"C:/kaynak/log{i}.evtx",
            dest_path=f"C:/hedef/log{i}.evtx",
            hash_value="0" * 64,
            hash_algorithm="sha256",
            size_bytes=1024,
            collected_at_utc=START,
            collecting_user="test.operator",
            case_id=GUI_QT_CASE_ID,
        )
        for i in range(artifact_count)
    ]
    manifest = CollectionManifest(
        case_id=GUI_QT_CASE_ID,
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=2, seconds=5),
        artifacts=artifacts,
    )
    manifest.to_json_file(resolve_manifest_path(config))

    detection = DetectionManifest(
        case_id=GUI_QT_CASE_ID,
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=1),
        findings=[
            Finding(
                artifact_type_id="event_logs",
                source_path="C:/hedef/log0.evtx",
                rule_title=f"Kural {i}",
                level="critical",
                timestamp="2026-06-07 22:03:00",
                computer="WS-01",
                channel="Security",
                event_id="4688",
                details="ornek",
            )
            for i in range(finding_count)
        ],
    )
    detection.to_json_file(resolve_detection_manifest_path(config))

    # Gercek defter: hash zinciri gercekten hesaplansin diye append_event.
    ledger = CustodyLedger(resolve_custody_log_path(config), GUI_QT_CASE_ID)
    ledger.append_event("case_opened", "test.operator", {"aciklama": "gui testi"})
    for i in range(artifact_count):
        ledger.append_event("artifact_collected", "test.operator", {"index": i})
    ledger.append_event("case_closed", "test.operator", {"artifact_count": artifact_count})
    return config


def test_pencere_vaka_yuklenmeden_kuruluyor(gui_qt_qt_app, gui_qt_config_path):
    """Hicbir vaka yuklenmeden pencere+Dashboard cokmeden kurulmali."""
    window = TriageChainWindow()

    assert window.metric_files[1].text() == "—"
    assert window.metric_duration[1].text() == "—"
    assert window.metric_findings[1].text() == "—"
    assert window.chain_badge.text() == "Henüz vaka yüklenmedi"
    assert window.table.rowCount() == 0
    # Toplama disindaki uc aksiyon vaka yokken kapali olmali.
    assert not window.collect_button.isEnabled()
    assert not window.route_button.isEnabled()
    assert not window.detect_button.isEnabled()
    assert not window.yara_button.isEnabled()
    assert not window.chainsaw_button.isEnabled()
    assert not window.capa_button.isEnabled()
    assert not window.report_button.isEnabled()


def test_tum_sidebar_sayfalari_farkli_indekse_gidiyor(gui_qt_qt_app, gui_qt_config_path):
    """Yedi nav dugmesi de cokmeden, BIRBIRINDEN FARKLI bir sayfaya gitmeli.

    Yer tutucu sayfa artik yok -- 'Vakalar', 'Delil Zinciri', 'Raporlar',
    'Bulgular', 'Toplanan Dosyalar', 'Zaman Çizelgesi' hepsi gercek sayfa
    (bkz. asagidaki test_<sayfa_adi>_sayfasi_* testleri, her biri kendi
    verisini dogruluyor)."""
    window = TriageChainWindow()
    seen_indexes = {0}  # Dashboard zaten acik basliyor.
    for name in SIDEBAR_PAGES:
        window.nav_buttons[name].click()
        index = window.stack.currentIndex()
        assert index not in seen_indexes
        seen_indexes.add(index)
    window.nav_buttons["dashboard"].click()
    assert window.stack.currentIndex() == 0


def test_toplanan_dosyalar_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["files"].click()
    assert window.stack.currentIndex() == 1
    assert window.files_table.rowCount() == 0
    assert "yüklenmedi" in window.files_subtitle.text()


def test_toplanan_dosyalar_sayfasi_gercek_veri(gui_qt_qt_app, gui_qt_config_path):
    """Yuklenen vakada her artefakt gercek diskteki manifestten satir olmali."""
    _write_fake_case(gui_qt_config_path, artifact_count=3)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.files_table.rowCount() == 3
    assert window.files_table.item(0, 1).text() == "1.0 KB"  # size_bytes=1024
    assert len(window.files_table.cellWidget(0, 3).text()) == 64  # tam hash
    assert window.files_footer.text() == "3 dosya toplandı, hepsi doğrulandı."


def test_toplanan_dosyalar_arama_kutusu_satirlari_filtreler(gui_qt_qt_app, gui_qt_config_path):
    """Cellebrite'in genel aramasindan esinlenilen arama -- dosya yoluna
    gore satirlari canli filtreler."""
    _write_fake_case(gui_qt_config_path, artifact_count=3)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    window.files_search.setText("log1")

    assert window.files_table.isRowHidden(0) is True
    assert window.files_table.isRowHidden(1) is False
    assert window.files_table.isRowHidden(2) is True

    window.files_search.setText("")
    assert window.files_table.isRowHidden(0) is False


def test_delil_zinciri_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["custody"].click()
    assert window.stack.currentIndex() == 2
    assert window.custody_table.rowCount() == 0
    assert window.custody_badge.text() == "Henüz vaka yüklenmedi"


def test_delil_zinciri_sayfasi_tam_liste(gui_qt_qt_app, gui_qt_config_path):
    """Dashboard'un aksine 50 satirla sinirli olmamali -- TUM olaylar gorunmeli."""
    _write_fake_case(gui_qt_config_path, artifact_count=3)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    # 1 acilis + 3 toplama + 1 kapanis = 5 olay -- Dashboard'daki mini
    # tabloyla (window.table) AYNI sayida olmali, ikisi de ayni snapshot'tan.
    assert window.custody_table.rowCount() == 5 == window.table.rowCount()
    assert "Zincir Geçerli" in window.custody_badge.text()
    assert window.custody_table.cellWidget(0, 3).text() == "Doğrulandı"


def test_bulgular_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["findings"].click()
    assert window.stack.currentIndex() == 3
    assert window.findings_table.rowCount() == 0
    assert "yüklenmedi" in window.findings_subtitle.text()


def test_bulgular_sayfasi_gercek_veri(gui_qt_qt_app, gui_qt_config_path):
    """Tespit manifestindeki HER bulgu (Dashboard'daki sayinin acilimi) satir olmali."""
    _write_fake_case(gui_qt_config_path, finding_count=2)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    # _write_fake_case butun bulgulari level="critical" yaziyor.
    assert window.findings_table.rowCount() == 2
    assert window.findings_table.cellWidget(0, 1).text() == "critical"
    assert window.findings_table.item(0, 2).text() == "2026-06-07 22:03:00"
    assert window.findings_subtitle.text() == f"{GUI_QT_CASE_ID} · 2 bulgu"


def test_bulgular_isaretleme_gorunur_ve_kaldirilabilir(gui_qt_qt_app, gui_qt_config_path):
    """Cellebrite'in 'Tags' fikrinden esinlenilen isaretleme -- gozetim
    zincirine YAZILMAZ, ayri bir tags.json'da tutulur (bkz. tag_store.py)."""
    _write_fake_case(gui_qt_config_path, finding_count=2)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    target_id = tag_store.target_id_for_finding(window.snapshot.findings[0])
    assert target_id not in window._tags

    # Dogrudan tag_store uzerinden isaretle (QInputDialog'u tetiklemeden --
    # o zaten tag_store.py'nin kendi testlerinde ayrica dogrulaniyor) ve
    # sayfayi yenile -- _on_toggle_tag'in kendisinin yaptigi gibi once
    # bellekteki _tags'i diskten tazeleyip sonra _refresh_findings cagiriyoruz.
    tag_store.set_tag(window._tags_path, target_id, "önemli - rapora eklenecek", "test.operator")
    window._tags = tag_store.load_tags(window._tags_path)
    window._refresh_findings()

    assert target_id in window._tags
    cell = window.findings_table.cellWidget(0, 4)
    btn = cell.findChild(QToolButton)
    assert btn.toolTip() == "önemli - rapora eklenecek"

    # Zaten isaretli bir hedefe tiklamak dogrudan kaldirir (diyalog acmaz --
    # bu yuzden headless testte guvenle tiklanabilir).
    btn.click()

    assert target_id not in window._tags
    assert tag_store.load_tags(window._tags_path) == {}


def test_bulgular_arama_kutusu_dort_tabloyu_birden_filtreler(gui_qt_qt_app, gui_qt_config_path):
    """Cellebrite'in genel arama kutusundan esinlenildi -- TEK kutu, TUM
    bulgu tablolarini ayni anda filtreler."""
    config = _write_fake_case(gui_qt_config_path, finding_count=2)
    yara_manifest = YaraManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START)
    yara_manifest.matches.append(
        YaraMatch(
            artifact_type_id="event_logs", source_path="C:/hedef/log0.evtx",
            rule_name="Kural 0 Benzer İmza", tags="",
        )
    )
    yara_manifest.to_json_file(resolve_yara_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    window.findings_search.setText("Kural 0")

    assert window.findings_table.isRowHidden(0) is False
    assert window.findings_table.isRowHidden(1) is True
    assert window.yara_table.isRowHidden(0) is False

    window.findings_search.setText("hiçbir-şeye-uymayan-sorgu")
    assert window.findings_table.isRowHidden(0) is True
    assert window.findings_table.isRowHidden(1) is True

    window.findings_search.setText("")
    assert window.findings_table.isRowHidden(0) is False
    assert window.findings_table.isRowHidden(1) is False


def test_bulgular_sayfasi_yara_ve_korelasyon(gui_qt_qt_app, gui_qt_config_path):
    """YARA manifesti Sigma bulgusuyla AYNI dosyayi isaretlerse korelasyon
    notu gorunmeli -- bkz. detection/correlation.py."""
    config = _write_fake_case(gui_qt_config_path, finding_count=1)
    # _write_fake_case'in TUM bulgulari ayni source_path'i kullaniyor.
    matched_path = "C:/hedef/log0.evtx"
    yara_manifest = YaraManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START)
    yara_manifest.matches.append(
        YaraMatch(
            artifact_type_id="event_logs", source_path=matched_path,
            rule_name="Mimikatz_Strings", tags="malware,mimikatz",
        )
    )
    yara_manifest.to_json_file(resolve_yara_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.yara_panel.isHidden()
    assert window.yara_empty_note.isHidden()
    assert window.yara_table.rowCount() == 1
    assert window.yara_table.item(0, 0).text() == "Mimikatz_Strings"
    assert not window.yara_correlation_note.isHidden()
    assert "1 dosya" in window.yara_correlation_note.text()


def test_bulgular_sayfasi_yara_calismamissa_bos_not_gosterir(gui_qt_qt_app, gui_qt_config_path):
    """YARA hic calismamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(gui_qt_config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.yara_panel.isHidden()
    assert not window.yara_empty_note.isHidden()
    assert window.yara_correlation_note.isHidden()


def test_bulgular_sayfasi_chainsaw_ve_motor_ittifaki(gui_qt_qt_app, gui_qt_config_path):
    """Chainsaw manifesti Hayabusa bulgusuyla AYNI kurali AYNI dosyada
    bulursa ittifak notu gorunmeli -- bkz. detection/correlation.py."""
    config = _write_fake_case(gui_qt_config_path, finding_count=1)
    # _write_fake_case'in TUM bulgulari "Kural 0" adini ve ayni source_path'i kullaniyor.
    matched_path = "C:/hedef/log0.evtx"
    chainsaw_manifest = DetectionManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START)
    chainsaw_manifest.findings.append(
        Finding(
            artifact_type_id="event_logs", source_path=matched_path, rule_title="Kural 0",
            level="critical", timestamp="2026-06-07 22:03:00", computer="WS-01",
            channel="Security", event_id="4688", details="ornek",
        )
    )
    chainsaw_manifest.to_json_file(resolve_chainsaw_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.chainsaw_panel.isHidden()
    assert window.chainsaw_empty_note.isHidden()
    assert window.chainsaw_table.rowCount() == 1
    assert window.chainsaw_table.cellWidget(0, 1).text() == "critical"
    assert not window.chainsaw_agreement_note.isHidden()
    assert "1 dosyada" in window.chainsaw_agreement_note.text()


def test_bulgular_sayfasi_chainsaw_calismamissa_bos_not_gosterir(gui_qt_qt_app, gui_qt_config_path):
    """Chainsaw hic calismamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(gui_qt_config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.chainsaw_panel.isHidden()
    assert not window.chainsaw_empty_note.isHidden()
    assert window.chainsaw_agreement_note.isHidden()


def test_bulgular_sayfasi_capa_gercek_veri(gui_qt_qt_app, gui_qt_config_path):
    """capa manifesti varsa Bulgular sayfasindaki capa paneli dolmali --
    YARA ile AYNI YaraMatch semasini kullanir (bkz. detection/capa_runner.py)."""
    config = _write_fake_case(gui_qt_config_path, finding_count=1)
    capa_manifest = YaraManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START)
    capa_manifest.matches.append(
        YaraMatch(
            artifact_type_id="suspicious_binary", source_path="C:/supheli/ornek.exe",
            rule_name="link function at runtime on Windows", tags="T1129",
            meta="namespace=linking/runtime-linking",
        )
    )
    capa_manifest.to_json_file(resolve_capa_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.capa_panel.isHidden()
    assert window.capa_empty_note.isHidden()
    assert window.capa_table.rowCount() == 1
    assert window.capa_table.item(0, 0).text() == "link function at runtime on Windows"
    assert window.capa_table.item(0, 1).text() == "T1129"


def test_bulgular_sayfasi_capa_calismamissa_bos_not_gosterir(gui_qt_qt_app, gui_qt_config_path):
    """capa hic calistirilmamissa panel gizli, bos-durum notu gorunmeli."""
    _write_fake_case(gui_qt_config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.capa_panel.isHidden()
    assert not window.capa_empty_note.isHidden()


def test_raporlar_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["reports"].click()
    assert window.stack.currentIndex() == 4
    assert window.reports_card.isHidden()
    assert window.report_chain_badge.text() == "Henüz vaka yüklenmedi"


def test_raporlar_sayfasi_rapor_uretilmemis(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklu ama 'Rapor Uret' hic calistirilmamissa bos not gorunmeli."""
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.reports_card.isHidden()
    assert not window.reports_empty_note.isHidden()
    assert window.report_chain_badge.text() == "Henüz rapor yok"


def test_raporlar_sayfasi_gercek_veri(gui_qt_qt_app, gui_qt_config_path):
    """report.json'daki gercek alanlar (uydurulmamis) ekrana yansimali."""
    config = _write_fake_case(gui_qt_config_path, artifact_count=3, finding_count=2)
    report = build_report(config)
    write_report(config, report)

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.reports_card.isHidden()
    assert window.reports_empty_note.isHidden()
    assert "Zincir Geçerli" in window.report_chain_badge.text()
    assert window.report_field_operator.text() == f"test.operator · {GUI_QT_CASE_ID}"
    assert "3 dosya" in window.report_field_collection.text()
    assert "2 bulgu" in window.report_field_detection.text()
    assert window.report_field_routing.text() == "Bu vaka için henüz çalıştırılmadı"
    # _write_fake_case route calistirmiyor -- zaman cizelgesi de bos kalmali.
    assert "Henüz oluşturulmadı" in window.report_field_timeline.text()

    # Yonetici Raporu sekmesi: _write_fake_case TUM bulgulari "critical"
    # yazdigi icin risk seviyesi Yuksek olmali (bkz. reporting/executive.py).
    assert window.reports_tabs.tabText(0) == "Yönetici Raporu"
    assert window.reports_tabs.tabText(1) == "Uzman Raporu"
    assert "Risk Seviyesi: Yüksek" in window.exec_risk_level.text()
    assert window.exec_tile_artifacts.text() == "3"
    assert window.exec_tile_findings.text() == "2"
    assert window.exec_tile_high.text() == "2"
    assert window.exec_tile_chain.text() == "Doğrulandı"
    assert GUI_QT_CASE_ID in window.exec_narrative.text()


def test_zaman_cizelgesi_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Vaka yuklenmeden sayfa cokmemeli, bos/durum mesaji gostermeli."""
    window = TriageChainWindow()
    window.nav_buttons["timeline"].click()
    assert window.stack.currentIndex() == 6
    assert window.timeline_table.rowCount() == 0
    assert "yüklenmedi" in window.timeline_subtitle.text()


def test_zaman_cizelgesi_sayfasi_route_calismamissa_bos_not_gosterir(gui_qt_qt_app, gui_qt_config_path):
    """route hic calistirilmamissa (routing_manifest.json yok) panel bos-durum
    notu gostermeli -- gercek YARA/Chainsaw/capa panelleriyle AYNI desen."""
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.timeline_table.isHidden()
    assert not window.timeline_empty_note.isHidden()


def test_zaman_cizelgesi_sayfasi_gercek_pecmd_verisiyle_dolar(gui_qt_qt_app, gui_qt_config_path):
    """routing_manifest.json'daki bir PECmd artefaktinin gercek Timeline
    CSV'si varsa tabloya yansimali -- gercek PECmd 2026.5.0 ciktisindan
    alinan sutunlarla (bkz. reporting/timeline.py, aldigim_kararlar.md)."""
    config = _write_fake_case(gui_qt_config_path)
    output_dir = Path(config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8",
    )
    routing = RoutingManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START, ended_at_utc=START)
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=START,
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.timeline_table.isHidden()
    assert window.timeline_empty_note.isHidden()
    assert window.timeline_table.rowCount() == 1
    assert window.timeline_table.item(0, 0).text() == "2019-06-05 19:23:00"
    assert window.timeline_table.item(0, 1).text() == "Prefetch"
    assert "1 olay" in window.timeline_subtitle.text()


def test_zaman_cizelgesi_arama_kutusu_satirlari_filtreler(gui_qt_qt_app, gui_qt_config_path):
    """Cellebrite'in genel aramasindan esinlenilen arama -- olay/dosya
    aciklamasina gore satirlari canli filtreler."""
    config = _write_fake_case(gui_qt_config_path)
    output_dir = Path(config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n"
        "2019-06-05 19:24:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\CALC.EXE\n",
        encoding="utf-8",
    )
    routing = RoutingManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START, ended_at_utc=START)
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=START,
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)
    assert window.timeline_table.rowCount() == 2

    window.timeline_search.setText("NOTEPAD")

    assert window.timeline_table.isRowHidden(0) is False
    assert window.timeline_table.isRowHidden(1) is True

    window.timeline_search.setText("")
    assert window.timeline_table.isRowHidden(1) is False


def test_yuklenen_vakada_metrikler_ve_defter_dogru(gui_qt_qt_app, gui_qt_config_path):
    """Sahte bir vaka yuklendiginde kartlar/tablo diskteki gercek veriyi gostermeli."""
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.metric_files[1].text() == "3"
    assert window.metric_duration[1].text() == "02:05"   # 2 dk 5 sn
    assert window.metric_findings[1].text() == "2"
    assert "Zincir Geçerli" in window.chain_badge.text()

    # Delta metni + sparkline verisi GERCEK diskteki veriden turemeli --
    # uydurulmus bir sayi degil (bkz. read_snapshot()).
    # "~" oneki referans tasarimdaki kucuk trend isaretiyle ayni gorsel
    # dili tasir, sadece gosterim katmaninda eklenir (bkz. _refresh_metrics).
    assert window.metric_files[2].text() == "~ tümü doğrulandı"
    assert window.metric_files[3]._values == [1, 2, 3]
    assert window.metric_findings[2].text() == "~ 2 yüksek önem"  # ikisi de "critical"
    assert window.metric_findings[3]._values == [1, 2]
    # _write_fake_case hem toplama hem tespit manifesti yaziyor (yonlendirme
    # yok) -- ikisinin de suresi trend'e girmeli, en son BITEN (toplama,
    # 02:05 > tespitin 1 dakikasi) basliktaki metni belirlemeli.
    assert window.metric_duration[2].text() == "~ toplama+tarama"
    assert window.metric_duration[3]._values == [125.0, 60.0]

    # 1 acilis + 3 toplama + 1 kapanis = 5 olay
    assert window.table.rowCount() == 5
    assert _event_name_at(window, 0) == "Vaka Açıldı"
    assert _event_name_at(window, 1) == "Dosya Toplandı"
    assert _event_name_at(window, 4) == "Vaka Kapatıldı"
    # Hash tam gosterilmeli (64 karakter), kesilmemeli.
    assert len(window.table.cellWidget(0, 2).text()) == 64
    assert all(
        window.table.cellWidget(row, 3).text() == "Doğrulandı"
        for row in range(window.table.rowCount())
    )
    assert window.table_footer.text() == "5 olay gösteriliyor"

    # Manifest artik var: yonlendirme/tarama/rapor butonlari acilmali.
    assert window.route_button.isEnabled()
    assert window.detect_button.isEnabled()
    assert window.yara_button.isEnabled()
    assert window.chainsaw_button.isEnabled()
    assert window.capa_button.isEnabled()
    assert window.report_button.isEnabled()


def test_bozulan_zincirde_supheli_durumu_gorunuyor(gui_qt_qt_app, gui_qt_config_path):
    """Defter kasitli bozulursa kirilmadan sonraki satirlar 'Şüpheli' olmali."""
    config = _write_fake_case(gui_qt_config_path)
    log_path = resolve_custody_log_path(config)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    # 2. olayin operator alanini degistir -> entry_hash artik uyusmaz.
    lines[1] = lines[1].replace('"test.operator"', '"sahtekar"')
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert "GEÇERSİZ" in window.chain_badge.text()
    assert window.table.cellWidget(0, 3).text() == "Doğrulandı"
    assert window.table.cellWidget(1, 3).text() == "Şüpheli"
    assert window.table.cellWidget(4, 3).text() == "Şüpheli"


def _case_id_at(window, row):
    """Vakalar tablosundaki vaka kimligini objectName ile isaretlenmis
    QLabel'dan okur -- _event_name_at ile ayni desen."""
    cell = window.cases_table.cellWidget(row, 0)
    return cell.findChild(QLabel, "case_id_label").text()


def test_vakalar_sayfasi_vaka_yuklenmeden(gui_qt_qt_app, gui_qt_config_path):
    """Config yuklenmeden output_dir bilinmiyor -- liste bos kalmali, cokmemeli."""
    window = TriageChainWindow()
    window.nav_buttons["cases"].click()
    assert window.stack.currentIndex() == 5
    assert window.cases_table.rowCount() == 0


def test_vakalar_sayfasi_kardes_vakalari_buluyor(gui_qt_qt_app, gui_qt_config_path):
    """Ayni output_dir altindaki BASKA bir vaka klasoru de listede gorunmeli,
    yuklu olan 'AKTIF' etiketiyle ayirt edilebilmeli."""
    config = _write_fake_case(gui_qt_config_path, artifact_count=3, finding_count=2)

    # Kardes vaka: sadece bir manifest.json'u olan, custody/tespit hic
    # calistirilmamis eksik bir vaka -- okunamayan alanlar cokmemeli.
    sibling_dir = Path(config.collection.output_dir) / "CASE-SIBLING-002"
    sibling_dir.mkdir(parents=True)
    sibling_manifest = CollectionManifest(
        case_id="CASE-SIBLING-002",
        started_at_utc=START,
        ended_at_utc=START + timedelta(minutes=1),
        artifacts=[
            CollectedArtifact(
                artifact_type_id="event_logs",
                source_path="C:/kaynak/log0.evtx",
                dest_path="C:/hedef/log0.evtx",
                hash_value="1" * 64,
                hash_algorithm="sha256",
                size_bytes=2048,
                collected_at_utc=START,
                collecting_user="baska.operator",
                case_id="CASE-SIBLING-002",
            )
        ],
    )
    sibling_manifest.to_json_file(sibling_dir / "manifest.json")

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.cases_table.rowCount() == 2
    case_ids = {_case_id_at(window, row) for row in range(2)}
    assert case_ids == {GUI_QT_CASE_ID, "CASE-SIBLING-002"}

    rows_by_id = {_case_id_at(window, row): row for row in range(2)}
    active_row = rows_by_id[GUI_QT_CASE_ID]
    sibling_row = rows_by_id["CASE-SIBLING-002"]
    assert window.cases_table.item(active_row, 1).text() == "3"
    assert window.cases_table.cellWidget(active_row, 2).text() == "Geçerli · 5 olay"
    # Kardes vakada custody/tespit hic yok -- bu alanlar "—"/"Defter yok" kalmali.
    assert window.cases_table.item(sibling_row, 1).text() == "1"
    assert window.cases_table.cellWidget(sibling_row, 2).text() == "Defter yok"
    assert window.cases_table.item(sibling_row, 3).text() == "—"


def test_bozuk_konfigurasyon_ham_traceback_gostermiyor(gui_qt_qt_app, tmp_path):
    """Gecersiz bir YAML yuklenince sade bir durum mesaji gosterilmeli."""
    bad = tmp_path / "bozuk.yaml"
    bad.write_text("case: [bu bir sozluk degil]\n", encoding="utf-8")

    window = TriageChainWindow()
    window.load_config_file(bad)

    assert window.config is None
    message = window.status_label.text()
    assert "Traceback" not in message
    assert message.strip()
    # Vaka yuklenemedigi icin aksiyonlar kapali kalmali.
    assert not window.collect_button.isEnabled()


# -- Ayarlar sayfasi: tema + dil (canli gecis) -------------------------------
# t.set_mode/i18n.set_language SUREC GENELINDE PAYLASILAN modul durumu --
# her testten SONRA varsayilana (dark/tr) donduruluyor ki bu dosyadaki
# BASKA testler (hepsi varsayilan temayi/dili varsayiyor) bozulmasin.

@pytest.fixture(autouse=True)
def _reset_theme_and_language_after_test():
    yield
    t.set_mode("dark")
    i18n.set_language("tr")


def test_ayarlar_sayfasi_varsayilan_koyu_ve_turkce_gosterir(gui_qt_qt_app):
    window = TriageChainWindow()

    assert window.theme_dark_radio.isChecked()
    assert not window.theme_light_radio.isChecked()
    assert window.language_combo.currentData() == "tr"
    assert window.windowTitle() == "TriageChain Konsolu"


def test_acik_tema_radyosu_canli_gecis_yapiyor(gui_qt_qt_app):
    window = TriageChainWindow()
    window._show_settings()

    window.theme_light_radio.setChecked(True)

    assert t.get_mode() == "light"
    # _apply_theme() kabugu YENIDEN KURDUGU icin eski referanslar gecersiz --
    # widget'lar YENIDEN alinmali (bkz. main_window.py::_build_shell notu).
    assert window.stack.currentIndex() == 7  # Ayarlar sayfasinda kaldi
    assert window.theme_light_radio.isChecked()
    assert not window.theme_dark_radio.isChecked()


def test_koyu_temaya_geri_donus_calisiyor(gui_qt_qt_app):
    window = TriageChainWindow()
    window._show_settings()
    window.theme_light_radio.setChecked(True)

    window.theme_dark_radio.setChecked(True)

    assert t.get_mode() == "dark"
    assert window.theme_dark_radio.isChecked()


def test_dil_secimi_pencere_basligini_degistiriyor(gui_qt_qt_app):
    window = TriageChainWindow()
    window._show_settings()
    en_index = list(i18n.SUPPORTED_LANGUAGES.keys()).index("en")

    window.language_combo.setCurrentIndex(en_index)

    assert i18n.get_language() == "en"
    assert window.windowTitle() == "TriageChain Console"
    assert window.stack.currentIndex() == 7


def test_dil_secimi_sidebar_etiketlerini_de_degistiriyor(gui_qt_qt_app):
    """Sidebar navigasyon etiketleri artik SABIT Ingilizce kimliklerle
    (SIDEBAR_PAGES) dispatch edilip GORUNEN metni i18n.t()'den alan --
    dil degisince hem etiketler hem ic dispatch (nav_buttons anahtarlari)
    dogru calismali."""
    window = TriageChainWindow()
    window._show_settings()
    en_index = list(i18n.SUPPORTED_LANGUAGES.keys()).index("en")

    window.language_combo.setCurrentIndex(en_index)

    assert window.nav_buttons["files"].text() == "Collected Files"
    assert window.nav_buttons["custody"].text() == "Chain of Custody"
    assert window.nav_buttons["dashboard"].text() == "Dashboard"
    # Dispatch hala calisiyor mu -- Ingilizce etiketli butona tiklamak
    # hala dogru sayfaya gotürmeli.
    window.nav_buttons["findings"].click()
    assert window.stack.currentIndex() == 3


def test_dil_acilir_listesi_kod_ve_ad_formatinda_ve_dogru_sirada(gui_qt_qt_app):
    window = TriageChainWindow()
    window._show_settings()

    labels = [window.language_combo.itemText(i) for i in range(window.language_combo.count())]

    assert labels[0] == "TR Türkçe"
    assert labels[1] == "EN English"
    assert labels[2].startswith("ES Español")
    assert labels[3].startswith("DE Deutsch")
    assert labels[4].startswith("PT Português")
    assert labels[5].startswith("FR Français")
    # Henuz cevrilmemis diller acikca isaretlenmeli, sessizce eksik
    # gosterilmemeli (kullaniciyi yanlis bilgilendirmemek icin).
    for label in labels[2:]:
        assert "çevrilmedi" in label


def test_tema_gecisi_dashboard_sayfasina_da_yansiyor(gui_qt_qt_app, gui_qt_config_path):
    """Sadece Ayarlar sayfasi degil, TUM kabuk yeniden kuruluyor mu?"""
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)
    window._show_settings()

    window.theme_light_radio.setChecked(True)

    assert t.get_mode() == "light"
    window._show_dashboard()
    # Kabuk yeniden kurulduktan sonra Dashboard verisi hala dogru --
    # _refresh() rebuild sonrasi tekrar cagriliyor.
    assert window.case_pill.text() == GUI_QT_CASE_ID


# -- Vaka Notlari (Dashboard) -------------------------------------------------

def test_vaka_notu_kaydedilir_ve_diskten_okunur(gui_qt_qt_app, gui_qt_config_path):
    """Oxygen Forensic Detective'in vaka notu fikrinden esinlenildi -- tek
    bir bulguya degil VAKANIN GENELINE ait, tag_store'dan AYRI bir dosyada."""
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.case_note_edit.toPlainText() == ""
    assert window.case_note_status.text() == "Henüz kaydedilmedi."

    window.case_note_edit.setPlainText("Şüpheli IP: 10.0.0.5, takip edilecek.")
    window._on_save_case_note()

    assert "test.operator" in window.case_note_status.text()
    from triagechain.gui_qt import case_note_store
    saved = case_note_store.load_case_note(window._case_note_path)
    assert saved.text == "Şüpheli IP: 10.0.0.5, takip edilecek."


def test_vaka_notu_ayni_vakada_yenilenince_kaydedilmemis_metni_bozmaz(gui_qt_qt_app, gui_qt_config_path):
    """Bir aksiyon bitip _refresh() tetiklendiginde (AYNI vaka), kullanicinin
    o an yazmakta oldugu kaydedilmemis metin sessizce KAYBOLMAMALI."""
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    window.case_note_edit.setPlainText("henüz kaydedilmemiş taslak")
    window._refresh()  # ayni vaka icin ikinci bir yenileme (orn. bir aksiyon sonrasi)

    assert window.case_note_edit.toPlainText() == "henüz kaydedilmemiş taslak"


def test_vaka_notu_farkli_vakaya_gecince_diskten_yeniden_yuklenir(gui_qt_qt_app, gui_qt_config_path, tmp_path):
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)
    window.case_note_edit.setPlainText("ilk vakanin notu")
    window._on_save_case_note()

    # Ikinci, FARKLI bir vaka.
    second_case_id = "CASE-GUI-002"
    second_output = tmp_path / "output2"
    second_config_path = tmp_path / "config2.yaml"
    second_config_path.write_text(
        yaml.safe_dump({
            "case": {"case_id": second_case_id, "operator": "test.operator", "description": ""},
            "collection": {"targets": ["event_logs"], "output_dir": str(second_output)},
        }),
        encoding="utf-8",
    )

    window.load_config_file(second_config_path)

    assert window.case_note_edit.toPlainText() == ""


# -- Bulgular: isaretlenenler ozeti + CSV disa aktarma ------------------------

def test_bulgular_isaretlenenler_ozeti_dogru_gosterir(gui_qt_qt_app, gui_qt_config_path):
    _write_fake_case(gui_qt_config_path, finding_count=2)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    target_id = tag_store.target_id_for_finding(window.snapshot.findings[0])
    tag_store.set_tag(window._tags_path, target_id, "önemli", "yasar")
    window._tags = tag_store.load_tags(window._tags_path)
    window._refresh_findings()

    assert window.tagged_table.rowCount() == 1
    assert window.tagged_table.item(0, 0).text() == "Hayabusa"
    assert window.tagged_table.item(0, 3).text() == "önemli"
    assert window.tagged_empty_note.isHidden()


def test_bulgular_isaretlenenler_ozeti_bossa_not_gosterir(gui_qt_qt_app, gui_qt_config_path):
    _write_fake_case(gui_qt_config_path, finding_count=1)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert window.tagged_table.rowCount() == 0
    assert not window.tagged_empty_note.isHidden()


def test_bulgular_csv_disa_aktarma_sadece_gorunen_satirlari_yazar(gui_qt_qt_app, gui_qt_config_path, tmp_path, monkeypatch):
    """Oxygen'in tablo disa aktarma ozelliginden esinlenildi -- arama
    filtresinden GECMEYEN (gizli) satirlar CSV'ye YAZILMAMALI."""
    _write_fake_case(gui_qt_config_path, finding_count=2)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)
    window.findings_search.setText("Kural 0")

    out_path = tmp_path / "bulgular.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(out_path), ""))

    window._on_export_findings_csv()

    assert out_path.is_file()
    content = out_path.read_text(encoding="utf-8-sig")
    assert "Kural 0" in content
    assert "Kural 1" not in content


def test_toplanan_dosyalar_csv_disa_aktarma(gui_qt_qt_app, gui_qt_config_path, tmp_path, monkeypatch):
    _write_fake_case(gui_qt_config_path, artifact_count=2)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    out_path = tmp_path / "dosyalar.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(out_path), ""))

    window._on_export_files_csv()

    assert out_path.is_file()
    content = out_path.read_text(encoding="utf-8-sig")
    assert "log0.evtx" in content
    assert "log1.evtx" in content


def test_zaman_cizelgesi_csv_disa_aktarma(gui_qt_qt_app, gui_qt_config_path, tmp_path, monkeypatch):
    config = _write_fake_case(gui_qt_config_path)
    output_dir = Path(config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        r"RunTime,ExecutableName" "\n"
        r"2019-06-05 19:23:00,\VOLUME{x}\WINDOWS\SYSTEM32\NOTEPAD.EXE" "\n",
        encoding="utf-8",
    )
    routing = RoutingManifest(case_id=GUI_QT_CASE_ID, started_at_utc=START, ended_at_utc=START)
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=START,
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(config))

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    out_path = tmp_path / "cizelge.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(out_path), ""))

    window._on_export_timeline_csv()

    assert out_path.is_file()
    assert "NOTEPAD" in out_path.read_text(encoding="utf-8-sig")


# -- Raporlar: PDF disa aktarma ------------------------------------------------

def test_raporlar_pdf_disa_aktarma_gercek_pdf_uretir(gui_qt_qt_app, gui_qt_config_path, tmp_path, monkeypatch):
    config = _write_fake_case(gui_qt_config_path, artifact_count=3, finding_count=2)
    report = build_report(config)
    write_report(config, report)

    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)
    assert window.export_pdf_button.isEnabled()

    out_path = tmp_path / "ozet.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(out_path), ""))

    window._on_export_report_pdf()

    assert out_path.is_file()
    assert out_path.read_bytes().startswith(b"%PDF-")


def test_raporlar_pdf_butonu_rapor_yokken_kapali(gui_qt_qt_app, gui_qt_config_path):
    _write_fake_case(gui_qt_config_path)
    window = TriageChainWindow()
    window.load_config_file(gui_qt_config_path)

    assert not window.export_pdf_button.isEnabled()


# ============================================================================
# Kaynak: tests/unit/test_hashing.py
# ============================================================================
# hash_file davranisi: bilinen icerik -> bilinen ozet.



HASHING_FIXTURES = Path(__file__).resolve().parents[0] / "fixtures" / "fake_artifacts"

# tests/fixtures/fake_artifacts/notes.txt icin elle hesaplanmis degerler.
NOTES_SIZE = 29
NOTES_SHA256 = "72c6f82825532438968540aae9551a97c3cae8d9cbbb6c836f152dd0d28b2241"


def test_hash_known_fixture_file():
    notes = HASHING_FIXTURES / "notes.txt"
    # Boyut kontrolu: satir sonu normalizasyonu olursa hata mesaji anlasilir olsun.
    assert notes.stat().st_size == NOTES_SIZE
    assert hash_file(notes) == NOTES_SHA256


def test_hash_accepts_open_stream():
    notes = HASHING_FIXTURES / "notes.txt"
    with open(notes, "rb") as stream:
        assert hash_file(stream) == NOTES_SHA256


def test_small_chunk_size_gives_same_digest():
    notes = HASHING_FIXTURES / "notes.txt"
    assert hash_file(notes, chunk_size=3) == NOTES_SHA256


def test_other_algorithms(tmp_path):
    sample = tmp_path / "abc.bin"
    sample.write_bytes(b"abc")
    assert hash_file(sample, "sha1") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hash_file(sample, "md5") == "900150983cd24fb0d6963f7d28e17f72"


# ============================================================================
# Kaynak: tests/unit/test_i18n.py
# ============================================================================
# i18n.py'nin dil tablosu testleri.
#
# i18n modulu SUREC GENELINDE PAYLASILAN modul-seviyesi durum tasiyor -- her
# test sonunda "tr"ye DONDURULUYOR (autouse fixture) ki bu dosyadaki testler
# diger test dosyalarinin varsaydigi varsayilan dili BOZMASIN.
#




@pytest.fixture(autouse=True)
def _reset_language_after_test():
    yield
    i18n.set_language("tr")


def test_varsayilan_dil_turkce():
    assert i18n.get_language() == "tr"
    assert i18n.t("nav_settings") == "Ayarlar"


def test_desteklenen_diller_kullanicinin_istedigi_sira_ve_kapsam():
    assert list(i18n.SUPPORTED_LANGUAGES.keys()) == ["tr", "en", "es", "de", "pt", "fr"]


def test_dil_basligi_aktif_dildeki_kelimeyi_ingilizceyle_esler():
    """Kullanicinin acik istegi: baslik aktif dildeki 'dil' kelimesini
    'Language' ile eslesin (henuz cevrilmemis bir dile gecilmis olsa bile),
    TEK istisna Ingilizce'nin kendisi -- o zaman tekrar olmasin diye
    sadece 'Language' gosterilir."""
    i18n.set_language("tr")
    assert i18n.language_heading() == "Dil / Language"

    i18n.set_language("en")
    assert i18n.language_heading() == "Language"

    i18n.set_language("es")
    assert i18n.language_heading() == "Idioma / Language"

    i18n.set_language("de")
    assert i18n.language_heading() == "Sprache / Language"

    i18n.set_language("pt")
    assert i18n.language_heading() == "Idioma / Language"

    i18n.set_language("fr")
    assert i18n.language_heading() == "Langue / Language"


def test_set_language_ingilizceye_geciyor():
    i18n.set_language("en")

    assert i18n.get_language() == "en"
    assert i18n.t("nav_settings") == "Settings"
    assert i18n.t("window_title") == "TriageChain Console"


def test_set_language_gecersiz_kod_turkceye_duser():
    i18n.set_language("xx")
    assert i18n.get_language() == "tr"


def test_tr_ve_en_gercekten_cevrili():
    assert i18n.is_translated("tr")
    assert i18n.is_translated("en")


def test_es_de_pt_fr_henuz_cevrilmedi():
    for code in ("es", "de", "pt", "fr"):
        assert not i18n.is_translated(code)


def test_cevrilmemis_dil_secilince_t_ingilizceye_duser():
    i18n.set_language("de")

    # get_language() KULLANICININ SECTIGI ham kodu doner (Ayarlar
    # sayfasindaki acilir liste bunu dogru gostersin diye), ama t() sessizce
    # (yanlis/eksik metin YERINE) Ingilizce'ye duser.
    assert i18n.get_language() == "de"
    assert i18n.t("window_title") == "TriageChain Console"


def test_bilinmeyen_anahtar_kendisini_doner_asla_patlamaz():
    assert i18n.t("hic_boyle_bir_anahtar_yok") == "hic_boyle_bir_anahtar_yok"


def test_tr_ve_en_ayni_anahtar_kumesine_sahip():
    tr_keys = set(i18n.STRINGS["tr"].keys())
    en_keys = set(i18n.STRINGS["en"].keys())
    assert tr_keys == en_keys


# ============================================================================
# Kaynak: tests/unit/test_pdf_export.py
# ============================================================================
# gui_qt/pdf_export.py'nin testleri.
#
# test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen -- QTextDocument/
# QPrinter QApplication gerektiriyor ama gercek bir pencere/yazici ACILMAZ,
# PDF dogrudan diske yaziliyor (elle dogrulandi: gercek %PDF-1.4 imzali bir
# dosya uretiyor, bkz. docs/aldigim_kararlar.md).
#
# NOT: bu dosyayi offscreen platformda calistirinca konsolda "Windows fatal
# exception: code 0x80040155" (COM REGDB_E_CLASSNOTREG) izi GORUNEBILIR --
# bu ZARARSIZ ve testin GECMESINI ETKILEMEZ. Elle dogrulandi: AYNI kod
# QT_QPA_PLATFORM AYARLANMADAN (gercek "windows" platformuyla, yani
# paketlenmis uygulamanin GERCEKTE calistigi kosullarda) calistirilinca bu
# iz HIC cikmiyor -- offscreen platform eklentisinin, gercek Windows
# platformunun sagladigi bir yazici/font COM kaydini sahte-eksiksiz
# saglamamasindan kaynaklaniyor, Qt bunu yakalayip PDF'i yine de dogru
# uretiyor (bkz. docs/aldigim_kararlar.md).
#






pytest.importorskip("PySide6")




@pytest.fixture(scope="session")
def pdf_export_qt_app():
    return QApplication.instance() or QApplication([])


def _make_report(**overrides) -> Report:
    defaults = dict(
        case_id="CASE-PDF-001",
        operator="yasar",
        description="",
        collection=CollectionSummary(
            run_id="r1", started_at_utc=datetime.now(timezone.utc), ended_at_utc=None,
            artifact_count=42, error_count=0,
        ),
        chain_status=ChainStatus(is_valid=True, total_events=5, broken_at_event_id=None, message="ok"),
    )
    defaults.update(overrides)
    return Report(**defaults)


def test_build_report_html_temel_alanlari_iceriyor(pdf_export_qt_app):
    report = _make_report()
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "CASE-PDF-001" in html
    assert "yasar" in html
    assert summary.risk_level in html


def test_build_report_html_kullanici_girdisini_kacirir(pdf_export_qt_app):
    """HTML enjeksiyonuna karsi -- operator/case_id gibi alanlar rapora
    dogrudan gomuluyor, kacirilmazsa bozuk/guvensiz bir PDF sablonu
    olusabilir."""
    report = _make_report(case_id="<script>evil</script>")
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "<script>evil</script>" not in html
    assert "&lt;script&gt;" in html


def test_build_report_html_bulgulari_listeler(pdf_export_qt_app):
    report = _make_report(
        detection=DetectionSummary(
            run_id="d1", started_at_utc=datetime.now(timezone.utc), ended_at_utc=None,
            scanned_count=3, finding_count=1,
            findings=[
                Finding(
                    artifact_type_id="event_logs", source_path="C:/case/Security.evtx",
                    rule_title="Şüpheli Oturum Açma", level="critical", timestamp="2026-06-07",
                    computer="WS-01", channel="Security", event_id="4625", details="",
                )
            ],
        )
    )
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "Şüpheli Oturum Açma" in html
    assert "Security.evtx" in html


def test_build_report_html_has_blank_signature_block(pdf_export_qt_app):
    """Kapak/imza alani -- raporun resmi bir gozetim zinciri belgesi gibi
    yazdirilip elle imzalanabilmesi icin (bkz. aldigim_kararlar.md)."""
    report = _make_report()
    summary = build_executive_summary(report)

    html = pdf_export.build_report_html(report, summary)

    assert "İmza Alanı" in html
    assert "İnceleyen (Ad Soyad)" in html
    assert "İmza" in html
    assert "Tarih" in html


def test_export_report_pdf_gercek_pdf_dosyasi_uretir(pdf_export_qt_app, tmp_path):
    report = _make_report()
    summary = build_executive_summary(report)
    out_path = tmp_path / "rapor.pdf"

    pdf_export.export_report_pdf(out_path, report, summary)

    assert out_path.is_file()
    assert out_path.stat().st_size > 0
    assert out_path.read_bytes().startswith(b"%PDF-")


# ============================================================================
# Kaynak: tests/unit/test_report_builder.py
# ============================================================================
# Rapor katmani: eksik/tam manifest senaryolari, sha256 yan dosyasi, kirik zincir.
#
# Hicbir test dis program calistirmaz; manifestler dogrudan yazilir, custody
# defteri gercek CustodyLedger ile uretilir.
#




REPORT_BUILDER_CASE_ID = "CASE-TEST-REPORT"
OPERATOR = "test.operator"


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def report_builder_config(tmp_path):
    """Rapor icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": REPORT_BUILDER_CASE_ID, "operator": OPERATOR, "description": "Rapor testi"},
        collection={
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
    )


def _write_collection(report_builder_config) -> CollectionManifest:
    """Sahte bir toplama kosusu: iki custody olayi + manifest.json."""
    ledger = CustodyLedger(resolve_custody_log_path(report_builder_config), REPORT_BUILDER_CASE_ID)
    manifest = CollectionManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now())
    ledger.append_event("case_opened", OPERATOR, {"run_id": manifest.run_id})

    dest = Path(report_builder_config.collection.output_dir) / REPORT_BUILDER_CASE_ID / "artifacts" / "prefetch" / "APP.pf"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"sahte artefakt")
    manifest.artifacts.append(
        CollectedArtifact(
            artifact_type_id="prefetch",
            source_path=r"C:\Windows\Prefetch\APP.pf",
            dest_path=str(dest),
            hash_value="0" * 64,
            hash_algorithm="sha256",
            size_bytes=14,
            collected_at_utc=_now(),
            collecting_user=OPERATOR,
            case_id=REPORT_BUILDER_CASE_ID,
        )
    )
    manifest.errors.append({"artifact_type_id": "prefetch", "message": "MISSING.pf bulunamadi"})
    manifest.ended_at_utc = _now()
    ledger.append_event("case_closed", OPERATOR, {"run_id": manifest.run_id})
    manifest.to_json_file(resolve_manifest_path(report_builder_config))
    return manifest


def _write_routing(report_builder_config) -> RoutingManifest:
    """Sahte bir yonlendirme kosusu."""
    routing = RoutingManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch",
            tool="pecmd",
            source_path="APP.pf",
            output_dir="parsed/pecmd/prefetch",
            exit_code=0,
            stdout_log_path="APP.pf.stdout.log",
            stderr_log_path="APP.pf.stderr.log",
            duration_seconds=0.5,
            processed_at_utc=_now(),
        )
    )
    routing.skipped.append({"artifact_type_id": "mft", "message": "arac konfigure edilmemis"})
    routing.to_json_file(resolve_routing_manifest_path(report_builder_config))
    return routing


def _write_detection(report_builder_config) -> DetectionManifest:
    """Sahte bir tespit kosusu: iki farkli seviyede bulgu."""
    detection = DetectionManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    for title, level in (("Mimikatz Detected", "critical"), ("Failed Logon", "low")):
        detection.findings.append(
            Finding(
                artifact_type_id="event_logs",
                source_path="Security.evtx",
                rule_title=title,
                level=level,
                timestamp="2026-01-02 03:04:05.678 +03:00",
                computer="WS-01",
                channel="Security",
                event_id="4688",
                details="ayrinti",
            )
        )
    detection.scanned.append(
        {"source_path": "Security.evtx", "finding_count": 2, "level_counts": {}}
    )
    detection.to_json_file(resolve_detection_manifest_path(report_builder_config))
    return detection


def _write_chainsaw(report_builder_config, rule_title="Mimikatz Detected", source_path="Security.evtx") -> DetectionManifest:
    """Sahte bir Chainsaw kosusu -- Hayabusa ile AYNI DetectionManifest/Finding
    semasini kullanir (bkz. detection/chainsaw_runner.py)."""
    chainsaw = DetectionManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    chainsaw.findings.append(
        Finding(
            artifact_type_id="event_logs", source_path=source_path, rule_title=rule_title,
            level="critical", timestamp="2026-01-02 03:04:05.678 +03:00", computer="WS-01",
            channel="Security", event_id="4688", details="ayrinti",
        )
    )
    chainsaw.scanned.append({"source_path": source_path, "finding_count": 1, "level_counts": {}})
    chainsaw.to_json_file(resolve_chainsaw_manifest_path(report_builder_config))
    return chainsaw


def _write_yara(report_builder_config, matched_source_path=None) -> YaraManifest:
    """Sahte bir YARA kosusu. matched_source_path verilirse, o dosyayi
    isaretleyen bir eslesme eklenir (korelasyon testleri icin)."""
    yara_manifest = YaraManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    if matched_source_path:
        yara_manifest.matches.append(
            YaraMatch(
                artifact_type_id="event_logs", source_path=matched_source_path,
                rule_name="Mimikatz_Strings", tags="malware",
            )
        )
    yara_manifest.scanned.append({"source_path": matched_source_path or "x", "match_count": 1})
    yara_manifest.to_json_file(resolve_yara_manifest_path(report_builder_config))
    return yara_manifest


def _write_capa(report_builder_config, rule_name="link function at runtime on Windows", source_path="C:/supheli/ornek.exe"):
    """Sahte bir capa kosusu -- YARA ile AYNI YaraManifest/YaraMatch semasini
    kullanir (bkz. detection/capa_runner.py)."""
    capa_manifest = YaraManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    capa_manifest.matches.append(
        YaraMatch(
            artifact_type_id="suspicious_binary", source_path=source_path,
            rule_name=rule_name, tags="T1129", meta="namespace=linking/runtime-linking",
        )
    )
    capa_manifest.scanned.append({"source_path": source_path, "match_count": 1})
    capa_manifest.to_json_file(resolve_capa_manifest_path(report_builder_config))
    return capa_manifest


def test_only_collection_leaves_other_sections_empty(report_builder_config):
    """Sadece toplama varsa yonlendirme/tespit bolumleri 'henuz calistirilmadi' olmali."""
    collection = _write_collection(report_builder_config)

    report = build_report(report_builder_config)

    assert report.case_id == REPORT_BUILDER_CASE_ID
    assert report.operator == OPERATOR
    assert report.description == "Rapor testi"
    assert report.collection.run_id == collection.run_id
    assert report.collection.artifact_count == 1
    assert report.collection.error_count == 1
    assert report.routing is None
    assert report.detection is None
    assert report.chain_status.is_valid
    assert [e.event_type for e in report.custody_events] == ["case_opened", "case_closed"]

    _, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    # Yonlendirme + tespit + Chainsaw + YARA + capa + watchlist hepsi henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 6
    assert "GEÇERLİ" in html


def test_routing_present_detection_missing(report_builder_config):
    """Toplama + yonlendirme var, tespit yok."""
    _write_collection(report_builder_config)
    routing = _write_routing(report_builder_config)

    report = build_report(report_builder_config)

    assert report.routing is not None
    assert report.routing.run_id == routing.run_id
    assert (report.routing.processed_count, report.routing.skipped_count) == (1, 1)
    assert report.detection is None

    _, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    # Tespit + Chainsaw + YARA + capa + watchlist henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 5


def test_all_three_layers_fill_findings_table(report_builder_config):
    """Toplama + yonlendirme + tespit: bulgu tablosu ve seviye dagilimi dolmali."""
    _write_collection(report_builder_config)
    _write_routing(report_builder_config)
    _write_detection(report_builder_config)

    report = build_report(report_builder_config)

    assert report.detection is not None
    assert report.detection.scanned_count == 1
    assert report.detection.finding_count == 2
    assert report.detection.level_counts == {"critical": 1, "low": 1}

    json_path, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    # Bulgu tablosu: kural/seviye/zaman/bilgisayar
    assert "Mimikatz Detected" in html and "Failed Logon" in html
    assert "WS-01" in html and "2026-01-02 03:04:05.678 +03:00" in html
    # Yonlendirme + tespit calisti, Chainsaw + YARA + capa + watchlist henuz calismamis.
    assert html.count("henüz çalıştırılmadı") == 4
    # Rapor tek basina okunabilir olmali: bulgular JSON'a da kopyalanir.
    reloaded = Report.from_json_file(json_path)
    assert [f.rule_title for f in reloaded.detection.findings] == [
        "Mimikatz Detected", "Failed Logon"
    ]
    assert reloaded.run_id == report.run_id
    assert len(reloaded.custody_events) == len(report.custody_events)


def test_html_has_both_yonetici_and_uzman_sekmeleri(report_builder_config):
    """report.html'de iki sekme de olmali; Yonetici sekmesi risk seviyesini,
    Uzman sekmesi teknik detayi (mevcut _detection_section) tasimali."""
    _write_collection(report_builder_config)
    _write_detection(report_builder_config)

    _, _, html_path = write_report(report_builder_config, build_report(report_builder_config))
    html = html_path.read_text(encoding="utf-8")

    assert "Yönetici Raporu" in html
    assert "Uzman Raporu" in html
    # Bir critical bulgu var -> risk Yuksek olmali (bkz. reporting/executive.py).
    assert "Risk Seviyesi: Yüksek" in html
    # Teknik detay (kural adi) SADECE uzman panelinde olmali, ama HTML tek
    # dosya oldugu icin string arama panel ayrimini test etmez -- en azindan
    # ikisinin de icerigi var mi kontrol ediliyor.
    assert "Mimikatz Detected" in html


def test_html_cover_page_has_case_info_and_blank_signature_lines(report_builder_config):
    """Kapak sayfasi vaka bilgisini + bos imza satirlarini icermeli, ve
    sekmelerin DISINDA olmali (hangi sekme secili olursa olsun gorunur)."""
    _write_collection(report_builder_config)

    _, _, html_path = write_report(report_builder_config, build_report(report_builder_config))
    html = html_path.read_text(encoding="utf-8")

    assert "Vaka Kapak Sayfası" in html
    assert "İnceleyen (Ad Soyad)" in html and "İmza" in html and "Tarih" in html
    assert REPORT_BUILDER_CASE_ID in html and OPERATOR in html
    # Kapak, sekme radyo dugmelerinden ONCE gelmeli (sekme secimine bagli
    # olmadan her zaman gorunmesi icin, bkz. renderer.py::_cover_section).
    assert html.index("Vaka Kapak Sayfası") < html.index('id="tab-exec"')


def test_timeline_is_built_from_real_pecmd_csv_and_rendered_in_html(report_builder_config):
    """routing_manifest.json'daki bir PECmd artefaktinin gercek Timeline
    CSV'si varsa, Report.timeline dolmali ve HTML'e islenmeli (bkz.
    reporting/timeline.py -- gercek PECmd 2026.5.0 ciktisindan alinan
    sutunlarla, aldigim_kararlar.md -> 'Birlesik zaman cizelgesi')."""
    _write_collection(report_builder_config)
    routing = RoutingManifest(case_id=REPORT_BUILDER_CASE_ID, started_at_utc=_now(), ended_at_utc=_now())
    output_dir = Path(report_builder_config.collection.output_dir) / "parsed" / "pecmd" / "prefetch"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8",
    )
    routing.processed.append(
        ProcessedArtifact(
            artifact_type_id="prefetch", tool="pecmd", source_path="APP.pf",
            output_dir=str(output_dir), exit_code=0, stdout_log_path="", stderr_log_path="",
            duration_seconds=0.1, processed_at_utc=_now(),
        )
    )
    routing.to_json_file(resolve_routing_manifest_path(report_builder_config))

    report = build_report(report_builder_config)

    assert len(report.timeline) == 1
    assert report.timeline[0].tool == "pecmd"
    assert report.timeline[0].timestamp == "2019-06-05 19:23:00"

    json_path, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "Zaman çizelgesi" in html
    assert "NOTEPAD.EXE" in html

    reloaded = Report.from_json_file(json_path)
    assert reloaded.timeline[0].tool == "pecmd"


def test_yara_present_and_correlated_with_sigma_finding(report_builder_config):
    """YARA VE Sigma ayni dosyayi isaretlerse Report.correlated_artifacts
    dolmali -- bkz. detection/correlation.py."""
    _write_collection(report_builder_config)
    detection = _write_detection(report_builder_config)
    matched_path = detection.findings[0].source_path
    _write_yara(report_builder_config, matched_source_path=matched_path)

    report = build_report(report_builder_config)

    assert report.yara is not None
    assert report.yara.match_count == 1
    assert len(report.correlated_artifacts) == 1
    assert report.correlated_artifacts[0].source_path == matched_path
    assert report.correlated_artifacts[0].yara_rule_names == ["Mimikatz_Strings"]

    json_path, _, _ = write_report(report_builder_config, report)
    reloaded = Report.from_json_file(json_path)
    assert reloaded.yara.matches[0].rule_name == "Mimikatz_Strings"
    assert reloaded.correlated_artifacts[0].source_path == matched_path


def test_chainsaw_present_and_agrees_with_hayabusa(report_builder_config):
    """Hayabusa VE Chainsaw AYNI kurali AYNI dosyada bulursa
    Report.engine_agreements dolmali -- bkz. detection/correlation.py."""
    _write_collection(report_builder_config)
    detection = _write_detection(report_builder_config)
    matched_path = detection.findings[0].source_path
    _write_chainsaw(report_builder_config, rule_title=detection.findings[0].rule_title, source_path=matched_path)

    report = build_report(report_builder_config)

    assert report.chainsaw is not None
    assert report.chainsaw.finding_count == 1
    assert len(report.engine_agreements) == 1
    assert report.engine_agreements[0].source_path == matched_path
    assert report.engine_agreements[0].rule_title == detection.findings[0].rule_title

    json_path, _, html_path = write_report(report_builder_config, report)
    reloaded = Report.from_json_file(json_path)
    assert reloaded.chainsaw.findings[0].rule_title == detection.findings[0].rule_title
    assert reloaded.engine_agreements[0].source_path == matched_path

    html = html_path.read_text(encoding="utf-8")
    assert "Chainsaw özeti" in html
    assert "Motor ittifakı (Hayabusa + Chainsaw)" in html
    assert matched_path in html


def test_chainsaw_without_hayabusa_has_no_engine_agreement(report_builder_config):
    """Sadece Chainsaw calismissa (Hayabusa yok) ittifak anlamsizdir, bos kalmali."""
    _write_collection(report_builder_config)
    _write_chainsaw(report_builder_config)

    report = build_report(report_builder_config)

    assert report.chainsaw is not None
    assert report.detection is None
    assert report.engine_agreements == []


def test_yara_without_detection_has_no_correlation(report_builder_config):
    """Sadece YARA calismissa (Sigma yok) korelasyon anlamsizdir, bos kalmali."""
    _write_collection(report_builder_config)
    _write_yara(report_builder_config, matched_source_path="C:/bir/dosya.evtx")

    report = build_report(report_builder_config)

    assert report.yara is not None
    assert report.detection is None
    assert report.correlated_artifacts == []


def test_capa_present_and_rendered_without_affecting_correlation(report_builder_config):
    """capa varsa Report.capa dolmali ve HTML'de gorunmeli; capa'nin YARA/
    Sigma korelasyonuna hic KATILMADIGI (bkz. aldigim_kararlar.md) ayrica
    dogrulanir -- capa tek basina calissa bile correlated_artifacts bos kalir."""
    _write_collection(report_builder_config)
    capa_manifest = _write_capa(report_builder_config)

    report = build_report(report_builder_config)

    assert report.capa is not None
    assert report.capa.match_count == 1
    assert report.capa.matches[0].rule_name == capa_manifest.matches[0].rule_name
    assert report.correlated_artifacts == []

    json_path, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "capa tarama özeti" in html
    assert capa_manifest.matches[0].rule_name in html

    reloaded = Report.from_json_file(json_path)
    assert reloaded.capa.matches[0].rule_name == capa_manifest.matches[0].rule_name


def test_sha256_sidecar_matches_written_report(report_builder_config):
    """report.json.sha256 GERCEKTEN report.json'un o anki iceriginin hash'i olmali."""
    _write_collection(report_builder_config)

    json_path, sha_path, _ = write_report(report_builder_config, build_report(report_builder_config))

    digest, filename = sha_path.read_text(encoding="utf-8").split()
    assert filename == "report.json"
    assert digest == hashlib.sha256(json_path.read_bytes()).hexdigest()

    # Rapor sonradan degistirilirse yan dosya artik tutmaz.
    json_path.write_text("degistirildi", encoding="utf-8")
    assert digest != hashlib.sha256(json_path.read_bytes()).hexdigest()


def test_broken_chain_is_reported_as_invalid(report_builder_config):
    """Elle degistirilmis bir custody satiri raporda GECERSIZ olarak gorunmeli."""
    _write_collection(report_builder_config)
    log_path = resolve_custody_log_path(report_builder_config)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    # Ikinci olayin operatoru degistiriliyor: JSON gecerli kalir, hash tutmaz.
    lines[1] = lines[1].replace(f'"operator":"{OPERATOR}"', '"operator":"saldirgan"')
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = build_report(report_builder_config)

    assert report.chain_status.is_valid is False
    assert report.chain_status.broken_at_event_id is not None
    # Olay listesi yine de TAM: rapor zincirin kirildigini soyler, olaylari gizlemez.
    assert len(report.custody_events) == 2

    _, _, html_path = write_report(report_builder_config, report)
    html = html_path.read_text(encoding="utf-8")
    assert "GEÇERSİZ" in html and "GEÇERLİ" not in html


def test_build_report_without_manifest_raises_typed_error(report_builder_config):
    """Toplama manifesti yoksa ham FileNotFoundError degil, tipli hata gelmeli."""
    with pytest.raises(ReportingError) as excinfo:
        build_report(report_builder_config)
    assert "triagechain collect" in str(excinfo.value)


def test_report_generation_does_not_touch_the_ledger(report_builder_config):
    """Rapor katmani salt-okunur: deftere yeni olay EKLEMEZ."""
    _write_collection(report_builder_config)
    log_path = resolve_custody_log_path(report_builder_config)
    before = log_path.read_bytes()

    write_report(report_builder_config, build_report(report_builder_config))

    assert log_path.read_bytes() == before
    assert len(list(read_events(log_path))) == 2


def test_cli_report_without_manifest_exits_with_code_2(tmp_path, capsys):
    """collect hic calistirilmamissa CLI net mesaj + cikis kodu 2 vermeli."""
    from triagechain.cli.main import main

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    data = {
        "case": {"case_id": REPORT_BUILDER_CASE_ID, "operator": OPERATOR},
        "collection": {
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(output_dir),
        },
    }
    config_path = tmp_path / "report_builder_config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    exit_code = main(["report", "--config", str(config_path)])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Toplama manifesti yok" in captured.err
    assert "triagechain collect" in captured.err
    assert not (output_dir / REPORT_BUILDER_CASE_ID / "report.json").exists()


# ============================================================================
# Kaynak: tests/unit/test_reporting_executive.py
# ============================================================================
# Yonetici Raporu ozeti: risk seviyesi kurali sadece Report'taki gercek
# sayilardan turer, hicbir sey uydurulmaz -- bkz. reporting/executive.py.



REPORTING_EXECUTIVE_NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _collection(artifact_count=5, error_count=0):
    return CollectionSummary(
        run_id="run-1", started_at_utc=REPORTING_EXECUTIVE_NOW, ended_at_utc=REPORTING_EXECUTIVE_NOW, artifact_count=artifact_count,
        error_count=error_count,
    )


def _chain(is_valid=True, message="zincir tutarli"):
    return ChainStatus(
        is_valid=is_valid, total_events=10, broken_at_event_id=None if is_valid else "evt-3",
        message=message,
    )


def _reporting_executive_finding(level):
    return Finding(
        artifact_type_id="event_logs", source_path="C:/x.evtx", rule_title="Kural",
        level=level, timestamp="2026-06-07 22:00:00", computer="WS-01", channel="Security",
        event_id="4688", details="",
    )


def _reporting_executive_detection(findings):
    return DetectionSummary(
        run_id="run-2", started_at_utc=REPORTING_EXECUTIVE_NOW, ended_at_utc=REPORTING_EXECUTIVE_NOW, scanned_count=1,
        finding_count=len(findings), level_counts={}, findings=list(findings),
    )


def _yara_summary(match_count):
    return YaraSummary(
        run_id="run-yara", started_at_utc=REPORTING_EXECUTIVE_NOW, ended_at_utc=REPORTING_EXECUTIVE_NOW, scanned_count=1,
        match_count=match_count,
    )


def _report(
    collection, chain_status, detection=None, yara=None, correlated=None,
    chainsaw=None, engine_agreements=None, capa=None,
):
    return Report(
        case_id="CASE-X", operator="e.demir", description="", collection=collection,
        chain_status=chain_status, detection=detection, yara=yara,
        correlated_artifacts=correlated or [], chainsaw=chainsaw,
        engine_agreements=engine_agreements or [], capa=capa,
    )


def test_gecersiz_zincir_her_zaman_kritik_dondurur():
    """Bulgu olmasa bile zincir bozuksa risk KRITIK olmali -- en ciddi sinyal."""
    report = _report(_collection(), _chain(is_valid=False, message="hash uyusmazligi"))
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "hash uyusmazligi" in reason


def test_yuksek_onemli_bulgu_yuksek_risk_dondurur():
    report = _report(
        _collection(), _chain(), _reporting_executive_detection([_reporting_executive_finding("critical"), _reporting_executive_finding("low")])
    )
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "1" in reason


def test_sadece_dusuk_onemli_bulgu_orta_risk_dondurur():
    report = _report(_collection(), _chain(), _reporting_executive_detection([_reporting_executive_finding("low"), _reporting_executive_finding("medium")]))
    level, _ = assess_risk(report)
    assert level == "Orta"


def test_bulgu_yok_ama_toplama_hatasi_var_dusuk_risk_dondurur():
    report = _report(_collection(error_count=2), _chain(), _reporting_executive_detection([]))
    level, _ = assess_risk(report)
    assert level == "Düşük"


def test_hicbir_sorun_yoksa_bulgu_yok_dondurur():
    report = _report(_collection(), _chain(), detection=None)
    level, _ = assess_risk(report)
    assert level == "Bulgu Yok"


def test_capa_eslesmeleri_risk_seviyesini_ETKILEMEZ():
    """capa 'yetenek' tespit eder, kotu amacli davranis degil -- gercek,
    zararsiz bir .exe'de bile onlarca capa kurali eslesir (bkz. aldigim_
    kararlar.md -> 'capa entegrasyonu'). Bulgu/YARA/korelasyon yoksa capa
    tek basina risk seviyesini yukseltmemeli."""
    report = _report(_collection(), _chain(), detection=None, capa=_yara_summary(35))
    level, _ = assess_risk(report)
    assert level == "Bulgu Yok"

    summary = build_executive_summary(report)
    assert summary.risk_level == "Bulgu Yok"


def test_korelasyon_varsa_kritik_dondurur_bulgu_seviyesinden_bagimsiz():
    """Iki motor da ayni dosyayi isaretlerse -- yuksek onemli bulgu olmasa
    bile -- risk KRITIK olmali (bkz. assess_risk dokstring'i)."""
    report = _report(
        _collection(), _chain(),
        detection=_reporting_executive_detection([_reporting_executive_finding("low")]),
        yara=_yara_summary(1),
        correlated=[CorrelatedArtifact(source_path="C:/a.evtx")],
    )
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "1 dosya" in reason


def test_motor_ittifaki_varsa_kritik_dondurur_bulgu_seviyesinden_bagimsiz():
    """Hayabusa VE Chainsaw ayni kurali ayni dosyada bulursa -- yuksek onemli
    bulgu olmasa bile -- risk KRITIK olmali (bkz. assess_risk dokstring'i)."""
    report = _report(
        _collection(), _chain(),
        detection=_reporting_executive_detection([_reporting_executive_finding("low")]),
        chainsaw=_reporting_executive_detection([_reporting_executive_finding("low")]),
        engine_agreements=[EngineAgreement(source_path="C:/a.evtx", rule_title="Kural")],
    )
    level, reason = assess_risk(report)
    assert level == "Kritik"
    assert "1 dosya" in reason


def test_chainsaw_yuksek_onemli_bulgu_tek_basina_yuksek_risk_dondurur():
    """Hayabusa hic calismamis olsa bile Chainsaw'in tek basina buldugu
    yuksek/kritik bulgu Yuksek risk demektir."""
    report = _report(
        _collection(), _chain(), detection=None,
        chainsaw=_reporting_executive_detection([_reporting_executive_finding("critical")]),
    )
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "1" in reason


def test_yara_eslesmesi_tek_basina_yuksek_risk_dondurur():
    """Sigma hic calismamis olsa bile bir YARA eslesmesi Yuksek risk demektir."""
    report = _report(_collection(), _chain(), detection=None, yara=_yara_summary(3))
    level, reason = assess_risk(report)
    assert level == "Yüksek"
    assert "3" in reason


def test_yonetici_ozeti_teknik_terim_icermeyen_bir_anlati_uretir():
    report = _report(
        _collection(artifact_count=7), _chain(), _reporting_executive_detection([_reporting_executive_finding("high")])
    )
    summary = build_executive_summary(report)

    assert summary.risk_level == "Yüksek"
    assert summary.artifact_count == 7
    assert summary.finding_count == 1
    assert summary.high_severity_count == 1
    assert summary.chain_is_valid is True
    assert "CASE-X" in summary.narrative
    assert "7 dosya" in summary.narrative
    # Teknik jargon ("manifest", "custody", "Sigma") yonetici ozetine sizmamali.
    for jargon in ("manifest", "custody", "Sigma", "run_id"):
        assert jargon not in summary.narrative


def test_ozet_chainsaw_bulgularini_hayabusa_ile_birlikte_sayar():
    """finding_count/high_severity_count Hayabusa VE Chainsaw'in toplami
    olmali -- ikisi de ayni DetectionSummary semasini kullaniyor."""
    report = _report(
        _collection(), _chain(),
        detection=_reporting_executive_detection([_reporting_executive_finding("high")]),
        chainsaw=_reporting_executive_detection([_reporting_executive_finding("critical"), _reporting_executive_finding("low")]),
    )
    summary = build_executive_summary(report)

    assert summary.finding_count == 3
    assert summary.high_severity_count == 2


def test_ozet_motor_ittifakini_anlatiya_ekler():
    report = _report(
        _collection(), _chain(),
        detection=_reporting_executive_detection([_reporting_executive_finding("low")]), chainsaw=_reporting_executive_detection([_reporting_executive_finding("low")]),
        engine_agreements=[EngineAgreement(source_path="C:/a.evtx", rule_title="Kural")],
    )
    summary = build_executive_summary(report)

    assert summary.engine_agreement_count == 1
    assert "bağımsız davranışsal tarama motoru" in summary.narrative


# ============================================================================
# Kaynak: tests/unit/test_router_mapping.py
# ============================================================================
# Arac esleme katalogu: her toplama hedefinin bir rotasi var mi, sablonlar tutarli mi.


# EZ araclarindan bir karsiligi olan ve bu yuzden rotasi bulunmasi ZORUNLU
# olan toplama hedefleri. Katalogda bunlardan biri rotasiz kalirsa test kirilir.
EXPECTED_TOOLS = {
    "mft": "mftecmd",
    "registry_system": "recmd",
    "registry_sam": "recmd",
    "registry_security": "recmd",
    "registry_software": "recmd",
    "registry_ntuser": "recmd",
    "registry_usrclass": "recmd",
    "event_logs": "evtxecmd",
    "prefetch": "pecmd",
}


def test_every_expected_artifact_type_has_a_route():
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, tool in EXPECTED_TOOLS.items():
        assert artifact_type_id in routes, f"{artifact_type_id} icin rota tanimli degil"
        assert routes[artifact_type_id].tool == tool


def test_routes_only_reference_known_collection_targets():
    # Ters yon: eslemede, toplama katalogunda karsiligi olmayan bir kimlik olmamali.
    routes = load_routes(router_catalog.default_catalog_path())
    collection_targets = load_catalog(collection_catalog.default_catalog_path())

    assert set(routes) <= set(collection_targets)


def test_arg_templates_use_both_placeholders():
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, route in routes.items():
        joined = " ".join(route.args)
        assert "{input}" in joined, f"{artifact_type_id}: girdi yer tutucusu yok"
        assert "{output_dir}" in joined, f"{artifact_type_id}: cikti yer tutucusu yok"
        # Sablonda calistirilabilirin kendisi durmaz; argv'nin basina runner ekler.
        assert not any(arg.lower().endswith(".exe") for arg in route.args)


def test_embedded_recmd_batch_file_is_present_and_reachable():
    """RECmd'in --bn dosyasi pakete GOMULU: kullanici hicbir sey
    konfigure etmeden de RECmd rotasi calisabilmeli."""
    batch_path = router_catalog.default_recmd_batch_path()

    assert batch_path.is_file(), f"gomulu toplu dosya yok: {batch_path}"
    assert batch_path.name == "DFIRBatch.reb"
    assert batch_path.parent == router_catalog.default_catalog_path().parent / "recmd_batch"
    # Kaynak/surum/SHA-256 kaydi da yaninda durmali (tekrarlanabilirlik).
    assert (batch_path.parent / "PROVENANCE.md").is_file()


def test_only_recmd_routes_ask_for_a_batch_file():
    """{batch_file} yalnizca RECmd rotalarinda olmali: diger EZ araclarinda
    ayri bir toplu/kural dosyasi kavrami yok."""
    routes = load_routes(router_catalog.default_catalog_path())

    for artifact_type_id, route in routes.items():
        uses_batch = "{batch_file}" in " ".join(route.args)
        assert uses_batch == (route.tool == "recmd"), artifact_type_id
        if uses_batch:
            # Yer tutucu her zaman --bn'in HEMEN ardindan gelmeli.
            assert route.args[route.args.index("--bn") + 1] == "{batch_file}"


# ============================================================================
# Kaynak: tests/unit/test_router_runner.py
# ============================================================================
# Yonlendirici: basarili kosu, hata kodu, zaman asimi, atlama ve yol kontrolu.
#
# Hicbir test gercek bir EZ Tools ikilisi calistirmaz: subprocess.run her
# testte unittest.mock ile yamalanir.
#




ROUTER_RUNNER_CASE_ID = "CASE-TEST-ROUTER"


def _router_runner_make_config(tmp_path, tools=None, timeout_seconds=300, recmd_batch_file=None):
    """Yonlendirme icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": ROUTER_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        router={
            "tools": tools or {},
            "timeout_seconds": timeout_seconds,
            "recmd_batch_file": recmd_batch_file,
        },
    )


def _router_runner_artifacts_root(config):
    return Path(config.collection.output_dir) / ROUTER_RUNNER_CASE_ID / "artifacts"


def _router_runner_make_artifact(config, artifact_type_id="prefetch", filename="APP.pf", dest_path=None):
    """Cikti agacinda gercek bir dosya olusturur ve manifest kaydini dondurur.

    dest_path verilirse dosya olusturulmaz; bu, agac disi yol testinde
    kullaniliyor.
    """
    if dest_path is None:
        dest = _router_runner_artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte artefakt")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id,
        source_path=rf"C:\Windows\Prefetch\{filename}",
        dest_path=dest_path,
        hash_value="0" * 64,
        hash_algorithm="sha256",
        size_bytes=14,
        collected_at_utc=datetime.now(timezone.utc),
        collecting_user="test.operator",
        case_id=ROUTER_RUNNER_CASE_ID,
    )


def _router_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=ROUTER_RUNNER_CASE_ID,
        started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc),
        artifacts=list(artifacts),
    )


def _router_runner_fake_tool(tmp_path, name="PECmd.exe"):
    """Diskte gercekten var olan, mutlak yollu sahte bir arac dosyasi."""
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _router_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", ROUTER_RUNNER_CASE_ID)


def _router_runner_completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _router_runner_assert_never_uses_shell(mock_run):
    """Guvenlik kurali #1: hicbir cagri shell=True ile yapilmamali."""
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        # Ilk konumsal arguman her zaman arguman LISTESI olmali, tek metin degil.
        assert isinstance(call.args[0], list)


def test_successful_run_is_recorded_as_processed(tmp_path):
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)})
    artifact = _router_runner_make_artifact(config)
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"], stdout=b"tamam", stderr=b"")
        routing = run_router(config, _router_runner_make_manifest([artifact]), ledger)

    assert len(routing.processed) == 1
    assert routing.errors == []
    assert routing.skipped == []

    processed = routing.processed[0]
    assert processed.tool == "pecmd"
    assert processed.exit_code == 0
    # stdout/stderr denetim izi diske yazilmis olmali.
    assert Path(processed.stdout_log_path).read_text(encoding="utf-8") == "tamam"
    assert Path(processed.stderr_log_path).is_file()

    # argv sablonu dogru dolduruldu mu?
    argv = mock_run.call_args.args[0]
    assert argv[0] == config.router.tools["pecmd"]
    assert argv[1] == "-f" and argv[2] == str(Path(artifact.dest_path).resolve())
    assert argv[3] == "--csv" and argv[4] == processed.output_dir
    _router_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["routing_started", "artifact_processed", "routing_completed"]
    assert verify_chain(ledger.log_path, ROUTER_RUNNER_CASE_ID).is_valid


def test_router_runner_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)})
    failing = _router_runner_make_artifact(config, filename="BAD.pf")
    ok = _router_runner_make_artifact(config, filename="GOOD.pf")
    ledger = _router_runner_ledger(tmp_path)

    def side_effect(argv, **kwargs):
        code = 1 if "BAD.pf" in argv[2] else 0
        return _router_runner_completed(argv, returncode=code, stderr=b"ayristirma bozuldu")

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        # Hicbir istisna yukari sizmamali.
        routing = run_router(config, _router_runner_make_manifest([failing, ok]), ledger)

    assert len(routing.errors) == 1
    assert routing.errors[0]["exit_code"] == 1
    assert routing.errors[0]["stderr_excerpt"] == "ayristirma bozuldu"
    # Kosu bir sonraki artefaktla devam etmis olmali.
    assert [p.source_path for p in routing.processed] == [str(Path(ok.dest_path).resolve())]
    assert mock_run.call_count == 2
    _router_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_error") == 1
    assert event_types.count("artifact_processed") == 1


def test_router_runner_timeout_is_a_non_fatal_error(tmp_path):
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)}, timeout_seconds=5)
    artifact = _router_runner_make_artifact(config)
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["PECmd.exe"], timeout=5)
        routing = run_router(config, _router_runner_make_manifest([artifact]), ledger)

    assert routing.processed == []
    assert len(routing.errors) == 1
    assert "5 saniyede bitmedi" in routing.errors[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_error") == 1
    assert verify_chain(ledger.log_path, ROUTER_RUNNER_CASE_ID).is_valid


def test_router_runner_tool_not_configured_is_skipped(tmp_path):
    # router.tools bos: 'pecmd' anahtari hic yok.
    config = _router_runner_make_config(tmp_path, tools={})
    artifact = _router_runner_make_artifact(config)
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _router_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert routing.processed == []
    assert routing.errors == []
    assert len(routing.skipped) == 1
    assert "konfigure edilmemis" in routing.skipped[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_skipped") == 1


def test_router_runner_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    # Yol mutlak (sema gecer) ama diskte boyle bir dosya yok.
    missing_exe = str(tmp_path / "olmayan" / "PECmd.exe")
    config = _router_runner_make_config(tmp_path, tools={"pecmd": missing_exe})
    artifact = _router_runner_make_artifact(config)
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _router_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert len(routing.skipped) == 1
    message = routing.skipped[0]["message"]
    # Iki durum birbirinden ayirt edilebilir olmali.
    assert "yolu bulunamadi" in message and missing_exe in message
    assert "konfigure edilmemis" not in message


def test_artifact_type_without_a_route_is_skipped_but_visible(tmp_path):
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)})
    artifact = _router_runner_make_artifact(config, artifact_type_id="fake_logs", filename="alpha.log")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _router_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert len(routing.skipped) == 1
    assert "tanimli bir arac yok" in routing.skipped[0]["message"]


def test_hive_transaction_log_files_are_never_routed_on_their_own(tmp_path):
    """Gercek bir makinede kesfedildi: SYSTEM.LOG1/.LOG2 gibi islem log
    dosyalari ayni registry_* hedefiyle toplanir ama RECmd'e TEK BASINA asla
    verilmemeli - onlar ana kovanla ayni dizinde durup kendiliginden
    kullanilir (bkz. docs/hatalar_ve_sonuclar.md)."""
    config = _router_runner_make_config(tmp_path, tools={"recmd": _router_runner_fake_tool(tmp_path, name="RECmd.exe")})
    log1 = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM.LOG1")
    log2 = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM.LOG2")
    hive = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"])
        routing = run_router(config, _router_runner_make_manifest([log1, log2, hive]), ledger)

    assert len(routing.skipped) == 2
    assert all("islem log dosyasi" in s["message"] for s in routing.skipped)
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[argv.index("-f") + 1] == str(Path(hive.dest_path).resolve())


def _recmd_config(tmp_path, **kwargs):
    """RECmd rotasini calistirabilen konfigurasyon (kovan hedefleri bu araca gider)."""
    return _router_runner_make_config(
        tmp_path, tools={"recmd": _router_runner_fake_tool(tmp_path, name="RECmd.exe")}, **kwargs
    )


def test_recmd_argv_uses_the_embedded_batch_file_by_default(tmp_path):
    """config'de bir sey yazmayan kullanici da RECmd'i calistirabilmeli:
    --bn, pakete gomulu DFIRBatch.reb ile doldurulur."""
    config = _recmd_config(tmp_path)
    hive = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"])
        routing = run_router(config, _router_runner_make_manifest([hive]), ledger)

    assert len(routing.processed) == 1
    argv = mock_run.call_args.args[0]
    # Yol argv'de TEK bir eleman olarak durmali (bosluk iceren bir yolun
    # ikiye bolunmedigi de boylece dogrulanmis oluyor).
    assert argv[argv.index("--bn") + 1] == str(router_catalog.default_recmd_batch_path())
    assert argv[argv.index("-f") + 1] == str(Path(hive.dest_path).resolve())
    _router_runner_assert_never_uses_shell(mock_run)


def test_configured_recmd_batch_file_overrides_the_embedded_default(tmp_path):
    custom = tmp_path / "kendi_toplu_dosyam.reb"
    custom.write_text("Description: kendi toplu dosyam", encoding="utf-8")
    config = _recmd_config(tmp_path, recmd_batch_file=str(custom))
    hive = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"])
        run_router(config, _router_runner_make_manifest([hive]), ledger)

    argv = mock_run.call_args.args[0]
    assert argv[argv.index("--bn") + 1] == str(custom)
    assert str(router_catalog.default_recmd_batch_path()) not in argv


def test_missing_batch_file_is_skipped_without_running_anything(tmp_path):
    """Toplu dosyanin varligi KOSU aninda kontrol edilir; yoksa bu olumcul
    degil, aracin kendisi bulunamadigindaki gibi bir 'atlandi' kaydidir."""
    missing = tmp_path / "olmayan" / "DFIRBatch.reb"
    config = _recmd_config(tmp_path, recmd_batch_file=str(missing))
    hive = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _router_runner_make_manifest([hive]), ledger)

    mock_run.assert_not_called()
    assert routing.processed == [] and routing.errors == []
    assert len(routing.skipped) == 1
    message = routing.skipped[0]["message"]
    assert "toplu dosyasi bulunamadi" in message and str(missing) in message

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_skipped") == 1
    assert verify_chain(ledger.log_path, ROUTER_RUNNER_CASE_ID).is_valid


def test_processed_event_carries_the_real_hash_of_the_batch_file(tmp_path):
    """Metodoloji izlenebilirligi: deftere yazilan sha256, GERCEKTEN kullanilan
    toplu dosyanin hash'i olmali - baska bir dosyaninki ya da sabit bir deger degil."""
    custom = tmp_path / "kural_seti.reb"
    custom.write_text("Description: izlenebilirlik testi", encoding="utf-8")
    config = _recmd_config(tmp_path, recmd_batch_file=str(custom))
    hive = _router_runner_make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    prefetch_tool = _router_runner_fake_tool(tmp_path)
    config.router.tools["pecmd"] = prefetch_tool
    pf = _router_runner_make_artifact(config, filename="APP.pf")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"])
        run_router(config, _router_runner_make_manifest([hive, pf]), ledger)

    processed = [e for e in read_events(ledger.log_path) if e.event_type == "artifact_processed"]
    by_tool = {e.payload["tool"]: e.payload for e in processed}

    assert by_tool["recmd"]["recmd_batch_path"] == str(custom)
    assert by_tool["recmd"]["recmd_batch_sha256"] == hash_file(custom)
    # Kural dosyasi kavrami olmayan araclarda bu alanlar HIC bulunmamali.
    assert "recmd_batch_sha256" not in by_tool["pecmd"]
    assert "recmd_batch_path" not in by_tool["pecmd"]
    # Mevcut alanlar (geriye donuk uyumluluk) korunmus olmali.
    for payload in by_tool.values():
        assert {"source_path", "output_dir", "exit_code", "duration_seconds"} <= set(payload)


def test_router_runner_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    """Guvenlik kurali #3: agac disindaki girdi icin hicbir sey CALISTIRILMAZ.

    Elle duzenlenmis / bozulmus bir manifest.json'i taklit eder.
    """
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)})
    # Vakanin artifacts kokunun kardesi: yol var ama agacin disinda.
    outside = tmp_path / "disarida" / "evil.pf"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"kotu")
    tampered = _router_runner_make_artifact(config, filename="evil.pf", dest_path=str(outside))
    # '..' ile agactan cikmaya calisan ikinci bir kalip.
    traversal = _router_runner_make_artifact(
        config,
        filename="traversal.pf",
        dest_path=str(_router_runner_artifacts_root(config) / "prefetch" / ".." / ".." / ".." / "escape.pf"),
    )
    legit = _router_runner_make_artifact(config, filename="GOOD.pf")
    ledger = _router_runner_ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _router_runner_completed(["x"])
        routing = run_router(config, _router_runner_make_manifest([tampered, traversal, legit]), ledger)

    # Iki bozuk girdi de hata olarak kaydedilmis olmali.
    rejected = {e["source_path"] for e in routing.errors}
    assert rejected == {tampered.dest_path, traversal.dest_path}
    for entry in routing.errors:
        assert "cikti agaci disinda" in entry["message"]

    # ...ve bu girdiler icin subprocess HIC cagrilmamis olmali.
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[2] == str(Path(legit.dest_path).resolve())
    assert str(outside) not in argv
    assert "escape.pf" not in " ".join(argv)
    assert [p.source_path for p in routing.processed] == [str(Path(legit.dest_path).resolve())]
    _router_runner_assert_never_uses_shell(mock_run)


def test_output_dir_creation_failure_is_fatal_router_error(tmp_path):
    """Cikti dizini olusturulamazsa (or. yolun bir parcasi aslinda bir dosya)
    bu olumcul sayilir ve tipli RouterError olarak yukselir; ham OSError
    kullaniciya sizmaz."""
    config = _router_runner_make_config(tmp_path, tools={"pecmd": _router_runner_fake_tool(tmp_path)})
    artifact = _router_runner_make_artifact(config)
    ledger = _router_runner_ledger(tmp_path)

    # "parsed" adinda bir DOSYA onceden var: alti icin dizin acilamaz.
    parsed_as_file = Path(config.collection.output_dir) / ROUTER_RUNNER_CASE_ID / "parsed"
    parsed_as_file.parent.mkdir(parents=True, exist_ok=True)
    parsed_as_file.write_text("bu bir dizin degil", encoding="utf-8")

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        with pytest.raises(RouterError):
            run_router(config, _router_runner_make_manifest([artifact]), ledger)
        mock_run.assert_not_called()


def test_relative_tool_path_is_rejected_at_config_time():
    """Guvenlik kurali #2: goreli arac yolu semada reddedilir."""
    with pytest.raises(ValueError) as exc_info:
        TriageChainConfig(
            case={"case_id": ROUTER_RUNNER_CASE_ID, "operator": "test.operator"},
            collection={"targets": ["prefetch"], "output_dir": "."},
            router={"tools": {"pecmd": "PECmd.exe"}},
        )
    assert "pecmd" in str(exc_info.value)


def test_absolute_tool_path_does_not_need_to_exist_at_config_time(tmp_path):
    # Kullanici araclari kurmadan once konfigurasyonu yazmis olabilir.
    config = _router_runner_make_config(tmp_path, tools={"pecmd": str(tmp_path / "henuz" / "yok.exe")})

    assert config.router.timeout_seconds == 300


# ============================================================================
# Kaynak: tests/unit/test_selector.py
# ============================================================================
# Hedef cozumleyici: glob acilimi, duz yol, bos eslesme ve bilinmeyen kimlik.




SELECTOR_FAKE_ARTIFACTS = Path(__file__).resolve().parents[0] / "fixtures" / "fake_artifacts"


@pytest.fixture
def test_catalog(tmp_path):
    """Gercek Windows dosyalarina ihtiyac duymayan, teste ozel katalog."""
    catalog = {
        "targets": [
            {
                "id": "fake_logs",
                "category": "test",
                "requires_vss": False,
                "paths": [str(SELECTOR_FAKE_ARTIFACTS / "*.log")],
                "description": "Sahte log dosyalari (glob)",
            },
            {
                "id": "fake_notes",
                "category": "test",
                "requires_vss": False,
                "paths": [str(SELECTOR_FAKE_ARTIFACTS / "notes.txt")],
                "description": "Tek dosya, glob yok",
            },
            {
                "id": "fake_missing",
                "category": "test",
                "requires_vss": False,
                "paths": [str(SELECTOR_FAKE_ARTIFACTS / "*.hicyok")],
                "description": "Hicbir seye uymayan glob",
            },
        ]
    }
    path = tmp_path / "test_targets.yaml"
    path.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    return path


def test_glob_expands_to_matching_files(test_catalog):
    (target,) = resolve_targets(["fake_logs"], test_catalog)

    assert [p.name for p in target.paths] == ["alpha.log", "beta.log"]
    assert target.requires_vss is False
    assert target.category == "test"


def test_plain_path_is_returned_as_is(test_catalog):
    (target,) = resolve_targets(["fake_notes"], test_catalog)

    assert len(target.paths) == 1
    assert target.paths[0].name == "notes.txt"


def test_glob_with_no_match_is_not_an_error(test_catalog):
    (target,) = resolve_targets(["fake_missing"], test_catalog)

    assert target.paths == []


def test_selector_unknown_target_id_raises_config_error(test_catalog):
    with pytest.raises(ConfigError) as exc_info:
        resolve_targets(["fake_logs", "hayali"], test_catalog)
    assert "hayali" in str(exc_info.value)


def test_multiple_targets_keep_requested_order(test_catalog):
    resolved = resolve_targets(["fake_notes", "fake_logs"], test_catalog)

    assert [t.target_id for t in resolved] == ["fake_notes", "fake_logs"]


def test_env_variable_expansion(monkeypatch):
    monkeypatch.setenv("WinDir", r"C:\Windows")
    assert expand_pattern(r"%WinDir%\Prefetch\readpf.txt") == [
        Path(r"C:\Windows\Prefetch\readpf.txt")
    ]


def test_env_variable_fallback_when_not_set(monkeypatch):
    # Windows disinda bu degisken tanimli olmayabilir; yedek deger devreye girmeli.
    monkeypatch.delenv("SystemDrive", raising=False)
    assert str(expand_pattern("%SystemDrive%/x")[0]).startswith("C:")
    assert "SystemDrive" not in os.environ


def test_source_root_rebases_env_variable_pattern(monkeypatch, tmp_path):
    # Ice aktarma modu: %WinDir% gibi bir degisken de, hardcoded 'C:' gibi,
    # AYNI surucu-kok mantigiyla source_root altina yeniden koklendirilmeli
    # (bkz. collection/selector.py -> expand_pattern dokstring'i).
    monkeypatch.setenv("WinDir", r"C:\Windows")
    result = expand_pattern(r"%WinDir%\System32\config\SYSTEM", source_root=tmp_path)
    assert result == [tmp_path / "Windows" / "System32" / "config" / "SYSTEM"]


def test_source_root_rebases_hardcoded_drive_letter_pattern(tmp_path):
    # registry_ntuser/registry_usrclass gibi hedefler %SystemDrive% DEGIL,
    # sabit 'C:\Users\*\...' kullaniyor -- source_root ikisini de AYNI
    # sekilde ele almali (drive-split + yeniden koklendirme).
    (tmp_path / "Users" / "kaan").mkdir(parents=True)
    (tmp_path / "Users" / "kaan" / "NTUSER.DAT").write_bytes(b"x")
    result = expand_pattern(r"C:\Users\*\NTUSER.DAT", source_root=tmp_path)
    assert result == [tmp_path / "Users" / "kaan" / "NTUSER.DAT"]


def test_resolve_targets_passes_source_root_through(test_catalog, tmp_path):
    # 'fake_notes' hedefi mutlak, sabit bir yola (SELECTOR_FAKE_ARTIFACTS/notes.txt)
    # isaret ediyor -- asil kontrol, resolve_targets'in source_root
    # parametresini GERCEKTEN expand_pattern'a ilettigi (drive-split sonrasi
    # kok source_root'a tasindigi icin path artik SELECTOR_FAKE_ARTIFACTS altinda
    # DEGIL, tmp_path altinda olmali). Var-olmayan bir dosyaya isaret etmesi
    # sorun degil: duz (glob'suz) bir yol icin varlik kontrolu yapilmiyor.
    (target,) = resolve_targets(["fake_notes"], test_catalog, source_root=tmp_path)
    assert target.paths[0] != SELECTOR_FAKE_ARTIFACTS / "notes.txt"
    assert str(target.paths[0]).startswith(str(tmp_path))


# ============================================================================
# Kaynak: tests/unit/test_tag_store.py
# ============================================================================
# gui_qt/tag_store.py'nin testleri -- Qt gerektirmez, saf dosya sistemi
# mantigi.



def _make_finding(**overrides) -> Finding:
    defaults = dict(
        artifact_type_id="event_logs",
        source_path="C:/case/artifacts/event_logs/Security.evtx",
        rule_title="Şüpheli Oturum Açma",
        level="high",
        timestamp="2026-06-07T22:10:00Z",
        computer="WORKSTATION-1",
        channel="Security",
        event_id="4625",
        details="LogonType=3",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_yara_match(**overrides) -> YaraMatch:
    defaults = dict(
        artifact_type_id="suspicious_binary",
        source_path="C:/case/artifacts/suspicious_binary/notepad.exe",
        rule_name="Mimikatz_Strings",
        tags="malware,mimikatz",
        meta="author=test",
    )
    defaults.update(overrides)
    return YaraMatch(**defaults)


def test_target_id_for_finding_kararli():
    """Ayni verilerle iki ayri cagri AYNI ID'yi vermeli -- isaret ikinci bir
    'Tara' kosusundan sonra da kaybolmamali."""
    finding = _make_finding()
    assert tag_store.target_id_for_finding(finding) == tag_store.target_id_for_finding(finding)


def test_target_id_for_finding_farkli_bulgular_farkli_id():
    a = _make_finding()
    b = _make_finding(event_id="4624")
    assert tag_store.target_id_for_finding(a) != tag_store.target_id_for_finding(b)


def test_target_id_for_yara_match_kararli_ve_ayirt_edici():
    a = _make_yara_match()
    b = _make_yara_match()
    c = _make_yara_match(rule_name="Baska_Kural")
    assert tag_store.target_id_for_yara_match(a) == tag_store.target_id_for_yara_match(b)
    assert tag_store.target_id_for_yara_match(a) != tag_store.target_id_for_yara_match(c)


def test_load_tags_dosya_yoksa_bos_sozluk_doner(tmp_path):
    assert tag_store.load_tags(tmp_path / "yok.json") == {}


def test_set_tag_ve_load_tags_round_trip(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "Şüpheli - rapora eklenecek", "yasar")

    tags = tag_store.load_tags(path)

    assert "abc123" in tags
    assert tags["abc123"].note == "Şüpheli - rapora eklenecek"
    assert tags["abc123"].tagged_by == "yasar"
    assert tags["abc123"].tagged_at_utc


def test_set_tag_var_olani_gunceller(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "ilk not", "yasar")
    tag_store.set_tag(path, "abc123", "güncellenmiş not", "yasar")

    tags = tag_store.load_tags(path)

    assert len(tags) == 1
    assert tags["abc123"].note == "güncellenmiş not"


def test_remove_tag(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "abc123", "not", "yasar")

    tag_store.remove_tag(path, "abc123")

    assert tag_store.load_tags(path) == {}


def test_remove_tag_olmayan_hedef_sessizce_gecer(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.remove_tag(path, "hic-yok")  # patlamamali
    assert not path.exists()


def test_load_tags_bozuk_dosyada_patlamiyor_bos_doner(tmp_path):
    path = tmp_path / "tags.json"
    path.write_text("bu gecerli bir json degil {{{", encoding="utf-8")

    assert tag_store.load_tags(path) == {}


def test_birden_fazla_hedef_bagimsiz_calisir(tmp_path):
    path = tmp_path / "tags.json"
    tag_store.set_tag(path, "id1", "not1", "yasar")
    tag_store.set_tag(path, "id2", "not2", "yasar")

    tags = tag_store.load_tags(path)

    assert set(tags.keys()) == {"id1", "id2"}
    assert tags["id1"].note == "not1"
    assert tags["id2"].note == "not2"


# ============================================================================
# Kaynak: tests/unit/test_theme.py
# ============================================================================
# theme.py'nin acik/koyu tema gecisinin (set_mode/get_mode) testleri.
#
# theme modulu SUREC GENELINDE PAYLASILAN modul-seviyesi durum tasiyor --
# her test sonunda "dark"a DONDURULUYOR (autouse fixture) ki bu dosyadaki
# testler diger test dosyalarinin (orn. test_gui_qt.py) varsaydigi varsayilan
# temayi BOZMASIN.
#




@pytest.fixture(autouse=True)
def _reset_theme_after_test():
    yield
    t.set_mode("dark")


def test_varsayilan_mod_koyu():
    assert t.get_mode() == "dark"
    assert t.ACCENT == "#3FB950"


def test_set_mode_acik_temaya_geciyor():
    t.set_mode("light")

    assert t.get_mode() == "light"
    assert t.BG_SURFACE == "#FFFFFF"
    assert t.TEXT_MAIN == "#1F2328"


def test_set_mode_gecersiz_deger_koyuya_duser():
    t.set_mode("purple")
    assert t.get_mode() == "dark"


def test_set_mode_dark_ve_light_ayni_anahtar_kumesini_tasir():
    dark_keys = set(t.DARK.keys())
    light_keys = set(t.LIGHT.keys())
    assert dark_keys == light_keys


def test_accent_tint_tema_degisince_yeniden_hesaplanir():
    dark_tint = t.ACCENT_TINT
    t.set_mode("light")
    light_tint = t.ACCENT_TINT

    assert dark_tint != light_tint
    assert light_tint.startswith("rgba(26, 127, 55,")  # #1A7F37'nin RGB'si


def test_risk_colors_tema_degisince_yeniden_hesaplanir():
    assert t.RISK_COLORS["Kritik"] == "#F85149"

    t.set_mode("light")

    assert t.RISK_COLORS["Kritik"] == "#D1242F"
    assert set(t.RISK_COLORS.keys()) == {"Bulgu Yok", "Düşük", "Orta", "Yüksek", "Kritik"}


def test_text_on_accent_iki_temada_da_farkli_ve_dogru():
    assert t.TEXT_ON_ACCENT == t.DARK["BG_DARKEST"]  # koyuda: en koyu renk
    t.set_mode("light")
    assert t.TEXT_ON_ACCENT == "#FFFFFF"


def test_border_iki_temada_da_ayni_deger():
    # Olculdugunde (bkz. aldigim_kararlar.md) ayni gri her iki temada da
    # 3:1'i rahatca geciyor, ayri bir deger icat edilmedi.
    assert t.DARK["BORDER"] == t.LIGHT["BORDER"] == "#6A727E"


def test_base_stylesheet_aktif_temanin_renklerini_kullanir():
    dark_css = t.base_stylesheet()
    assert t.DARK["BG_DARKEST"] in dark_css

    t.set_mode("light")
    light_css = t.base_stylesheet()
    assert t.LIGHT["BG_DARKEST"] in light_css
    assert t.DARK["BG_DARKEST"] not in light_css


# -- WCAG 2.1 kontrast dogrulamasi (acik tema) -------------------------------
# Koyu temanin degerleri onceki oturumlarda dogrulanmisti; acik tema
# BURADA, GERCEK sRGB luminance formuluyle (tahmin degil) dogrulaniyor.

def _contrast(hex1: str, hex2: str) -> float:
    def srgb_to_linear(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(hex_color: str) -> float:
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
        r, g, b = srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    l1, l2 = luminance(hex1), luminance(hex2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize(
    "fg_key, bg_key, minimum",
    [
        ("ACCENT_TEXT", "BG_DARKEST", 4.5),
        ("ACCENT_TEXT", "BG_SURFACE", 4.5),
        ("TEXT_MAIN", "BG_DARKEST", 4.5),
        ("TEXT_SECONDARY", "BG_SURFACE", 4.5),
        ("ERROR", "BG_SURFACE", 4.5),
        ("ATTENTION", "BG_SURFACE", 4.5),
        ("INFO", "BG_SURFACE", 4.5),
        ("BORDER", "BG_LAYER2", 3.0),
    ],
)
def test_acik_tema_wcag_aa_kontrasti_geciyor(fg_key, bg_key, minimum):
    ratio = _contrast(t.LIGHT[fg_key], t.LIGHT[bg_key])
    assert ratio >= minimum, f"{fg_key}/{bg_key} = {ratio:.2f}:1 (>= {minimum} olmali)"


def test_acik_temada_buton_yazisi_dolguya_karsi_yeterli_kontrast():
    ratio = _contrast(t.LIGHT["TEXT_ON_ACCENT"], t.LIGHT["ACCENT"])
    assert ratio >= 4.5, f"TEXT_ON_ACCENT/ACCENT = {ratio:.2f}:1"


# ============================================================================
# Kaynak: tests/unit/test_timeline.py
# ============================================================================
# Birlesik zaman cizelgesi: MFTECmd/RECmd/EvtxECmd/PECmd CSV ciktilarinin
# normallestirilip kronolojik olarak birlestirilmesi.
#
# Hicbir test gercek bir EZ Tools ikilisi calistirmaz -- CSV fixture'lari
# gercek MFTECmd/RECmd/EvtxECmd/PECmd 2026.5.0 (net9) ciktilarindan alinan
# GERCEK sutun basliklarini kullanir (gercek bir $MFT ornegi, NTUSER.DAT
# registry kovani, UACME_59_Sysmon.evtx ve bir NOTEPAD.EXE prefetch ornegine
# karsi calistirilarak dogrulandi, bkz. docs/aldigim_kararlar.md -> "Birlesik
# zaman cizelgesi"). Router'in gercek dosya adlandirma deseni de (zaman
# damgali "<...>_Output.csv" / PECmd icin ayrica "<...>_Output_Timeline.csv")
# fixture dosya adlarinda BIREBIR korunuyor.
#



TIMELINE_NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _artifact(tool, output_dir, source_path="C:/kaynak/x"):
    return ProcessedArtifact(
        artifact_type_id="x", tool=tool, source_path=source_path, output_dir=str(output_dir),
        exit_code=0, stdout_log_path="", stderr_log_path="", duration_seconds=0.1,
        processed_at_utc=TIMELINE_NOW,
    )


def _routing(*artifacts):
    return RoutingManifest(case_id="CASE-X", started_at_utc=TIMELINE_NOW, processed=list(artifacts))


def test_mftecmd_expands_macb_timestamps_into_separate_events(tmp_path):
    csv_path = tmp_path / "20260101000000_MFTECmd_$MFT_Output.csv"
    header = (
        "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,"
        "FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,"
        "SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,"
        "LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,"
        "LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,"
        "ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,"
        "ResidentDataHex,ResidentDataASCII\n"
    )
    row = (
        "10,1,True,5,5,.\\Pictures,McCoy.jpg,.jpg,1024,1,,False,False,False,False,False,"
        "False,,DosWindows,"
        "1995-07-01 15:30:00.0000000,,"  # Created0x10, Created0x30
        "1995-07-01 15:32:34.0000000,,"  # LastModified0x10, LastModified0x30
        "1995-07-01 15:33:00.0000000,,"  # LastRecordChange0x10, LastRecordChange0x30
        ",,"  # LastAccess0x10 BOS -- bu MACB harfi olay URETMEMELI
        "0,123,256,,,,samples/mft,,,\n"
    )
    csv_path.write_text(header + row, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("mftecmd", tmp_path)))

    # LastAccess0x10 bos oldugu icin 4 degil 3 olay uretilmeli.
    assert len(events) == 3
    activities = {e.activity for e in events}
    assert activities == {"B", "M", "C"}
    modified = next(e for e in events if e.activity == "M")
    assert modified.timestamp == "1995-07-01 15:32:34.0000000"
    assert modified.detail == ".\\Pictures\\McCoy.jpg"
    assert modified.tool == "mftecmd"


def test_pecmd_reads_its_own_timeline_csv_not_the_main_csv(tmp_path):
    # PECmd'nin ANA CSV'si de ayni dizinde durur ama _parse_pecmd SADECE
    # _Output_Timeline.csv'yi okumali -- yanlislikla ana CSV'yi RunTime
    # sutunu yokken parse edip sessizce 0 olay uretmemeli.
    (tmp_path / "20260101000000_PECmd_Output.csv").write_text(
        "Note,SourceFilename,ExecutableName,RunCount\n,notepad.pf,NOTEPAD.EXE,2\n",
        encoding="utf-8-sig",
    )
    (tmp_path / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n"
        "2019-06-05 19:55:04,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8-sig",
    )

    events = build_timeline(_routing(_artifact("pecmd", tmp_path)))

    assert len(events) == 2
    assert {e.timestamp for e in events} == {"2019-06-05 19:23:00", "2019-06-05 19:55:04"}
    assert all(e.tool == "pecmd" and "NOTEPAD.EXE" in e.detail for e in events)


def test_evtxecmd_uses_mapdescription_falls_back_to_event_id(tmp_path):
    csv_path = tmp_path / "20260101000000_EvtxECmd_Output.csv"
    header = (
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,"
        "ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,RemoteHost,"
        "PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,"
        "ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload\n"
    )
    with_map = (
        "1,2164891,2020-10-05 20:43:58.4505228,10,Info,Microsoft-Windows-Sysmon,"
        "Microsoft-Windows-Sysmon/Operational,1,2,WS-01,0,,ProcessAccess,,,,,,,,,,"
        "False,sample.evtx,Classic,0,{}\n"
    )
    without_map = (
        "2,2164892,2020-10-05 20:43:58.4513146,1,Info,Microsoft-Windows-Sysmon,"
        "Microsoft-Windows-Sysmon/Operational,1,2,WS-01,0,,,,,,,,,,,"
        "False,sample.evtx,Classic,0,{}\n"
    )
    csv_path.write_text(header + with_map + without_map, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("evtxecmd", tmp_path)))

    assert len(events) == 2
    described = next(e for e in events if e.activity == "10")
    assert described.description == "ProcessAccess"
    assert "Microsoft-Windows-Sysmon" in described.detail
    fallback = next(e for e in events if e.activity == "1")
    assert fallback.description == "Olay 1"


def test_recmd_deduplicates_by_key_path_and_timestamp(tmp_path):
    csv_path = tmp_path / "20260101000000_RECmd_Batch_DFIRBatch_Output.csv"
    header = (
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
        "ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,"
        "PluginDetailFile\n"
    )
    # Ayni anahtarin ALTINDAKI iki farkli deger -- gercek RECmd ciktisinda
    # oldugu gibi AYNI LastWriteTimestamp'i tasiyor (bkz. modul dokstring'i).
    same_key_1 = (
        "NTUSER.DAT,NtUser,MountPoints2,Devices,"
        "Software\\Microsoft\\Explorer\\MountPoints2,_LabelFromReg,RegSz,User drive,,,"
        "Mount Points,True,False,2014-05-20 14:23:55.4574741,\n"
    )
    same_key_2 = (
        "NTUSER.DAT,NtUser,MountPoints2,Devices,"
        "Software\\Microsoft\\Explorer\\MountPoints2,_LabelFromDesktopINI,RegSz,,,,"
        "Mount Points,True,False,2014-05-20 14:23:55.4574741,\n"
    )
    different_key = (
        "NTUSER.DAT,NtUser,System Info,System Info,"
        "Software\\Microsoft\\Windows Media\\WMSDK,ComputerName,RegSz,HAXOR4,,,"
        "Computer name,False,False,2014-05-20 14:19:40.2296199,\n"
    )
    csv_path.write_text(header + same_key_1 + same_key_2 + different_key, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("recmd", tmp_path)))

    # 3 deger satiri var ama sadece 2 BENZERSIZ (KeyPath, LastWriteTimestamp) cifti.
    assert len(events) == 2
    assert {e.description for e in events} == {"MountPoints2", "System Info"}


def test_missing_output_csv_is_not_an_error(tmp_path):
    """Bir arac hic calismamis/cikti uretmemis olabilir -- olumcul degil,
    sadece o kaynaktan hic olay gelmez (bkz. modul dokstring'i)."""
    events = build_timeline(_routing(_artifact("mftecmd", tmp_path)))
    assert events == []


def test_unknown_tool_name_is_silently_skipped(tmp_path):
    events = build_timeline(_routing(_artifact("bilinmeyen_arac", tmp_path)))
    assert events == []


def test_events_from_multiple_tools_are_merged_and_sorted_chronologically(tmp_path):
    mft_dir, pf_dir = tmp_path / "mft", tmp_path / "pf"
    mft_dir.mkdir()
    pf_dir.mkdir()
    (mft_dir / "20260101000000_MFTECmd_$MFT_Output.csv").write_text(
        "FileName,ParentPath,Created0x10,LastModified0x10,LastRecordChange0x10,LastAccess0x10\n"
        "old.txt,.,2020-01-01 00:00:00.0000000,,,\n",
        encoding="utf-8-sig",
    )
    (pf_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n2025-01-01 00:00:00,APP.EXE\n", encoding="utf-8-sig",
    )

    events = build_timeline(
        _routing(_artifact("pecmd", pf_dir), _artifact("mftecmd", mft_dir))
    )

    assert [e.tool for e in events] == ["mftecmd", "pecmd"]
    assert events[0].timestamp < events[1].timestamp


# ============================================================================
# Kaynak: tests/unit/test_vss_snapshot.py
# ============================================================================
# VssSnapshot: WMI (pywin32) tabanli golge kopya olusturma/silme testleri.
#
# Hicbir test gercek bir golge kopya olusturmaz ve GERCEK pywin32'ye de
# ihtiyac duymaz: `win32com.client` sys.modules'a sahte bir modul olarak
# enjekte ediliyor (bkz. `fake_win32com` fixture'i). Bu sart, cunku CI
# `ubuntu-latest` uzerinde calisiyor ve orada pywin32 kurulu olmayacak.
#
# Gercek makinede dogrulanan bulgular icin bkz. docs/hatalar_ve_sonuclar.md.
#




SHADOW_ID = "{B6A8C555-5A91-40EF-9F04-7A5A59C338BA}"
DEVICE_PATH = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7"


@pytest.fixture
def fake_win32com(monkeypatch):
    """Sahte bir `win32com.client` enjekte edip modulu taze import eder.

    Modul-seviyesindeki `try: import win32com.client` satirinin sahte modulu
    yakalamasi icin `vss_snapshot` her testte yeniden yukleniyor; testten
    sonra da gercek/orijinal duruma geri donduruluyor.
    """
    fake_client = MagicMock()
    monkeypatch.setitem(sys.modules, "win32com", MagicMock(client=fake_client))
    monkeypatch.setitem(sys.modules, "win32com.client", fake_client)

    import triagechain.collection.vss_snapshot as mod

    importlib.reload(mod)
    yield fake_client, mod
    monkeypatch.undo()  # once sahte moduller kaldirilsin...
    importlib.reload(mod)  # ...sonra modul gercek durumuyla yeniden yuklensin


def _wire_wmi(fake_client, return_value=0, query_results=None):
    """Dogrulanmis WMI cagri zincirini sahte nesnelerle kurar.

    Donen `shadow_instance`, `__exit__`'te `Delete_()` cagrilacak nesnedir.
    """
    out_values = {"ReturnValue": return_value, "ShadowID": SHADOW_ID}
    out_params = MagicMock()
    out_params.Properties_.side_effect = lambda name: MagicMock(Value=out_values[name])

    shadow_instance = MagicMock()
    shadow_instance.Properties_.side_effect = lambda name: MagicMock(
        Value={"DeviceObject": DEVICE_PATH}[name]
    )

    wmi = MagicMock()
    wmi.ExecMethod.return_value = out_params
    wmi.ExecQuery.return_value = (
        [shadow_instance] if query_results is None else query_results
    )
    fake_client.GetObject.return_value = wmi
    return wmi, shadow_instance


def test_enter_creates_snapshot_and_exit_deletes_it(fake_win32com):
    fake_client, mod = fake_win32com
    wmi, shadow_instance = _wire_wmi(fake_client)

    with mod.VssSnapshot(volume="C:") as snap:
        assert snap.shadow_id == SHADOW_ID
        assert snap.device_path == DEVICE_PATH
        assert str(snap.translate(r"C:\$MFT")) == DEVICE_PATH + r"\$MFT"

    # Volume, WMI'nin bekledigi bicimde (surucu harfi + ters slash) verilmis olmali.
    in_params = wmi.Get.return_value.Methods_.return_value.InParameters.SpawnInstance_.return_value
    assert in_params.Volume == "C:\\"
    assert in_params.Context == "ClientAccessible"
    # Silme, ayri bir vssadmin cagrisi degil, WMI orneginin kendi metodu.
    shadow_instance.Delete_.assert_called_once_with()


def test_enter_raises_collection_error_on_nonzero_return_value(fake_win32com):
    fake_client, mod = fake_win32com
    _wire_wmi(fake_client, return_value=8)

    with pytest.raises(CollectionError):
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover - __enter__ hata firlatir, buraya gelinmez


def test_enter_wraps_raw_com_exception_in_collection_error(fake_win32com):
    """Ham COM/WMI istisnasi disari sizmamali, CollectionError'a sarilmali."""
    fake_client, mod = fake_win32com
    raw = Exception("COM hatasi: erisim reddedildi")
    fake_client.GetObject.side_effect = raw

    with pytest.raises(CollectionError) as excinfo:
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover
    assert excinfo.value.__cause__ is raw


def test_enter_raises_collection_error_when_pywin32_missing(fake_win32com):
    """pywin32 hic kurulu degilmis gibi (Linux) davranildiginda anlamli hata."""
    _, mod = fake_win32com
    mod.win32com = None

    with pytest.raises(CollectionError, match="pywin32"):
        with mod.VssSnapshot(volume="C:"):
            pass  # pragma: no cover


def test_enter_raises_collection_error_on_real_timeout(fake_win32com):
    """WMI cagrisi gercekten askida kalirsa (timeout'tan uzun surerse)
    CollectionError firlatilmali -- eskiden bu asla olmazdi (timeout hic
    kullanilmiyordu), bkz. aldigim_kararlar.md -> 'VSS icin gercek zaman asimi'."""
    fake_client, mod = fake_win32com
    wmi, _ = _wire_wmi(fake_client)
    # GetObject cagrisini yavaslatarak gercek bir "askida kalma" simule edilir.
    real_get_object = fake_client.GetObject

    def slow_get_object(*args, **kwargs):
        time.sleep(0.3)
        return real_get_object(*args, **kwargs)

    fake_client.GetObject = MagicMock(side_effect=slow_get_object)

    with pytest.raises(CollectionError, match="saniyede tamamlanmadi"):
        with mod.VssSnapshot(volume="C:", timeout=0):
            pass  # pragma: no cover


def test_exit_delete_timeout_is_logged_not_raised(fake_win32com, caplog):
    """Silme cagrisi askida kalirsa (timeout) with blogundan yine de
    istisnasiz cikilmali -- sadece loglanir, tipki normal silme hatasi gibi."""
    fake_client, mod = fake_win32com
    _, shadow_instance = _wire_wmi(fake_client)

    def slow_delete():
        time.sleep(0.3)

    shadow_instance.Delete_ = MagicMock(side_effect=slow_delete)

    # Kucuk ama sifir olmayan bir zaman asimi: olusturma (yavaslatilmamis,
    # hemen biter) icin yeterli, yavaslatilmis silme (0.3s) icin yetersiz.
    with mod.VssSnapshot(volume="C:", timeout=0.05):
        pass

    assert any("saniyede tamamlanmadi" in message for message in caplog.messages)


def test_exit_failure_is_logged_not_raised(fake_win32com, caplog):
    """Silme basarisiz olsa bile with blogundan cikarken istisna firlamamali
    (orijinal hatayi maskeleme riski) - sadece loglanir."""
    fake_client, mod = fake_win32com
    _, shadow_instance = _wire_wmi(fake_client)
    shadow_instance.Delete_.side_effect = Exception("silinemiyor")

    with mod.VssSnapshot(volume="C:"):
        pass

    assert any("silinemedi" in message for message in caplog.messages)


# ============================================================================
# Kaynak: tests/unit/test_watchlist_runner.py
# ============================================================================
# Hash listesi (watchlist/IOC) eslestirme kosusu: dosya ayristirma, eslesme,
# eslesme-yok, atlama ve yol kontrolu.
#
# capa/YARA testlerinin AKSINE hicbir subprocess YAMASI gerekmez -- watchlist
# saf Python hash karsilastirmasi yapar (bkz. detection/watchlist_runner.py
# modul dokstring'i).



WATCHLIST_RUNNER_CASE_ID = "CASE-TEST-WATCHLIST"
KNOWN_BAD_HASH = "e" * 64


def _watchlist_runner_make_config(tmp_path, hashes_file=None):
    return TriageChainConfig(
        case={"case_id": WATCHLIST_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={"watchlist_hashes_file": hashes_file},
    )


def _watchlist_runner_make_artifact(hash_value, artifact_type_id="prefetch", filename="APP.pf", dest_path=None):
    if dest_path is None:
        dest_path = str(Path("C:/vaka/artifacts") / artifact_type_id / filename)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\kaynak\{filename}",
        dest_path=dest_path, hash_value=hash_value, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=WATCHLIST_RUNNER_CASE_ID,
    )


def _watchlist_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=WATCHLIST_RUNNER_CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _watchlist_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", WATCHLIST_RUNNER_CASE_ID)


def _write_hashes(tmp_path, text):
    path = tmp_path / "watchlist.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


# -- load_watchlist -----------------------------------------------------------

def test_load_watchlist_parses_comma_and_space_labels(tmp_path):
    path = _write_hashes(
        tmp_path,
        "AAAA,Mimikatz\n"
        "bbbb Cobalt Strike beacon\n"
        "cccc\n",
    )
    hashes = load_watchlist(Path(path))
    assert hashes == {
        "aaaa": "Mimikatz",
        "bbbb": "Cobalt Strike beacon",
        "cccc": "cccc",
    }


def test_load_watchlist_skips_comments_and_blank_lines(tmp_path):
    path = _write_hashes(
        tmp_path,
        "# bu bir yorum satiri\n"
        "\n"
        "   \n"
        "dddd,gercek girdi\n"
        "# dddd degil bu\n",
    )
    hashes = load_watchlist(Path(path))
    assert hashes == {"dddd": "gercek girdi"}


def test_load_watchlist_is_case_insensitive_via_lowercasing(tmp_path):
    path = _write_hashes(tmp_path, "ABCDEF1234,Etiket\n")
    hashes = load_watchlist(Path(path))
    assert "abcdef1234" in hashes and "ABCDEF1234" not in hashes


def test_load_watchlist_last_duplicate_wins(tmp_path):
    path = _write_hashes(tmp_path, "aaaa,ilk\naaaa,sonuncu\n")
    hashes = load_watchlist(Path(path))
    assert hashes == {"aaaa": "sonuncu"}


# -- run_watchlist_check --------------------------------------------------------

def test_not_configured_is_skipped(tmp_path):
    config = _watchlist_runner_make_config(tmp_path, hashes_file=None)
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([_watchlist_runner_make_artifact("0" * 64)]), ledger)

    assert manifest.matches == []
    assert "konfigure edilmemis" in manifest.skipped[0]["message"]


def test_missing_file_is_skipped(tmp_path):
    config = _watchlist_runner_make_config(tmp_path, hashes_file=str(tmp_path / "olmayan.txt"))
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([_watchlist_runner_make_artifact("0" * 64)]), ledger)

    assert manifest.matches == []
    assert "bulunamadi" in manifest.skipped[0]["message"]


def test_matching_hash_produces_a_match(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Bilinen kötü araç\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    artifact = _watchlist_runner_make_artifact(KNOWN_BAD_HASH, filename="kotu.exe")
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([artifact]), ledger)

    assert len(manifest.matches) == 1
    match = manifest.matches[0]
    assert match.rule_name == "watchlist:Bilinen kötü araç"
    assert match.tags == "watchlist"
    assert match.meta == "hash_algorithm=sha256"
    assert match.source_path == artifact.dest_path
    assert manifest.scanned == [
        {
            "artifact_type_id": artifact.artifact_type_id,
            "source_path": artifact.dest_path,
            "match_count": 1,
        }
    ]


def test_case_insensitive_hash_comparison(tmp_path):
    """Kullanicinin sozunu verdigi 'buyuk/kucuk harf duyarsiz eslesme' ilkesi
    (arama ozelligiyle AYNI karar) hash karsilastirmasina da uygulanir."""
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH.upper()},Etiket\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    artifact = _watchlist_runner_make_artifact(KNOWN_BAD_HASH.lower())
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([artifact]), ledger)

    assert len(manifest.matches) == 1


def test_no_match_is_not_an_error(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    artifact = _watchlist_runner_make_artifact("1" * 64)
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([artifact]), ledger)

    assert manifest.matches == [] and manifest.errors == [] and manifest.skipped == []
    assert manifest.scanned[0]["match_count"] == 0


def test_multiple_artifacts_only_matching_ones_produce_matches(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Kötü Dosya\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    bad = _watchlist_runner_make_artifact(KNOWN_BAD_HASH, filename="kotu.exe")
    good1 = _watchlist_runner_make_artifact("1" * 64, filename="temiz1.exe")
    good2 = _watchlist_runner_make_artifact("2" * 64, filename="temiz2.exe")
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(config, _watchlist_runner_make_manifest([good1, bad, good2]), ledger)

    assert len(manifest.scanned) == 3
    assert len(manifest.matches) == 1
    assert manifest.matches[0].source_path == bad.dest_path


def test_ledger_events_and_no_per_artifact_event(tmp_path):
    """YARA/capa'nin AKSINE artefakt basina custody olayi YAZILMAZ (bkz.
    watchlist_runner.py modul dokstring'i) -- sadece basla/bitir cifti."""
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    ledger = _watchlist_runner_ledger(tmp_path)

    run_watchlist_check(
        config,
        _watchlist_runner_make_manifest([_watchlist_runner_make_artifact(KNOWN_BAD_HASH), _watchlist_runner_make_artifact("1" * 64)]),
        ledger,
    )

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["watchlist_started", "watchlist_completed"]
    assert verify_chain(ledger.log_path, WATCHLIST_RUNNER_CASE_ID).is_valid


def test_manifest_is_written_and_its_hash_recorded(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _watchlist_runner_make_config(tmp_path, hashes_file=hashes_file)
    ledger = _watchlist_runner_ledger(tmp_path)

    manifest = run_watchlist_check(
        config, _watchlist_runner_make_manifest([_watchlist_runner_make_artifact(KNOWN_BAD_HASH)]), ledger
    )

    manifest_path = Path(config.collection.output_dir) / WATCHLIST_RUNNER_CASE_ID / "watchlist_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "watchlist_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["watchlist_manifest_sha256"] == expected

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == manifest.run_id
    assert len(reloaded.matches) == 1


def test_cli_watchlist_check_without_manifest_exits_with_code_2(tmp_path):
    """'watchlist-check' da diger tarama komutlariyla ayni kural: once
    'collect' calismali."""
    import yaml

    from triagechain.cli.main import main

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    data = {
        "case": {"case_id": WATCHLIST_RUNNER_CASE_ID, "operator": "test.operator"},
        "collection": {
            "targets": ["event_logs"], "hash_algorithm": "sha256", "output_dir": str(output_dir),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    exit_code = main(["watchlist-check", "--config", str(config_path)])

    assert exit_code == 2


# ============================================================================
# Kaynak: tests/unit/test_widgets.py
# ============================================================================
# gui_qt/widgets.py bilesenlerinin ekransiz testleri.
#
# test_gui_qt.py ile ayni desen: QT_QPA_PLATFORM=offscreen, gercek pencere
# acilmaz.
#




pytest.importorskip("PySide6")




@pytest.fixture(scope="session")
def widgets_qt_app():
    return QApplication.instance() or QApplication([])


def test_monolabel_klavye_ile_odaklanabilir(widgets_qt_app):
    """Erisilebilirlik: fare kullanmayan biri de metni secebilmeli."""
    label = MonoLabel("abc123")
    assert label.focusPolicy() != 0  # NoFocus degil


def test_monolabel_kendi_focus_stilini_tanimliyor(widgets_qt_app):
    """Gercek bir kullanici hatasi: StrongFocus + ozel bir `:focus` QSS
    kurali OLMADAN Qt/Windows kendi ham (markanin yesil paletiyle
    uyusmayan, mavi) varsayilan odak dikdortgenini ciziyordu -- kullanici
    bunu gercek bir ekran goruntusunde bulup bildirdi. Bu test, bilesenin
    KENDI stylesheet'inin ACCENT_TEXT tabanli bir `:focus` kurali
    tasidigini dogrudan dogrular (goruntu karsilastirmasi degil, ama
    regresyonu yakalar)."""
    label = MonoLabel("abc123")
    stylesheet = label.styleSheet()
    assert "QLabel:focus" in stylesheet
    assert t.ACCENT_TEXT in stylesheet


# ============================================================================
# Kaynak: tests/unit/test_winpath.py
# ============================================================================
r"""Windows'un 260 karakter MAX_PATH sinirini asan \\?\ oneki yardimcisi.

Gercek bir MAX_PATH hatasi, gercek bir KAPE ice aktarma testinde (uzun
olay gunlugu kanal adlari + derin vaka klasoru) bulundu -- bkz.
aldigim_kararlar.md -> "Windows MAX_PATH duzeltmesi".
"""




pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="\\\\?\\ oneki Windows'a ozgu")


def test_absolute_path_gets_prefixed():
    result = to_long_path(Path(r"C:\Users\test\uzun\bir\yol\dosya.txt"))
    assert str(result) == r"\\?\C:\Users\test\uzun\bir\yol\dosya.txt"


def test_already_prefixed_path_is_not_double_prefixed():
    already = Path(r"\\?\C:\Users\test\dosya.txt")
    assert to_long_path(already) == already


def test_relative_path_is_returned_unchanged():
    # Onek SADECE mutlak yollarda gecerlidir -- goreli bir yolu \\?\ ile
    # sarmak onu bozardi (Win32 API mutlak bekler).
    relative = Path("goreli") / "dosya.txt"
    assert to_long_path(relative) == relative


def test_unc_path_gets_unc_prefix():
    unc = Path(r"\\sunucu\pay\dosya.txt")
    result = to_long_path(unc)
    assert str(result) == r"\\?\UNC\sunucu\pay\dosya.txt"


# ============================================================================
# Kaynak: tests/unit/test_yara_runner.py
# ============================================================================
# YARA tarama kosusu: basarili tarama, eslesmesiz tarama, hata kodu, zaman
# asimi, atlama ve yol kontrolu.
#
# Hicbir test gercek bir YARA ikilisi calistirmaz: subprocess.run her testte
# YAMALANDIGI YERDE (triagechain.detection.yara_runner.subprocess.run)
# unittest.mock ile degistirilir -- test_detection_runner.py ile AYNI desen.
# Gercek yara64.exe 4.5.5'e karsi manuel dogrulama yapildi (bkz.
# docs/hatalar_ve_sonuclar.md); buradaki FAKE_STDOUT o gercek ciktinin
# bicimini birebir yansitir.
#




YARA_RUNNER_CASE_ID = "CASE-TEST-YARA"

# Gercek yara64.exe 4.5.5 ciktisi (bkz. docs/hatalar_ve_sonuclar.md):
# "<kural> [<tag,tag>] [<k>=\"v\",...] <dosya>", eslesme yoksa BOS stdout.
FAKE_STDOUT_MATCH = (
    'Test_Suspicious_String [malware,mimikatz] [author="test",severity="high"] {path}\n'
)


def _yara_runner_make_config(tmp_path, yara_path=None, yara_rules_file=None, yara_timeout_seconds=300):
    return TriageChainConfig(
        case={"case_id": YARA_RUNNER_CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "yara_path": yara_path,
            "yara_rules_file": yara_rules_file,
            "yara_timeout_seconds": yara_timeout_seconds,
        },
    )


def _yara_runner_artifacts_root(config):
    return Path(config.collection.output_dir) / YARA_RUNNER_CASE_ID / "artifacts"


def _yara_runner_make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    if dest_path is None:
        dest = _yara_runner_artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte artefakt")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id,
        source_path=rf"C:\kaynak\{filename}",
        dest_path=dest_path,
        hash_value="0" * 64,
        hash_algorithm="sha256",
        size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc),
        collecting_user="test.operator",
        case_id=YARA_RUNNER_CASE_ID,
    )


def _yara_runner_make_manifest(artifacts):
    return CollectionManifest(
        case_id=YARA_RUNNER_CASE_ID,
        started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc),
        artifacts=list(artifacts),
    )


def _yara_runner_fake_tool(tmp_path, name="yara64.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules_file(tmp_path):
    rules = tmp_path / "rules" / "custom.yar"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text("rule ornek { condition: true }", encoding="utf-8")
    return str(rules)


def _yara_runner_configured(tmp_path, **kwargs):
    return _yara_runner_make_config(
        tmp_path, yara_path=_yara_runner_fake_tool(tmp_path), yara_rules_file=_fake_rules_file(tmp_path),
        **kwargs,
    )


def _yara_runner_ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", YARA_RUNNER_CASE_ID)


def _yara_runner_completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _no_match():
    """Sahte YARA: hicbir esleşme yok -- gercek ikilinin dogrulanmis davranisi
    (bos stdout, cikis kodu 0)."""
    def side_effect(argv, **kwargs):
        return _yara_runner_completed(argv, stdout=b"")
    return side_effect


def _matches(path_in_argv_index=-1):
    """Sahte YARA: taranan dosyanin KENDI yoluyla eslesen bir satir uretir."""
    def side_effect(argv, **kwargs):
        target = argv[-1]
        return _yara_runner_completed(argv, stdout=FAKE_STDOUT_MATCH.format(path=target).encode("utf-8"))
    return side_effect


def _yara_runner_assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_with_match_produces_one_yaramatch(tmp_path):
    config = _yara_runner_configured(tmp_path)
    artifact = _yara_runner_make_artifact(config)
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _matches()
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([artifact]), ledger)

    assert len(yara_manifest.matches) == 1
    match = yara_manifest.matches[0]
    assert match.rule_name == "Test_Suspicious_String"
    assert match.tags == "malware,mimikatz"
    assert match.meta == 'author="test",severity="high"'
    assert match.source_path == str(Path(artifact.dest_path).resolve())
    assert yara_manifest.errors == [] and yara_manifest.skipped == []

    assert len(yara_manifest.scanned) == 1
    assert yara_manifest.scanned[0]["match_count"] == 1

    argv = mock_run.call_args.args[0]
    assert argv[0] == config.detection.yara_path
    assert argv[-2] == config.detection.yara_rules_file
    assert argv[-1] == str(Path(artifact.dest_path).resolve())
    assert mock_run.call_args.kwargs["timeout"] == 300
    _yara_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["yara_started", "yara_completed_for_artifact", "yara_completed"]
    assert verify_chain(ledger.log_path, YARA_RUNNER_CASE_ID).is_valid


def test_no_match_is_not_an_error_empty_stdout(tmp_path):
    """Gercek yara64.exe'nin dogrulanmis davranisi: eslesme yoksa bos stdout +
    cikis kodu 0 -- bu bir hata degil, sadece 0 eslesmeli bir tarama sonucu."""
    config = _yara_runner_configured(tmp_path)
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _no_match()
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    assert yara_manifest.matches == []
    assert yara_manifest.errors == []
    assert yara_manifest.scanned[0]["match_count"] == 0


def test_yara_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _yara_runner_configured(tmp_path)
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _matches()
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / YARA_RUNNER_CASE_ID / "yara_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "yara_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["yara_manifest_sha256"] == expected
    assert closing.payload["match_count"] == 1

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == yara_manifest.run_id
    assert len(reloaded.matches) == 1


def test_yara_runner_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _yara_runner_configured(tmp_path)
    failing = _yara_runner_make_artifact(config, filename="Bad.bin")
    ok = _yara_runner_make_artifact(config, filename="Good.bin")
    ledger = _yara_runner_ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if "Bad.bin" in argv[-1]:
            return _yara_runner_completed(argv, returncode=1, stderr=b"kural dosyasi derlenemedi")
        return _no_match()(argv, **kwargs)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([failing, ok]), ledger)

    assert len(yara_manifest.errors) == 1
    assert yara_manifest.errors[0]["exit_code"] == 1
    assert yara_manifest.errors[0]["stderr_excerpt"] == "kural dosyasi derlenemedi"
    assert [Path(s["source_path"]).name for s in yara_manifest.scanned] == ["Good.bin"]
    assert mock_run.call_count == 2
    _yara_runner_assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("yara_error") == 1
    assert event_types.count("yara_completed_for_artifact") == 1


def test_yara_runner_timeout_is_a_non_fatal_error(tmp_path):
    config = _yara_runner_configured(tmp_path, yara_timeout_seconds=5)
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["yara64.exe"], timeout=5)
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    assert yara_manifest.scanned == [] and yara_manifest.matches == []
    assert len(yara_manifest.errors) == 1
    assert "5 saniyede bitmedi" in yara_manifest.errors[0]["message"]
    assert verify_chain(ledger.log_path, YARA_RUNNER_CASE_ID).is_valid


def test_yara_runner_tool_not_configured_is_skipped(tmp_path):
    config = _yara_runner_make_config(tmp_path)
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert yara_manifest.matches == [] and yara_manifest.errors == []
    assert len(yara_manifest.skipped) == 1
    assert "konfigure edilmemis" in yara_manifest.skipped[0]["message"]


def test_rules_file_not_configured_is_skipped(tmp_path):
    config = _yara_runner_make_config(tmp_path, yara_path=_yara_runner_fake_tool(tmp_path))
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural dosyasi konfigure edilmemis" in yara_manifest.skipped[0]["message"]


def test_yara_runner_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    missing_exe = str(tmp_path / "olmayan" / "yara64.exe")
    config = _yara_runner_make_config(tmp_path, yara_path=missing_exe, yara_rules_file=_fake_rules_file(tmp_path))
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([_yara_runner_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    message = yara_manifest.skipped[0]["message"]
    assert "yolu bulunamadi" in message and missing_exe in message


def test_yara_runner_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _yara_runner_configured(tmp_path)
    outside = tmp_path / "disari" / "Security.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _yara_runner_make_artifact(config, dest_path=str(outside))
    ledger = _yara_runner_ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _yara_runner_make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert len(yara_manifest.errors) == 1
    assert "cikti agaci disinda" in yara_manifest.errors[0]["message"]


def test_cli_yara_scan_without_manifest_exits_with_code_2(tmp_path, capsys):
    """'yara-scan' da 'detect' ile ayni kural: once 'collect' calismali."""
    import yaml

    from triagechain.cli.main import main

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    data = {
        "case": {"case_id": YARA_RUNNER_CASE_ID, "operator": "test.operator"},
        "collection": {
            "targets": ["event_logs"], "hash_algorithm": "sha256", "output_dir": str(output_dir),
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    exit_code = main(["yara-scan", "--config", str(config_path)])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Toplama manifesti yok" in captured.err
    assert not (output_dir / YARA_RUNNER_CASE_ID / "yara_manifest.json").exists()


# ============================================================================
# Kaynak: tests/integration/test_end_to_end_collection.py
# ============================================================================
# Uctan uca toplama testi.
#
# Bu test bilerek VSS'siz kurgulanmistir: sahte katalogtaki her girdide
# end_to_end_collection_requires_vss=False oldugu icin yonetici haklarina ya da gercek Windows'a
# ihtiyac duymaz, CI'da da calisir.
#




END_TO_END_COLLECTION_FAKE_ARTIFACTS = Path(__file__).resolve().parents[0] / "fixtures" / "fake_artifacts"
END_TO_END_COLLECTION_CASE_ID = "CASE-TEST-E2E"


@pytest.fixture
def end_to_end_collection_fake_catalog(tmp_path, monkeypatch):
    """Gomulu katalogun yerine, fixture dosyalarini gosteren sahte katalog koyar."""
    catalog = {
        "targets": [
            {
                "id": "fake_logs",
                "category": "test",
                "end_to_end_collection_requires_vss": False,
                "paths": [str(END_TO_END_COLLECTION_FAKE_ARTIFACTS / "*.log")],
                "description": "Sahte log dosyalari",
            },
            {
                "id": "fake_notes",
                "category": "test",
                "end_to_end_collection_requires_vss": False,
                "paths": [str(END_TO_END_COLLECTION_FAKE_ARTIFACTS / "notes.txt")],
                "description": "Tek dosya",
            },
            {
                "id": "fake_missing",
                "category": "test",
                "end_to_end_collection_requires_vss": False,
                "paths": [str(END_TO_END_COLLECTION_FAKE_ARTIFACTS / "*.hicyok")],
                "description": "Hicbir seye uymayan glob",
            },
        ]
    }
    path = tmp_path / "test_targets.yaml"
    path.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    # Hem sema dogrulamasi hem toplayici bu fonksiyonu cagirdigi icin tek yama yeter.
    monkeypatch.setattr(catalog_module, "default_catalog_path", lambda: path)
    return path


@pytest.fixture
def end_to_end_collection_config(tmp_path, end_to_end_collection_fake_catalog):
    data = {
        "case": {"case_id": END_TO_END_COLLECTION_CASE_ID, "operator": "test.operator", "description": "e2e"},
        "collection": {
            "targets": ["fake_logs", "fake_notes", "fake_missing"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "end_to_end_collection_config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def test_end_to_end_collection(end_to_end_collection_config):
    log_path = resolve_custody_log_path(end_to_end_collection_config)
    ledger = CustodyLedger(log_path, END_TO_END_COLLECTION_CASE_ID)

    manifest = run_collection(end_to_end_collection_config, ledger)

    # 1) Dosyalar kopyalanmis olmali (2 log + 1 not).
    assert len(manifest.artifacts) == 3
    for artifact in manifest.artifacts:
        dest = Path(artifact.dest_path)
        assert dest.is_file()
        assert dest.stat().st_size == artifact.size_bytes
        # 2) Hash'ler kaynak ve hedefte ayni olmali.
        assert hash_file(dest, artifact.hash_algorithm) == artifact.hash_value
        assert hash_file(artifact.source_path, artifact.hash_algorithm) == artifact.hash_value
        assert artifact.case_id == END_TO_END_COLLECTION_CASE_ID

    # 3) Eslesmeyen hedef olumcul degil, hata olarak kaydedilmis olmali.
    assert [e["artifact_type_id"] for e in manifest.errors] == ["fake_missing"]

    # 4) Manifest diske yazilip geri okunabilmeli.
    manifest_path = Path(end_to_end_collection_config.collection.output_dir) / END_TO_END_COLLECTION_CASE_ID / "manifest.json"
    manifest.to_json_file(manifest_path)
    reloaded = CollectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == manifest.run_id
    assert len(reloaded.artifacts) == 3
    assert reloaded.ended_at_utc is not None

    # 5) Custody zinciri saglam olmali.
    result = verify_chain(log_path, END_TO_END_COLLECTION_CASE_ID)
    assert result.is_valid, result.message

    event_types = [event.event_type for event in read_events(log_path)]
    assert event_types[0] == "case_opened"
    assert event_types[-1] == "case_closed"
    assert event_types.count("artifact_collected") == 3
    assert event_types.count("collection_error") == 1


def test_artifacts_are_written_under_type_directories(end_to_end_collection_config):
    ledger = CustodyLedger(resolve_custody_log_path(end_to_end_collection_config), END_TO_END_COLLECTION_CASE_ID)

    manifest = run_collection(end_to_end_collection_config, ledger)

    artifacts_root = Path(end_to_end_collection_config.collection.output_dir) / END_TO_END_COLLECTION_CASE_ID / "artifacts"
    assert sorted(p.name for p in (artifacts_root / "fake_logs").iterdir()) == [
        "alpha.log",
        "beta.log",
    ]
    assert (artifacts_root / "fake_notes" / "notes.txt").is_file()
    assert all(Path(a.dest_path).is_relative_to(artifacts_root) for a in manifest.artifacts)


# ============================================================================
# Kaynak: tests/integration/test_end_to_end_detection.py
# ============================================================================
# Uctan uca topla + tespit et testi.
#
# Faz 1'in uctan uca testiyle ayni kurgu: sahte katalogtaki her girdide
# end_to_end_detection_requires_vss=False oldugu icin yonetici hakki ya da gercek Windows gerekmez.
# Faz 4 tarafinda gercek bir Hayabusa ikilisi CALISTIRILMAZ; subprocess.run
# yamalanip, cikti CSV'sini yazan bir "arac" taklit edilir.
#




END_TO_END_DETECTION_CASE_ID = "CASE-TEST-E2E-DETECT"

END_TO_END_DETECTION_FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Mimikatz Detected,critical,WS-01,Security,4688,lsass erisimi\n"
    "2026-01-02 03:06:00.000 +03:00,Failed Logon,low,WS-01,Security,4625,Yanlis parola\n"
)


@pytest.fixture
def end_to_end_detection_fake_catalog(tmp_path, monkeypatch):
    """Toplama katalogunu, tmp_path'teki sahte .evtx dosyalarini gosteren bir kopyayla degistirir."""
    evtx_dir = tmp_path / "kaynak" / "winevt"
    evtx_dir.mkdir(parents=True)
    for name in ("Security.evtx", "System.evtx"):
        (evtx_dir / name).write_bytes(b"sahte evtx icerigi")
    # Tespit katmaninin dokunmamasi gereken ikinci bir tip.
    pf_dir = tmp_path / "kaynak" / "prefetch"
    pf_dir.mkdir(parents=True)
    (pf_dir / "APP.pf").write_bytes(b"sahte prefetch")

    targets = {
        "targets": [
            {
                "id": "event_logs",
                "category": "test",
                "end_to_end_detection_requires_vss": False,
                "paths": [str(evtx_dir / "*.evtx")],
                "description": "Sahte olay gunlukleri",
            },
            {
                "id": "prefetch",
                "category": "test",
                "end_to_end_detection_requires_vss": False,
                "paths": [str(pf_dir / "*.pf")],
                "description": "Hayabusa'nin taramamasi gereken tip",
            },
        ]
    }
    targets_path = tmp_path / "test_targets.yaml"
    targets_path.write_text(yaml.safe_dump(targets, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(collection_catalog, "default_catalog_path", lambda: targets_path)
    return targets_path


@pytest.fixture
def end_to_end_detection_config(tmp_path, end_to_end_detection_fake_catalog):
    hayabusa = tmp_path / "tools" / "hayabusa.exe"
    hayabusa.parent.mkdir(parents=True, exist_ok=True)
    hayabusa.write_text("sahte arac", encoding="utf-8")
    rules_dir = tmp_path / "sigma" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "ornek.yml").write_text("title: ornek", encoding="utf-8")

    data = {
        "case": {"case_id": END_TO_END_DETECTION_CASE_ID, "operator": "test.operator", "description": "e2e detect"},
        "collection": {
            "targets": ["event_logs", "prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "detection": {
            "hayabusa_path": str(hayabusa),
            "rules_dir": str(rules_dir),
            "timeout_seconds": 60,
        },
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "end_to_end_detection_config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _fake_hayabusa_run(argv, **kwargs):
    """Gercek aracin yerine gecer: -o ile verilen yola CSV yazip 0 ile doner."""
    Path(argv[argv.index("-o") + 1]).write_text(END_TO_END_DETECTION_FAKE_CSV, encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_then_detect_end_to_end(end_to_end_detection_config):
    log_path = resolve_custody_log_path(end_to_end_detection_config)
    ledger = CustodyLedger(log_path, END_TO_END_DETECTION_CASE_ID)

    collection = run_collection(end_to_end_detection_config, ledger)
    assert len(collection.artifacts) == 3  # 2 evtx + 1 prefetch

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _fake_hayabusa_run
        detection = run_detection(end_to_end_detection_config, collection, ledger)

    # 1) Yalnizca iki olay gunlugu taranmis, prefetch'e dokunulmamis olmali.
    assert mock_run.call_count == 2
    assert {Path(s["source_path"]).name for s in detection.scanned} == {
        "Security.evtx", "System.evtx"
    }
    assert len(detection.findings) == 4  # dosya basina 2 bulgu
    assert detection.errors == [] and detection.skipped == []
    assert {f.rule_title for f in detection.findings} == {"Mimikatz Detected", "Failed Logon"}

    # 2) "Arac" ciktisini ve denetim loglarini vakanin agacina yazmis olmali.
    detections_root = Path(end_to_end_detection_config.collection.output_dir) / END_TO_END_DETECTION_CASE_ID / "detections" / "hayabusa"
    for item in detection.scanned:
        assert Path(item["output_csv_path"]).is_file()
        assert Path(item["output_csv_path"]).parent == detections_root
        assert Path(item["stdout_log_path"]).read_text(encoding="utf-8") == "bitti\n"
        assert item["level_counts"] == {"critical": 1, "low": 1}

    # 3) Hicbir cagri kabuk uzerinden yapilmamis, hepsinin zaman asimi olmali.
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)
        assert call.kwargs["timeout"] == 60

    # 4) Tespit manifesti diske yazilip geri okunabilmeli.
    manifest_path = resolve_detection_manifest_path(end_to_end_detection_config)
    assert manifest_path.is_file()
    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 4
    assert reloaded.ended_at_utc is not None

    # 5) Tek bir custody zinciri hem toplama hem tespit olaylarini kapsamali.
    result = verify_chain(log_path, END_TO_END_DETECTION_CASE_ID)
    assert result.is_valid, result.message

    events = list(read_events(log_path))
    event_types = [event.event_type for event in events]
    assert event_types[0] == "case_opened"
    assert event_types[-1] == "detection_completed"
    assert event_types.count("artifact_collected") == 3
    assert event_types.count("detection_started") == 1
    # Bulgu basina degil, taranan DOSYA basina tek ozet olay.
    assert event_types.count("detection_completed_for_artifact") == 2
    assert event_types.index("case_closed") < event_types.index("detection_started")

    # 6) Kapanis olayi manifestin sha256'sini tasimali (detaylar sadece manifeste yazilir).
    closing = events[-1]
    assert closing.payload["finding_count"] == 4
    assert closing.payload["detection_manifest_sha256"] == hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    # Bulgu detaylari defterde DURMAMALI.
    assert "findings" not in closing.payload


# ============================================================================
# Kaynak: tests/integration/test_end_to_end_report.py
# ============================================================================
# Uctan uca topla + yonlendir + tara + raporla testi.
#
# Diger uctan uca testlerle ayni kurgu: sahte katalogtaki her girdide
# end_to_end_report_requires_vss=False, dis araclar (EZ Tools/Hayabusa) hic calistirilmaz -
# subprocess.run yamalanir. Rapor komutu CLI uzerinden cagrilir.
#




END_TO_END_REPORT_CASE_ID = "CASE-TEST-E2E-REPORT"

END_TO_END_REPORT_FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Mimikatz Detected,critical,WS-01,Security,4688,lsass erisimi\n"
)


@pytest.fixture
def end_to_end_report_fake_catalog(tmp_path, monkeypatch):
    """Toplama katalogunu tmp_path'teki sahte dosyalari gosteren bir kopyayla degistirir."""
    evtx_dir = tmp_path / "kaynak" / "winevt"
    evtx_dir.mkdir(parents=True)
    (evtx_dir / "Security.evtx").write_bytes(b"sahte evtx icerigi")

    targets = {
        "targets": [
            {
                "id": "event_logs",
                "category": "test",
                "end_to_end_report_requires_vss": False,
                "paths": [str(evtx_dir / "*.evtx")],
                "description": "Sahte olay gunlukleri",
            }
        ]
    }
    targets_path = tmp_path / "test_targets.yaml"
    targets_path.write_text(yaml.safe_dump(targets, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(collection_catalog, "default_catalog_path", lambda: targets_path)
    return targets_path


@pytest.fixture
def end_to_end_report_config_path(tmp_path, end_to_end_report_fake_catalog):
    """Router ve detection araclari tanimli (ama calistirilmayacak) konfigurasyon."""
    evtxecmd = tmp_path / "tools" / "EvtxECmd.exe"
    evtxecmd.parent.mkdir(parents=True, exist_ok=True)
    evtxecmd.write_text("sahte arac", encoding="utf-8")
    hayabusa = tmp_path / "tools" / "hayabusa.exe"
    hayabusa.write_text("sahte arac", encoding="utf-8")
    rules_dir = tmp_path / "sigma" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "ornek.yml").write_text("title: ornek", encoding="utf-8")

    data = {
        "case": {"case_id": END_TO_END_REPORT_CASE_ID, "operator": "test.operator", "description": "e2e rapor"},
        "collection": {
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "router": {"tools": {"evtxecmd": str(evtxecmd)}, "timeout_seconds": 60},
        "detection": {
            "hayabusa_path": str(hayabusa),
            "rules_dir": str(rules_dir),
            "timeout_seconds": 60,
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def _fake_evtxecmd(argv, **kwargs):
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def _fake_hayabusa(argv, **kwargs):
    Path(argv[argv.index("-o") + 1]).write_text(END_TO_END_REPORT_FAKE_CSV, encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_route_detect_then_report(end_to_end_report_config_path, capsys):
    assert main(["collect", "--config", str(end_to_end_report_config_path)]) == 0
    with patch("triagechain.router.runner.subprocess.run", side_effect=_fake_evtxecmd):
        assert main(["route", "--config", str(end_to_end_report_config_path)]) == 0
    with patch("triagechain.detection.runner.subprocess.run", side_effect=_fake_hayabusa):
        assert main(["detect", "--config", str(end_to_end_report_config_path)]) == 0

    config = load_config(end_to_end_report_config_path)
    log_path = resolve_custody_log_path(config)
    events_before = len(list(read_events(log_path)))
    capsys.readouterr()

    assert main(["report", "--config", str(end_to_end_report_config_path)]) == 0
    out = capsys.readouterr().out

    case_dir = Path(config.collection.output_dir) / END_TO_END_REPORT_CASE_ID
    json_path = case_dir / "report.json"
    html_path = case_dir / "report.html"
    sha_path = case_dir / "report.json.sha256"

    # 1) Uc dosya da yan yana yazilmis olmali.
    assert json_path.is_file() and html_path.is_file() and sha_path.is_file()
    assert "Zincir durumu : GECERLI" in out
    assert str(html_path) in out

    # 2) Rapor uc katmani da doldurmus olmali.
    report = Report.from_json_file(json_path)
    assert report.case_id == END_TO_END_REPORT_CASE_ID
    assert report.collection.artifact_count == 1
    assert report.routing is not None and report.routing.processed_count == 1
    assert report.detection is not None and report.detection.finding_count == 1
    assert report.detection.level_counts == {"critical": 1}
    assert report.chain_status.is_valid
    assert report.chain_status.total_events == events_before
    assert len(report.custody_events) == events_before

    # 3) Rapor uretimi deftere HICBIR olay eklememeli (salt-okunur katman).
    assert len(list(read_events(log_path))) == events_before

    # 4) sha256 yan dosyasi raporun gercek hash'i olmali.
    digest, filename = sha_path.read_text(encoding="utf-8").split()
    assert filename == "report.json"
    assert digest == hashlib.sha256(json_path.read_bytes()).hexdigest()

    # 5) HTML tamamen offline acilabilmeli: harici hicbir kaynak referansi yok.
    html = html_path.read_text(encoding="utf-8")
    for forbidden in ("http://", "https://", "<script", "cdn.", "@import"):
        assert forbidden not in html
    assert "GEÇERLİ" in html
    assert "Mimikatz Detected" in html
    # Logo base64 GOMULU olmali (data: URI) -- harici dosya referansi degil,
    # "tamamen offline acilabilmeli" kuralini bozmaz (bkz. renderer.py).
    assert 'class="report-logo" src="data:image/png;base64,' in html
    # Bu senaryo yara-scan/chainsaw-scan/capa-scan/watchlist-check calistirmiyor,
    # o dort bolum "henuz calistirilmadi" olmali.
    assert html.count("henüz çalıştırılmadı") == 4


# ============================================================================
# Kaynak: tests/integration/test_end_to_end_routing.py
# ============================================================================
# Uctan uca topla + yonlendir testi.
#
# Faz 1'in uctan uca testiyle ayni kurgu: sahte katalogtaki her girdide
# end_to_end_routing_requires_vss=False oldugu icin yonetici hakki ya da gercek Windows gerekmez.
# Faz 2 tarafinda ise gercek bir EZ Tools ikilisi CALISTIRILMAZ; subprocess.run
# yamalanip, cikti dizinine sahte bir CSV yazan bir "arac" taklit edilir.
#




END_TO_END_ROUTING_FAKE_ARTIFACTS = Path(__file__).resolve().parents[0] / "fixtures" / "fake_artifacts"
END_TO_END_ROUTING_CASE_ID = "CASE-TEST-E2E-ROUTE"


@pytest.fixture
def fake_catalogs(tmp_path, monkeypatch):
    """Hem toplama katalogunu hem arac esleme katalogunu sahtesiyle degistirir."""
    targets = {
        "targets": [
            {
                "id": "fake_logs",
                "category": "test",
                "end_to_end_routing_requires_vss": False,
                "paths": [str(END_TO_END_ROUTING_FAKE_ARTIFACTS / "*.log")],
                "description": "Sahte log dosyalari",
            },
            {
                "id": "fake_notes",
                "category": "test",
                "end_to_end_routing_requires_vss": False,
                "paths": [str(END_TO_END_ROUTING_FAKE_ARTIFACTS / "notes.txt")],
                "description": "Tek dosya; bu tip icin tanimli arac yok",
            },
        ]
    }
    targets_path = tmp_path / "test_targets.yaml"
    targets_path.write_text(yaml.safe_dump(targets, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(collection_catalog, "default_catalog_path", lambda: targets_path)

    # fake_logs -> sahte 'faketool'; fake_notes bilerek rotasiz birakildi.
    routes = {
        "routes": {
            "fake_logs": {
                "tool": "faketool",
                "args": ["-f", "{input}", "--csv", "{output_dir}"],
            }
        }
    }
    routes_path = tmp_path / "test_tool_mapping.yaml"
    routes_path.write_text(yaml.safe_dump(routes, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(router_catalog, "default_catalog_path", lambda: routes_path)
    return targets_path, routes_path


@pytest.fixture
def fake_tool_exe(tmp_path):
    """Diskte var olan, mutlak yollu sahte arac dosyasi (calistirilmaz)."""
    exe = tmp_path / "tools" / "FakeTool.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return exe


@pytest.fixture
def end_to_end_routing_config(tmp_path, fake_catalogs, fake_tool_exe):
    data = {
        "case": {"case_id": END_TO_END_ROUTING_CASE_ID, "operator": "test.operator", "description": "e2e route"},
        "collection": {
            "targets": ["fake_logs", "fake_notes"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "router": {"tools": {"faketool": str(fake_tool_exe)}, "timeout_seconds": 30},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "end_to_end_routing_config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _fake_tool_run(argv, **kwargs):
    """Gercek aracin yerine gecer: cikti dizinine bir CSV yazip 0 ile doner."""
    output_dir = Path(argv[argv.index("--csv") + 1])
    input_name = Path(argv[argv.index("-f") + 1]).name
    (output_dir / f"{input_name}.csv").write_text("satir1,satir2\n", encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_then_route_end_to_end(end_to_end_routing_config):
    log_path = resolve_custody_log_path(end_to_end_routing_config)
    ledger = CustodyLedger(log_path, END_TO_END_ROUTING_CASE_ID)

    collection = run_collection(end_to_end_routing_config, ledger)
    assert len(collection.artifacts) == 3  # 2 log + 1 not

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _fake_tool_run
        routing = run_router(end_to_end_routing_config, collection, ledger)

    # 1) Rotasi olan iki log islenmis, rotasiz not atlanmis olmali.
    assert len(routing.processed) == 2
    assert {Path(p.source_path).name for p in routing.processed} == {"alpha.log", "beta.log"}
    assert routing.errors == []
    assert [s["artifact_type_id"] for s in routing.skipped] == ["fake_notes"]

    # 2) "Arac" ciktisini ve denetim loglarini yazmis olmali.
    for item in routing.processed:
        output_dir = Path(item.output_dir)
        assert (output_dir / f"{Path(item.source_path).name}.csv").is_file()
        assert Path(item.stdout_log_path).read_text(encoding="utf-8") == "bitti\n"
        assert Path(item.stderr_log_path).is_file()
        assert item.exit_code == 0
        assert output_dir.is_relative_to(Path(end_to_end_routing_config.collection.output_dir) / END_TO_END_ROUTING_CASE_ID / "parsed")

    # 3) Hicbir cagri kabuk uzerinden yapilmamis olmali.
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)
        assert call.kwargs["timeout"] == 30

    # 4) Yonlendirme manifesti diske yazilip geri okunabilmeli.
    routing_path = Path(end_to_end_routing_config.collection.output_dir) / END_TO_END_ROUTING_CASE_ID / "routing_manifest.json"
    routing.to_json_file(routing_path)
    reloaded = RoutingManifest.from_json_file(routing_path)
    assert reloaded.run_id == routing.run_id
    assert len(reloaded.processed) == 2
    assert reloaded.ended_at_utc is not None

    # 5) Tek bir custody zinciri hem toplama hem yonlendirme olaylarini kapsamali.
    result = verify_chain(log_path, END_TO_END_ROUTING_CASE_ID)
    assert result.is_valid, result.message

    event_types = [event.event_type for event in read_events(log_path)]
    assert event_types[0] == "case_opened"
    assert event_types[-1] == "routing_completed"
    assert event_types.count("artifact_collected") == 3
    assert event_types.count("routing_started") == 1
    assert event_types.count("artifact_processed") == 2
    assert event_types.count("processing_skipped") == 1
    # Toplama kapanisi, yonlendirme baslangicindan once gelmeli.
    assert event_types.index("case_closed") < event_types.index("routing_started")


# ============================================================================
# Kaynak: tests/integration/test_import_mode_collection.py
# ============================================================================
# Ice aktarma modu: `collection.source_root` ayarlandiginda BASKA bir aracla
# (orn. KAPE) ONCEDEN toplanmis bir artefakt agacinin, canli sistem yerine
# kaynak olarak kullanildigini dogrular.
#
# GERCEK bir KAPE toplama zip'ine (384 gercek dosya: $MFT, SAM/SECURITY/
# SYSTEM/SOFTWARE kovanlari, 121 gercek .evtx, gercek prefetch dosyalari)
# karsi da elle dogrulandi -- bkz. aldigim_kararlar.md -> "Ice aktarma modu".
# Buradaki testler kucuk, sahte ama GERCEKCI bir artefakt agaciyla ayni
# mantigi (VSS ACILMAZ, requires_vss=True olsa bile; katalog kalibi
# source_root altina rebase edilir) izole olarak dogruluyor.
#




IMPORT_MODE_COLLECTION_CASE_ID = "CASE-TEST-IMPORT-MODE"


@pytest.fixture
def import_mode_collection_fake_catalog(tmp_path, monkeypatch):
    """`requires_vss: True` BILEREK secildi: import modunda bu etiket
    KORUNUR ama collector VSS'i hic acmamali -- asil test budur."""
    catalog = {
        "targets": [
            {
                "id": "fake_mft",
                "category": "filesystem",
                "requires_vss": True,
                "paths": [r"%SystemDrive%\$MFT"],
                "description": "Sahte $MFT (ice aktarma testi icin)",
            },
            {
                "id": "fake_ntuser",
                "category": "registry",
                "requires_vss": True,
                "paths": [r"C:\Users\*\NTUSER.DAT"],
                "description": "Sahte NTUSER.DAT (sabit surucu harfi, %SystemDrive% DEGIL)",
            },
        ]
    }
    path = tmp_path / "test_targets.yaml"
    path.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(catalog_module, "default_catalog_path", lambda: path)
    return path


def _import_mode_collection_config(tmp_path, import_mode_collection_fake_catalog, source_root):
    data = {
        "case": {"case_id": IMPORT_MODE_COLLECTION_CASE_ID, "operator": "test.operator", "description": "ice aktarma"},
        "collection": {
            "targets": ["fake_mft", "fake_ntuser"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
            "source_root": str(source_root),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _imported_tree(tmp_path):
    """KAPE'nin kendi ciktisiyla AYNI sekle sahip, kucuk sahte bir agac:
    tek bir 'C' kok klasoru altinda $MFT + kullanici basina NTUSER.DAT."""
    root = tmp_path / "imported" / "C"
    (root).mkdir(parents=True)
    (root / "$MFT").write_bytes(b"sahte mft icerigi")
    (root / "Users" / "kaan").mkdir(parents=True)
    (root / "Users" / "kaan" / "NTUSER.DAT").write_bytes(b"sahte ntuser icerigi")
    return root


def test_import_mode_collects_without_opening_vss(tmp_path, import_mode_collection_fake_catalog, monkeypatch):
    # requires_vss=True olan hedefler bile VAR -- VssSnapshot CAGRILIRSA
    # test patlamali, import modunun "VSS'e hic gerek yok" ilkesini kilitler.
    monkeypatch.setattr(
        "triagechain.collection.collector.VssSnapshot",
        MagicMock(side_effect=AssertionError("VSS ice aktarma modunda ACILMAMALI")),
    )
    source_root = _imported_tree(tmp_path)
    config = _import_mode_collection_config(tmp_path, import_mode_collection_fake_catalog, source_root)
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, IMPORT_MODE_COLLECTION_CASE_ID)

    manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 2
    assert manifest.errors == []
    by_type = {a.artifact_type_id: a for a in manifest.artifacts}
    assert by_type["fake_mft"].source_path == str(source_root / "$MFT")
    assert Path(by_type["fake_mft"].dest_path).read_bytes() == b"sahte mft icerigi"
    assert by_type["fake_ntuser"].source_path == str(source_root / "Users" / "kaan" / "NTUSER.DAT")

    result = verify_chain(log_path, IMPORT_MODE_COLLECTION_CASE_ID)
    assert result.is_valid, result.message


def test_import_mode_is_recorded_in_custody_payload(tmp_path, import_mode_collection_fake_catalog, monkeypatch):
    # Denetim izinde "bu bir CANLI toplama degil" acikca gorunmeli --
    # bkz. collector.py -> run_collection dokstring'i.
    monkeypatch.setattr("triagechain.collection.collector.VssSnapshot", MagicMock())
    source_root = _imported_tree(tmp_path)
    config = _import_mode_collection_config(tmp_path, import_mode_collection_fake_catalog, source_root)
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, IMPORT_MODE_COLLECTION_CASE_ID)

    run_collection(config, ledger)

    from triagechain.custody.ledger import read_events

    case_opened = next(e for e in read_events(log_path) if e.event_type == "case_opened")
    assert case_opened.payload["mode"] == "import"
    assert case_opened.payload["source_root"] == str(source_root)


def test_without_source_root_behavior_is_unchanged(tmp_path, import_mode_collection_fake_catalog, monkeypatch):
    """source_root ayarlanmamissa (varsayilan None) davranis HIC degismemeli:
    VSS gerektiren hedefler icin snapshot yine acilmaya CALISILIR (burada
    gercek VSS yerine bir mock ile, sadece cagrildigini dogrulamak icin)."""
    vss_mock = MagicMock()
    vss_mock.return_value.__enter__.return_value = vss_mock.return_value
    # translate() gercek gibi davransin (yolu oldugu gibi geri versin) --
    # boylece asagidaki gercek dosya-yok hatasi normal (OSError) yoldan
    # yakalanir, mock'un kendisi beklenmedik bir istisna FIRLATMAZ.
    vss_mock.return_value.translate.side_effect = lambda p: p
    monkeypatch.setattr("triagechain.collection.collector.VssSnapshot", vss_mock)

    data = {
        "case": {"case_id": IMPORT_MODE_COLLECTION_CASE_ID, "operator": "test.operator"},
        "collection": {
            "targets": ["fake_mft", "fake_ntuser"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
            # source_root YOK -- varsayilan davranis.
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    config = load_config(config_path)
    ledger = CustodyLedger(resolve_custody_log_path(config), IMPORT_MODE_COLLECTION_CASE_ID)

    run_collection(config, ledger)

    vss_mock.assert_called_once_with()


# ============================================================================
# Kaynak: tests/integration/test_multi_disk_collection.py
# ============================================================================
# Coklu disk destegi: `collection.additional_volumes`'daki her birimin
# kendi $MFT'sinin de toplandigini dogrular.
#
# VSS gercekten cagrilmiyor (CI Linux'ta calisiyor, gercek WMI'ye ihtiyac
# yok): `VssSnapshot` `triagechain.collection.collector` icindeki kullanim
# yerinde sahte bir surumle degistiriliyor -- `translate()` dogrudan sahte
# bir "$MFT" dosyasina isaret ediyor. VSS'in KENDI davranisi zaten
# test_vss_snapshot.py'de ayrica test ediliyor.
#




MULTI_DISK_COLLECTION_CASE_ID = "CASE-TEST-MULTIDISK"


@pytest.fixture
def multi_disk_collection_fake_catalog(tmp_path, monkeypatch):
    """Hicbir katalog hedefi secilmeyecek -- bu test SADECE additional_volumes'i
    kapsiyor, ama sema en az bir 'targets' girdisi zorunlu kildigi icin
    zararsiz, VSS gerektirmeyen tek bir sahte hedef tanimlaniyor."""
    harmless = tmp_path / "harmless.txt"
    harmless.write_text("zararsiz", encoding="utf-8")
    catalog = {
        "targets": [
            {
                "id": "harmless",
                "category": "test",
                "requires_vss": False,
                "paths": [str(harmless)],
                "description": "additional_volumes disindaki zorunlu hedef",
            },
        ]
    }
    path = tmp_path / "test_targets.yaml"
    path.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(catalog_module, "default_catalog_path", lambda: path)
    return path


@pytest.fixture
def fake_mft_d(tmp_path):
    """D: biriminin (sahte) $MFT'si -- gercek VSS yerine dogrudan bu dosya okunur."""
    mft = tmp_path / "fake_mft_d.bin"
    mft.write_bytes(b"sahte NTFS MFT kaydi - D birimi")
    return mft


@pytest.fixture
def multi_disk_collection_config(tmp_path, multi_disk_collection_fake_catalog):
    data = {
        "case": {"case_id": MULTI_DISK_COLLECTION_CASE_ID, "operator": "test.operator", "description": "coklu disk"},
        "collection": {
            "targets": ["harmless"],
            "additional_volumes": ["D:"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "multi_disk_collection_config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _fake_vss_snapshot_class(translated_path: Path):
    """`VssSnapshot(volume=...)` cagrisinin yerine gececek sahte sinif --
    context manager olarak davranir, translate() HER ZAMAN ayni sahte
    dosyayi dondurur (bu testte tek bir ek birim/dosya var)."""
    instance = MagicMock()
    instance.__enter__ = MagicMock(return_value=instance)
    instance.__exit__ = MagicMock(return_value=False)
    instance.translate = MagicMock(return_value=translated_path)
    return MagicMock(return_value=instance)


def test_additional_volume_mft_is_collected(multi_disk_collection_config, fake_mft_d, monkeypatch):
    monkeypatch.setattr(
        "triagechain.collection.collector.VssSnapshot",
        _fake_vss_snapshot_class(fake_mft_d),
    )

    log_path = resolve_custody_log_path(multi_disk_collection_config)
    ledger = CustodyLedger(log_path, MULTI_DISK_COLLECTION_CASE_ID)
    manifest = run_collection(multi_disk_collection_config, ledger)

    # 1 normal hedef (harmless) + 1 ek birim MFT'si = 2 artefakt.
    assert len(manifest.artifacts) == 2
    mft_artifacts = [a for a in manifest.artifacts if a.artifact_type_id == "mft_d"]
    assert len(mft_artifacts) == 1
    mft_artifact = mft_artifacts[0]
    assert mft_artifact.source_path == r"D:\$MFT"
    assert Path(mft_artifact.dest_path).read_bytes() == fake_mft_d.read_bytes()
    assert manifest.errors == []

    result = verify_chain(log_path, MULTI_DISK_COLLECTION_CASE_ID)
    assert result.is_valid, result.message


def test_unavailable_additional_volume_is_a_non_fatal_error(multi_disk_collection_config, monkeypatch):
    """Ek birimin golge kopyasi acilamazsa (or. birim yok/erisim yok) kosu
    durmamali, sadece o birim icin hata kaydedilmeli."""
    from triagechain.core.errors import CollectionError

    failing_snapshot = MagicMock(side_effect=CollectionError("birim bulunamadi"))
    monkeypatch.setattr("triagechain.collection.collector.VssSnapshot", failing_snapshot)

    log_path = resolve_custody_log_path(multi_disk_collection_config)
    ledger = CustodyLedger(log_path, MULTI_DISK_COLLECTION_CASE_ID)
    manifest = run_collection(multi_disk_collection_config, ledger)

    assert len(manifest.artifacts) == 1  # sadece 'harmless'
    assert [e["artifact_type_id"] for e in manifest.errors] == ["mft_d"]
    assert "birim bulunamadi" in manifest.errors[0]["message"]

    result = verify_chain(log_path, MULTI_DISK_COLLECTION_CASE_ID)
    assert result.is_valid, result.message


def test_additional_volumes_must_be_drive_letters():
    from pydantic import ValidationError

    from triagechain.config.schema import CollectionConfig

    with pytest.raises(ValidationError, match="surucu harfi"):
        CollectionConfig(
            targets=["mft"], output_dir="C:/tmp",
            additional_volumes=["not-a-drive"],
        )


def test_additional_volume_letter_is_normalized():
    from triagechain.config.schema import CollectionConfig

    multi_disk_collection_config = CollectionConfig(
        targets=["mft"], output_dir="C:/tmp", additional_volumes=["d:\\"],
    )
    assert multi_disk_collection_config.additional_volumes == ["D:"]


# ============================================================================
# Kaynak: tests/integration/test_suspicious_binary_collection.py
# ============================================================================
# capa'nin girdisi: `collection.suspicious_binaries`'daki analistin elle
# gosterdigi yurutulebilir dosyalarin toplandigini dogrular.
#
# additional_volumes'dan (bkz. test_multi_disk_collection.py) FARKI: VSS
# gerektirmez (analistin gosterdigi dosya genelde kilitli degildir), bu yuzden
# hicbir VSS mock'lamaya ihtiyac yok -- gercek dosyalar gercekten okunup
# kopyalanip hash'leniyor.
#




SUSPICIOUS_BINARY_COLLECTION_CASE_ID = "CASE-TEST-SUSPICIOUS-BINARY"


@pytest.fixture
def suspicious_binary_collection_fake_catalog(tmp_path, monkeypatch):
    """test_multi_disk_collection.py'deki AYNI gerekce: sema en az bir
    'targets' girdisi zorunlu kildigi icin zararsiz, VSS gerektirmeyen tek
    bir sahte hedef tanimlaniyor -- bu test SADECE suspicious_binaries'i
    kapsiyor."""
    harmless = tmp_path / "harmless.txt"
    harmless.write_text("zararsiz", encoding="utf-8")
    catalog = {
        "targets": [
            {
                "id": "harmless",
                "category": "test",
                "requires_vss": False,
                "paths": [str(harmless)],
                "description": "suspicious_binaries disindaki zorunlu hedef",
            },
        ]
    }
    path = tmp_path / "test_targets.yaml"
    path.write_text(yaml.safe_dump(catalog, allow_unicode=True), encoding="utf-8")
    monkeypatch.setattr(catalog_module, "default_catalog_path", lambda: path)
    return path


def _suspicious_binary_collection_config(tmp_path, suspicious_binary_collection_fake_catalog, binaries):
    data = {
        "case": {"case_id": SUSPICIOUS_BINARY_COLLECTION_CASE_ID, "operator": "test.operator", "description": "capa girdisi"},
        "collection": {
            "targets": ["harmless"],
            "suspicious_binaries": binaries,
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def test_suspicious_binary_is_collected(tmp_path, suspicious_binary_collection_fake_catalog):
    sample = tmp_path / "supheli.exe"
    sample.write_bytes(b"sahte PE icerigi")
    config = _suspicious_binary_collection_config(tmp_path, suspicious_binary_collection_fake_catalog, [str(sample)])

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, SUSPICIOUS_BINARY_COLLECTION_CASE_ID)
    manifest = run_collection(config, ledger)

    # 1 normal hedef (harmless) + 1 supheli dosya = 2 artefakt.
    assert len(manifest.artifacts) == 2
    binaries = [a for a in manifest.artifacts if a.artifact_type_id == "suspicious_binary"]
    assert len(binaries) == 1
    assert binaries[0].source_path == str(sample)
    assert Path(binaries[0].dest_path).read_bytes() == sample.read_bytes()
    assert manifest.errors == []

    result = verify_chain(log_path, SUSPICIOUS_BINARY_COLLECTION_CASE_ID)
    assert result.is_valid, result.message


def test_multiple_suspicious_binaries_collected_under_same_artifact_type(tmp_path, suspicious_binary_collection_fake_catalog):
    first = tmp_path / "birinci.exe"
    second = tmp_path / "ikinci.dll"
    first.write_bytes(b"birinci")
    second.write_bytes(b"ikinci")
    config = _suspicious_binary_collection_config(tmp_path, suspicious_binary_collection_fake_catalog, [str(first), str(second)])

    ledger = CustodyLedger(resolve_custody_log_path(config), SUSPICIOUS_BINARY_COLLECTION_CASE_ID)
    manifest = run_collection(config, ledger)

    binaries = [a for a in manifest.artifacts if a.artifact_type_id == "suspicious_binary"]
    assert {Path(a.source_path).name for a in binaries} == {"birinci.exe", "ikinci.dll"}


def test_missing_suspicious_binary_is_a_non_fatal_error(tmp_path, suspicious_binary_collection_fake_catalog):
    missing = tmp_path / "yok.exe"
    config = _suspicious_binary_collection_config(tmp_path, suspicious_binary_collection_fake_catalog, [str(missing)])

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, SUSPICIOUS_BINARY_COLLECTION_CASE_ID)
    manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 1  # sadece 'harmless'
    assert [e["artifact_type_id"] for e in manifest.errors] == ["suspicious_binary"]

    result = verify_chain(log_path, SUSPICIOUS_BINARY_COLLECTION_CASE_ID)
    assert result.is_valid, result.message


def test_no_suspicious_binaries_configured_collects_nothing_extra(tmp_path, suspicious_binary_collection_fake_catalog):
    config = _suspicious_binary_collection_config(tmp_path, suspicious_binary_collection_fake_catalog, [])
    manifest = run_collection(config, CustodyLedger(resolve_custody_log_path(config), SUSPICIOUS_BINARY_COLLECTION_CASE_ID))

    assert len(manifest.artifacts) == 1  # sadece 'harmless', hic ekstra hata da yok
    assert manifest.errors == []


def test_suspicious_binaries_must_be_absolute_paths():
    from pydantic import ValidationError

    from triagechain.config.schema import CollectionConfig

    with pytest.raises(ValidationError, match="mutlak yol"):
        CollectionConfig(
            targets=["mft"], output_dir="C:/tmp",
            suspicious_binaries=["goreli/yol.exe"],
        )

