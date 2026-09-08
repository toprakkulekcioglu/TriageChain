"""Ice aktarma modu: `collection.source_root` ayarlandiginda BASKA bir aracla
(orn. KAPE) ONCEDEN toplanmis bir artefakt agacinin, canli sistem yerine
kaynak olarak kullanildigini dogrular.

GERCEK bir KAPE toplama zip'ine (384 gercek dosya: $MFT, SAM/SECURITY/
SYSTEM/SOFTWARE kovanlari, 121 gercek .evtx, gercek prefetch dosyalari)
karsi da elle dogrulandi -- bkz. aldigim_kararlar.md -> "Ice aktarma modu".
Buradaki testler kucuk, sahte ama GERCEKCI bir artefakt agaciyla ayni
mantigi (VSS ACILMAZ, requires_vss=True olsa bile; katalog kalibi
source_root altina rebase edilir) izole olarak dogruluyor.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import CustodyLedger, verify_chain

CASE_ID = "CASE-TEST-IMPORT-MODE"


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
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


def _config(tmp_path, fake_catalog, source_root):
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "ice aktarma"},
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


def test_import_mode_collects_without_opening_vss(tmp_path, fake_catalog, monkeypatch):
    # requires_vss=True olan hedefler bile VAR -- VssSnapshot CAGRILIRSA
    # test patlamali, import modunun "VSS'e hic gerek yok" ilkesini kilitler.
    monkeypatch.setattr(
        "triagechain.collection.collector.VssSnapshot",
        MagicMock(side_effect=AssertionError("VSS ice aktarma modunda ACILMAMALI")),
    )
    source_root = _imported_tree(tmp_path)
    config = _config(tmp_path, fake_catalog, source_root)
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)

    manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 2
    assert manifest.errors == []
    by_type = {a.artifact_type_id: a for a in manifest.artifacts}
    assert by_type["fake_mft"].source_path == str(source_root / "$MFT")
    assert Path(by_type["fake_mft"].dest_path).read_bytes() == b"sahte mft icerigi"
    assert by_type["fake_ntuser"].source_path == str(source_root / "Users" / "kaan" / "NTUSER.DAT")

    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message


def test_import_mode_is_recorded_in_custody_payload(tmp_path, fake_catalog, monkeypatch):
    # Denetim izinde "bu bir CANLI toplama degil" acikca gorunmeli --
    # bkz. collector.py -> run_collection dokstring'i.
    monkeypatch.setattr("triagechain.collection.collector.VssSnapshot", MagicMock())
    source_root = _imported_tree(tmp_path)
    config = _config(tmp_path, fake_catalog, source_root)
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)

    run_collection(config, ledger)

    from triagechain.custody.ledger import read_events

    case_opened = next(e for e in read_events(log_path) if e.event_type == "case_opened")
    assert case_opened.payload["mode"] == "import"
    assert case_opened.payload["source_root"] == str(source_root)


def test_without_source_root_behavior_is_unchanged(tmp_path, fake_catalog, monkeypatch):
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
        "case": {"case_id": CASE_ID, "operator": "test.operator"},
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
    ledger = CustodyLedger(resolve_custody_log_path(config), CASE_ID)

    run_collection(config, ledger)

    vss_mock.assert_called_once_with()