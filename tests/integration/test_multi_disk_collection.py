"""Coklu disk destegi: `collection.additional_volumes`'daki her birimin
kendi $MFT'sinin de toplandigini dogrular.

VSS gercekten cagrilmiyor (CI Linux'ta calisiyor, gercek WMI'ye ihtiyac
yok): `VssSnapshot` `triagechain.collection.collector` icindeki kullanim
yerinde sahte bir surumle degistiriliyor -- `translate()` dogrudan sahte
bir "$MFT" dosyasina isaret ediyor. VSS'in KENDI davranisi zaten
test_vss_snapshot.py'de ayrica test ediliyor.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import CustodyLedger, verify_chain

CASE_ID = "CASE-TEST-MULTIDISK"


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
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
def config(tmp_path, fake_catalog):
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "coklu disk"},
        "collection": {
            "targets": ["harmless"],
            "additional_volumes": ["D:"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "config.yaml"
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


def test_additional_volume_mft_is_collected(config, fake_mft_d, monkeypatch):
    monkeypatch.setattr(
        "triagechain.collection.collector.VssSnapshot",
        _fake_vss_snapshot_class(fake_mft_d),
    )

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)
    manifest = run_collection(config, ledger)

    # 1 normal hedef (harmless) + 1 ek birim MFT'si = 2 artefakt.
    assert len(manifest.artifacts) == 2
    mft_artifacts = [a for a in manifest.artifacts if a.artifact_type_id == "mft_d"]
    assert len(mft_artifacts) == 1
    mft_artifact = mft_artifacts[0]
    assert mft_artifact.source_path == r"D:\$MFT"
    assert Path(mft_artifact.dest_path).read_bytes() == fake_mft_d.read_bytes()
    assert manifest.errors == []

    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message


def test_unavailable_additional_volume_is_a_non_fatal_error(config, monkeypatch):
    """Ek birimin golge kopyasi acilamazsa (or. birim yok/erisim yok) kosu
    durmamali, sadece o birim icin hata kaydedilmeli."""
    from triagechain.core.errors import CollectionError

    failing_snapshot = MagicMock(side_effect=CollectionError("birim bulunamadi"))
    monkeypatch.setattr("triagechain.collection.collector.VssSnapshot", failing_snapshot)

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)
    manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 1  # sadece 'harmless'
    assert [e["artifact_type_id"] for e in manifest.errors] == ["mft_d"]
    assert "birim bulunamadi" in manifest.errors[0]["message"]

    result = verify_chain(log_path, CASE_ID)
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

    config = CollectionConfig(
        targets=["mft"], output_dir="C:/tmp", additional_volumes=["d:\\"],
    )
    assert config.additional_volumes == ["D:"]
