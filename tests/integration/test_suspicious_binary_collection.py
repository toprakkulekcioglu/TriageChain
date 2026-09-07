"""capa'nin girdisi: `collection.suspicious_binaries`'daki analistin elle
gosterdigi yurutulebilir dosyalarin toplandigini dogrular.

additional_volumes'dan (bkz. test_multi_disk_collection.py) FARKI: VSS
gerektirmez (analistin gosterdigi dosya genelde kilitli degildir), bu yuzden
hicbir VSS mock'lamaya ihtiyac yok -- gercek dosyalar gercekten okunup
kopyalanip hash'leniyor.
"""

from pathlib import Path

import pytest
import yaml

from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import CustodyLedger, verify_chain

CASE_ID = "CASE-TEST-SUSPICIOUS-BINARY"


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
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


def _config(tmp_path, fake_catalog, binaries):
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "capa girdisi"},
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


def test_suspicious_binary_is_collected(tmp_path, fake_catalog):
    sample = tmp_path / "supheli.exe"
    sample.write_bytes(b"sahte PE icerigi")
    config = _config(tmp_path, fake_catalog, [str(sample)])

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)
    manifest = run_collection(config, ledger)

    # 1 normal hedef (harmless) + 1 supheli dosya = 2 artefakt.
    assert len(manifest.artifacts) == 2
    binaries = [a for a in manifest.artifacts if a.artifact_type_id == "suspicious_binary"]
    assert len(binaries) == 1
    assert binaries[0].source_path == str(sample)
    assert Path(binaries[0].dest_path).read_bytes() == sample.read_bytes()
    assert manifest.errors == []

    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message


def test_multiple_suspicious_binaries_collected_under_same_artifact_type(tmp_path, fake_catalog):
    first = tmp_path / "birinci.exe"
    second = tmp_path / "ikinci.dll"
    first.write_bytes(b"birinci")
    second.write_bytes(b"ikinci")
    config = _config(tmp_path, fake_catalog, [str(first), str(second)])

    ledger = CustodyLedger(resolve_custody_log_path(config), CASE_ID)
    manifest = run_collection(config, ledger)

    binaries = [a for a in manifest.artifacts if a.artifact_type_id == "suspicious_binary"]
    assert {Path(a.source_path).name for a in binaries} == {"birinci.exe", "ikinci.dll"}


def test_missing_suspicious_binary_is_a_non_fatal_error(tmp_path, fake_catalog):
    missing = tmp_path / "yok.exe"
    config = _config(tmp_path, fake_catalog, [str(missing)])

    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)
    manifest = run_collection(config, ledger)

    assert len(manifest.artifacts) == 1  # sadece 'harmless'
    assert [e["artifact_type_id"] for e in manifest.errors] == ["suspicious_binary"]

    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message


def test_no_suspicious_binaries_configured_collects_nothing_extra(tmp_path, fake_catalog):
    config = _config(tmp_path, fake_catalog, [])
    manifest = run_collection(config, CustodyLedger(resolve_custody_log_path(config), CASE_ID))

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
