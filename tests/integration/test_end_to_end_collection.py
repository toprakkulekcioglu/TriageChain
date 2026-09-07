"""Uctan uca toplama testi.

Bu test bilerek VSS'siz kurgulanmistir: sahte katalogtaki her girdide
requires_vss=False oldugu icin yonetici haklarina ya da gercek Windows'a
ihtiyac duymaz, CI'da da calisir.
"""

from pathlib import Path

import pytest
import yaml

from triagechain.collection import catalog as catalog_module
from triagechain.collection.collector import run_collection
from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectionManifest
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain

FAKE_ARTIFACTS = Path(__file__).resolve().parents[1] / "fixtures" / "fake_artifacts"
CASE_ID = "CASE-TEST-E2E"


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
    """Gomulu katalogun yerine, fixture dosyalarini gosteren sahte katalog koyar."""
    catalog = {
        "targets": [
            {
                "id": "fake_logs",
                "category": "test",
                "requires_vss": False,
                "paths": [str(FAKE_ARTIFACTS / "*.log")],
                "description": "Sahte log dosyalari",
            },
            {
                "id": "fake_notes",
                "category": "test",
                "requires_vss": False,
                "paths": [str(FAKE_ARTIFACTS / "notes.txt")],
                "description": "Tek dosya",
            },
            {
                "id": "fake_missing",
                "category": "test",
                "requires_vss": False,
                "paths": [str(FAKE_ARTIFACTS / "*.hicyok")],
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
def config(tmp_path, fake_catalog):
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "e2e"},
        "collection": {
            "targets": ["fake_logs", "fake_notes", "fake_missing"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def test_end_to_end_collection(config):
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)

    manifest = run_collection(config, ledger)

    # 1) Dosyalar kopyalanmis olmali (2 log + 1 not).
    assert len(manifest.artifacts) == 3
    for artifact in manifest.artifacts:
        dest = Path(artifact.dest_path)
        assert dest.is_file()
        assert dest.stat().st_size == artifact.size_bytes
        # 2) Hash'ler kaynak ve hedefte ayni olmali.
        assert hash_file(dest, artifact.hash_algorithm) == artifact.hash_value
        assert hash_file(artifact.source_path, artifact.hash_algorithm) == artifact.hash_value
        assert artifact.case_id == CASE_ID

    # 3) Eslesmeyen hedef olumcul degil, hata olarak kaydedilmis olmali.
    assert [e["artifact_type_id"] for e in manifest.errors] == ["fake_missing"]

    # 4) Manifest diske yazilip geri okunabilmeli.
    manifest_path = Path(config.collection.output_dir) / CASE_ID / "manifest.json"
    manifest.to_json_file(manifest_path)
    reloaded = CollectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == manifest.run_id
    assert len(reloaded.artifacts) == 3
    assert reloaded.ended_at_utc is not None

    # 5) Custody zinciri saglam olmali.
    result = verify_chain(log_path, CASE_ID)
    assert result.is_valid, result.message

    event_types = [event.event_type for event in read_events(log_path)]
    assert event_types[0] == "case_opened"
    assert event_types[-1] == "case_closed"
    assert event_types.count("artifact_collected") == 3
    assert event_types.count("collection_error") == 1


def test_artifacts_are_written_under_type_directories(config):
    ledger = CustodyLedger(resolve_custody_log_path(config), CASE_ID)

    manifest = run_collection(config, ledger)

    artifacts_root = Path(config.collection.output_dir) / CASE_ID / "artifacts"
    assert sorted(p.name for p in (artifacts_root / "fake_logs").iterdir()) == [
        "alpha.log",
        "beta.log",
    ]
    assert (artifacts_root / "fake_notes" / "notes.txt").is_file()
    assert all(Path(a.dest_path).is_relative_to(artifacts_root) for a in manifest.artifacts)
