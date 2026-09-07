"""Uctan uca topla + tespit et testi.

Faz 1'in uctan uca testiyle ayni kurgu: sahte katalogtaki her girdide
requires_vss=False oldugu icin yonetici hakki ya da gercek Windows gerekmez.
Faz 4 tarafinda gercek bir Hayabusa ikilisi CALISTIRILMAZ; subprocess.run
yamalanip, cikti CSV'sini yazan bir "arac" taklit edilir.
"""

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from triagechain.collection import catalog as collection_catalog
from triagechain.collection.collector import run_collection
from triagechain.config.loader import (
    load_config,
    resolve_custody_log_path,
    resolve_detection_manifest_path,
)
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.models import DetectionManifest
from triagechain.detection.runner import run_detection

CASE_ID = "CASE-TEST-E2E-DETECT"

FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Mimikatz Detected,critical,WS-01,Security,4688,lsass erisimi\n"
    "2026-01-02 03:06:00.000 +03:00,Failed Logon,low,WS-01,Security,4625,Yanlis parola\n"
)


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
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
                "requires_vss": False,
                "paths": [str(evtx_dir / "*.evtx")],
                "description": "Sahte olay gunlukleri",
            },
            {
                "id": "prefetch",
                "category": "test",
                "requires_vss": False,
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
def config(tmp_path, fake_catalog):
    hayabusa = tmp_path / "tools" / "hayabusa.exe"
    hayabusa.parent.mkdir(parents=True, exist_ok=True)
    hayabusa.write_text("sahte arac", encoding="utf-8")
    rules_dir = tmp_path / "sigma" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "ornek.yml").write_text("title: ornek", encoding="utf-8")

    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "e2e detect"},
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
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _fake_hayabusa_run(argv, **kwargs):
    """Gercek aracin yerine gecer: -o ile verilen yola CSV yazip 0 ile doner."""
    Path(argv[argv.index("-o") + 1]).write_text(FAKE_CSV, encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_then_detect_end_to_end(config):
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)

    collection = run_collection(config, ledger)
    assert len(collection.artifacts) == 3  # 2 evtx + 1 prefetch

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _fake_hayabusa_run
        detection = run_detection(config, collection, ledger)

    # 1) Yalnizca iki olay gunlugu taranmis, prefetch'e dokunulmamis olmali.
    assert mock_run.call_count == 2
    assert {Path(s["source_path"]).name for s in detection.scanned} == {
        "Security.evtx", "System.evtx"
    }
    assert len(detection.findings) == 4  # dosya basina 2 bulgu
    assert detection.errors == [] and detection.skipped == []
    assert {f.rule_title for f in detection.findings} == {"Mimikatz Detected", "Failed Logon"}

    # 2) "Arac" ciktisini ve denetim loglarini vakanin agacina yazmis olmali.
    detections_root = Path(config.collection.output_dir) / CASE_ID / "detections" / "hayabusa"
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
    manifest_path = resolve_detection_manifest_path(config)
    assert manifest_path.is_file()
    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 4
    assert reloaded.ended_at_utc is not None

    # 5) Tek bir custody zinciri hem toplama hem tespit olaylarini kapsamali.
    result = verify_chain(log_path, CASE_ID)
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
