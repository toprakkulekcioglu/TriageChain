"""Uctan uca topla + yonlendir + tara + raporla testi.

Diger uctan uca testlerle ayni kurgu: sahte katalogtaki her girdide
requires_vss=False, dis araclar (EZ Tools/Hayabusa) hic calistirilmaz -
subprocess.run yamalanir. Rapor komutu CLI uzerinden cagrilir.
"""

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from triagechain.cli.main import main
from triagechain.collection import catalog as collection_catalog
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import read_events
from triagechain.reporting.models import Report

CASE_ID = "CASE-TEST-E2E-REPORT"

FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Mimikatz Detected,critical,WS-01,Security,4688,lsass erisimi\n"
)


@pytest.fixture
def fake_catalog(tmp_path, monkeypatch):
    """Toplama katalogunu tmp_path'teki sahte dosyalari gosteren bir kopyayla degistirir."""
    evtx_dir = tmp_path / "kaynak" / "winevt"
    evtx_dir.mkdir(parents=True)
    (evtx_dir / "Security.evtx").write_bytes(b"sahte evtx icerigi")

    targets = {
        "targets": [
            {
                "id": "event_logs",
                "category": "test",
                "requires_vss": False,
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
def config_path(tmp_path, fake_catalog):
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
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "e2e rapor"},
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
    Path(argv[argv.index("-o") + 1]).write_text(FAKE_CSV, encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_route_detect_then_report(config_path, capsys):
    assert main(["collect", "--config", str(config_path)]) == 0
    with patch("triagechain.router.runner.subprocess.run", side_effect=_fake_evtxecmd):
        assert main(["route", "--config", str(config_path)]) == 0
    with patch("triagechain.detection.runner.subprocess.run", side_effect=_fake_hayabusa):
        assert main(["detect", "--config", str(config_path)]) == 0

    config = load_config(config_path)
    log_path = resolve_custody_log_path(config)
    events_before = len(list(read_events(log_path)))
    capsys.readouterr()

    assert main(["report", "--config", str(config_path)]) == 0
    out = capsys.readouterr().out

    case_dir = Path(config.collection.output_dir) / CASE_ID
    json_path = case_dir / "report.json"
    html_path = case_dir / "report.html"
    sha_path = case_dir / "report.json.sha256"

    # 1) Uc dosya da yan yana yazilmis olmali.
    assert json_path.is_file() and html_path.is_file() and sha_path.is_file()
    assert "Zincir durumu : GECERLI" in out
    assert str(html_path) in out

    # 2) Rapor uc katmani da doldurmus olmali.
    report = Report.from_json_file(json_path)
    assert report.case_id == CASE_ID
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
    # Bu senaryo yara-scan/chainsaw-scan/capa-scan calistirmiyor, o uc bolum
    # "henuz calistirilmadi" olmali.
    assert html.count("henüz çalıştırılmadı") == 3
