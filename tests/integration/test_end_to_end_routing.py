"""Uctan uca topla + yonlendir testi.

Faz 1'in uctan uca testiyle ayni kurgu: sahte katalogtaki her girdide
requires_vss=False oldugu icin yonetici hakki ya da gercek Windows gerekmez.
Faz 2 tarafinda ise gercek bir EZ Tools ikilisi CALISTIRILMAZ; subprocess.run
yamalanip, cikti dizinine sahte bir CSV yazan bir "arac" taklit edilir.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from triagechain.collection import catalog as collection_catalog
from triagechain.collection.collector import run_collection
from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.router import catalog as router_catalog
from triagechain.router.models import RoutingManifest
from triagechain.router.runner import run_router

FAKE_ARTIFACTS = Path(__file__).resolve().parents[1] / "fixtures" / "fake_artifacts"
CASE_ID = "CASE-TEST-E2E-ROUTE"


@pytest.fixture
def fake_catalogs(tmp_path, monkeypatch):
    """Hem toplama katalogunu hem arac esleme katalogunu sahtesiyle degistirir."""
    targets = {
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
def config(tmp_path, fake_catalogs, fake_tool_exe):
    data = {
        "case": {"case_id": CASE_ID, "operator": "test.operator", "description": "e2e route"},
        "collection": {
            "targets": ["fake_logs", "fake_notes"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        "custody": {"log_path": None},
        "router": {"tools": {"faketool": str(fake_tool_exe)}, "timeout_seconds": 30},
        "logging": {"level": "INFO"},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return load_config(config_path)


def _fake_tool_run(argv, **kwargs):
    """Gercek aracin yerine gecer: cikti dizinine bir CSV yazip 0 ile doner."""
    output_dir = Path(argv[argv.index("--csv") + 1])
    input_name = Path(argv[argv.index("-f") + 1]).name
    (output_dir / f"{input_name}.csv").write_text("satir1,satir2\n", encoding="utf-8")
    return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"bitti\n", stderr=b"")


def test_collect_then_route_end_to_end(config):
    log_path = resolve_custody_log_path(config)
    ledger = CustodyLedger(log_path, CASE_ID)

    collection = run_collection(config, ledger)
    assert len(collection.artifacts) == 3  # 2 log + 1 not

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _fake_tool_run
        routing = run_router(config, collection, ledger)

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
        assert output_dir.is_relative_to(Path(config.collection.output_dir) / CASE_ID / "parsed")

    # 3) Hicbir cagri kabuk uzerinden yapilmamis olmali.
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)
        assert call.kwargs["timeout"] == 30

    # 4) Yonlendirme manifesti diske yazilip geri okunabilmeli.
    routing_path = Path(config.collection.output_dir) / CASE_ID / "routing_manifest.json"
    routing.to_json_file(routing_path)
    reloaded = RoutingManifest.from_json_file(routing_path)
    assert reloaded.run_id == routing.run_id
    assert len(reloaded.processed) == 2
    assert reloaded.ended_at_utc is not None

    # 5) Tek bir custody zinciri hem toplama hem yonlendirme olaylarini kapsamali.
    result = verify_chain(log_path, CASE_ID)
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
