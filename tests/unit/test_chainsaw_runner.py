"""Chainsaw tarama kosusu: basarili tarama, hata kodu, zaman asimi, atlama
ve yol kontrolu.

Hicbir test gercek bir Chainsaw ikilisi calistirmaz: subprocess.run her
testte YAMALANDIGI YERDE (triagechain.detection.chainsaw_runner.subprocess.run)
unittest.mock ile degistirilir. FAKE_JSON, gercek chainsaw 2.16.5'in GERCEK
SigmaHQ kurallariyla GERCEK bir EVTX-ATTACK-SAMPLES dosyasina karsi urettigi
ciktinin BIREBIR bicimidir (bkz. docs/aldigim_kararlar.md) -- alan adlari
(document.data.Event.System.*, tags) uydurulmadi.
"""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.chainsaw_runner import run_chainsaw_detection
from triagechain.detection.models import DetectionManifest

CASE_ID = "CASE-TEST-CHAINSAW"

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


def _make_config(tmp_path, chainsaw_path=None, rules_dir=None, mapping_file=None, timeout=600):
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "chainsaw_path": chainsaw_path, "rules_dir": rules_dir,
            "chainsaw_mapping_file": mapping_file, "chainsaw_timeout_seconds": timeout,
        },
    )


def _artifacts_root(config):
    return Path(config.collection.output_dir) / CASE_ID / "artifacts"


def _make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    if dest_path is None:
        dest = _artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte evtx")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\kaynak\{filename}",
        dest_path=dest_path, hash_value="0" * 64, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=CASE_ID,
    )


def _make_manifest(artifacts):
    return CollectionManifest(
        case_id=CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _fake_tool(tmp_path, name="chainsaw.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules_dir(tmp_path):
    rules = tmp_path / "sigma"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "ornek.yml").write_text("title: ornek", encoding="utf-8")
    return str(rules)


def _fake_mapping(tmp_path):
    mapping = tmp_path / "mapping.yml"
    mapping.write_text("name: sahte esleme", encoding="utf-8")
    return str(mapping)


def _configured(tmp_path, **kwargs):
    return _make_config(
        tmp_path, chainsaw_path=_fake_tool(tmp_path), rules_dir=_fake_rules_dir(tmp_path),
        mapping_file=_fake_mapping(tmp_path), **kwargs,
    )


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _writes_json(records):
    """Sahte Chainsaw: -o ile verilen yola bir JSON listesi yazip 0 ile doner."""
    def side_effect(argv, **kwargs):
        out_path = Path(argv[argv.index("-o") + 1])
        out_path.write_text(json.dumps(records), encoding="utf-8")
        return _completed(argv, stdout=b"[+] 1 Detections found\n")
    return side_effect


def _assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_findings_with_real_field_shape(tmp_path):
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([FAKE_JSON_RECORD])
        detection = run_chainsaw_detection(config, _make_manifest([artifact]), ledger)

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
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["chainsaw_started", "chainsaw_completed_for_artifact", "chainsaw_completed"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_no_findings_is_empty_json_list_not_an_error(tmp_path):
    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([])
        detection = run_chainsaw_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    assert detection.findings == [] and detection.errors == []
    assert detection.scanned[0]["finding_count"] == 0


def test_chainsaw_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([FAKE_JSON_RECORD])
        detection = run_chainsaw_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CASE_ID / "chainsaw_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "chainsaw_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["chainsaw_manifest_sha256"] == expected

    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 1


def test_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _configured(tmp_path)
    failing = _make_artifact(config, filename="Bad.evtx")
    ok = _make_artifact(config, filename="Good.evtx")
    ledger = _ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if any("Bad.evtx" in part for part in argv):
            return _completed(argv, returncode=1, stderr=b"kural yuklenemedi")
        return _writes_json([])(argv, **kwargs)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        detection = run_chainsaw_detection(config, _make_manifest([failing, ok]), ledger)

    assert len(detection.errors) == 1
    assert detection.errors[0]["exit_code"] == 1
    assert detection.errors[0]["stderr_excerpt"] == "kural yuklenemedi"
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    _assert_never_uses_shell(mock_run)


def test_timeout_is_a_non_fatal_error(tmp_path):
    config = _configured(tmp_path, timeout=5)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["chainsaw.exe"], timeout=5)
        detection = run_chainsaw_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    assert detection.scanned == [] and detection.findings == []
    assert len(detection.errors) == 1
    assert "5 saniyede bitmedi" in detection.errors[0]["message"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_tool_not_configured_is_skipped(tmp_path):
    config = _make_config(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "konfigure edilmemis" in detection.skipped[0]["message"]


def test_mapping_file_not_configured_is_skipped(tmp_path):
    config = _make_config(
        tmp_path, chainsaw_path=_fake_tool(tmp_path), rules_dir=_fake_rules_dir(tmp_path),
    )
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "esleme dosyasi konfigure edilmemis" in detection.skipped[0]["message"]


def test_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _configured(tmp_path)
    outside = tmp_path / "disari" / "Security.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _make_artifact(config, dest_path=str(outside))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        detection = run_chainsaw_detection(config, _make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert "cikti agaci disinda" in detection.errors[0]["message"]


def test_only_event_logs_are_scanned(tmp_path):
    """Hayabusa ile ayni kisit: sadece event_logs taranir."""
    config = _configured(tmp_path)
    evtx = _make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx")
    prefetch = _make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.chainsaw_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_json([])
        run_chainsaw_detection(config, _make_manifest([evtx, prefetch]), ledger)

    assert mock_run.call_count == 1
