"""YARA tarama kosusu: basarili tarama, eslesmesiz tarama, hata kodu, zaman
asimi, atlama ve yol kontrolu.

Hicbir test gercek bir YARA ikilisi calistirmaz: subprocess.run her testte
YAMALANDIGI YERDE (triagechain.detection.yara_runner.subprocess.run)
unittest.mock ile degistirilir -- test_detection_runner.py ile AYNI desen.
Gercek yara64.exe 4.5.5'e karsi manuel dogrulama yapildi (bkz.
docs/hatalar_ve_sonuclar.md); buradaki FAKE_STDOUT o gercek ciktinin
bicimini birebir yansitir.
"""

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.models import YaraManifest
from triagechain.detection.yara_runner import run_yara_scan

CASE_ID = "CASE-TEST-YARA"

# Gercek yara64.exe 4.5.5 ciktisi (bkz. docs/hatalar_ve_sonuclar.md):
# "<kural> [<tag,tag>] [<k>=\"v\",...] <dosya>", eslesme yoksa BOS stdout.
FAKE_STDOUT_MATCH = (
    'Test_Suspicious_String [malware,mimikatz] [author="test",severity="high"] {path}\n'
)


def _make_config(tmp_path, yara_path=None, yara_rules_file=None, yara_timeout_seconds=300):
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
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


def _artifacts_root(config):
    return Path(config.collection.output_dir) / CASE_ID / "artifacts"


def _make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    if dest_path is None:
        dest = _artifacts_root(config) / artifact_type_id / filename
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
        case_id=CASE_ID,
    )


def _make_manifest(artifacts):
    return CollectionManifest(
        case_id=CASE_ID,
        started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc),
        artifacts=list(artifacts),
    )


def _fake_tool(tmp_path, name="yara64.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules_file(tmp_path):
    rules = tmp_path / "rules" / "custom.yar"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text("rule ornek { condition: true }", encoding="utf-8")
    return str(rules)


def _configured(tmp_path, **kwargs):
    return _make_config(
        tmp_path, yara_path=_fake_tool(tmp_path), yara_rules_file=_fake_rules_file(tmp_path),
        **kwargs,
    )


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _no_match():
    """Sahte YARA: hicbir esleşme yok -- gercek ikilinin dogrulanmis davranisi
    (bos stdout, cikis kodu 0)."""
    def side_effect(argv, **kwargs):
        return _completed(argv, stdout=b"")
    return side_effect


def _matches(path_in_argv_index=-1):
    """Sahte YARA: taranan dosyanin KENDI yoluyla eslesen bir satir uretir."""
    def side_effect(argv, **kwargs):
        target = argv[-1]
        return _completed(argv, stdout=FAKE_STDOUT_MATCH.format(path=target).encode("utf-8"))
    return side_effect


def _assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_with_match_produces_one_yaramatch(tmp_path):
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _matches()
        yara_manifest = run_yara_scan(config, _make_manifest([artifact]), ledger)

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
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["yara_started", "yara_completed_for_artifact", "yara_completed"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_no_match_is_not_an_error_empty_stdout(tmp_path):
    """Gercek yara64.exe'nin dogrulanmis davranisi: eslesme yoksa bos stdout +
    cikis kodu 0 -- bu bir hata degil, sadece 0 eslesmeli bir tarama sonucu."""
    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _no_match()
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    assert yara_manifest.matches == []
    assert yara_manifest.errors == []
    assert yara_manifest.scanned[0]["match_count"] == 0


def test_yara_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _matches()
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CASE_ID / "yara_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "yara_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["yara_manifest_sha256"] == expected
    assert closing.payload["match_count"] == 1

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == yara_manifest.run_id
    assert len(reloaded.matches) == 1


def test_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _configured(tmp_path)
    failing = _make_artifact(config, filename="Bad.bin")
    ok = _make_artifact(config, filename="Good.bin")
    ledger = _ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if "Bad.bin" in argv[-1]:
            return _completed(argv, returncode=1, stderr=b"kural dosyasi derlenemedi")
        return _no_match()(argv, **kwargs)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        yara_manifest = run_yara_scan(config, _make_manifest([failing, ok]), ledger)

    assert len(yara_manifest.errors) == 1
    assert yara_manifest.errors[0]["exit_code"] == 1
    assert yara_manifest.errors[0]["stderr_excerpt"] == "kural dosyasi derlenemedi"
    assert [Path(s["source_path"]).name for s in yara_manifest.scanned] == ["Good.bin"]
    assert mock_run.call_count == 2
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("yara_error") == 1
    assert event_types.count("yara_completed_for_artifact") == 1


def test_timeout_is_a_non_fatal_error(tmp_path):
    config = _configured(tmp_path, yara_timeout_seconds=5)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["yara64.exe"], timeout=5)
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    assert yara_manifest.scanned == [] and yara_manifest.matches == []
    assert len(yara_manifest.errors) == 1
    assert "5 saniyede bitmedi" in yara_manifest.errors[0]["message"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_tool_not_configured_is_skipped(tmp_path):
    config = _make_config(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert yara_manifest.matches == [] and yara_manifest.errors == []
    assert len(yara_manifest.skipped) == 1
    assert "konfigure edilmemis" in yara_manifest.skipped[0]["message"]


def test_rules_file_not_configured_is_skipped(tmp_path):
    config = _make_config(tmp_path, yara_path=_fake_tool(tmp_path))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural dosyasi konfigure edilmemis" in yara_manifest.skipped[0]["message"]


def test_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    missing_exe = str(tmp_path / "olmayan" / "yara64.exe")
    config = _make_config(tmp_path, yara_path=missing_exe, yara_rules_file=_fake_rules_file(tmp_path))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    message = yara_manifest.skipped[0]["message"]
    assert "yolu bulunamadi" in message and missing_exe in message


def test_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _configured(tmp_path)
    outside = tmp_path / "disari" / "Security.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _make_artifact(config, dest_path=str(outside))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.yara_runner.subprocess.run") as mock_run:
        yara_manifest = run_yara_scan(config, _make_manifest([artifact]), ledger)

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
        "case": {"case_id": CASE_ID, "operator": "test.operator"},
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
    assert not (output_dir / CASE_ID / "yara_manifest.json").exists()
