"""capa tarama kosusu: basarili tarama, hata kodu, zaman asimi, atlama ve yol kontrolu.

Hicbir test gercek bir capa ikilisi calistirmaz: subprocess.run her testte
YAMALANDIGI YERDE (triagechain.detection.capa_runner.subprocess.run)
unittest.mock ile degistirilir. FAKE_JSON_OUTPUT, gercek capa 9.4.0'in
gercek bir PE dosyasina (notepad.exe) karsi urettigi --json ciktisinin
sadelestirilmis ama GERCEK alan yollarini (meta.namespace, meta.attack[].id)
koruyan bir kopyasidir (bkz. docs/aldigim_kararlar.md -> "capa entegrasyonu").
"""

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

CASE_ID = "CASE-TEST-CAPA"

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


def _make_config(tmp_path, capa_path=None, rules_dir=None, timeout=1800):
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "capa_path": capa_path, "capa_rules_dir": rules_dir, "capa_timeout_seconds": timeout,
        },
    )


def _artifacts_root(config):
    return Path(config.collection.output_dir) / CASE_ID / "artifacts"


def _make_artifact(
    config, artifact_type_id="suspicious_binary", filename="sample.exe", dest_path=None
):
    if dest_path is None:
        dest = _artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte pe")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\supheli\{filename}",
        dest_path=dest_path, hash_value="0" * 64, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=CASE_ID,
    )


def _make_manifest(artifacts):
    return CollectionManifest(
        case_id=CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _fake_tool(tmp_path, name="capa.exe"):
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules_dir(tmp_path):
    rules = tmp_path / "capa-rules"
    rules.mkdir(parents=True, exist_ok=True)
    return str(rules)


def _configured(tmp_path, **kwargs):
    return _make_config(tmp_path, capa_path=_fake_tool(tmp_path), **kwargs)


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _writes_stdout(payload):
    """Sahte capa: JSON'u DOGRUDAN stdout'a yazip 0 ile doner (capa'nin -j
    davranisi -- Chainsaw'in -o dosyasindan FARKLI, bkz. capa_args.yaml)."""
    def side_effect(argv, **kwargs):
        return _completed(argv, stdout=json.dumps(payload).encode("utf-8"))
    return side_effect


def _assert_never_uses_shell(mock_run):
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_matches_with_real_field_shape(tmp_path):
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout(FAKE_JSON_OUTPUT)
        capa_manifest = run_capa_scan(config, _make_manifest([artifact]), ledger)

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
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["capa_started", "capa_completed_for_artifact", "capa_completed"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_custom_rules_dir_is_added_to_argv_when_configured(tmp_path):
    config = _configured(tmp_path, rules_dir=_fake_rules_dir(tmp_path))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    argv = mock_run.call_args.args[0]
    assert "-r" in argv and config.detection.capa_rules_dir in argv


def test_no_matched_rules_is_empty_dict_not_an_error(tmp_path):
    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        capa_manifest = run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    assert capa_manifest.matches == [] and capa_manifest.errors == []
    assert capa_manifest.scanned[0]["match_count"] == 0


def test_capa_manifest_is_written_and_its_hash_recorded(tmp_path):
    import hashlib

    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout(FAKE_JSON_OUTPUT)
        capa_manifest = run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CASE_ID / "capa_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "capa_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["capa_manifest_sha256"] == expected

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == capa_manifest.run_id
    assert len(reloaded.matches) == 2


def test_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _configured(tmp_path)
    failing = _make_artifact(config, filename="bad.exe")
    ok = _make_artifact(config, filename="good.exe")
    ledger = _ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if any("bad.exe" in part for part in argv):
            return _completed(argv, returncode=16, stderr=b"desteklenmeyen dosya bicimi")
        return _writes_stdout({"meta": {}, "rules": {}})(argv, **kwargs)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        capa_manifest = run_capa_scan(config, _make_manifest([failing, ok]), ledger)

    assert len(capa_manifest.errors) == 1
    assert capa_manifest.errors[0]["exit_code"] == 16
    assert capa_manifest.errors[0]["stderr_excerpt"] == "desteklenmeyen dosya bicimi"
    assert [Path(s["source_path"]).name for s in capa_manifest.scanned] == ["good.exe"]
    _assert_never_uses_shell(mock_run)


def test_timeout_is_a_non_fatal_error(tmp_path):
    config = _configured(tmp_path, timeout=5)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["capa.exe"], timeout=5)
        capa_manifest = run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    assert capa_manifest.scanned == [] and capa_manifest.matches == []
    assert len(capa_manifest.errors) == 1
    assert "5 saniyede bitmedi" in capa_manifest.errors[0]["message"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_tool_not_configured_is_skipped(tmp_path):
    config = _make_config(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "konfigure edilmemis" in capa_manifest.skipped[0]["message"]


def test_missing_rules_dir_is_skipped_even_though_it_is_optional(tmp_path):
    """capa_rules_dir SADECE ayarlandiginda kontrol edilir -- ayarlanip da
    diskte bulunamazsa (yanlis yazilmis bir yol) sessizce yok sayilmaz."""
    config = _configured(tmp_path, rules_dir=str(tmp_path / "olmayan-klasor"))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural klasoru bulunamadi" in capa_manifest.skipped[0]["message"]


def test_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    config = _configured(tmp_path)
    outside = tmp_path / "disari" / "sample.exe"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"x")
    artifact = _make_artifact(config, dest_path=str(outside))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        capa_manifest = run_capa_scan(config, _make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert "cikti agaci disinda" in capa_manifest.errors[0]["message"]


def test_cli_capa_scan_without_manifest_exits_with_code_2(tmp_path):
    """'capa-scan' da 'detect'/'yara-scan' ile ayni kural: once 'collect' calismali."""
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

    exit_code = main(["capa-scan", "--config", str(config_path)])

    assert exit_code == 2


def test_only_suspicious_binaries_are_scanned(tmp_path):
    """Hayabusa/Chainsaw'in 'sadece event_logs' kisitiyla ayni ilke: capa da
    SADECE analistin elle gosterdigi supheli dosyalari tarar."""
    config = _configured(tmp_path)
    binary = _make_artifact(config, artifact_type_id="suspicious_binary", filename="sample.exe")
    prefetch = _make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.capa_runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_stdout({"meta": {}, "rules": {}})
        run_capa_scan(config, _make_manifest([binary, prefetch]), ledger)

    assert mock_run.call_count == 1
