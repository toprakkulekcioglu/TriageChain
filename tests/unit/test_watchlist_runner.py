"""Hash listesi (watchlist/IOC) eslestirme kosusu: dosya ayristirma, eslesme,
eslesme-yok, atlama ve yol kontrolu.

capa/YARA testlerinin AKSINE hicbir subprocess YAMASI gerekmez -- watchlist
saf Python hash karsilastirmasi yapar (bkz. detection/watchlist_runner.py
modul dokstring'i)."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.models import YaraManifest
from triagechain.detection.watchlist_runner import load_watchlist, run_watchlist_check

CASE_ID = "CASE-TEST-WATCHLIST"
KNOWN_BAD_HASH = "e" * 64


def _make_config(tmp_path, hashes_file=None):
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"], "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={"watchlist_hashes_file": hashes_file},
    )


def _make_artifact(hash_value, artifact_type_id="prefetch", filename="APP.pf", dest_path=None):
    if dest_path is None:
        dest_path = str(Path("C:/vaka/artifacts") / artifact_type_id / filename)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id, source_path=rf"C:\kaynak\{filename}",
        dest_path=dest_path, hash_value=hash_value, hash_algorithm="sha256", size_bytes=10,
        collected_at_utc=datetime.now(timezone.utc), collecting_user="test.operator", case_id=CASE_ID,
    )


def _make_manifest(artifacts):
    return CollectionManifest(
        case_id=CASE_ID, started_at_utc=datetime.now(timezone.utc),
        ended_at_utc=datetime.now(timezone.utc), artifacts=list(artifacts),
    )


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _write_hashes(tmp_path, text):
    path = tmp_path / "watchlist.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


# -- load_watchlist -----------------------------------------------------------

def test_load_watchlist_parses_comma_and_space_labels(tmp_path):
    path = _write_hashes(
        tmp_path,
        "AAAA,Mimikatz\n"
        "bbbb Cobalt Strike beacon\n"
        "cccc\n",
    )
    hashes = load_watchlist(Path(path))
    assert hashes == {
        "aaaa": "Mimikatz",
        "bbbb": "Cobalt Strike beacon",
        "cccc": "cccc",
    }


def test_load_watchlist_skips_comments_and_blank_lines(tmp_path):
    path = _write_hashes(
        tmp_path,
        "# bu bir yorum satiri\n"
        "\n"
        "   \n"
        "dddd,gercek girdi\n"
        "# dddd degil bu\n",
    )
    hashes = load_watchlist(Path(path))
    assert hashes == {"dddd": "gercek girdi"}


def test_load_watchlist_is_case_insensitive_via_lowercasing(tmp_path):
    path = _write_hashes(tmp_path, "ABCDEF1234,Etiket\n")
    hashes = load_watchlist(Path(path))
    assert "abcdef1234" in hashes and "ABCDEF1234" not in hashes


def test_load_watchlist_last_duplicate_wins(tmp_path):
    path = _write_hashes(tmp_path, "aaaa,ilk\naaaa,sonuncu\n")
    hashes = load_watchlist(Path(path))
    assert hashes == {"aaaa": "sonuncu"}


# -- run_watchlist_check --------------------------------------------------------

def test_not_configured_is_skipped(tmp_path):
    config = _make_config(tmp_path, hashes_file=None)
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([_make_artifact("0" * 64)]), ledger)

    assert manifest.matches == []
    assert "konfigure edilmemis" in manifest.skipped[0]["message"]


def test_missing_file_is_skipped(tmp_path):
    config = _make_config(tmp_path, hashes_file=str(tmp_path / "olmayan.txt"))
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([_make_artifact("0" * 64)]), ledger)

    assert manifest.matches == []
    assert "bulunamadi" in manifest.skipped[0]["message"]


def test_matching_hash_produces_a_match(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Bilinen kötü araç\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    artifact = _make_artifact(KNOWN_BAD_HASH, filename="kotu.exe")
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([artifact]), ledger)

    assert len(manifest.matches) == 1
    match = manifest.matches[0]
    assert match.rule_name == "watchlist:Bilinen kötü araç"
    assert match.tags == "watchlist"
    assert match.meta == "hash_algorithm=sha256"
    assert match.source_path == artifact.dest_path
    assert manifest.scanned == [
        {
            "artifact_type_id": artifact.artifact_type_id,
            "source_path": artifact.dest_path,
            "match_count": 1,
        }
    ]


def test_case_insensitive_hash_comparison(tmp_path):
    """Kullanicinin sozunu verdigi 'buyuk/kucuk harf duyarsiz eslesme' ilkesi
    (arama ozelligiyle AYNI karar) hash karsilastirmasina da uygulanir."""
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH.upper()},Etiket\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    artifact = _make_artifact(KNOWN_BAD_HASH.lower())
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([artifact]), ledger)

    assert len(manifest.matches) == 1


def test_no_match_is_not_an_error(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    artifact = _make_artifact("1" * 64)
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([artifact]), ledger)

    assert manifest.matches == [] and manifest.errors == [] and manifest.skipped == []
    assert manifest.scanned[0]["match_count"] == 0


def test_multiple_artifacts_only_matching_ones_produce_matches(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Kötü Dosya\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    bad = _make_artifact(KNOWN_BAD_HASH, filename="kotu.exe")
    good1 = _make_artifact("1" * 64, filename="temiz1.exe")
    good2 = _make_artifact("2" * 64, filename="temiz2.exe")
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(config, _make_manifest([good1, bad, good2]), ledger)

    assert len(manifest.scanned) == 3
    assert len(manifest.matches) == 1
    assert manifest.matches[0].source_path == bad.dest_path


def test_ledger_events_and_no_per_artifact_event(tmp_path):
    """YARA/capa'nin AKSINE artefakt basina custody olayi YAZILMAZ (bkz.
    watchlist_runner.py modul dokstring'i) -- sadece basla/bitir cifti."""
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    ledger = _ledger(tmp_path)

    run_watchlist_check(
        config,
        _make_manifest([_make_artifact(KNOWN_BAD_HASH), _make_artifact("1" * 64)]),
        ledger,
    )

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["watchlist_started", "watchlist_completed"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_manifest_is_written_and_its_hash_recorded(tmp_path):
    hashes_file = _write_hashes(tmp_path, f"{KNOWN_BAD_HASH},Etiket\n")
    config = _make_config(tmp_path, hashes_file=hashes_file)
    ledger = _ledger(tmp_path)

    manifest = run_watchlist_check(
        config, _make_manifest([_make_artifact(KNOWN_BAD_HASH)]), ledger
    )

    manifest_path = Path(config.collection.output_dir) / CASE_ID / "watchlist_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "watchlist_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["watchlist_manifest_sha256"] == expected

    reloaded = YaraManifest.from_json_file(manifest_path)
    assert reloaded.run_id == manifest.run_id
    assert len(reloaded.matches) == 1


def test_cli_watchlist_check_without_manifest_exits_with_code_2(tmp_path):
    """'watchlist-check' da diger tarama komutlariyla ayni kural: once
    'collect' calismali."""
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

    exit_code = main(["watchlist-check", "--config", str(config_path)])

    assert exit_code == 2
