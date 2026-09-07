"""Tespit kosusu: basarili tarama, hata kodu, zaman asimi, atlama ve yol kontrolu.

Hicbir test gercek bir Hayabusa ikilisi calistirmaz: subprocess.run her testte
YAMALANDIGI YERDE (triagechain.detection.runner.subprocess.run) unittest.mock
ile degistirilir.
"""

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import DetectionError
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.detection.models import DetectionManifest
from triagechain.detection.runner import run_detection

CASE_ID = "CASE-TEST-DETECT"

# Hayabusa'nin uretmesi beklenen CSV'nin sahtesi (basliklar hayabusa_args.yaml
# icindeki adaylarla eslesir).
FAKE_CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n"
    "2026-01-02 03:04:05.678 +03:00,Suspicious PowerShell,high,WS-01,Security,4104,Encoded komut\n"
    "2026-01-02 03:05:00.000 +03:00,Failed Logon,low,WS-01,Security,4625,Yanlis parola\n"
)


def _make_config(tmp_path, hayabusa_path=None, rules_dir=None, timeout_seconds=600):
    """Tespit icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["event_logs"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        detection={
            "hayabusa_path": hayabusa_path,
            "rules_dir": rules_dir,
            "timeout_seconds": timeout_seconds,
        },
    )


def _artifacts_root(config):
    return Path(config.collection.output_dir) / CASE_ID / "artifacts"


def _make_artifact(config, artifact_type_id="event_logs", filename="Security.evtx", dest_path=None):
    """Cikti agacinda gercek bir dosya olusturur ve manifest kaydini dondurur.

    dest_path verilirse dosya olusturulmaz; bu, agac disi yol testinde kullaniliyor.
    """
    if dest_path is None:
        dest = _artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte evtx")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id,
        source_path=rf"C:\Windows\System32\winevt\Logs\{filename}",
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


def _fake_tool(tmp_path, name="hayabusa.exe"):
    """Diskte gercekten var olan, mutlak yollu sahte bir arac dosyasi."""
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _fake_rules(tmp_path):
    """Diskte var olan sahte bir Sigma kural klasoru."""
    rules = tmp_path / "sigma" / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "ornek.yml").write_text("title: ornek", encoding="utf-8")
    return str(rules)


def _configured(tmp_path, **kwargs):
    """Hem arac hem kural klasoru gercekten var olan konfigurasyon."""
    return _make_config(
        tmp_path, hayabusa_path=_fake_tool(tmp_path), rules_dir=_fake_rules(tmp_path), **kwargs
    )


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _writes_csv(content=FAKE_CSV):
    """Sahte Hayabusa: -o ile verilen yola bir CSV yazip 0 ile doner."""
    def side_effect(argv, **kwargs):
        Path(argv[argv.index("-o") + 1]).write_text(content, encoding="utf-8")
        return _completed(argv, stdout=b"tarama bitti\n")
    return side_effect


def _assert_never_uses_shell(mock_run):
    """Guvenlik kurali #1: hicbir cagri shell=True ile yapilmamali."""
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        # Ilk konumsal arguman her zaman arguman LISTESI olmali, tek metin degil.
        assert isinstance(call.args[0], list)


def test_successful_scan_produces_findings_and_one_summary_event(tmp_path):
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _make_manifest([artifact]), ledger)

    assert len(detection.findings) == 2
    assert detection.errors == [] and detection.skipped == []
    assert detection.findings[0].rule_title == "Suspicious PowerShell"
    assert detection.findings[0].level == "high"
    assert detection.findings[0].event_id == "4104"
    assert detection.findings[0].source_path == str(Path(artifact.dest_path).resolve())

    # Dosya basina TEK ozet kayit: bulgu sayisi + seviye dagilimi.
    assert len(detection.scanned) == 1
    scanned = detection.scanned[0]
    assert scanned["finding_count"] == 2
    assert scanned["level_counts"] == {"high": 1, "low": 1}
    assert Path(scanned["output_csv_path"]).is_file()
    assert Path(scanned["stdout_log_path"]).read_text(encoding="utf-8") == "tarama bitti\n"

    # argv sablonu dogru dolduruldu mu?
    argv = mock_run.call_args.args[0]
    assert argv[0] == config.detection.hayabusa_path
    assert argv[argv.index("-f") + 1] == str(Path(artifact.dest_path).resolve())
    assert argv[argv.index("-r") + 1] == config.detection.rules_dir
    assert mock_run.call_args.kwargs["timeout"] == 600
    _assert_never_uses_shell(mock_run)

    # Custody: bulgu basina degil, dosya basina tek olay.
    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == [
        "detection_started", "detection_completed_for_artifact", "detection_completed",
    ]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_mitre_attack_tags_are_surfaced_when_hayabusa_provides_them(tmp_path):
    """MitreTactics sutunu Hayabusa ciktisinda VARSA Finding.mitre_tags'e
    yansimali; bu yeni bir veri kaynagi degil, Sigma kuralinin kendi
    metadatasi -- sutun yoksa (FAKE_CSV'deki gibi) bos kalir, bu test o
    bos-kalma davranisini da dogas geregi kapsiyor (bkz. yukaridaki test)."""
    csv_with_mitre = (
        "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details,MitreTactics\n"
        "2026-01-02 03:04:05.678 +03:00,Suspicious PowerShell,high,WS-01,Security,"
        '4104,Encoded komut,"attack.t1059.001,attack.execution"\n'
    )
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv(csv_with_mitre)
        detection = run_detection(config, _make_manifest([artifact]), ledger)

    assert detection.findings[0].mitre_tags == "attack.t1059.001,attack.execution"


def test_mitre_attack_tags_are_empty_when_hayabusa_omits_them(tmp_path):
    """MitreTactics sutunu YOKSA (FAKE_CSV) alan bos kalmali, uydurulmamali."""
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _make_manifest([artifact]), ledger)

    assert detection.findings[0].mitre_tags == ""


def test_detection_manifest_is_written_and_its_hash_recorded(tmp_path):
    """Kapanis olayi, diske yazilan manifestin sha256'sini tasimali."""
    import hashlib

    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    manifest_path = Path(config.collection.output_dir) / CASE_ID / "detection_manifest.json"
    assert manifest_path.is_file()

    closing = [e for e in read_events(ledger.log_path) if e.event_type == "detection_completed"][0]
    expected = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert closing.payload["detection_manifest_sha256"] == expected
    assert closing.payload["finding_count"] == 2

    # Manifest diskten geri okunabilmeli.
    reloaded = DetectionManifest.from_json_file(manifest_path)
    assert reloaded.run_id == detection.run_id
    assert len(reloaded.findings) == 2
    assert reloaded.ended_at_utc is not None


def test_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _configured(tmp_path)
    failing = _make_artifact(config, filename="Bad.evtx")
    ok = _make_artifact(config, filename="Good.evtx")
    ledger = _ledger(tmp_path)

    def side_effect(argv, **kwargs):
        if "Bad.evtx" in argv[argv.index("-f") + 1]:
            return _completed(argv, returncode=3, stderr=b"kural yuklenemedi")
        return _writes_csv()(argv, **kwargs)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        # Hicbir istisna yukari sizmamali.
        detection = run_detection(config, _make_manifest([failing, ok]), ledger)

    assert len(detection.errors) == 1
    assert detection.errors[0]["exit_code"] == 3
    assert detection.errors[0]["stderr_excerpt"] == "kural yuklenemedi"
    # Kosu bir sonraki dosyayla devam etmis olmali.
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    assert mock_run.call_count == 2
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_error") == 1
    assert event_types.count("detection_completed_for_artifact") == 1


def test_timeout_is_a_non_fatal_error(tmp_path):
    config = _configured(tmp_path, timeout_seconds=5)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["hayabusa.exe"], timeout=5)
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    assert detection.scanned == [] and detection.findings == []
    assert len(detection.errors) == 1
    assert "5 saniyede bitmedi" in detection.errors[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_error") == 1
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_tool_not_configured_is_skipped(tmp_path):
    # detection bolumu hic yazilmamis: hayabusa_path da rules_dir de None.
    config = _make_config(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert detection.findings == [] and detection.errors == []
    assert len(detection.skipped) == 1
    assert "konfigure edilmemis" in detection.skipped[0]["message"]
    assert detection.skipped[0]["artifact_count"] == 1

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_skipped") == 1


def test_rules_dir_not_configured_is_skipped(tmp_path):
    # Arac var ama kural klasoru bildirilmemis: kuralsiz tarama anlamsiz.
    config = _make_config(tmp_path, hayabusa_path=_fake_tool(tmp_path))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert len(detection.skipped) == 1
    assert "kural klasoru konfigure edilmemis" in detection.skipped[0]["message"]


def test_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    # Yol mutlak (sema gecer) ama diskte boyle bir dosya yok.
    missing_exe = str(tmp_path / "olmayan" / "hayabusa.exe")
    config = _make_config(tmp_path, hayabusa_path=missing_exe, rules_dir=_fake_rules(tmp_path))
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    message = detection.skipped[0]["message"]
    # Iki durum birbirinden ayirt edilebilir olmali.
    assert "yolu bulunamadi" in message and missing_exe in message
    assert "konfigure edilmemis" not in message


def test_missing_rules_dir_on_disk_is_skipped(tmp_path):
    missing_rules = str(tmp_path / "olmayan" / "rules")
    config = _make_config(
        tmp_path, hayabusa_path=_fake_tool(tmp_path), rules_dir=missing_rules
    )
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    mock_run.assert_not_called()
    assert "kural klasoru bulunamadi" in detection.skipped[0]["message"]


def test_only_event_log_artifacts_are_scanned(tmp_path):
    """Hayabusa bir .evtx tarayicisidir: prefetch/registry ona verilmez."""
    config = _configured(tmp_path)
    evtx = _make_artifact(config)
    prefetch = _make_artifact(config, artifact_type_id="prefetch", filename="APP.pf")
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _make_manifest([prefetch, evtx, hive]), ledger)

    assert mock_run.call_count == 1
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Security.evtx"]
    # Taranmayan tipler "atlandi" olarak da kaydedilmez: bunlar zaten bu
    # katmanin isi degil, gurultu olurdu.
    assert detection.skipped == []

    started = [e for e in read_events(ledger.log_path) if e.event_type == "detection_started"][0]
    assert started.payload["artifact_count"] == 1


def test_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    """Guvenlik kurali #3: agac disindaki girdi icin hicbir sey CALISTIRILMAZ.

    Elle duzenlenmis / bozulmus bir manifest.json'i taklit eder.
    """
    config = _configured(tmp_path)
    # Vakanin artifacts kokunun kardesi: yol var ama agacin disinda.
    outside = tmp_path / "disarida" / "evil.evtx"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"kotu")
    tampered = _make_artifact(config, filename="evil.evtx", dest_path=str(outside))
    # '..' ile agactan cikmaya calisan ikinci bir kalip.
    traversal = _make_artifact(
        config,
        filename="traversal.evtx",
        dest_path=str(_artifacts_root(config) / "event_logs" / ".." / ".." / ".." / "escape.evtx"),
    )
    legit = _make_artifact(config, filename="Good.evtx")
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        detection = run_detection(config, _make_manifest([tampered, traversal, legit]), ledger)

    # Iki bozuk girdi de hata olarak kaydedilmis olmali.
    rejected = {e["source_path"] for e in detection.errors}
    assert rejected == {tampered.dest_path, traversal.dest_path}
    for entry in detection.errors:
        assert "cikti agaci disinda" in entry["message"]

    # ...ve bu girdiler icin subprocess HIC cagrilmamis olmali.
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[argv.index("-f") + 1] == str(Path(legit.dest_path).resolve())
    assert str(outside) not in argv
    assert "escape.evtx" not in " ".join(argv)
    assert [Path(s["source_path"]).name for s in detection.scanned] == ["Good.evtx"]
    _assert_never_uses_shell(mock_run)


def test_unparsable_output_is_not_fatal(tmp_path):
    """Ayristirma basarisiz olursa kosu devam eder: 0 bulgu + uyari kaydi."""
    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        # Arac 0 ile donuyor ama CSV yerine taninmayan bir sey yaziyor.
        mock_run.side_effect = _writes_csv("bu bir CSV degil\n")
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    assert detection.findings == []
    assert detection.errors == []
    scanned = detection.scanned[0]
    assert scanned["finding_count"] == 0
    assert "taninmadi" in scanned["parse_warning"]
    # Ham cikti diskte durmali: veri kaybolmuyor, sadece ayristirilamiyor.
    assert Path(scanned["output_csv_path"]).is_file()


def test_missing_output_file_is_not_fatal(tmp_path):
    """Arac 0 ile donup hic dosya yazmazsa da kosu devam eder."""
    config = _configured(tmp_path)
    ledger = _ledger(tmp_path)

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        detection = run_detection(config, _make_manifest([_make_artifact(config)]), ledger)

    assert detection.findings == []
    assert "olusmadi" in detection.scanned[0]["parse_warning"]


def test_output_dir_creation_failure_is_fatal_detection_error(tmp_path):
    """Cikti dizini olusturulamazsa (yolun bir parcasi aslinda bir dosya) bu
    olumcul sayilir ve tipli DetectionError olarak yukselir; ham OSError
    kullaniciya sizmaz."""
    config = _configured(tmp_path)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    # "detections" adinda bir DOSYA onceden var: alti icin dizin acilamaz.
    detections_as_file = Path(config.collection.output_dir) / CASE_ID / "detections"
    detections_as_file.parent.mkdir(parents=True, exist_ok=True)
    detections_as_file.write_text("bu bir dizin degil", encoding="utf-8")

    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        with pytest.raises(DetectionError):
            run_detection(config, _make_manifest([artifact]), ledger)
        mock_run.assert_not_called()


def test_relative_tool_and_rules_paths_are_rejected_at_config_time():
    """Guvenlik kurali #2: goreli arac/kural yolu semada reddedilir."""
    for detection in ({"hayabusa_path": "hayabusa.exe"}, {"rules_dir": "rules"}):
        with pytest.raises(ValueError) as exc_info:
            TriageChainConfig(
                case={"case_id": CASE_ID, "operator": "test.operator"},
                collection={"targets": ["event_logs"], "output_dir": "."},
                detection=detection,
            )
        assert "mutlak yol" in str(exc_info.value)


def test_absolute_paths_do_not_need_to_exist_at_config_time(tmp_path):
    # Kullanici Hayabusa'yi kurmadan once konfigurasyonu yazmis olabilir.
    config = _make_config(
        tmp_path,
        hayabusa_path=str(tmp_path / "henuz" / "yok.exe"),
        rules_dir=str(tmp_path / "henuz" / "rules"),
    )

    assert config.detection.timeout_seconds == 600


def _started_payload(ledger):
    """Defterdeki detection_started olayinin yukunu dondurur."""
    events = [e for e in read_events(ledger.log_path) if e.event_type == "detection_started"]
    assert len(events) == 1
    return events[0].payload


def _run_and_get_started_payload(tmp_path, config, ledger):
    artifact = _make_artifact(config)
    with patch("triagechain.detection.runner.subprocess.run") as mock_run:
        mock_run.side_effect = _writes_csv()
        run_detection(config, _make_manifest([artifact]), ledger)
    return _started_payload(ledger)


def test_detection_started_records_the_rule_set_fingerprint(tmp_path):
    """Metodoloji izlenebilirligi: "hangi kural seti bu bulgulari uretti"
    sorusu defterden cevaplanabilmeli."""
    config = _configured(tmp_path)
    payload = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path))

    assert payload["rules_dir"] == config.detection.rules_dir
    assert payload["rules_file_count"] == 1  # _fake_rules tek bir .yml yaziyor
    assert len(payload["rules_fingerprint_sha256"]) == 64
    # Mevcut alanlar (geriye donuk uyumluluk) korunmus olmali.
    assert {"run_id", "collection_run_id", "artifact_count", "output_dir"} <= set(payload)


def test_rule_set_fingerprint_is_stable_for_an_unchanged_directory(tmp_path):
    config = _configured(tmp_path)
    first = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path / "a"))
    second = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path / "b"))

    assert first["rules_fingerprint_sha256"] == second["rules_fingerprint_sha256"]


def test_rule_set_fingerprint_changes_when_a_rule_file_is_added_or_removed(tmp_path):
    """Parmak izi YAPISALDIR: dosya eklenmesi/cikarilmasi yakalanir (icerigi
    ayni boyutta degistirmek YAKALANMAZ - bilincli sinirlama, bkz.
    docs/chain_of_custody.md)."""
    config = _configured(tmp_path)
    rules = Path(config.detection.rules_dir)
    before = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path / "a"))

    yeni_kural = rules / "yeni_kural.yml"
    yeni_kural.write_text("title: yeni kural", encoding="utf-8")
    after_add = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path / "b"))

    assert after_add["rules_file_count"] == before["rules_file_count"] + 1
    assert after_add["rules_fingerprint_sha256"] != before["rules_fingerprint_sha256"]

    yeni_kural.unlink()
    after_remove = _run_and_get_started_payload(tmp_path, config, _ledger(tmp_path / "c"))

    # Dosya geri cikarilinca parmak izi ilk haline donmeli.
    assert after_remove["rules_fingerprint_sha256"] == before["rules_fingerprint_sha256"]


def test_fingerprint_fields_are_absent_when_the_rules_directory_is_missing(tmp_path):
    """Kural klasoru yoksa uydurma bir deger yazmaktansa alan HIC yazilmaz;
    kosunun neden atlandigi zaten detection_skipped olayinda duruyor."""
    config = _make_config(tmp_path, hayabusa_path=_fake_tool(tmp_path),
                          rules_dir=str(tmp_path / "olmayan" / "rules"))
    ledger = _ledger(tmp_path)
    payload = _run_and_get_started_payload(tmp_path, config, ledger)

    assert "rules_fingerprint_sha256" not in payload
    assert "rules_file_count" not in payload
    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("detection_skipped") == 1
