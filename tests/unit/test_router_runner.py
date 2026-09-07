"""Yonlendirici: basarili kosu, hata kodu, zaman asimi, atlama ve yol kontrolu.

Hicbir test gercek bir EZ Tools ikilisi calistirmaz: subprocess.run her
testte unittest.mock ile yamalanir.
"""

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from triagechain.collection.hashing import hash_file
from triagechain.collection.models import CollectedArtifact, CollectionManifest
from triagechain.config.schema import TriageChainConfig
from triagechain.core.errors import RouterError
from triagechain.custody.ledger import CustodyLedger, read_events, verify_chain
from triagechain.router import catalog as router_catalog
from triagechain.router.runner import run_router

CASE_ID = "CASE-TEST-ROUTER"


def _make_config(tmp_path, tools=None, timeout_seconds=300, recmd_batch_file=None):
    """Yonlendirme icin en kucuk gecerli konfigurasyon."""
    return TriageChainConfig(
        case={"case_id": CASE_ID, "operator": "test.operator"},
        collection={
            "targets": ["prefetch"],
            "hash_algorithm": "sha256",
            "output_dir": str(tmp_path / "output"),
        },
        router={
            "tools": tools or {},
            "timeout_seconds": timeout_seconds,
            "recmd_batch_file": recmd_batch_file,
        },
    )


def _artifacts_root(config):
    return Path(config.collection.output_dir) / CASE_ID / "artifacts"


def _make_artifact(config, artifact_type_id="prefetch", filename="APP.pf", dest_path=None):
    """Cikti agacinda gercek bir dosya olusturur ve manifest kaydini dondurur.

    dest_path verilirse dosya olusturulmaz; bu, agac disi yol testinde
    kullaniliyor.
    """
    if dest_path is None:
        dest = _artifacts_root(config) / artifact_type_id / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"sahte artefakt")
        dest_path = str(dest)
    return CollectedArtifact(
        artifact_type_id=artifact_type_id,
        source_path=rf"C:\Windows\Prefetch\{filename}",
        dest_path=dest_path,
        hash_value="0" * 64,
        hash_algorithm="sha256",
        size_bytes=14,
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


def _fake_tool(tmp_path, name="PECmd.exe"):
    """Diskte gercekten var olan, mutlak yollu sahte bir arac dosyasi."""
    exe = tmp_path / "tools" / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("sahte arac", encoding="utf-8")
    return str(exe)


def _ledger(tmp_path):
    return CustodyLedger(tmp_path / "custody.jsonl", CASE_ID)


def _completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=argv, returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _assert_never_uses_shell(mock_run):
    """Guvenlik kurali #1: hicbir cagri shell=True ile yapilmamali."""
    for call in mock_run.call_args_list:
        assert call.kwargs.get("shell") is not True
        # Ilk konumsal arguman her zaman arguman LISTESI olmali, tek metin degil.
        assert isinstance(call.args[0], list)


def test_successful_run_is_recorded_as_processed(tmp_path):
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)})
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"], stdout=b"tamam", stderr=b"")
        routing = run_router(config, _make_manifest([artifact]), ledger)

    assert len(routing.processed) == 1
    assert routing.errors == []
    assert routing.skipped == []

    processed = routing.processed[0]
    assert processed.tool == "pecmd"
    assert processed.exit_code == 0
    # stdout/stderr denetim izi diske yazilmis olmali.
    assert Path(processed.stdout_log_path).read_text(encoding="utf-8") == "tamam"
    assert Path(processed.stderr_log_path).is_file()

    # argv sablonu dogru dolduruldu mu?
    argv = mock_run.call_args.args[0]
    assert argv[0] == config.router.tools["pecmd"]
    assert argv[1] == "-f" and argv[2] == str(Path(artifact.dest_path).resolve())
    assert argv[3] == "--csv" and argv[4] == processed.output_dir
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types == ["routing_started", "artifact_processed", "routing_completed"]
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_non_zero_exit_code_is_an_error_and_run_continues(tmp_path):
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)})
    failing = _make_artifact(config, filename="BAD.pf")
    ok = _make_artifact(config, filename="GOOD.pf")
    ledger = _ledger(tmp_path)

    def side_effect(argv, **kwargs):
        code = 1 if "BAD.pf" in argv[2] else 0
        return _completed(argv, returncode=code, stderr=b"ayristirma bozuldu")

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = side_effect
        # Hicbir istisna yukari sizmamali.
        routing = run_router(config, _make_manifest([failing, ok]), ledger)

    assert len(routing.errors) == 1
    assert routing.errors[0]["exit_code"] == 1
    assert routing.errors[0]["stderr_excerpt"] == "ayristirma bozuldu"
    # Kosu bir sonraki artefaktla devam etmis olmali.
    assert [p.source_path for p in routing.processed] == [str(Path(ok.dest_path).resolve())]
    assert mock_run.call_count == 2
    _assert_never_uses_shell(mock_run)

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_error") == 1
    assert event_types.count("artifact_processed") == 1


def test_timeout_is_a_non_fatal_error(tmp_path):
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)}, timeout_seconds=5)
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["PECmd.exe"], timeout=5)
        routing = run_router(config, _make_manifest([artifact]), ledger)

    assert routing.processed == []
    assert len(routing.errors) == 1
    assert "5 saniyede bitmedi" in routing.errors[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_error") == 1
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_tool_not_configured_is_skipped(tmp_path):
    # router.tools bos: 'pecmd' anahtari hic yok.
    config = _make_config(tmp_path, tools={})
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert routing.processed == []
    assert routing.errors == []
    assert len(routing.skipped) == 1
    assert "konfigure edilmemis" in routing.skipped[0]["message"]

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_skipped") == 1


def test_configured_tool_path_that_does_not_exist_is_skipped(tmp_path):
    # Yol mutlak (sema gecer) ama diskte boyle bir dosya yok.
    missing_exe = str(tmp_path / "olmayan" / "PECmd.exe")
    config = _make_config(tmp_path, tools={"pecmd": missing_exe})
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert len(routing.skipped) == 1
    message = routing.skipped[0]["message"]
    # Iki durum birbirinden ayirt edilebilir olmali.
    assert "yolu bulunamadi" in message and missing_exe in message
    assert "konfigure edilmemis" not in message


def test_artifact_type_without_a_route_is_skipped_but_visible(tmp_path):
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)})
    artifact = _make_artifact(config, artifact_type_id="fake_logs", filename="alpha.log")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _make_manifest([artifact]), ledger)

    mock_run.assert_not_called()
    assert len(routing.skipped) == 1
    assert "tanimli bir arac yok" in routing.skipped[0]["message"]


def test_hive_transaction_log_files_are_never_routed_on_their_own(tmp_path):
    """Gercek bir makinede kesfedildi: SYSTEM.LOG1/.LOG2 gibi islem log
    dosyalari ayni registry_* hedefiyle toplanir ama RECmd'e TEK BASINA asla
    verilmemeli - onlar ana kovanla ayni dizinde durup kendiliginden
    kullanilir (bkz. docs/hatalar_ve_sonuclar.md)."""
    config = _make_config(tmp_path, tools={"recmd": _fake_tool(tmp_path, name="RECmd.exe")})
    log1 = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM.LOG1")
    log2 = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM.LOG2")
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        routing = run_router(config, _make_manifest([log1, log2, hive]), ledger)

    assert len(routing.skipped) == 2
    assert all("islem log dosyasi" in s["message"] for s in routing.skipped)
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[argv.index("-f") + 1] == str(Path(hive.dest_path).resolve())


def _recmd_config(tmp_path, **kwargs):
    """RECmd rotasini calistirabilen konfigurasyon (kovan hedefleri bu araca gider)."""
    return _make_config(
        tmp_path, tools={"recmd": _fake_tool(tmp_path, name="RECmd.exe")}, **kwargs
    )


def test_recmd_argv_uses_the_embedded_batch_file_by_default(tmp_path):
    """config'de bir sey yazmayan kullanici da RECmd'i calistirabilmeli:
    --bn, pakete gomulu DFIRBatch.reb ile doldurulur."""
    config = _recmd_config(tmp_path)
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        routing = run_router(config, _make_manifest([hive]), ledger)

    assert len(routing.processed) == 1
    argv = mock_run.call_args.args[0]
    # Yol argv'de TEK bir eleman olarak durmali (bosluk iceren bir yolun
    # ikiye bolunmedigi de boylece dogrulanmis oluyor).
    assert argv[argv.index("--bn") + 1] == str(router_catalog.default_recmd_batch_path())
    assert argv[argv.index("-f") + 1] == str(Path(hive.dest_path).resolve())
    _assert_never_uses_shell(mock_run)


def test_configured_recmd_batch_file_overrides_the_embedded_default(tmp_path):
    custom = tmp_path / "kendi_toplu_dosyam.reb"
    custom.write_text("Description: kendi toplu dosyam", encoding="utf-8")
    config = _recmd_config(tmp_path, recmd_batch_file=str(custom))
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        run_router(config, _make_manifest([hive]), ledger)

    argv = mock_run.call_args.args[0]
    assert argv[argv.index("--bn") + 1] == str(custom)
    assert str(router_catalog.default_recmd_batch_path()) not in argv


def test_missing_batch_file_is_skipped_without_running_anything(tmp_path):
    """Toplu dosyanin varligi KOSU aninda kontrol edilir; yoksa bu olumcul
    degil, aracin kendisi bulunamadigindaki gibi bir 'atlandi' kaydidir."""
    missing = tmp_path / "olmayan" / "DFIRBatch.reb"
    config = _recmd_config(tmp_path, recmd_batch_file=str(missing))
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        routing = run_router(config, _make_manifest([hive]), ledger)

    mock_run.assert_not_called()
    assert routing.processed == [] and routing.errors == []
    assert len(routing.skipped) == 1
    message = routing.skipped[0]["message"]
    assert "toplu dosyasi bulunamadi" in message and str(missing) in message

    event_types = [e.event_type for e in read_events(ledger.log_path)]
    assert event_types.count("processing_skipped") == 1
    assert verify_chain(ledger.log_path, CASE_ID).is_valid


def test_processed_event_carries_the_real_hash_of_the_batch_file(tmp_path):
    """Metodoloji izlenebilirligi: deftere yazilan sha256, GERCEKTEN kullanilan
    toplu dosyanin hash'i olmali - baska bir dosyaninki ya da sabit bir deger degil."""
    custom = tmp_path / "kural_seti.reb"
    custom.write_text("Description: izlenebilirlik testi", encoding="utf-8")
    config = _recmd_config(tmp_path, recmd_batch_file=str(custom))
    hive = _make_artifact(config, artifact_type_id="registry_system", filename="SYSTEM")
    prefetch_tool = _fake_tool(tmp_path)
    config.router.tools["pecmd"] = prefetch_tool
    pf = _make_artifact(config, filename="APP.pf")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        run_router(config, _make_manifest([hive, pf]), ledger)

    processed = [e for e in read_events(ledger.log_path) if e.event_type == "artifact_processed"]
    by_tool = {e.payload["tool"]: e.payload for e in processed}

    assert by_tool["recmd"]["recmd_batch_path"] == str(custom)
    assert by_tool["recmd"]["recmd_batch_sha256"] == hash_file(custom)
    # Kural dosyasi kavrami olmayan araclarda bu alanlar HIC bulunmamali.
    assert "recmd_batch_sha256" not in by_tool["pecmd"]
    assert "recmd_batch_path" not in by_tool["pecmd"]
    # Mevcut alanlar (geriye donuk uyumluluk) korunmus olmali.
    for payload in by_tool.values():
        assert {"source_path", "output_dir", "exit_code", "duration_seconds"} <= set(payload)


def test_dest_path_outside_output_tree_is_rejected_without_running_anything(tmp_path):
    """Guvenlik kurali #3: agac disindaki girdi icin hicbir sey CALISTIRILMAZ.

    Elle duzenlenmis / bozulmus bir manifest.json'i taklit eder.
    """
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)})
    # Vakanin artifacts kokunun kardesi: yol var ama agacin disinda.
    outside = tmp_path / "disarida" / "evil.pf"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"kotu")
    tampered = _make_artifact(config, filename="evil.pf", dest_path=str(outside))
    # '..' ile agactan cikmaya calisan ikinci bir kalip.
    traversal = _make_artifact(
        config,
        filename="traversal.pf",
        dest_path=str(_artifacts_root(config) / "prefetch" / ".." / ".." / ".." / "escape.pf"),
    )
    legit = _make_artifact(config, filename="GOOD.pf")
    ledger = _ledger(tmp_path)

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["x"])
        routing = run_router(config, _make_manifest([tampered, traversal, legit]), ledger)

    # Iki bozuk girdi de hata olarak kaydedilmis olmali.
    rejected = {e["source_path"] for e in routing.errors}
    assert rejected == {tampered.dest_path, traversal.dest_path}
    for entry in routing.errors:
        assert "cikti agaci disinda" in entry["message"]

    # ...ve bu girdiler icin subprocess HIC cagrilmamis olmali.
    assert mock_run.call_count == 1
    argv = mock_run.call_args.args[0]
    assert argv[2] == str(Path(legit.dest_path).resolve())
    assert str(outside) not in argv
    assert "escape.pf" not in " ".join(argv)
    assert [p.source_path for p in routing.processed] == [str(Path(legit.dest_path).resolve())]
    _assert_never_uses_shell(mock_run)


def test_output_dir_creation_failure_is_fatal_router_error(tmp_path):
    """Cikti dizini olusturulamazsa (or. yolun bir parcasi aslinda bir dosya)
    bu olumcul sayilir ve tipli RouterError olarak yukselir; ham OSError
    kullaniciya sizmaz."""
    config = _make_config(tmp_path, tools={"pecmd": _fake_tool(tmp_path)})
    artifact = _make_artifact(config)
    ledger = _ledger(tmp_path)

    # "parsed" adinda bir DOSYA onceden var: alti icin dizin acilamaz.
    parsed_as_file = Path(config.collection.output_dir) / CASE_ID / "parsed"
    parsed_as_file.parent.mkdir(parents=True, exist_ok=True)
    parsed_as_file.write_text("bu bir dizin degil", encoding="utf-8")

    with patch("triagechain.router.runner.subprocess.run") as mock_run:
        with pytest.raises(RouterError):
            run_router(config, _make_manifest([artifact]), ledger)
        mock_run.assert_not_called()


def test_relative_tool_path_is_rejected_at_config_time():
    """Guvenlik kurali #2: goreli arac yolu semada reddedilir."""
    with pytest.raises(ValueError) as exc_info:
        TriageChainConfig(
            case={"case_id": CASE_ID, "operator": "test.operator"},
            collection={"targets": ["prefetch"], "output_dir": "."},
            router={"tools": {"pecmd": "PECmd.exe"}},
        )
    assert "pecmd" in str(exc_info.value)


def test_absolute_tool_path_does_not_need_to_exist_at_config_time(tmp_path):
    # Kullanici araclari kurmadan once konfigurasyonu yazmis olabilir.
    config = _make_config(tmp_path, tools={"pecmd": str(tmp_path / "henuz" / "yok.exe")})

    assert config.router.timeout_seconds == 300
