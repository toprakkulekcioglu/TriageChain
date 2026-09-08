"""Hedef cozumleyici: glob acilimi, duz yol, bos eslesme ve bilinmeyen kimlik."""

import os
from pathlib import Path

import pytest
import yaml

from triagechain.collection.selector import expand_pattern, resolve_targets
from triagechain.core.errors import ConfigError

FAKE_ARTIFACTS = Path(__file__).resolve().parents[1] / "fixtures" / "fake_artifacts"


@pytest.fixture
def test_catalog(tmp_path):
    """Gercek Windows dosyalarina ihtiyac duymayan, teste ozel katalog."""
    catalog = {
        "targets": [
            {
                "id": "fake_logs",
                "category": "test",
                "requires_vss": False,
                "paths": [str(FAKE_ARTIFACTS / "*.log")],
                "description": "Sahte log dosyalari (glob)",
            },
            {
                "id": "fake_notes",
                "category": "test",
                "requires_vss": False,
                "paths": [str(FAKE_ARTIFACTS / "notes.txt")],
                "description": "Tek dosya, glob yok",
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
    return path


def test_glob_expands_to_matching_files(test_catalog):
    (target,) = resolve_targets(["fake_logs"], test_catalog)

    assert [p.name for p in target.paths] == ["alpha.log", "beta.log"]
    assert target.requires_vss is False
    assert target.category == "test"


def test_plain_path_is_returned_as_is(test_catalog):
    (target,) = resolve_targets(["fake_notes"], test_catalog)

    assert len(target.paths) == 1
    assert target.paths[0].name == "notes.txt"


def test_glob_with_no_match_is_not_an_error(test_catalog):
    (target,) = resolve_targets(["fake_missing"], test_catalog)

    assert target.paths == []


def test_unknown_target_id_raises_config_error(test_catalog):
    with pytest.raises(ConfigError) as exc_info:
        resolve_targets(["fake_logs", "hayali"], test_catalog)
    assert "hayali" in str(exc_info.value)


def test_multiple_targets_keep_requested_order(test_catalog):
    resolved = resolve_targets(["fake_notes", "fake_logs"], test_catalog)

    assert [t.target_id for t in resolved] == ["fake_notes", "fake_logs"]


def test_env_variable_expansion(monkeypatch):
    monkeypatch.setenv("WinDir", r"C:\Windows")
    assert expand_pattern(r"%WinDir%\Prefetch\readpf.txt") == [
        Path(r"C:\Windows\Prefetch\readpf.txt")
    ]


def test_env_variable_fallback_when_not_set(monkeypatch):
    # Windows disinda bu degisken tanimli olmayabilir; yedek deger devreye girmeli.
    monkeypatch.delenv("SystemDrive", raising=False)
    assert str(expand_pattern("%SystemDrive%/x")[0]).startswith("C:")
    assert "SystemDrive" not in os.environ


def test_source_root_rebases_env_variable_pattern(monkeypatch, tmp_path):
    # Ice aktarma modu: %WinDir% gibi bir degisken de, hardcoded 'C:' gibi,
    # AYNI surucu-kok mantigiyla source_root altina yeniden koklendirilmeli
    # (bkz. collection/selector.py -> expand_pattern dokstring'i).
    monkeypatch.setenv("WinDir", r"C:\Windows")
    result = expand_pattern(r"%WinDir%\System32\config\SYSTEM", source_root=tmp_path)
    assert result == [tmp_path / "Windows" / "System32" / "config" / "SYSTEM"]


def test_source_root_rebases_hardcoded_drive_letter_pattern(tmp_path):
    # registry_ntuser/registry_usrclass gibi hedefler %SystemDrive% DEGIL,
    # sabit 'C:\Users\*\...' kullaniyor -- source_root ikisini de AYNI
    # sekilde ele almali (drive-split + yeniden koklendirme).
    (tmp_path / "Users" / "kaan").mkdir(parents=True)
    (tmp_path / "Users" / "kaan" / "NTUSER.DAT").write_bytes(b"x")
    result = expand_pattern(r"C:\Users\*\NTUSER.DAT", source_root=tmp_path)
    assert result == [tmp_path / "Users" / "kaan" / "NTUSER.DAT"]


def test_resolve_targets_passes_source_root_through(test_catalog, tmp_path):
    # 'fake_notes' hedefi mutlak, sabit bir yola (FAKE_ARTIFACTS/notes.txt)
    # isaret ediyor -- asil kontrol, resolve_targets'in source_root
    # parametresini GERCEKTEN expand_pattern'a ilettigi (drive-split sonrasi
    # kok source_root'a tasindigi icin path artik FAKE_ARTIFACTS altinda
    # DEGIL, tmp_path altinda olmali). Var-olmayan bir dosyaya isaret etmesi
    # sorun degil: duz (glob'suz) bir yol icin varlik kontrolu yapilmiyor.
    (target,) = resolve_targets(["fake_notes"], test_catalog, source_root=tmp_path)
    assert target.paths[0] != FAKE_ARTIFACTS / "notes.txt"
    assert str(target.paths[0]).startswith(str(tmp_path))
