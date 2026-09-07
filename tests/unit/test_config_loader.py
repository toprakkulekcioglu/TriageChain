"""Konfigurasyon yukleyicisi: gecerli dosya, bilinmeyen hedef, kotu vaka kimligi."""

from pathlib import Path

import pytest
import yaml

from triagechain.config.loader import load_config, resolve_custody_log_path
from triagechain.core.errors import ConfigError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _write_config(tmp_path, **overrides):
    """Ornek konfigurasyonu gecici dizine, istenen degisikliklerle yazar."""
    data = yaml.safe_load((FIXTURES / "sample_config.yaml").read_text(encoding="utf-8"))
    data["collection"]["output_dir"] = str(tmp_path / "output")
    for section, values in overrides.items():
        data[section].update(values)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return config_path


def test_valid_config_parses(tmp_path):
    config = load_config(_write_config(tmp_path))

    assert config.case.case_id == "CASE-TEST-001"
    assert config.case.operator == "test.operator"
    assert config.collection.targets == ["event_logs", "prefetch"]
    assert config.collection.hash_algorithm == "sha256"
    assert config.logging.level == "INFO"
    # Cikti dizini yoksa yukleyici tarafindan olusturulur.
    assert Path(config.collection.output_dir).is_dir()


def test_custody_log_path_is_derived_when_null(tmp_path):
    config = load_config(_write_config(tmp_path))
    expected = Path(config.collection.output_dir) / "CASE-TEST-001" / "custody.jsonl"

    assert resolve_custody_log_path(config) == expected


def test_unknown_target_id_raises_config_error(tmp_path):
    config_path = _write_config(tmp_path, collection={"targets": ["event_logs", "hayali_hedef"]})

    with pytest.raises(ConfigError) as exc_info:
        load_config(config_path)
    assert "hayali_hedef" in str(exc_info.value)


def test_unsafe_case_id_raises_config_error(tmp_path):
    config_path = _write_config(tmp_path, case={"case_id": "../kacis"})

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_missing_output_dir_parent_raises_config_error(tmp_path):
    config_path = _write_config(
        tmp_path, collection={"output_dir": str(tmp_path / "olmayan" / "output")}
    )

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "yok.yaml")
