from pathlib import Path

import pytest

from pipguard.config import config_hash, load_config
from pipguard.errors import PipGuardError
from pipguard.models import Config


def test_defaults_when_missing(tmp_path: Path) -> None:
    assert load_config(None) == Config()
    assert load_config(tmp_path / "nope.toml") == Config()


def test_loads_values(tmp_path: Path) -> None:
    p = tmp_path / "pipguard.toml"
    p.write_text('allowlist = ["Foo"]\n[timeouts]\ninstall_s = 30\n')
    cfg = load_config(p)
    assert cfg.allowlist == ["foo"] and cfg.timeouts.install_s == 30


def test_malformed_is_error(tmp_path: Path) -> None:
    p = tmp_path / "pipguard.toml"
    p.write_text("allowlist = [")
    with pytest.raises(PipGuardError):
        load_config(p)
    p.write_text("unknown_key = 1")
    with pytest.raises(PipGuardError):
        load_config(p)


def test_hash_changes_with_config() -> None:
    assert config_hash(Config()) == config_hash(Config())
    assert config_hash(Config()) != config_hash(Config(allowlist=["x"]))


def test_parse_config_text() -> None:
    from pipguard.config import parse_config

    assert parse_config("") == Config()
    assert parse_config('allowlist = ["A"]').allowlist == ["a"]
    with pytest.raises(PipGuardError):
        parse_config("x = [")
