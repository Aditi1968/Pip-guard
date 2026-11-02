"""Load ``pipguard.toml`` (FR-7.2) and hash it for the cache key (FR-1.3)."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

from pipguard.errors import PipGuardError
from pipguard.models import Config


def load_config(path: Path | None) -> Config:
    """Read ``path`` if given and present; otherwise defaults. Malformed config is an error."""
    if path is None or not path.exists():
        return Config()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return Config.model_validate(data.get("pipguard", data))
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise PipGuardError(f"invalid config {path}: {exc}") from exc


def config_hash(config: Config) -> str:
    """Stable hash of the effective config, so a config change invalidates the cache."""
    return hashlib.sha256(config.model_dump_json().encode()).hexdigest()[:16]
