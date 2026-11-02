"""Shared test setup. Unit tests must never touch the network (CLAUDE.md, PRD reproducibility)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any inet connection attempt. Docker-marked tests talk to the daemon, so skip them."""
    if request.node.get_closest_marker("docker"):
        return
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: object) -> None:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            raise RuntimeError(f"network access in a unit test: {address!r}")
        real_connect(self, address)  # type: ignore[arg-type]

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
