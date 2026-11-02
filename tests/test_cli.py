from typer.testing import CliRunner

from pipguard import SCANNER_VERSION
from pipguard.cli import app

runner = CliRunner()


def test_help() -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0


def test_non_pin_exits_3() -> None:
    assert runner.invoke(app, ["scan", "requests>=2"]).exit_code == 3


def test_version() -> None:
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and SCANNER_VERSION in r.output
