import gzip
import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pipguard import SCANNER_VERSION
from pipguard.cli import app, main
from scripts.make_wheel import build_wheel

runner = CliRunner()


def test_help() -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0


def test_non_pin_exits_3() -> None:
    assert runner.invoke(app, ["scan", "requests>=2"]).exit_code == 3


def test_spec_xor_artifact() -> None:
    assert runner.invoke(app, ["scan"]).exit_code == 3


def test_version() -> None:
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and SCANNER_VERSION in r.output


def test_scan_artifact_json_and_pretty(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path, "quietpkg", "1.0", {"quietpkg/__init__.py": "X = 1\n"})
    r = runner.invoke(app, ["scan", "--no-sandbox", "--artifact", str(wheel)])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["verdicts"][0]["level"] == "allow"
    r = runner.invoke(app, ["scan", "--no-sandbox", "--pretty", "--artifact", str(wheel)])
    assert "quietpkg==1.0" in r.output and "allow" in r.output


def test_bad_config_exits_3(tmp_path: Path) -> None:
    cfg = tmp_path / "pipguard.toml"
    cfg.write_text("nonsense = [")
    r = runner.invoke(app, ["scan", "--no-sandbox", "--config", str(cfg), "--artifact", "x.whl"])
    assert r.exit_code == 3


@pytest.mark.parametrize("argv", [["scan", "--bogus"], ["nope"]])
def test_main_maps_usage_errors_to_3(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # click's default for usage errors is 2, which would read as "block".
    monkeypatch.setattr("sys.argv", ["pipguard", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 3


def test_main_maps_crash_to_3(monkeypatch: pytest.MonkeyPatch) -> None:
    def crash(*a: object, **k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("pipguard.cli.app", crash)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 3


def test_main_success_exit_0(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["pipguard", "version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "requirements.txt").write_text("quietpkg==1.0\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    return repo


def test_ci_blocks_typosquat_and_writes_outputs(repo: Path, tmp_path: Path) -> None:
    index = tmp_path / "index"
    build_wheel(index, "quietpkg", "1.0", {"quietpkg/__init__.py": "X = 1\n"})
    build_wheel(index, "requets", "2.31.0", {"requets/__init__.py": "X = 1\n"})
    (repo / "requirements.txt").write_text("quietpkg==1.0\nrequets==2.31.0\nflask>=3\n")
    _git(repo, "commit", "-qam", "head")
    summary, report, comment = tmp_path / "s.md", tmp_path / "r.json.gz", tmp_path / "c.md"
    r = runner.invoke(
        app,
        [
            "ci",
            "--base",
            "HEAD~1",
            "--repo",
            str(repo),
            "--no-sandbox",
            "--local-index",
            str(index),
            "--summary",
            str(summary),
            "--report",
            str(report),
            "--comment-file",
            str(comment),
            "--cache",
            str(tmp_path / "c.sqlite"),
        ],
    )
    assert r.exit_code == 2, r.output
    md = summary.read_text(encoding="utf-8")
    assert "FAIL: blocked" in md and "requets" in md
    data = json.loads(gzip.decompress(report.read_bytes()))
    levels = {v["raw_spec"]: v["level"] for v in data["verdicts"]}
    assert levels == {"requets==2.31.0": "block", "flask>=3": "warn"}
    assert comment.read_text(encoding="utf-8").startswith("<!-- pipguard-report -->")


def test_ci_no_changes_passes(repo: Path) -> None:
    r = runner.invoke(app, ["ci", "--base", "HEAD", "--repo", str(repo), "--no-sandbox"])
    assert r.exit_code == 0 and "No added or changed" in r.output


def test_ci_bad_ref_fails_closed(repo: Path) -> None:
    r = runner.invoke(app, ["ci", "--base", "nosuchref", "--repo", str(repo), "--no-sandbox"])
    assert r.exit_code == 3


def test_ci_uses_base_config_not_the_prs(repo: Path, tmp_path: Path) -> None:
    index = tmp_path / "index"
    build_wheel(index, "requets", "2.31.0", {"requets/__init__.py": "X = 1\n"})
    # The PR tries to switch the gate off and allowlist its own package.
    (repo / "pipguard.toml").write_text('watched_files = []\nallowlist = ["requets"]\n')
    (repo / "requirements.txt").write_text("quietpkg==1.0\nrequets==2.31.0\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "head")
    r = runner.invoke(
        app,
        [
            "ci",
            "--base",
            "HEAD~1",
            "--repo",
            str(repo),
            "--no-sandbox",
            "--local-index",
            str(index),
        ],
    )
    assert r.exit_code == 2, r.output
    assert "base branch" in r.output
