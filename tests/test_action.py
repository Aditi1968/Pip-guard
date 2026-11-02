"""The composite action maps every exit code explicitly and cannot be quietly defanged (FR-6.6)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ACTION_DIR = Path(__file__).resolve().parent.parent / "action"
BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize(
    ("code", "status", "text"),
    [
        ("0", 0, "pip guard: pass"),
        ("1", 1, "::error title=pip guard::warn with fail-on-warn"),
        ("2", 2, "::error title=pip guard::blocked"),
        ("3", 3, "::error title=pip guard::error/incomplete: failing closed"),
        ("4", 3, "::error title=pip guard::unexpected exit code '4', failing closed"),
        ("127", 3, "::error title=pip guard::unexpected exit code '127', failing closed"),
        ("", 3, "::error title=pip guard::unexpected exit code '', failing closed"),
        ("abc", 3, "::error title=pip guard::unexpected exit code 'abc', failing closed"),
        ("0 ", 3, "unexpected exit code (unprintable), failing closed"),
        ("1::warning::y", 3, "unexpected exit code (unprintable), failing closed"),
    ],
)
def test_map_exit(code: str, status: int, text: str) -> None:
    assert BASH is not None
    script = (ACTION_DIR / "map_exit.sh").as_posix()
    proc = subprocess.run([BASH, script, code], capture_output=True, text=True, check=False)
    assert proc.returncode == status
    assert text in proc.stdout
    assert "::warning::y" not in proc.stdout


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_map_exit_no_argument_fails_closed() -> None:
    assert BASH is not None
    script = (ACTION_DIR / "map_exit.sh").as_posix()
    proc = subprocess.run([BASH, script], capture_output=True, text=True, check=False)
    assert proc.returncode == 3


@pytest.fixture(scope="module")
def action() -> dict[str, Any]:
    return yaml.safe_load((ACTION_DIR / "action.yml").read_text(encoding="utf-8"))


def _step(action: dict[str, Any], name: str) -> dict[str, Any]:
    return next(s for s in action["runs"]["steps"] if s.get("name") == name)


def test_no_continue_on_error_or_pull_request_target(action: dict[str, Any]) -> None:
    raw = (ACTION_DIR / "action.yml").read_text(encoding="utf-8")
    # Comments may *mention* the words; no YAML key or expression may use them.
    code_only = "\n".join(line.split("#", 1)[0] for line in raw.splitlines())
    assert "continue-on-error" not in code_only
    assert "pull_request_target" not in code_only
    assert all("continue-on-error" not in s for s in action["runs"]["steps"])


def test_every_uses_is_pinned_to_sha(action: dict[str, Any]) -> None:
    uses = [s["uses"] for s in action["runs"]["steps"] if "uses" in s]
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u), u


def test_upload_and_map_always_run(action: dict[str, Any]) -> None:
    assert _step(action, "Upload report")["if"] == "always()"
    mapper = _step(action, "Map exit code")
    assert mapper["if"] == "always()"
    assert "map_exit.sh" in mapper["run"]
    assert action["runs"]["steps"][-1] is mapper  # last word on the outcome


def test_scan_step_records_and_propagates_code(action: dict[str, Any]) -> None:
    run = _step(action, "Scan dependencies")["run"]
    assert "|| code=$?" in run and 'exit "$code"' in run
    assert "${{" not in run  # inputs only through env


def test_cache_save_and_comment_skip_forks(action: dict[str, Any]) -> None:
    assert "fork == 'false'" in _step(action, "Save verdict cache")["if"]
    comment_if = _step(action, "Post or update PR comment")["if"]
    assert "head.repo.full_name == github.repository" in comment_if
    assert "<!-- pipguard-report -->" in _step(action, "Post or update PR comment")["run"]


def test_action_runs_locked_source_and_only_edits_own_comment(action: dict[str, Any]) -> None:
    runs = "\n".join(s.get("run", "") for s in action["runs"]["steps"])
    assert "uv sync --locked" in runs and "uv tool install" not in runs
    assert "github-actions[bot]" in _step(action, "Post or update PR comment")["run"]
    assert "--local-index" in _step(action, "Scan dependencies")["run"]
