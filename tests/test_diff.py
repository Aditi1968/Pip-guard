from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pipguard.diff import (
    diff_dependencies,
    parse_pyproject,
    parse_requirement,
    parse_requirements,
    read_files_at,
)
from pipguard.errors import PipGuardError
from pipguard.models import ChangeKind


def test_exact_pin() -> None:
    r = parse_requirement("Foo_Bar == 1.2.3")
    assert r.name == "foo-bar"
    assert r.spec is not None and r.spec.version == "1.2.3"
    assert r.unsupported_reason is None


@pytest.mark.parametrize(
    ("line", "reason_part", "has_name"),
    [
        ("foo>=1.0", ">=", True),
        ("foo~=1.0", "~=", True),
        ("foo!=1.0", "!=", True),
        ("foo<2", "<", True),
        ("foo===1.0", "===", True),
        ("foo", "unpinned", True),
        ("foo==1.*", "wildcard", True),
        ("foo==1.0,<2", "multiple", True),
        ("foo[bar]==1.0", "extras", True),
        ('foo==1.0; python_version < "3.13"', "markers", True),
        ("foo @ https://example.com/foo.whl", "direct URL", True),
        ("https://example.com/foo-1.0.whl", "URL or local path", False),
        ("./local/pkg", "URL or local path", False),
        ("/abs/pkg", "URL or local path", False),
        ("C:\\pkgs\\foo.whl", "URL or local path", False),
        ("foo==not a version", "invalid version", True),
        ("foo ?? 1", "unparseable", True),
        ("!!!", "unparseable", False),
    ],
)
def test_unsupported(line: str, reason_part: str, has_name: bool) -> None:
    r = parse_requirement(line)
    assert r.spec is None
    assert r.unsupported_reason is not None and reason_part in r.unsupported_reason
    assert (r.name is not None) == has_name


def test_requirements_file_handling() -> None:
    text = """
# a comment
--index-url https://example.com/simple
-i https://example.com/simple
--extra-index-url=https://x

requests==2.32.3  # trailing comment
numpy==2.1.0 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
-r other.txt
--requirement=more.txt
-c constraints.txt
-e ./src
git+https://example.com/repo#egg=foo
"""
    reqs = parse_requirements(text)
    pins = [str(r.spec) for r in reqs if r.spec]
    assert pins == ["requests==2.32.3", "numpy==2.1.0"]
    reasons = [r.unsupported_reason for r in reqs if r.spec is None]
    assert reasons == [
        "included file not followed",
        "included file not followed",
        "included file not followed",
        "editable requirement",
        "URL or local path requirement",
    ]


def test_trailing_continuation_without_next_line() -> None:
    assert [str(r.spec) for r in parse_requirements("foo==1 \\")] == ["foo==1"]


def test_pyproject_pep621_only() -> None:
    text = """
[project]
name = "x"
dependencies = ["a==1.0", "b>=2"]

[tool.poetry.dependencies]
c = "3.0"
"""
    reqs = parse_pyproject(text)
    assert [r.name for r in reqs] == ["a", "b"]
    assert reqs[0].spec is not None and reqs[1].spec is None


def test_pyproject_without_project_table() -> None:
    assert parse_pyproject("[tool.x]\ny = 1\n") == []


@pytest.mark.parametrize("text", ["not toml [[[", "[project]\ndependencies = 'a==1'\n"])
def test_pyproject_malformed_raises(text: str) -> None:
    with pytest.raises(PipGuardError):
        parse_pyproject(text)


def test_diff_added_changed_removed_unchanged() -> None:
    base = {"requirements.txt": "keep==1.0\nbump==1.0\nremoved==1.0\nloose>=1\nPin-Me>=1\n"}
    head = {"requirements.txt": "keep==1.0\nbump==1.1\nnew==0.1\nloose>=1\npin_me==2.0\n"}
    changes = {c.raw: c for c in diff_dependencies(base, head)}
    assert set(changes) == {"bump==1.1", "new==0.1", "pin_me==2.0"}
    assert changes["bump==1.1"].kind is ChangeKind.CHANGED
    assert changes["bump==1.1"].previous_version == "1.0"
    assert changes["new==0.1"].kind is ChangeKind.ADDED
    assert changes["pin_me==2.0"].kind is ChangeKind.CHANGED  # pin-ness changed
    assert changes["pin_me==2.0"].previous_version is None


def test_diff_unsupported_only_when_added_or_changed() -> None:
    base = {"requirements.txt": "same>=1\nwas==1.0\n-r a.txt\n"}
    head = {"requirements.txt": "same>=1\nwas>=1.0\n-r a.txt\n-r b.txt\n"}
    changes = diff_dependencies(base, head)
    assert [(c.raw, c.kind, c.unsupported_reason is not None) for c in changes] == [
        ("was>=1.0", ChangeKind.CHANGED, True),
        ("-r b.txt", ChangeKind.ADDED, True),
    ]


def test_diff_new_file_and_pyproject() -> None:
    head = {
        "requirements.txt": "a==1\n",
        "pyproject.toml": '[project]\ndependencies = ["b==2"]\n',
    }
    changes = diff_dependencies({}, head)
    assert [(c.source_file, c.raw, c.kind) for c in changes] == [
        ("requirements.txt", "a==1", ChangeKind.ADDED),
        ("pyproject.toml", "b==2", ChangeKind.ADDED),
    ]


def test_diff_whitespace_only_change_is_unchanged() -> None:
    assert diff_dependencies({"r.txt": "a == 1\n"}, {"r.txt": "a==1\n"}) == []


@given(st.text(max_size=300))
def test_parse_requirements_never_crashes(text: str) -> None:
    for r in parse_requirements(text):
        assert (r.spec is None) != (r.unsupported_reason is None)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git not available")

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    (tmp_path / "requirements.txt").write_text("a==1\n")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    git("tag", "base")
    (tmp_path / "requirements.txt").write_text("a==2\n")
    git("commit", "-q", "-am", "head")
    return tmp_path


def test_read_files_at(git_repo: Path) -> None:
    files = read_files_at("base", ["requirements.txt", "pyproject.toml"], repo=git_repo)
    assert files == {"requirements.txt": "a==1\n", "pyproject.toml": ""}
    head = read_files_at("HEAD", ["requirements.txt"], repo=git_repo)
    assert [c.raw for c in diff_dependencies(files, head)] == ["a==2"]


@pytest.mark.parametrize("ref", ["nope", "", "--output=/tmp/x"])
def test_read_files_at_bad_ref_raises(git_repo: Path, ref: str) -> None:
    with pytest.raises(PipGuardError):
        read_files_at(ref, ["requirements.txt"], repo=git_repo)
