from __future__ import annotations

import gzip
import itertools
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pipguard.models import (
    ArtifactKind,
    ArtifactRef,
    BehaviorTrace,
    Completeness,
    ConnectAttempt,
    Coverage,
    Level,
    PackageSpec,
    ScanReport,
    StageStatus,
    SubprocessCall,
    Verdict,
)
from pipguard.report import (
    COMMENT_MARKER,
    MAX_CELL,
    _cell,
    cap_trace,
    exit_code,
    render_comment,
    render_summary,
    write_report_artifact,
)

# ------------------------------------------------------------------ exit codes (FR-7.4)


def _expected(levels: tuple[Level, ...], fail_on_warn: bool) -> int:
    if Level.ERROR in levels or Level.INCOMPLETE in levels:
        return 3
    if Level.BLOCK in levels:
        return 2
    return 1 if fail_on_warn and Level.WARN in levels else 0


@pytest.mark.parametrize("fail_on_warn", [False, True])
def test_exit_code_exhaustive(fail_on_warn: bool) -> None:
    # Every multiset of up to 3 levels, both flag values.
    for n in range(4):
        for combo in itertools.combinations_with_replacement(list(Level), n):
            got = exit_code(list(combo), fail_on_warn=fail_on_warn)
            assert got == _expected(combo, fail_on_warn), combo


@pytest.mark.parametrize(
    ("levels", "fow", "code"),
    [
        ([], False, 0),
        ([], True, 0),
        ([Level.ALLOW], True, 0),
        ([Level.WARN], False, 0),
        ([Level.WARN], True, 1),
        ([Level.BLOCK, Level.WARN], True, 2),
        ([Level.BLOCK, Level.ERROR], False, 3),
        ([Level.INCOMPLETE, Level.ALLOW], False, 3),
    ],
)
def test_exit_code_table(levels: list[Level], fow: bool, code: int) -> None:
    assert exit_code(levels, fail_on_warn=fow) == code


# ------------------------------------------------------------------ fixtures

SHA = "ab" * 32


def verdict(
    level: Level,
    name: str = "foo",
    *,
    reasons: list[str] | None = None,
    raw: str | None = None,
    filename: str = "foo-1.0-py3-none-any.whl",
    overrides: list[str] | None = None,
    unsupported: bool = False,
    **kw: object,
) -> Verdict:
    spec = None if unsupported else PackageSpec(name=name, version="1.0")
    return Verdict(
        spec=spec,
        raw_spec=raw or f"{name}==1.0",
        level=level,
        reasons=reasons if reasons is not None else ([] if level is Level.ALLOW else ["r1"]),
        coverage=Coverage(
            fetch=StageStatus.COMPLETED,
            static=StageStatus.COMPLETED,
            sandbox=StageStatus.COMPLETED,
            scoring=StageStatus.COMPLETED,
            sandbox_completeness=Completeness.COMPLETE,
            artifacts=[ArtifactRef(filename=filename, sha256=SHA, kind=ArtifactKind.WHEEL)],
            not_evaluated=["sdist build behaviour"],
        ),
        overrides=overrides or [],
        scanner_version="0.1",
        model_version="m1",
        **kw,  # type: ignore[arg-type]
    )


def report(verdicts: list[Verdict], **kw: object) -> ScanReport:
    return ScanReport(
        scanner_version="0.1",
        correlation_id="cid123",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        verdicts=verdicts,
        **kw,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------ summary (FR-6.1)


def test_summary_layout() -> None:
    r = report(
        [
            verdict(Level.BLOCK, "evil", reasons=["a", "b", "c", "d-hidden"], score=0.93),
            verdict(Level.ALLOW, "numpy", cache_hit=True),
            verdict(Level.WARN, "ok", overrides=["allowlisted: capped at warn"]),
        ],
        notes=["something worth knowing"],
    )
    md = render_summary(r)
    assert md.startswith("## pip guard: FAIL: blocked")
    assert "| package | artifact | verdict | coverage | top reasons |" in md
    block_row = next(line for line in md.splitlines() if line.startswith("| evil==1.0"))
    assert "**block** (score 0.93)" in block_row
    assert "foo-1.0-py3-none-any.whl (abababababab)" in block_row
    assert "d-hidden" not in md  # max 3 reasons
    # allow rows collapsed
    details = md[md.index("<details>") : md.index("</details>")]
    assert "numpy==1.0" in details and "(cached)" in details
    assert "evil==1.0" not in details
    assert "**Overrides applied:**" in md and "allowlisted" in md
    assert "something worth knowing" in md
    assert "environment-variable reads and DNS names" in md
    assert "Fork PR" not in md


@pytest.mark.parametrize(
    ("levels", "fow", "headline"),
    [
        ([], False, "PASS"),
        ([Level.ALLOW], False, "PASS"),
        ([Level.WARN], False, "PASS with warnings"),
        ([Level.WARN], True, "FAIL: warnings (fail-on-warn)"),
        ([Level.BLOCK], False, "FAIL: blocked"),
        ([Level.INCOMPLETE], False, "FAIL: error or incomplete scan (failing closed)"),
    ],
)
def test_summary_headline(levels: list[Level], fow: bool, headline: str) -> None:
    md = render_summary(report([verdict(lvl) for lvl in levels]), fail_on_warn=fow)
    assert md.splitlines()[0] == f"## pip guard: {headline}"


def test_summary_empty_and_fork() -> None:
    md = render_summary(report([]), fork_pr=True)
    assert "No added or changed pinned dependencies." in md
    assert "Fork PR" in md and "no PR comment" in md


def test_unsupported_row_uses_raw_spec() -> None:
    v = verdict(Level.WARN, unsupported=True, raw="foo>=1", reasons=["not an exact pin"])
    md = render_summary(report([v]))
    assert "| foo&#62;=1 |" in md


def test_cell_neutralises_markup() -> None:
    out = _cell("a|b\n| x | y |\r`code` <img src=x> [l](u) @admin https://e.com www.e.com")
    for bad in ("|", "\n", "\r", "`", "<", ">", "[", "]", "(", ")"):
        assert bad not in out
    assert "@admin" not in out and "https://" not in out and "www.e" not in out
    assert len(_cell("x" * 10_000)) <= MAX_CELL * 6


_ALLOWED_TAGS = re.compile(r"</?(br|details|summary|sub)>|<!-- pipguard-report -->")


def _shape(md: str) -> list[int]:
    return [line.count("|") for line in md.splitlines()]


hostile = st.text(
    alphabet=st.sampled_from([*"|\n\r`<>&[]()!#*_\\@:/w. -abc", "\u2028", "\x00"]),
    max_size=400,
)


@settings(max_examples=150, deadline=None)
@given(name=hostile, reason=hostile, filename=hostile, override=hostile, note=hostile)
def test_hostile_strings_cannot_change_table_shape(
    name: str, reason: str, filename: str, override: str, note: str
) -> None:
    def build(n: str, r: str, f: str, o: str, t: str) -> ScanReport:
        return report(
            [
                verdict(
                    Level.WARN,
                    unsupported=True,
                    raw=n or "x",
                    reasons=[r or "x"],
                    filename=f,
                    overrides=[o or "x"],
                ),
                verdict(Level.ALLOW, filename=f),
            ],
            notes=[t or "x"],
        )

    baseline = render_comment(build("x", "x", "x", "x", "x"))
    md = render_comment(build(name, reason, filename, override, note))
    assert _shape(md) == _shape(baseline)
    assert "<" not in _ALLOWED_TAGS.sub("", md)
    assert ">" not in _ALLOWED_TAGS.sub("", md).replace("\n> ", "\n")
    assert "`" not in md


# ------------------------------------------------------------------ comment (FR-6.4)


def test_comment_has_marker_and_is_capped() -> None:
    c = render_comment(report([verdict(Level.ALLOW)]))
    assert c.startswith(COMMENT_MARKER + "\n")
    many = report([verdict(Level.WARN, f"p{i}", reasons=["r" * 300] * 3) for i in range(300)])
    big = render_comment(many)
    assert len(big) < 65_536 and "Truncated" in big


# ------------------------------------------------------------------ JSON artifact (FR-6.3)


def trace(name: str, n_connects: int = 0) -> BehaviorTrace:
    return BehaviorTrace(
        spec=PackageSpec(name=name, version="1.0"),
        completeness=Completeness.COMPLETE,
        connects=[
            ConnectAttempt(step="import", family="AF_INET", address="10.0.0.1", port=i)
            for i in range(n_connects)
        ],
        subprocesses=[SubprocessCall(step="install", argv=["sh", "-c", "x" * 50])] * n_connects,
    )


def test_report_artifact_keeps_only_non_allow_traces(tmp_path: Path) -> None:
    r = report(
        [verdict(Level.ALLOW, "good"), verdict(Level.BLOCK, "bad")],
        traces={"good": trace("good"), "bad": trace("bad"), "orphan": trace("orphan")},
    )
    out = tmp_path / "r.json.gz"
    write_report_artifact(r, out)
    data = json.loads(gzip.decompress(out.read_bytes()))
    assert set(data["traces"]) == {"bad", "orphan"}
    assert ScanReport.model_validate(data).verdicts == r.verdicts


def test_trace_cap(tmp_path: Path) -> None:
    t = trace("bad", 2000)
    size = len(t.model_dump_json())
    capped = cap_trace(t, limit=size // 3)
    assert capped.truncated
    assert len(capped.model_dump_json()) <= size // 3
    assert 0 < len(capped.connects) < len(t.connects)
    assert cap_trace(t, limit=size) is t  # under the cap: untouched


def test_report_artifact_applies_5mb_cap(tmp_path: Path) -> None:
    big = trace("bad", 40_000)  # ~7 MB serialised
    assert len(big.model_dump_json()) > 5 * 1024 * 1024
    r = report([verdict(Level.BLOCK, "bad")], traces={"bad": big})
    out = tmp_path / "r.json.gz"
    write_report_artifact(r, out)
    data = json.loads(gzip.decompress(out.read_bytes()))
    t = data["traces"]["bad"]
    assert t["truncated"] is True
    assert len(json.dumps(t)) <= 5 * 1024 * 1024 + 100_000  # json.dumps spacing differs
