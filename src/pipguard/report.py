"""Job summary, PR comment, JSON report artifact and exit codes (FR-6, FR-7.4).

Everything interpolated into Markdown comes from package metadata, archives or strace
output, i.e. from the attacker. ``_cell`` makes it inert: one line, capped, with every
character that could open a table cell, HTML tag, code span, link, mention or
autolink neutralised.
"""

from __future__ import annotations

import gzip
from collections import Counter
from pathlib import Path

from pipguard.models import BehaviorTrace, Level, ScanReport, Verdict

COMMENT_MARKER = "<!-- pipguard-report -->"
MAX_CELL = 200
MAX_REASONS = 3
MAX_COMMENT = 60_000  # GitHub rejects comment bodies over 65,536 characters
MAX_TRACE_BYTES = 5 * 1024 * 1024  # FR-6.3, per package

_FAILING = frozenset({Level.BLOCK, Level.ERROR, Level.INCOMPLETE})
_ZWSP = "\u200b"
# Markdown/HTML-active ASCII punctuation -> numeric entities (rendered as the literal char).
_ESCAPES = str.maketrans({c: f"&#{ord(c)};" for c in "&<>|`*_[]()!#~\\$:"})

FORK_NOTE = (
    "Fork PR: the token is read-only, so no PR comment was posted and the cache was not updated."
)
NEVER_OBSERVED = (
    "Never observed: environment-variable reads and DNS names (strace cannot see them), "
    "sdist build behaviour, and behaviour that triggers only on specific inputs, timers or "
    "environment checks."
)


def exit_code(levels: list[Level], *, fail_on_warn: bool) -> int:
    """FR-7.4: 3 error/incomplete (wins), 2 block, 1 warn with --fail-on-warn, else 0."""
    found = set(levels)
    if found & {Level.ERROR, Level.INCOMPLETE}:
        return 3
    if Level.BLOCK in found:
        return 2
    if fail_on_warn and Level.WARN in found:
        return 1
    return 0


def _cell(text: object, limit: int = MAX_CELL) -> str:
    """Untrusted text -> one inert Markdown table-cell fragment."""
    s = " ".join(str(text).split())  # newlines/tabs cannot start a new row
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    # Break @mentions and www./scheme autolinks with a zero-width space, then entity-escape.
    for token in ("@", "://", "www."):
        s = s.replace(token, token[0] + _ZWSP + token[1:])
    return s.translate(_ESCAPES)


def _verdict_cell(v: Verdict) -> str:
    out = f"**{v.level.value}**"
    if v.score is not None:
        out += f" ({v.score_label} {v.score:.2f})"
    if v.cache_hit:
        out += " (cached)"
    return out


def _artifact_cell(v: Verdict) -> str:
    refs = [f"{_cell(a.filename, 80)} ({a.sha256[:12]})" for a in v.coverage.artifacts]
    return "<br>".join(refs) or "none examined"


def _coverage_cell(v: Verdict) -> str:
    c = v.coverage
    parts = [f"fetch {c.fetch}, static {c.static}, sandbox {c.sandbox}, scoring {c.scoring}"]
    if c.sandbox_completeness is not None:
        parts.append(f"sandbox result: {c.sandbox_completeness}")
    if c.not_evaluated:
        parts.append("not evaluated: " + ", ".join(c.not_evaluated[:5]))
    return _cell("; ".join(parts), 400)


def _row(v: Verdict) -> str:
    package = _cell(str(v.spec) if v.spec else v.raw_spec, 120)
    reasons = "<br>".join(_cell(r) for r in v.reasons[:MAX_REASONS]) or "-"
    cells = [package, _artifact_cell(v), _verdict_cell(v), _coverage_cell(v), reasons]
    return "| " + " | ".join(cells) + " |"


_HEADER = [
    "| package | artifact | verdict | coverage | top reasons |",
    "|---|---|---|---|---|",
]


def _outcome(levels: list[Level], fail_on_warn: bool) -> str:
    code = exit_code(levels, fail_on_warn=fail_on_warn)
    if code == 3:
        return "FAIL: error or incomplete scan (failing closed)"
    if code == 2:
        return "FAIL: blocked"
    if code == 1:
        return "FAIL: warnings (fail-on-warn)"
    if Level.WARN in levels:
        return "PASS with warnings"
    return "PASS"


def render_summary(report: ScanReport, *, fail_on_warn: bool = False, fork_pr: bool = False) -> str:
    """GitHub job-summary Markdown (FR-6.1)."""
    verdicts = report.verdicts
    levels = [v.level for v in verdicts]
    counts = Counter(levels)
    lines = [f"## pip guard: {_outcome(levels, fail_on_warn)}", ""]
    if not verdicts:
        lines.append("No added or changed pinned dependencies.")
    else:
        lines.append(", ".join(f"{lvl.value}: {counts[lvl]}" for lvl in Level))
        lines.append("")
        shown = [v for v in verdicts if v.level is not Level.ALLOW]
        allowed = [v for v in verdicts if v.level is Level.ALLOW]
        if shown:
            lines += [*_HEADER, *(_row(v) for v in shown), ""]
        if allowed:
            lines += [f"<details><summary>{len(allowed)} allowed</summary>", ""]
            lines += [*_HEADER, *(_row(v) for v in allowed), "", "</details>", ""]
    overridden = [v for v in verdicts if v.overrides]
    if overridden:
        lines += ["**Overrides applied:**", ""]
        lines += [
            f"- {_cell(str(v.spec) if v.spec else v.raw_spec, 120)}: "
            + "; ".join(_cell(o) for o in v.overrides[:5])
            for v in overridden
        ]
        lines.append("")
    for note in report.notes[:10]:
        lines.append(f"> {_cell(note, 300)}")
    if fork_pr:
        lines.append(f"> {FORK_NOTE}")
    footer = f"scanner {_cell(report.scanner_version, 40)}, run {_cell(report.correlation_id, 40)}"
    lines += ["", f"_{NEVER_OBSERVED}_", f"<sub>{footer}</sub>", ""]
    return "\n".join(lines)


def render_comment(report: ScanReport, *, fail_on_warn: bool = False) -> str:
    """PR comment body (FR-6.4); the marker lets the Action find and update it in place."""
    body = render_summary(report, fail_on_warn=fail_on_warn)
    if len(body) > MAX_COMMENT:
        body = body[:MAX_COMMENT] + "\n\n_Truncated: see the job summary and report artifact._\n"
    return f"{COMMENT_MARKER}\n{body}"


_TRACE_LISTS = (
    "imported_modules",
    "writes_outside_allowed",
    "credential_reads",
    "subprocesses",
    "connects",
)


def cap_trace(trace: BehaviorTrace, limit: int = MAX_TRACE_BYTES) -> BehaviorTrace:
    """Halve every list field until the serialised trace fits ``limit``; mark it truncated."""
    if len(trace.model_dump_json()) <= limit:
        return trace
    trace = trace.model_copy(
        update={"truncated": True, "completeness_reason": trace.completeness_reason[:1000]}
    )
    while len(trace.model_dump_json()) > limit and any(getattr(trace, f) for f in _TRACE_LISTS):
        trace = trace.model_copy(
            update={f: getattr(trace, f)[: len(getattr(trace, f)) // 2] for f in _TRACE_LISTS}
        )
    return trace


def write_report_artifact(report: ScanReport, path: Path) -> None:
    """gzip JSON report (FR-6.3). Traces only for non-allow verdicts, each capped at 5 MB.

    A trace is dropped only when the verdict for its spec is ``allow``; a trace with no
    matching verdict is kept, since evidence is cheaper than a missing explanation.
    """
    allowed = {
        (v.spec.normalized_name, v.spec.version)
        for v in report.verdicts
        if v.spec is not None and v.level is Level.ALLOW
    }
    flagged = {
        (v.spec.normalized_name, v.spec.version)
        for v in report.verdicts
        if v.spec is not None and v.level is not Level.ALLOW
    }
    traces = {
        key: cap_trace(t)
        for key, t in report.traces.items()
        if (k := (t.spec.normalized_name, t.spec.version)) not in allowed or k in flagged
    }
    data = report.model_copy(update={"traces": traces}).model_dump_json()
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(data)
