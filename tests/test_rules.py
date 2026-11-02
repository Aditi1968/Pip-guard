import unicodedata
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pipguard.errors import PipGuardError
from pipguard.features import FEATURE_NAMES
from pipguard.models import (
    ArtifactStaticFeatures,
    BehaviorTrace,
    Completeness,
    ConnectAttempt,
    CredentialRead,
    FileWrite,
    InstallIndicators,
    Level,
    PackageMetadata,
    PackageSpec,
    ScanReport,
    StaticFeatures,
    SubprocessCall,
    SuspiciousCounts,
    TyposquatResult,
    Verdict,
)
from pipguard.report import render_summary
from pipguard.rules import (
    EVIDENCE_KEYS,
    build_inputs,
    evaluate,
    load_rules,
    render,
    safe_text,
)

SPEC = PackageSpec(name="pkg", version="1.0")
RULES = load_rules()


def static(typo: TyposquatResult | None = None, **art: object) -> StaticFeatures:
    a = ArtifactStaticFeatures.model_validate(
        {"filename": "pkg-1.0-py3-none-any.whl", "sha256": "0" * 64, "kind": "wheel"} | art
    )
    return StaticFeatures(
        spec=SPEC,
        artifacts=[a],
        typosquat=typo or TyposquatResult(snapshot_date=date(2026, 10, 1)),
        metadata=PackageMetadata(),
    )


def trace(**kw: object) -> BehaviorTrace:
    return BehaviorTrace(spec=SPEC, completeness=Completeness.COMPLETE, **kw)  # type: ignore[arg-type]


def hit_ids(sf: StaticFeatures, tr: BehaviorTrace | None = None) -> set[str]:
    return {h.rule_id for h in evaluate(RULES, *build_inputs(sf, tr))}


def test_clean_package_fires_nothing() -> None:
    assert hit_ids(static(), trace()) == set()
    assert hit_ids(static()) == set()


@pytest.mark.parametrize(
    ("tr", "expected"),
    [
        (
            trace(
                connects=[
                    ConnectAttempt(step="install", family="AF_INET", address="185.1.2.3", port=443)
                ]
            ),
            {"B_CONNECT_INSTALL", "W_CONNECT_INSTALL"},
        ),
        # Loopback / unspecified / Unix sockets during install only warn.
        (
            trace(
                connects=[
                    ConnectAttempt(step="install", family="AF_INET", address="127.0.0.1", port=80)
                ]
            ),
            {"W_CONNECT_INSTALL"},
        ),
        (
            trace(
                connects=[ConnectAttempt(step="install", family="AF_INET6", address="::", port=80)]
            ),
            {"W_CONNECT_INSTALL"},
        ),
        (
            trace(connects=[ConnectAttempt(step="install", family="AF_UNIX", address="/dev/log")]),
            {"W_CONNECT_INSTALL"},
        ),
        # Unparseable inet address counts as external.
        (
            trace(connects=[ConnectAttempt(step="install", family="AF_INET", address="garbage")]),
            {"B_CONNECT_INSTALL", "W_CONNECT_INSTALL"},
        ),
        (
            trace(
                connects=[
                    ConnectAttempt(step="import", family="AF_INET", address="8.8.8.8", port=53)
                ]
            ),
            {"W_CONNECT_IMPORT"},
        ),
        (
            trace(credential_reads=[CredentialRead(step="import", path="/root/.aws/credentials")]),
            {"W_CREDENTIAL_READ"},
        ),
        (
            trace(
                credential_reads=[CredentialRead(step="import", path="/root/.ssh/id_rsa")],
                subprocesses=[SubprocessCall(step="import", argv=["/bin/true"])],
            ),
            {"B_CREDENTIAL_EXFIL", "W_CREDENTIAL_READ"},
        ),
        (trace(subprocesses=[SubprocessCall(step="import", argv=["git", "rev-parse"])]), set()),
        (
            trace(
                subprocesses=[SubprocessCall(step="install", argv=["/usr/bin/curl", "http://x"])]
            ),
            {"W_SUSPICIOUS_SUBPROCESS"},
        ),
        (
            trace(writes_outside_allowed=[FileWrite(step="install", path="/etc/cron.d/x")]),
            {"W_WRITE_OUTSIDE"},
        ),
    ],
)
def test_behaviour_rules(tr: BehaviorTrace, expected: set[str]) -> None:
    assert hit_ids(static(), tr) == expected


@pytest.mark.parametrize(
    ("art", "expected"),
    [
        ({"install": InstallIndicators(setup_py_cmdclass=True)}, {"W_INSTALL_HOOK"}),
        ({"install": InstallIndicators(overridden_install_command=True)}, {"W_INSTALL_HOOK"}),
        ({"install": InstallIndicators(pep517_build_backend=True)}, set()),
        ({"install": InstallIndicators(pth_import_lines=True)}, {"W_PTH_IMPORT"}),
        ({"ip_literals": ["10.0.0.1"]}, {"W_IP_LITERAL"}),
        ({"shortener_urls": ["https://bit.ly/x"]}, {"W_URL_SHORTENER"}),
        ({"suspicious": SuspiciousCounts(b64decode=1, exec=1)}, {"W_OBFUSCATION"}),
        ({"suspicious": SuspiciousCounts(marshal_loads=2, eval=1)}, {"W_OBFUSCATION"}),
        ({"suspicious": SuspiciousCounts(b64decode=3)}, set()),
        ({"suspicious": SuspiciousCounts(exec=3)}, set()),
    ],
)
def test_static_rules(art: dict[str, Any], expected: set[str]) -> None:
    assert hit_ids(static(**art)) == expected


def _typo(distance: int | None, rank: int | None, fired: bool) -> TyposquatResult:
    return TyposquatResult(
        distance=distance,
        target="requests" if rank else None,
        target_rank=rank,
        fired=fired,
        snapshot_date=date(2026, 10, 1),
    )


@pytest.mark.parametrize(
    ("typo", "expected"),
    [
        (_typo(1, 5, True), {"B_TYPOSQUAT_TOP100", "W_TYPOSQUAT"}),
        (_typo(1, 100, True), {"B_TYPOSQUAT_TOP100", "W_TYPOSQUAT"}),
        (_typo(1, 101, True), {"W_TYPOSQUAT"}),
        (_typo(2, 5, True), {"W_TYPOSQUAT"}),
        (_typo(2, 5, False), set()),
        (_typo(None, None, False), set()),
    ],
)
def test_typosquat_rules(typo: TyposquatResult, expected: set[str]) -> None:
    assert hit_ids(static(typo)) == expected


def test_reason_rendering() -> None:
    tr = trace(
        connects=[ConnectAttempt(step="install", family="AF_INET", address="185.1.2.3", port=443)]
    )
    hits = evaluate(RULES, *build_inputs(static(), tr))
    block = next(h for h in hits if h.rule_id == "B_CONNECT_INSTALL")
    assert block.klass == "blocking"
    assert block.reason == (
        "attempted 1 outbound connect() call(s) during pip install, e.g. 185.1.2.3:443"
    )
    hits = evaluate(RULES, *build_inputs(static(_typo(1, 3, True))))
    assert "top-100 package requests" in hits[0].reason


def test_ipv6_endpoint_and_missing_evidence() -> None:
    tr = trace(
        connects=[ConnectAttempt(step="import", family="AF_INET6", address="2001:db8::1", port=80)]
    )
    _, ev = build_inputs(static(), tr)
    assert ev["first_connect_import"] == "[2001:db8::1]:80"
    assert render("x {first_ip} {susp_total}", {"susp_total": 2.5}, {}) == "x unknown 2.50"


def test_hostile_values_are_one_line() -> None:
    tr = trace(
        subprocesses=[SubprocessCall(step="install", argv=["sh", "-c", "a|b\n`rm` <x> [l](u) @me"])]
    )
    hits = evaluate(RULES, *build_inputs(static(), tr))
    reason = next(h.reason for h in hits if h.rule_id == "W_SUSPICIOUS_SUBPROCESS")
    # Plain text on one line; report.py escapes Markdown once, at render time.
    assert "\n" not in reason and "a|b" in reason


def test_safe_text_caps_length() -> None:
    out = safe_text("a" * 500)
    assert out == "a" * 120 + "…"
    assert safe_text("x‮y​z") == "x y z"


@given(st.text())
def test_safe_text_is_one_bounded_line(value: str) -> None:
    out = safe_text(value)
    assert not any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in out)
    assert len(out) <= 121
    assert len(value) <= 120 or out.endswith("…")


@given(st.lists(st.text(), min_size=1, max_size=5), st.text())
def test_hostile_trace_never_breaks_table(argv: list[str], path: str) -> None:
    tr = trace(
        subprocesses=[SubprocessCall(step="install", argv=["curl", *argv])],
        credential_reads=[CredentialRead(step="import", path=path)],
        writes_outside_allowed=[FileWrite(step="install", path=path)],
    )
    hits = evaluate(RULES, *build_inputs(static(), tr))
    assert all("\n" not in h.reason and "\r" not in h.reason for h in hits)
    # The rendering boundary keeps the table shape whatever the reasons contain.
    v = Verdict(
        spec=None,
        raw_spec="p==1",
        level=Level.WARN,
        reasons=[h.reason for h in hits] or ["x"],
        scanner_version="t",
        model_version="m",
    )
    report = ScanReport(
        scanner_version="t",
        correlation_id="c",
        generated_at=datetime(2026, 11, 2, tzinfo=UTC),
        verdicts=[v],
    )
    row = next(line for line in render_summary(report).splitlines() if "p==1" in line)
    assert row.count("|") == 6


# ---------------------------------------------------------------- schema / loading


def _load(tmp_path: Path, text: str):
    p = tmp_path / "rules.yaml"
    p.write_text(text, encoding="utf-8")
    return load_rules(p)


GOOD_RULE = """
  - id: W_X
    description: d
    reason: "{susp_exec} exec"
    when: {feature: susp_exec, op: ">=", value: 1}
"""


def test_load_custom_rules(tmp_path: Path) -> None:
    rs = _load(tmp_path, "warning:" + GOOD_RULE)
    assert [r.id for r in rs.warning] == ["W_X"]


@pytest.mark.parametrize(
    "text",
    [
        "warning:" + GOOD_RULE.replace("susp_exec, op", "no_such_feature, op"),
        "warning:" + GOOD_RULE.replace('"{susp_exec} exec"', '"{nope}"'),
        "warning:" + GOOD_RULE.replace('"{susp_exec} exec"', '"{susp_exec!r}"'),
        "warning:" + GOOD_RULE.replace('"{susp_exec} exec"', '"{susp_exec:>999}"'),
        "warning:" + GOOD_RULE.replace('"{susp_exec} exec"', '"{susp_exec.real}"'),
        "warning:" + GOOD_RULE.replace('"{susp_exec} exec"', '"{unclosed"'),
        "warning:" + GOOD_RULE.replace('op: ">="', 'op: "!="'),
        "warning:" + GOOD_RULE.replace("id: W_X", "id: lower"),
        "warning:" + GOOD_RULE + GOOD_RULE,  # duplicate id
        "warning:"
        + GOOD_RULE.replace('when: {feature: susp_exec, op: ">=", value: 1}', "when: {all: []}"),
        "warning:" + GOOD_RULE + "    extra: 1\n",
        "blocking: []\nwarning: []\n",
        "- just a list",
        "warning: [unclosed",
        "",
        "!!python/object/apply:os.system ['echo hi']",
    ],
)
def test_bad_rules_files_raise(tmp_path: Path, text: str) -> None:
    with pytest.raises(PipGuardError):
        _load(tmp_path, text)


def test_missing_rules_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PipGuardError):
        load_rules(tmp_path / "absent.yaml")


def test_missing_feature_at_evaluation_raises() -> None:
    with pytest.raises(PipGuardError):
        evaluate(RULES, {}, {})


def test_evidence_and_extra_features_cover_contract() -> None:
    feats, ev = build_inputs(static(), trace())
    assert set(FEATURE_NAMES) <= set(feats)
    assert set(ev) == set(EVIDENCE_KEYS)
