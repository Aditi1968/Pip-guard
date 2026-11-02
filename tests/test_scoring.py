import json
import math
from datetime import date
from pathlib import Path

import pytest

from pipguard import scoring
from pipguard.errors import PipGuardError
from pipguard.features import FEATURE_NAMES
from pipguard.models import (
    Artifact,
    ArtifactKind,
    ArtifactStaticFeatures,
    BehaviorTrace,
    ChangeKind,
    Completeness,
    Config,
    ConnectAttempt,
    Coverage,
    DependencyChange,
    FetchedPackage,
    InstallIndicators,
    Level,
    ModelArtifact,
    PackageMetadata,
    PackageSpec,
    StageStatus,
    StaticFeatures,
    SubprocessCall,
    Thresholds,
    TyposquatResult,
)
from pipguard.scoring import (
    NOT_RUN_SANDBOX,
    RULES_ONLY,
    SDIST_BUILD,
    effective_thresholds,
    error_verdict,
    load_model,
    predict,
    score,
    score_label,
    unsupported_verdict,
)

SPEC = PackageSpec(name="My_Pkg", version="1.0")
SHA = "a" * 64


def static(**art: object) -> StaticFeatures:
    a = ArtifactStaticFeatures(filename="w.whl", sha256=SHA, kind=ArtifactKind.WHEEL, **art)  # type: ignore[arg-type]
    return StaticFeatures(
        spec=SPEC,
        artifacts=[a],
        typosquat=TyposquatResult(snapshot_date=date(2026, 10, 1)),
        metadata=PackageMetadata(),
    )


def pkg(sdist: bool = False) -> FetchedPackage:
    arts = [Artifact(filename="w.whl", kind=ArtifactKind.WHEEL, sha256=SHA, size=1, path="w.whl")]
    if sdist:
        arts.append(
            Artifact(
                filename="s.tar.gz", kind=ArtifactKind.SDIST, sha256="b" * 64, size=1, path="s"
            )
        )
    return FetchedPackage(spec=SPEC, artifacts=arts, metadata=PackageMetadata())


def trace(completeness: Completeness = Completeness.COMPLETE, **kw: object) -> BehaviorTrace:
    return BehaviorTrace(spec=SPEC, completeness=completeness, **kw)  # type: ignore[arg-type]


BAD_CONNECT = [ConnectAttempt(step="install", family="AF_INET", address="185.1.2.3", port=443)]
HOOK = {"install": InstallIndicators(setup_py_cmdclass=True)}


def run(
    sf: StaticFeatures | None = None,
    tr: BehaviorTrace | None = None,
    *,
    config: Config | None = None,
    sandbox_requested: bool = True,
    model: ModelArtifact = RULES_ONLY,
    sdist: bool = False,
):
    return score(
        sf or static(),
        tr,
        pkg(sdist),
        config=config or Config(),
        sandbox_requested=sandbox_requested,
        model=model,
        scanner_version="test",
    )


def logreg(**kw: object) -> ModelArtifact:
    base: dict[str, object] = {
        "model_version": "lr-1",
        "kind": "logreg",
        "feature_names": ["susp_exec", "url_count"],
        "feature_means": [1.0, 0.0],
        "feature_scales": [2.0, 1.0],
        "coefficients": [1.0, 0.5],
        "intercept": -1.0,
    }
    return ModelArtifact.model_validate(base | kw)


# ---------------------------------------------------------------- levels


def test_clean_complete_trace_allows() -> None:
    v = run(tr=trace())
    assert v.level is Level.ALLOW
    assert v.reasons == [] and v.score is None and v.score_label == "score"
    assert v.model_version == "rules-only-0" and v.scanner_version == "test"
    c = v.coverage
    assert (c.fetch, c.static, c.sandbox, c.scoring) == (StageStatus.COMPLETED,) * 4
    assert c.sandbox_completeness is Completeness.COMPLETE
    assert c.artifacts[0].sha256 == SHA
    assert c.not_evaluated == scoring.ALWAYS_NOT_EVALUATED


def test_blocking_hit_blocks() -> None:
    v = run(tr=trace(connects=BAD_CONNECT))
    assert v.level is Level.BLOCK
    assert "B_CONNECT_INSTALL" in v.rule_hits
    assert any("185.1.2.3:443" in r for r in v.reasons)


def test_warning_hit_warns() -> None:
    v = run(static(**HOOK), trace(), sdist=True)
    assert v.level is Level.WARN and v.rule_hits == ["W_INSTALL_HOOK"]
    assert SDIST_BUILD in v.coverage.not_evaluated


def test_allowlist_caps_block_at_warn_and_keeps_reasons() -> None:
    cfg = Config(allowlist=["my-pkg"])
    v = run(tr=trace(connects=BAD_CONNECT), config=cfg)
    assert v.level is Level.WARN
    assert v.overrides == ["allowlisted in pipguard.toml: capped block → warn"]
    assert "B_CONNECT_INSTALL" in v.rule_hits and v.reasons


def test_allowlist_never_lowers_warning_to_allow() -> None:
    v = run(static(**HOOK), trace(), config=Config(allowlist=["My.Pkg"]))
    assert v.level is Level.WARN and v.overrides == []


@pytest.mark.parametrize(
    "c",
    [
        Completeness.TIMEOUT,
        Completeness.IMPORT_FAILED,
        Completeness.NO_IMPORTABLE_MODULE,
        Completeness.NO_WHEEL,
        Completeness.SANDBOX_ERROR,
        Completeness.TRACE_TRUNCATED,
        Completeness.SKIPPED_POLICY,
    ],
)
def test_incomplete_trace_is_incomplete(c: Completeness) -> None:
    v = run(static(**HOOK), trace(c, completeness_reason="killed | after `90s`"))
    assert v.level is Level.INCOMPLETE
    assert any(c.value in r for r in v.reasons)
    assert all("|" not in r and "`" not in r for r in v.reasons)


def test_incomplete_with_blocking_hit_is_block() -> None:
    v = run(tr=trace(Completeness.TIMEOUT, connects=BAD_CONNECT))
    assert v.level is Level.BLOCK
    assert v.coverage.sandbox is StageStatus.FAILED
    assert any("incomplete:timeout" in r for r in v.reasons)


def test_incomplete_allowlisted_block_stays_failing() -> None:
    v = run(
        tr=trace(Completeness.TIMEOUT, connects=BAD_CONNECT), config=Config(allowlist=["my-pkg"])
    )
    assert v.level is Level.INCOMPLETE


def test_sandbox_requested_but_no_trace_is_incomplete() -> None:
    v = run(tr=None, sandbox_requested=True)
    assert v.level is Level.INCOMPLETE
    assert v.coverage.sandbox is StageStatus.FAILED


def test_no_sandbox_uses_static_evidence() -> None:
    v = run(tr=None, sandbox_requested=False)
    assert v.level is Level.ALLOW
    assert v.coverage.sandbox is StageStatus.SKIPPED
    assert NOT_RUN_SANDBOX in v.coverage.not_evaluated
    # policy-skipped trace when not requested is the same thing
    v = run(tr=trace(Completeness.SKIPPED_POLICY), sandbox_requested=False)
    assert v.level is Level.ALLOW and v.coverage.sandbox is StageStatus.SKIPPED


def test_incomplete_but_not_requested_still_incomplete() -> None:
    v = run(tr=trace(Completeness.TIMEOUT), sandbox_requested=False)
    assert v.level is Level.INCOMPLETE


# ---------------------------------------------------------------- model


def test_predict_logreg_known_numbers() -> None:
    feats = dict.fromkeys(FEATURE_NAMES, 0.0) | {"susp_exec": 5.0, "url_count": 2.0}
    # z = -1 + 1*(5-1)/2 + 0.5*(2-0)/1 = 2
    assert predict(logreg(), feats) == pytest.approx(1 / (1 + math.exp(-2)))
    assert predict(RULES_ONLY, feats) is None
    calibrated = logreg(platt_a=-2.0, platt_b=1.0)
    # p = 1 / (1 + exp(a*z + b)) = 1 / (1 + exp(-3))
    assert predict(calibrated, feats) == pytest.approx(1 / (1 + math.exp(-3)))
    assert score_label(calibrated) == "calibrated probability"
    assert score_label(logreg()) == "score"


def test_predict_errors() -> None:
    feats = dict.fromkeys(FEATURE_NAMES, 0.0)
    with pytest.raises(PipGuardError):
        predict(logreg(feature_names=["nope", "url_count"]), feats)
    with pytest.raises(PipGuardError):
        predict(logreg(feature_scales=[0.0, 1.0]), feats)
    with pytest.raises(PipGuardError):
        predict(ModelArtifact(model_version="g", kind="lightgbm"), feats)


def test_model_score_warns_and_blocks_with_contributions() -> None:
    lr = logreg(thresholds=Thresholds(warn=0.5, block=0.9))
    v = run(static(suspicious={"exec": 5}), trace(), model=lr)  # type: ignore[arg-type]
    # z = -1 + 2 + 0 = 1 -> 0.73: warn
    assert v.level is Level.WARN and v.score == pytest.approx(0.731, abs=1e-3)
    assert v.reasons[0] == "model score 0.73 ≥ threshold 0.50"
    assert v.reasons[1] == "model contribution +2.00 from susp_exec = 5"
    assert v.model_version == "lr-1"
    v = run(static(suspicious={"exec": 21}), trace(), model=lr)  # type: ignore[arg-type]
    assert v.level is Level.BLOCK
    v = run(static(), trace(), model=lr)
    assert v.level is Level.ALLOW and v.reasons == []


def test_model_cannot_lower_rule_level() -> None:
    v = run(tr=trace(connects=BAD_CONNECT), model=logreg())
    assert v.level is Level.BLOCK


def test_threshold_precedence() -> None:
    model = logreg(thresholds=Thresholds(warn=0.3, block=0.6))
    assert effective_thresholds(model, Config()) == Thresholds(warn=0.3, block=0.6)
    user = Config(thresholds=Thresholds(warn=0.2, block=0.95))
    assert effective_thresholds(model, user) == user.thresholds


def test_load_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scoring, "DEFAULT_MODEL_PATH", tmp_path / "missing.json")
    assert load_model() is RULES_ONLY
    good = tmp_path / "model.json"
    good.write_text(logreg().model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(scoring, "DEFAULT_MODEL_PATH", good)
    assert load_model().model_version == "lr-1"
    assert load_model(good).kind == "logreg"
    bad = tmp_path / "bad.json"
    for text in ("{not json", json.dumps({"kind": "logreg", "model_version": "x"}), "[]"):
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(PipGuardError):
            load_model(bad)
    with pytest.raises(PipGuardError):
        load_model(tmp_path / "absent.json")


# ---------------------------------------------------------------- invariants (FR-5.4)

CASES = [
    (static(), trace()),
    (static(**HOOK), trace()),
    (static(), trace(connects=BAD_CONNECT)),
    (static(**HOOK), trace(Completeness.TIMEOUT)),
    (static(), trace(Completeness.SKIPPED_POLICY)),
    (static(), None),
    (static(), trace(subprocesses=[SubprocessCall(step="import", argv=["bash"])])),
]


@pytest.mark.parametrize(("sf", "tr"), CASES)
@pytest.mark.parametrize("allow", [[], ["my-pkg"]])
@pytest.mark.parametrize("requested", [True, False])
def test_invariants(
    sf: StaticFeatures, tr: BehaviorTrace | None, allow: list[str], requested: bool
) -> None:
    v = run(sf, tr, config=Config(allowlist=allow), sandbox_requested=requested)
    if v.level is not Level.ALLOW:
        assert v.reasons
    blocking = any(h.startswith("B_") for h in v.rule_hits)
    if blocking and not allow:
        assert v.level is Level.BLOCK
    if v.rule_hits:
        assert v.level is not Level.ALLOW
    incomplete_trace = (tr is None and requested) or (
        tr is not None
        and not tr.completeness.is_complete
        and not (tr.completeness is Completeness.SKIPPED_POLICY and not requested)
    )
    if incomplete_trace:
        assert v.level in (Level.INCOMPLETE, Level.BLOCK)


# ---------------------------------------------------------------- helpers


def test_error_verdict() -> None:
    v = error_verdict("pkg==1", SPEC, "hash mismatch\n| `x`", scanner_version="t")
    assert v.level is Level.ERROR and v.reasons == ["hash mismatch &#124; &#96;x&#96;"]
    assert v.coverage.fetch is StageStatus.NOT_RUN
    cov = Coverage(fetch=StageStatus.FAILED)
    assert error_verdict("x", None, "", coverage=cov).reasons == ["scan failed"]


def test_unsupported_verdict() -> None:
    ch = DependencyChange(
        raw="requests>=2",
        source_file="requirements.txt",
        kind=ChangeKind.ADDED,
        spec=None,
        unsupported_reason=">=",
    )
    v = unsupported_verdict(ch)
    assert v.level is Level.WARN and v.spec is None and v.raw_spec == "requests>=2"
    assert v.reasons == ["not an exact pin (&gt;=): not scanned"]
    pinned = DependencyChange(raw="a==1", source_file="r", kind=ChangeKind.ADDED, spec=SPEC)
    with pytest.raises(ValueError):
        unsupported_verdict(pinned)
