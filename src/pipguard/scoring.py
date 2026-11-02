"""Rules + model -> ``Verdict`` with reasons, coverage and overrides (PRD FR-5, FR-7.2).

Level decision, in order:

1. Blocking-rule hit -> ``block``; warning-rule hit -> at least ``warn``; a model score at or
   above a threshold can raise the level further (never lower it).
2. Allowlist (per package, PEP 503 name): ``block`` is capped at ``warn`` and the override is
   named. All reasons stay.
3. Incomplete evidence -> ``incomplete``, unless the level is already ``block``: both fail the
   check, and ``block`` says more (we saw something bad in what we did collect). An
   allowlisted package that was capped to ``warn`` and is incomplete becomes ``incomplete``,
   so the allowlist can never pass an unexamined package.

Thresholds: the model artifact's thresholds win, unless ``pipguard.toml`` sets thresholds
that differ from the defaults (an explicit user choice beats the shipped model).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from pydantic import ValidationError

from pipguard import SCANNER_VERSION
from pipguard.errors import PipGuardError
from pipguard.models import (
    ArtifactRef,
    BehaviorTrace,
    Completeness,
    Config,
    Coverage,
    DependencyChange,
    FetchedPackage,
    Level,
    ModelArtifact,
    PackageSpec,
    StageStatus,
    StaticFeatures,
    Thresholds,
    Verdict,
)
from pipguard.rules import RuleSet, build_inputs, evaluate, load_rules, safe_text

DEFAULT_MODEL_PATH = Path(__file__).parent / "model" / "model.json"
RULES_ONLY = ModelArtifact(model_version="rules-only-0", kind="rules")

ALWAYS_NOT_EVALUATED = [
    "environment-variable reads (not observable)",
    "DNS names (not observable)",
]
NOT_RUN_SANDBOX = "behaviour (sandbox not run)"
SDIST_BUILD = "sdist build-backend behaviour (not exercised)"

_RANK = {Level.ALLOW: 0, Level.WARN: 1, Level.BLOCK: 2}


# ---------------------------------------------------------------- model


def load_model(path: Path | None = None) -> ModelArtifact:
    """The trained artifact at ``path`` (default: packaged ``model/model.json`` if present).

    No default file -> the rules-only artifact. An explicit path that is missing, or any
    malformed file, raises: a broken model must never quietly score everything as allow.
    """
    if path is None:
        if not DEFAULT_MODEL_PATH.exists():
            return RULES_ONLY
        path = DEFAULT_MODEL_PATH
    try:
        return ModelArtifact.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError) as exc:
        raise PipGuardError(f"invalid model artifact {path}: {exc}") from exc


def _sigmoid(z: float) -> float:
    z = max(-500.0, min(500.0, z))  # exp overflow guard
    return 1.0 / (1.0 + math.exp(-z))


def contributions(artifact: ModelArtifact, features: dict[str, float]) -> list[tuple[str, float]]:
    """Per-feature logit contributions ``coef * (x - mean) / scale`` for a logreg artifact."""
    out: list[tuple[str, float]] = []
    for name, coef, mean, scale in zip(
        artifact.feature_names,
        artifact.coefficients,
        artifact.feature_means,
        artifact.feature_scales,
        strict=True,
    ):
        if name not in features:
            raise PipGuardError(f"model feature {safe_text(name)} is not computed by this scanner")
        if not scale > 0:
            raise PipGuardError(f"model feature {safe_text(name)} has non-positive scale")
        out.append((name, coef * (features[name] - mean) / scale))
    return out


def predict(artifact: ModelArtifact, features: dict[str, float]) -> float | None:
    """Model score in [0, 1], or ``None`` for the rules-only artifact.

    Logistic regression is a pure-Python dot product (no scikit-learn at runtime). Platt
    scaling, when present, is applied to the raw logit: ``1 / (1 + exp(a*z + b))``.
    """
    if artifact.kind == "rules":
        return None
    if artifact.kind == "lightgbm":
        # FR-5.2: LightGBM is only adopted if the evaluation says so; no runtime path yet.
        raise PipGuardError("lightgbm model artifacts are not supported by this scanner")
    z = artifact.intercept + sum(c for _, c in contributions(artifact, features))
    if artifact.platt_a is not None and artifact.platt_b is not None:
        return _sigmoid(-(artifact.platt_a * z + artifact.platt_b))
    return _sigmoid(z)


def score_label(artifact: ModelArtifact) -> str:
    calibrated = artifact.platt_a is not None and artifact.platt_b is not None
    return "calibrated probability" if calibrated else "score"


def effective_thresholds(model: ModelArtifact, config: Config) -> Thresholds:
    """Config thresholds win only if the user changed them from the defaults."""
    return config.thresholds if config.thresholds != Thresholds() else model.thresholds


def _model_reasons(
    artifact: ModelArtifact, features: dict[str, float], value: float, threshold: float
) -> list[str]:
    reasons = [f"model {score_label(artifact)} {value:.2f} ≥ threshold {threshold:.2f}"]
    # FR-5.5 (P1): top-3 positive coefficient contributions, one fixed template.
    top = sorted((c for c in contributions(artifact, features) if c[1] > 0), key=lambda c: -c[1])
    for name, contrib in top[:3]:
        reasons.append(
            f"model contribution +{contrib:.2f} from {safe_text(name, 60)} = "
            f"{safe_text(f'{features[name]:g}')}"
        )
    return reasons


# ---------------------------------------------------------------- coverage


def _sandbox_state(
    trace: BehaviorTrace | None, sandbox_requested: bool
) -> tuple[StageStatus, bool]:
    """(coverage status, evidence complete?)."""
    if trace is None:
        return (StageStatus.FAILED, False) if sandbox_requested else (StageStatus.SKIPPED, True)
    if trace.completeness is Completeness.COMPLETE:
        return StageStatus.COMPLETED, True
    if trace.completeness is Completeness.SKIPPED_POLICY:
        return StageStatus.SKIPPED, not sandbox_requested
    return StageStatus.FAILED, False


def _coverage(pkg: FetchedPackage, trace: BehaviorTrace | None, sandbox: StageStatus) -> Coverage:
    not_evaluated = list(ALWAYS_NOT_EVALUATED)
    if pkg.sdist is not None:
        not_evaluated.append(SDIST_BUILD)
    if sandbox is StageStatus.SKIPPED:
        not_evaluated.append(NOT_RUN_SANDBOX)
    elif sandbox is StageStatus.FAILED:
        not_evaluated.append("behaviour after the sandbox stopped (trace incomplete)")
    return Coverage(
        fetch=StageStatus.COMPLETED,
        static=StageStatus.COMPLETED,
        sandbox=sandbox,
        scoring=StageStatus.COMPLETED,
        sandbox_completeness=trace.completeness if trace else None,
        artifacts=[
            ArtifactRef(filename=a.filename, sha256=a.sha256, kind=a.kind) for a in pkg.artifacts
        ],
        not_evaluated=not_evaluated,
    )


# ---------------------------------------------------------------- verdicts


def score(
    static: StaticFeatures,
    trace: BehaviorTrace | None,
    pkg: FetchedPackage,
    *,
    config: Config,
    sandbox_requested: bool,
    model: ModelArtifact,
    scanner_version: str = SCANNER_VERSION,
    ruleset: RuleSet | None = None,
) -> Verdict:
    """Assemble the verdict for one fetched, statically analysed (and maybe traced) package."""
    ruleset = ruleset or load_rules()
    sandbox, complete = _sandbox_state(trace, sandbox_requested)
    # A policy-skipped trace holds no behaviour; vectorising it would claim behaviour_available.
    usable = (
        trace
        if trace is not None and trace.completeness is not Completeness.SKIPPED_POLICY
        else None
    )
    features, evidence = build_inputs(static, usable)

    hits = evaluate(ruleset, features, evidence)
    reasons = [h.reason for h in hits]
    level = Level.ALLOW
    if any(h.klass == "blocking" for h in hits):
        level = Level.BLOCK
    elif hits:
        level = Level.WARN

    thresholds = effective_thresholds(model, config)
    value = predict(model, features)
    if value is not None:
        model_level, cut = Level.ALLOW, 0.0
        if value >= thresholds.block:
            model_level, cut = Level.BLOCK, thresholds.block
        elif value >= thresholds.warn:
            model_level, cut = Level.WARN, thresholds.warn
        if model_level is not Level.ALLOW:
            reasons += _model_reasons(model, features, value, cut)
            if _RANK[model_level] > _RANK[level]:
                level = model_level

    overrides: list[str] = []
    if level is Level.BLOCK and static.spec.normalized_name in config.allowlist:
        level = Level.WARN
        overrides.append("allowlisted in pipguard.toml: capped block → warn")

    if not complete:
        if trace is None:
            reasons.append("sandbox was requested but produced no trace")
        else:
            detail = (
                f": {safe_text(trace.completeness_reason)}" if trace.completeness_reason else ""
            )
            reasons.append(f"sandbox trace {trace.completeness.value}{detail}")
        if level is not Level.BLOCK:
            level = Level.INCOMPLETE

    return Verdict(
        spec=static.spec,
        raw_spec=str(static.spec),
        level=level,
        score=value,
        score_label=score_label(model),  # type: ignore[arg-type]
        reasons=reasons,
        coverage=_coverage(pkg, trace, sandbox),
        overrides=overrides,
        rule_hits=[h.rule_id for h in hits],
        scanner_version=scanner_version,
        model_version=model.model_version,
        thresholds=thresholds,
    )


def error_verdict(
    raw_spec: str,
    spec: PackageSpec | None,
    reason: str,
    *,
    coverage: Coverage | None = None,
    scanner_version: str = SCANNER_VERSION,
    model_version: str = RULES_ONLY.model_version,
) -> Verdict:
    """A scan that could not finish (fetch failure, hash mismatch, crash). Fails the check."""
    coverage = coverage or Coverage(not_evaluated=["package (scan failed before analysis)"])
    return Verdict(
        spec=spec,
        raw_spec=raw_spec,
        level=Level.ERROR,
        reasons=[safe_text(reason, 300) or "scan failed"],
        coverage=coverage,
        scanner_version=scanner_version,
        model_version=model_version,
    )


def unsupported_verdict(
    change: DependencyChange,
    *,
    scanner_version: str = SCANNER_VERSION,
    model_version: str = RULES_ONLY.model_version,
) -> Verdict:
    """FR-1.2: a spec that is not an exact pin is reported as ``warn`` and not scanned."""
    if change.unsupported_reason is None:
        raise ValueError("unsupported_verdict needs a change without an exact pin")
    return Verdict(
        spec=None,
        raw_spec=change.raw,
        level=Level.WARN,
        reasons=[f"not scanned: {safe_text(change.unsupported_reason)}"],
        coverage=Coverage(not_evaluated=["package (not an exact pin, not scanned)"]),
        scanner_version=scanner_version,
        model_version=model_version,
    )
