"""Flatten stage outputs into the tabular feature vector (PRD: "Feature set (v1)").

This one function feeds both training (``scripts/eval``) and inference (``scoring.py``), so
the two can never drift apart. Missing metadata is encoded as 0 plus an explicit
``*_missing`` flag rather than a sentinel the model might read as a real value.
"""

from __future__ import annotations

import posixpath

from pipguard.models import (
    ArtifactKind,
    BehaviorTrace,
    Completeness,
    ImportCategory,
    StaticFeatures,
    SuspiciousCounts,
)

# Typosquat distance beyond this means "no close name"; keeps the feature bounded.
TYPOSQUAT_FAR = 3

SUSPICIOUS_ARGV = frozenset({"curl", "wget", "sh", "bash", "dash", "powershell", "pwsh", "nc"})

STATIC_FEATURE_NAMES: list[str] = [
    "has_wheel",
    "has_sdist",
    "file_count",
    "total_size_kb",
    "py_file_count",
    "syntax_error_count",
    "has_compiled_extensions",
    "setup_py_cmdclass",
    "overridden_install_command",
    "pth_import_lines",
    "pep517_build_backend",
    *(f"susp_{name}" for name in SuspiciousCounts.model_fields),
    "susp_total",
    "max_string_entropy",
    "high_entropy_string_count",
    "url_count",
    "ip_literal_count",
    "domain_count",
    "shortener_count",
    *(f"imports_{c.value}" for c in ImportCategory),
    "typosquat_distance",
    "typosquat_fired",
    "typosquat_target_rank",
    "days_since_release",
    "days_since_release_missing",
    "days_since_first_release",
    "days_since_first_release_missing",
    "version_count",
    "version_count_missing",
    "maintainer_count",
    "maintainer_count_missing",
]

BEHAVIOUR_FEATURE_NAMES: list[str] = [
    "behaviour_available",
    "connect_install_count",
    "connect_import_count",
    "credential_read_count",
    "subprocess_count",
    "subprocess_suspicious_argv",
    "write_outside_allowed_count",
    "sandbox_timeout",
    "sandbox_import_failed",
    "credential_read_and_connect_or_subprocess",
]

FEATURE_NAMES: list[str] = STATIC_FEATURE_NAMES + BEHAVIOUR_FEATURE_NAMES


def _opt(value: int | None) -> tuple[float, float]:
    return (0.0, 1.0) if value is None else (float(value), 0.0)


def static_vector(sf: StaticFeatures) -> dict[str, float]:
    """Static features aggregated over all artifacts (wheel and sdist): sum, max or any."""
    arts = sf.artifacts
    v: dict[str, float] = {
        "has_wheel": float(any(a.kind is ArtifactKind.WHEEL for a in arts)),
        "has_sdist": float(any(a.kind is ArtifactKind.SDIST for a in arts)),
        "file_count": float(max((a.file_count for a in arts), default=0)),
        "total_size_kb": max((a.total_size for a in arts), default=0) / 1024,
        "py_file_count": float(max((a.py_file_count for a in arts), default=0)),
        "syntax_error_count": float(sum(a.syntax_error_count for a in arts)),
        "has_compiled_extensions": float(any(a.has_compiled_extensions for a in arts)),
        "max_string_entropy": max((a.max_string_entropy for a in arts), default=0.0),
        "high_entropy_string_count": float(sum(a.high_entropy_string_count for a in arts)),
        "url_count": float(len({u for a in arts for u in a.urls})),
        "ip_literal_count": float(len({i for a in arts for i in a.ip_literals})),
        "domain_count": float(len({d for a in arts for d in a.domains})),
        "shortener_count": float(len({s for a in arts for s in a.shortener_urls})),
    }
    for flag in (
        "setup_py_cmdclass",
        "overridden_install_command",
        "pth_import_lines",
        "pep517_build_backend",
    ):
        v[flag] = float(any(getattr(a.install, flag) for a in arts))
    for name in SuspiciousCounts.model_fields:
        # Wheel and sdist usually hold the same files; max avoids double counting.
        v[f"susp_{name}"] = float(max((getattr(a.suspicious, name) for a in arts), default=0))
    v["susp_total"] = float(max((a.suspicious.total for a in arts), default=0))
    for c in ImportCategory:
        v[f"imports_{c.value}"] = float(any(c in a.risky_import_categories for a in arts))

    ts = sf.typosquat
    v["typosquat_distance"] = (
        float(min(ts.distance, TYPOSQUAT_FAR)) if ts.distance is not None else float(TYPOSQUAT_FAR)
    )
    v["typosquat_fired"] = float(ts.fired)
    v["typosquat_target_rank"] = float(ts.target_rank or 0)

    m = sf.metadata
    for name, value in (
        ("days_since_release", m.days_since_release),
        ("days_since_first_release", m.days_since_first_release),
        ("version_count", m.version_count),
        ("maintainer_count", m.maintainer_count),
    ):
        v[name], v[f"{name}_missing"] = _opt(value)
    return v


def _suspicious_argv(argv: list[str]) -> bool:
    return any(posixpath.basename(a) in SUSPICIOUS_ARGV for a in argv[:8])


def behaviour_vector(trace: BehaviorTrace | None) -> dict[str, float]:
    """Behavioural features; all zero with ``behaviour_available=0`` when not traced."""
    v = dict.fromkeys(BEHAVIOUR_FEATURE_NAMES, 0.0)
    if trace is None:
        return v
    v["behaviour_available"] = 1.0
    v["connect_install_count"] = float(sum(c.step == "install" for c in trace.connects))
    v["connect_import_count"] = float(sum(c.step == "import" for c in trace.connects))
    v["credential_read_count"] = float(len(trace.credential_reads))
    v["subprocess_count"] = float(len(trace.subprocesses))
    v["subprocess_suspicious_argv"] = float(
        any(_suspicious_argv(s.argv) for s in trace.subprocesses)
    )
    v["write_outside_allowed_count"] = float(len(trace.writes_outside_allowed))
    v["sandbox_timeout"] = float(trace.completeness is Completeness.TIMEOUT)
    v["sandbox_import_failed"] = float(trace.completeness is Completeness.IMPORT_FAILED)
    v["credential_read_and_connect_or_subprocess"] = float(
        bool(trace.credential_reads) and bool(trace.connects or trace.subprocesses)
    )
    return v


def vectorize(sf: StaticFeatures, trace: BehaviorTrace | None = None) -> dict[str, float]:
    """Full feature dict, keys exactly ``FEATURE_NAMES`` in order."""
    v = static_vector(sf) | behaviour_vector(trace)
    return {name: v[name] for name in FEATURE_NAMES}
