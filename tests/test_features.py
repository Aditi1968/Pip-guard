from datetime import date

import pytest
from pydantic import ValidationError

from pipguard.features import (
    BEHAVIOUR_FEATURE_NAMES,
    FEATURE_NAMES,
    TYPOSQUAT_FAR,
    behaviour_vector,
    static_vector,
    vectorize,
)
from pipguard.models import (
    ArtifactKind,
    ArtifactStaticFeatures,
    BehaviorTrace,
    Completeness,
    ConnectAttempt,
    CredentialRead,
    ImportCategory,
    ModelArtifact,
    PackageMetadata,
    PackageSpec,
    StaticFeatures,
    SubprocessCall,
    SuspiciousCounts,
    TyposquatResult,
)

SPEC = PackageSpec(name="pkg", version="1.0")


def _art(kind: ArtifactKind, **kw: object) -> ArtifactStaticFeatures:
    return ArtifactStaticFeatures(filename=f"f.{kind}", sha256="0" * 64, kind=kind, **kw)  # type: ignore[arg-type]


def _sf(*arts: ArtifactStaticFeatures, **meta: object) -> StaticFeatures:
    return StaticFeatures(
        spec=SPEC,
        artifacts=list(arts),
        typosquat=TyposquatResult(snapshot_date=date(2026, 11, 1)),
        metadata=PackageMetadata(**meta),  # type: ignore[arg-type]
    )


def test_vectorize_keys_in_order() -> None:
    assert list(vectorize(_sf())) == FEATURE_NAMES
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_static_aggregation_uses_max_not_sum_for_counts() -> None:
    w = _art(
        ArtifactKind.WHEEL,
        suspicious=SuspiciousCounts(exec=2),
        risky_import_categories=[ImportCategory.NETWORK],
        urls=["http://a"],
    )
    s = _art(ArtifactKind.SDIST, suspicious=SuspiciousCounts(exec=2), urls=["http://a", "http://b"])
    v = static_vector(_sf(w, s))
    assert v["susp_exec"] == 2 and v["susp_total"] == 2
    assert v["url_count"] == 2
    assert v["imports_network"] == 1 and v["imports_subprocess"] == 0
    assert v["has_wheel"] == v["has_sdist"] == 1


def test_missing_metadata_flagged() -> None:
    v = static_vector(_sf(version_count=7))
    assert (v["version_count"], v["version_count_missing"]) == (7, 0)
    assert (v["maintainer_count"], v["maintainer_count_missing"]) == (0, 1)


def test_typosquat_distance_bounded() -> None:
    assert static_vector(_sf())["typosquat_distance"] == TYPOSQUAT_FAR


def test_behaviour_absent_is_zero() -> None:
    assert behaviour_vector(None) == dict.fromkeys(BEHAVIOUR_FEATURE_NAMES, 0.0)


def test_behaviour_interaction_flags() -> None:
    t = BehaviorTrace(
        spec=SPEC,
        completeness=Completeness.COMPLETE,
        connects=[ConnectAttempt(step="install", family="AF_INET", address="1.2.3.4", port=443)],
        credential_reads=[CredentialRead(step="import", path="/home/sandbox/.aws/credentials")],
        subprocesses=[SubprocessCall(step="import", argv=["/usr/bin/curl", "-d", "x"])],
    )
    v = behaviour_vector(t)
    assert v["behaviour_available"] == 1
    assert v["connect_install_count"] == 1 and v["connect_import_count"] == 0
    assert v["subprocess_suspicious_argv"] == 1
    assert v["credential_read_and_connect_or_subprocess"] == 1


def test_model_artifact_shape_check() -> None:
    with pytest.raises(ValidationError):
        ModelArtifact(model_version="m", kind="logreg", feature_names=["a"], coefficients=[])
    ModelArtifact(
        model_version="m",
        kind="logreg",
        feature_names=["a"],
        coefficients=[1.0],
        feature_means=[0.0],
        feature_scales=[1.0],
    )
    ModelArtifact(model_version="rules-only", kind="rules")
