from datetime import date

import pytest
from pydantic import ValidationError

from pipguard.models import (
    Artifact,
    ArtifactKind,
    BehaviorTrace,
    ChangeKind,
    Completeness,
    Config,
    DependencyChange,
    Level,
    PackageMetadata,
    PackageSpec,
    StaticFeatures,
    SuspiciousCounts,
    Thresholds,
    TyposquatResult,
    Verdict,
    normalize_name,
)

SHA = "a" * 64


def test_parse_exact_pin() -> None:
    spec = PackageSpec.parse(" requests==2.31.0 ")
    assert (spec.name, spec.version) == ("requests", "2.31.0")
    assert str(spec) == "requests==2.31.0"


@pytest.mark.parametrize(
    "text", ["requests", "requests>=2", "requests~=2.0", "requests===2.0", "==1.0", "x==", "a b==1"]
)
def test_parse_rejects_non_pins(text: str) -> None:
    with pytest.raises(ValueError):
        PackageSpec.parse(text)


def test_normalize_name_pep503() -> None:
    assert normalize_name("Foo__Bar.baz-Q") == "foo-bar-baz-q"
    assert PackageSpec(name="Py_YAML", version="6").normalized_name == "py-yaml"


def test_models_are_frozen_and_strict() -> None:
    spec = PackageSpec(name="a", version="1")
    with pytest.raises(ValidationError):
        spec.name = "b"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PackageSpec(name="a", version="1", extra=1)  # type: ignore[call-arg]


def test_artifact_requires_hex_sha256() -> None:
    with pytest.raises(ValidationError):
        Artifact(filename="a.whl", kind=ArtifactKind.WHEEL, sha256="XYZ", size=1, path="a")


def test_non_allow_verdict_needs_reason() -> None:
    with pytest.raises(ValidationError):
        Verdict(spec=None, raw_spec="x", level=Level.BLOCK, scanner_version="0", model_version="0")
    v = Verdict(spec=None, raw_spec="x", level=Level.ALLOW, scanner_version="0", model_version="0")
    assert v.reasons == []


def test_thresholds_ordered() -> None:
    with pytest.raises(ValidationError):
        Thresholds(warn=0.9, block=0.5)


def test_dependency_change_exactly_one_of_spec_or_reason() -> None:
    with pytest.raises(ValidationError):
        DependencyChange(raw="a", source_file="r", kind=ChangeKind.ADDED, spec=None)
    DependencyChange(
        raw="a>=1",
        source_file="r",
        kind=ChangeKind.ADDED,
        spec=None,
        unsupported_reason="not an exact pin",
    )


def test_config_allowlist_normalised() -> None:
    assert Config(allowlist=["Foo_Bar", "foo-bar"]).allowlist == ["foo-bar"]


def test_suspicious_total() -> None:
    assert SuspiciousCounts(exec=2, ctypes=1).total == 3


def test_completeness_flags() -> None:
    assert Completeness.COMPLETE.is_complete
    assert not Completeness.TIMEOUT.is_complete


def test_round_trip_json() -> None:
    spec = PackageSpec(name="a", version="1")
    sf = StaticFeatures(
        spec=spec,
        artifacts=[],
        metadata=PackageMetadata(),
        typosquat=TyposquatResult(snapshot_date=date(2026, 11, 1)),
    )
    assert StaticFeatures.model_validate_json(sf.model_dump_json()) == sf
    bt = BehaviorTrace(spec=spec, completeness=Completeness.TIMEOUT)
    assert BehaviorTrace.model_validate_json(bt.model_dump_json()) == bt
